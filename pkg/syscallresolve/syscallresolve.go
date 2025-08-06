// Package syscallresolve provides functionality to resolve Windows syscall numbers.
package syscallresolve

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"
	"unsafe"
	"github.com/Binject/debug/pe"
	"github.com/carved4/go-native-syscall/pkg/debug"
	"github.com/carved4/go-native-syscall/pkg/obf"
)

// Windows structures needed for PEB access
type LIST_ENTRY struct {
	Flink *LIST_ENTRY
	Blink *LIST_ENTRY
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks       LIST_ENTRY
	InMemoryOrderLinks     LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	DllBase                uintptr
	EntryPoint             uintptr
	SizeOfImage            uintptr
	FullDllName            UNICODE_STRING
	BaseDllName            UNICODE_STRING
}

type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     uint32
	SsHandle                        uintptr
	InLoadOrderModuleList           LIST_ENTRY
	InMemoryOrderModuleList         LIST_ENTRY
	InInitializationOrderModuleList LIST_ENTRY
}

type PEB struct {
	Reserved1              [2]byte
	BeingDebugged          byte
	Reserved2              byte
	Reserved3              [2]uintptr
	Ldr                    *PEB_LDR_DATA
	ProcessParameters      uintptr
	Reserved4              [3]uintptr
	AtlThunkSListPtr       uintptr
	Reserved5              uintptr
	Reserved6              uint32
	Reserved7              uintptr
	Reserved8              uint32
	AtlThunkSListPtr32     uint32
	Reserved9              [45]uintptr
	Reserved10             [96]byte
	PostProcessInitRoutine uintptr
	Reserved11             [128]byte
	Reserved12             [1]uintptr
	SessionId              uint32
}

// GetPEB directly using assembly (Windows x64)
//
//go:nosplit
//go:noinline
func GetPEB() uintptr

// The x64 implementation is kept in assembly in pkg/syscallresolve/peb_windows_amd64.s
// Using the following:
/*
// Assembly for peb_windows_amd64.s:
TEXT ·GetPEB(SB), $0-8
    MOVQ 0x60(GS), AX  // Access PEB from GS register (x64)
    MOVQ AX, ret+0(FP)
    RET
*/

// UTF16ToString converts a UTF16 string to a Go string
func UTF16ToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}

	// Find the length by searching for null terminator
	length := 0
	for tmp := ptr; *tmp != 0; tmp = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(tmp)) + 2)) {
		length++
	}

	// Create a slice of uint16 values
	slice := make([]uint16, length)
	for i := 0; i < length; i++ {
		slice[i] = *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i*2)))
	}

	// Convert to a Go string
	return string(utf16BytesToString(slice))
}

// utf16BytesToString converts UTF-16 bytes to string
func utf16BytesToString(b []uint16) string {
	// Decode UTF-16 to runes
	runes := make([]rune, 0, len(b))
	for i := 0; i < len(b); i++ {
		r := rune(b[i])
		// Handle surrogate pairs
		if r >= 0xD800 && r <= 0xDBFF && i+1 < len(b) {
			r2 := rune(b[i+1])
			if r2 >= 0xDC00 && r2 <= 0xDFFF {
				r = (r-0xD800)<<10 + (r2 - 0xDC00) + 0x10000
				i++
			}
		}
		runes = append(runes, r)
	}
	return string(runes)
}

// GetCurrentProcessPEB retrieves a pointer to the PEB of the current process
// This uses a direct assembly approach without any Windows API calls
func GetCurrentProcessPEB() *PEB {
	// Using direct assembly to get PEB
	pebAddr := GetPEB()
	if pebAddr == 0 {
		debug.Printfln("SYSCALLRESOLVE", "Failed to get PEB address via assembly\n")
		return nil
	}
	
	// Add some retry attempts to ensure stability
	maxRetries := 5
	var peb *PEB
	
	for i := 0; i < maxRetries; i++ {
		peb = (*PEB)(unsafe.Pointer(pebAddr))
		
		// Validate PEB pointer
		if peb != nil && peb.Ldr != nil {
			return peb
		}
		
		debug.Printfln("SYSCALLRESOLVE", "PEB validation failed (retry %d/%d), waiting...\n", i+1, maxRetries)
		time.Sleep(100 * time.Millisecond)
	}
	
	return peb
}

// GetModuleBase retrieves the base address of a module by its name hash
func GetModuleBase(moduleHash uint32) uintptr {
	// Add retry mechanism for GetModuleBase
	maxRetries := 5
	var moduleBase uintptr
	
	for i := 0; i < maxRetries; i++ {
		peb := GetCurrentProcessPEB()
		if peb == nil {
			debug.Printfln("SYSCALLRESOLVE", "Failed to get PEB, retrying (%d/%d)...\n", i+1, maxRetries)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		if peb.Ldr == nil {
			debug.Printfln("SYSCALLRESOLVE", "PEB.Ldr is nil, retrying (%d/%d)...\n", i+1, maxRetries)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		// Get the head of the InLoadOrderModuleList
		entry := &peb.Ldr.InLoadOrderModuleList
		currentEntry := entry.Flink
	
		// Ensure the linked list is valid
		if currentEntry == nil {
			debug.Printfln("SYSCALLRESOLVE", "Module list is invalid (nil), retrying (%d/%d)...\n", i+1, maxRetries)
			time.Sleep(100 * time.Millisecond)
			continue
		}
	
		// Iterate through the module list
		for currentEntry != entry {
			// Convert the list entry to a LDR_DATA_TABLE_ENTRY
			// Since we're iterating through InLoadOrderModuleList, and InLoadOrderLinks is the first field
			// in LDR_DATA_TABLE_ENTRY, we can directly cast
			dataTableEntry := (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(currentEntry))
	
			// Get the module name
			baseName := UTF16ToString(dataTableEntry.BaseDllName.Buffer)
			
			// Calculate the hash of the module name
			currentHash := obf.DBJ2HashStr(baseName)
			
			// If the hash matches, return the module base
			if currentHash == moduleHash {
				moduleBase = dataTableEntry.DllBase
				break
			}
	
			// Move to the next entry
			currentEntry = currentEntry.Flink
			
			// Safety check to prevent infinite loops
			if currentEntry == nil {
				break
			}
		}
		
		if moduleBase != 0 {
			break
		}
		
		// Wait before retrying
		time.Sleep(100 * time.Millisecond)
	}

	return moduleBase
}

// GetFunctionAddress retrieves the address of a function in a module by its name hash using Binject PE parser
func GetFunctionAddress(moduleBase uintptr, functionHash uint32) uintptr {
	if moduleBase == 0 {
		return 0
	}

	// Read the PE header to get the actual size of the image
	dosHeader := (*[64]byte)(unsafe.Pointer(moduleBase))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		debug.Printfln("SYSCALLRESOLVE", "Invalid DOS signature\n")
		return 0
	}
	
	// Get the offset to the PE header
	peOffset := *(*uint32)(unsafe.Pointer(moduleBase + 60))
	if peOffset >= 1024 {
		debug.Printfln("SYSCALLRESOLVE", "PE offset too large: %d\n", peOffset)
		return 0
	}
	
	// Read the PE header to get the SizeOfImage
	peHeader := (*[1024]byte)(unsafe.Pointer(moduleBase + uintptr(peOffset)))
	if peHeader[0] != 'P' || peHeader[1] != 'E' {
		debug.Printfln("SYSCALLRESOLVE", "Invalid PE signature\n")
		return 0
	}
	
	// SizeOfImage is at offset 56 from the start of the OptionalHeader
	// OptionalHeader starts at offset 24 from PE signature
	sizeOfImage := *(*uint32)(unsafe.Pointer(moduleBase + uintptr(peOffset) + 24 + 56))
	
	
	// Create a memory reader for the PE file with the correct size
	dataSlice := unsafe.Slice((*byte)(unsafe.Pointer(moduleBase)), sizeOfImage)
	
	// Parse the PE file from memory
	file, err := pe.NewFileFromMemory(&memoryReaderAt{data: dataSlice})
	if err != nil {
		debug.Printfln("SYSCALLRESOLVE", "Failed to parse PE file: %v\n", err)
		return 0
	}
	defer file.Close()

	// Get the exports
	exports, err := file.Exports()
	if err != nil {
		debug.Printfln("SYSCALLRESOLVE", "Failed to get exports: %v\n", err)
		return 0
	}

	// Search for the function by hash
	for _, export := range exports {
		if export.Name != "" {
			currentHash := obf.DBJ2HashStr(export.Name)
			if currentHash == functionHash {
				// Return the function address (module base + RVA)
				return moduleBase + uintptr(export.VirtualAddress)
			}
		}
	}

	return 0
}

// memoryReaderAt implements io.ReaderAt for in-memory data
type memoryReaderAt struct {
	data []byte
}

func (r *memoryReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off >= int64(len(r.data)) {
		return 0, fmt.Errorf("offset out of range")
	}
	n = copy(p, r.data[off:])
	if n < len(p) {
		err = fmt.Errorf("EOF")
	}
	return n, err
}

// GetSyscallNumber extracts the syscall number from a NTDLL syscall function
// This function uses ONLY manual PE parsing and PEB walking - NO Windows API calls
func GetSyscallNumber(functionHash uint32) uint16 {
	// Try cache first for performance
	if cached := getSyscallFromCache(functionHash); cached != 0 {
		return cached
	}

	// Get the base address of ntdll.dll using PEB walking (no LoadLibrary)
	ntdllHash := obf.GetHash("ntdll.dll")
	
	// Add retry mechanism with exponential backoff
	var ntdllBase uintptr
	maxRetries := 8
	baseDelay := 50 * time.Millisecond
	
	for i := 0; i < maxRetries; i++ {
		ntdllBase = GetModuleBase(ntdllHash)
		if ntdllBase != 0 {
			break
		}
		
		// Exponential backoff
		delay := baseDelay * time.Duration(1<<uint(i))
		if delay > 2*time.Second {
			delay = 2 * time.Second
		}
		
		debug.Printfln("SYSCALLRESOLVE", "Failed to get ntdll.dll base address, retrying (%d/%d) after %v...\n", i+1, maxRetries, delay)
		time.Sleep(delay)
	}
	
	if ntdllBase == 0 {
		debug.Printfln("SYSCALLRESOLVE", "Failed to get ntdll.dll base address after %d retries\n", maxRetries)
		return 0
	}
	
	// Get the address of the syscall function using PE parsing (no GetProcAddress)
	var funcAddr uintptr
	
	for i := 0; i < maxRetries; i++ {
		funcAddr = GetFunctionAddress(ntdllBase, functionHash)
		if funcAddr != 0 {
			break
		}
		
		// Exponential backoff
		delay := baseDelay * time.Duration(1<<uint(i))
		if delay > 2*time.Second {
			delay = 2 * time.Second
		}
		
		debug.Printfln("SYSCALLRESOLVE", "Failed to get function address, retrying (%d/%d) after %v...\n", i+1, maxRetries, delay)
		time.Sleep(delay)
	}
	
	if funcAddr == 0 {
		debug.Printfln("SYSCALLRESOLVE", "Failed to get function address for hash: 0x%X after %d retries\n", functionHash, maxRetries)
		return 0
	}

	// Enhanced syscall stub validation and extraction
	syscallNumber := extractSyscallNumberWithValidation(funcAddr, functionHash)
	
	// Cache the result if valid
	if syscallNumber != 0 {
		cacheSyscallNumber(functionHash, syscallNumber)
	}
	
	return syscallNumber
}

// Helper function to map function hashes to their string names (for debugging/testing)
func getFunctionNameFromHash(functionHash uint32) string {
	// Map common function hashes to their names
	commonFunctions := map[uint32]string{
		obf.GetHash("NtAllocateVirtualMemory"): "NtAllocateVirtualMemory",
		obf.GetHash("NtWriteVirtualMemory"):    "NtWriteVirtualMemory", 
		obf.GetHash("NtCreateThreadEx"):        "NtCreateThreadEx",
		obf.GetHash("NtProtectVirtualMemory"):  "NtProtectVirtualMemory",
		obf.GetHash("NtCreateProcess"):         "NtCreateProcess",
		obf.GetHash("NtCreateThread"):          "NtCreateThread",
		obf.GetHash("NtOpenProcess"):           "NtOpenProcess",
		obf.GetHash("NtClose"):                 "NtClose",
	}
	
	return commonFunctions[functionHash]
}

// GetSyscallAndAddress returns both the syscall number and the address of the syscall instruction
func GetSyscallAndAddress(functionHash uint32) (uint16, uintptr) {
	// Get the base address of ntdll.dll using PEB walking (no LoadLibrary)
	ntdllHash := obf.GetHash("ntdll.dll")
	
	// Add retry mechanism
	var ntdllBase uintptr
	maxRetries := 5
	
	for i := 0; i < maxRetries; i++ {
		ntdllBase = GetModuleBase(ntdllHash)
		if ntdllBase != 0 {
			break
		}
		debug.Printfln("SYSCALLRESOLVE", "Failed to get ntdll.dll base address, retrying (%d/%d)...\n", i+1, maxRetries)
		time.Sleep(100 * time.Millisecond)
	}
	
	if ntdllBase == 0 {
		debug.Printfln("SYSCALLRESOLVE", "Failed to get ntdll.dll base address after %d retries\n", maxRetries)
		return 0, 0
	}

	// Get the address of the syscall function using PE parsing (no GetProcAddress)
	var funcAddr uintptr
	
	for i := 0; i < maxRetries; i++ {
		funcAddr = GetFunctionAddress(ntdllBase, functionHash)
		if funcAddr != 0 {
			break
		}
		debug.Printfln("SYSCALLRESOLVE", "Failed to get function address, retrying (%d/%d)...\n", i+1, maxRetries)
		time.Sleep(100 * time.Millisecond)
	}
	
	if funcAddr == 0 {
		debug.Printfln("SYSCALLRESOLVE", "Failed to get function address for hash: 0x%X after %d retries\n", functionHash, maxRetries)
		return 0, 0
	}

	// The syscall number is at offset 4 in the syscall stub
	syscallNumber := *(*uint16)(unsafe.Pointer(funcAddr + 4))
	
	// The syscall instruction is at offset 0x12 for x64
	syscallInstructionAddr := funcAddr + 0x12
	
	return syscallNumber, syscallInstructionAddr
}

// Helper function to dump memory for debugging
func dumpMemory(addr uintptr, size int) {
	debug.Printfln("SYSCALLRESOLVE", "Memory dump at 0x%X:\n", addr)
	for i := 0; i < size; i++ {
		if i%16 == 0 {
			debug.Printf("%08X: ", i)
		}
		b := *(*byte)(unsafe.Pointer(addr + uintptr(i)))
		debug.Printf("%02X ", b)
		if i%16 == 15 || i == size-1 {
			debug.Printf("\n")
		}
	}
}

// SyscallCache provides thread-safe caching for resolved syscall numbers
type SyscallCache struct {
	cache map[uint32]uint16
	mutex sync.RWMutex
}

var globalSyscallCache = &SyscallCache{
	cache: make(map[uint32]uint16),
}

// getSyscallFromCache retrieves a cached syscall number
func getSyscallFromCache(functionHash uint32) uint16 {
	globalSyscallCache.mutex.RLock()
	defer globalSyscallCache.mutex.RUnlock()
	
	if syscallNum, exists := globalSyscallCache.cache[functionHash]; exists {
		return syscallNum
	}
	return 0
}

// cacheSyscallNumber stores a syscall number in the cache
func cacheSyscallNumber(functionHash uint32, syscallNumber uint16) {
	globalSyscallCache.mutex.Lock()
	defer globalSyscallCache.mutex.Unlock()
	
	globalSyscallCache.cache[functionHash] = syscallNumber
}

// clearSyscallCache clears all cached syscall numbers (useful for testing)
func clearSyscallCache() {
	globalSyscallCache.mutex.Lock()
	defer globalSyscallCache.mutex.Unlock()
	
	globalSyscallCache.cache = make(map[uint32]uint16)
}

// GetSyscallCacheSize returns the number of cached syscalls
func GetSyscallCacheSize() int {
	globalSyscallCache.mutex.RLock()
	defer globalSyscallCache.mutex.RUnlock()
	
	return len(globalSyscallCache.cache)
}

// extractSyscallNumberWithValidation performs enhanced validation and extraction
func extractSyscallNumberWithValidation(funcAddr uintptr, functionHash uint32) uint16 {
	if funcAddr == 0 {
		return 0
	}

	// Read enough bytes to analyze the function
	const maxBytes = 32
	funcBytes := make([]byte, maxBytes)
	
	// Safely read memory with bounds checking
	for i := 0; i < maxBytes; i++ {
		funcBytes[i] = *(*byte)(unsafe.Pointer(funcAddr + uintptr(i)))
	}

	// Try multiple syscall stub patterns for robustness
	syscallNumber := tryExtractSyscallNumber(funcBytes, funcAddr, functionHash)
	
	// Validate the extracted syscall number
	if syscallNumber > 0 && validateSyscallNumber(syscallNumber, functionHash) {
		return syscallNumber
	}

	// Fallback: try alternative extraction methods
	return tryAlternativeExtractionMethods(funcBytes, funcAddr, functionHash)
}

// tryExtractSyscallNumber attempts to extract syscall number using multiple patterns
func tryExtractSyscallNumber(funcBytes []byte, funcAddr uintptr, functionHash uint32) uint16 {
	if len(funcBytes) < 16 {
		return 0
	}

	// Pattern 1: Standard x64 syscall stub
	// 0: 4c 8b d1             mov r10, rcx
	// 3: b8 XX XX 00 00       mov eax, XXXX
	// 8: f6 04 25 08 03 fe 7f test byte ptr [0x7ffe0308], 1
	if len(funcBytes) >= 8 &&
		funcBytes[0] == 0x4c && funcBytes[1] == 0x8b && funcBytes[2] == 0xd1 &&
		funcBytes[3] == 0xb8 {
		
		syscallNum := uint16(funcBytes[4]) | (uint16(funcBytes[5]) << 8)
		if syscallNum > 0 && syscallNum < 2000 { // Reasonable range check
			return syscallNum
		}
	}

	// Pattern 2: Alternative syscall stub (some Windows versions)
	// 0: b8 XX XX 00 00       mov eax, XXXX
	// 5: 4c 8b d1             mov r10, rcx
	if len(funcBytes) >= 8 &&
		funcBytes[0] == 0xb8 &&
		funcBytes[5] == 0x4c && funcBytes[6] == 0x8b && funcBytes[7] == 0xd1 {
		
		syscallNum := uint16(funcBytes[1]) | (uint16(funcBytes[2]) << 8)
		if syscallNum > 0 && syscallNum < 2000 {
			return syscallNum
		}
	}

	// Enhanced hook detection - check for various hook patterns
	if IsHooked(funcBytes, funcAddr, functionHash) {
		return 0
	}

	return 0
}

// validateSyscallNumber performs additional validation on extracted syscall numbers
func validateSyscallNumber(syscallNumber uint16, functionHash uint32) bool {
	// Basic range validation
	if syscallNumber == 0 || syscallNumber >= 2000 {
		return false
	}

	// Check against known invalid ranges
	// Syscall numbers should be reasonable for NT kernel functions
	if syscallNumber < 2 {
		// Only syscall numbers 0 and 1 are truly suspicious
		debug.Printfln("SYSCALLRESOLVE", "Warning: Unusually low syscall number %d for hash 0x%X\n", 
			syscallNumber, functionHash)
	}

	// Additional validation could include (if you want to submit a PR)
	// - Cross-referencing with known good syscall numbers
	// - Checking if the syscall number fits expected patterns
	// - Validating against syscall tables from different Windows versions

	return true
}

// tryAlternativeExtractionMethods provides fallback extraction when standard methods fail
func tryAlternativeExtractionMethods(funcBytes []byte, funcAddr uintptr, functionHash uint32) uint16 {
	// Method 1: Scan for MOV EAX instructions in the first 32 bytes
	for i := 0; i < len(funcBytes)-4; i++ {
		if funcBytes[i] == 0xb8 { // MOV EAX, imm32
			syscallNum := uint16(funcBytes[i+1]) | (uint16(funcBytes[i+2]) << 8)
			if syscallNum > 0 && syscallNum < 2000 {
				debug.Printfln("SYSCALLRESOLVE", "Alternative extraction found syscall %d at offset %d for hash 0x%X\n", 
					syscallNum, i, functionHash)
				return syscallNum
			}
		}
	}

	// Method 2: Look for syscall instruction and backtrack
	for i := 0; i < len(funcBytes)-1; i++ {
		if funcBytes[i] == 0x0f && funcBytes[i+1] == 0x05 { // SYSCALL instruction
			// Found syscall instruction, now look backwards for MOV EAX
			for j := i; j >= 4; j-- {
				if funcBytes[j-4] == 0xb8 { // MOV EAX, imm32
					syscallNum := uint16(funcBytes[j-3]) | (uint16(funcBytes[j-2]) << 8)
					if syscallNum > 0 && syscallNum < 2000 {
						debug.Printfln("SYSCALLRESOLVE", "Backtrack extraction found syscall %d for hash 0x%X\n", 
							syscallNum, functionHash)
						return syscallNum
					}
				}
			}
			break
		}
	}

	// Method 3: Try reading at different offsets (handle potential hooks/patches)
	alternativeOffsets := []int{8, 12, 16, 20}
	for _, offset := range alternativeOffsets {
		if offset+1 < len(funcBytes) {
			if funcBytes[offset] == 0xb8 { // MOV EAX
				syscallNum := uint16(funcBytes[offset+1]) | (uint16(funcBytes[offset+2]) << 8)
				if syscallNum > 0 && syscallNum < 2000 {
					debug.Printfln("SYSCALLRESOLVE", "Offset extraction found syscall %d at offset %d for hash 0x%X\n", 
						syscallNum, offset, functionHash)
					return syscallNum
				}
			}
		}
	}

	debug.Printfln("SYSCALLRESOLVE", "All extraction methods failed for hash 0x%X\n", functionHash)
	return 0
}

// GetSyscallWithValidation provides additional metadata and validation
func GetSyscallWithValidation(functionHash uint32) (uint16, bool, error) {
	syscallNum := GetSyscallNumber(functionHash)
	
	if syscallNum == 0 {
		return 0, false, fmt.Errorf("failed to resolve syscall for hash 0x%X", functionHash)
	}

	// Additional validation
	isValid := validateSyscallNumber(syscallNum, functionHash)
	
	return syscallNum, isValid, nil
}

// GuessSyscallNumber attempts to infer a syscall number for a hooked function
// by finding clean left and right neighbors and interpolating the missing number.
func GuessSyscallNumber(targetHash uint32) uint16 {
	ntdllBase := GetModuleBase(obf.GetHash("ntdll.dll"))
	if ntdllBase == 0 {
		debug.Printfln("SYSCALLRESOLVE", "Failed to get ntdll.dll base for delta guessing\n")
		return 0
	}

	// Parse exports from NTDLL
	dosHeader := (*[2]byte)(unsafe.Pointer(ntdllBase))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		debug.Printfln("SYSCALLRESOLVE", "Invalid DOS signature in NTDLL\n")
		return 0
	}

	peOffset := *(*uint32)(unsafe.Pointer(ntdllBase + 0x3C))
	file := (*[1024]byte)(unsafe.Pointer(ntdllBase + uintptr(peOffset)))
	if file[0] != 'P' || file[1] != 'E' {
		debug.Printfln("SYSCALLRESOLVE", "Invalid PE signature\n")
		return 0
	}

	sizeOfImage := *(*uint32)(unsafe.Pointer(ntdllBase + uintptr(peOffset) + 24 + 56))
	slice := unsafe.Slice((*byte)(unsafe.Pointer(ntdllBase)), sizeOfImage)
	peFile, err := pe.NewFileFromMemory(&memoryReaderAt{data: slice})
	if err != nil {
		debug.Printfln("SYSCALLRESOLVE", "Failed to parse NTDLL PE: %v\n", err)
		return 0
	}
	exports, err := peFile.Exports()
	if err != nil {
		debug.Printfln("SYSCALLRESOLVE", "Failed to list NTDLL exports: %v\n", err)
		return 0
	}

	// Sort exports by address
	sort.Slice(exports, func(i, j int) bool {
		return exports[i].VirtualAddress < exports[j].VirtualAddress
	})

	// Find the target function
	targetIndex := -1
	for i, exp := range exports {
		if obf.GetHash(exp.Name) == targetHash {
			targetIndex = i
			break
		}
	}

	if targetIndex == -1 {
		debug.Printfln("SYSCALLRESOLVE", "Target function not found for hash 0x%X\n", targetHash)
		return 0
	}

	// Helper function to check if a function is hooked
	isCleanSyscall := func(addr uintptr) (bool, uint16) {
		bytes := *(*[8]byte)(unsafe.Pointer(addr))
		// Check for standard syscall stub pattern
		if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8 {
			syscallNum := uint16(bytes[4]) | uint16(bytes[5])<<8
			return true, syscallNum
		}
		return false, 0
	}

	// Helper function to check if two function names are NT/ZW pairs
	isNtZwPair := func(name1, name2 string) bool {
		if len(name1) < 2 || len(name2) < 2 {
			return false
		}
		// Check if one starts with Nt and other with Zw, and rest is same
		if (name1[:2] == "Nt" && name2[:2] == "Zw" && name1[2:] == name2[2:]) ||
		   (name1[:2] == "Zw" && name2[:2] == "Nt" && name1[2:] == name2[2:]) {
			return true
		}
		return false
	}

	// First, check if there's a ZW/NT pair nearby (they have identical syscall numbers)
	for offset := -5; offset <= 5; offset++ {
		if offset == 0 {
			continue
		}
		
		pairIdx := targetIndex + offset
		if pairIdx < 0 || pairIdx >= len(exports) {
			continue
		}

		if isNtZwPair(exports[targetIndex].Name, exports[pairIdx].Name) {
			pairAddr := ntdllBase + uintptr(exports[pairIdx].VirtualAddress)
			if clean, syscallNum := isCleanSyscall(pairAddr); clean {
				debug.Printfln("SYSCALLRESOLVE", "Found NT/ZW pair %s with syscall %d for target %s\n", 
					exports[pairIdx].Name, syscallNum, exports[targetIndex].Name)
				return syscallNum
			}
		}
	}

	// Find clean left neighbor
	var leftSyscall uint16
	var leftIndex int = -1
	for i := targetIndex - 1; i >= 0 && i >= targetIndex-10; i-- {
		addr := ntdllBase + uintptr(exports[i].VirtualAddress)
		if clean, syscallNum := isCleanSyscall(addr); clean {
			leftSyscall = syscallNum
			leftIndex = i
			break
		}
	}

	// Find clean right neighbor  
	var rightSyscall uint16
	var rightIndex int = -1
	for i := targetIndex + 1; i < len(exports) && i <= targetIndex+10; i++ {
		addr := ntdllBase + uintptr(exports[i].VirtualAddress)
		if clean, syscallNum := isCleanSyscall(addr); clean {
			rightSyscall = syscallNum
			rightIndex = i
			break
		}
	}

	// If we have both neighbors, interpolate
	if leftIndex != -1 && rightIndex != -1 {
		// Calculate the expected syscall number based on position
		positionDiff := targetIndex - leftIndex
		syscallDiff := rightSyscall - leftSyscall
		indexDiff := rightIndex - leftIndex
		
		if indexDiff > 0 {
			interpolated := leftSyscall + uint16((syscallDiff*uint16(positionDiff))/uint16(indexDiff))
			debug.Printfln("SYSCALLRESOLVE", "Interpolated syscall %d for hash 0x%X between %s(%d) and %s(%d)\n", 
				interpolated, targetHash, exports[leftIndex].Name, leftSyscall, exports[rightIndex].Name, rightSyscall)
			return interpolated
		}
	}

	// Fallback: use single neighbor with small offset
	if leftIndex != -1 {
		offset := targetIndex - leftIndex
		guessed := leftSyscall + uint16(offset)
		debug.Printfln("SYSCALLRESOLVE", "Guessed syscall %d for hash 0x%X using left neighbor %s(%d) + %d\n", 
			guessed, targetHash, exports[leftIndex].Name, leftSyscall, offset)
		return guessed
	}

	if rightIndex != -1 {
		offset := rightIndex - targetIndex
		guessed := rightSyscall - uint16(offset)
		debug.Printfln("SYSCALLRESOLVE", "Guessed syscall %d for hash 0x%X using right neighbor %s(%d) - %d\n", 
			guessed, targetHash, exports[rightIndex].Name, rightSyscall, offset)
		return guessed
	}

	debug.Printfln("SYSCALLRESOLVE", "Failed to find clean neighbors for hash 0x%X\n", targetHash)
	return 0
}

// IsHooked performs comprehensive hook detection on a function
func IsHooked(funcBytes []byte, funcAddr uintptr, functionHash uint32) bool {
	if len(funcBytes) < 8 {
		return true // Too small to be a valid syscall stub
	}

	// Pattern 1: Direct JMP hooks (most common)
	// 0xe9 = JMP rel32, 0xeb = JMP rel8, 0xff = JMP r/m64
	if funcBytes[0] == 0xe9 || funcBytes[0] == 0xeb || 
	   (funcBytes[0] == 0xff && (funcBytes[1] & 0xf8) == 0x20) { // JMP [mem]
		debug.Printfln("SYSCALLRESOLVE", "Hook detected: JMP instruction at start (0x%02X 0x%02X) for hash 0x%X\n", 
			funcBytes[0], funcBytes[1], functionHash)
		return true
	}

	// Pattern 2: PUSH/RET hook (trampoline style)
	if funcBytes[0] == 0x68 { // PUSH imm32
		debug.Printfln("SYSCALLRESOLVE", "Hook detected: PUSH/RET trampoline for hash 0x%X\n", functionHash)
		return true
	}

	// Pattern 3: MOV to register + JMP (indirect hook)
	if (funcBytes[0] == 0x48 || funcBytes[0] == 0x49) && // REX prefix
	   (funcBytes[1] == 0xb8 || funcBytes[1] == 0xb9 || funcBytes[1] == 0xba) { // MOV to RAX/RCX/RDX
		// Check if followed by JMP
		for i := 2; i < len(funcBytes)-1 && i < 16; i++ {
			if funcBytes[i] == 0xff && (funcBytes[i+1] & 0xf8) == 0xe0 { // JMP reg
				debug.Printfln("SYSCALLRESOLVE", "Hook detected: MOV+JMP pattern for hash 0x%X\n", functionHash)
				return true
			}
		}
	}

	// Pattern 4: INT3 breakpoint hook
	if funcBytes[0] == 0xcc {
		debug.Printfln("SYSCALLRESOLVE", "Hook detected: INT3 breakpoint for hash 0x%X\n", functionHash)
		return true
	}

	// Pattern 5: NOP sled followed by hook (evasion technique)
	nopCount := 0
	for i := 0; i < len(funcBytes) && i < 8; i++ {
		if funcBytes[i] == 0x90 { // NOP
			nopCount++
		} else {
			break
		}
	}
	if nopCount >= 3 { // Suspicious NOP sled
		debug.Printfln("SYSCALLRESOLVE", "Hook detected: NOP sled (%d NOPs) for hash 0x%X\n", nopCount, functionHash)
		return true
	}

	// Pattern 6: Inline patch detection - look for unexpected instructions
	// A clean syscall should start with standard patterns
	isStandardPattern := false
	
	// Check for standard syscall patterns
	if len(funcBytes) >= 8 {
		// Pattern: MOV R10, RCX; MOV EAX, imm
		if funcBytes[0] == 0x4c && funcBytes[1] == 0x8b && funcBytes[2] == 0xd1 && funcBytes[3] == 0xb8 {
			isStandardPattern = true
		}
		// Pattern: MOV EAX, imm; MOV R10, RCX  
		if funcBytes[0] == 0xb8 && funcBytes[5] == 0x4c && funcBytes[6] == 0x8b && funcBytes[7] == 0xd1 {
			isStandardPattern = true
		}
	}

	if !isStandardPattern {
		debug.Printfln("SYSCALLRESOLVE", "Hook detected: Non-standard syscall pattern for hash 0x%X\n", functionHash)
		return true
	}

	// Pattern 7: Check for modified syscall number (syscall number should be reasonable)
	if len(funcBytes) >= 8 && funcBytes[3] == 0xb8 {
		syscallNum := uint16(funcBytes[4]) | (uint16(funcBytes[5]) << 8)
		if syscallNum == 0 || syscallNum >= 2000 {
			debug.Printfln("SYSCALLRESOLVE", "Hook detected: Invalid syscall number %d for hash 0x%X\n", syscallNum, functionHash)
			return true
		}
	}

	return false
}

// CleanSyscallStub represents a clean syscall stub that can be used as a template
type CleanSyscallStub struct {
	FunctionHash uint32
	SyscallNumber uint16
	StubBytes []byte
	SyscallInstructionOffset int
}

// cleanStubCache stores verified clean syscall stubs
var cleanStubCache = struct {
	stubs map[uint32]*CleanSyscallStub
	mutex sync.RWMutex
}{
	stubs: make(map[uint32]*CleanSyscallStub),
}

// CacheCleanStub stores a clean syscall stub for later use
func CacheCleanStub(functionHash uint32, syscallNumber uint16, funcAddr uintptr) {
	if funcAddr == 0 {
		return
	}

	// Read the clean stub bytes
	const stubSize = 32
	stubBytes := make([]byte, stubSize)
	for i := 0; i < stubSize; i++ {
		stubBytes[i] = *(*byte)(unsafe.Pointer(funcAddr + uintptr(i)))
	}
	runtime.KeepAlive(stubBytes)

	// Find the syscall instruction offset (0x0f 0x05)
	syscallOffset := -1
	for i := 0; i < len(stubBytes)-1; i++ {
		if stubBytes[i] == 0x0f && stubBytes[i+1] == 0x05 {
			syscallOffset = i
			break
		}
	}

	if syscallOffset == -1 {
		debug.Printfln("SYSCALLRESOLVE", "Warning: No syscall instruction found in clean stub for hash 0x%X\n", functionHash)
		return
	}

	cleanStubCache.mutex.Lock()
	defer cleanStubCache.mutex.Unlock()

	cleanStubCache.stubs[functionHash] = &CleanSyscallStub{
		FunctionHash: functionHash,
		SyscallNumber: syscallNumber,
		StubBytes: stubBytes,
		SyscallInstructionOffset: syscallOffset,
	}

	// Quietly cache the stub without debug spam
}

// GetCleanStubTemplate returns a clean syscall stub that can be used as a template
func GetCleanStubTemplate() *CleanSyscallStub {
	cleanStubCache.mutex.RLock()
	defer cleanStubCache.mutex.RUnlock()

	// Return any clean stub as a template (they all have the same structure)
	for _, stub := range cleanStubCache.stubs {
		return stub
	}
	return nil
}

// BuildDynamicSyscallStub creates a new syscall stub using a clean template
func BuildDynamicSyscallStub(targetSyscallNumber uint16) ([]byte, error) {
	template := GetCleanStubTemplate()
	if template == nil {
		return nil, fmt.Errorf("no clean syscall stub template available")
	}

	// Copy the template
	newStub := make([]byte, len(template.StubBytes))
	copy(newStub, template.StubBytes)
	runtime.KeepAlive(template.StubBytes)

	// Update the syscall number in the new stub
	// Look for MOV EAX, imm32 instruction (0xb8)
	for i := 0; i < len(newStub)-4; i++ {
		if newStub[i] == 0xb8 { // MOV EAX, imm32
			// Replace the syscall number (little endian)
			newStub[i+1] = byte(targetSyscallNumber & 0xff)
			newStub[i+2] = byte((targetSyscallNumber >> 8) & 0xff)
			newStub[i+3] = 0x00
			newStub[i+4] = 0x00
			
			// Built dynamic syscall stub successfully
			runtime.KeepAlive(newStub)
			return newStub, nil
		}
	}
	
	runtime.KeepAlive(newStub)

	return nil, fmt.Errorf("failed to find syscall number location in template")
}

// GetSyscallNumberWithHookHandling attempts to get syscall number, handling hooks gracefully
func GetSyscallNumberWithHookHandling(functionHash uint32) (uint16, bool) {
	// First try normal resolution
	syscallNum := GetSyscallNumber(functionHash)
	if syscallNum != 0 {
		// Cache the clean stub if we got a valid result
		ntdllBase := GetModuleBase(obf.GetHash("ntdll.dll"))
		if ntdllBase != 0 {
			funcAddr := GetFunctionAddress(ntdllBase, functionHash)
			if funcAddr != 0 {
				CacheCleanStub(functionHash, syscallNum, funcAddr)
			}
		}
		return syscallNum, false // Not hooked
	}

	// If normal resolution failed, try guessing (handles hooked functions)
	guessedNum := GuessSyscallNumber(functionHash)
	if guessedNum != 0 {
		debug.Printfln("SYSCALLRESOLVE", "Function appears hooked, using guessed syscall number %d for hash 0x%X\n", 
			guessedNum, functionHash)
		return guessedNum, true // Hooked
	}

	return 0, true // Failed and likely hooked
}

// PrewarmSyscallCache preloads common syscall numbers for better performance
func PrewarmSyscallCache() error {
	// All NT functions available in winapi.go
	commonFunctions := []string{
		// Memory Management
		"NtAllocateVirtualMemory",
		"NtWriteVirtualMemory",
		"NtReadVirtualMemory",
		"NtProtectVirtualMemory",
		"NtFreeVirtualMemory",
		"NtQueryVirtualMemory",
		"NtCreateThreadEx",
		"NtCreateThread",
		"NtOpenProcess",
		"NtOpenThread",
		"NtTerminateProcess",
		"NtSuspendProcess",
		"NtResumeProcess",
		"NtCreateProcess",
		"NtSuspendThread",
		"NtResumeThread",
		"NtTerminateThread",
		"NtQuerySystemInformation",
		"NtQueryInformationProcess",
		"NtCreateSection",
		"NtMapViewOfSection",
		"NtUnmapViewOfSection",
		"NtClose",
		"NtDuplicateObject",
		"NtQueryObject",
		"NtCreateFile",
		"NtReadFile",
		"NtWriteFile",
		"NtDeleteFile",
		"NtQueryDirectoryFile",
		"NtQueryInformationFile",
		"NtSetInformationFile",
		"NtCreateKey",
		"NtOpenKey",
		"NtDeleteKey",
		"NtSetValueKey",
		"NtQueryValueKey",
		"NtDeleteValueKey",
		"NtOpenProcessToken",
		"NtOpenThreadToken",
		"NtQueryInformationToken",
		"NtSetInformationToken",
		"NtAdjustPrivilegesToken",
		"NtSetSystemInformation",
		"NtQuerySystemTime",	
		"NtSetSystemTime",
		"NtCreateEvent",
		"NtOpenEvent",
		"NtSetEvent",
		"NtResetEvent",
		"NtWaitForSingleObject",
		"NtWaitForMultipleObjects",
	}
	
	for _, funcName := range commonFunctions {
		functionHash := obf.GetHash(funcName)
		// Use the hook-aware resolution which also caches clean stubs
		GetSyscallNumberWithHookHandling(functionHash)
	}
	
	return nil
}

