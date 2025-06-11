// Package syscallresolve provides functionality to resolve Windows syscall numbers.
package syscallresolve

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"
	
	"github.com/Binject/debug/pe"
	"github.com/carved4/go-direct-syscall/pkg/debug"
	"github.com/carved4/go-direct-syscall/pkg/obf"
)

/*
#cgo LDFLAGS: -L../../ -ldo_syscall -ldo_call
extern long long do_syscall(int ssn, int nargs, 
    long long a0, long long a1, long long a2, long long a3, long long a4, long long a5,
    long long a6, long long a7, long long a8, long long a9, long long a10, long long a11);
extern long long do_call(void* func_addr, int nargs, 
    long long a0, long long a1, long long a2, long long a3, long long a4, long long a5,
    long long a6, long long a7, long long a8, long long a9, long long a10, long long a11);

// This simulates what the assembly was doing using a C function
// We're adding this to replace the assembly file with pure Go+C
#include <stdint.h>

#ifdef _WIN64
// On 64-bit, the PEB is at GS:[0x60]
uintptr_t getPEB() {
    uintptr_t peb;
    __asm__ ("movq %%gs:0x60, %0" : "=r" (peb));
    return peb;
}
#else
// On 32-bit, the PEB is at FS:[0x30]
uintptr_t getPEB() {
    uintptr_t peb;
    __asm__ ("movl %%fs:0x30, %0" : "=r" (peb));
    return peb;
}
#endif
*/
import "C"

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

// GetPEB returns the Process Environment Block address
//
//go:nosplit
//go:noinline
func GetPEB() uintptr {
	// Use CGO to access the PEB, simulating what the assembly was doing
	// This is the most reliable cross-platform way to access thread-local storage
	return uintptr(C.getPEB())
}

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
func GetSyscallNumberLegacy(functionHash uint32) uint16 {
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

	// Pattern 3: Hooked syscall detection (look for JMP instruction)
	// If we find a JMP at the beginning, the function might be hooked
	if funcBytes[0] == 0xe9 || funcBytes[0] == 0xeb || funcBytes[0] == 0xff {
		debug.Printfln("SYSCALLRESOLVE", "Warning: Function at 0x%X appears to be hooked (starts with JMP: 0x%02X)\n", 
			funcAddr, funcBytes[0])
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

// GetSyscallNumber now prioritizes using the fresh ntdll copy
// This is the main entry point for all syscall number resolution
func GetSyscallNumber(functionHash uint32) uint16 {
	// Try cache first
	if cached := getSyscallFromCache(functionHash); cached != 0 {
		return cached
	}
	
	// Always prefer fresh ntdll copy
	syscallNum := GetSyscallNumberFromFreshNtdll(functionHash)
	if syscallNum != 0 {
		return syscallNum
	}
	
	// Fall back to the original method using PEB only if fresh ntdll failed
	debug.Printfln("SYSCALLRESOLVE", "Fresh ntdll method failed, falling back to PEB method for hash: 0x%X\n", functionHash)
	return GetSyscallNumberLegacy(functionHash)
}

// PrewarmFreshNtdll loads the fresh ntdll copy on startup
// Call this function early in your application to ensure the fresh copy is ready
func PrewarmFreshNtdll() error {
	_, err := LoadFreshNtdllCopy()
	if err != nil {
		debug.Printfln("SYSCALLRESOLVE", "Failed to prewarm fresh ntdll: %v\n", err)
		return err
	}
	
	// Also prewarm common syscalls
	debug.Printfln("SYSCALLRESOLVE", "Prewarming common syscalls from fresh ntdll...\n")
	PrewarmSyscallCache()
	
	debug.Printfln("SYSCALLRESOLVE", "Fresh ntdll prewarmed successfully\n")
	return nil
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
	
	// Ensure fresh ntdll is loaded first
	_, err := LoadFreshNtdllCopy()
	if err != nil {
		debug.Printfln("SYSCALLRESOLVE", "Warning: Failed to load fresh ntdll, falling back to legacy method for prewarming\n")
	}
	
	// Now populate the cache
	for _, funcName := range commonFunctions {
		functionHash := obf.GetHash(funcName)
		syscallNum := GetSyscallNumber(functionHash)
		if syscallNum != 0 {
			debug.Printfln("SYSCALLRESOLVE", "Prewarmed syscall for %s: %d\n", funcName, syscallNum)
		}
	}
	
	return nil
}

// DoSyscallExternal calls the external assembly function using cgo
func DoSyscallExternal(ssn uint16, nargs uint32, args ...uintptr) uintptr {
	// Lock the OS thread for syscall safety
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	
	// Pad args to ensure we have exactly 12 arguments  
	paddedArgs := make([]uintptr, 12)
	copy(paddedArgs, args)
	
	result := C.do_syscall(
		C.int(ssn),
		C.int(nargs),
		C.longlong(paddedArgs[0]),
		C.longlong(paddedArgs[1]),
		C.longlong(paddedArgs[2]),
		C.longlong(paddedArgs[3]),
		C.longlong(paddedArgs[4]),
		C.longlong(paddedArgs[5]),
		C.longlong(paddedArgs[6]),
		C.longlong(paddedArgs[7]),
		C.longlong(paddedArgs[8]),
		C.longlong(paddedArgs[9]),
		C.longlong(paddedArgs[10]),
		C.longlong(paddedArgs[11]))
	
	return uintptr(result)
}

// ExternalSyscall is a wrapper that uses the external assembly implementation
func ExternalSyscall(syscallNumber uint16, args ...uintptr) (uintptr, error) {
	result := DoSyscallExternal(syscallNumber, uint32(len(args)), args...)
	return result, nil
}

// HashSyscall executes a direct syscall using a function name hash
// This simplifies API calls by automatically resolving the syscall number
func HashSyscall(functionHash uint32, args ...uintptr) (uintptr, error) {
	syscallNum := GetSyscallNumber(functionHash)
	return ExternalSyscall(syscallNum, args...)
}

// DirectCall calls a Windows API function directly by address
// This is different from DoSyscallExternal - it calls regular API functions, not syscalls
func DirectCall(funcAddr uintptr, args ...uintptr) (uintptr, error) {
	// Lock the OS thread for call safety
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	
	// Pad args to ensure we have exactly 12 arguments  
	paddedArgs := make([]uintptr, 12)
	copy(paddedArgs, args)
	
	result := C.do_call(
		unsafe.Pointer(funcAddr),
		C.int(len(args)),
		C.longlong(paddedArgs[0]),
		C.longlong(paddedArgs[1]),
		C.longlong(paddedArgs[2]),
		C.longlong(paddedArgs[3]),
		C.longlong(paddedArgs[4]),
		C.longlong(paddedArgs[5]),
		C.longlong(paddedArgs[6]),
		C.longlong(paddedArgs[7]),
		C.longlong(paddedArgs[8]),
		C.longlong(paddedArgs[9]),
		C.longlong(paddedArgs[10]),
		C.longlong(paddedArgs[11]))
	
	return uintptr(result), nil
}

// FreshNtdllBase holds the base address of the clean ntdll.dll mapping
var FreshNtdllBase uintptr
var freshNtdllOnce sync.Once

// Constants needed for NT API calls
const (
	SECTION_MAP_READ     = 0x0004
	PAGE_READONLY        = 0x02
	SEC_IMAGE            = 0x1000000
	FILE_SHARE_READ      = 0x00000001
	FILE_SHARE_WRITE     = 0x00000002
	FILE_SHARE_DELETE    = 0x00000004
	GENERIC_READ         = 0x80000000
	FILE_ATTRIBUTE_NORMAL = 0x00000080
	CREATE_ALWAYS        = 2
	OPEN_EXISTING        = 3
	OBJ_CASE_INSENSITIVE = 0x00000040
	ViewShare            = 1
	STATUS_SUCCESS       = 0
)

// UNICODE_STRING Windows struct for object names
type NT_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// OBJECT_ATTRIBUTES Windows struct for object handles
type NT_OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *NT_UNICODE_STRING
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// IO_STATUS_BLOCK Windows struct for I/O operations
type NT_IO_STATUS_BLOCK struct {
	Status      uintptr
	Information uintptr
}

// LoadFreshNtdllCopy maps a fresh copy of ntdll.dll from disk to avoid hooks
func LoadFreshNtdllCopy() (uintptr, error) {
	var err error
	
	freshNtdllOnce.Do(func() {
		// Use the absolute system path to ntdll.dll to ensure it works regardless of working directory
		// %SystemRoot%\System32\ntdll.dll is the standard location
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = "C:\\Windows" // Fallback if SystemRoot env var is not available
		}
		
		systemDir := systemRoot + "\\System32\\ntdll.dll"
		debug.Printfln("SYSCALLRESOLVE", "Using ntdll.dll from: %s\n", systemDir)
		
		// Initialize the syscall numbers we need
		ntCreateFileHash := obf.GetHash("NtCreateFile")
		ntCreateSectionHash := obf.GetHash("NtCreateSection") 
		ntMapViewOfSectionHash := obf.GetHash("NtMapViewOfSection")
		ntCloseHash := obf.GetHash("NtClose")
		
		// Get syscall numbers directly
		ntCreateFileSSN := GetSyscallNumberLegacy(ntCreateFileHash)
		ntCreateSectionSSN := GetSyscallNumberLegacy(ntCreateSectionHash)
		ntMapViewOfSectionSSN := GetSyscallNumberLegacy(ntMapViewOfSectionHash) 
		ntCloseSSN := GetSyscallNumberLegacy(ntCloseHash)
		
		// Convert the path to a UNICODE_STRING
		ntPathStr := StringToUTF16(systemDir)
		
		// Calculate UTF-16 string length properly (without direct indexing)
		// More precisely calculate the length by measuring the actual UTF-16 encoded string
		// We need to do this without indexing the *uint16 directly
		actualLen := uint16(0)
		ptr := unsafe.Pointer(ntPathStr)
		for {
			// Read the current UTF-16 character
			if *(*uint16)(ptr) == 0 {
				break // Found null terminator
			}
			actualLen += 2 // Count 2 bytes for each UTF-16 character
			ptr = unsafe.Pointer(uintptr(ptr) + 2) // Move to next UTF-16 character
		}
		
		objectName := NT_UNICODE_STRING{
			Length:        actualLen,
			MaximumLength: actualLen + 2, // Add space for null terminator
			Buffer:        ntPathStr,
		}
		
		// Create OBJECT_ATTRIBUTES structure
		objAttr := NT_OBJECT_ATTRIBUTES{
			Length:                   uint32(unsafe.Sizeof(NT_OBJECT_ATTRIBUTES{})),
			RootDirectory:            0,
			ObjectName:               &objectName,
			Attributes:               OBJ_CASE_INSENSITIVE,
			SecurityDescriptor:       0,
			SecurityQualityOfService: 0,
		}
		
		// Initialize IO_STATUS_BLOCK
		var ioStatusBlock NT_IO_STATUS_BLOCK
		
		// Open the file
		var fileHandle uintptr
		status, _ := ExternalSyscall(ntCreateFileSSN,
			uintptr(unsafe.Pointer(&fileHandle)),
			GENERIC_READ,
			uintptr(unsafe.Pointer(&objAttr)),
			uintptr(unsafe.Pointer(&ioStatusBlock)),
			0, // AllocationSize
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			OPEN_EXISTING,
			0, // CreateOptions
			0, // EaBuffer
			0, // EaLength
		)
		
		if status != STATUS_SUCCESS {
			debug.Printfln("SYSCALLRESOLVE", "NtCreateFile failed with status: 0x%X\n", status)
			err = fmt.Errorf("failed to open ntdll.dll: 0x%X", status)
			return
		}
		defer ExternalSyscall(ntCloseSSN, fileHandle)
		
		// Create a section for the file
		var sectionHandle uintptr
		status, _ = ExternalSyscall(ntCreateSectionSSN,
			uintptr(unsafe.Pointer(&sectionHandle)),
			SECTION_MAP_READ,
			0, // ObjectAttributes
			0, // MaximumSize
			PAGE_READONLY,
			SEC_IMAGE,
			fileHandle,
		)
		
		if status != STATUS_SUCCESS {
			debug.Printfln("SYSCALLRESOLVE", "NtCreateSection failed with status: 0x%X\n", status)
			err = fmt.Errorf("failed to create section for ntdll.dll: 0x%X", status)
			return
		}
		defer ExternalSyscall(ntCloseSSN, sectionHandle)
		
		// Map the section into memory
		var baseAddress uintptr
		var viewSize uintptr
		status, _ = ExternalSyscall(ntMapViewOfSectionSSN,
			sectionHandle,
			uintptr(0xFFFFFFFFFFFFFFFF), // Current process
			uintptr(unsafe.Pointer(&baseAddress)),
			0, // ZeroBits
			0, // CommitSize
			0, // SectionOffset
			uintptr(unsafe.Pointer(&viewSize)),
			ViewShare,
			0, // AllocationType
			PAGE_READONLY,
		)
		
		if status != STATUS_SUCCESS {
			debug.Printfln("SYSCALLRESOLVE", "NtMapViewOfSection failed with status: 0x%X\n", status)
			err = fmt.Errorf("failed to map view of ntdll.dll: 0x%X", status)
			return
		}
		
		// Store the base address
		FreshNtdllBase = baseAddress
		debug.Printfln("SYSCALLRESOLVE", "Mapped fresh ntdll.dll at: 0x%X, size: %d bytes\n", 
			baseAddress, viewSize)
	})
	
	if err != nil {
		return 0, err
	}
	
	return FreshNtdllBase, nil
}

// StringToUTF16 converts a Go string to a UTF16 string pointer
func StringToUTF16(s string) *uint16 {
	if s == "" {
		// Return pointer to null terminator for empty strings
		nullTerm := uint16(0)
		return &nullTerm
	}
	
	// Convert string to runes first (handles Unicode properly)
	runes := []rune(s)
	
	// Allocate buffer for UTF16 + null terminator
	utf16Slice := make([]uint16, 0, len(runes)+1)
	
	// Convert each rune to UTF16
	for _, r := range runes {
		if r < 0x10000 {
			// Basic Multilingual Plane - single UTF16 unit
			utf16Slice = append(utf16Slice, uint16(r))
		} else {
			// Supplementary plane - needs surrogate pair
			r -= 0x10000
			high := uint16((r>>10)&0x3FF) + 0xD800  // High surrogate
			low := uint16(r&0x3FF) + 0xDC00         // Low surrogate
			utf16Slice = append(utf16Slice, high, low)
		}
	}
	
	// Add null terminator
	utf16Slice = append(utf16Slice, 0)
	
	// Return pointer to first element
	return &utf16Slice[0]
}

// GetFunctionAddressFromFreshNtdll retrieves a function address from the fresh ntdll copy
func GetFunctionAddressFromFreshNtdll(functionHash uint32) uintptr {
	// Ensure fresh ntdll is loaded
	freshBase, err := LoadFreshNtdllCopy()
	if err != nil || freshBase == 0 {
		debug.Printfln("SYSCALLRESOLVE", "Failed to load fresh ntdll.dll: %v\n", err)
		return 0
	}
	
	// Read the PE header to get the size of the image
	dosHeader := (*[64]byte)(unsafe.Pointer(freshBase))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		debug.Printfln("SYSCALLRESOLVE", "Invalid DOS signature in fresh ntdll\n")
		return 0
	}
	
	// Get the offset to the PE header
	peOffset := *(*uint32)(unsafe.Pointer(freshBase + 60))
	if peOffset >= 1024 {
		debug.Printfln("SYSCALLRESOLVE", "PE offset too large in fresh ntdll: %d\n", peOffset)
		return 0
	}
	
	// Read the PE header to get the SizeOfImage
	peHeader := (*[1024]byte)(unsafe.Pointer(freshBase + uintptr(peOffset)))
	if peHeader[0] != 'P' || peHeader[1] != 'E' {
		debug.Printfln("SYSCALLRESOLVE", "Invalid PE signature in fresh ntdll\n")
		return 0
	}
	
	// SizeOfImage is at offset 56 from the start of the OptionalHeader
	// OptionalHeader starts at offset 24 from PE signature
	sizeOfImage := *(*uint32)(unsafe.Pointer(freshBase + uintptr(peOffset) + 24 + 56))
	
	// Create a memory reader for the PE file with the correct size
	dataSlice := unsafe.Slice((*byte)(unsafe.Pointer(freshBase)), sizeOfImage)
	
	// Parse the PE file from memory
	file, err := pe.NewFileFromMemory(&memoryReaderAt{data: dataSlice})
	if err != nil {
		debug.Printfln("SYSCALLRESOLVE", "Failed to parse fresh ntdll PE: %v\n", err)
		return 0
	}
	defer file.Close()

	// Get the exports
	exports, err := file.Exports()
	if err != nil {
		debug.Printfln("SYSCALLRESOLVE", "Failed to get exports from fresh ntdll: %v\n", err)
		return 0
	}

	// Search for the function by hash
	for _, export := range exports {
		if export.Name != "" {
			currentHash := obf.DBJ2HashStr(export.Name)
			if currentHash == functionHash {
				// Return the function address (module base + RVA)
				return freshBase + uintptr(export.VirtualAddress)
			}
		}
	}

	return 0
}

// GetSyscallNumberFromFreshNtdll extracts the syscall number from the fresh ntdll copy
func GetSyscallNumberFromFreshNtdll(functionHash uint32) uint16 {
	// Try cache first for performance
	if cached := getSyscallFromCache(functionHash); cached != 0 {
		return cached
	}
	
	// Get the function address in the fresh ntdll
	funcAddr := GetFunctionAddressFromFreshNtdll(functionHash)
	if funcAddr == 0 {
		debug.Printfln("SYSCALLRESOLVE", "Failed to find function in fresh ntdll for hash: 0x%X\n", functionHash)
		return 0
	}
	
	// Extract the syscall number with validation
	syscallNumber := extractSyscallNumberWithValidation(funcAddr, functionHash)
	
	// Cache the result if valid
	if syscallNumber != 0 {
		cacheSyscallNumber(functionHash, syscallNumber)
	}
	
	return syscallNumber
}
