// Package syscallresolve provides functionality to resolve Windows syscall numbers.
package syscallresolve

import (
	"fmt"
	"time"
	"unsafe"
	
	"github.com/Binject/debug/pe"
	"github.com/carved4/go-direct-syscall/pkg/obf"
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
		fmt.Printf("Failed to get PEB address via assembly\n")
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
		
		fmt.Printf("PEB validation failed (retry %d/%d), waiting...\n", i+1, maxRetries)
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
			fmt.Printf("Failed to get PEB, retrying (%d/%d)...\n", i+1, maxRetries)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		if peb.Ldr == nil {
			fmt.Printf("PEB.Ldr is nil, retrying (%d/%d)...\n", i+1, maxRetries)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		// Get the head of the InLoadOrderModuleList
		entry := &peb.Ldr.InLoadOrderModuleList
		currentEntry := entry.Flink
	
		// Ensure the linked list is valid
		if currentEntry == nil {
			fmt.Printf("Module list is invalid (nil), retrying (%d/%d)...\n", i+1, maxRetries)
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
		fmt.Printf("Invalid DOS signature\n")
		return 0
	}
	
	// Get the offset to the PE header
	peOffset := *(*uint32)(unsafe.Pointer(moduleBase + 60))
	if peOffset >= 1024 {
		fmt.Printf("PE offset too large: %d\n", peOffset)
		return 0
	}
	
	// Read the PE header to get the SizeOfImage
	peHeader := (*[1024]byte)(unsafe.Pointer(moduleBase + uintptr(peOffset)))
	if peHeader[0] != 'P' || peHeader[1] != 'E' {
		fmt.Printf("Invalid PE signature\n")
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
		fmt.Printf("Failed to parse PE file: %v\n", err)
		return 0
	}
	defer file.Close()

	// Get the exports
	exports, err := file.Exports()
	if err != nil {
		fmt.Printf("Failed to get exports: %v\n", err)
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
		fmt.Printf("Failed to get ntdll.dll base address, retrying (%d/%d)...\n", i+1, maxRetries)
		time.Sleep(100 * time.Millisecond)
	}
	
	if ntdllBase == 0 {
		fmt.Printf("Failed to get ntdll.dll base address after %d retries\n", maxRetries)
		return 0
	}
	
	// Get the address of the syscall function using PE parsing (no GetProcAddress)
	var funcAddr uintptr
	
	for i := 0; i < maxRetries; i++ {
		funcAddr = GetFunctionAddress(ntdllBase, functionHash)
		if funcAddr != 0 {
			break
		}
		fmt.Printf("Failed to get function address, retrying (%d/%d)...\n", i+1, maxRetries)
		time.Sleep(100 * time.Millisecond)
	}
	
	if funcAddr == 0 {
		fmt.Printf("Failed to get function address for hash: 0x%X after %d retries\n", functionHash, maxRetries)
		return 0
	}
	

	// The syscall number is at offset 4 in the syscall stub for x64
	// The typical pattern is:
	// 0:  4c 8b d1             mov    r10,rcx
	// 3:  b8 XX XX 00 00       mov    eax,0xXXXX  <-- syscall number is here
	// 8:  f6 04 25 08 03 fe 7f test   byte ptr [0x7ffe0308],0x1
	// f:  75 03                jne    14
	// 11: 0f 05                syscall
	// 13: c3                   ret
	syscallNumber := *(*uint16)(unsafe.Pointer(funcAddr + 4))
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
		fmt.Printf("Failed to get ntdll.dll base address, retrying (%d/%d)...\n", i+1, maxRetries)
		time.Sleep(100 * time.Millisecond)
	}
	
	if ntdllBase == 0 {
		fmt.Printf("Failed to get ntdll.dll base address after %d retries\n", maxRetries)
		return 0, 0
	}

	// Get the address of the syscall function using PE parsing (no GetProcAddress)
	var funcAddr uintptr
	
	for i := 0; i < maxRetries; i++ {
		funcAddr = GetFunctionAddress(ntdllBase, functionHash)
		if funcAddr != 0 {
			break
		}
		fmt.Printf("Failed to get function address, retrying (%d/%d)...\n", i+1, maxRetries)
		time.Sleep(100 * time.Millisecond)
	}
	
	if funcAddr == 0 {
		fmt.Printf("Failed to get function address for hash: 0x%X after %d retries\n", functionHash, maxRetries)
		return 0, 0
	}

	// The syscall number is at offset 4 in the syscall stub
	syscallNumber := *(*uint16)(unsafe.Pointer(funcAddr + 4))
	
	// The syscall instruction is at offset 0x12 for x64
	syscallInstructionAddr := funcAddr + 0x12
	
	return syscallNumber, syscallInstructionAddr
}

// Helper function to dump memory for debugging
func DumpMemory(addr uintptr, size int) {
	data := make([]byte, size)
	for i := 0; i < size; i++ {
		data[i] = *(*byte)(unsafe.Pointer(addr + uintptr(i)))
	}
	
	fmt.Printf("Memory dump at %X (%d bytes):\n", addr, size)
	for i := 0; i < size; i += 16 {
		end := i + 16
		if end > size {
			end = size
		}
		
		// Print hex values
		fmt.Printf("%04X: ", i)
		for j := i; j < end; j++ {
			fmt.Printf("%02X ", data[j])
		}
		
		// Pad with spaces if needed
		for j := end; j < i+16; j++ {
			fmt.Printf("   ")
		}
		
		// Print ASCII representation
		fmt.Printf(" | ")
		for j := i; j < end; j++ {
			if data[j] >= 32 && data[j] <= 126 {
				fmt.Printf("%c", data[j])
			} else {
				fmt.Printf(".")
			}
		}
		fmt.Println()
	}
}
