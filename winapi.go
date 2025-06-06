// Package winapi provides direct Windows API syscalls using assembly and PE parsing
package winapi

import (
	"fmt"
	"time"
	"unsafe"
	
	"github.com/Binject/debug/pe"
	"github.com/carved4/go-direct-syscall/pkg/obf"
	"github.com/carved4/go-direct-syscall/pkg/syscall"
	"github.com/carved4/go-direct-syscall/pkg/syscallresolve"
)

// DirectSyscall executes a direct syscall by function name
// This is the main function library users should use
func DirectSyscall(functionName string, args ...uintptr) (uintptr, error) {
	functionHash := obf.GetHash(functionName)
	return syscall.HashSyscall(functionHash, args...)
}

// DirectSyscallByHash executes a direct syscall by function name hash
// Useful for obfuscation when you want to pre-compute hashes
func DirectSyscallByHash(functionHash uint32, args ...uintptr) (uintptr, error) {
	return syscall.HashSyscall(functionHash, args...)
}

// GetSyscallNumber returns the syscall number for a given function name
// Useful for debugging or when you need the raw syscall number
func GetSyscallNumber(functionName string) uint16 {
	functionHash := obf.GetHash(functionName)
	return syscallresolve.GetSyscallNumber(functionHash)
}

// GetFunctionHash returns the hash for a function name
// Useful for pre-computing hashes for obfuscation
func GetFunctionHash(functionName string) uint32 {
	return obf.GetHash(functionName)
}

// Common Windows API functions with proper type safety

// NtAllocateVirtualMemory allocates memory in a process
func NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType, protect uintptr) (uintptr, error) {
	return DirectSyscall("NtAllocateVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		zeroBits,
		uintptr(unsafe.Pointer(regionSize)),
		allocationType,
		protect)
}

// NtWriteVirtualMemory writes to memory in a process
func NtWriteVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer unsafe.Pointer, size uintptr, bytesWritten *uintptr) (uintptr, error) {
	fmt.Printf("NtWriteVirtualMemory debug:\n")
	
	// Initialize bytesWritten to 0 before the syscall
	if bytesWritten != nil {
		*bytesWritten = 0
	}
	
	// Create a local bytesWritten if none was provided
	var localBytesWritten uintptr
	if bytesWritten == nil {
		bytesWritten = &localBytesWritten
	}
	
	// Maximum number of retries
	const maxRetries = 3
	var result uintptr
	var err error
	
	// Add a small delay before syscall to ensure everything is properly set up
	time.Sleep(100 * time.Millisecond)
	
	// Try a few times with increasing delays if needed
	for i := 0; i < maxRetries; i++ {
		// Make the syscall
		result, err = DirectSyscall("NtWriteVirtualMemory",
			processHandle,
			baseAddress,
			uintptr(buffer),
			size,
			uintptr(unsafe.Pointer(bytesWritten)))
		
		fmt.Printf("  Attempt %d - Result status: 0x%X\n", i+1, result)
		fmt.Printf("  Attempt %d - Bytes written: %d\n", i+1, *bytesWritten)
		
		// Check if bytes were written
		if *bytesWritten > 0 {
			break
		}
		
		// If no bytes written and not the last attempt, wait and retry
		if i < maxRetries-1 {
			waitTime := time.Duration(100*(i+1)) * time.Millisecond
			fmt.Printf("  No bytes written, retrying in %v...\n", waitTime)
			time.Sleep(waitTime)
		}
	}
	
	return result, err
}

// NtReadVirtualMemory reads from memory in a process
func NtReadVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer unsafe.Pointer, size uintptr, bytesRead *uintptr) (uintptr, error) {
	return DirectSyscall("NtReadVirtualMemory",
		processHandle,
		baseAddress,
		uintptr(buffer),
		size,
		uintptr(unsafe.Pointer(bytesRead)))
}

// NtProtectVirtualMemory changes memory protection
func NtProtectVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, newProtect uintptr, oldProtect *uintptr) (uintptr, error) {
	return DirectSyscall("NtProtectVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		newProtect,
		uintptr(unsafe.Pointer(oldProtect)))
}

// NtCreateThreadEx creates a thread in a process
func NtCreateThreadEx(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, processHandle uintptr, startAddress uintptr, arg uintptr, createFlags uintptr, zeroBits uintptr, stackSize uintptr, maximumStackSize uintptr, attributeList uintptr) (uintptr, error) {
	return DirectSyscall("NtCreateThreadEx",
		uintptr(unsafe.Pointer(threadHandle)),
		desiredAccess,
		objectAttributes,
		processHandle,
		startAddress,
		arg,
		createFlags,
		zeroBits,
		stackSize,
		maximumStackSize,
		attributeList)
}

// NtOpenProcess opens a handle to a process
func NtOpenProcess(processHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, clientId uintptr) (uintptr, error) {
	return DirectSyscall("NtOpenProcess",
		uintptr(unsafe.Pointer(processHandle)),
		desiredAccess,
		objectAttributes,
		clientId)
}

// NtClose closes a handle
func NtClose(handle uintptr) (uintptr, error) {
	return DirectSyscall("NtClose", handle)
}

// NtQuerySystemInformation queries system information
func NtQuerySystemInformation(systemInformationClass uintptr, systemInformation unsafe.Pointer, systemInformationLength uintptr, returnLength *uintptr) (uintptr, error) {
	return DirectSyscall("NtQuerySystemInformation",
		systemInformationClass,
		uintptr(systemInformation),
		systemInformationLength,
		uintptr(unsafe.Pointer(returnLength)))
}

// NtQueryInformationProcess queries process information
func NtQueryInformationProcess(processHandle uintptr, processInformationClass uintptr, processInformation unsafe.Pointer, processInformationLength uintptr, returnLength *uintptr) (uintptr, error) {
	return DirectSyscall("NtQueryInformationProcess",
		processHandle,
		processInformationClass,
		uintptr(processInformation),
		processInformationLength,
		uintptr(unsafe.Pointer(returnLength)))
}

// NtCreateFile creates or opens a file
func NtCreateFile(fileHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, ioStatusBlock uintptr, allocationSize *uint64, fileAttributes uintptr, shareAccess uintptr, createDisposition uintptr, createOptions uintptr, eaBuffer unsafe.Pointer, eaLength uintptr) (uintptr, error) {
	return DirectSyscall("NtCreateFile",
		uintptr(unsafe.Pointer(fileHandle)),
		desiredAccess,
		objectAttributes,
		ioStatusBlock,
		uintptr(unsafe.Pointer(allocationSize)),
		fileAttributes,
		shareAccess,
		createDisposition,
		createOptions,
		uintptr(eaBuffer),
		eaLength)
}

// NtWriteFile writes to a file
func NtWriteFile(fileHandle uintptr, event uintptr, apcRoutine uintptr, apcContext uintptr, ioStatusBlock uintptr, buffer unsafe.Pointer, length uintptr, byteOffset *uint64, key *uintptr) (uintptr, error) {
	return DirectSyscall("NtWriteFile",
		fileHandle,
		event,
		apcRoutine,
		apcContext,
		ioStatusBlock,
		uintptr(buffer),
		length,
		uintptr(unsafe.Pointer(byteOffset)),
		uintptr(unsafe.Pointer(key)))
}

// NtReadFile reads from a file
func NtReadFile(fileHandle uintptr, event uintptr, apcRoutine uintptr, apcContext uintptr, ioStatusBlock uintptr, buffer unsafe.Pointer, length uintptr, byteOffset *uint64, key *uintptr) (uintptr, error) {
	return DirectSyscall("NtReadFile",
		fileHandle,
		event,
		apcRoutine,
		apcContext,
		ioStatusBlock,
		uintptr(buffer),
		length,
		uintptr(unsafe.Pointer(byteOffset)),
		uintptr(unsafe.Pointer(key)))
}

// SyscallInfo holds information about a single syscall
type SyscallInfo struct {
	Name          string
	Hash          uint32
	SyscallNumber uint16
	Address       uintptr
}

// DumpAllSyscalls enumerates all syscall functions from ntdll.dll and returns their information
// This function uses the same logic as the existing pkg modules to discover and resolve syscalls
func DumpAllSyscalls() ([]SyscallInfo, error) {
	fmt.Printf("Starting syscall enumeration...\n")
	
	// Get the base address of ntdll.dll using the same logic as GetSyscallNumber
	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllBase := syscallresolve.GetModuleBase(ntdllHash)
	if ntdllBase == 0 {
		return nil, fmt.Errorf("failed to get ntdll.dll base address")
	}
	
	fmt.Printf("Found ntdll.dll at: 0x%X\n", ntdllBase)
	
	// Parse the PE file to get all exports (similar to GetFunctionAddress logic)
	// Read the PE header to get the actual size of the image
	dosHeader := (*[64]byte)(unsafe.Pointer(ntdllBase))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return nil, fmt.Errorf("invalid DOS signature")
	}
	
	// Get the offset to the PE header
	peOffset := *(*uint32)(unsafe.Pointer(ntdllBase + 60))
	if peOffset >= 1024 {
		return nil, fmt.Errorf("PE offset too large: %d", peOffset)
	}
	
	// Read the PE header to get the SizeOfImage
	peHeader := (*[1024]byte)(unsafe.Pointer(ntdllBase + uintptr(peOffset)))
	if peHeader[0] != 'P' || peHeader[1] != 'E' {
		return nil, fmt.Errorf("invalid PE signature")
	}
	
	// SizeOfImage is at offset 56 from the start of the OptionalHeader
	// OptionalHeader starts at offset 24 from PE signature
	sizeOfImage := *(*uint32)(unsafe.Pointer(ntdllBase + uintptr(peOffset) + 24 + 56))
	
	fmt.Printf("PE SizeOfImage: %d bytes\n", sizeOfImage)
	
	// Create a memory reader for the PE file with the correct size
	dataSlice := unsafe.Slice((*byte)(unsafe.Pointer(ntdllBase)), sizeOfImage)
	
	// Parse the PE file from memory using the same memoryReaderAt approach
	memReader := &memoryReaderAt{data: dataSlice}
	
	// Use the debug/pe package to parse the file
	file, err := pe.NewFileFromMemory(memReader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE file: %v", err)
	}
	defer file.Close()
	
	// Get all exports
	exports, err := file.Exports()
	if err != nil {
		return nil, fmt.Errorf("failed to get exports: %v", err)
	}
	
	fmt.Printf("Found %d exports in ntdll.dll\n", len(exports))
	
	var syscalls []SyscallInfo
	
	// Filter for syscall functions (those that start with "Nt" or "Zw")
	for _, export := range exports {
		if export.Name == "" {
			continue
		}
		
		// Check if this is a syscall function (starts with Nt or Zw)
		if !(len(export.Name) > 2 && (export.Name[:2] == "Nt" || export.Name[:2] == "Zw")) {
			continue
		}
		
		// Get function address
		funcAddr := ntdllBase + uintptr(export.VirtualAddress)
		
		// Calculate hash using the same obfuscation logic
		funcHash := obf.GetHash(export.Name)
		
		// Try to extract syscall number
		// The syscall number is at offset 4 in the syscall stub for x64
		// The typical pattern is:
		// 0:  4c 8b d1             mov    r10,rcx
		// 3:  b8 XX XX 00 00       mov    eax,0xXXXX  <-- syscall number is here
		// We need to check if this is actually a syscall stub
		
		var syscallNumber uint16
		
		// Check if the function starts with the expected syscall stub pattern
		if funcAddr != 0 {
			// Read first few bytes to check if it's a syscall stub
			firstBytes := make([]byte, 16)
			for i := 0; i < 16; i++ {
				firstBytes[i] = *(*byte)(unsafe.Pointer(funcAddr + uintptr(i)))
			}
			
			// Check for typical syscall stub pattern: 4c 8b d1 b8 (mov r10,rcx; mov eax,XXXX)
			if len(firstBytes) >= 8 && firstBytes[0] == 0x4c && firstBytes[1] == 0x8b && 
			   firstBytes[2] == 0xd1 && firstBytes[3] == 0xb8 {
				// Extract syscall number (little endian uint16 at offset 4)
				syscallNumber = *(*uint16)(unsafe.Pointer(funcAddr + 4))
			}
		}
		
		// Only include functions that have valid syscall numbers
		if syscallNumber > 0 {
			syscallInfo := SyscallInfo{
				Name:          export.Name,
				Hash:          funcHash,
				SyscallNumber: syscallNumber,
				Address:       funcAddr,
			}
			syscalls = append(syscalls, syscallInfo)
		}
	}
	
	fmt.Printf("Found %d syscall functions\n", len(syscalls))
	
	return syscalls, nil
}

// memoryReaderAt implements io.ReaderAt for in-memory data (copied from syscallresolve logic)
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