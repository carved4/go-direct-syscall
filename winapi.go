// Package winapi provides direct Windows API syscalls using assembly and PE parsing
package winapi

import (
	"fmt"
	"time"
	"unsafe"
	
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