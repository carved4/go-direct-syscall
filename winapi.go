// Package winapi provides direct Windows API syscalls using assembly and PE parsing
package winapi

import (
	"fmt"
	"os"
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

// DirectCall executes a direct call to any Windows API function by address
// This is different from DirectSyscall - it calls regular API functions, not syscalls
func DirectCall(functionAddr uintptr, args ...uintptr) (uintptr, error) {
	return syscall.DirectCall(functionAddr, args...)
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

// GetSyscallWithValidation provides enhanced syscall resolution with validation
// Returns the syscall number, validation status, and any errors
func GetSyscallWithValidation(functionName string) (uint16, bool, error) {
	functionHash := obf.GetHash(functionName)
	return syscallresolve.GetSyscallWithValidation(functionHash)
}

// PrewarmSyscallCache preloads common syscall numbers for better performance
// This should be called early in your application to improve syscall resolution speed
func PrewarmSyscallCache() error {
	return syscallresolve.PrewarmSyscallCache()
}

// GetSyscallCacheSize returns the number of cached syscall numbers
func GetSyscallCacheSize() int {
	return syscallresolve.GetSyscallCacheSize()
}

// GetSyscallCacheStats returns detailed cache statistics
func GetSyscallCacheStats() map[string]interface{} {
	return map[string]interface{}{
		"cache_size": syscallresolve.GetSyscallCacheSize(),
		"cache_enabled": true,
		"hash_algorithm": "DBJ2",
	}
}


// StringToUTF16 converts a Go string to a UTF16 string pointer
// This replaces syscall.UTF16PtrFromString to avoid standard library dependencies
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

// Additional Process Manipulation Functions

// NtTerminateProcess terminates a process
func NtTerminateProcess(processHandle uintptr, exitStatus uintptr) (uintptr, error) {
	return DirectSyscall("NtTerminateProcess",
		processHandle,
		exitStatus)
}

// NtSuspendProcess suspends all threads in a process
func NtSuspendProcess(processHandle uintptr) (uintptr, error) {
	return DirectSyscall("NtSuspendProcess", processHandle)
}

// NtResumeProcess resumes all threads in a process
func NtResumeProcess(processHandle uintptr) (uintptr, error) {
	return DirectSyscall("NtResumeProcess", processHandle)
}

// NtCreateProcess creates a new process
func NtCreateProcess(processHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, parentProcess uintptr, inheritObjectTable bool, sectionHandle uintptr, debugPort uintptr, exceptionPort uintptr) (uintptr, error) {
	inherit := uintptr(0)
	if inheritObjectTable {
		inherit = 1
	}
	return DirectSyscall("NtCreateProcess",
		uintptr(unsafe.Pointer(processHandle)),
		desiredAccess,
		objectAttributes,
		parentProcess,
		inherit,
		sectionHandle,
		debugPort,
		exceptionPort)
}

// Thread Management Functions

// NtCreateThread creates a thread in a process
func NtCreateThread(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, processHandle uintptr, startAddress uintptr, arg uintptr, createSuspended bool, zeroBits uintptr, stackSize uintptr, maximumStackSize uintptr, initialTeb uintptr) (uintptr, error) {
	flags := uintptr(0)
	if createSuspended {
		flags = 1
	}
	return DirectSyscall("NtCreateThread",
		uintptr(unsafe.Pointer(threadHandle)),
		desiredAccess,
		objectAttributes,
		processHandle,
		startAddress,
		arg,
		flags,
		zeroBits,
		stackSize,
		maximumStackSize,
		initialTeb)
}

// NtOpenThread opens a handle to a thread
func NtOpenThread(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, clientId uintptr) (uintptr, error) {
	return DirectSyscall("NtOpenThread",
		uintptr(unsafe.Pointer(threadHandle)),
		desiredAccess,
		objectAttributes,
		clientId)
}

// NtSuspendThread suspends a thread
func NtSuspendThread(threadHandle uintptr, previousSuspendCount *uintptr) (uintptr, error) {
	return DirectSyscall("NtSuspendThread",
		threadHandle,
		uintptr(unsafe.Pointer(previousSuspendCount)))
}

// NtResumeThread resumes a thread
func NtResumeThread(threadHandle uintptr, previousSuspendCount *uintptr) (uintptr, error) {
	return DirectSyscall("NtResumeThread",
		threadHandle,
		uintptr(unsafe.Pointer(previousSuspendCount)))
}

// NtTerminateThread terminates a thread
func NtTerminateThread(threadHandle uintptr, exitStatus uintptr) (uintptr, error) {
	return DirectSyscall("NtTerminateThread",
		threadHandle,
		exitStatus)
}

// Memory and Section Functions

// NtCreateSection creates a section object
func NtCreateSection(sectionHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, maximumSize *uint64, sectionPageProtection uintptr, allocationAttributes uintptr, fileHandle uintptr) (uintptr, error) {
	return DirectSyscall("NtCreateSection",
		uintptr(unsafe.Pointer(sectionHandle)),
		desiredAccess,
		objectAttributes,
		uintptr(unsafe.Pointer(maximumSize)),
		sectionPageProtection,
		allocationAttributes,
		fileHandle)
}

// NtMapViewOfSection maps a view of a section
func NtMapViewOfSection(sectionHandle uintptr, processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, commitSize uintptr, sectionOffset *uint64, viewSize *uintptr, inheritDisposition uintptr, allocationType uintptr, win32Protect uintptr) (uintptr, error) {
	return DirectSyscall("NtMapViewOfSection",
		sectionHandle,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		zeroBits,
		commitSize,
		uintptr(unsafe.Pointer(sectionOffset)),
		uintptr(unsafe.Pointer(viewSize)),
		inheritDisposition,
		allocationType,
		win32Protect)
}

// NtUnmapViewOfSection unmaps a view of a section
func NtUnmapViewOfSection(processHandle uintptr, baseAddress uintptr) (uintptr, error) {
	return DirectSyscall("NtUnmapViewOfSection",
		processHandle,
		baseAddress)
}

// NtFreeVirtualMemory frees virtual memory
func NtFreeVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, freeType uintptr) (uintptr, error) {
	return DirectSyscall("NtFreeVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		freeType)
}

// NtQueryVirtualMemory queries virtual memory information
func NtQueryVirtualMemory(processHandle uintptr, baseAddress uintptr, memoryInformationClass uintptr, memoryInformation unsafe.Pointer, memoryInformationLength uintptr, returnLength *uintptr) (uintptr, error) {
	return DirectSyscall("NtQueryVirtualMemory",
		processHandle,
		baseAddress,
		memoryInformationClass,
		uintptr(memoryInformation),
		memoryInformationLength,
		uintptr(unsafe.Pointer(returnLength)))
}

// Registry Functions

// NtCreateKey creates or opens a registry key
func NtCreateKey(keyHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, titleIndex uintptr, class uintptr, createOptions uintptr, disposition *uintptr) (uintptr, error) {
	return DirectSyscall("NtCreateKey",
		uintptr(unsafe.Pointer(keyHandle)),
		desiredAccess,
		objectAttributes,
		titleIndex,
		class,
		createOptions,
		uintptr(unsafe.Pointer(disposition)))
}

// NtOpenKey opens a registry key
func NtOpenKey(keyHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr) (uintptr, error) {
	return DirectSyscall("NtOpenKey",
		uintptr(unsafe.Pointer(keyHandle)),
		desiredAccess,
		objectAttributes)
}

// NtDeleteKey deletes a registry key
func NtDeleteKey(keyHandle uintptr) (uintptr, error) {
	return DirectSyscall("NtDeleteKey", keyHandle)
}

// NtSetValueKey sets a registry value
func NtSetValueKey(keyHandle uintptr, valueName uintptr, titleIndex uintptr, dataType uintptr, data unsafe.Pointer, dataSize uintptr) (uintptr, error) {
	return DirectSyscall("NtSetValueKey",
		keyHandle,
		valueName,
		titleIndex,
		dataType,
		uintptr(data),
		dataSize)
}

// NtQueryValueKey queries a registry value
func NtQueryValueKey(keyHandle uintptr, valueName uintptr, keyValueInformationClass uintptr, keyValueInformation unsafe.Pointer, length uintptr, resultLength *uintptr) (uintptr, error) {
	return DirectSyscall("NtQueryValueKey",
		keyHandle,
		valueName,
		keyValueInformationClass,
		uintptr(keyValueInformation),
		length,
		uintptr(unsafe.Pointer(resultLength)))
}

// NtDeleteValueKey deletes a registry value
func NtDeleteValueKey(keyHandle uintptr, valueName uintptr) (uintptr, error) {
	return DirectSyscall("NtDeleteValueKey",
		keyHandle,
		valueName)
}

// Security and Token Functions

// NtOpenProcessToken opens a process token
func NtOpenProcessToken(processHandle uintptr, desiredAccess uintptr, tokenHandle *uintptr) (uintptr, error) {
	return DirectSyscall("NtOpenProcessToken",
		processHandle,
		desiredAccess,
		uintptr(unsafe.Pointer(tokenHandle)))
}

// NtOpenThreadToken opens a thread token
func NtOpenThreadToken(threadHandle uintptr, desiredAccess uintptr, openAsSelf bool, tokenHandle *uintptr) (uintptr, error) {
	openSelf := uintptr(0)
	if openAsSelf {
		openSelf = 1
	}
	return DirectSyscall("NtOpenThreadToken",
		threadHandle,
		desiredAccess,
		openSelf,
		uintptr(unsafe.Pointer(tokenHandle)))
}

// NtQueryInformationToken queries token information
func NtQueryInformationToken(tokenHandle uintptr, tokenInformationClass uintptr, tokenInformation unsafe.Pointer, tokenInformationLength uintptr, returnLength *uintptr) (uintptr, error) {
	return DirectSyscall("NtQueryInformationToken",
		tokenHandle,
		tokenInformationClass,
		uintptr(tokenInformation),
		tokenInformationLength,
		uintptr(unsafe.Pointer(returnLength)))
}

// NtSetInformationToken sets token information
func NtSetInformationToken(tokenHandle uintptr, tokenInformationClass uintptr, tokenInformation unsafe.Pointer, tokenInformationLength uintptr) (uintptr, error) {
	return DirectSyscall("NtSetInformationToken",
		tokenHandle,
		tokenInformationClass,
		uintptr(tokenInformation),
		tokenInformationLength)
}

// NtAdjustPrivilegesToken adjusts token privileges
func NtAdjustPrivilegesToken(tokenHandle uintptr, disableAllPrivileges bool, newState unsafe.Pointer, bufferLength uintptr, previousState unsafe.Pointer, returnLength *uintptr) (uintptr, error) {
	disable := uintptr(0)
	if disableAllPrivileges {
		disable = 1
	}
	return DirectSyscall("NtAdjustPrivilegesToken",
		tokenHandle,
		disable,
		uintptr(newState),
		bufferLength,
		uintptr(previousState),
		uintptr(unsafe.Pointer(returnLength)))
}

// Object and Handle Functions

// NtDuplicateObject duplicates an object handle
func NtDuplicateObject(sourceProcessHandle uintptr, sourceHandle uintptr, targetProcessHandle uintptr, targetHandle *uintptr, desiredAccess uintptr, inheritHandle bool, options uintptr) (uintptr, error) {
	inherit := uintptr(0)
	if inheritHandle {
		inherit = 1
	}
	return DirectSyscall("NtDuplicateObject",
		sourceProcessHandle,
		sourceHandle,
		targetProcessHandle,
		uintptr(unsafe.Pointer(targetHandle)),
		desiredAccess,
		inherit,
		options)
}

// NtQueryObject queries object information
func NtQueryObject(handle uintptr, objectInformationClass uintptr, objectInformation unsafe.Pointer, objectInformationLength uintptr, returnLength *uintptr) (uintptr, error) {
	return DirectSyscall("NtQueryObject",
		handle,
		objectInformationClass,
		uintptr(objectInformation),
		objectInformationLength,
		uintptr(unsafe.Pointer(returnLength)))
}

// System Information and Control Functions

// NtSetSystemInformation sets system information
func NtSetSystemInformation(systemInformationClass uintptr, systemInformation unsafe.Pointer, systemInformationLength uintptr) (uintptr, error) {
	return DirectSyscall("NtSetSystemInformation",
		systemInformationClass,
		uintptr(systemInformation),
		systemInformationLength)
}

// NtQuerySystemTime queries system time
func NtQuerySystemTime(systemTime *uint64) (uintptr, error) {
	return DirectSyscall("NtQuerySystemTime",
		uintptr(unsafe.Pointer(systemTime)))
}

// NtSetSystemTime sets system time
func NtSetSystemTime(systemTime *uint64, previousTime *uint64) (uintptr, error) {
	return DirectSyscall("NtSetSystemTime",
		uintptr(unsafe.Pointer(systemTime)),
		uintptr(unsafe.Pointer(previousTime)))
}

// Event and Synchronization Functions

// NtCreateEvent creates an event object
func NtCreateEvent(eventHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, eventType uintptr, initialState bool) (uintptr, error) {
	state := uintptr(0)
	if initialState {
		state = 1
	}
	return DirectSyscall("NtCreateEvent",
		uintptr(unsafe.Pointer(eventHandle)),
		desiredAccess,
		objectAttributes,
		eventType,
		state)
}

// NtOpenEvent opens an event object
func NtOpenEvent(eventHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr) (uintptr, error) {
	return DirectSyscall("NtOpenEvent",
		uintptr(unsafe.Pointer(eventHandle)),
		desiredAccess,
		objectAttributes)
}

// NtSetEvent sets an event to signaled state
func NtSetEvent(eventHandle uintptr, previousState *uintptr) (uintptr, error) {
	return DirectSyscall("NtSetEvent",
		eventHandle,
		uintptr(unsafe.Pointer(previousState)))
}

// NtResetEvent resets an event to non-signaled state
func NtResetEvent(eventHandle uintptr, previousState *uintptr) (uintptr, error) {
	return DirectSyscall("NtResetEvent",
		eventHandle,
		uintptr(unsafe.Pointer(previousState)))
}

// NtWaitForSingleObject waits for a single object
func NtWaitForSingleObject(handle uintptr, alertable bool, timeout *uint64) (uintptr, error) {
	alert := uintptr(0)
	if alertable {
		alert = 1
	}
	return DirectSyscall("NtWaitForSingleObject",
		handle,
		alert,
		uintptr(unsafe.Pointer(timeout)))
}

// NtWaitForMultipleObjects waits for multiple objects
func NtWaitForMultipleObjects(count uintptr, handles *uintptr, waitType uintptr, alertable bool, timeout *uint64) (uintptr, error) {
	alert := uintptr(0)
	if alertable {
		alert = 1
	}
	return DirectSyscall("NtWaitForMultipleObjects",
		count,
		uintptr(unsafe.Pointer(handles)),
		waitType,
		alert,
		uintptr(unsafe.Pointer(timeout)))
}

// File System Functions

// NtDeleteFile deletes a file
func NtDeleteFile(objectAttributes uintptr) (uintptr, error) {
	return DirectSyscall("NtDeleteFile", objectAttributes)
}

// NtQueryDirectoryFile queries directory contents
func NtQueryDirectoryFile(fileHandle uintptr, event uintptr, apcRoutine uintptr, apcContext uintptr, ioStatusBlock uintptr, fileInformation unsafe.Pointer, length uintptr, fileInformationClass uintptr, returnSingleEntry bool, fileName uintptr, restartScan bool) (uintptr, error) {
	single := uintptr(0)
	if returnSingleEntry {
		single = 1
	}
	restart := uintptr(0)
	if restartScan {
		restart = 1
	}
	return DirectSyscall("NtQueryDirectoryFile",
		fileHandle,
		event,
		apcRoutine,
		apcContext,
		ioStatusBlock,
		uintptr(fileInformation),
		length,
		fileInformationClass,
		single,
		fileName,
		restart)
}

// NtQueryInformationFile queries file information
func NtQueryInformationFile(fileHandle uintptr, ioStatusBlock uintptr, fileInformation unsafe.Pointer, length uintptr, fileInformationClass uintptr) (uintptr, error) {
	return DirectSyscall("NtQueryInformationFile",
		fileHandle,
		ioStatusBlock,
		uintptr(fileInformation),
		length,
		fileInformationClass)
}

// NtSetInformationFile sets file information
func NtSetInformationFile(fileHandle uintptr, ioStatusBlock uintptr, fileInformation unsafe.Pointer, length uintptr, fileInformationClass uintptr) (uintptr, error) {
	return DirectSyscall("NtSetInformationFile",
		fileHandle,
		ioStatusBlock,
		uintptr(fileInformation),
		length,
		fileInformationClass)
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

// DumpAllSyscallsWithFiles enumerates all syscall functions and exports to both JSON and Go files
// This is the enhanced version that generates both JSON and Go syscall table files
func DumpAllSyscallsWithFiles() ([]SyscallInfo, error) {
	// Get the syscall information using the existing function
	syscalls, err := DumpAllSyscalls()
	if err != nil {
		return nil, err
	}

	// Generate Go syscall table file
	err = generateSyscallTableFile(syscalls)
	if err != nil {
		fmt.Printf("Warning: Failed to generate Go syscall table: %v\n", err)
	}

	return syscalls, nil
}

// generateSyscallTableFile creates a Go file with syscall table map
func generateSyscallTableFile(syscalls []SyscallInfo) error {
	// Create a map to store unique syscall entries (prefer Nt over Zw functions)
	syscallMap := make(map[string]uint16)
	
	// First pass: add all Nt functions
	for _, sc := range syscalls {
		if len(sc.Name) > 2 && sc.Name[:2] == "Nt" {
			syscallMap[sc.Name] = sc.SyscallNumber
		}
	}
	
	// Second pass: add Zw functions only if no corresponding Nt function exists
	for _, sc := range syscalls {
		if len(sc.Name) > 2 && sc.Name[:2] == "Zw" {
			// Convert Zw name to Nt equivalent
			ntName := "Nt" + sc.Name[2:]
			if _, exists := syscallMap[ntName]; !exists {
				// No Nt equivalent exists, add the Zw function
				syscallMap[sc.Name] = sc.SyscallNumber
			}
		}
	}

	// Generate filename with timestamp
	now := time.Now()
	timestamp := fmt.Sprintf("%d%02d%02d_%02d%02d%02d", 
		now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	filename := fmt.Sprintf("syscall_table_%s.go", timestamp)

	// Create the Go file content
	content := `// Package syscalltable provides pre-computed syscall numbers
// Auto-generated by go-direct-syscall DumpAllSyscalls function
// WARNING: These syscall numbers are specific to this Windows version
package syscalltable

// SyscallTable contains pre-computed syscall numbers for Windows NT functions
// Key: Function name, Value: Syscall number (SSN)
var SyscallTable = map[string]uint16{
`

	// Sort the functions for consistent output
	var sortedNames []string
	for name := range syscallMap {
		sortedNames = append(sortedNames, name)
	}
	
	// Simple sorting (bubble sort for simplicity)
	for i := 0; i < len(sortedNames)-1; i++ {
		for j := 0; j < len(sortedNames)-i-1; j++ {
			if sortedNames[j] > sortedNames[j+1] {
				sortedNames[j], sortedNames[j+1] = sortedNames[j+1], sortedNames[j]
			}
		}
	}

	// Add each syscall to the map
	for _, name := range sortedNames {
		ssn := syscallMap[name]
		content += fmt.Sprintf("\t\"%s\": %d,\n", name, ssn)
	}

	content += `}

// GetSyscallNumber returns the syscall number for a given function name
// Returns 0 if the function is not found in the table
func GetSyscallNumber(functionName string) uint16 {
	if ssn, exists := SyscallTable[functionName]; exists {
		return ssn
	}
	return 0
}

// GetAllSyscalls returns a copy of the complete syscall table
func GetAllSyscalls() map[string]uint16 {
	result := make(map[string]uint16)
	for name, ssn := range SyscallTable {
		result[name] = ssn
	}
	return result
}

// GetSyscallCount returns the total number of syscalls in the table
func GetSyscallCount() int {
	return len(SyscallTable)
}
`

	// Write the Go file
	err := writeFileContent(filename, []byte(content))
	if err != nil {
		return fmt.Errorf("failed to write Go syscall table file: %v", err)
	}

	fmt.Printf("Generated Go syscall table: %s\n", filename)
	fmt.Printf("Syscall table contains %d unique functions\n", len(syscallMap))
	
	return nil
}

// writeFileContent writes content to a file (helper function)
func writeFileContent(filename string, content []byte) error {
	return os.WriteFile(filename, content, 0644)
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

// Note: CreateThreadDirect and callCreateThread functions removed 
// We now use NtCreateThreadEx for true direct syscall thread creation (was using createthread earlier because ntcreatethreadex was introducing segfaults but it works now :3)
// This avoids any dependency on Win32 API layer

// NtInjectSelfShellcode injects shellcode into the current process using direct syscalls ONLY
// This function follows the proven pattern: allocate RW -> copy -> change to RX -> create thread
func NtInjectSelfShellcode(payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("payload is empty")
	}
	currentProcess := ^uintptr(0) // Use pseudo-handle for current process

	// Step 1: Allocate RW memory
	var baseAddress uintptr
	size := uintptr(len(payload))

	status, err := NtAllocateVirtualMemory(
		currentProcess,
		&baseAddress,
		0,
		&size,
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	if err != nil || status != STATUS_SUCCESS {
		return fmt.Errorf("memory allocation failed: %v %s", err, FormatNTStatus(status))
	}

	// Step 2: Copy shellcode
	copy((*[1 << 30]byte)(unsafe.Pointer(baseAddress))[:len(payload)], payload)

	// Step 3: Change protection to RX
	var oldProtect uintptr
	status, err = NtProtectVirtualMemory(
		currentProcess,
		&baseAddress,
		&size,
		PAGE_EXECUTE_READ,
		&oldProtect,
	)
	if err != nil || status != STATUS_SUCCESS {
		return fmt.Errorf("protect failed: %v %s", err, FormatNTStatus(status))
	}

	// Step 4: Create thread using NtCreateThreadEx (true direct syscall)
	var hThread uintptr
	
	// NtCreateThreadEx parameters:
	// threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, arg, 
	// createFlags, zeroBits, stackSize, maximumStackSize, attributeList
	status, err = NtCreateThreadEx(
		&hThread,                    // threadHandle - pointer to receive handle
		THREAD_ALL_ACCESS,           // desiredAccess - full access to thread
		0,                           // objectAttributes - NULL for basic usage
		currentProcess,              // processHandle - current process pseudo-handle
		baseAddress,                 // startAddress - our shellcode address
		0,                           // arg - no parameter to pass
		0,                           // createFlags - 0 = run immediately, 1 = create suspended
		0,                           // zeroBits - 0 for default
		0,                           // stackSize - 0 for default
		0,                           // maximumStackSize - 0 for default
		0,                           // attributeList - NULL for basic usage
	)
	
	if err != nil || status != STATUS_SUCCESS {
		return fmt.Errorf("NtCreateThreadEx failed: %v %s", err, FormatNTStatus(status))
	}

	fmt.Printf("  Thread created successfully: 0x%X\n", hThread)
	
	// Wait for thread to complete execution
	fmt.Printf("Step 5: Waiting for thread to complete...\n")
	
	// Wait for the thread with a timeout (10 seconds to be safe)
	timeout := uint64(10000 * 1000 * 10) // 10 seconds in 100ns units
	waitStatus, err := NtWaitForSingleObject(hThread, false, &timeout)
	if err != nil {
		fmt.Printf("  Warning: Wait failed: %v\n", err)
	} else {
		fmt.Printf("  Thread wait completed with status: %s\n", FormatNTStatus(waitStatus))
	}
	
	// Give it a moment and then clean up
	time.Sleep(1 * time.Second)
	
	// Close the thread handle
	closeStatus, err := NtClose(hThread)
	if err != nil || closeStatus != STATUS_SUCCESS {
		fmt.Printf("  Warning: Failed to close thread handle: %v %s\n", err, FormatNTStatus(closeStatus))
	} else {
		fmt.Printf("  Thread handle closed successfully\n")
	}
	return nil
}





