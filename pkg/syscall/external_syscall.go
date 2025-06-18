package syscall

import (
	"fmt"
	"runtime"
	"unsafe"
	_ "unsafe" // for go:linkname
	
	"github.com/carved4/go-direct-syscall/pkg/syscallresolve"
)

/*
#cgo LDFLAGS: -L../../ -ldo_syscall -ldo_call -ldo_indirect_syscall
extern long long do_syscall(int ssn, int nargs, 
    long long a0, long long a1, long long a2, long long a3, long long a4, long long a5,
    long long a6, long long a7, long long a8, long long a9, long long a10, long long a11);
extern long long do_call(void* func_addr, int nargs, 
    long long a0, long long a1, long long a2, long long a3, long long a4, long long a5,
    long long a6, long long a7, long long a8, long long a9, long long a10, long long a11);
extern long long do_indirect_syscall(int ssn, void* syscall_addr, int nargs,
    long long a0, long long a1, long long a2, long long a3, long long a4, long long a5,
    long long a6, long long a7, long long a8, long long a9, long long a10, long long a11);
*/
import "C"

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
	syscallNum := syscallresolve.GetSyscallNumber(functionHash)
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

// DoIndirectSyscallExternal calls the external indirect assembly function using cgo
func DoIndirectSyscallExternal(ssn uint16, syscallAddr uintptr, nargs uint32, args ...uintptr) uintptr {
	// Lock the OS thread for syscall safety
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	
	// Pad args to ensure we have exactly 12 arguments  
	paddedArgs := make([]uintptr, 12)
	copy(paddedArgs, args)
	
	result := C.do_indirect_syscall(
		C.int(ssn),
		unsafe.Pointer(syscallAddr),
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

// IndirectSyscall executes an indirect syscall using a syscall instruction from ntdll
func IndirectSyscall(syscallNumber uint16, syscallAddr uintptr, args ...uintptr) (uintptr, error) {
	result := DoIndirectSyscallExternal(syscallNumber, syscallAddr, uint32(len(args)), args...)
	return result, nil
}

// HashIndirectSyscall executes an indirect syscall using a function name hash
func HashIndirectSyscall(functionHash uint32, args ...uintptr) (uintptr, error) {
	syscallNum, syscallAddr := syscallresolve.GetSyscallAndAddress(functionHash)
	if syscallNum == 0 || syscallAddr == 0 {
		return 0, fmt.Errorf("failed to resolve syscall number or address for hash 0x%X", functionHash)
	}
	return IndirectSyscall(syscallNum, syscallAddr, args...)
}
