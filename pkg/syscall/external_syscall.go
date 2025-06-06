package syscall

import (
	"runtime"
	"unsafe"
	_ "unsafe" // for go:linkname
	
	"github.com/carved4/go-direct-syscall/pkg/obf"
	"github.com/carved4/go-direct-syscall/pkg/syscallresolve"
)

/*
#cgo LDFLAGS: -L../../ -ldo_syscall
extern long long do_syscall(int ssn, int nargs, 
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

// NtAllocateVirtualMemory allocates memory in a process using direct syscall
func NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType, protect uintptr) uintptr {
	functionHash := obf.GetHash("NtAllocateVirtualMemory")
	r1, _ := HashSyscall(functionHash,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		zeroBits,
		uintptr(unsafe.Pointer(regionSize)),
		allocationType,
		protect)
	return r1
}

// NtWriteVirtualMemory writes to memory in a process using direct syscall
func NtWriteVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer unsafe.Pointer, size uintptr, bytesWritten *uintptr) uintptr {
	functionHash := obf.GetHash("NtWriteVirtualMemory")
	r1, _ := HashSyscall(functionHash,
		processHandle,
		baseAddress,
		uintptr(buffer),
		size,
		uintptr(unsafe.Pointer(bytesWritten)))
	return r1
}

// NtCreateThreadEx creates a thread in a process using direct syscall
func NtCreateThreadEx(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, processHandle uintptr, startAddress uintptr, arg uintptr, createFlags uintptr, zeroBits uintptr, stackSize uintptr, maximumStackSize uintptr, attributeList uintptr) uintptr {
	functionHash := obf.GetHash("NtCreateThreadEx")
	r1, _ := HashSyscall(functionHash,
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
	return r1
}