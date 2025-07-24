package syscall

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/carved4/go-native-syscall/pkg/obf"
	"github.com/carved4/go-native-syscall/pkg/syscallresolve"
)

var (
	loadLibraryWAddr   uintptr
	getProcAddressAddr uintptr
	wincallOnce        sync.Once
)

// DoSyscallExternal calls the assembly function directly
func DoSyscallExternal(ssn uint16, nargs uint32, args ...uintptr) uintptr {
	// Lock the OS thread for syscall safety
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	result := do_syscall(ssn, args...)
	return uintptr(result)
}

// ExternalSyscall is a wrapper that uses the assembly implementation
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

// DirectCall calls a Windows API function directly by address using the libcall structure
func DirectCall(funcAddr uintptr, args ...uintptr) (uintptr, error) {
	// Lock the OS thread for call safety
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Create libcall structure
	lc := &libcall{
		fn:   funcAddr,
		n:    uintptr(len(args)),
		args: uintptr(unsafe.Pointer(&args[0])),
	}

	// Call the assembly function
	wincall(lc)

	return lc.r1, nil
}

// DoIndirectSyscallExternal calls the assembly indirect function directly
func DoIndirectSyscallExternal(ssn uint16, syscallAddr uintptr, nargs uint32, args ...uintptr) uintptr {
	// Lock the OS thread for syscall safety
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Automatically resolve trampoline from the stub address
	trampoline := getTrampoline(syscallAddr)
	if trampoline == 0 {
		// Return error status if trampoline resolution fails
		return 0xC0000005 // STATUS_ACCESS_VIOLATION
	}

	result := do_syscall_indirect(ssn, trampoline, args...)
	return uintptr(result)
}

// This function is now defined in assembly.go

// HashIndirectSyscall executes an indirect syscall using a function name hash
func HashIndirectSyscall(functionHash uint32, args ...uintptr) (uintptr, error) {
	syscallNum, syscallAddr := syscallresolve.GetSyscallAndAddress(functionHash)
	if syscallNum == 0 || syscallAddr == 0 {
		return 0, fmt.Errorf("failed to resolve syscall number or address for hash 0x%X", functionHash)
	}
	result := DoIndirectSyscallExternal(syscallNum, syscallAddr, uint32(len(args)), args...)
	return result, nil
}

func initAddresses() {
	kernel32Hash := obf.DBJ2HashStr("kernel32.dll")
	kernel32Base := syscallresolve.GetModuleBase(kernel32Hash)
	if kernel32Base == 0 {
		return
	}
	loadLibraryWHash := obf.DBJ2HashStr("LoadLibraryW")
	loadLibraryWAddr = syscallresolve.GetFunctionAddress(kernel32Base, loadLibraryWHash)

	getProcAddressHash := obf.DBJ2HashStr("GetProcAddress")
	getProcAddressAddr = syscallresolve.GetFunctionAddress(kernel32Base, getProcAddressHash)
}

func LoadLibraryW(name string) uintptr {
	namePtr, _ := UTF16PtrFromString(name)
	r1, _ := DirectCall(getLoadLibraryWAddr(), uintptr(unsafe.Pointer(namePtr)))
	return r1
}

func GetProcAddress(moduleHandle uintptr, proc unsafe.Pointer) uintptr {
	r1, _ := DirectCall(getGetProcAddressAddr(), moduleHandle, uintptr(proc))
	return r1
}

func getLoadLibraryWAddr() uintptr {
	wincallOnce.Do(initAddresses)
	return loadLibraryWAddr
}

func getGetProcAddressAddr() uintptr {
	wincallOnce.Do(initAddresses)
	return getProcAddressAddr
}

func IsDebuggerPresent() bool {
	kernel32Hash := obf.DBJ2HashStr("kernel32.dll")
	kernel32Base := syscallresolve.GetModuleBase(kernel32Hash)
	procName, _ := BytePtrFromString("IsDebuggerPresent")
	isDebuggerPresentAddr := GetProcAddress(kernel32Base, unsafe.Pointer(procName))
	if isDebuggerPresentAddr == 0 {
		return false
	}
	r1, _ := DirectCall(isDebuggerPresentAddr)
	return r1 != 0
}

func CheckRemoteDebuggerPresent(hProcess uintptr, pbDebuggerPresent *bool) error {
	kernel32Hash := obf.DBJ2HashStr("kernel32.dll")
	kernel32Base := syscallresolve.GetModuleBase(kernel32Hash)
	procName, _ := BytePtrFromString("CheckRemoteDebuggerPresent")
	checkRemoteDebuggerPresentAddr := GetProcAddress(kernel32Base, unsafe.Pointer(procName))
	if checkRemoteDebuggerPresentAddr == 0 {
		return fmt.Errorf("could not find CheckRemoteDebuggerPresent")
	}
	var isPresent uint32
	r1, _ := DirectCall(checkRemoteDebuggerPresentAddr, hProcess, uintptr(unsafe.Pointer(&isPresent)))
	*pbDebuggerPresent = (isPresent != 0)
	if r1 == 0 {
		return fmt.Errorf("CheckRemoteDebuggerPresent failed")
	}
	return nil
}

func UTF16PtrFromString(s string) (*uint16, error) {
	runes := []rune(s)
	buf := make([]uint16, len(runes)+1)
	for i, r := range runes {
		if r <= 0xFFFF {
			buf[i] = uint16(r)
		} else {
			// surrogate pair
			r -= 0x10000
			buf[i] = 0xD800 + uint16(r>>10)
			i++
			buf[i] = 0xDC00 + uint16(r&0x3FF)
		}
	}
	return &buf[0], nil
}

func BytePtrFromString(s string) (*byte, error) {
	bytes := append([]byte(s), 0)
	return &bytes[0], nil
}

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
