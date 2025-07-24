package syscall

import "fmt"

//go:noescape
func do_syscall(callid uint16, argh ...uintptr) uint32

//go:noescape
func do_syscall_indirect(ssn uint16, trampoline uintptr, argh ...uintptr) uint32

//go:noescape
func getTrampoline(stubAddr uintptr) uintptr

//go:noescape
func wincall(libcall *libcall)

//go:noescape
func getlasterror() uint32

// libcall structure for Windows API calls
// This matches the Go runtime's libcall structure
type libcall struct {
	fn   uintptr
	n    uintptr
	args uintptr
	r1   uintptr
	r2   uintptr
	err  uintptr
}

// Syscall executes a direct syscall with the given number and arguments.
// This function acts as a wrapper around the assembly implementation.
func Syscall(syscallNum uint16, args ...uintptr) (uintptr, error) {
	result := do_syscall(syscallNum, args...)
	return uintptr(result), nil
}

// IndirectSyscall executes an indirect syscall with the given number, syscall address, and arguments.
// This function acts as a wrapper around the assembly implementation with automatic trampoline resolution.
func IndirectSyscall(syscallNum uint16, syscallAddr uintptr, args ...uintptr) (uintptr, error) {
	// Automatically resolve trampoline from the stub address
	trampoline := getTrampoline(syscallAddr)
	if trampoline == 0 {
		return 0, fmt.Errorf("failed to find clean syscall;ret gadget in stub at 0x%X", syscallAddr)
	}

	result := do_syscall_indirect(syscallNum, trampoline, args...)
	return uintptr(result), nil
}

