package unhook

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"
	"github.com/Binject/debug/pe"
	"github.com/carved4/go-wincall"
)

func UnhookNtdll() error {
	ntdllHash := wincall.GetHash("ntdll.dll")
	ntdllHandle := wincall.GetModuleBase(ntdllHash)
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
	
	_, err = wincall.NtProtectVirtualMemory(
		currentProcess,
		&targetAddr,
		&textSize,
		0x40,
		&oldProtect,
	)
	if err != nil {
		return fmt.Errorf("failed to change memory protection: %v", err)
	}
	
	if len(cleanTextData) == 0 {
		return fmt.Errorf("clean .text section data is empty")
	}
	
	sourceAddr := uintptr(unsafe.Pointer(&cleanTextData[0]))
	runtime.KeepAlive(cleanTextData)
	
	_, err = wincall.Call("kernel32.dll", "RtlCopyMemory",
		targetAddr,
		sourceAddr,
		textSize,
	)
	if err != nil {
		return fmt.Errorf("failed to copy clean .text section: %v", err)
	}
	runtime.KeepAlive(cleanTextData)
	var dummy uintptr
	_, err = wincall.NtProtectVirtualMemory(
		currentProcess,
		&targetAddr,
		&textSize,
		oldProtect,
		&dummy,
	)
	if err != nil {
		return fmt.Errorf("failed to restore memory protection: %v", err)
	}
	
	return nil
}
