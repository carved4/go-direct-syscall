package unhook

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/carved4/go-direct-syscall/pkg/debug"
	"github.com/carved4/go-direct-syscall/pkg/syscall"
	"github.com/carved4/go-direct-syscall/pkg/syscallresolve"
	"github.com/carved4/go-direct-syscall/pkg/obf"
)

const (
	IMAGE_DOS_SIGNATURE    = 0x5A4D
	IMAGE_NT_SIGNATURE     = 0x00004550
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READONLY          = 0x02
	SECTION_MAP_READ       = 0x0004
)

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]uint8
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks           [2]uintptr
	InMemoryOrderLinks         [2]uintptr
	InInitializationOrderLinks [2]uintptr
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uint32
	FullDllName                UNICODE_STRING
	BaseDllName                UNICODE_STRING
	Flags                      uint32
	LoadCount                  uint16
	TlsIndex                   uint16
	HashLinks                  [2]uintptr
	TimeDateStamp              uint32
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     uint8
	SsHandle                        uintptr
	InLoadOrderModuleList           [2]uintptr
	InMemoryOrderModuleList         [2]uintptr
	InInitializationOrderModuleList [2]uintptr
	EntryInProgress                 uintptr
	ShutdownInProgress              uint8
	ShutdownThreadId                uintptr
}

type PEB struct {
	InheritedAddressSpace      uint8
	ReadImageFileExecOptions   uint8
	BeingDebugged              uint8
	BitField                   uint8
	Mutant                     uintptr
	ImageBaseAddress           uintptr
	Ldr                        uintptr
	ProcessParameters          uintptr
	SubSystemData              uintptr
	ProcessHeap                uintptr
	FastPebLock                uintptr
	AtlThunkSListPtr           uintptr
	IFEOKey                    uintptr
	CrossProcessFlags          uint32
	UserSharedInfoPtr          uintptr
	SystemReserved             uint32
	AtlThunkSListPtr32         uint32
	ApiSetMap                  uintptr
}

type OBJECT_ATTRIBUTES struct {
	Length             uint32
	RootDirectory      uintptr
	ObjectName         uintptr
	Attributes         uint32
	SecurityDescriptor uintptr
	SecurityQualityOfService uintptr
}

// Use the working syscall infrastructure
func do_syscall(number uintptr, args ...uintptr) (uintptr, error) {
	return syscall.ExternalSyscall(uint16(number), args...)
}

// getSyscallNumbers gets all the syscall numbers we need for unhooking
func getSyscallNumbers() (map[string]uintptr, error) {
	numbers := make(map[string]uintptr)
	funcs := []string{
		"NtOpenSection",
		"NtMapViewOfSection",
		"NtUnmapViewOfSection",
		"NtClose",
		"NtProtectVirtualMemory",
		"NtWriteVirtualMemory",
		"NtFreeVirtualMemory",
		"NtCreateProcess",
		"NtQueryInformationProcess", 
		"NtReadVirtualMemory",
	}

	for _, fname := range funcs {
		hash := obf.GetHash(fname)
		
		// First try GuessSyscallNumber (handles hooked functions better)
		num := syscallresolve.GuessSyscallNumber(hash)
		if num != 0 {
			debug.Printfln("UNHOOK", "Got syscall number %d for %s via GuessSyscallNumber\n", num, fname)
			numbers[fname] = uintptr(num)
			continue
		}
		
		// Fallback to GetSyscallAndAddress if guessing fails
		debug.Printfln("UNHOOK", "GuessSyscallNumber failed for %s, trying GetSyscallAndAddress...\n", fname)
		num, _ = syscallresolve.GetSyscallAndAddress(hash)
		if num == 0 {
			return nil, fmt.Errorf("failed to get syscall number for %s using both methods", fname)
		}
		
		debug.Printfln("UNHOOK", "Got syscall number %d for %s via GetSyscallAndAddress\n", num, fname)
		numbers[fname] = uintptr(num)
	}

	return numbers, nil
}

// UnhookNtdll performs ntdll unhooking by loading a fresh copy from KnownDlls
func UnhookNtdll() error {
	debug.Printfln("UNHOOK", "Attempting to unhook ntdll.dll by loading a fresh copy...\n")

	// Step 1: Get current ntdll base address using PEB first (before syscall resolution)
	debug.Printfln("UNHOOK", "Getting current ntdll base address...\n")
	currentNtdllBase, err := getCurrentNtdllBase()
	if err != nil {
		return fmt.Errorf("failed to get current ntdll base: %v", err)
	}
	debug.Printfln("UNHOOK", "Current ntdll base: 0x%x\n", currentNtdllBase)

	// Step 2: Get all syscall numbers
	debug.Printfln("UNHOOK", "Resolving syscall numbers...\n")
	syscalls, err := getSyscallNumbers()
	if err != nil {
		return fmt.Errorf("failed to get syscall numbers: %v", err)
	}
	debug.Printfln("UNHOOK", "Successfully resolved %d syscalls\n", len(syscalls))

	// Step 2: Load fresh ntdll from KnownDlls using direct syscalls
	freshNtdllBase, freshNtdllSize, err := loadFreshNtdll(syscalls)
	if err != nil {
		return fmt.Errorf("failed to load fresh ntdll: %v", err)
	}
	defer func() {
		regionSize := uintptr(freshNtdllSize)
		base := freshNtdllBase
		do_syscall(syscalls["NtFreeVirtualMemory"], 
			getCurrentProcess(), 
			uintptr(unsafe.Pointer(&base)), 
			uintptr(unsafe.Pointer(&regionSize)), 
			0x8000) // MEM_RELEASE
	}()
	debug.Printfln("UNHOOK", "Fresh ntdll loaded at: 0x%x (size: %d)\n", freshNtdllBase, freshNtdllSize)

	if currentNtdllBase == 0 {
		return fmt.Errorf("currentNtdllBase is 0")
	}
	if freshNtdllBase == 0 {
		return fmt.Errorf("freshNtdllBase is 0")
	}

	err = copyTextSection(currentNtdllBase, freshNtdllBase, syscalls)
	if err != nil {
		return fmt.Errorf("failed to copy text section: %v", err)
	}

	debug.Printfln("UNHOOK", "NTDLL unhooking completed successfully!\n")
	return nil
}

func GetPEB() uintptr

func getCurrentProcess() uintptr {
	return ^uintptr(0) // -1 as uintptr, which is the handle for current process
}

// UTF16ToString converts a UTF-16 encoded slice to a Go string
func UTF16ToString(s []uint16) string {
	for i, v := range s {
		if v == 0 {
			s = s[:i]
			break
		}
	}
	result := make([]rune, len(s))
	for i, v := range s {
		result[i] = rune(v)
	}
	return string(result)
}

func getCurrentNtdllBase() (uintptr, error) {
	debug.Printfln("UNHOOK", "Calling GetPEB()...\n")
	// Use the assembly function to get PEB
	pebAddr := GetPEB()
	if pebAddr == 0 {
		return 0, fmt.Errorf("failed to get PEB address")
	}
	debug.Printfln("UNHOOK", "PEB address: 0x%x\n", pebAddr)
	
	peb := (*PEB)(unsafe.Pointer(pebAddr))
	if peb == nil {
		return 0, fmt.Errorf("PEB pointer is null")
	}
	
	debug.Printfln("UNHOOK", "PEB.Ldr: 0x%x\n", peb.Ldr)
	if peb.Ldr == 0 {
		return 0, fmt.Errorf("PEB.Ldr is null")
	}
	
	ldr := (*PEB_LDR_DATA)(unsafe.Pointer(peb.Ldr))
	if ldr == nil {
		return 0, fmt.Errorf("LDR pointer is null")
	}
	
	debug.Printfln("UNHOOK", "LDR structure loaded, walking module list...\n")
	
	// Walk the InLoadOrderModuleList to find ntdll
	head := uintptr(unsafe.Pointer(&ldr.InLoadOrderModuleList[0]))
	current := ldr.InLoadOrderModuleList[0]
	
	debug.Printfln("UNHOOK", "Head: 0x%x, Current: 0x%x\n", head, current)
	
	if current == 0 {
		return 0, fmt.Errorf("module list is empty")
	}
	
	count := 0
	for current != head && count < 100 { // Safety limit
		count++
		debug.Printfln("UNHOOK", "Processing module %d at 0x%x\n", count, current)
		
		if current == 0 {
			return 0, fmt.Errorf("null pointer in module list at entry %d", count)
		}
		
		entry := (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(current))
		if entry == nil {
			return 0, fmt.Errorf("null LDR entry at position %d", count)
		}
		
		debug.Printfln("UNHOOK", "Entry DllBase: 0x%x, BaseDllName.Buffer: 0x%x, Length: %d\n", 
			entry.DllBase, uintptr(unsafe.Pointer(entry.BaseDllName.Buffer)), entry.BaseDllName.Length)
		
		// Safety check for name buffer
		if entry.BaseDllName.Buffer == nil {
			debug.Printfln("UNHOOK", "Module %d has null name buffer, skipping\n", count)
			current = entry.InLoadOrderLinks[0]
			continue
		}
		
		nameLen := int(entry.BaseDllName.Length / 2)
		if nameLen <= 0 || nameLen > 256 { // Reasonable limits
			debug.Printfln("UNHOOK", "Module %d has invalid name length %d, skipping\n", count, nameLen)
			current = entry.InLoadOrderLinks[0]
			continue
		}
		
		// Get the DLL name safely
		nameBuffer := (*uint16)(unsafe.Pointer(entry.BaseDllName.Buffer))
		name := make([]uint16, nameLen)
		for i := 0; i < nameLen; i++ {
			name[i] = *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(nameBuffer)) + uintptr(i*2)))
		}
		
		dllName := UTF16ToString(name)
		debug.Printfln("UNHOOK", "Module %d: %s (base: 0x%x)\n", count, dllName, entry.DllBase)
		
		if dllName == "ntdll.dll" {
			debug.Printfln("UNHOOK", "Found ntdll.dll at base: 0x%x\n", entry.DllBase)
			return entry.DllBase, nil
		}
		
		current = entry.InLoadOrderLinks[0]
	}
	
	if count >= 100 {
		return 0, fmt.Errorf("module list walk exceeded safety limit")
	}
	
	return 0, fmt.Errorf("ntdll.dll not found in PEB")
}

// initUnicodeString mimics the behavior of the Windows RtlInitUnicodeString function.
func initUnicodeString(us *UNICODE_STRING, s []uint16) {
	// Find length of null-terminated string
	strLen := 0
	for strLen < len(s) && s[strLen] != 0 {
		strLen++
	}
	us.Length = uint16(strLen * 2)
	us.MaximumLength = uint16(len(s) * 2)
	if len(s) > 0 {
		us.Buffer = &s[0]
	}
}

func loadFreshNtdll(syscalls map[string]uintptr) (uintptr, uint32, error) {
	debug.Printfln("UNHOOK", "Loading fresh ntdll from KnownDlls directory...\n")

	// Create unicode string for KnownDlls\ntdll.dll
	debug.Printfln("UNHOOK", "Creating unicode string for KnownDlls path...\n")
	var unicodeString UNICODE_STRING
	ntdllPath := [...]uint16{
		'\\', 'K', 'n', 'o', 'w', 'n', 'D', 'l', 'l', 's', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0,
	}
	initUnicodeString(&unicodeString, ntdllPath[:])
	debug.Printfln("UNHOOK", "Unicode string created: Length=%d, Buffer=0x%x\n", 
		unicodeString.Length, uintptr(unsafe.Pointer(unicodeString.Buffer)))

	// Set up object attributes
	debug.Printfln("UNHOOK", "Setting up object attributes...\n")
	var objAttr OBJECT_ATTRIBUTES
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))
	objAttr.RootDirectory = 0
	objAttr.ObjectName = uintptr(unsafe.Pointer(&unicodeString))
	objAttr.Attributes = 0x40 // OBJ_CASE_INSENSITIVE
	objAttr.SecurityDescriptor = 0
	objAttr.SecurityQualityOfService = 0
	debug.Printfln("UNHOOK", "Object attributes set up: Length=%d, ObjectName=0x%x\n", 
		objAttr.Length, objAttr.ObjectName)

	// Check syscall number
	ntOpenSectionNum := syscalls["NtOpenSection"]
	debug.Printfln("UNHOOK", "NtOpenSection syscall number: %d\n", ntOpenSectionNum)

	// Open section using direct syscall
	debug.Printfln("UNHOOK", "About to call NtOpenSection via do_syscall...\n")
	var sectionHandle uintptr
	debug.Printfln("UNHOOK", "Calling do_syscall with args: syscall=%d, handle_ptr=0x%x, access=%d, objattr_ptr=0x%x\n",
		ntOpenSectionNum, uintptr(unsafe.Pointer(&sectionHandle)), SECTION_MAP_READ, uintptr(unsafe.Pointer(&objAttr)))
	
	status, err := do_syscall(ntOpenSectionNum,
		uintptr(unsafe.Pointer(&sectionHandle)),
		SECTION_MAP_READ,
		uintptr(unsafe.Pointer(&objAttr)))

	if err != nil {
		return 0, 0, fmt.Errorf("NtOpenSection direct syscall failed: %v", err)
	}

	if status != 0 {
		return 0, 0, fmt.Errorf("NtOpenSection failed with status: 0x%x", status)
	}

	debug.Printfln("UNHOOK", "Successfully opened section handle: 0x%x\n", sectionHandle)

	// Map the section using direct syscall
	baseAddress, viewSize, err := ntMapViewOfSection(sectionHandle, 0, syscalls)
	if err != nil {
		do_syscall(syscalls["NtClose"], sectionHandle)
		return 0, 0, fmt.Errorf("mapping section failed: %w", err)
	}

	// Close section handle using direct syscall
	do_syscall(syscalls["NtClose"], sectionHandle)

	debug.Printfln("UNHOOK", "Successfully mapped clean ntdll from KnownDlls at: 0x%x (size: %d)\n", baseAddress, viewSize)

	return baseAddress, uint32(viewSize), nil
}

type ProcessBasicInformation struct {
	ExitStatus                   uintptr
	PebBaseAddress              uintptr
	AffinityMask                uintptr
	BasePriority                uintptr
	UniqueProcessId             uintptr
	InheritedFromUniqueProcessId uintptr
}

func copyTextSection(currentBase, freshBase uintptr, syscalls map[string]uintptr) error {
	debug.Printfln("UNHOOK", "copyTextSection called: currentBase=0x%x, freshBase=0x%x\n", currentBase, freshBase)
	
	// Parse DOS header from the fresh ntdll in memory
	debug.Printfln("UNHOOK", "Reading DOS header from freshBase...\n")
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(freshBase))
	if dosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		return fmt.Errorf("invalid DOS signature in fresh ntdll: 0x%x", dosHeader.E_magic)
	}
	debug.Printfln("UNHOOK", "DOS header valid, e_lfanew=0x%x\n", dosHeader.E_lfanew)
	
	// Parse NT headers from fresh ntdll in memory
	debug.Printfln("UNHOOK", "Reading NT headers...\n")
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(freshBase + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != IMAGE_NT_SIGNATURE {
		return fmt.Errorf("invalid NT signature in fresh ntdll: 0x%x", ntHeaders.Signature)
	}
	
	// Get image size and section information from the fresh ntdll
	imageSize := ntHeaders.OptionalHeader.SizeOfImage
	debug.Printfln("UNHOOK", "Image size: %d bytes\n", imageSize)
	
	// Find .text section by parsing section headers directly from memory
	sectionsOffset := uintptr(dosHeader.E_lfanew) + unsafe.Sizeof(*ntHeaders)
	numSections := int(ntHeaders.FileHeader.NumberOfSections)
	debug.Printfln("UNHOOK", "Number of sections: %d\n", numSections)
	
	var textSection *IMAGE_SECTION_HEADER
	for i := 0; i < numSections; i++ {
		sectionHeader := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(freshBase + sectionsOffset + uintptr(i)*unsafe.Sizeof(IMAGE_SECTION_HEADER{})))
		
		// Convert section name to string
		sectionName := string(sectionHeader.Name[:])
		// Remove null bytes
		if nullIndex := strings.IndexByte(sectionName, 0); nullIndex != -1 {
			sectionName = sectionName[:nullIndex]
		}
		
		debug.Printfln("UNHOOK", "Section %d: %s (VirtualAddress=0x%x, VirtualSize=0x%x)\n", 
			i, sectionName, sectionHeader.VirtualAddress, sectionHeader.VirtualSize)
		
		if sectionName == ".text" {
			textSection = sectionHeader
			break
		}
	}
	
	if textSection == nil {
		return fmt.Errorf(".text section not found in fresh ntdll")
	}
	
	debug.Printfln("UNHOOK", "Found .text section: VirtualAddress=0x%x, VirtualSize=0x%x\n", 
		textSection.VirtualAddress, textSection.VirtualSize)
	
	// Get the .text section data directly from the fresh ntdll in memory
	textAddr := freshBase + uintptr(textSection.VirtualAddress)
	textSize := uintptr(textSection.VirtualSize)
	
	debug.Printfln("UNHOOK", "Text section address in fresh ntdll: 0x%x, size: %d\n", textAddr, textSize)
	
	// Calculate target address in current ntdll
	currentTextAddr := currentBase + uintptr(textSection.VirtualAddress)
	
	// Change protection to allow writing
	var oldProtect uintptr
	addr := currentTextAddr
	size := textSize
	status, err := do_syscall(syscalls["NtProtectVirtualMemory"],
		getCurrentProcess(),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)))
	
	if err != nil {
		return fmt.Errorf("NtProtectVirtualMemory failed: %v", err)
	}
	
	if status != 0 {
		return fmt.Errorf("NtProtectVirtualMemory failed (making writable): 0x%x", status)
	}

	// Copy the fresh .text section over the current one using direct memory copy
	var bytesWritten uintptr
	const maxRetries = 5
	const retryDelay = 100 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		status, err = do_syscall(syscalls["NtWriteVirtualMemory"],
			getCurrentProcess(),
			currentTextAddr,
			textAddr, // Source: fresh .text section in memory
			textSize,
			uintptr(unsafe.Pointer(&bytesWritten)))

		if err == nil && status == 0 && bytesWritten == textSize {
			break
		}

		if i < maxRetries-1 {
			debug.Printfln("UNHOOK", "NtWriteVirtualMemory attempt %d/%d failed: status=0x%x, bytesWritten=%d, err=%v. Retrying in %v...\n", 
				i+1, maxRetries, status, bytesWritten, err, retryDelay)
			time.Sleep(retryDelay)
		}
	}

	if err != nil {
		return fmt.Errorf("NtWriteVirtualMemory failed after %d retries: %v", maxRetries, err)
	}
	if status != 0 {
		return fmt.Errorf("NtWriteVirtualMemory failed after %d retries with status: 0x%x", maxRetries, status)
	}
	if bytesWritten != textSize {
		return fmt.Errorf("NtWriteVirtualMemory only wrote %d of %d bytes after %d retries", bytesWritten, textSize, maxRetries)
	}

	debug.Printfln("UNHOOK", "Copied %d bytes from fresh .text section (wrote %d bytes)\n", textSize, bytesWritten)
	
	// Restore original protection
	addr = currentTextAddr
	size = textSize
	status, err = do_syscall(syscalls["NtProtectVirtualMemory"],
		getCurrentProcess(),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		oldProtect,
		uintptr(unsafe.Pointer(&oldProtect)))
	
	if err != nil {
		return fmt.Errorf("NtProtectVirtualMemory failed: %v", err)
	}
	
	if status != 0 {
		return fmt.Errorf("NtProtectVirtualMemory failed (restoring protection): 0x%x", status)
	}
	
	return nil
}

func ntMapViewOfSection(sectionHandle uintptr, sizeOfImage uint32, syscalls map[string]uintptr) (uintptr, uintptr, error) {
	const maxRetries = 10
	const baseDelay = 10 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		var bAddress uintptr
		viewSize := uintptr(sizeOfImage)

		if attempt > 0 {
			delay := time.Duration(attempt) * baseDelay
			time.Sleep(delay)
		}

		status, err := do_syscall(syscalls["NtMapViewOfSection"],
			sectionHandle,
			getCurrentProcess(),
			uintptr(unsafe.Pointer(&bAddress)),
			0,
			0,
			0,
			uintptr(unsafe.Pointer(&viewSize)),
			2, // ViewShare
			0,
			PAGE_READONLY)

		if err != nil {
			return 0, 0, fmt.Errorf("NtMapViewOfSection failed: %w", err)
		}

		if status >= 0x80000000 {
			return 0, 0, fmt.Errorf("NtMapViewOfSection failed with NTSTATUS: 0x%x", status)
		}

		if bAddress != 0 {
			return bAddress, viewSize, nil
		}

		if attempt == maxRetries-1 {
			return 0, 0, fmt.Errorf("NtMapViewOfSection returned NULL base address after %d attempts", maxRetries)
		}
	}

	return 0, 0, fmt.Errorf("unexpected exit from retry loop")
}