#!/bin/bash

echo "Building Go Direct Syscall Enhanced API Test..."
echo

# Build the test program
echo "🔨 Building test_enhanced_api..."
go build -o test_enhanced_api test_enhanced_api.go

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

echo "✅ Build successful!"
echo
echo "🚀 Running enhanced API test..."
echo "================================================"
echo

# Run the test program
./test_enhanced_api

echo
echo "================================================"
echo "✅ Test completed! Check the generated files above."
echo

# Show generated files
echo "📁 Generated files in current directory:"
ls -la winapi_functions_*.go syscall_table_*.go 2>/dev/null | head -10

echo
echo "💡 Tip: You can now import the generated function tables in your Go projects!" 