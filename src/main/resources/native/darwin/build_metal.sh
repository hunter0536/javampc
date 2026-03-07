#!/bin/bash

# 编译Metal文件为metallib和Native代码为动态库

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"

# Metal shader compilation
METAL_FILE="$SCRIPT_DIR/big_integer_shaders_complete.metal"
METALLIB_OUTPUT="$SCRIPT_DIR/big_integer_shaders_complete.metallib"

# Native code compilation
OBJECTIVE_C_FILE="$SCRIPT_DIR/MetalBigIntegerBackend.m"
DYLIB_OUTPUT="$SCRIPT_DIR/libmetal_biginteger.dylib"

# Find Java home
if [ -z "$JAVA_HOME" ]; then
    JAVA_HOME=$(java -XshowSettings:properties -version 2>&1 | grep -E 'java.home' | awk '{print $3}')
fi

# Check Java home
if [ -z "$JAVA_HOME" ]; then
    echo "ERROR: JAVA_HOME not found. Please set JAVA_HOME environment variable."
    exit 1
fi

echo "=== Metal Shader Compilation ==="
echo "Input: $METAL_FILE"
echo "Output: $METALLIB_OUTPUT"

# 使用xcrun调用metal命令
METAL_CMD="xcrun metal"

# 验证metal命令是否可用
if ! $METAL_CMD --version &> /dev/null; then
    echo "ERROR: metal command not found. Please install Xcode command line tools."
    exit 1
fi

echo "Using metal command via xcrun"

# 检查输入文件是否存在
if [ ! -f "$METAL_FILE" ]; then
    echo "ERROR: Metal source file not found: $METAL_FILE"
    exit 1
fi

# 编译Metal文件
echo "Compiling Metal shader..."
$METAL_CMD "$METAL_FILE" -o "$METALLIB_OUTPUT"

if [ $? -eq 0 ]; then
    echo "SUCCESS: Metal shader compiled successfully!"
    ls -la "$METALLIB_OUTPUT"
else
    echo "ERROR: Metal shader compilation failed"
    exit 1
fi

echo "=== Native Code Compilation ==="
echo "Input: $OBJECTIVE_C_FILE"
echo "Output: $DYLIB_OUTPUT"
echo "Java home: $JAVA_HOME"

# 检查Objective-C文件是否存在
if [ ! -f "$OBJECTIVE_C_FILE" ]; then
    echo "ERROR: Objective-C source file not found: $OBJECTIVE_C_FILE"
    exit 1
fi

# 编译Objective-C代码为动态库
echo "Compiling Native code..."
clang -framework Foundation -framework Metal -o "$DYLIB_OUTPUT" \
    "$OBJECTIVE_C_FILE" \
    -shared -fPIC \
    -I"$JAVA_HOME/include" \
    -I"$JAVA_HOME/include/darwin"

if [ $? -eq 0 ]; then
    echo "SUCCESS: Native code compiled successfully!"
    ls -la "$DYLIB_OUTPUT"
else
    echo "ERROR: Native code compilation failed"
    exit 1
fi

echo "=== Compilation Complete ==="
echo "All files compiled successfully!"
echo "Output files:"
echo "- $METALLIB_OUTPUT"
echo "- $DYLIB_OUTPUT"
