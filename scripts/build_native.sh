#!/bin/bash

# 编译 GMP JNI 原生库
# 支持两种模式:
#   1. 静态链接 (默认) - 将 GMP 编译进 JNI 库，部署时无需安装 GMP
#   2. 动态链接 - 使用系统 GMP，部署时需要安装 GMP
#
# 静态编译 GMP (推荐，无需部署依赖):
#   ./build_native.sh --static
#
# 使用系统 GMP 动态链接:
#   ./build_native.sh --dynamic

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NATIVE_SRC="$PROJECT_ROOT/src/main/native"
NATIVE_LIB="$PROJECT_ROOT/src/main/resources/native"
GMP_BUILD="$PROJECT_ROOT/build/gmp"

STATIC_BUILD=false
for arg in "$@"; do
    case $arg in
        --static) STATIC_BUILD=true ;;
        --dynamic) STATIC_BUILD=false ;;
    esac
done

OS=$(uname -s)
ARCH=$(uname -m)

echo "Building GMP JNI library for $OS-$ARCH (static=$STATIC_BUILD)"

mkdir -p "$NATIVE_LIB"

if [ "$OS" = "Darwin" ]; then
    LIB_NAME="libmpc_gmp.dylib"
    JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home)}"
    INCLUDES="-I$JAVA_HOME/include -I$JAVA_HOME/include/darwin"
    FLAGS="-shared -fPIC -O3"
elif [ "$OS" = "Linux" ]; then
    LIB_NAME="libmpc_gmp.so"
    JAVA_HOME="${JAVA_HOME:-$(dirname $(dirname $(readlink -f $(which java))))}"
    INCLUDES="-I$JAVA_HOME/include -I$JAVA_HOME/include/linux"
    FLAGS="-shared -fPIC -O3"
else
    echo "Unsupported OS: $OS"
    echo "Native acceleration will be disabled, using Java BigInteger fallback."
    exit 0
fi

if [ "$STATIC_BUILD" = true ]; then
    echo "=== Static build mode: compiling GMP from source ==="
    
    GMP_VERSION="6.3.0"
    GMP_TARBALL="$GMP_BUILD/gmp-$GMP_VERSION.tar.xz"
    GMP_SRC="$GMP_BUILD/gmp-$GMP_VERSION"
    
    mkdir -p "$GMP_BUILD"
    
    # 下载 GMP 源码
    if [ ! -f "$GMP_TARBALL" ]; then
        echo "Downloading GMP $GMP_VERSION..."
        curl -L "https://ftp.gnu.org/gnu/gmp/gmp-$GMP_VERSION.tar.xz" -o "$GMP_TARBALL"
    fi
    
    # 解压
    if [ ! -d "$GMP_SRC" ]; then
        echo "Extracting GMP..."
        tar -xf "$GMP_TARBALL" -C "$GMP_BUILD"
    fi
    
    # 编译 GMP 静态库
    GMP_INSTALL="$GMP_BUILD/install"
    if [ ! -f "$GMP_INSTALL/lib/libgmp.a" ]; then
        echo "Compiling GMP static library..."
        cd "$GMP_SRC"
        ./configure --prefix="$GMP_INSTALL" --enable-static --disable-shared --disable-dependency-tracking
        make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)
        make install
        cd "$PROJECT_ROOT"
    fi
    
    GMP_INCLUDE="$GMP_INSTALL/include"
    GMP_LIB="$GMP_INSTALL/lib"
    
    echo "Compiling $LIB_NAME with static GMP..."
    gcc $FLAGS $INCLUDES -I"$GMP_INCLUDE" \
        "$NATIVE_SRC/mpc_gmp.c" \
        "$GMP_LIB/libgmp.a" \
        -o "$NATIVE_LIB/$LIB_NAME"
    
else
    echo "=== Dynamic build mode: using system GMP ==="
    
    # 检查系统 GMP
    if [ "$OS" = "Darwin" ]; then
        GMP_INCLUDE=$(brew --prefix gmp 2>/dev/null)/include
        GMP_LIB=$(brew --prefix gmp 2>/dev/null)/lib
        if [ ! -f "$GMP_INCLUDE/gmp.h" ]; then
            echo "GMP not found. Install with: brew install gmp"
            echo "Or use static build: ./build_native.sh --static"
            echo "Native acceleration will be disabled, using Java BigInteger fallback."
            exit 0
        fi
    elif [ "$OS" = "Linux" ]; then
        if [ -f "/usr/include/gmp.h" ]; then
            GMP_INCLUDE="/usr/include"
            GMP_LIB="/usr/lib"
        elif [ -f "/usr/local/include/gmp.h" ]; then
            GMP_INCLUDE="/usr/local/include"
            GMP_LIB="/usr/local/lib"
        else
            echo "GMP not found. Install with: apt-get install libgmp-dev"
            echo "Or use static build: ./build_native.sh --static"
            echo "Native acceleration will be disabled, using Java BigInteger fallback."
            exit 0
        fi
    fi
    
    echo "Compiling $LIB_NAME with dynamic GMP..."
    gcc $FLAGS $INCLUDES -I"$GMP_INCLUDE" -L"$GMP_LIB" \
        "$NATIVE_SRC/mpc_gmp.c" \
        -lgmp -o "$NATIVE_LIB/$LIB_NAME"
fi

if [ $? -eq 0 ]; then
    echo ""
    echo "=== Build successful! ==="
    echo "Output: $NATIVE_LIB/$LIB_NAME"
    ls -la "$NATIVE_LIB/$LIB_NAME"
    echo ""
    if [ "$STATIC_BUILD" = true ]; then
        echo "Static build: No GMP dependency required at runtime."
    else
        echo "Dynamic build: GMP must be installed on target machines."
    fi
else
    echo "Build failed!"
    echo "Native acceleration will be disabled, using Java BigInteger fallback."
    exit 0
fi
