#!/usr/bin/env bash
set -euo pipefail

# Script to install liboqs on Ubuntu/Debian systems
# Tries to install via apt first, falls back to building from source if unavailable

LIBOQS_VERSION="${LIBOQS_VERSION:-0.11.0}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"

echo "=== Installing liboqs ==="

# Try installing from apt first
echo "Attempting to install liboqs-dev from apt..."
if sudo apt-get install -y liboqs-dev 2>/dev/null; then
    echo "✓ Successfully installed liboqs-dev from apt"
    exit 0
fi

echo "liboqs-dev not available in apt, building from source..."

# Install build dependencies
echo "Installing build dependencies..."
sudo apt-get update
sudo apt-get install -y cmake gcc g++ libssl-dev ninja-build

# Create temporary build directory
BUILD_DIR=$(mktemp -d)
trap "rm -rf $BUILD_DIR" EXIT

cd "$BUILD_DIR"

# Download liboqs source
echo "Downloading liboqs ${LIBOQS_VERSION}..."
wget -q "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" -O liboqs.tar.gz
tar -xzf liboqs.tar.gz
cd "liboqs-${LIBOQS_VERSION}"

# Configure with CMake
echo "Configuring liboqs..."
cmake -S . -B build -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=ON \
    -DOQS_USE_OPENSSL=ON

# Build
echo "Building liboqs (this may take a few minutes)..."
cmake --build build --parallel $(nproc)

# Install
echo "Installing liboqs to ${INSTALL_PREFIX}..."
sudo cmake --install build

# Update library cache
sudo ldconfig

echo "✓ Successfully built and installed liboqs ${LIBOQS_VERSION}"

# Verify installation
if pkg-config --exists liboqs 2>/dev/null || [ -f "${INSTALL_PREFIX}/include/oqs/oqs.h" ]; then
    echo "✓ liboqs installation verified"
else
    echo "⚠ Warning: liboqs installation could not be verified"
fi
