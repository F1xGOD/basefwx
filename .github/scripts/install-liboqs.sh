#!/usr/bin/env bash
set -euo pipefail

# Script to install liboqs on Ubuntu/Debian systems
# Tries to install via apt first, falls back to building from source if unavailable

LIBOQS_VERSION="${LIBOQS_VERSION:-0.11.0}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
LIBOQS_USE_APT="${LIBOQS_USE_APT:-1}"
LIBOQS_BUILD_SHARED="${LIBOQS_BUILD_SHARED:-ON}"

if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    echo "sudo is required when not running as root" >&2
    exit 1
fi

run_as_root() {
    if [[ -n "${SUDO}" ]]; then
        ${SUDO} "$@"
    else
        "$@"
    fi
}

echo "=== Installing liboqs ==="
echo "liboqs version: ${LIBOQS_VERSION}"
echo "install prefix: ${INSTALL_PREFIX}"
echo "use apt: ${LIBOQS_USE_APT}"
echo "build shared libs: ${LIBOQS_BUILD_SHARED}"

# Try installing from apt first only for shared-linking mode.
if [[ "${LIBOQS_USE_APT}" == "1" && "${LIBOQS_BUILD_SHARED}" == "ON" ]]; then
    echo "Attempting to install liboqs-dev from apt..."
    if run_as_root apt-get install -y liboqs-dev 2>/dev/null; then
        echo "✓ Successfully installed liboqs-dev from apt"
        exit 0
    fi
else
    echo "Skipping apt install (requested source build mode)."
fi

echo "liboqs-dev not available in apt, building from source..."

# Install build dependencies
echo "Installing build dependencies..."
run_as_root apt-get update
run_as_root apt-get install -y cmake gcc g++ libssl-dev ninja-build wget ca-certificates

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
    -DBUILD_SHARED_LIBS="${LIBOQS_BUILD_SHARED}" \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=ON \
    -DOQS_USE_OPENSSL=ON

# Build
echo "Building liboqs (this may take a few minutes)..."
cmake --build build --parallel $(nproc)

# Install
echo "Installing liboqs to ${INSTALL_PREFIX}..."
run_as_root cmake --install build

# Update library cache
if command -v ldconfig >/dev/null 2>&1; then
    run_as_root ldconfig || true
fi

echo "✓ Successfully built and installed liboqs ${LIBOQS_VERSION}"

# Verify installation
if pkg-config --exists liboqs 2>/dev/null || [ -f "${INSTALL_PREFIX}/include/oqs/oqs.h" ]; then
    echo "✓ liboqs installation verified"
else
    echo "⚠ Warning: liboqs installation could not be verified"
fi

if [[ "${LIBOQS_BUILD_SHARED}" == "OFF" ]]; then
    if [[ -f "${INSTALL_PREFIX}/lib/liboqs.a" ]]; then
        echo "✓ Static lib installed: ${INSTALL_PREFIX}/lib/liboqs.a"
    else
        echo "✗ Static lib missing: ${INSTALL_PREFIX}/lib/liboqs.a"
        exit 1
    fi
fi
