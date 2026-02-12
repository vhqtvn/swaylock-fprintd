#!/bin/bash

if [ $(id -u) -eq 0 ]; then
    echo "Don't run as root"
    exit 1
fi

set -e

echo "=== Setting up build environment ==="
if [ -d build ]; then
    echo "Cleaning existing build directory..."
    rm -rf build
fi

echo "=== Running meson setup ==="
meson setup build --prefix=/usr/local --bindir=/usr/local/bin

echo "=== Building with ninja ==="
ninja -v -C build

echo "=== Installing (requires sudo) ==="
sudo ninja -C build install

echo "=== Build completed successfully ==="