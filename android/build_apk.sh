#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Tirri-Shield APK Builder ==="
echo ""

# Check prerequisites
for cmd in python3 java git; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not found."
        exit 1
    fi
done

JAVA_VER=$(java -version 2>&1 | head -1 | grep -oP '\"(\d+)' | tr -d '"')
if [ "$JAVA_VER" -lt 17 ]; then
    echo "ERROR: Java 17+ is required (found Java $JAVA_VER)"
    exit 1
fi

# Install buildozer if needed
if ! command -v buildozer &>/dev/null; then
    echo "Installing buildozer and cython..."
    pip install buildozer cython
fi

echo "Building debug APK (this will take 10-20 minutes on first run)..."
echo "The Android SDK/NDK will be downloaded automatically if needed."
echo ""

yes | buildozer android debug 2>&1 | tee build.log

APK=$(find bin/ -name "*.apk" 2>/dev/null | head -1)
if [ -n "$APK" ]; then
    echo ""
    echo "=== BUILD SUCCESSFUL ==="
    echo "APK: $APK"
    echo "Size: $(du -h "$APK" | cut -f1)"
    echo ""
    echo "Install on device: adb install $APK"
else
    echo ""
    echo "=== BUILD FAILED ==="
    echo "Check build.log for details"
    exit 1
fi
