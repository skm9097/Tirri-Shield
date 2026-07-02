[app]

# Application title
title = Tirri-Shield

# Package name (Java-style)
package.name = tirrishield

# Package domain (for android.package)
package.domain = com.tirrishield

# Source directory (where main.py is)
source.dir = .

# Source files to include
source.include_exts = py,png,jpg,kv,atlas,json

# Application versioning
version = 0.1.0

# Application requirements
# Only include what the Android app needs (not bleak — uses native Android BLE)
requirements = python3,kivy,pyjnius,android

# Android permissions for BLE scanning
android.permissions = BLUETOOTH,BLUETOOTH_ADMIN,BLUETOOTH_SCAN,BLUETOOTH_CONNECT,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION

# Android API levels
android.minapi = 26
android.api = 34
android.ndk_api = 26

# Target architecture
android.archs = arm64-v8a,armeabi-v7a

# Orientation
orientation = portrait

# Fullscreen mode
fullscreen = 0

# Android features
android.features = android.hardware.bluetooth_le

# App icon (will use default if not provided)
# icon.filename = %(source.dir)s/data/icon.png

# Presplash
# presplash.filename = %(source.dir)s/data/presplash.png

# OSX / iOS / Windows settings (not used for Android)
osx.python_version = 3
osx.kivy_version = 2.3.1

# Android specific
android.accept_sdk_license = True
android.enable_androidx = True

# Log level
log_level = 2

# Build type: debug or release
# For testing, use debug. For distribution, use release.
# android.release_artifact = apk

[buildozer]

# Build directory
# build_dir = ./.buildozer

# Log level (0 = error only, 1 = info, 2 = debug)
log_level = 2

# Display warning if buildozer is run as root (0 = False, 1 = True)
warn_on_root = 1
