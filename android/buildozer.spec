[app]

title = Tirri-Shield
package.name = tirrishield
package.domain = com.tirrishield
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json
version = 0.1.0

requirements = python3,kivy,pyjnius,android

android.permissions = BLUETOOTH,BLUETOOTH_ADMIN,BLUETOOTH_SCAN,BLUETOOTH_CONNECT,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION

android.minapi = 26
android.api = 34
android.ndk_api = 26

android.archs = arm64-v8a,armeabi-v7a

orientation = portrait
fullscreen = 0
android.features = android.hardware.bluetooth_le
android.accept_sdk_license = True
android.enable_androidx = True

osx.python_version = 3
osx.kivy_version = 2.3.1

log_level = 2

[buildozer]
log_level = 2
warn_on_root = 1
