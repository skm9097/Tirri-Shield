"""Android BLE ScanCallback bridge via pyjnius.

This module creates a Java ScanCallback subclass that bridges BLE scan results
back to Python callbacks. Only loaded on Android.
"""

from jnius import PythonJavaClass, java_method, autoclass

ScanResult = autoclass("android.bluetooth.le.ScanResult")


class TirriScanCallback(PythonJavaClass):
    """Java ScanCallback that forwards results to a Python callback."""

    __javainterfaces__ = ["android/bluetooth/le/ScanCallback"]
    __javacontext__ = "app"

    def __init__(self, on_device_found):
        super().__init__()
        self._on_device_found = on_device_found

    @java_method("(ILjava/util/List;)V")
    def onBatchScanResults(self, callbackType, results):
        if results is None:
            return
        for i in range(results.size()):
            result = results.get(i)
            self._process_result(result)

    @java_method("(ILandroid/bluetooth/le/ScanResult;)V")
    def onScanResult(self, callbackType, result):
        self._process_result(result)

    @java_method("(I)V")
    def onScanFailed(self, errorCode):
        pass

    def _process_result(self, result):
        try:
            device = result.getDevice()
            address = device.getAddress()
            name = device.getName()
            rssi = result.getRssi()

            if self._on_device_found:
                self._on_device_found(address, name, rssi)
        except Exception:
            pass
