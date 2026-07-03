"""BLE device discovery and scanning for BMS devices."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator, Callable

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from tirri_shield.ble.signatures import identify_device, is_likely_bms
from tirri_shield.models import BMSDevice

logger = logging.getLogger(__name__)


class BMSDiscovery:
    """Discovers BMS devices via BLE scanning."""

    def __init__(self, scan_duration: float = 10.0, bms_only: bool = True):
        self.scan_duration = scan_duration
        self.bms_only = bms_only
        self._discovered: dict[str, BMSDevice] = {}
        self._callbacks: list[Callable[[BMSDevice], None]] = []

    def on_device_found(self, callback: Callable[[BMSDevice], None]) -> None:
        self._callbacks.append(callback)

    def _detection_callback(
        self, device: BLEDevice, adv_data: AdvertisementData
    ) -> None:
        service_uuids = adv_data.service_uuids or []
        name = adv_data.local_name or device.name

        if self.bms_only and not is_likely_bms(name, service_uuids):
            return

        device_type = identify_device(name, service_uuids, adv_data.manufacturer_data)

        if device.address in self._discovered:
            existing = self._discovered[device.address]
            existing.rssi = adv_data.rssi or -100
            existing.last_seen = time.time()
            return

        bms_device = BMSDevice(
            address=device.address,
            name=name,
            rssi=adv_data.rssi or -100,
            device_type=device_type,
            service_uuids=list(service_uuids),
            manufacturer_data=dict(adv_data.manufacturer_data or {}),
        )
        self._discovered[device.address] = bms_device
        logger.info("Found BMS device: %s (%s)", name, device.address)

        for callback in self._callbacks:
            try:
                callback(bms_device)
            except Exception:
                logger.exception("Callback error for device %s", device.address)

    async def scan_once(self) -> list[BMSDevice]:
        self._discovered.clear()
        scanner = BleakScanner(detection_callback=self._detection_callback)
        await scanner.start()
        await asyncio.sleep(self.scan_duration)
        await scanner.stop()
        return list(self._discovered.values())

    async def scan_continuous(
        self, interval: float = 5.0
    ) -> AsyncIterator[list[BMSDevice]]:
        scanner = BleakScanner(detection_callback=self._detection_callback)
        await scanner.start()
        try:
            while True:
                await asyncio.sleep(interval)
                yield list(self._discovered.values())
        finally:
            await scanner.stop()

    @property
    def discovered_devices(self) -> list[BMSDevice]:
        return list(self._discovered.values())

    def clear(self) -> None:
        self._discovered.clear()
