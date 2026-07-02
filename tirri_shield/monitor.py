"""Real-time BLE monitoring for unauthorized connection attempts to BMS devices.

Detection strategy:
- Continuously scans for BLE devices
- Tracks which devices are present and their RSSI
- Detects new devices appearing (potential attacker phone)
- Detects RSSI changes (device approaching)
- If monitoring a specific BMS, detects when it stops advertising
  (indicates someone else connected to it)
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from collections.abc import Callable

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from tirri_shield.ble.signatures import identify_device, is_likely_bms
from tirri_shield.models import AlertEvent, BMSDevice, ConnectionEvent, SecurityLevel

logger = logging.getLogger(__name__)

MISSED_CYCLES_BEFORE_ALERT = 3
MAX_STORED_EVENTS = 1000


class BLEMonitor:
    """Monitors BLE environment for unauthorized access to BMS devices."""

    def __init__(
        self,
        target_address: str | None = None,
        authorized_addresses: list[str] | None = None,
        poll_interval: float = 5.0,
        rssi_change_threshold: int = 20,
    ):
        self.target_address = target_address
        self.authorized_addresses = set(authorized_addresses or [])
        self.poll_interval = poll_interval
        self.rssi_change_threshold = rssi_change_threshold

        self._known_devices: dict[str, BMSDevice] = {}
        self._missed_cycles: dict[str, int] = {}
        self._alert_callbacks: list[Callable[[AlertEvent], None]] = []
        self._event_callbacks: list[Callable[[ConnectionEvent], None]] = []
        self._running = False
        self._alerts: deque[AlertEvent] = deque(maxlen=MAX_STORED_EVENTS)
        self._events: deque[ConnectionEvent] = deque(maxlen=MAX_STORED_EVENTS)

    def on_alert(self, callback: Callable[[AlertEvent], None]) -> None:
        self._alert_callbacks.append(callback)

    def on_event(self, callback: Callable[[ConnectionEvent], None]) -> None:
        self._event_callbacks.append(callback)

    async def start(self) -> None:
        self._running = True
        logger.info("Starting BLE monitor (interval: %.1fs)", self.poll_interval)
        if self.target_address:
            logger.info("Monitoring target: %s", self.target_address)

        while self._running:
            try:
                await self._scan_cycle()
            except Exception:
                logger.exception("Monitor scan cycle failed")
            await asyncio.sleep(self.poll_interval)

    async def stop(self) -> None:
        self._running = False
        logger.info("Monitor stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def alerts(self) -> list[AlertEvent]:
        return list(self._alerts)

    @property
    def events(self) -> list[ConnectionEvent]:
        return list(self._events)

    @property
    def known_devices(self) -> dict[str, BMSDevice]:
        return dict(self._known_devices)

    async def _scan_cycle(self) -> None:
        current_scan: dict[str, BMSDevice] = {}

        def detection_callback(device: BLEDevice, adv_data: AdvertisementData) -> None:
            name = adv_data.local_name or device.name
            service_uuids = list(adv_data.service_uuids or [])
            device_type = identify_device(name, service_uuids)
            bms_device = BMSDevice(
                address=device.address,
                name=name,
                rssi=adv_data.rssi or -100,
                device_type=device_type,
                service_uuids=service_uuids,
                manufacturer_data=dict(adv_data.manufacturer_data or {}),
            )
            current_scan[device.address] = bms_device

        scanner = BleakScanner(detection_callback=detection_callback)
        await scanner.start()
        await asyncio.sleep(min(self.poll_interval, 3.0))
        await scanner.stop()

        self._check_new_devices(current_scan)
        self._check_rssi_changes(current_scan)
        self._check_target_disappeared(current_scan)
        self._update_known_devices(current_scan)

    def _check_new_devices(self, current: dict[str, BMSDevice]) -> None:
        for addr, device in current.items():
            if addr in self._known_devices:
                continue
            if addr in self.authorized_addresses:
                continue

            if is_likely_bms(device.name, device.service_uuids):
                alert = AlertEvent(
                    message=f"New BMS device detected: {device.name or 'Unknown'} ({addr})",
                    severity=SecurityLevel.MEDIUM,
                    device=device,
                )
                self._emit_alert(alert)
            else:
                event = ConnectionEvent(
                    device_address=addr,
                    device_name=device.name,
                    event_type="new_device",
                    details=f"New BLE device appeared: {device.name or 'Unknown'}",
                )
                self._emit_event(event)

    def _check_rssi_changes(self, current: dict[str, BMSDevice]) -> None:
        for addr, device in current.items():
            if addr not in self._known_devices:
                continue

            old_rssi = self._known_devices[addr].rssi
            new_rssi = device.rssi
            delta = new_rssi - old_rssi

            if delta > self.rssi_change_threshold:
                alert = AlertEvent(
                    message=(
                        f"Device approaching: {device.name or addr} "
                        f"(RSSI: {old_rssi} -> {new_rssi} dBm, +{delta})"
                    ),
                    severity=SecurityLevel.HIGH if delta > 30 else SecurityLevel.MEDIUM,
                    device=device,
                )
                self._emit_alert(alert)

    def _check_target_disappeared(self, current: dict[str, BMSDevice]) -> None:
        if not self.target_address:
            return

        if self.target_address in current:
            self._missed_cycles[self.target_address] = 0
            return

        missed = self._missed_cycles.get(self.target_address, 0) + 1
        self._missed_cycles[self.target_address] = missed

        if missed == MISSED_CYCLES_BEFORE_ALERT:
            target_device = self._known_devices.get(self.target_address)
            alert = AlertEvent(
                message=(
                    f"ALERT: Target BMS {self.target_address} has stopped advertising! "
                    "This may indicate an unauthorized device has connected to it."
                ),
                severity=SecurityLevel.CRITICAL,
                device=target_device,
            )
            self._emit_alert(alert)

    def _update_known_devices(self, current: dict[str, BMSDevice]) -> None:
        for addr, device in current.items():
            device.last_seen = time.time()
            self._known_devices[addr] = device

    def _emit_alert(self, alert: AlertEvent) -> None:
        self._alerts.append(alert)
        logger.warning("ALERT [%s]: %s", alert.severity.value, alert.message)
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception:
                logger.exception("Alert callback error")

    def _emit_event(self, event: ConnectionEvent) -> None:
        self._events.append(event)
        logger.info("EVENT: %s", event.details)
        for callback in self._event_callbacks:
            try:
                callback(event)
            except Exception:
                logger.exception("Event callback error")
