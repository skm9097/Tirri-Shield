"""High-level scanner combining discovery and security assessment."""

from __future__ import annotations

import logging

from tirri_shield.analyzer import SecurityAnalyzer
from tirri_shield.ble.discovery import BMSDiscovery
from tirri_shield.models import BMSDevice, SecurityReport

logger = logging.getLogger(__name__)


class TirriScanner:
    """Scans for vulnerable BMS devices and produces security reports."""

    def __init__(
        self,
        scan_duration: float = 10.0,
        deep_inspect: bool = False,
    ):
        self.scan_duration = scan_duration
        self.deep_inspect = deep_inspect
        self._discovery = BMSDiscovery(scan_duration=scan_duration, bms_only=True)
        self._analyzer = SecurityAnalyzer()

    async def scan(self) -> list[SecurityReport]:
        logger.info("Starting BMS scan (duration: %.1fs)...", self.scan_duration)
        devices = await self._discovery.scan_once()
        logger.info("Found %d BMS device(s)", len(devices))

        reports = []
        for device in devices:
            report = self._analyzer.analyze(device)

            if self.deep_inspect:
                try:
                    deep_report = await self._analyzer.deep_analyze(device)
                    report.findings.extend(deep_report.findings)
                    report.compute_overall_level()
                except Exception:
                    logger.exception("Deep inspection failed for %s", device.address)

            reports.append(report)

        return reports

    async def scan_and_watch(
        self,
        on_device: callable | None = None,
        interval: float = 5.0,
    ) -> None:
        logger.info("Starting continuous BMS scan...")
        if on_device:
            self._discovery.on_device_found(on_device)

        async for devices in self._discovery.scan_continuous(interval=interval):
            for device in devices:
                self._analyzer.analyze(device)
                if on_device:
                    on_device(device)

    @property
    def discovered_devices(self) -> list[BMSDevice]:
        return self._discovery.discovered_devices
