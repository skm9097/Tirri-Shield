"""Security analysis engine for BMS devices."""

from __future__ import annotations

import logging

from tirri_shield.ble.inspector import inspect_device
from tirri_shield.ble.signatures import get_signature
from tirri_shield.models import BMSDevice, SecurityFinding, SecurityLevel, SecurityReport

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """Analyzes BMS devices for security vulnerabilities."""

    def analyze(self, device: BMSDevice) -> SecurityReport:
        report = SecurityReport(device=device)
        self._check_authentication(device, report)
        self._check_encryption(device, report)
        self._check_known_vulnerable(device, report)
        self._check_signal_exposure(device, report)
        self._check_device_name_exposure(device, report)
        report.compute_overall_level()
        return report

    async def deep_analyze(self, device: BMSDevice) -> SecurityReport:
        report = SecurityReport(device=device)

        result = await inspect_device(device)

        if result.connected_without_auth:
            report.findings.append(SecurityFinding(
                title="No Authentication Required",
                description=(
                    "Connected to device without any PIN, password, or pairing "
                    "verification. Any nearby phone with a BMS app (e.g., BAT-BMS) "
                    "can connect and potentially control this device."
                ),
                severity=SecurityLevel.CRITICAL,
                recommendation=(
                    "Contact the battery/BMS manufacturer to request a firmware "
                    "update that requires PIN-based pairing. As a temporary measure, "
                    "consider physically disconnecting the Bluetooth module."
                ),
                device=device,
            ))

        if result.has_unprotected_control:
            report.findings.append(SecurityFinding(
                title="Unprotected Control Characteristics",
                description=(
                    "Found writable BLE characteristics that likely control power "
                    "output (discharge switch). An attacker can write to these "
                    "to remotely disable the vehicle's motor."
                ),
                severity=SecurityLevel.CRITICAL,
                recommendation=(
                    "This is the primary vulnerability exploited by the BAT-BMS prank. "
                    "The discharge function should require authenticated access. "
                    "Physically disconnect the Bluetooth module or replace the BMS "
                    "with one that has proper access control."
                ),
                device=device,
            ))

        if result.has_writable_characteristics and not result.has_unprotected_control:
            report.findings.append(SecurityFinding(
                title="Writable Characteristics Detected",
                description=(
                    f"Found {result.writable_count} writable BLE characteristic(s). "
                    "While not confirmed as control functions, any writable "
                    "characteristic could potentially be abused."
                ),
                severity=SecurityLevel.HIGH,
                recommendation=(
                    "Investigate what these characteristics control. If they include "
                    "power management functions, treat them as critical vulnerabilities."
                ),
                device=device,
            ))

        if result.error:
            report.findings.append(SecurityFinding(
                title="Inspection Incomplete",
                description=f"Could not complete deep inspection: {result.error}",
                severity=SecurityLevel.MEDIUM,
                recommendation="Retry the scan when closer to the device.",
                device=device,
            ))

        report.compute_overall_level()
        return report

    def _check_authentication(self, device: BMSDevice, report: SecurityReport) -> None:
        if not device.has_authentication:
            report.findings.append(SecurityFinding(
                title="No BLE Authentication",
                description=(
                    "This BMS device does not require authentication for BLE "
                    "connections. Anyone within Bluetooth range (~15m) can connect "
                    "using apps like BAT-BMS, Smart BMS, or similar tools."
                ),
                severity=SecurityLevel.CRITICAL,
                recommendation=(
                    "1. Check if the BMS firmware supports PIN pairing and enable it.\n"
                    "2. If no PIN support exists, physically disconnect or shield the "
                    "Bluetooth module.\n"
                    "3. Consider replacing the BMS with a model that supports "
                    "authenticated BLE access."
                ),
                device=device,
            ))

    def _check_encryption(self, device: BMSDevice, report: SecurityReport) -> None:
        if not device.has_encryption:
            report.findings.append(SecurityFinding(
                title="No BLE Encryption",
                description=(
                    "BLE communication is not encrypted. Data including battery "
                    "status, cell voltages, and control commands are transmitted "
                    "in plaintext, making them vulnerable to interception and replay."
                ),
                severity=SecurityLevel.HIGH,
                recommendation=(
                    "Enable BLE Secure Connections (LE Secure Connections) if "
                    "supported by the BMS firmware. This provides AES-CCM encryption "
                    "for all GATT traffic."
                ),
                device=device,
            ))

    def _check_known_vulnerable(self, device: BMSDevice, report: SecurityReport) -> None:
        sig = get_signature(device.device_type)
        if sig and sig.known_vulnerable:
            report.findings.append(SecurityFinding(
                title=f"Known Vulnerable BMS: {sig.device_type.value}",
                description=(
                    f"This device matches the signature of {sig.description}. "
                    "This BMS type is known to be vulnerable to unauthorized "
                    "remote control via apps like BAT-BMS."
                ),
                severity=SecurityLevel.CRITICAL,
                recommendation=(
                    "This specific BMS type has been confirmed vulnerable to the "
                    "BAT-BMS discharge attack. Immediate protective action is needed:\n"
                    "1. Physically disconnect the Bluetooth module from the BMS.\n"
                    "2. Install a Bluetooth signal blocker/shield around the BMS.\n"
                    "3. Contact the manufacturer for a security firmware update.\n"
                    "4. Consider upgrading to a BMS with proper security features."
                ),
                device=device,
            ))

    def _check_signal_exposure(self, device: BMSDevice, report: SecurityReport) -> None:
        if device.rssi >= -60:
            report.findings.append(SecurityFinding(
                title="Strong BLE Signal Exposure",
                description=(
                    f"Device has a strong signal (RSSI: {device.rssi} dBm, "
                    f"est. distance: {device.estimated_distance_m:.1f}m). "
                    "Strong signals make the device easily discoverable from "
                    "further away, increasing the attack surface."
                ),
                severity=SecurityLevel.MEDIUM,
                recommendation=(
                    "Consider shielding the BMS Bluetooth antenna to reduce signal "
                    "range. A metal enclosure or Faraday-type shielding can limit "
                    "the effective range to within the vehicle body."
                ),
                device=device,
            ))

    def _check_device_name_exposure(
        self, device: BMSDevice, report: SecurityReport
    ) -> None:
        if device.name and any(
            kw in device.name.lower()
            for kw in ("bms", "battery", "xiaoxiang", "daly", "jbd", "smart bms")
        ):
            report.findings.append(SecurityFinding(
                title="Identifiable BMS Device Name",
                description=(
                    f'Device broadcasts name "{device.name}" which clearly '
                    "identifies it as a BMS. This makes it trivial for attackers "
                    "to locate target devices using scanning apps."
                ),
                severity=SecurityLevel.MEDIUM,
                recommendation=(
                    "If the BMS firmware allows it, change the device name to "
                    "something non-descriptive. Some BMS units allow name changes "
                    "via their companion app before being locked down."
                ),
                device=device,
            ))
