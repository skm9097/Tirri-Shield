"""Tests for data models."""

from tirri_shield.models import (
    BMSDevice,
    DeviceType,
    SecurityFinding,
    SecurityLevel,
    SecurityReport,
)


class TestBMSDevice:
    def test_signal_strength_excellent(self):
        device = BMSDevice(address="AA:BB:CC:DD:EE:FF", name="test", rssi=-45)
        assert device.signal_strength == "Excellent"

    def test_signal_strength_good(self):
        device = BMSDevice(address="AA:BB:CC:DD:EE:FF", name="test", rssi=-55)
        assert device.signal_strength == "Good"

    def test_signal_strength_fair(self):
        device = BMSDevice(address="AA:BB:CC:DD:EE:FF", name="test", rssi=-65)
        assert device.signal_strength == "Fair"

    def test_signal_strength_weak(self):
        device = BMSDevice(address="AA:BB:CC:DD:EE:FF", name="test", rssi=-80)
        assert device.signal_strength == "Weak"

    def test_estimated_distance(self):
        device = BMSDevice(address="AA:BB:CC:DD:EE:FF", name="test", rssi=-59)
        assert device.estimated_distance_m >= 0

    def test_estimated_distance_zero_rssi(self):
        device = BMSDevice(address="AA:BB:CC:DD:EE:FF", name="test", rssi=0)
        assert device.estimated_distance_m == -1.0

    def test_default_device_type(self):
        device = BMSDevice(address="AA:BB:CC:DD:EE:FF", name="test", rssi=-60)
        assert device.device_type == DeviceType.UNKNOWN

    def test_default_security_level(self):
        device = BMSDevice(address="AA:BB:CC:DD:EE:FF", name="test", rssi=-60)
        assert device.security_level == SecurityLevel.CRITICAL


class TestSecurityReport:
    def test_compute_overall_level_critical(self, vulnerable_bms_device):
        report = SecurityReport(device=vulnerable_bms_device)
        report.findings.append(
            SecurityFinding(
                title="No Auth",
                description="test",
                severity=SecurityLevel.CRITICAL,
                recommendation="fix it",
                device=vulnerable_bms_device,
            )
        )
        assert report.compute_overall_level() == SecurityLevel.CRITICAL

    def test_compute_overall_level_empty(self, vulnerable_bms_device):
        report = SecurityReport(device=vulnerable_bms_device)
        assert report.compute_overall_level() == SecurityLevel.SECURE

    def test_compute_overall_level_mixed(self, vulnerable_bms_device):
        report = SecurityReport(device=vulnerable_bms_device)
        report.findings.append(
            SecurityFinding(
                title="Medium Issue",
                description="test",
                severity=SecurityLevel.MEDIUM,
                recommendation="fix it",
                device=vulnerable_bms_device,
            )
        )
        report.findings.append(
            SecurityFinding(
                title="High Issue",
                description="test",
                severity=SecurityLevel.HIGH,
                recommendation="fix it",
                device=vulnerable_bms_device,
            )
        )
        assert report.compute_overall_level() == SecurityLevel.HIGH

    def test_compute_overall_level_low_only(self, vulnerable_bms_device):
        report = SecurityReport(device=vulnerable_bms_device)
        report.findings.append(
            SecurityFinding(
                title="Low Issue",
                description="test",
                severity=SecurityLevel.LOW,
                recommendation="minor fix",
                device=vulnerable_bms_device,
            )
        )
        assert report.compute_overall_level() == SecurityLevel.LOW
