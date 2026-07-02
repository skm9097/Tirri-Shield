"""Tests for the security analyzer."""

from tirri_shield.analyzer import SecurityAnalyzer
from tirri_shield.models import BMSDevice, DeviceType, SecurityLevel


class TestSecurityAnalyzer:
    def setup_method(self):
        self.analyzer = SecurityAnalyzer()

    def test_analyze_vulnerable_device(self, vulnerable_bms_device):
        report = self.analyzer.analyze(vulnerable_bms_device)
        assert report.overall_level == SecurityLevel.CRITICAL
        assert len(report.findings) > 0

    def test_analyze_secure_device(self, secure_bms_device):
        report = self.analyzer.analyze(secure_bms_device)
        assert report.overall_level != SecurityLevel.CRITICAL
        auth_findings = [
            f for f in report.findings if "Authentication" in f.title
        ]
        assert len(auth_findings) == 0

    def test_no_auth_finding(self, vulnerable_bms_device):
        report = self.analyzer.analyze(vulnerable_bms_device)
        auth_findings = [
            f for f in report.findings if "Authentication" in f.title
        ]
        assert len(auth_findings) == 1
        assert auth_findings[0].severity == SecurityLevel.CRITICAL

    def test_no_encryption_finding(self, vulnerable_bms_device):
        report = self.analyzer.analyze(vulnerable_bms_device)
        enc_findings = [
            f for f in report.findings if "Encryption" in f.title
        ]
        assert len(enc_findings) == 1
        assert enc_findings[0].severity == SecurityLevel.HIGH

    def test_known_vulnerable_finding(self, vulnerable_bms_device):
        report = self.analyzer.analyze(vulnerable_bms_device)
        vuln_findings = [
            f for f in report.findings if "Known Vulnerable" in f.title
        ]
        assert len(vuln_findings) == 1

    def test_strong_signal_finding(self, daly_bms_device):
        report = self.analyzer.analyze(daly_bms_device)
        signal_findings = [
            f for f in report.findings if "Signal" in f.title
        ]
        assert len(signal_findings) == 1

    def test_identifiable_name_finding(self, vulnerable_bms_device):
        report = self.analyzer.analyze(vulnerable_bms_device)
        name_findings = [
            f for f in report.findings if "Name" in f.title
        ]
        assert len(name_findings) == 1

    def test_recommendations_present(self, vulnerable_bms_device):
        report = self.analyzer.analyze(vulnerable_bms_device)
        for finding in report.findings:
            assert finding.recommendation
            assert len(finding.recommendation) > 10

    def test_device_without_bms_keywords_in_name(self):
        device = BMSDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Generic-Device-123",
            rssi=-75,
            device_type=DeviceType.BMS_GENERIC,
            has_authentication=False,
            has_encryption=False,
        )
        report = self.analyzer.analyze(device)
        name_findings = [
            f for f in report.findings if "Name" in f.title
        ]
        assert len(name_findings) == 0

    def test_weak_signal_no_signal_finding(self):
        device = BMSDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="bms-test",
            rssi=-85,
            device_type=DeviceType.BMS_GENERIC,
            has_authentication=True,
            has_encryption=True,
        )
        report = self.analyzer.analyze(device)
        signal_findings = [
            f for f in report.findings if "Signal" in f.title
        ]
        assert len(signal_findings) == 0
