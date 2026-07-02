"""Data models for Tirri-Shield."""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field


class SecurityLevel(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SECURE = "secure"


class DeviceType(enum.Enum):
    BMS_GENERIC = "Generic BMS"
    BMS_DALY = "Daly BMS"
    BMS_JBD = "JBD/Xiaoxiang BMS"
    BMS_ANT = "ANT BMS"
    BMS_JIKONG = "JiKong BMS"
    UNKNOWN = "Unknown"


@dataclass
class BMSDevice:
    address: str
    name: str | None
    rssi: int
    device_type: DeviceType = DeviceType.UNKNOWN
    security_level: SecurityLevel = SecurityLevel.CRITICAL
    is_connectable: bool = True
    has_authentication: bool = False
    has_encryption: bool = False
    has_bonding: bool = False
    service_uuids: list[str] = field(default_factory=list)
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    connection_count: int = 0

    @property
    def signal_strength(self) -> str:
        if self.rssi >= -50:
            return "Excellent"
        if self.rssi >= -60:
            return "Good"
        if self.rssi >= -70:
            return "Fair"
        return "Weak"

    @property
    def estimated_distance_m(self) -> float:
        tx_power = -59
        if self.rssi >= 0:
            return -1.0
        ratio = self.rssi / tx_power
        if ratio < 1.0:
            return ratio**10
        return 0.89976 * (ratio**7.7095) + 0.111


@dataclass
class SecurityFinding:
    title: str
    description: str
    severity: SecurityLevel
    recommendation: str
    device: BMSDevice


@dataclass
class SecurityReport:
    device: BMSDevice
    findings: list[SecurityFinding] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    overall_level: SecurityLevel = SecurityLevel.CRITICAL

    def compute_overall_level(self) -> SecurityLevel:
        if not self.findings:
            return SecurityLevel.SECURE
        severity_order = [
            SecurityLevel.CRITICAL,
            SecurityLevel.HIGH,
            SecurityLevel.MEDIUM,
            SecurityLevel.LOW,
        ]
        for level in severity_order:
            if any(f.severity == level for f in self.findings):
                self.overall_level = level
                return level
        self.overall_level = SecurityLevel.SECURE
        return SecurityLevel.SECURE


@dataclass
class ConnectionEvent:
    device_address: str
    device_name: str | None
    timestamp: float = field(default_factory=time.time)
    is_authorized: bool = False
    event_type: str = "connection_attempt"
    details: str = ""


@dataclass
class AlertEvent:
    message: str
    severity: SecurityLevel
    device: BMSDevice | None = None
    timestamp: float = field(default_factory=time.time)
    acknowledged: bool = False
