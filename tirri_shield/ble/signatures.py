"""Known BMS device signatures for identification and vulnerability detection.

Contains BLE service UUIDs, manufacturer IDs, and name patterns used by
common Chinese BMS units found in Indian e-rickshaws (tirris).
"""

from __future__ import annotations

from dataclasses import dataclass

from tirri_shield.models import DeviceType


@dataclass(frozen=True)
class BMSSignature:
    device_type: DeviceType
    name_patterns: tuple[str, ...]
    service_uuids: tuple[str, ...]
    manufacturer_ids: tuple[int, ...] = ()
    description: str = ""
    known_vulnerable: bool = False


KNOWN_SIGNATURES: list[BMSSignature] = [
    BMSSignature(
        device_type=DeviceType.BMS_DALY,
        name_patterns=("daly",),
        service_uuids=(
            "0000fff0-0000-1000-8000-00805f9b34fb",
        ),
        description="Daly Smart BMS - common in aftermarket lithium conversions",
        known_vulnerable=True,
    ),
    BMSSignature(
        device_type=DeviceType.BMS_ANT,
        name_patterns=("ant-", "antbms"),
        service_uuids=(),
        description="ANT BMS - used in some e-rickshaw and e-scooter packs",
        known_vulnerable=True,
    ),
    BMSSignature(
        device_type=DeviceType.BMS_JIKONG,
        name_patterns=("jk-", "jkbms", "jk_b"),
        service_uuids=(
            "0000fee7-0000-1000-8000-00805f9b34fb",
        ),
        description="JiKong/JK BMS - another common Chinese BMS brand",
        known_vulnerable=True,
    ),
    BMSSignature(
        device_type=DeviceType.BMS_JBD,
        name_patterns=("xiaoxiang", "jbd-", "sp0", "sp1"),
        service_uuids=(
            "0000ff00-0000-1000-8000-00805f9b34fb",
        ),
        description="JBD/Xiaoxiang Smart BMS - widely used in budget e-rickshaw battery packs",
        known_vulnerable=True,
    ),
]

GENERIC_BMS_SERVICE_UUIDS = {
    "0000ff00-0000-1000-8000-00805f9b34fb",
    "0000ffe0-0000-1000-8000-00805f9b34fb",
    "0000fff0-0000-1000-8000-00805f9b34fb",
    "0000fee7-0000-1000-8000-00805f9b34fb",
}

BMS_NAME_KEYWORDS = (
    "bms",
    "battery",
    "bat-",
    "bat_",
    "xiaoxiang",
    "daly",
    "jbd",
    "ant-",
    "antbms",
    "jk-",
    "jkbms",
    "smart bms",
    "sp0",
    "sp1",
    "grenergy",
)


def identify_device(
    name: str | None,
    service_uuids: list[str],
    manufacturer_data: dict[int, bytes] | None = None,
) -> DeviceType:
    name_lower = (name or "").lower()

    for sig in KNOWN_SIGNATURES:
        for pattern in sig.name_patterns:
            if pattern in name_lower:
                return sig.device_type
        for uuid in sig.service_uuids:
            if uuid in service_uuids:
                return sig.device_type

    if any(kw in name_lower for kw in BMS_NAME_KEYWORDS):
        return DeviceType.BMS_GENERIC
    if any(uuid in GENERIC_BMS_SERVICE_UUIDS for uuid in service_uuids):
        return DeviceType.BMS_GENERIC

    return DeviceType.UNKNOWN


def is_likely_bms(
    name: str | None,
    service_uuids: list[str],
) -> bool:
    return identify_device(name, service_uuids) != DeviceType.UNKNOWN


def get_signature(device_type: DeviceType) -> BMSSignature | None:
    for sig in KNOWN_SIGNATURES:
        if sig.device_type == device_type:
            return sig
    return None
