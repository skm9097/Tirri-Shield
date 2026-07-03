"""BLE GATT service inspector for security analysis of BMS devices."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from bleak import BleakClient

from tirri_shield.ble.signatures import GENERIC_BMS_SERVICE_UUIDS
from tirri_shield.models import BMSDevice

logger = logging.getLogger(__name__)


@dataclass
class CharacteristicInfo:
    uuid: str
    handle: int
    properties: list[str]
    is_writable: bool = False
    is_readable: bool = False
    is_notifiable: bool = False
    description: str = ""


@dataclass
class ServiceInfo:
    uuid: str
    characteristics: list[CharacteristicInfo] = field(default_factory=list)
    is_bms_related: bool = False


@dataclass
class InspectionResult:
    device: BMSDevice
    services: list[ServiceInfo] = field(default_factory=list)
    connected_without_auth: bool = False
    has_writable_characteristics: bool = False
    has_unprotected_control: bool = False
    error: str | None = None

    @property
    def total_characteristics(self) -> int:
        return sum(len(s.characteristics) for s in self.services)

    @property
    def writable_count(self) -> int:
        return sum(
            1
            for s in self.services
            for c in s.characteristics
            if c.is_writable
        )

    @property
    def bms_services(self) -> list[ServiceInfo]:
        return [s for s in self.services if s.is_bms_related]


CONTROL_CHARACTERISTIC_PATTERNS = (
    "0000ff02",
    "0000ff01",
    "0000ffe1",
    "0000fff2",
    "0000fff1",
)


async def inspect_device(device: BMSDevice, timeout: float = 10.0) -> InspectionResult:
    result = InspectionResult(device=device)

    try:
        async with BleakClient(device.address, timeout=timeout) as client:
            result.connected_without_auth = True
            logger.warning(
                "Connected to %s (%s) WITHOUT authentication",
                device.name,
                device.address,
            )

            for service in client.services:
                svc_info = ServiceInfo(
                    uuid=service.uuid,
                    is_bms_related=service.uuid in GENERIC_BMS_SERVICE_UUIDS,
                )

                for char in service.characteristics:
                    props = char.properties
                    char_info = CharacteristicInfo(
                        uuid=char.uuid,
                        handle=char.handle,
                        properties=list(props),
                        is_writable="write" in props or "write-without-response" in props,
                        is_readable="read" in props,
                        is_notifiable="notify" in props or "indicate" in props,
                    )

                    if char_info.is_writable:
                        result.has_writable_characteristics = True
                        for pattern in CONTROL_CHARACTERISTIC_PATTERNS:
                            if char.uuid.startswith(pattern):
                                result.has_unprotected_control = True
                                char_info.description = (
                                    "CRITICAL: Writable control characteristic — "
                                    "may allow discharge toggle"
                                )
                                break

                    svc_info.characteristics.append(char_info)

                result.services.append(svc_info)

    except Exception as e:
        result.error = str(e)
        logger.error("Inspection failed for %s: %s", device.address, e)

    return result
