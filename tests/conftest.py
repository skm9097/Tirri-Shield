"""Shared test fixtures for Tirri-Shield tests."""

from __future__ import annotations

import pytest

from tirri_shield.models import BMSDevice, DeviceType


@pytest.fixture
def vulnerable_bms_device() -> BMSDevice:
    return BMSDevice(
        address="AA:BB:CC:DD:EE:01",
        name="xiaoxiang BMS",
        rssi=-55,
        device_type=DeviceType.BMS_JBD,
        is_connectable=True,
        has_authentication=False,
        has_encryption=False,
        service_uuids=["0000ff00-0000-1000-8000-00805f9b34fb"],
    )


@pytest.fixture
def secure_bms_device() -> BMSDevice:
    return BMSDevice(
        address="AA:BB:CC:DD:EE:02",
        name="SecureBMS-X1",
        rssi=-70,
        device_type=DeviceType.BMS_GENERIC,
        is_connectable=True,
        has_authentication=True,
        has_encryption=True,
        has_bonding=True,
        service_uuids=["0000ff00-0000-1000-8000-00805f9b34fb"],
    )


@pytest.fixture
def daly_bms_device() -> BMSDevice:
    return BMSDevice(
        address="AA:BB:CC:DD:EE:03",
        name="DalyBMS-4S",
        rssi=-45,
        device_type=DeviceType.BMS_DALY,
        is_connectable=True,
        has_authentication=False,
        has_encryption=False,
        service_uuids=["0000fff0-0000-1000-8000-00805f9b34fb"],
    )


@pytest.fixture
def non_bms_device() -> BMSDevice:
    return BMSDevice(
        address="AA:BB:CC:DD:EE:04",
        name="RandomSpeaker",
        rssi=-80,
        device_type=DeviceType.UNKNOWN,
        service_uuids=["0000110a-0000-1000-8000-00805f9b34fb"],
    )
