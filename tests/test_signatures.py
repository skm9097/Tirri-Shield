"""Tests for BMS device signature matching."""

from tirri_shield.ble.signatures import (
    identify_device,
    is_likely_bms,
    get_signature,
    KNOWN_SIGNATURES,
)
from tirri_shield.models import DeviceType


class TestIdentifyDevice:
    def test_jbd_by_name(self):
        result = identify_device("xiaoxiang BMS", [])
        assert result == DeviceType.BMS_JBD

    def test_jbd_by_service_uuid(self):
        result = identify_device(
            "Unknown", ["0000ff00-0000-1000-8000-00805f9b34fb"]
        )
        assert result == DeviceType.BMS_JBD

    def test_daly_by_name(self):
        result = identify_device("Daly-BMS-4S", [])
        assert result == DeviceType.BMS_DALY

    def test_daly_by_service_uuid(self):
        result = identify_device(
            None, ["0000fff0-0000-1000-8000-00805f9b34fb"]
        )
        assert result == DeviceType.BMS_DALY

    def test_ant_by_name(self):
        result = identify_device("ANT-BMS-48V", [])
        assert result == DeviceType.BMS_ANT

    def test_jikong_by_name(self):
        result = identify_device("JK-B2A8S20P", [])
        assert result == DeviceType.BMS_JIKONG

    def test_generic_bms_by_keyword(self):
        result = identify_device("battery monitor", [])
        assert result == DeviceType.BMS_GENERIC

    def test_generic_bms_by_uuid(self):
        result = identify_device(
            "NoName", ["0000ffe0-0000-1000-8000-00805f9b34fb"]
        )
        # Could match ANT or JiKong first since they use ffe0
        assert result != DeviceType.UNKNOWN

    def test_unknown_device(self):
        result = identify_device("MyHeadphones", [])
        assert result == DeviceType.UNKNOWN

    def test_none_name(self):
        result = identify_device(None, [])
        assert result == DeviceType.UNKNOWN

    def test_case_insensitive_name(self):
        result = identify_device("XIAOXIANG BMS", [])
        assert result == DeviceType.BMS_JBD

    def test_grenergy_keyword(self):
        result = identify_device("grenergy-module", [])
        assert result == DeviceType.BMS_GENERIC

    def test_sp0_pattern(self):
        result = identify_device("SP05-BMS", [])
        assert result == DeviceType.BMS_JBD


class TestIsLikelyBMS:
    def test_bms_device(self):
        assert is_likely_bms("xiaoxiang BMS", [])

    def test_non_bms_device(self):
        assert not is_likely_bms("AirPods", [])

    def test_bms_by_uuid(self):
        assert is_likely_bms(None, ["0000ff00-0000-1000-8000-00805f9b34fb"])

    def test_none_name_no_uuid(self):
        assert not is_likely_bms(None, [])


class TestGetSignature:
    def test_known_device_type(self):
        sig = get_signature(DeviceType.BMS_JBD)
        assert sig is not None
        assert sig.known_vulnerable is True

    def test_unknown_device_type(self):
        sig = get_signature(DeviceType.UNKNOWN)
        assert sig is None

    def test_all_known_signatures_marked_vulnerable(self):
        for sig in KNOWN_SIGNATURES:
            assert sig.known_vulnerable is True
