"""Tests for the BLE monitor."""

from tirri_shield.models import BMSDevice, SecurityLevel
from tirri_shield.monitor import BLEMonitor, MISSED_CYCLES_BEFORE_ALERT


class TestBLEMonitor:
    def test_init_defaults(self):
        monitor = BLEMonitor()
        assert monitor.target_address is None
        assert monitor.poll_interval == 5.0
        assert not monitor.is_running
        assert len(monitor.alerts) == 0

    def test_init_with_target(self):
        monitor = BLEMonitor(target_address="AA:BB:CC:DD:EE:FF")
        assert monitor.target_address == "AA:BB:CC:DD:EE:FF"

    def test_init_with_authorized(self):
        monitor = BLEMonitor(authorized_addresses=["11:22:33:44:55:66"])
        assert "11:22:33:44:55:66" in monitor.authorized_addresses

    def test_new_bms_device_triggers_alert(self, vulnerable_bms_device):
        monitor = BLEMonitor()
        alerts = []
        monitor.on_alert(lambda a: alerts.append(a))

        current = {vulnerable_bms_device.address: vulnerable_bms_device}
        monitor._check_new_devices(current)

        assert len(alerts) == 1
        assert "BMS" in alerts[0].message

    def test_authorized_device_no_alert(self, vulnerable_bms_device):
        monitor = BLEMonitor(
            authorized_addresses=[vulnerable_bms_device.address]
        )
        alerts = []
        monitor.on_alert(lambda a: alerts.append(a))

        current = {vulnerable_bms_device.address: vulnerable_bms_device}
        monitor._check_new_devices(current)

        assert len(alerts) == 0

    def test_known_device_no_alert(self, vulnerable_bms_device):
        monitor = BLEMonitor()
        monitor._known_devices[vulnerable_bms_device.address] = vulnerable_bms_device
        alerts = []
        monitor.on_alert(lambda a: alerts.append(a))

        current = {vulnerable_bms_device.address: vulnerable_bms_device}
        monitor._check_new_devices(current)

        assert len(alerts) == 0

    def test_rssi_increase_triggers_alert(self, vulnerable_bms_device):
        monitor = BLEMonitor(rssi_change_threshold=10)

        old_device = BMSDevice(
            address=vulnerable_bms_device.address,
            name=vulnerable_bms_device.name,
            rssi=-80,
        )
        monitor._known_devices[old_device.address] = old_device

        alerts = []
        monitor.on_alert(lambda a: alerts.append(a))

        approaching = BMSDevice(
            address=vulnerable_bms_device.address,
            name=vulnerable_bms_device.name,
            rssi=-50,
        )
        current = {approaching.address: approaching}
        monitor._check_rssi_changes(current)

        assert len(alerts) == 1
        assert "approaching" in alerts[0].message.lower()

    def test_small_rssi_change_no_alert(self, vulnerable_bms_device):
        monitor = BLEMonitor(rssi_change_threshold=20)

        old_device = BMSDevice(
            address=vulnerable_bms_device.address,
            name=vulnerable_bms_device.name,
            rssi=-70,
        )
        monitor._known_devices[old_device.address] = old_device

        alerts = []
        monitor.on_alert(lambda a: alerts.append(a))

        slightly_closer = BMSDevice(
            address=vulnerable_bms_device.address,
            name=vulnerable_bms_device.name,
            rssi=-60,
        )
        current = {slightly_closer.address: slightly_closer}
        monitor._check_rssi_changes(current)

        assert len(alerts) == 0

    def test_target_disappeared_triggers_critical_alert(self):
        target_addr = "AA:BB:CC:DD:EE:FF"
        monitor = BLEMonitor(target_address=target_addr)
        monitor._known_devices[target_addr] = BMSDevice(
            address=target_addr, name="TestBMS", rssi=-60
        )

        alerts = []
        monitor.on_alert(lambda a: alerts.append(a))

        for _ in range(MISSED_CYCLES_BEFORE_ALERT):
            monitor._check_target_disappeared({})

        assert len(alerts) == 1
        assert alerts[0].severity == SecurityLevel.CRITICAL
        assert "stopped advertising" in alerts[0].message

    def test_target_present_no_alert(self):
        target_addr = "AA:BB:CC:DD:EE:FF"
        monitor = BLEMonitor(target_address=target_addr)
        target_device = BMSDevice(
            address=target_addr, name="TestBMS", rssi=-60
        )

        alerts = []
        monitor.on_alert(lambda a: alerts.append(a))

        current = {target_addr: target_device}
        monitor._check_target_disappeared(current)

        assert len(alerts) == 0

    def test_no_target_no_disappearance_check(self):
        monitor = BLEMonitor()
        alerts = []
        monitor.on_alert(lambda a: alerts.append(a))

        monitor._check_target_disappeared({})
        assert len(alerts) == 0

    def test_event_callback(self, non_bms_device):
        monitor = BLEMonitor()
        events = []
        monitor.on_event(lambda e: events.append(e))

        current = {non_bms_device.address: non_bms_device}
        monitor._check_new_devices(current)

        assert len(events) == 1
        assert events[0].event_type == "new_device"
