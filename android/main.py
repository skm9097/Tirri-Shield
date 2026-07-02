"""Tirri-Shield Android App — BMS Security Scanner for E-Rickshaws.

Uses Kivy for UI and Android BLE APIs via pyjnius for Bluetooth scanning.
Falls back to bleak on desktop for development/testing.
"""

from __future__ import annotations

import os
import time
from functools import partial

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.metrics import dp
from kivy.properties import (
    BooleanProperty,
    ListProperty,
    NumericProperty,
    StringProperty,
)
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.scrollview import ScrollView

ANDROID = "ANDROID_ARGUMENT" in os.environ

if ANDROID:
    from android.permissions import Permission, request_permissions


# ---------------------------------------------------------------------------
# BLE Scanner abstraction
# ---------------------------------------------------------------------------

class BLEScanner:
    """Cross-platform BLE scanner: uses Android APIs on device, bleak on desktop."""

    def __init__(self):
        self.devices: list[dict] = []
        self.scanning = False
        self._on_device_callback = None
        self._on_scan_complete = None

    def set_callbacks(self, on_device=None, on_complete=None):
        self._on_device_callback = on_device
        self._on_scan_complete = on_complete

    def start_scan(self):
        self.devices.clear()
        self.scanning = True
        if ANDROID:
            self._start_android_scan()
        else:
            self._start_desktop_scan()

    def stop_scan(self):
        self.scanning = False
        if ANDROID:
            self._stop_android_scan()

    def _start_android_scan(self):
        from jnius import autoclass

        BluetoothAdapter = autoclass("android.bluetooth.BluetoothAdapter")
        BluetoothDevice = autoclass("android.bluetooth.BluetoothDevice")
        ScanCallback = autoclass("android.bluetooth.le.ScanCallback")

        adapter = BluetoothAdapter.getDefaultAdapter()
        if adapter is None or not adapter.isEnabled():
            if self._on_scan_complete:
                Clock.schedule_once(
                    lambda dt: self._on_scan_complete("Bluetooth not available or disabled"), 0
                )
            return

        scanner = adapter.getBluetoothLeScanner()
        if scanner is None:
            if self._on_scan_complete:
                Clock.schedule_once(
                    lambda dt: self._on_scan_complete("BLE scanner not available"), 0
                )
            return

        from android_ble_callback import TirriScanCallback

        self._callback = TirriScanCallback(self._on_android_device_found)
        scanner.startScan(self._callback)
        Clock.schedule_once(lambda dt: self._finish_android_scan(scanner), 10)

    def _on_android_device_found(self, address, name, rssi):
        device_info = {
            "address": address,
            "name": name or "Unknown",
            "rssi": rssi,
            "device_type": _classify_device(name),
            "signal_strength": _signal_strength(rssi),
            "vulnerabilities": _assess_vulnerabilities(name, rssi),
        }

        for existing in self.devices:
            if existing["address"] == address:
                existing.update(device_info)
                return
        self.devices.append(device_info)

        if self._on_device_callback:
            Clock.schedule_once(lambda dt: self._on_device_callback(device_info), 0)

    def _finish_android_scan(self, scanner):
        try:
            scanner.stopScan(self._callback)
        except Exception:
            pass
        self.scanning = False
        if self._on_scan_complete:
            self._on_scan_complete(None)

    def _stop_android_scan(self):
        if ANDROID:
            try:
                from jnius import autoclass

                BluetoothAdapter = autoclass("android.bluetooth.BluetoothAdapter")
                adapter = BluetoothAdapter.getDefaultAdapter()
                if adapter:
                    scanner = adapter.getBluetoothLeScanner()
                    if scanner and hasattr(self, "_callback"):
                        scanner.stopScan(self._callback)
            except Exception:
                pass

    def _start_desktop_scan(self):
        import asyncio
        import threading

        def _run_scan():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                devices = loop.run_until_complete(self._bleak_scan())
                loop.close()
            except Exception as e:
                Clock.schedule_once(
                    lambda dt: self._on_scan_complete(str(e)) if self._on_scan_complete else None,
                    0,
                )
                return

            self.scanning = False
            if self._on_scan_complete:
                Clock.schedule_once(lambda dt: self._on_scan_complete(None), 0)

        thread = threading.Thread(target=_run_scan, daemon=True)
        thread.start()

    async def _bleak_scan(self):
        from bleak import BleakScanner

        def detection_callback(device, adv_data):
            name = adv_data.local_name or device.name
            rssi = adv_data.rssi or -100
            device_info = {
                "address": device.address,
                "name": name or "Unknown",
                "rssi": rssi,
                "device_type": _classify_device(name),
                "signal_strength": _signal_strength(rssi),
                "vulnerabilities": _assess_vulnerabilities(name, rssi),
            }

            for existing in self.devices:
                if existing["address"] == device.address:
                    existing.update(device_info)
                    if self._on_device_callback:
                        Clock.schedule_once(lambda dt: self._on_device_callback(device_info), 0)
                    return
            self.devices.append(device_info)
            if self._on_device_callback:
                Clock.schedule_once(lambda dt: self._on_device_callback(device_info), 0)

        scanner = BleakScanner(detection_callback=detection_callback)
        await scanner.start()
        import asyncio

        await asyncio.sleep(10)
        await scanner.stop()
        return self.devices


# ---------------------------------------------------------------------------
# Device classification and security assessment (portable, no bleak needed)
# ---------------------------------------------------------------------------

BMS_NAME_PATTERNS = {
    "xiaoxiang": "JBD/Xiaoxiang BMS",
    "jbd-": "JBD/Xiaoxiang BMS",
    "sp0": "JBD/Xiaoxiang BMS",
    "sp1": "JBD/Xiaoxiang BMS",
    "daly": "Daly BMS",
    "ant-": "ANT BMS",
    "antbms": "ANT BMS",
    "jk-": "JiKong BMS",
    "jkbms": "JiKong BMS",
    "jk_b": "JiKong BMS",
    "bms": "Generic BMS",
    "battery": "Generic BMS",
    "bat-": "Generic BMS",
    "bat_": "Generic BMS",
    "smart bms": "Generic BMS",
    "grenergy": "Generic BMS",
}


def _classify_device(name: str | None) -> str:
    if not name:
        return "Unknown"
    lower = name.lower()
    for pattern, device_type in BMS_NAME_PATTERNS.items():
        if pattern in lower:
            return device_type
    return "Unknown"


def _signal_strength(rssi: int) -> str:
    if rssi >= -50:
        return "Excellent"
    if rssi >= -60:
        return "Good"
    if rssi >= -70:
        return "Fair"
    return "Weak"


def _assess_vulnerabilities(name: str | None, rssi: int) -> list[dict]:
    findings = []
    device_type = _classify_device(name)

    if device_type != "Unknown":
        findings.append({
            "title": "No BLE Authentication",
            "severity": "critical",
            "description": (
                "This BMS does not require authentication. Anyone nearby "
                "with a BMS app can connect and control it."
            ),
            "recommendation": (
                "Physically disconnect the Bluetooth module or upgrade "
                "to a BMS with PIN-based pairing."
            ),
        })
        findings.append({
            "title": "No BLE Encryption",
            "severity": "high",
            "description": (
                "Communication is unencrypted. Control commands are sent in plaintext."
            ),
            "recommendation": "Upgrade to a BMS supporting BLE Secure Connections.",
        })

    if device_type in ("JBD/Xiaoxiang BMS", "Daly BMS", "ANT BMS", "JiKong BMS"):
        findings.append({
            "title": f"Known Vulnerable: {device_type}",
            "severity": "critical",
            "description": (
                f"This {device_type} is confirmed vulnerable to the BAT-BMS "
                "discharge attack."
            ),
            "recommendation": (
                "1. Disconnect the Bluetooth module immediately.\n"
                "2. Install metal shielding around the BMS.\n"
                "3. Contact manufacturer for firmware update.\n"
                "4. Consider upgrading to a secure BMS."
            ),
        })

    if rssi >= -60 and device_type != "Unknown":
        findings.append({
            "title": "Strong Signal Exposure",
            "severity": "medium",
            "description": f"Strong BLE signal (RSSI: {rssi} dBm) makes this device easy to find.",
            "recommendation": "Shield the BMS antenna to reduce Bluetooth range.",
        })

    if name and device_type != "Unknown":
        lower = name.lower()
        if any(kw in lower for kw in ("bms", "battery", "xiaoxiang", "daly")):
            findings.append({
                "title": "Identifiable Device Name",
                "severity": "medium",
                "description": f'Broadcasting name "{name}" identifies it as a BMS target.',
                "recommendation": "Change the device name if firmware allows it.",
            })

    return findings


# ---------------------------------------------------------------------------
# Color constants
# ---------------------------------------------------------------------------

COLORS = {
    "bg": (0.05, 0.067, 0.09, 1),
    "card": (0.086, 0.106, 0.133, 1),
    "card_border": (0.188, 0.212, 0.247, 1),
    "accent": (0.345, 0.651, 1, 1),
    "text": (0.9, 0.929, 0.953, 1),
    "text_dim": (0.545, 0.58, 0.62, 1),
    "critical": (0.973, 0.318, 0.286, 1),
    "high": (0.941, 0.533, 0.243, 1),
    "medium": (0.824, 0.6, 0.133, 1),
    "secure": (0.247, 0.725, 0.314, 1),
}

SEVERITY_COLORS = {
    "critical": COLORS["critical"],
    "high": COLORS["high"],
    "medium": COLORS["medium"],
    "low": COLORS["accent"],
    "secure": COLORS["secure"],
}


# ---------------------------------------------------------------------------
# UI Widgets
# ---------------------------------------------------------------------------

class DeviceCard(BoxLayout):
    def __init__(self, device_info: dict, app_ref, **kwargs):
        super().__init__(**kwargs)
        self.orientation = "vertical"
        self.size_hint_y = None
        self.padding = [dp(12), dp(10)]
        self.spacing = dp(6)

        vulns = device_info.get("vulnerabilities", [])
        worst = "secure"
        for v in vulns:
            sev = v.get("severity", "low")
            if sev == "critical":
                worst = "critical"
                break
            if sev == "high" and worst not in ("critical",):
                worst = "high"
            if sev == "medium" and worst not in ("critical", "high"):
                worst = "medium"

        border_color = SEVERITY_COLORS.get(worst, COLORS["card_border"])

        from kivy.graphics import Color, Line, Rectangle

        with self.canvas.before:
            Color(*COLORS["card"])
            self._bg_rect = Rectangle(pos=self.pos, size=self.size)
            Color(*border_color)
            self._border_line = Line(
                rectangle=(self.pos[0], self.pos[1], self.size[0], self.size[1]),
                width=1.2,
            )

        self.bind(pos=self._update_canvas, size=self._update_canvas)

        header = BoxLayout(size_hint_y=None, height=dp(30))
        name_label = Label(
            text=device_info.get("name", "Unknown"),
            font_size=dp(15),
            bold=True,
            color=COLORS["text"],
            halign="left",
            valign="middle",
        )
        name_label.bind(size=name_label.setter("text_size"))
        header.add_widget(name_label)

        badge_text = worst.upper()
        badge = Label(
            text=f"  {badge_text}  ",
            font_size=dp(11),
            bold=True,
            color=(1, 1, 1, 1),
            size_hint_x=None,
            width=dp(80),
            halign="center",
            valign="middle",
        )
        badge.bind(size=badge.setter("text_size"))
        header.add_widget(badge)
        self.add_widget(header)

        meta_text = (
            f"Address: {device_info.get('address', 'N/A')}  |  "
            f"Type: {device_info.get('device_type', 'Unknown')}  |  "
            f"RSSI: {device_info.get('rssi', 'N/A')} dBm  |  "
            f"Signal: {device_info.get('signal_strength', 'N/A')}"
        )
        meta = Label(
            text=meta_text,
            font_size=dp(11),
            color=COLORS["text_dim"],
            size_hint_y=None,
            height=dp(20),
            halign="left",
            valign="middle",
        )
        meta.bind(size=meta.setter("text_size"))
        self.add_widget(meta)

        for vuln in vulns[:4]:
            sev = vuln.get("severity", "low")
            sev_color = SEVERITY_COLORS.get(sev, COLORS["text_dim"])
            finding_text = f"[{sev.upper()}] {vuln['title']}: {vuln['description']}"
            finding_label = Label(
                text=finding_text,
                font_size=dp(11),
                color=sev_color,
                size_hint_y=None,
                halign="left",
                valign="top",
                markup=False,
            )
            finding_label.bind(size=finding_label.setter("text_size"))
            finding_label.bind(
                texture_size=lambda inst, val: setattr(inst, "height", val[1] + dp(4))
            )
            self.add_widget(finding_label)

        detail_btn = Button(
            text="View Details & Recommendations",
            size_hint_y=None,
            height=dp(36),
            background_color=COLORS["accent"],
            color=(0, 0, 0, 1),
            font_size=dp(12),
            bold=True,
        )
        detail_btn.bind(on_press=lambda x: app_ref.show_device_detail(device_info))
        self.add_widget(detail_btn)

        total_h = dp(30) + dp(20) + dp(36) + dp(10) * 2 + dp(6) * (3 + len(vulns[:4]))
        for child in self.children:
            if hasattr(child, "height"):
                total_h += dp(4)
        self.height = max(total_h, dp(160))

    def _update_canvas(self, *args):
        self._bg_rect.pos = self.pos
        self._bg_rect.size = self.size
        self._border_line.rectangle = (
            self.pos[0], self.pos[1], self.size[0], self.size[1]
        )


class ScanScreen(Screen):
    pass


class MonitorScreen(Screen):
    pass


class InfoScreen(Screen):
    pass


class DetailScreen(Screen):
    pass


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------

class TirriShieldApp(App):
    scanning = BooleanProperty(False)
    monitoring = BooleanProperty(False)
    device_count = NumericProperty(0)
    status_text = StringProperty("Ready to scan")
    devices = ListProperty([])

    def build(self):
        self.title = "Tirri-Shield"

        if not ANDROID:
            Window.size = (400, 700)
            Window.clearcolor = COLORS["bg"]

        self.scanner = BLEScanner()
        self.scanner.set_callbacks(
            on_device=self._on_device_found,
            on_complete=self._on_scan_complete,
        )

        self.sm = ScreenManager()
        self.sm.add_widget(self._build_scan_screen())
        self.sm.add_widget(self._build_info_screen())
        self.sm.add_widget(self._build_detail_screen())

        root = BoxLayout(orientation="vertical")

        from kivy.graphics import Color, Rectangle

        with root.canvas.before:
            Color(*COLORS["bg"])
            self._root_bg = Rectangle(size=Window.size)
        root.bind(size=lambda w, s: setattr(self._root_bg, "size", s))

        header = self._build_header()
        root.add_widget(header)
        root.add_widget(self.sm)
        nav = self._build_nav()
        root.add_widget(nav)

        return root

    def _build_header(self):
        header = BoxLayout(
            size_hint_y=None,
            height=dp(56),
            padding=[dp(16), dp(8)],
        )
        from kivy.graphics import Color, Rectangle

        with header.canvas.before:
            Color(*COLORS["card"])
            self._header_bg = Rectangle(size=header.size, pos=header.pos)
        header.bind(
            size=lambda w, s: setattr(self._header_bg, "size", s),
            pos=lambda w, p: setattr(self._header_bg, "pos", p),
        )

        title = Label(
            text="Tirri-Shield",
            font_size=dp(20),
            bold=True,
            color=COLORS["accent"],
            halign="left",
            valign="middle",
        )
        title.bind(size=title.setter("text_size"))
        header.add_widget(title)

        self.status_label = Label(
            text=self.status_text,
            font_size=dp(12),
            color=COLORS["text_dim"],
            halign="right",
            valign="middle",
        )
        self.status_label.bind(size=self.status_label.setter("text_size"))
        self.bind(status_text=self.status_label.setter("text"))
        header.add_widget(self.status_label)

        return header

    def _build_nav(self):
        nav = BoxLayout(
            size_hint_y=None,
            height=dp(50),
        )
        from kivy.graphics import Color, Rectangle

        with nav.canvas.before:
            Color(*COLORS["card"])
            self._nav_bg = Rectangle(size=nav.size, pos=nav.pos)
        nav.bind(
            size=lambda w, s: setattr(self._nav_bg, "size", s),
            pos=lambda w, p: setattr(self._nav_bg, "pos", p),
        )

        scan_btn = Button(
            text="Scanner",
            background_color=COLORS["accent"],
            color=(0, 0, 0, 1),
            font_size=dp(13),
            bold=True,
        )
        scan_btn.bind(on_press=lambda x: setattr(self.sm, "current", "scan"))
        nav.add_widget(scan_btn)

        info_btn = Button(
            text="Protection Guide",
            background_color=COLORS["card_border"],
            color=COLORS["text"],
            font_size=dp(13),
        )
        info_btn.bind(on_press=lambda x: setattr(self.sm, "current", "info"))
        nav.add_widget(info_btn)

        return nav

    def _build_scan_screen(self):
        screen = ScanScreen(name="scan")
        layout = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(10))

        controls = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))

        self.scan_btn = Button(
            text="Scan for BMS Devices",
            background_color=COLORS["accent"],
            color=(0, 0, 0, 1),
            font_size=dp(14),
            bold=True,
        )
        self.scan_btn.bind(on_press=self._start_scan)
        controls.add_widget(self.scan_btn)
        layout.add_widget(controls)

        scroll = ScrollView()
        self.results_layout = BoxLayout(
            orientation="vertical",
            size_hint_y=None,
            spacing=dp(10),
            padding=[0, dp(4)],
        )
        self.results_layout.bind(
            minimum_height=self.results_layout.setter("height")
        )

        placeholder = Label(
            text="Tap 'Scan for BMS Devices' to search for\nvulnerable e-rickshaw BMS devices nearby.",
            font_size=dp(13),
            color=COLORS["text_dim"],
            halign="center",
            valign="middle",
            size_hint_y=None,
            height=dp(100),
        )
        placeholder.bind(size=placeholder.setter("text_size"))
        self.results_layout.add_widget(placeholder)

        scroll.add_widget(self.results_layout)
        layout.add_widget(scroll)

        screen.add_widget(layout)
        return screen

    def _build_info_screen(self):
        screen = InfoScreen(name="info")
        scroll = ScrollView()
        content = BoxLayout(
            orientation="vertical",
            size_hint_y=None,
            padding=dp(16),
            spacing=dp(12),
        )
        content.bind(minimum_height=content.setter("height"))

        sections = [
            (
                "What is the BAT-BMS Attack?",
                "A Chinese app called BAT-BMS is being used to remotely disable "
                "e-rickshaws (tirris/totos) by connecting to their Battery "
                "Management System (BMS) via Bluetooth and toggling the discharge "
                "switch, cutting power to the motor.",
            ),
            (
                "Why Are E-Rickshaws Vulnerable?",
                "Most budget BMS units have:\n"
                "- No Bluetooth authentication (no PIN/password)\n"
                "- No encryption on BLE communication\n"
                "- Open advertising (visible to anyone scanning)\n"
                "- Writable control characteristics (discharge switch)",
            ),
            (
                "Step 1: Disconnect Bluetooth (Immediate)",
                "Physically disconnect the Bluetooth module from your BMS. "
                "This is a small board/antenna inside the battery pack. "
                "Ask your mechanic or battery supplier for help. "
                "This completely eliminates the attack surface.",
            ),
            (
                "Step 2: Shield the BMS (Short-term)",
                "If you need Bluetooth for monitoring, wrap the BMS in "
                "metal shielding or use a metal enclosure to reduce "
                "Bluetooth signal range. Even partial shielding helps.",
            ),
            (
                "Step 3: Upgrade Your BMS (Long-term)",
                "Replace your BMS with one that supports PIN-based "
                "Bluetooth pairing and encrypted communication. "
                "Ask for 'secure BLE' or 'PIN-protected BMS'.",
            ),
            (
                "Step 4: Demand Better Standards",
                "Ask your battery and BMS supplier to provide firmware "
                "updates that add authentication. Report the issue to "
                "local transport authorities. Support industry standards "
                "for BMS security.",
            ),
        ]

        for title, body in sections:
            section_box = BoxLayout(
                orientation="vertical",
                size_hint_y=None,
                padding=dp(12),
                spacing=dp(6),
            )

            from kivy.graphics import Color, Rectangle

            with section_box.canvas.before:
                Color(*COLORS["card"])
                bg = Rectangle(size=section_box.size, pos=section_box.pos)
            section_box.bind(
                size=lambda w, s, r=bg: setattr(r, "size", s),
                pos=lambda w, p, r=bg: setattr(r, "pos", p),
            )

            title_label = Label(
                text=title,
                font_size=dp(15),
                bold=True,
                color=COLORS["accent"],
                size_hint_y=None,
                height=dp(24),
                halign="left",
                valign="middle",
            )
            title_label.bind(size=title_label.setter("text_size"))
            section_box.add_widget(title_label)

            body_label = Label(
                text=body,
                font_size=dp(12),
                color=COLORS["text"],
                size_hint_y=None,
                halign="left",
                valign="top",
            )
            body_label.bind(size=body_label.setter("text_size"))
            body_label.bind(
                texture_size=lambda inst, val: setattr(inst, "height", val[1] + dp(8))
            )
            section_box.add_widget(body_label)

            section_box.bind(
                minimum_height=section_box.setter("height")
            )
            content.add_widget(section_box)

        scroll.add_widget(content)
        screen.add_widget(scroll)
        return screen

    def _build_detail_screen(self):
        screen = DetailScreen(name="detail")
        layout = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(10))

        back_btn = Button(
            text="< Back to Scanner",
            size_hint_y=None,
            height=dp(40),
            background_color=COLORS["card_border"],
            color=COLORS["text"],
            font_size=dp(13),
        )
        back_btn.bind(on_press=lambda x: setattr(self.sm, "current", "scan"))
        layout.add_widget(back_btn)

        scroll = ScrollView()
        self.detail_layout = BoxLayout(
            orientation="vertical",
            size_hint_y=None,
            spacing=dp(8),
            padding=[0, dp(4)],
        )
        self.detail_layout.bind(
            minimum_height=self.detail_layout.setter("height")
        )
        scroll.add_widget(self.detail_layout)
        layout.add_widget(scroll)

        screen.add_widget(layout)
        return screen

    def _start_scan(self, instance):
        if self.scanning:
            return

        if ANDROID:
            request_permissions(
                [
                    Permission.BLUETOOTH_SCAN,
                    Permission.BLUETOOTH_CONNECT,
                    Permission.ACCESS_FINE_LOCATION,
                ],
                callback=self._on_permissions_result,
            )
        else:
            self._do_scan()

    def _on_permissions_result(self, permissions, grants):
        if all(grants):
            self._do_scan()
        else:
            self.status_text = "Bluetooth permissions denied"

    def _do_scan(self):
        self.scanning = True
        self.status_text = "Scanning..."
        self.scan_btn.text = "Scanning..."
        self.scan_btn.disabled = True
        self.results_layout.clear_widgets()

        scanning_label = Label(
            text="Scanning for BMS devices...\nThis takes about 10 seconds.",
            font_size=dp(13),
            color=COLORS["text_dim"],
            halign="center",
            valign="middle",
            size_hint_y=None,
            height=dp(80),
        )
        scanning_label.bind(size=scanning_label.setter("text_size"))
        self.results_layout.add_widget(scanning_label)

        self.scanner.start_scan()

    def _on_device_found(self, device_info):
        self.device_count = len(self.scanner.devices)
        self.status_text = f"Found {self.device_count} device(s)..."

    def _on_scan_complete(self, error):
        self.scanning = False
        self.scan_btn.text = "Scan for BMS Devices"
        self.scan_btn.disabled = False

        self.results_layout.clear_widgets()

        if error:
            self.status_text = f"Scan failed: {error}"
            err_label = Label(
                text=f"Scan failed: {error}\n\nMake sure Bluetooth is enabled.",
                font_size=dp(13),
                color=COLORS["critical"],
                halign="center",
                valign="middle",
                size_hint_y=None,
                height=dp(80),
            )
            err_label.bind(size=err_label.setter("text_size"))
            self.results_layout.add_widget(err_label)
            return

        devices = self.scanner.devices
        bms_devices = [d for d in devices if d.get("device_type", "Unknown") != "Unknown"]
        self.device_count = len(bms_devices)

        if not bms_devices:
            self.status_text = f"Scan complete — {len(devices)} device(s), 0 BMS"
            no_result = Label(
                text=(
                    "No BMS devices found nearby.\n\n"
                    "Tips:\n"
                    "- Move closer to the e-rickshaw\n"
                    "- Make sure the battery is powered on\n"
                    "- Try scanning again"
                ),
                font_size=dp(13),
                color=COLORS["text_dim"],
                halign="center",
                valign="middle",
                size_hint_y=None,
                height=dp(140),
            )
            no_result.bind(size=no_result.setter("text_size"))
            self.results_layout.add_widget(no_result)
            return

        critical_count = sum(
            1 for d in bms_devices
            if any(v.get("severity") == "critical" for v in d.get("vulnerabilities", []))
        )
        self.status_text = (
            f"Found {len(bms_devices)} BMS device(s), {critical_count} critical"
        )

        if critical_count:
            warning = Label(
                text=(
                    f"WARNING: {critical_count} device(s) with CRITICAL vulnerabilities!\n"
                    "These can be remotely disabled by anyone with a BMS app."
                ),
                font_size=dp(12),
                bold=True,
                color=COLORS["critical"],
                size_hint_y=None,
                height=dp(50),
                halign="center",
                valign="middle",
            )
            warning.bind(size=warning.setter("text_size"))
            self.results_layout.add_widget(warning)

        for device_info in bms_devices:
            card = DeviceCard(device_info, self)
            self.results_layout.add_widget(card)

    def show_device_detail(self, device_info):
        self.detail_layout.clear_widgets()

        from kivy.graphics import Color, Rectangle

        name_label = Label(
            text=device_info.get("name", "Unknown Device"),
            font_size=dp(18),
            bold=True,
            color=COLORS["accent"],
            size_hint_y=None,
            height=dp(30),
            halign="left",
            valign="middle",
        )
        name_label.bind(size=name_label.setter("text_size"))
        self.detail_layout.add_widget(name_label)

        info_text = (
            f"Address: {device_info.get('address', 'N/A')}\n"
            f"Type: {device_info.get('device_type', 'Unknown')}\n"
            f"RSSI: {device_info.get('rssi', 'N/A')} dBm\n"
            f"Signal: {device_info.get('signal_strength', 'N/A')}"
        )
        info_label = Label(
            text=info_text,
            font_size=dp(13),
            color=COLORS["text"],
            size_hint_y=None,
            halign="left",
            valign="top",
        )
        info_label.bind(size=info_label.setter("text_size"))
        info_label.bind(
            texture_size=lambda inst, val: setattr(inst, "height", val[1] + dp(8))
        )
        self.detail_layout.add_widget(info_label)

        vulns = device_info.get("vulnerabilities", [])
        if vulns:
            vuln_header = Label(
                text="Security Findings",
                font_size=dp(16),
                bold=True,
                color=COLORS["text"],
                size_hint_y=None,
                height=dp(30),
                halign="left",
                valign="middle",
            )
            vuln_header.bind(size=vuln_header.setter("text_size"))
            self.detail_layout.add_widget(vuln_header)

            for vuln in vulns:
                sev = vuln.get("severity", "low")
                sev_color = SEVERITY_COLORS.get(sev, COLORS["text_dim"])

                vuln_box = BoxLayout(
                    orientation="vertical",
                    size_hint_y=None,
                    padding=dp(10),
                    spacing=dp(4),
                )
                with vuln_box.canvas.before:
                    Color(*COLORS["card"])
                    bg = Rectangle(size=vuln_box.size, pos=vuln_box.pos)
                vuln_box.bind(
                    size=lambda w, s, r=bg: setattr(r, "size", s),
                    pos=lambda w, p, r=bg: setattr(r, "pos", p),
                )

                title_l = Label(
                    text=f"[{sev.upper()}] {vuln['title']}",
                    font_size=dp(13),
                    bold=True,
                    color=sev_color,
                    size_hint_y=None,
                    height=dp(22),
                    halign="left",
                    valign="middle",
                )
                title_l.bind(size=title_l.setter("text_size"))
                vuln_box.add_widget(title_l)

                desc_l = Label(
                    text=vuln.get("description", ""),
                    font_size=dp(11),
                    color=COLORS["text_dim"],
                    size_hint_y=None,
                    halign="left",
                    valign="top",
                )
                desc_l.bind(size=desc_l.setter("text_size"))
                desc_l.bind(
                    texture_size=lambda inst, val: setattr(inst, "height", val[1] + dp(4))
                )
                vuln_box.add_widget(desc_l)

                rec_l = Label(
                    text="Recommendation: " + vuln.get("recommendation", ""),
                    font_size=dp(11),
                    color=COLORS["secure"],
                    size_hint_y=None,
                    halign="left",
                    valign="top",
                )
                rec_l.bind(size=rec_l.setter("text_size"))
                rec_l.bind(
                    texture_size=lambda inst, val: setattr(inst, "height", val[1] + dp(4))
                )
                vuln_box.add_widget(rec_l)

                vuln_box.bind(minimum_height=vuln_box.setter("height"))
                self.detail_layout.add_widget(vuln_box)

        self.sm.current = "detail"

    def on_start(self):
        if ANDROID:
            request_permissions(
                [
                    Permission.BLUETOOTH_SCAN,
                    Permission.BLUETOOTH_CONNECT,
                    Permission.ACCESS_FINE_LOCATION,
                ],
            )

    def on_stop(self):
        if self.scanner.scanning:
            self.scanner.stop_scan()


if __name__ == "__main__":
    TirriShieldApp().run()
