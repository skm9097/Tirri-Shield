"""Rich command-line interface for Tirri-Shield."""

from __future__ import annotations

import asyncio
import json
import logging
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from tirri_shield import __version__
from tirri_shield.models import AlertEvent, BMSDevice, SecurityLevel, SecurityReport
from tirri_shield.monitor import BLEMonitor
from tirri_shield.scanner import TirriScanner

console = Console()

SEVERITY_STYLES = {
    SecurityLevel.CRITICAL: "bold red",
    SecurityLevel.HIGH: "red",
    SecurityLevel.MEDIUM: "yellow",
    SecurityLevel.LOW: "cyan",
    SecurityLevel.SECURE: "green",
}

SEVERITY_LABELS = {
    SecurityLevel.CRITICAL: "[!!!] CRITICAL",
    SecurityLevel.HIGH: "[!!]  HIGH",
    SecurityLevel.MEDIUM: "[!]   MEDIUM",
    SecurityLevel.LOW: "[~]   LOW",
    SecurityLevel.SECURE: "[OK]  SECURE",
}


def _serialize_reports(reports: list[SecurityReport]) -> list[dict]:
    result = []
    for report in reports:
        result.append({
            "device": {
                "address": report.device.address,
                "name": report.device.name,
                "type": report.device.device_type.value,
                "rssi": report.device.rssi,
            },
            "overall_level": report.overall_level.value,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "description": f.description,
                    "recommendation": f.recommendation,
                }
                for f in report.findings
            ],
        })
    return result


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _severity_text(level: SecurityLevel) -> Text:
    return Text(SEVERITY_LABELS[level], style=SEVERITY_STYLES[level])


def _display_device_table(devices: list[BMSDevice]) -> None:
    table = Table(title="Discovered BMS Devices", show_lines=True)
    table.add_column("Address", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Type", style="magenta")
    table.add_column("RSSI", justify="right")
    table.add_column("Distance", justify="right")
    table.add_column("Signal", style="yellow")

    for dev in devices:
        rssi_style = "green" if dev.rssi >= -60 else "yellow" if dev.rssi >= -70 else "red"
        table.add_row(
            dev.address,
            dev.name or "Unknown",
            dev.device_type.value,
            Text(f"{dev.rssi} dBm", style=rssi_style),
            f"{dev.estimated_distance_m:.1f}m",
            dev.signal_strength,
        )

    console.print(table)


def _display_report(report: SecurityReport) -> None:
    device = report.device
    title = f"Security Report: {device.name or device.address}"
    severity = _severity_text(report.overall_level)

    header = Table.grid(padding=1)
    header.add_row("Device:", f"{device.name or 'Unknown'} ({device.address})")
    header.add_row("Type:", device.device_type.value)
    header.add_row("RSSI:", f"{device.rssi} dBm ({device.signal_strength})")
    header.add_row("Overall Risk:", severity)

    border_style = SEVERITY_STYLES.get(report.overall_level, "white")
    console.print(Panel(header, title=title, border_style=border_style))

    if report.findings:
        findings_table = Table(title="Findings", show_lines=True, expand=True)
        findings_table.add_column("Severity", width=18)
        findings_table.add_column("Finding", ratio=2)
        findings_table.add_column("Recommendation", ratio=2)

        for finding in report.findings:
            findings_table.add_row(
                _severity_text(finding.severity),
                f"[bold]{finding.title}[/bold]\n{finding.description}",
                finding.recommendation,
            )

        console.print(findings_table)
    else:
        console.print("[green]No security issues found.[/green]")

    console.print()


def _display_alert(alert: AlertEvent) -> None:
    style = SEVERITY_STYLES.get(alert.severity, "white")
    label = SEVERITY_LABELS.get(alert.severity, "[?]")
    label_text = Text(label, style=style)
    msg_text = Text(" " + alert.message)
    combined = label_text.append_text(msg_text)
    console.print(combined)


@click.group()
@click.version_option(version=__version__, prog_name="tirri-shield")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def main(verbose: bool) -> None:
    """Tirri-Shield: Protect your e-rickshaw BMS from unauthorized BLE access.

    A defensive security toolkit that scans for vulnerable Battery Management
    System (BMS) devices and monitors for unauthorized Bluetooth connections.
    """
    _setup_logging(verbose)


@main.command()
@click.option("--duration", "-d", default=10.0, help="Scan duration in seconds")
@click.option("--deep", is_flag=True, help="Connect to devices for detailed assessment")
@click.option("--output", "-o", type=click.Path(), help="Save report to JSON file")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["rich", "json"]),
    default="rich",
    help="Output format",
)
def scan(duration: float, deep: bool, output: str | None, fmt: str) -> None:
    """Scan for vulnerable BMS devices nearby."""
    console.print(
        Panel(
            "[bold]Tirri-Shield BMS Vulnerability Scanner[/bold]\n"
            f"Scanning for {duration}s"
            + (" with deep inspection" if deep else "")
            + "...",
            border_style="blue",
        )
    )

    scanner = TirriScanner(scan_duration=duration, deep_inspect=deep)

    try:
        reports = asyncio.run(scanner.scan())
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        console.print(
            "\n[yellow]Make sure Bluetooth is enabled and you have the "
            "required permissions.[/yellow]\n"
            "On Linux, try: sudo setcap 'cap_net_raw,cap_net_admin=eip' "
            "$(which python3)"
        )
        sys.exit(1)

    if not reports:
        console.print("\n[yellow]No BMS devices found nearby.[/yellow]")
        console.print(
            "Tips:\n"
            "  - Move closer to the e-rickshaw\n"
            "  - Make sure the battery is powered on\n"
            "  - Try increasing scan duration with --duration 30"
        )
        return

    devices = [r.device for r in reports]
    if fmt == "rich":
        _display_device_table(devices)
        console.print()
        for report in reports:
            _display_report(report)

        critical_count = sum(
            1 for r in reports if r.overall_level == SecurityLevel.CRITICAL
        )
        if critical_count:
            console.print(
                Panel(
                    f"[bold red]Found {critical_count} device(s) with CRITICAL "
                    f"vulnerabilities.[/bold red]\n"
                    "These devices can be remotely disabled by anyone with a "
                    "BMS app.\nSee recommendations above for immediate actions.",
                    title="Action Required",
                    border_style="red",
                )
            )
    elif fmt == "json":
        click.echo(json.dumps(_serialize_reports(reports), indent=2))

    if output:
        with open(output, "w") as f:
            json.dump(_serialize_reports(reports), f, indent=2)
        console.print(f"\n[green]Report saved to {output}[/green]")


@main.command()
@click.option("--target", "-t", help="BMS device address to monitor")
@click.option("--interval", "-i", default=5.0, help="Scan interval in seconds")
@click.option(
    "--authorize",
    "-a",
    multiple=True,
    help="Authorized device address (can specify multiple)",
)
def monitor(target: str | None, interval: float, authorize: tuple[str, ...]) -> None:
    """Monitor for unauthorized BLE connections to a BMS.

    Watches the Bluetooth environment and alerts when:
    - A new unknown device appears near your BMS
    - A device rapidly approaches (RSSI spike)
    - Your BMS stops advertising (someone may have connected to it)
    """
    console.print(
        Panel(
            "[bold]Tirri-Shield BLE Monitor[/bold]\n"
            + (f"Target: {target}\n" if target else "Monitoring all nearby BMS devices\n")
            + f"Interval: {interval}s\n"
            + (f"Authorized: {', '.join(authorize)}" if authorize else "No authorized devices set"),
            border_style="blue",
        )
    )
    console.print("[dim]Press Ctrl+C to stop monitoring[/dim]\n")

    ble_monitor = BLEMonitor(
        target_address=target,
        authorized_addresses=list(authorize),
        poll_interval=interval,
    )
    ble_monitor.on_alert(_display_alert)

    try:
        asyncio.run(ble_monitor.start())
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped.[/yellow]")
    except Exception as e:
        console.print(f"[red]Monitor failed: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option("--host", default="127.0.0.1", help="Web server host")
@click.option("--port", "-p", default=8080, help="Web server port")
def web(host: str, port: int) -> None:
    """Start the web dashboard for visual monitoring."""
    from tirri_shield.web.server import DashboardServer

    console.print(
        Panel(
            f"[bold]Tirri-Shield Web Dashboard[/bold]\n"
            f"Starting at http://{host}:{port}",
            border_style="blue",
        )
    )

    server = DashboardServer(host=host, port=port)
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped.[/yellow]")
    except Exception as e:
        console.print(f"[red]Server failed: {e}[/red]")
        sys.exit(1)


@main.command()
def info() -> None:
    """Show information about the BAT-BMS vulnerability and how to protect yourself."""
    console.print(
        Panel(
            "[bold]BAT-BMS Vulnerability Information[/bold]\n\n"
            "[bold]What is happening?[/bold]\n"
            "A Chinese app called BAT-BMS is being used to remotely disable\n"
            "e-rickshaws (tirris/totos) by connecting to their Battery Management\n"
            "System (BMS) via Bluetooth and toggling the discharge switch.\n\n"
            "[bold]Why does this work?[/bold]\n"
            "Many budget BMS units used in Indian e-rickshaws have:\n"
            "  - No Bluetooth authentication (no PIN/password required)\n"
            "  - No encryption on BLE communication\n"
            "  - Open advertising (visible to anyone scanning)\n"
            "  - Writable control characteristics (discharge switch)\n\n"
            "[bold]How to protect yourself:[/bold]\n"
            "  1. [yellow]Immediate:[/yellow] Physically disconnect the Bluetooth module\n"
            "     from your BMS. This is a small board/antenna inside the battery\n"
            "     pack. Ask your mechanic or battery supplier for help.\n"
            "  2. [yellow]Short-term:[/yellow] Shield the BMS with metal or foil to reduce\n"
            "     Bluetooth range. Even partial shielding helps.\n"
            "  3. [yellow]Long-term:[/yellow] Upgrade to a BMS that requires PIN-based\n"
            "     Bluetooth pairing (ask for 'secure BLE' or 'PIN-protected BMS').\n"
            "  4. [yellow]Advocate:[/yellow] Ask your battery supplier to provide firmware\n"
            "     updates that add authentication.\n\n"
            "[bold]Use Tirri-Shield to:[/bold]\n"
            "  - Scan: Check if your BMS is vulnerable\n"
            "  - Monitor: Watch for unauthorized connection attempts\n"
            "  - Assess: Get a detailed security report for your device",
            border_style="cyan",
            expand=False,
        )
    )
