# Tirri-Shield

**Defensive security toolkit for e-rickshaw BMS Bluetooth protection**

Tirri-Shield detects and reports security vulnerabilities in Battery Management System (BMS) devices used in Indian e-rickshaws (tirris/totos). It helps vehicle owners and operators protect against unauthorized Bluetooth access — such as the viral BAT-BMS app prank that remotely disables vehicles by toggling the discharge switch over BLE.

> **This is a purely defensive tool.** It scans, monitors, and reports — it never sends control commands to BMS devices.

## The Problem

Many budget Chinese-manufactured BMS units used in India's e-rickshaw fleet include a Bluetooth Low Energy (BLE) module for wireless monitoring. These modules typically have:

- **No authentication** — anyone nearby can connect without a PIN or password
- **No encryption** — commands are sent in plaintext
- **Open advertising** — the device broadcasts its presence continuously
- **Writable control characteristics** — the discharge switch can be toggled remotely

Apps like BAT-BMS exploit these weaknesses to connect to e-rickshaw batteries and cut power to the motor, stranding drivers mid-road.

## Features

### BMS Vulnerability Scanner
Scan for nearby BMS devices and get a detailed security assessment:
```bash
tirri-shield scan --duration 15
tirri-shield scan --deep  # connects to devices for detailed inspection
```

### Real-time BLE Monitor
Watch for unauthorized Bluetooth connections to your BMS:
```bash
tirri-shield monitor --target AA:BB:CC:DD:EE:FF
tirri-shield monitor --authorize 11:22:33:44:55:66  # whitelist your phone
```

### Web Dashboard
Visual security dashboard for non-technical users:
```bash
tirri-shield web --port 8080
```

### Protection Guide
Built-in information about the vulnerability and how to protect yourself:
```bash
tirri-shield info
```

## Installation

### Requirements
- Python 3.9+
- Bluetooth 5.0+ adapter with BLE support
- Linux: BlueZ 5.43+ (most modern distros)
- macOS: Core Bluetooth (built-in)

### Install from source
```bash
git clone https://github.com/skm9097/tirri-shield.git
cd tirri-shield
pip install -e .
```

### Install with development dependencies
```bash
pip install -e ".[dev]"
```

### Linux permissions
On Linux, BLE scanning requires elevated privileges. Either run as root or grant capabilities:
```bash
sudo setcap 'cap_net_raw,cap_net_admin=eip' $(which python3)
```

## Quick Start

1. **Check if your BMS is vulnerable:**
   ```bash
   tirri-shield scan
   ```

2. **Monitor your vehicle for unauthorized access:**
   ```bash
   tirri-shield monitor
   ```

3. **Learn how to protect yourself:**
   ```bash
   tirri-shield info
   ```

## How It Works

### Scanner
The scanner discovers nearby BLE devices, identifies BMS units using a database of known signatures (device names, service UUIDs, manufacturer IDs), and assesses their security posture. In deep-scan mode, it connects to each device to enumerate GATT services and identify writable control characteristics.

### Monitor
The monitor continuously scans the BLE environment and alerts when:
- A new unknown device appears near your BMS (potential attacker)
- A device rapidly approaches (RSSI spike)
- Your BMS stops advertising — indicating someone else has connected to it

### Detection Strategy
BLE devices typically stop advertising when they accept a connection. If a monitored BMS suddenly disappears from scan results, it likely means an unauthorized device has connected. Combined with new-device detection, this provides practical unauthorized access detection.

## Known Vulnerable BMS Types

| BMS Type | Common Names | Service UUID |
|----------|-------------|--------------|
| JBD/Xiaoxiang | xiaoxiang, JBD-, SP0/SP1 | 0xFF00 |
| Daly | DalyBMS, Smart BMS | 0xFFF0 |
| ANT | ANT-BMS | 0xFFE0 |
| JiKong/JK | JK-B, JKBMS | 0xFFE0 |

## Immediate Protection Steps

1. **Disconnect the Bluetooth module** from your BMS (most effective)
2. **Shield the BMS** with metal enclosure to reduce Bluetooth range
3. **Upgrade** to a BMS with PIN-based pairing
4. **Demand** firmware updates from your battery supplier

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=tirri_shield

# Lint
ruff check tirri_shield/
```

## Project Structure

```
tirri_shield/
├── __init__.py          # Package metadata
├── __main__.py          # python -m entry point
├── cli.py               # Click CLI with Rich output
├── scanner.py           # Vulnerability scanner orchestrator
├── monitor.py           # Real-time BLE connection monitor
├── analyzer.py          # Security assessment engine
├── models.py            # Data models
├── ble/
│   ├── discovery.py     # BLE device discovery
│   ├── inspector.py     # GATT service inspection
│   └── signatures.py    # Known vulnerable device signatures
└── web/
    └── server.py        # Web dashboard server
```

## Contributing

Contributions are welcome. Please focus on defensive capabilities:
- Adding signatures for newly identified vulnerable BMS models
- Improving detection accuracy
- Translations (especially Hindi, Bengali, Assamese for e-rickshaw drivers)
- Platform support improvements

## License

MIT License. See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for **defensive security assessment only**. Using Bluetooth to connect to and control vehicles you do not own may have legal consequences. Always obtain proper authorization before scanning or assessing devices.
