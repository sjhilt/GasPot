# GasPot HMI -- Veeder-Root TLS-350 Web Console

A standalone web-based Human-Machine Interface (HMI) that mimics the Veeder-Root TLS-350 console. It connects to a running GasPot instance over TCP and displays tank data in a green-phosphor-on-black terminal style.

![TLS-350 Style](https://img.shields.io/badge/style-TLS--350-green?style=flat-square)

## Features

- **Dashboard** — Visual tank gauges with fill levels, volumes, temperatures, water levels
- **Status** — System status and per-tank status with color-coded alerts
- **Alarms** — Priority alarm history and in-tank alarm history
- **Reports** — Delivery, leak detect, diagnostics, sensor status, tank config
- **Raw Console** — Send any TLS command directly with quick-access buttons
- **Live Polling** — Dashboard auto-refreshes every 10 seconds via AJAX
- **Green Phosphor** — Authentic CRT scanline effect and VT323 monospace font

## Quick Start

```bash
# 1. Start GasPot (in the parent directory)
cd ..
python GasPot.py

# 2. In another terminal, start the HMI
cd hmi
pip install -r requirements.txt
python app.py
```

Then open **http://localhost:5000** in your browser.

## Command Line Options

```
python app.py [OPTIONS]

  --gaspot-host HOST   GasPot IP address (default: 127.0.0.1)
  --gaspot-port PORT   GasPot TCP port (default: 10001)
  --host HOST          HMI listen address (default: 0.0.0.0)
  --port PORT          HMI web port (default: 5000)
  --debug              Enable Flask debug mode
```

### Examples

```bash
# Connect to a remote GasPot
python app.py --gaspot-host 192.168.1.100

# Run HMI on port 8080
python app.py --port 8080

# Both
python app.py --gaspot-host 10.0.0.5 --gaspot-port 10001 --port 8080
```

## Architecture

```
hmi/
├── app.py              # Flask web server with routes & API endpoints
├── atg_client.py       # TCP client that speaks TLS protocol to GasPot
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── templates/
    ├── base.html       # Base template with nav, styling, scanline effect
    ├── dashboard.html  # Tank gauges + inventory table (auto-refreshes)
    ├── status.html     # System + tank status
    ├── alarms.html     # Priority & in-tank alarm history
    ├── reports.html    # Delivery, leak, diagnostics, sensors, config
    └── console.html    # Raw TLS command console
```

## Pages

| Key | Page | Description |
|-----|------|-------------|
| F1 | Inventory | Tank gauges with fill %, volume, temp, water |
| F2 | Status | System status + per-tank status |
| F3 | Alarms | Priority and in-tank alarm history |
| F4 | Reports | Delivery, leak detect, diagnostics, sensors, config |
| F5 | Console | Raw TLS command input with quick buttons |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/inventory` | GET | JSON tank inventory (used by live polling) |
| `/api/command` | POST | Send raw TLS command, returns JSON response |

## Notes

- This is a **simulator display** — it says "NOT A REAL ATG SYSTEM" in the footer
- The HMI connects to GasPot the same way a real TLS console would talk to an ATG
- Connection status is shown with a green/red dot in the header
- If GasPot isn't running, pages show a red "CONNECTION FAILED" message
- The scanline CRT effect can be disabled by removing the `body::after` CSS
