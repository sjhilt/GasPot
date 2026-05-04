#!/usr/bin/env python3
"""
GasPot HMI -- Veeder-Root TLS-350 style web interface.

This is a standalone Flask web application that acts as a Human-Machine
Interface (HMI) for GasPot.  It connects to a running GasPot instance
over TCP and displays the tank data in a green-phosphor-on-black
terminal style that mimics the real Veeder-Root TLS-350 console.

Architecture:
    Browser  ──HTTP──▶  This Flask app (port 5000/8080)
                              │
                              │ TCP (TLS protocol)
                              ▼
                        GasPot (port 10001)

Each page request triggers one or more TLS commands to GasPot via
the ATGClient.  The dashboard also has JavaScript that polls the
/api/inventory endpoint every 10 seconds to keep the gauges live.

Usage:
    python app.py                          # defaults: GasPot on localhost:10001
    python app.py --gaspot-host 10.0.0.5   # remote GasPot
    python app.py --port 8080              # HMI on different port

Pages:
    /          Dashboard -- tank gauges + inventory table (F1)
    /status    System & tank status (F2)
    /alarms    Priority & in-tank alarm history (F3)
    /reports   Delivery, leak, diagnostics, sensors, config (F4)
    /console   Raw TLS command console (F5)

API endpoints (JSON):
    GET  /api/inventory   -- live tank data for AJAX polling
    POST /api/command     -- send any raw TLS command
"""

import argparse
import json
from datetime import datetime

from flask import Flask, render_template, jsonify, request
from atg_client import ATGClient

app = Flask(__name__)

# Global ATG client instance -- set from command line args in main().
# All routes use this to talk to GasPot.
client: ATGClient = None

# ═══════════════════════════════════════════════════════════════════════
# FOOTER TEXT -- CHANGE THIS BEFORE GOING ONLINE
# ═══════════════════════════════════════════════════════════════════════
# This text appears at the bottom of every page.  The default value
# clearly identifies this as a simulator, which is fine for development
# but WILL blow your cover if you deploy this as a honeypot.
#
# Before deploying, change this to something innocuous like:
#   HMI_FOOTER_TEXT = "Veeder-Root TLS-350 Console v4.02"
#   HMI_FOOTER_TEXT = ""   (empty string hides the footer entirely)
#
# CHANGE THIS BEFORE GOING ONLINE
HMI_FOOTER_TEXT = "GasPot HMI — Veeder-Root TLS-350 Simulator — NOT A REAL ATG SYSTEM"

# ═══════════════════════════════════════════════════════════════════════
# STATION NAME -- Fetch from GasPot via I50100 or I20100
# ═══════════════════════════════════════════════════════════════════════
# Uncomment the function below and the @app.context_processor to pull
# the station name from GasPot dynamically and display it in the header.
# This makes the HMI look more realistic but requires GasPot to be running.
#
# def _get_station_name() -> str:
#     """Fetch the station name from GasPot by sending I20100 and parsing
#     the header.  Falls back to a generic name on failure."""
#     try:
#         raw = client.send_command("\x01I20100\n")
#         # Station name is on line 5 of I20100 response (after header)
#         for line in raw.splitlines():
#             stripped = line.strip()
#             if stripped and not stripped.startswith("I201") and not stripped[0].isdigit():
#                 return stripped
#     except Exception:
#         pass
#     return "VEEDER-ROOT TLS-350"


# ═══════════════════════════════════════════════════════════════════════
# Template context processor -- injects variables into ALL templates
# ═══════════════════════════════════════════════════════════════════════

@app.context_processor
def inject_globals():
    """Make footer_text (and optionally station_name) available in every template."""
    ctx = {
        "footer_text": HMI_FOOTER_TEXT,
        # Uncomment the line below (and _get_station_name above) to show
        # the station name from GasPot in the HMI header:
        # "station_name": _get_station_name(),
    }
    return ctx


# ════════════════════════════════════════════════════════════════════
# Page routes -- each one fetches data from GasPot via the ATG client
# and renders an HTML template.  If GasPot is unreachable, the page
# still loads but shows a "CONNECTION FAILED" message.
# ════════════════════════════════════════════════════════════════════

@app.route("/")
def dashboard():
    """Main dashboard -- tank inventory with visual gauges.

    Sends I20100 (In-Tank Inventory) to GasPot and renders the
    dashboard template with tank cards showing fill level gauges,
    volumes, temperatures, and water levels.

    The page also includes a detail table and JavaScript that
    polls /api/inventory every 10 seconds to keep values live.
    """
    try:
        tanks = client.get_inventory()
        connected = True
    except Exception:
        tanks = []
        connected = False

    return render_template("dashboard.html",
                           tanks=tanks,
                           connected=connected,
                           now=datetime.now().strftime("%m/%d/%Y %H:%M:%S"))


@app.route("/alarms")
def alarms():
    """Priority alarm history page.

    Sends two commands to GasPot:
      - I11100 (Priority Alarm History) -- system-wide alarms
      - I20600 (In-Tank Alarm History) -- per-tank alarms

    Both responses are displayed as raw terminal text blocks.
    """
    try:
        raw = client.get_alarm_history()
        tank_alarms = client.get_tank_alarm_history()
        connected = True
    except Exception:
        raw = "CONNECTION ERROR"
        tank_alarms = ""
        connected = False

    return render_template("alarms.html",
                           alarm_text=raw,
                           tank_alarm_text=tank_alarms,
                           connected=connected,
                           now=datetime.now().strftime("%m/%d/%Y %H:%M:%S"))


@app.route("/status")
def status():
    """System status and per-tank status page.

    Sends two commands:
      - I10100 (System Status) -- serial#, software ver, power, etc.
      - I20500 (In-Tank Status) -- per-tank status (parsed into objects)

    The system status is shown as raw text; tank statuses are shown
    in a table with color-coded status indicators:
      - Green  = NORMAL
      - Yellow = WARNING
      - Red (blinking) = ALARM
    """
    try:
        sys_status = client.get_system_status()
        tank_statuses = client.get_status()
        connected = True
    except Exception:
        sys_status = "CONNECTION ERROR"
        tank_statuses = []
        connected = False

    return render_template("status.html",
                           sys_status=sys_status,
                           tank_statuses=tank_statuses,
                           connected=connected,
                           now=datetime.now().strftime("%m/%d/%Y %H:%M:%S"))


@app.route("/reports")
def reports():
    """Reports page with tabbed report types.

    The ?type= query parameter selects which report to show:
      - delivery    → I20200 (Delivery Report)
      - leak        → I20300 (Leak Detect Report)
      - diagnostics → I20700 (Diagnostics Report)
      - sensors     → I30100 (Sensor Status)
      - config      → I60100 (Tank Configuration)

    All reports are displayed as raw terminal text blocks.
    The template shows tab buttons to switch between report types.
    """
    report_type = request.args.get("type", "delivery")

    try:
        connected = True
        if report_type == "delivery":
            raw = client.get_delivery_report()
        elif report_type == "leak":
            raw = client.get_leak_detect()
        elif report_type == "diagnostics":
            raw = client.get_diagnostics()
        elif report_type == "sensors":
            raw = client.get_sensor_status()
        elif report_type == "config":
            raw = client.get_tank_config()
        else:
            raw = client.get_delivery_report()
    except Exception:
        raw = "CONNECTION ERROR"
        connected = False

    return render_template("reports.html",
                           report_text=raw,
                           report_type=report_type,
                           connected=connected,
                           now=datetime.now().strftime("%m/%d/%Y %H:%M:%S"))


@app.route("/console")
def console():
    """Raw command console page.

    This page lets you type any TLS command (e.g. I20100, I50100)
    and see the raw response.  It also has quick-access buttons
    for the 12 most common commands.

    Commands are sent via JavaScript POST to /api/command and the
    response is appended to a scrollable terminal output area.
    """
    return render_template("console.html",
                           connected=client.is_connected(),
                           now=datetime.now().strftime("%m/%d/%Y %H:%M:%S"))


# ════════════════════════════════════════════════════════════════════
# API endpoints -- JSON responses for AJAX calls from the browser.
# These are used by the dashboard's live polling and the console's
# command submission.
# ════════════════════════════════════════════════════════════════════

@app.route("/api/inventory")
def api_inventory():
    """JSON endpoint for live tank data.

    Called by the dashboard's JavaScript every 10 seconds to update
    the tank gauges without a full page reload.

    Returns JSON like:
    {
        "connected": true,
        "timestamp": "05/04/2026 15:30:00",
        "tanks": [
            {
                "tank_id": 1,
                "product": "SUPER",
                "volume": 1906,
                "fill_pct": 31.7,
                ...
            },
            ...
        ]
    }

    The fill_pct field is calculated here so the JavaScript doesn't
    have to do the math -- it just sets the CSS gauge height directly.
    """
    try:
        tanks = client.get_inventory()
        return jsonify({
            "connected": True,
            "timestamp": datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
            "tanks": [
                {
                    "tank_id": t.tank_id,
                    "product": t.product,
                    "volume": t.volume,
                    "tc_volume": t.tc_volume,
                    "ullage": t.ullage,
                    "height": t.height,
                    "water": t.water,
                    "temperature": t.temperature,
                    # Calculate fill percentage for the gauge display.
                    # volume / (volume + ullage) gives us the fraction full.
                    "fill_pct": round(t.volume / (t.volume + t.ullage) * 100, 1) if (t.volume + t.ullage) > 0 else 0,
                }
                for t in tanks
            ],
        })
    except Exception as e:
        return jsonify({"connected": False, "error": str(e)})


@app.route("/api/command", methods=["POST"])
def api_command():
    """Send a raw TLS command and return the response as JSON.

    Used by the Console page's JavaScript.  Expects a JSON body:
        {"command": "I20100"}

    Returns:
        {"command": "I20100", "response": "...raw text..."}
    or:
        {"error": "connection failed"}
    """
    cmd = request.json.get("command", "").strip()
    if not cmd:
        return jsonify({"error": "No command provided"})
    try:
        response = client.send_command(cmd)
        return jsonify({"response": response, "command": cmd})
    except Exception as e:
        return jsonify({"error": str(e)})


# ════════════════════════════════════════════════════════════════════
# CLI argument parsing and startup
# ════════════════════════════════════════════════════════════════════

def parse_args():
    """Parse command line arguments.

    Two sets of connection parameters:
      1. GasPot connection (--gaspot-host, --gaspot-port)
         Where the ATG simulator is running.

      2. HMI web server (--host, --port)
         Where this Flask app listens for browser connections.
    """
    parser = argparse.ArgumentParser(
        description="GasPot HMI -- Veeder-Root TLS-350 Web Interface"
    )
    parser.add_argument("--gaspot-host", default="127.0.0.1",
                        help="GasPot host (default: 127.0.0.1)")
    parser.add_argument("--gaspot-port", type=int, default=10001,
                        help="GasPot port (default: 10001)")
    parser.add_argument("--host", default="0.0.0.0",
                        help="HMI listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000,
                        help="HMI listen port (default: 5000)")
    parser.add_argument("--debug", action="store_true",
                        help="Flask debug mode")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    # Create the ATG client that all routes will use to talk to GasPot
    client = ATGClient(host=args.gaspot_host, port=args.gaspot_port)

    print(f"GasPot HMI starting on http://{args.host}:{args.port}")
    print(f"Connecting to GasPot at {args.gaspot_host}:{args.gaspot_port}")

    # Start the Flask development server.
    # In production you'd use gunicorn or similar, but for a honeypot
    # HMI the built-in server is fine.
    app.run(host=args.host, port=args.port, debug=args.debug)
