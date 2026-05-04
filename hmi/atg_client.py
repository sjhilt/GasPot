"""
ATG Client -- talks to GasPot over TCP using the Veeder-Root TLS protocol.

This module implements the TCP client side of the Veeder-Root TLS serial
interface (per manual 576013-635).  It connects to a running GasPot
instance (or any device that speaks TLS protocol) and sends inquiry
commands like I20100, I10100, etc.

Commands are wrapped in the SOH/ETX envelope that the real TLS-350
uses on its serial/TCP interface:

    SOH (0x01)  +  command bytes  +  newline

The response comes back similarly wrapped in SOH...ETX.  We strip
those control characters and return clean ASCII text.

Parsed helpers (get_inventory, get_status) turn the raw text into
Python dataclasses so the Flask HMI can work with structured data
instead of parsing text in the templates.
"""

import socket
import re
from dataclasses import dataclass

# ── TLS protocol constants ──────────────────────────────────────────
# SOH (Start of Header) -- marks the beginning of a TLS command frame.
# ETX (End of Text) -- marks the end of a TLS response frame.
# These are defined in the Veeder-Root serial interface spec.
SOH = b'\x01'
ETX = b'\x03'

# How long to wait for a response before giving up (seconds).
# Real TLS consoles typically respond within 1-2s; 5s is generous.
TIMEOUT = 5.0


# ── Data structures ─────────────────────────────────────────────────
# These dataclasses hold parsed tank data so the HMI templates can
# access fields like t.volume, t.temperature, etc. instead of
# having to regex-parse raw text in Jinja2.

@dataclass
class TankReading:
    """Parsed result from I20100 (In-Tank Inventory) for one tank.

    Fields match the columns in the TLS inventory report:
        TANK  PRODUCT  VOLUME  TC VOLUME  ULLAGE  HEIGHT  WATER  TEMP
    """
    tank_id: int        # Tank number (1-based)
    product: str        # Product name, e.g. "SUPER", "DIESEL"
    volume: int         # Current volume in gallons
    tc_volume: int      # Temperature-compensated volume
    ullage: int         # Remaining capacity (how much more fits)
    height: float       # Product height in inches
    water: float        # Water level in inches
    temperature: float  # Product temperature in °F


@dataclass
class TankStatus:
    """Parsed result from I20500 (In-Tank Status) for one tank.

    The status field is a string like "NORMAL", "HIGH WATER ALARM",
    "OVERFILL ALARM", etc.
    """
    tank_id: int   # Tank number (1-based)
    product: str   # Product name
    status: str    # Status string from the TLS report


# ── ATG Client ──────────────────────────────────────────────────────

class ATGClient:
    """Connects to a GasPot (or real TLS-350) and sends TLS commands.

    Usage:
        client = ATGClient("192.168.1.100", 10001)
        tanks = client.get_inventory()    # parsed tank data
        raw = client.send_command("I20700")  # raw text response
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 10001):
        """Initialize with the GasPot host and port.

        Args:
            host: IP address of the GasPot instance (default: localhost)
            port: TCP port GasPot is listening on (default: 10001,
                  which is the standard Veeder-Root TLS port)
        """
        self.host = host
        self.port = port

    def send_command(self, cmd: str) -> str:
        """Send a TLS command and return the raw response text.

        Opens a new TCP connection for each command (just like the
        real TLS protocol -- each transaction is a separate connection).

        The command is prefixed with SOH (0x01) per the TLS spec.
        We read until we see ETX (0x03) or the connection closes.

        Args:
            cmd: The TLS command string, e.g. "I20100", "I10100"

        Returns:
            The response text with SOH/ETX bytes stripped out.
            On connection failure, returns an error message string.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(TIMEOUT)
                sock.connect((self.host, self.port))

                # Send: SOH + command + newline
                sock.sendall(SOH + cmd.encode('ascii') + b'\n')

                # Read the response -- keep reading until we see ETX
                # or the connection closes or we hit our size limit
                response = b''
                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break  # Connection closed
                        response += chunk
                        # ETX marks end of response in TLS protocol
                        if ETX in chunk or len(response) > 65536:
                            break
                    except socket.timeout:
                        break  # No more data coming

                # Strip the SOH/ETX control characters -- the HMI
                # just wants the printable text
                text = response.decode('ascii', errors='replace')
                text = text.replace('\x01', '').replace('\x03', '')
                return text

        except (socket.timeout, socket.error) as e:
            return f"CONNECTION ERROR: {e}"

    # ── Parsed inquiry methods ──────────────────────────────────────
    # These methods call send_command() and then parse the raw text
    # into structured Python objects.  This keeps the parsing logic
    # in one place instead of scattered across the Flask templates.

    def get_inventory(self) -> list[TankReading]:
        """I20100 -- In-Tank Inventory report, parsed into TankReading objects.

        This is the most commonly used command.  The raw response looks like:

            TANK  PRODUCT      VOLUME  TC VOLUME  ULLAGE  HEIGHT   WATER    TEMP
              1   SUPER          1906       1916     4110   33.99    0.14   52.53
              2   UNLEAD         3496       3506     2520   40.22    0.38   55.72
              ...

        We regex-match each data line and return a list of TankReading objects.
        """
        raw = self.send_command("I20100")
        readings = []
        for line in raw.split('\n'):
            # Match lines with tank data -- 8 numeric fields after tank# and product name
            # Example: "  1  SUPER                   1906        1916      4110    33.99      0.14    52.53"
            m = re.match(
                r'^\s*(\d+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)',
                line
            )
            if m:
                readings.append(TankReading(
                    tank_id=int(m.group(1)),
                    product=m.group(2),
                    volume=int(float(m.group(3))),
                    tc_volume=int(float(m.group(4))),
                    ullage=int(float(m.group(5))),
                    height=float(m.group(6)),
                    water=float(m.group(7)),
                    temperature=float(m.group(8)),
                ))
        return readings

    def get_status(self) -> list[TankStatus]:
        """I20500 -- In-Tank Status report, parsed into TankStatus objects.

        The raw response has lines like:
            TANK  PRODUCT     STATUS
              1   SUPER       NORMAL
              2   UNLEAD      HIGH WATER WARNING

        We skip the header line and parse each tank's status.
        """
        raw = self.send_command("I20500")
        statuses = []
        for line in raw.split('\n'):
            m = re.match(r'^\s*(\d+)\s+(\S+)\s+(.*\S)', line)
            if m:
                tank_id = int(m.group(1))
                product = m.group(2)
                status = m.group(3).strip()
                # Skip the header row ("TANK  PRODUCT  STATUS")
                if product.upper() in ('PRODUCT', 'TANK'):
                    continue
                statuses.append(TankStatus(
                    tank_id=tank_id,
                    product=product,
                    status=status if status else "NORMAL",
                ))
        return statuses

    # ── Raw inquiry methods ─────────────────────────────────────────
    # These just return the raw text response.  The HMI displays
    # them in a <pre> block styled like a terminal output.

    def get_system_status(self) -> str:
        """I10100 -- System Status Report (raw text).

        Shows serial#, software version, power status, battery,
        printer, comm port status, etc.
        """
        return self.send_command("I10100")

    def get_alarm_history(self) -> str:
        """I11100 -- Priority Alarm History (raw text).

        Shows recent alarm events with timestamps.
        Scanners probe this command frequently.
        """
        return self.send_command("I11100")

    def get_tank_alarm_history(self) -> str:
        """I20600 -- In-Tank Alarm History (raw text).

        Shows alarm events specific to individual tanks
        (overfill, high water, leak detect, etc.)
        """
        return self.send_command("I20600")

    def get_delivery_report(self) -> str:
        """I20200 -- Delivery Report (raw text).

        Shows recent fuel deliveries with start/end volumes
        and delivery amounts.
        """
        return self.send_command("I20200")

    def get_leak_detect(self) -> str:
        """I20300 -- Leak Detect Report (raw text).

        Shows results of the continuous statistical leak detection
        (CSLD) monitoring.
        """
        return self.send_command("I20300")

    def get_diagnostics(self) -> str:
        """I20700 -- Diagnostics Report (raw text).

        Shows probe diagnostics, measurement quality indicators,
        and hardware status.
        """
        return self.send_command("I20700")

    def get_sensor_status(self) -> str:
        """I30100 -- Sensor Status Report (raw text).

        Shows environmental sensor readings (interstitial sensors,
        sump sensors, etc.)
        """
        return self.send_command("I30100")

    def get_tank_config(self) -> str:
        """I60100 -- Tank Configuration Data (raw text).

        Shows tank dimensions, capacity, product type, and
        probe configuration for each tank.
        """
        return self.send_command("I60100")

    def get_datetime(self) -> str:
        """I50100 -- Date/Time Query (raw text).

        Returns the ATG's current date and time.
        Recon scanners love this command because it reveals
        the system's timezone and whether the clock is accurate.
        """
        return self.send_command("I50100")

    # ── Connection check ────────────────────────────────────────────

    def is_connected(self) -> bool:
        """Quick check if GasPot is reachable on its TCP port.

        Just attempts a TCP connect -- doesn't send any command.
        Used by the HMI to show the green/red connection indicator.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((self.host, self.port))
                return True
        except (socket.error, socket.timeout):
            return False
