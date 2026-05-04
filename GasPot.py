#!/usr/bin/env python3
#######################################################################
# GasPot.py
#
# Honeypot that simulates a Veeder-Root Guardian AST (TLS-350/TLS-450).
# Records connections and commands for threat intel.
#
# v2 rewrite -- cleaned up for Python 3.10+, added a bunch more
# Veeder-Root commands, better logging, and the tank values are now
# based on actual cylinder geometry so they look realistic.
#
#   Authors: Kyle Wilhoit
#            Stephen Hilt
#
########################################################################

from __future__ import annotations

import argparse
import ast
import configparser
import datetime
import json
import logging
import math
import os
import random
import select
import signal
import socket
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

__version__ = "2.2.0"

# Tank geometry constants -- used to make the values look real
THERMAL_COEFF = 0.000700  # per degree F, standard petroleum
REFERENCE_TEMP = 60.0     # API standard temp for TC volume correction

# Logging setup

logger = logging.getLogger("gaspot")


def _setup_logging(log_path: str, quiet: bool, json_log: bool) -> None:
    # Set up logging to file and optionally to console
    logger.setLevel(logging.DEBUG)
    fmt_text = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    fmt_text.converter = lambda *_: datetime.datetime.now(datetime.UTC).timetuple()

    # File handler -- always enabled
    if json_log:
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(_JsonFormatter())
    else:
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(fmt_text)
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)

    # Console handler -- unless --quiet
    if not quiet:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt_text)
        ch.setLevel(logging.INFO)
        logger.addHandler(ch)


class _JsonFormatter(logging.Formatter):
    # Formats log entries as JSON lines -- makes it easy to pipe into Splunk/ELK/etc

    def format(self, record: logging.LogRecord) -> str:
        obj = {
            "ts": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        if hasattr(record, "remote_ip"):
            obj["remote_ip"] = record.remote_ip
        if hasattr(record, "command"):
            obj["command"] = record.command
        return json.dumps(obj, default=str)


# Tank geometry math
#
# Real tanks are horizontal cylinders so we use the cross-section area
# formula to get volume from height. This way height/volume/ullage are
# all consistent with each other instead of just random numbers.


def _cylinder_volume_from_height(diameter_in: float, length_in: float, height_in: float) -> float:
    # Calculate gallons of liquid in a horizontal cylinder from the product height
    # All measurements in inches, returns gallons (1 cubic inch = 0.004329 gal)
    r = diameter_in / 2.0
    h = max(0.0, min(height_in, diameter_in))  # clamp
    # Cross-sectional area of a circular segment
    area = r * r * math.acos((r - h) / r) - (r - h) * math.sqrt(2 * r * h - h * h)
    volume_cubic_in = area * length_in
    return volume_cubic_in * 0.004329


def _height_from_fill_fraction(diameter_in: float, fill_fraction: float) -> float:
    # Given a fill percentage (0.0-1.0) figure out the height in inches
    # Uses Newton's method to solve the circle segment area equation
    r = diameter_in / 2.0
    target_area = fill_fraction * math.pi * r * r  # target cross-section area

    # Newton's method -- converges quickly for this
    h = diameter_in * fill_fraction  # initial guess (linear)
    for _ in range(20):
        if h <= 0:
            h = 0.01
        if h >= diameter_in:
            h = diameter_in - 0.01
        area = r * r * math.acos((r - h) / r) - (r - h) * math.sqrt(2 * r * h - h * h)
        # derivative of area w.r.t. h
        d_area = math.sqrt(2 * r * h - h * h) + (r - h) * (r - h) / (r * math.sqrt(1 - ((r - h) / r) ** 2)) if h > 0.01 else 1.0
        try:
            d_area = 2 * math.sqrt(2 * r * h - h * h)
        except ValueError:
            break
        if abs(d_area) < 1e-10:
            break
        h = h - (area - target_area) / d_area
        h = max(0.01, min(h, diameter_in - 0.01))

    return round(h, 2)


# Data model for the station and tanks

@dataclass
class Tank:
    # Represents a single fuel tank -- all the values are derived from
    # fill_fraction and the physical dimensions so everything stays consistent

    number: int
    product: str

    # Physical dimensions (inches)
    diameter: float = 96.0
    length: float = 192.0  # 16 feet typical

    # Core state -- fill_fraction drives everything else
    fill_fraction: float = 0.5   # 0.0 = empty, 1.0 = full
    base_temperature: float = 55.0  # degrees F
    base_water_inches: float = 0.3

    # Delivery simulation
    fill_start: datetime.datetime = field(default_factory=lambda: datetime.datetime.now(datetime.UTC))
    fill_stop: datetime.datetime = field(default_factory=lambda: datetime.datetime.now(datetime.UTC))

    # Consumption simulation -- how fast this tank drains (gallons/hour).
    # Each tank gets a slightly different rate so they don't all empty at
    # the same time.  Set to 0.0 to disable for this tank.
    consumption_gph: float = 0.0

    # Slow-drift accumulators for temperature and water level.
    # These accumulate tiny random changes each tick (~2s) so readings
    # look stable on rapid refresh but still drift realistically over hours.
    _temp_drift: float = field(default=0.0, repr=False)
    _water_drift: float = field(default=0.0, repr=False)

    # Internal: per-request jitter seed, updated each query
    _query_count: int = field(default=0, repr=False)

    def product_padded(self, width: int = 22) -> str:
        return self.product.ljust(width)

    @property
    def capacity(self) -> int:
        # Total tank capacity in gallons
        return round(_cylinder_volume_from_height(self.diameter, self.length, self.diameter))

    @property
    def temperature(self) -> float:
        # Returns base_temperature + slow-drifting offset.
        # The _temp_drift accumulator is nudged each tick (~2s) by a tiny
        # amount, so readings are rock-stable on rapid refresh but still
        # wander ±1°F over many hours -- just like a real underground tank
        # whose temperature barely changes.
        return round(self.base_temperature + self._temp_drift, 2)

    @property
    def water(self) -> float:
        # Same slow-drift approach as temperature.
        return round(max(0.0, self.base_water_inches + self._water_drift), 2)

    @property
    def height(self) -> float:
        # Product height in inches based on how full the tank is
        return _height_from_fill_fraction(self.diameter, self.fill_fraction)

    @property
    def volume(self) -> int:
        # Current volume in gallons
        return round(_cylinder_volume_from_height(self.diameter, self.length, self.height))

    @property
    def tc_volume(self) -> int:
        # Temperature-compensated volume -- this is what the real systems report
        temp = self.temperature
        correction = 1.0 + THERMAL_COEFF * (REFERENCE_TEMP - temp)
        return round(self.volume * correction)

    @property
    def ullage(self) -> int:
        # Remaining capacity (how much more fuel can fit)
        return max(0, self.capacity - self.volume)

    def fmt_temp(self) -> str:
        return f"{self.temperature:.2f}"

    def fmt_water(self) -> str:
        return f"{self.water:.2f}"

    def fmt_height(self) -> str:
        return f"{self.height:.2f}"

    def tick_consumption(self, elapsed_seconds: float,
                         time_of_day_factor: float = 1.0) -> None:
        """Simulate fuel being sold -- reduce fill_fraction based on
        consumption_gph and the elapsed time since the last tick.

        The rate has a small random jitter (±15%) each tick to simulate
        the irregular pattern of real customer purchases -- sometimes
        nobody is buying, sometimes several cars at once.

        time_of_day_factor scales the rate:
            1.0  = normal daytime business
            0.6  = early morning / late evening (slow)
            0.05 = overnight closed hours (near zero, just a trickle
                    for generator/cooler fuel consumption)
            1.3  = rush hour peak
        """
        if self.consumption_gph <= 0 or elapsed_seconds <= 0:
            return

        # Jitter: sometimes busy, sometimes quiet
        jitter = random.uniform(0.85, 1.15)
        effective_rate = self.consumption_gph * jitter * time_of_day_factor
        gallons_consumed = effective_rate * (elapsed_seconds / 3600.0)

        # Convert gallons consumed to a fill_fraction decrease
        cap = self.capacity
        if cap > 0:
            fraction_consumed = gallons_consumed / cap
            self.fill_fraction = max(0.01, self.fill_fraction - fraction_consumed)


@dataclass
class StationState:
    # State for the whole station -- name, tanks, serial number, etc.

    name: str
    tanks: list[Tank] = field(default_factory=list)
    serial_number: str = "0000112233"
    software_version: str = "V364.200"
    hardware_version: str = "HW 4.02"
    created_at: datetime.datetime = field(default_factory=lambda: datetime.datetime.now(datetime.UTC))

    # Track date/time override attempts
    time_override: datetime.datetime | None = None

    @property
    def now(self) -> datetime.datetime:
        return self.time_override or datetime.datetime.now(datetime.UTC)


def build_station(config: configparser.ConfigParser) -> StationState:
    # Build the station from the config file -- randomize everything so
    # no two instances look the same
    low_temp = config.getint("parameters", "low_temperature")
    high_temp = config.getint("parameters", "high_temperature")
    min_h2o = config.getint("parameters", "min_h2o")
    max_h2o = config.getint("parameters", "max_h2o")

    products = [
        config.get("products", f"product{i}") for i in range(1, 5)
    ]

    station_names = ast.literal_eval(config.get("stations", "list"))
    station_name = random.choice(station_names)

    now = datetime.datetime.now(datetime.UTC)

    # Standard tank sizes (diameter x length in inches)
    tank_sizes = [
        (96.0, 192.0),   # 8ft x 16ft  ~  ~12,000 gal
        (96.0, 144.0),   # 8ft x 12ft  ~  ~9,000 gal
        (64.0, 192.0),   # 5.3ft x 16ft ~ ~5,300 gal
        (96.0, 240.0),   # 8ft x 20ft  ~  ~15,000 gal
    ]

    tanks: list[Tank] = []
    for i, prod in enumerate(products, start=1):
        diam, length = tank_sizes[i - 1] if i <= len(tank_sizes) else (96.0, 192.0)

        # Realistic fill levels: 25-85% full
        fill_frac = random.uniform(0.25, 0.85)

        # Each tank gets its own delivery time
        delivery_offset = random.randint(120, 720)  # 2-12 hours ago
        fill_start = now - datetime.timedelta(minutes=delivery_offset + 10)
        fill_stop = now - datetime.timedelta(minutes=delivery_offset)

        tanks.append(
            Tank(
                number=i,
                product=prod,
                diameter=diam,
                length=length,
                fill_fraction=fill_frac,
                base_temperature=random.uniform(low_temp, high_temp),
                base_water_inches=random.uniform(min_h2o * 0.1, max_h2o * 0.1),
                fill_start=fill_start,
                fill_stop=fill_stop,
            )
        )

    # Consumption simulation -- set per-tank drain rates from config
    # Each tank gets the base GPH ±30% so they drain at different rates
    base_gph = 0.0
    if config.has_section("consumption") and config.getboolean("consumption", "enabled", fallback=False):
        base_gph = config.getfloat("consumption", "gallons_per_hour", fallback=80.0)

    for t in tanks:
        if base_gph > 0:
            # Randomize ±30% so tanks don't all empty at the same time
            t.consumption_gph = base_gph * random.uniform(0.70, 1.30)

    return StationState(name=station_name, tanks=tanks)


# Veeder-Root TLS command handlers
#
# Each function handles one command code. They take the station state
# and any extra payload data, return the response string. The command
# registry dict at the bottom maps codes to functions.

def _ts(station: StationState) -> str:
    # formatted timestamp for response headers
    return station.now.strftime("%m/%d/%Y %H:%M")


# I101xx -- System Status Report

def cmd_I10100(station: StationState, _payload: str) -> str:
    lines = [
        "",
        "I10100",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "SYSTEM STATUS REPORT",
        "",
        f"       SERIAL# : {station.serial_number}",
        f"  SOFTWARE VER : {station.software_version}",
        "",
        "  POWER STATUS : AC ON",
        "  BATTERY      : OK",
        "  PRINTER      : ACTIVE",
        "",
        "  COMM 1       : ENABLED  IDLE",
        "  COMM 2       : DISABLED",
        "",
    ]
    return "\n".join(lines)


# I102xx -- System Configuration

def cmd_I10200(station: StationState, _payload: str) -> str:
    lines = [
        "",
        "I10200",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "SYSTEM CONFIGURATION",
        "",
        f"  SERIAL#      : {station.serial_number}",
        f"  SOFTWARE VER : {station.software_version}",
        "  LANGUAGE     : ENGLISH",
        "  UNITS        : U.S.",
        f"  NUMBER OF TANKS: {len(station.tanks)}",
        "",
    ]
    for t in station.tanks:
        lines.append(f"  TANK {t.number}: {t.product_padded()} CAPACITY: {t.capacity}")
    lines.append("")
    return "\n".join(lines)


# I111xx -- Priority Alarm History Report
# (Function Code 111 per Veeder-Root manual 576013-635)
# Shows recent alarm events. Scanners probe this a lot.

def cmd_I11100(station: StationState, _payload: str) -> str:
    alarm_time = (station.now - datetime.timedelta(hours=6)).strftime("%-m-%d-%y  %-I:%M%p")
    clear_time = (station.now - datetime.timedelta(hours=5, minutes=45)).strftime("%-m-%d-%y  %-I:%M%p")
    lines = [
        "",
        "I11100",
        _ts(station),
        f"    {station.name}",
        "",
        "",
        "",
        "PRIORITY ALARM HISTORY",
        "",
        "ID  CATEGORY  DESCRIPTION          ALARM TYPE           STATE    DATE    TIME",
        f"    SYSTEM                         BATTERY IS OFF       CLEAR   {clear_time}",
        f"    SYSTEM                         BATTERY IS OFF       ALARM   {alarm_time}",
        "",
    ]
    return "\n".join(lines)


# I201xx -- In-Tank Inventory (this is the most commonly probed command)

def cmd_I20100(station: StationState, _payload: str) -> str:
    lines = [
        "",
        "I20100",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "IN-TANK INVENTORY",
        "",
        "TANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP",
    ]
    for t in station.tanks:
        lines.append(
            f"  {t.number}  {t.product_padded()}"
            f"{t.volume!s:>6}      {t.tc_volume!s:>6}     "
            f"{t.ullage!s:>5}    {t.fmt_height():>5}     "
            f"{t.fmt_water():>5}    {t.fmt_temp():>5}"
        )
    lines.append("")
    return "\n".join(lines)


# I202xx -- Delivery Report

def cmd_I20200(station: StationState, _payload: str) -> str:
    t = station.tanks[0]
    # Simulate delivery: before delivery was ~30% lower fill
    pre_delivery_frac = max(0.1, t.fill_fraction - 0.30)
    pre_height = _height_from_fill_fraction(t.diameter, pre_delivery_frac)
    pre_vol = round(_cylinder_volume_from_height(t.diameter, t.length, pre_height))
    pre_tc = round(pre_vol * (1.0 + THERMAL_COEFF * (REFERENCE_TEMP - t.base_temperature)))
    delivered = t.volume - pre_vol
    delivered_tc = t.tc_volume - pre_tc

    lines = [
        "",
        "I20200",
        _ts(station),
        "",
        "",
        f"    {station.name}",
        "",
        "",
        "DELIVERY REPORT",
        "",
        f"T {t.number}:{t.product_padded()}",
        "INCREASE   DATE / TIME             GALLONS TC GALLONS WATER  TEMP DEG F  HEIGHT",
        "",
        f"      END: {t.fill_stop.strftime('%m/%d/%Y %H:%M')}"
        f"         {t.volume}       {t.tc_volume}"
        f"   {t.fmt_water()}      {t.fmt_temp()}   {t.fmt_height()}",
        f"    START: {t.fill_start.strftime('%m/%d/%Y %H:%M')}"
        f"         {pre_vol}       {pre_tc}"
        f"   {t.fmt_water()}      {t.fmt_temp()}   {pre_height:.2f}",
        f"   AMOUNT:                          {max(0, delivered)}       {max(0, delivered_tc)}",
        "",
    ]
    return "\n".join(lines)


# I203xx -- Leak Detect Report

def cmd_I20300(station: StationState, _payload: str) -> str:
    lines = [
        "",
        "I20300",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
    ]
    for t in station.tanks:
        lines.extend([
            f"TANK {t.number}    {t.product_padded()}",
            "    TEST STATUS: OFF",
            "LEAK DATA NOT AVAILABLE ON THIS TANK",
            "",
            "",
        ])
    return "\n".join(lines)


# I204xx -- Shift Report

def cmd_I20400(station: StationState, _payload: str) -> str:
    t = station.tanks[0]
    # Shift start: slightly less product (sold during shift)
    shift_sold_frac = random.uniform(0.03, 0.08)
    start_frac = min(1.0, t.fill_fraction + shift_sold_frac)
    start_height = _height_from_fill_fraction(t.diameter, start_frac)
    start_vol = round(_cylinder_volume_from_height(t.diameter, t.length, start_height))
    start_tc = round(start_vol * (1.0 + THERMAL_COEFF * (REFERENCE_TEMP - t.base_temperature)))
    sold = start_vol - t.volume

    lines = [
        "",
        "I20400",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        " SHIFT REPORT",
        "",
        "SHIFT 1 TIME: 12:00 AM",
        "",
        "TANK PRODUCT",
        "",
        f"  {t.number}  {t.product_padded()}"
        f"                  VOLUME TC VOLUME  ULLAGE  HEIGHT  WATER   TEMP",
        f"SHIFT  1 STARTING VALUES      {start_vol}     {start_tc}"
        f"    {t.capacity - start_vol}   {start_height:.2f}   {t.fmt_water()}    {t.fmt_temp()}",
        f"         ENDING VALUES        {t.volume}     {t.tc_volume}"
        f"    {t.ullage}   {t.fmt_height()}"
        f"  {t.fmt_water()}    {t.fmt_temp()}",
        "         DELIVERY VALUE          0",
        f"         TOTALS                {max(0, sold)}",
        "",
    ]
    return "\n".join(lines)


# I205xx -- In-Tank Status

def cmd_I20500(station: StationState, _payload: str) -> str:
    lines = [
        "",
        "I20500",
        _ts(station),
        "",
        "",
        f"    {station.name}",
        "",
        "",
        "TANK   PRODUCT                 STATUS",
        "",
    ]
    for t in station.tanks:
        # Generate realistic status based on actual water level
        if t.water > 1.5:
            status = "HIGH WATER ALARM\n                               HIGH WATER WARNING"
        elif t.water > 1.0:
            status = "HIGH WATER WARNING"
        elif t.fill_fraction > 0.95:
            status = "HIGH PRODUCT ALARM"
        elif t.fill_fraction < 0.10:
            status = "LOW PRODUCT ALARM"
        else:
            status = "NORMAL"
        lines.extend([
            f"  {t.number}    {t.product_padded()}                   {status}",
            "",
        ])
    return "\n".join(lines)


# I206xx -- In-Tank Alarm History

def cmd_I20600(station: StationState, _payload: str) -> str:
    alarm_time = (station.now - datetime.timedelta(hours=3)).strftime("%m/%d/%Y %H:%M")
    clear_time = (station.now - datetime.timedelta(hours=2, minutes=45)).strftime("%m/%d/%Y %H:%M")
    lines = [
        "",
        "I20600",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "IN-TANK ALARM HISTORY",
        "",
    ]
    t2 = station.tanks[1] if len(station.tanks) > 1 else station.tanks[0]
    lines.extend([
        f"TANK {t2.number}    {t2.product_padded()}",
        "",
        f"  {alarm_time}  HIGH WATER WARNING  ALARM",
        f"  {clear_time}  HIGH WATER WARNING  CLEARED",
        "",
        "  NUMBER OF ALARMS: 1",
        "",
    ])
    for t in station.tanks:
        if t.number == t2.number:
            continue
        lines.extend([
            f"TANK {t.number}    {t.product_padded()}",
            "",
            "  NO ALARMS TO REPORT",
            "",
        ])
    return "\n".join(lines)


# I207xx -- Diagnostics Report

def cmd_I20700(station: StationState, _payload: str) -> str:
    lines = [
        "",
        "I20700",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "IN-TANK DIAGNOSTICS REPORT",
        "",
    ]
    for t in station.tanks:
        lines.extend([
            f"TANK {t.number}    {t.product_padded()}",
            "      PROBE TYPE       : MAG",
            "      PROBE STATUS     : OK",
            "      LEAK STATUS      : OK",
            "      TEMP SENSOR      : OK",
            "      WATER SENSOR     : OK",
            "",
        ])
    return "\n".join(lines)


# I208xx -- Tank Test Results

def cmd_I20800(station: StationState, _payload: str) -> str:
    test_time = (station.now - datetime.timedelta(days=1)).strftime("%m/%d/%Y %H:%M")
    lines = [
        "",
        "I20800",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "TANK TEST RESULTS",
        "",
    ]
    for t in station.tanks:
        lines.extend([
            f"TANK {t.number}    {t.product_padded()}",
            f"      LAST TEST DATE   : {test_time}",
            "      TEST RESULT      : PASS",
            "      LEAK RATE (GAL/H): 0.00",
            "      TEST DURATION    : 02:00",
            "      TEST TYPE        : STANDARD",
            "",
        ])
    return "\n".join(lines)


# I209xx -- Tank Tightness Test

def cmd_I20900(station: StationState, _payload: str) -> str:
    test_time = (station.now - datetime.timedelta(days=7)).strftime("%m/%d/%Y %H:%M")
    lines = [
        "",
        "I20900",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "TANK TIGHTNESS TEST RESULTS",
        "",
    ]
    for t in station.tanks:
        lines.extend([
            f"TANK {t.number}    {t.product_padded()}",
            f"      LAST TEST DATE   : {test_time}",
            "      TEST RESULT      : PASS",
            "      LEAK RATE (GAL/H): 0.000",
            "      DURATION (HRS)   : 04:00",
            "      TYPE             : PRECISION",
            f"      TEMP COMP VOL    : {t.tc_volume}",
            "",
        ])
    return "\n".join(lines)


# I214xx -- Overfill/High Product Alarm History

def cmd_I21400(station: StationState, _payload: str) -> str:
    alarm_time = (station.now - datetime.timedelta(days=2, hours=5)).strftime("%m/%d/%Y %H:%M")
    clear_time = (station.now - datetime.timedelta(days=2, hours=4, minutes=48)).strftime("%m/%d/%Y %H:%M")
    lines = [
        "",
        "I21400",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "OVERFILL/HIGH PRODUCT ALARM HISTORY",
        "",
    ]
    t1 = station.tanks[0]
    high_limit = int(t1.capacity * 0.95)
    lines.extend([
        f"TANK {t1.number}    {t1.product_padded()}",
        "",
        f"  {alarm_time}  HIGH PRODUCT ALARM   {high_limit + 50} GALLONS  ALARM",
        f"  {clear_time}  HIGH PRODUCT ALARM   {high_limit - 100} GALLONS  CLEARED",
        "",
        "  NUMBER OF ALARMS: 1",
        "",
    ])
    for t in station.tanks[1:]:
        lines.extend([
            f"TANK {t.number}    {t.product_padded()}",
            "",
            "  NO ALARMS TO REPORT",
            "",
        ])
    return "\n".join(lines)


# I251xx -- Line Leak Test Results

def cmd_I25100(station: StationState, _payload: str) -> str:
    test_time = (station.now - datetime.timedelta(hours=6)).strftime("%m/%d/%Y %H:%M")
    lines = [
        "",
        "I25100",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "LINE LEAK TEST RESULTS",
        "",
    ]
    for t in station.tanks:
        lines.extend([
            f"LINE {t.number}    {t.product_padded()}",
            f"      TEST DATE        : {test_time}",
            "      RESULT           : PASS",
            "      LEAK RATE (GPH)  : 0.00",
            "      TEST TYPE        : 3.0 GPH",
            "",
        ])
    return "\n".join(lines)


# I301xx -- Sensor Status

def cmd_I30100(station: StationState, _payload: str) -> str:
    lines = [
        "",
        "I30100",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "SENSOR STATUS REPORT",
        "",
    ]
    sensor_labels = ["SUMP SENSOR 1", "SUMP SENSOR 2", "DISPENSER PAN 1", "DISPENSER PAN 2"]
    for i, label in enumerate(sensor_labels, start=1):
        lines.extend([
            f"  SENSOR {i}: {label}",
            "      STATUS : SENSOR DRY",
            "      TYPE   : LIQUID DISCRIMINATING",
            "",
        ])
    return "\n".join(lines)


# I302xx -- Sensor Alarm History

def cmd_I30200(station: StationState, _payload: str) -> str:
    lines = [
        "",
        "I30200",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "SENSOR ALARM HISTORY",
        "",
        "  NO ALARMS TO REPORT",
        "",
    ]
    return "\n".join(lines)


# I501xx -- Date/Time Query (recon scanners love this one)

def cmd_I50100(station: StationState, _payload: str) -> str:
    lines = [
        "",
        "I50100",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        f"  DATE: {station.now.strftime('%m/%d/%Y')}",
        f"  TIME: {station.now.strftime('%H:%M:%S')}",
        f"  DAY : {station.now.strftime('%A').upper()}",
        "",
    ]
    return "\n".join(lines)


# I601xx -- Tank Configuration Data

def cmd_I60100(station: StationState, _payload: str) -> str:
    lines = [
        "",
        "I60100",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "TANK CONFIGURATION DATA",
        "",
    ]
    for t in station.tanks:
        lines.extend([
            f"TANK {t.number}    {t.product_padded()}",
            f"      CAPACITY   (GAL) : {t.capacity}",
            f"      DIAMETER   (IN)  : {t.diameter:.2f}",
            f"      TILT       (DEG) : 0.00",
            f"      PROBE LENGTH(IN) : {t.diameter:.2f}",
            f"      PROBE OFFSET(IN) : 0.00",
            f"      THERMAL COEFF    : {THERMAL_COEFF:.6f}",
            f"      HIGH PRODUCT ALM : {int(t.capacity * 0.95)}",
            f"      HIGH WATER ALM   : 2.00",
            f"      HIGH WATER WARN  : 1.50",
            f"      LOW PRODUCT ALM  : {int(t.capacity * 0.10)}",
            f"      DELIVERY NEEDED  : {int(t.capacity * 0.20)}",
            f"      MAX TEMP ALM     : 150.00",
            "",
        ])
    return "\n".join(lines)


# I602xx -- Tank Product Label Config

def cmd_I60200(station: StationState, _payload: str) -> str:
    lines = [
        "",
        "I60200",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "TANK PRODUCT LABEL CONFIGURATION",
        "",
    ]
    for t in station.tanks:
        lines.append(f"  TANK {t.number}: {t.product}")
    lines.append("")
    return "\n".join(lines)


# I609xx -- Sensor Configuration

def cmd_I60900(station: StationState, _payload: str) -> str:
    lines = [
        "",
        "I60900",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "SENSOR CONFIGURATION DATA",
        "",
    ]
    sensor_labels = ["SUMP SENSOR 1", "SUMP SENSOR 2", "DISPENSER PAN 1", "DISPENSER PAN 2"]
    for i, label in enumerate(sensor_labels, start=1):
        lines.extend([
            f"  SENSOR {i}: {label}",
            "      TYPE     : LIQUID DISCRIMINATING",
            "      ALARM    : FUEL ALARM",
            "      POSITION : IN CONTAINMENT",
            "",
        ])
    return "\n".join(lines)


# I902xx -- Alarm Reset
# If someone is trying to reset alarms, that's active tampering

def cmd_I90200(station: StationState, _payload: str) -> str:
    logger.warning(
        "ALARM RESET ATTEMPT",
        extra={"command": "I90200"},
    )
    lines = [
        "",
        "I90200",
        _ts(station),
        "",
        f"    {station.name}",
        "",
        "",
        "ALARM RESET",
        "",
        "  ALL ALARMS CLEARED",
        "",
    ]
    return "\n".join(lines)


# S501xx -- Set Date/Time
# If an attacker is changing the time, that's a big deal -- always log it

def cmd_S50100(station: StationState, payload: str) -> str:
    logger.warning(
        "DATE/TIME CHANGE ATTEMPT: payload=%r",
        payload,
        extra={"command": "S50100"},
    )
    try:
        date_str = payload.strip()
        if len(date_str) >= 10:
            station.time_override = datetime.datetime.strptime(date_str[:10], "%y%m%d%H%M")
            logger.warning("Date/time overridden to %s", station.time_override.isoformat())
    except (ValueError, IndexError):
        pass
    return f"\nS50100\n{_ts(station)}\n\nDATE/TIME SET\n"


# S601xx -- Set Station Name

def cmd_S60100(station: StationState, payload: str) -> str:
    # rename the station -- log this
    new_name = payload.strip()
    if not new_name:
        return "9999FF1B\n"
    old_name = station.name
    station.name = new_name
    logger.warning(
        "STATION NAME CHANGED: %r -> %r",
        old_name,
        new_name,
        extra={"command": "S60100"},
    )
    return f"\nS60100\n{_ts(station)}\n\nSTATION NAME SET: {new_name}\n"


# S602xx -- Set Product Label
# S60200 sets all tanks, S60201-S60204 set individual tanks
# (used to be copy-pasted 5 times, now its one function)

def cmd_S602xx(station: StationState, payload: str, cmd: str) -> str:
    tank_digit = cmd[5]  # '0' = all, '1'-'4' = individual
    new_label = payload.strip()

    if not new_label:
        return "9999FF1B\n"

    if len(new_label) > 22:
        new_label = new_label[:20] + "  "
    else:
        new_label = new_label.ljust(22)

    if tank_digit == "0":
        for t in station.tanks:
            t.product = new_label.strip()
        logger.warning("ALL tank labels set to %r", new_label.strip(), extra={"command": cmd})
    else:
        idx = int(tank_digit) - 1
        if 0 <= idx < len(station.tanks):
            station.tanks[idx].product = new_label.strip()
            logger.warning("Tank %s label set to %r", tank_digit, new_label.strip(), extra={"command": cmd})
        else:
            return "9999FF1B\n"

    return ""


# Command registry -- maps command codes to handler functions

INQUIRY_COMMANDS: dict[str, Callable[[StationState, str], str]] = {
    # System-level
    "I10100": cmd_I10100,
    "I10200": cmd_I10200,
    "I11100": cmd_I11100,
    # In-tank reports
    "I20100": cmd_I20100,
    "I20200": cmd_I20200,
    "I20300": cmd_I20300,
    "I20400": cmd_I20400,
    "I20500": cmd_I20500,
    "I20600": cmd_I20600,
    "I20700": cmd_I20700,
    "I20800": cmd_I20800,
    "I20900": cmd_I20900,
    "I21400": cmd_I21400,
    # Line leak
    "I25100": cmd_I25100,
    # Sensor reports
    "I30100": cmd_I30100,
    "I30200": cmd_I30200,
    # Date/time query
    "I50100": cmd_I50100,
    # Configuration queries
    "I60100": cmd_I60100,
    "I60200": cmd_I60200,
    "I60900": cmd_I60900,
    # Alarm reset
    "I90200": cmd_I90200,
}

SET_COMMANDS: dict[str, Callable[[StationState, str], str]] = {
    "S50100": cmd_S50100,
    "S60100": cmd_S60100,
}

# S602xx is handled specially (variable last digit)


# Connection handler -- parse the incoming data, figure out what command
# they sent, and call the right function

def handle_command(station: StationState, raw: bytes, remote_ip: str) -> str | None:
    decoded = raw.decode(errors="replace")

    # Strip the SOH prefix:  ^A (literal two chars) or 0x01
    if decoded.startswith("^A"):
        cmd_area = decoded[2:]
    elif decoded.startswith("\x01"):
        cmd_area = decoded[1:]
    else:
        logger.info(
            "Non-^A command from %s: %r",
            remote_ip,
            decoded[:40],
            extra={"remote_ip": remote_ip},
        )
        return None

    cmd_area = cmd_area.strip()
    if len(cmd_area) < 6:
        logger.info(
            "Short command from %s: %r",
            remote_ip,
            cmd_area,
            extra={"remote_ip": remote_ip},
        )
        return None

    cmd = cmd_area[:6]
    payload = cmd_area[6:]

    # 1. Exact-match inquiry commands
    if cmd in INQUIRY_COMMANDS:
        logger.info(
            "CMD %s from %s",
            cmd,
            remote_ip,
            extra={"remote_ip": remote_ip, "command": cmd},
        )
        return INQUIRY_COMMANDS[cmd](station, payload)

    # 2. Exact-match set commands
    if cmd in SET_COMMANDS:
        logger.warning(
            "SET CMD %s from %s payload=%r",
            cmd,
            remote_ip,
            payload[:60],
            extra={"remote_ip": remote_ip, "command": cmd},
        )
        return SET_COMMANDS[cmd](station, payload)

    # 3. S602xx  -- set product label (variable last digit)
    if cmd.startswith("S6020"):
        logger.warning(
            "SET CMD %s from %s payload=%r",
            cmd,
            remote_ip,
            payload[:60],
            extra={"remote_ip": remote_ip, "command": cmd},
        )
        return cmd_S602xx(station, payload, cmd)

    # 4. Unknown command -- log and return error
    logger.warning(
        "UNKNOWN CMD %r from %s raw=%r",
        cmd,
        remote_ip,
        decoded[:80],
        extra={"remote_ip": remote_ip, "command": cmd},
    )
    return None


# Protocol envelope characters (from the Veeder-Root serial interface manual)
# Responses get wrapped in SOH...ETX, errors are SOH+9999FF1B+ETX
SOH = "\x01"  # Start of Header (ASCII 01)
ETX = "\x03"  # End of Text (ASCII 03)

ERROR_RESPONSE = f"{SOH}9999FF1B{ETX}"

# TCP server

def _get_time_of_day_factor(hour: int) -> float:
    """Return a consumption rate multiplier based on time of day.

    Models realistic gas station traffic patterns:
        - Overnight (11 PM - 5 AM):  nearly closed, just a trickle
          for generator/refrigeration fuel use
        - Early morning (5-7 AM):    opening up, light traffic
        - Morning rush (7-9 AM):     commuters filling up
        - Midday (9 AM - 4 PM):      steady normal traffic
        - Evening rush (4-7 PM):     commuters again, peak
        - Evening (7-11 PM):         winding down

    With these factors, a base GPH of 80 averages out to roughly
    50 effective GPH over 24 hours.  At ~50 GPH per tank with
    ~6000 gallon tanks, each tank empties in about 5 days, meaning
    deliveries happen roughly once a week per tank — realistic for
    a moderately busy station.
    """
    if 23 <= hour or hour < 5:       # Overnight -- station closed/minimal
        return 0.05
    elif 5 <= hour < 7:              # Early morning -- opening, light traffic
        return 0.40
    elif 7 <= hour < 9:              # Morning rush -- commuters
        return 1.30
    elif 9 <= hour < 12:             # Late morning -- steady
        return 1.00
    elif 12 <= hour < 14:            # Lunch rush -- bump
        return 1.15
    elif 14 <= hour < 16:            # Afternoon -- steady
        return 0.90
    elif 16 <= hour < 19:            # Evening rush -- peak
        return 1.40
    elif 19 <= hour < 21:            # Evening -- winding down
        return 0.60
    else:                            # Late evening (21-23) -- slow
        return 0.25


def _tick_consumption(station: StationState, elapsed: float,
                      delivery_threshold: float, delivery_fill_to: float) -> None:
    """Simulate fuel consumption and auto-delivery for all tanks.

    Called every select() cycle (every ~2 seconds).  Each tank drains
    based on its consumption_gph rate, scaled by the time-of-day factor
    so consumption is realistic -- busy during rush hours, near-zero
    overnight when the station is effectively closed.

    With default settings (80 GPH base), tanks drain to the delivery
    threshold roughly once a week, at which point an automatic delivery
    is triggered to refill them.

    Args:
        station: The station state with all tanks
        elapsed: Seconds since the last tick
        delivery_threshold: Fill fraction (0.0-1.0) below which to trigger delivery
        delivery_fill_to: Fill fraction (0.0-1.0) to fill to after delivery
    """
    now = datetime.datetime.now(datetime.UTC)
    hour = now.hour
    tod_factor = _get_time_of_day_factor(hour)

    for t in station.tanks:
        old_fill = t.fill_fraction
        t.tick_consumption(elapsed, time_of_day_factor=tod_factor)

        # Nudge temperature and water drift accumulators.
        # Each tick (~2s) adds a *tiny* random step.  At ±0.001°F per
        # tick, it takes ~500 ticks (about 17 minutes) to drift just
        # 0.5°F — readings look rock-stable on rapid refresh but still
        # wander slowly over hours, just like a real underground tank.
        # Clamped to ±0.50°F and ±0.05 inches total drift.
        t._temp_drift += random.uniform(-0.001, 0.001)
        t._temp_drift = max(-0.50, min(0.50, t._temp_drift))
        t._water_drift += random.uniform(-0.0005, 0.0005)
        t._water_drift = max(-0.05, min(0.05, t._water_drift))

        # Auto-delivery: when tank drops below threshold, simulate a
        # fuel truck delivery (fill back up to delivery_fill_to level)
        if t.fill_fraction < delivery_threshold and old_fill >= delivery_threshold:
            logger.info(
                "Tank %d (%s) at %.1f%% -- triggering auto-delivery to %.0f%%",
                t.number, t.product, t.fill_fraction * 100, delivery_fill_to * 100,
            )
            # Record delivery timestamps
            t.fill_start = now
            t.fill_fraction = delivery_fill_to
            t.fill_stop = now + datetime.timedelta(minutes=random.randint(8, 15))


def run_server(station: StationState, host: str, port: int, buffer_size: int,
               config: configparser.ConfigParser | None = None) -> None:
    # Main server loop -- uses select() so we can handle multiple connections
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setblocking(False)
    server.bind((host, port))
    server.listen(16)

    logger.info("GasPot v%s listening on %s:%d", __version__, host, port)
    logger.info("Station: %s  |  Tanks: %d", station.name, len(station.tanks))

    # Consumption simulation settings from config
    consumption_enabled = False
    delivery_threshold = 0.20  # 20% fill
    delivery_fill_to = 0.85   # 85% fill
    if config and config.has_section("consumption"):
        consumption_enabled = config.getboolean("consumption", "enabled", fallback=False)
        delivery_threshold = config.getfloat("consumption", "delivery_threshold", fallback=20) / 100.0
        delivery_fill_to = config.getfloat("consumption", "delivery_fill_to", fallback=85) / 100.0

    if consumption_enabled:
        gph_rates = [f"T{t.number}:{t.consumption_gph:.0f}" for t in station.tanks]
        logger.info("Consumption simulation ON  |  GPH: %s  |  Delivery at %.0f%% → %.0f%%",
                     ", ".join(gph_rates), delivery_threshold * 100, delivery_fill_to * 100)
    else:
        logger.info("Consumption simulation OFF (tank levels stay static)")

    import time as _time
    last_tick = _time.monotonic()

    active: list[socket.socket] = [server]
    shutdown_event = threading.Event()

    def _signal_handler(signum: int, _frame) -> None:
        logger.info("Received signal %d -- shutting down", signum)
        shutdown_event.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    try:
        while not shutdown_event.is_set():
            try:
                readable, _, errored = select.select(active, [], active, 2.0)
            except (OSError, ValueError):
                break

            # Consumption tick -- runs every select() cycle (~2 seconds)
            # even when no connections come in, so tanks drain continuously
            if consumption_enabled:
                now_mono = _time.monotonic()
                elapsed = now_mono - last_tick
                last_tick = now_mono
                _tick_consumption(station, elapsed, delivery_threshold, delivery_fill_to)

            for sock in errored:
                active.remove(sock)
                sock.close()

            for sock in readable:
                if sock is server:
                    try:
                        client, addr = server.accept()
                        client.settimeout(30.0)
                        active.append(client)
                        logger.info("Connection from %s:%d", addr[0], addr[1])
                    except OSError:
                        continue
                else:
                    _handle_client(sock, active, station)
    finally:
        for s in active:
            try:
                s.close()
            except OSError:
                pass
        logger.info("Server shut down cleanly")


def _handle_client(
    conn: socket.socket,
    active: list[socket.socket],
    station: StationState,
) -> None:
    # Handle one client connection
    try:
        addr = conn.getpeername()
        remote_ip = addr[0]
    except OSError:
        _close(conn, active)
        return

    try:
        data = conn.recv(4096)
        if not data:
            _close(conn, active)
            return

        # Read until we see a newline or '00' terminator (TLS protocol)
        while b"\n" not in data and b"00" not in data:
            more = conn.recv(4096)
            if not more:
                break
            data += more

        response = handle_command(station, data, remote_ip)
        if response is not None:
            # Wrap in SOH...ETX envelope per Veeder-Root display format spec
            wrapped = f"{SOH}{response}{ETX}"
            conn.sendall(wrapped.encode(errors="replace"))
        else:
            conn.sendall(ERROR_RESPONSE.encode())

    except socket.timeout:
        logger.debug("Timeout on connection from %s", remote_ip)
        _close(conn, active)
    except OSError as exc:
        logger.debug("OS error on %s: %s", remote_ip, exc)
        _close(conn, active)
    except Exception:
        logger.exception("Unexpected error handling client %s", remote_ip)
        _close(conn, active)


def _close(conn: socket.socket, active: list[socket.socket]) -> None:
    # Clean up a socket
    if conn in active:
        active.remove(conn)
    try:
        conn.close()
    except OSError:
        pass


# Entry point


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GasPot -- Veeder-Root TLS ATG Honeypot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Emulates a Veeder-Root TLS-350/TLS-450 Automatic Tank Gauge controller.
Supports 21 inquiry commands and several set/write commands.
All connections and commands are logged for threat intelligence.

Supported commands:
  I10100  System Status          I20700  Diagnostics
  I10200  System Configuration   I20800  Tank Test Results
  I11100  Priority Alarm History I20900  Tightness Test
  I20100  In-Tank Inventory      I21400  Overfill Alarm History
  I20200  Delivery Report        I25100  Line Leak Test
  I20300  Leak Detect Report     I30100  Sensor Status
  I20400  Shift Report           I30200  Sensor Alarm History
  I20500  In-Tank Status         I50100  Date/Time Query
  I20600  Alarm History          I60100  Tank Config
  I60200  Product Labels         I60900  Sensor Config
  I90200  Alarm Reset            S50100  Set Date/Time
  S60100  Set Station Name       S602xx  Set Product Labels
""",
    )
    parser.add_argument(
        "--config",
        default="config.ini",
        help="configuration file path (default: config.ini)",
    )
    parser.add_argument(
        "--log",
        default="gaspot.log",
        help="log file path (default: gaspot.log)",
    )
    parser.add_argument(
        "--json-log",
        action="store_true",
        default=False,
        help="emit logs as JSON lines (useful for SIEM ingest)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="suppress console output; log only to file",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"GasPot {__version__}",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    # Logging
    _setup_logging(args.log, args.quiet, args.json_log)

    # Configuration
    config_path = Path(args.config)
    if not config_path.is_file():
        logger.error(
            "Configuration file not found: %s  "
            "(copy config.ini.dist -> config.ini)",
            config_path,
        )
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(str(config_path))

    # Build station
    station = build_station(config)

    # Run
    host = config.get("host", "tcp_ip")
    port = config.getint("host", "tcp_port")
    buf = config.getint("host", "buffer_size")

    run_server(station, host, port, buf, config=config)


if __name__ == "__main__":
    main()
