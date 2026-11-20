import csv, hmac, io, json, math, os, time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import firebase_admin
from firebase_admin import credentials, messaging
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, ConfigDict, Field, model_validator

DATABASE_URL = os.environ["DATABASE_URL"]
API_KEY = os.environ["GATEWAY_API_KEY"]
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")          # set in Render to enable admin login
SESSION_SECRET = os.environ.get("SESSION_SECRET") or ADMIN_PASSWORD
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get(
    "ALLOWED_ORIGINS", "https://shreylism.github.io").split(",") if o.strip()]
ONLINE_SECONDS = 90
ALERT_MAX_AGE = timedelta(minutes=2)   # ignore readings older than this for alerts
MAX_TOKENS = 1000
ADMIN_TOKEN_HOURS = 8

# ---------- fire decision thresholds (prototype values) ----------
TH = {
    "temp_warn": 35.0, "temp_fire": 40.0,         # TMP117, deg C
    "rate_warn": 5.0,  "rate_fire": 8.0,          # deg C per minute
    "co_warn": 7.5,   "co_fire": 15.0,           # ZE07 CO, ppm
    "pm25_warn": 200.0, "pm25_fire": 250.0,       # SPS30 PM2.5, ug/m3
    "pm10_warn": 200.0, "pm10_fire": 250.0,  # SPS30 PM10, ug/m3
}
LEVEL_NAMES = ["NORMAL", "WARNING", "FIRE SUSPECTED", "FIRE ALERT"]
LOGIC_VERSION = "firesense-central-v1"
CAMERA_TRIGGER_LEVEL = 1  # Legacy compatibility only; camera trigger is now based on ALL warning thresholds.
CAMERA_TRIGGER_MODE = "ALL_WARNING_THRESHOLDS"
CAMERA_CAPTURE_INTERVAL_SECONDS = 5


def public_logic_config():
    """Single source of truth consumed by the dashboard, Pi and device clients."""
    return {
        "logic_version": LOGIC_VERSION,
        "thresholds": TH,
        "levels": LEVEL_NAMES,
        "camera_trigger_level": CAMERA_TRIGGER_LEVEL,
        "camera_trigger_level_name": LEVEL_NAMES[CAMERA_TRIGGER_LEVEL],  # legacy compatibility
        "camera_trigger_mode": CAMERA_TRIGGER_MODE,
        "camera_capture_interval_seconds": CAMERA_CAPTURE_INTERVAL_SECONDS,
        "camera_trigger_condition": (f"TEMP >= {TH['temp_warn']} C AND CO >= {TH['co_warn']} ppm "
                                     f"AND PM2.5 >= {TH['pm25_warn']} ug/m3 AND PM10 >= {TH['pm10_warn']} ug/m3; "
                                     "all four must be present and true"),
        "classification": {
            "temperature": "temp_c >= temp_fire OR temp_rate_c_min >= rate_fire => strong temperature signal; warn thresholds produce WARNING",
            "co": "co_ppm >= co_fire => strong CO signal; co_warn produces WARNING",
            "particles": "pm25 >= pm25_fire OR pm10 >= pm10_fire => strong smoke signal; warn thresholds produce WARNING",
            "level_3": "3 or more strong signal groups (temperature, CO, and particles)",
            "level_2": "2 strong signal groups",
            "level_1": "1 strong signal group or any warning signal",
            "level_0": "no warning or strong signals",
            "missing_sensors": "missing sensor values are ignored; they are not treated as zero",
        },
    }

def classify(temp, rate, co, pm25, pm10):
    """Return (level 0-3, reasons). Missing sensor values are ignored.

    The physical IR/flame sensor has been removed from this installation.
    Fire classification uses TMP117 temperature/rate, ZE07-CO, and SPS30 particles.
    """
    strong, warn, why = set(), set(), []

    def ge(value, threshold):
        return value is not None and value >= threshold

    if ge(temp, TH["temp_fire"]) or ge(rate, TH["rate_fire"]):
        strong.add("temperature")
        why.append("temperature")
    elif ge(temp, TH["temp_warn"]) or ge(rate, TH["rate_warn"]):
        warn.add("temperature")

    if ge(co, TH["co_fire"]):
        strong.add("co")
        why.append("CO")
    elif ge(co, TH["co_warn"]):
        warn.add("co")

    if ge(pm25, TH["pm25_fire"]) or ge(pm10, TH["pm10_fire"]):
        strong.add("particles")
        why.append("smoke particles")
    elif ge(pm25, TH["pm25_warn"]) or ge(pm10, TH["pm10_warn"]):
        warn.add("particles")

    strong_count = len(strong)
