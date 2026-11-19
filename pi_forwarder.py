"""Drop this file next to your UDP receiver on the Raspberry Pi.
Env vars: FIRESENSE_URL (https://...onrender.com), FIRESENSE_KEY, GATEWAY_ID (optional)."""
import json, os, sqlite3, threading, time
from datetime import datetime, timezone
import requests

URL = os.environ["FIRESENSE_URL"].rstrip("/")
HEADERS = {"X-API-Key": os.environ["FIRESENSE_KEY"]}
GATEWAY_ID = os.environ.get("GATEWAY_ID", "pi-gw-01")
export CAMERA_URL=http://10.29.8.53/capture
export CAMERA_KEY=9db066fa78241b7371ac02537f2af5cd1a65972a4eb036c0bd9d81b661f96c8e

_db = sqlite3.connect("outbox.db", check_same_thread=False)
_lock = threading.Lock()
_db.execute("create table if not exists q (id integer primary key, body text)")
_db.commit()

def forward(**reading):
    """Call this once per decoded packet, e.g. forward(device_id='node-01', seq=7, co_ppm=4.2, rssi=-80)"""
    reading.setdefault("gateway_id", GATEWAY_ID)
    reading.setdefault("ts", datetime.now(timezone.utc).isoformat())
    with _lock:
        _db.execute("insert into q (body) values (?)", (json.dumps(reading),))
        _db.commit()

def _worker():
    last_hb = 0
    while True:
        try:
            if time.time() - last_hb > 30:
                requests.post(URL + "/api/v1/gateway/heartbeat", json={"gateway_id": GATEWAY_ID},
                              headers=HEADERS, timeout=10)
                last_hb = time.time()
            with _lock:
                rows = _db.execute("select id, body from q order by id desc limit 50").fetchall()
            if not rows:
                time.sleep(1); continue
            r = requests.post(URL + "/api/v1/readings/batch", json=[json.loads(b) for _, b in rows],
                              headers=HEADERS, timeout=60)
            if r.status_code in (200, 201, 422):   # 422 = bad data, drop it
                if r.status_code == 422:
                    print("FIRESENSE: dropped invalid batch:", r.text[:200])
                with _lock:
                    _db.executemany("delete from q where id = ?", [(i,) for i, _ in rows]); _db.commit()
            else:
                print("FIRESENSE: upload failed", r.status_code, r.text[:200], "will retry"); time.sleep(5)
        except Exception as e:
            print("FIRESENSE: offline, will retry:", e); time.sleep(5)

threading.Thread(target=_worker, daemon=True).start()
# ---------- Camera snapshot on fire ----------
CAMERA_URL = os.environ.get("CAMERA_URL", "").strip()   # e.g. http://192.168.1.50/capture
CAMERA_KEY = os.environ.get("CAMERA_KEY", "").strip()   # same value as CAMERA_API_KEY in Render
CAM_COOLDOWN = float(os.environ.get("CAM_COOLDOWN", "10"))  # seconds between pictures
FIRE = {"co": float(os.environ.get("CO_FIRE", "15")),
        "pm25": float(os.environ.get("PM25_FIRE", "50")),
        "pm10": float(os.environ.get("PM10_FIRE", "50")),
        "temp": float(os.environ.get("TEMP_FIRE", "65"))}
_last_cam = 0.0

def _fire_groups(r):
    def hit(key, lim):
        try: return float(r.get(key)) >= lim
        except (TypeError, ValueError): return False
    return sum([hit("temp_c", FIRE["temp"]),
                hit("co_ppm", FIRE["co"]),
                hit("pm25", FIRE["pm25"]) or hit("pm10", FIRE["pm10"])])

def _snap(device_id):
    try:
        img = requests.get(CAMERA_URL, timeout=10)
        img.raise_for_status()
        r = requests.post(URL + "/api/v1/camera/snapshots",
            params=dict(device_id=device_id, prediction="fire", confidence=90,
                        fire_probability=90, alarm="true",
                        timestamp=datetime.now(timezone.utc).isoformat()),
            headers={"X-Camera-Key": CAMERA_KEY, "Content-Type": "image/jpeg"},
            data=img.content, timeout=60)
        print("FIRESENSE camera upload:", r.status_code, "" if r.status_code == 201 else r.text[:150])
    except Exception as e:
        print("FIRESENSE camera problem:", e)

_orig_forward = forward
def forward(**reading):
    global _last_cam
    _orig_forward(**reading)
    if CAMERA_URL and CAMERA_KEY and _fire_groups(reading) >= 2 and time.time() - _last_cam > CAM_COOLDOWN:
        _last_cam = time.time()
        threading.Thread(target=_snap, args=(reading.get("device_id", "cam-01"),), daemon=True).start()
