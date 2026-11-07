"""Drop this file next to your UDP receiver on the Raspberry Pi.
Env vars: FIRESENSE_URL (https://...onrender.com), FIRESENSE_KEY, GATEWAY_ID (optional)."""
import json, os, sqlite3, threading, time
from datetime import datetime, timezone
import requests

URL = os.environ["FIRESENSE_URL"].rstrip("/")
HEADERS = {"X-API-Key": os.environ["FIRESENSE_KEY"]}
GATEWAY_ID = os.environ.get("GATEWAY_ID", "pi-gw-01")

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
                              headers=HEADERS, timeout=5)
                last_hb = time.time()
            with _lock:
                rows = _db.execute("select id, body from q order by id limit 50").fetchall()
            if not rows:
                time.sleep(1); continue
            r = requests.post(URL + "/api/v1/readings/batch", json=[json.loads(b) for _, b in rows],
                              headers=HEADERS, timeout=10)
            if r.status_code in (200, 201) or r.status_code == 422:   # 422 = bad data, drop it
                if r.status_code == 422:
                    print("FIRESENSE: dropped invalid batch:", r.text[:200])
                with _lock:
                    _db.execute("delete from q where id <= ?", (rows[-1][0],)); _db.commit()
            else:
                print("FIRESENSE: upload failed", r.status_code, "will retry"); time.sleep(5)
        except Exception as e:
            print("FIRESENSE: offline, will retry:", e); time.sleep(5)

threading.Thread(target=_worker, daemon=True).start()
