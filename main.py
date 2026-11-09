import csv, hmac, io, json, os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import firebase_admin
from firebase_admin import credentials, messaging
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field

DATABASE_URL = os.environ["DATABASE_URL"]
API_KEY = os.environ["GATEWAY_API_KEY"]
ONLINE_SECONDS = 90
ALERT_MAX_AGE = timedelta(minutes=2)   # ignore readings older than this for alerts
MAX_TOKENS = 1000

pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=5, open=False,
                      kwargs={"row_factory": dict_row, "prepare_threshold": None})

# ---------- Firebase (notifications only) ----------
FCM_READY = False
try:
    _sa = os.environ.get("FIREBASE_SERVICE_ACCOUNT")
    if _sa:
        firebase_admin.initialize_app(credentials.Certificate(json.loads(_sa)))
        FCM_READY = True
    else:
        print("FIREBASE_SERVICE_ACCOUNT not set: notifications disabled")
except Exception as e:
    print("Firebase init failed:", e)

@asynccontextmanager
async def lifespan(app):
    pool.open()
    yield
    pool.close()

app = FastAPI(title="FIRESENSE API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class Reading(BaseModel):
    device_id: str
    gateway_id: Optional[str] = None
    ts: Optional[datetime] = None
    seq: Optional[int] = None
    rssi: Optional[float] = None
    snr: Optional[float] = None
    co_ppm: Optional[float] = None
    temp_c: Optional[float] = None
    pm25: Optional[float] = None
    pm10: Optional[float] = None
    status: int = Field(0, ge=0, le=2)
    raw_b64: Optional[str] = None

class Heartbeat(BaseModel):
    gateway_id: str

class PushToken(BaseModel):
    token: str = Field(min_length=20, max_length=4096)


def check(key: Optional[str]):
    if not key or not hmac.compare_digest(key, API_KEY):
        raise HTTPException(401, "bad api key")

def send_push(title: str, body: str):
    """Send a data-only push to every registered phone and remove dead tokens."""
    if not FCM_READY:
        return
    try:
        with pool.connection() as c:
            tokens = [x["token"] for x in c.execute("select token from push_tokens").fetchall()]
        if not tokens:
            return
        tokens = tokens[:500]
        msg = messaging.MulticastMessage(
            data={"title": title, "body": body},
            tokens=tokens,
            android=messaging.AndroidConfig(priority="high"),
            webpush=messaging.WebpushConfig(headers={"Urgency": "high", "TTL": "300"}),
        )
        resp = messaging.send_each_for_multicast(msg)
        dead = [t for t, x in zip(tokens, resp.responses)
                if not x.success and isinstance(
                    x.exception, (messaging.UnregisteredError, messaging.SenderIdMismatchError))]
        if dead:
            with pool.connection() as c:
                c.execute("delete from push_tokens where token = any(%s)", (dead,))
        print(f"push sent: {resp.success_count} ok, {resp.failure_count} failed, {len(dead)} removed")
    except Exception as e:
        print("push error:", e)

def fire_alert(readings: List[Reading]):
    r = readings[0]
    co = f"{r.co_ppm:.0f} ppm CO" if r.co_ppm is not None else "dangerous readings"
    send_push("FIRE detected", f"Device {r.device_id}: {co}. Check the dashboard now.")

def store(c, r: Reading, alerts: Optional[list] = None) -> bool:
    ts = r.ts or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    prev = c.execute("select last_status from devices where device_id=%s", (r.device_id,)).fetchone()
    row = c.execute(
        """insert into readings (device_id,gateway_id,ts,seq,rssi,snr,co_ppm,temp_c,pm25,pm10,status,raw_b64)
           values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           on conflict (device_id,ts,seq) do nothing returning id""",
        (r.device_id, r.gateway_id, ts, r.seq, r.rssi, r.snr, r.co_ppm, r.temp_c, r.pm25, r.pm10, r.status, r.raw_b64),
    ).fetchone()
    c.execute(
        """insert into devices (device_id,last_seen,last_status) values (%s,%s,%s)
           on conflict (device_id) do update set
             last_status = case when excluded.last_seen >= devices.last_seen
                                then excluded.last_status else devices.last_status end,
             last_seen = greatest(devices.last_seen, excluded.last_seen)""",
        (r.device_id, ts, r.status),
    )
    # alert only on a NEW, FRESH reading that moves the device into fire status
    if (alerts is not None and row is not None and r.status == 2
            and (prev is None or prev["last_status"] != 2)
            and datetime.now(timezone.utc) - ts < ALERT_MAX_AGE):
        alerts.append(r)
    return row is not None


@app.get("/")
def root():
    return {"service": "FIRESENSE API", "docs": "/docs"}

@app.get("/health")
def health():
    return {"ok": True, "push": FCM_READY}

# ---------- from the Raspberry Pi (needs X-API-Key) ----------
@app.post("/api/v1/readings", status_code=201)
def add_reading(r: Reading, bg: BackgroundTasks, x_api_key: Optional[str] = Header(None)):
    check(x_api_key)
    alerts: list = []
    with pool.connection() as c:
        stored = store(c, r, alerts)
    if alerts:
        bg.add_task(fire_alert, alerts)
    return {"stored": stored}

@app.post("/api/v1/readings/batch", status_code=201)
def add_batch(rs: List[Reading], bg: BackgroundTasks, x_api_key: Optional[str] = Header(None)):
    check(x_api_key)
    alerts: list = []
    with pool.connection() as c:
        n = sum(store(c, r, alerts) for r in rs)
    if alerts:
        bg.add_task(fire_alert, alerts)
    return {"received": len(rs), "stored": n}

@app.post("/api/v1/gateway/heartbeat")
def heartbeat(h: Heartbeat, x_api_key: Optional[str] = Header(None)):
    check(x_api_key)
    with pool.connection() as c:
        c.execute("""insert into gateways (gateway_id,last_seen) values (%s, now())
                     on conflict (gateway_id) do update set last_seen = now()""", (h.gateway_id,))
    return {"ok": True}

# ---------- phone notifications ----------
@app.post("/api/v1/push/register")
def push_register(t: PushToken):
    with pool.connection() as c:
        n = c.execute("select count(*) as n from push_tokens").fetchone()["n"]
        if n >= MAX_TOKENS:
            raise HTTPException(429, "too many registered phones")
        c.execute("insert into push_tokens (token) values (%s) on conflict do nothing", (t.token,))
    return {"ok": True}

@app.post("/api/v1/push/test")
def push_test(bg: BackgroundTasks, x_api_key: Optional[str] = Header(None)):
    check(x_api_key)
    bg.add_task(send_push, "FireSense test", "If you can read this, notifications work.")
    return {"queued": True, "push_ready": FCM_READY}

# ---------- public read-only (website + mobile app) ----------
@app.get("/api/v1/devices")
def devices():
    q = "select {k}, last_seen, (last_seen > now() - make_interval(secs => %s)) as online from {t} order by 1"
    with pool.connection() as c:
        d = c.execute(q.format(k="device_id, last_status", t="devices"), (ONLINE_SECONDS,)).fetchall()
        g = c.execute(q.format(k="gateway_id", t="gateways"), (ONLINE_SECONDS,)).fetchall()
    return {"gateways": g, "devices": d}

@app.get("/api/v1/readings/latest")
def latest(device_id: str):
    with pool.connection() as c:
        row = c.execute("select * from readings where device_id=%s order by ts desc limit 1", (device_id,)).fetchone()
    if not row:
        raise HTTPException(404, "no readings yet")
    return row

RANGES = {"1h": (timedelta(hours=1), "10 seconds"),
          "24h": (timedelta(hours=24), "1 minute"),
          "7d": (timedelta(days=7), "10 minutes")}

@app.get("/api/v1/readings")
def history(device_id: str, range: str = Query("1h", pattern="^(1h|24h|7d)$")):
    span, step = RANGES[range]
    with pool.connection() as c:
        rows = c.execute(
            """select date_bin(%s::interval, ts, timestamptz '2000-01-01') as ts,
                      avg(co_ppm) as co_ppm, avg(temp_c) as temp_c, avg(pm25) as pm25,
                      avg(pm10) as pm10, max(status) as status
               from readings where device_id=%s and ts >= %s group by 1 order by 1""",
            (step, device_id, datetime.now(timezone.utc) - span)).fetchall()
    return rows

@app.get("/api/v1/stats")
def stats():
    with pool.connection() as c:
        return c.execute("select count(*) as total_packets, max(ts) as last_packet_at from readings").fetchone()

@app.get("/api/v1/readings/export.csv")
def export_csv(device_id: str, hours: int = Query(168, ge=1, le=720)):
    cols = ["ts", "device_id", "gateway_id", "seq", "rssi", "snr", "co_ppm", "temp_c", "pm25", "pm10", "status"]
    with pool.connection() as c:
        rows = c.execute(f"select {','.join(cols)} from readings where device_id=%s and ts >= %s order by ts",
                         (device_id, datetime.now(timezone.utc) - timedelta(hours=hours))).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf); w.writerow(cols)
    for r in rows:
        w.writerow([r[k] for k in cols])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=readings.csv"})
