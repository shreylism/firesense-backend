import csv, hmac, io, os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field

DATABASE_URL = os.environ["DATABASE_URL"]
API_KEY = os.environ["GATEWAY_API_KEY"]
ONLINE_SECONDS = 90

pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=5, open=False,
                      kwargs={"row_factory": dict_row, "prepare_threshold": None})

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


def check(key: Optional[str]):
    if not key or not hmac.compare_digest(key, API_KEY):
        raise HTTPException(401, "bad api key")

def store(c, r: Reading) -> bool:
    ts = r.ts or datetime.now(timezone.utc)
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
    return row is not None


@app.get("/")
def root():
    return {"service": "FIRESENSE API", "docs": "/docs"}

@app.get("/health")
def health():
    return {"ok": True}

# ---------- from the Raspberry Pi (needs X-API-Key) ----------
@app.post("/api/v1/readings", status_code=201)
def add_reading(r: Reading, x_api_key: Optional[str] = Header(None)):
    check(x_api_key)
    with pool.connection() as c:
        return {"stored": store(c, r)}

@app.post("/api/v1/readings/batch", status_code=201)
def add_batch(rs: List[Reading], x_api_key: Optional[str] = Header(None)):
    check(x_api_key)
    with pool.connection() as c:
        n = sum(store(c, r) for r in rs)
    return {"received": len(rs), "stored": n}

@app.post("/api/v1/gateway/heartbeat")
def heartbeat(h: Heartbeat, x_api_key: Optional[str] = Header(None)):
    check(x_api_key)
    with pool.connection() as c:
        c.execute("""insert into gateways (gateway_id,last_seen) values (%s, now())
                     on conflict (gateway_id) do update set last_seen = now()""", (h.gateway_id,))
    return {"ok": True}

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
