import json, os, secrets, urllib.request
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import (Column, Integer, MetaData, String, Table, Text,
                        create_engine, insert, select, update)
from sqlalchemy.exc import IntegrityError

ADMIN_KEY = os.getenv("ADMIN_KEY")
SLACK = os.getenv("SLACK_WEBHOOK_URL")
DATABASE_URL = os.getenv("DATABASE_URL")  # set this on Render to use Postgres

if not ADMIN_KEY:
    raise SystemExit("Set the ADMIN_KEY environment variable first.")
if DATABASE_URL and len(ADMIN_KEY) < 20:
    raise SystemExit("In production, ADMIN_KEY must be at least 20 characters.")

if DATABASE_URL:
    # Render gives postgres://... ; SQLAlchemy with psycopg needs the prefix below
    url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    engine = create_engine(url, pool_pre_ping=True)
else:
    engine = create_engine("sqlite:///" + os.getenv("DB_PATH", "alerts.db"),
                           connect_args={"check_same_thread": False, "timeout": 10})

md = MetaData()
clients = Table("clients", md,
    Column("id", Integer, primary_key=True),
    Column("name", String(200), unique=True, nullable=False),
    Column("ingest_key", String(100), unique=True),
    Column("portal_key", String(100), unique=True))
alerts = Table("alerts", md,
    Column("id", Integer, primary_key=True),
    Column("client_id", Integer, index=True),
    Column("title", Text), Column("severity", String(20)),
    Column("source", String(50)), Column("status", String(20), default="new"),
    Column("actions", Text, default="[]"), Column("created", String(40)))
rules = Table("rules", md,
    Column("id", Integer, primary_key=True),
    Column("name", String(200)), Column("severities", String(100)),
    Column("action", String(50)), Column("enabled", Integer, default=1))
md.create_all(engine)

with engine.begin() as conn:
    if not conn.execute(select(rules.c.id)).first():
        conn.execute(insert(rules), [
            {"name": "Notify the team on Slack", "severities": "critical", "action": "slack", "enabled": 1},
            {"name": "Open a ticket", "severities": "high", "action": "ticket", "enabled": 1},
            {"name": "Add to the daily digest", "severities": "medium,low", "action": "digest", "enabled": 0}])

app = FastAPI(title="Security alerts API")
origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins,
                   allow_methods=["*"], allow_headers=["*"])


def require_admin(key):
    if not key or not secrets.compare_digest(key, ADMIN_KEY):
        raise HTTPException(401, "Invalid admin key")


def client_for(column, key):
    with engine.connect() as conn:
        row = conn.execute(select(clients).where(clients.c[column] == (key or ""))).mappings().first()
    if not row:
        raise HTTPException(401, "Invalid key")
    return row


def notify(text):
    if not SLACK:
        print("NOTIFY:", text)
        return
    try:
        req = urllib.request.Request(SLACK, json.dumps({"text": text}).encode(),
                                     {"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print("Slack failed:", e)


def create_alert(client, title, severity, source):
    done = []
    with engine.begin() as conn:
        active = conn.execute(select(rules).where(rules.c.enabled == 1)).mappings().all()
        for r in active:
            if severity in r["severities"].split(","):
                if r["action"] == "slack":
                    notify(f"[{severity.upper()}] {client['name']}: {title}")
                done.append(r["name"])  # ticket and digest actions: connect your tools here
        res = conn.execute(insert(alerts).values(
            client_id=client["id"], title=title, severity=severity, source=source,
            status="new", actions=json.dumps(done),
            created=datetime.now(timezone.utc).isoformat()))
        alert_id = res.inserted_primary_key[0]
    return {"id": alert_id, "actions": done}


class Alert(BaseModel):
    title: str
    severity: str = "medium"
    source: str = "api"


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/ingest")
def ingest(a: Alert, x_ingest_key: str = Header(None)):
    if a.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(422, "severity must be critical, high, medium or low")
    return create_alert(client_for("ingest_key", x_ingest_key), a.title[:500], a.severity, a.source[:50])


@app.post("/ingest/wazuh")
def ingest_wazuh(payload: dict, x_ingest_key: str = Header(None)):
    level = int(payload.get("rule", {}).get("level", 0))
    sev = "critical" if level >= 12 else "high" if level >= 9 else "medium" if level >= 5 else "low"
    agent = payload.get("agent", {}).get("name", "unknown device")
    title = f"{payload.get('rule', {}).get('description', 'Security event')} ({agent})"
    return create_alert(client_for("ingest_key", x_ingest_key), title[:500], sev, "wazuh")


# ---- Operations (you and your team) ----
@app.post("/ops/clients")
def add_client(body: dict, x_admin_key: str = Header(None)):
    require_admin(x_admin_key)
    name = str(body.get("name", "")).strip()
    if not name:
        raise HTTPException(422, "name is required")
    keys = (secrets.token_urlsafe(24), secrets.token_urlsafe(24))
    try:
        with engine.begin() as conn:
            conn.execute(insert(clients).values(name=name, ingest_key=keys[0], portal_key=keys[1]))
    except IntegrityError:
        raise HTTPException(409, "A client with this name already exists. Use a different "
                                 "name, or reset its keys with POST /ops/clients/reset-keys")
    return {"name": name, "ingest_key": keys[0], "portal_key": keys[1]}


@app.get("/ops/clients")
def list_clients(x_admin_key: str = Header(None)):
    require_admin(x_admin_key)
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(select(clients.c.id, clients.c.name)).mappings()]


@app.post("/ops/clients/reset-keys")
def reset_keys(body: dict, x_admin_key: str = Header(None)):
    require_admin(x_admin_key)
    name = str(body.get("name", "")).strip()
    keys = (secrets.token_urlsafe(24), secrets.token_urlsafe(24))
    with engine.begin() as conn:
        res = conn.execute(update(clients).where(clients.c.name == name)
                           .values(ingest_key=keys[0], portal_key=keys[1]))
    if res.rowcount == 0:
        raise HTTPException(404, "No client with that name")
    return {"name": name, "ingest_key": keys[0], "portal_key": keys[1]}


@app.get("/ops/alerts")
def ops_alerts(x_admin_key: str = Header(None)):
    require_admin(x_admin_key)
    q = (select(alerts, clients.c.name.label("client"))
         .join(clients, clients.c.id == alerts.c.client_id)
         .order_by(alerts.c.id.desc()).limit(200))
    with engine.connect() as conn:
        rows = conn.execute(q).mappings().all()
    return [dict(r, actions=json.loads(r["actions"] or "[]")) for r in rows]


@app.patch("/ops/alerts/{alert_id}")
def set_status(alert_id: int, body: dict, x_admin_key: str = Header(None)):
    require_admin(x_admin_key)
    if body.get("status") not in ("new", "ack", "done"):
        raise HTTPException(422, "status must be new, ack or done")
    with engine.begin() as conn:
        conn.execute(update(alerts).where(alerts.c.id == alert_id).values(status=body["status"]))
    return {"ok": True}


@app.get("/ops/rules")
def get_rules(x_admin_key: str = Header(None)):
    require_admin(x_admin_key)
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(select(rules).order_by(rules.c.id)).mappings()]


@app.patch("/ops/rules/{rule_id}")
def toggle_rule(rule_id: int, body: dict, x_admin_key: str = Header(None)):
    require_admin(x_admin_key)
    with engine.begin() as conn:
        conn.execute(update(rules).where(rules.c.id == rule_id)
                     .values(enabled=int(bool(body.get("enabled")))))
    return {"ok": True}


# ---- Client portal (each client sees only their own alerts) ----
@app.get("/portal/alerts")
def portal_alerts(x_portal_key: str = Header(None)):
    client = client_for("portal_key", x_portal_key)
    q = (select(alerts.c.id, alerts.c.title, alerts.c.severity, alerts.c.status,
                alerts.c.actions, alerts.c.created)
         .where(alerts.c.client_id == client["id"]).order_by(alerts.c.id.desc()).limit(100))
    with engine.connect() as conn:
        rows = conn.execute(q).mappings().all()
    return {"client": client["name"],
            "alerts": [dict(r, actions=json.loads(r["actions"] or "[]")) for r in rows]}
