"""Node Manager Agent transport and task queue. NO SSH after provisioning.

Agent identity: a random 256-bit bearer secret bound to a single node, stored
as a SHA-256 digest. Transport relies on the existing HTTPS reverse proxy;
keys are never returned to the admin UI after initial SSH bootstrap.
"""
import hashlib
import hmac
import json
import re
import secrets
import time
import threading
import asyncio
import uuid
from datetime import datetime, timezone

from . import storage

ALLOWED = {"system.status", "docker.status", "docker.restart", "docker.logs", "logs.read",
           "service.status", "service.restart", "cert.status", "baseline.status",
           "config.read", "config.apply", "agent.update", "node.cleanup", "node.cleanup.finish",
           "security.fail2ban.install", "security.fail2ban.unban"}
MAX_RESULT = 48000
LEASE_SECONDS = 120

_WAIT_LOCK=threading.Lock()
_ASYNC_WAITERS={}


def _async_waiter(node_id: str):
    loop=asyncio.get_running_loop()
    with _WAIT_LOCK:
        saved=_ASYNC_WAITERS.get(node_id)
        if saved is None or saved[0] is not loop:
            saved=(loop,asyncio.Event())
            _ASYNC_WAITERS[node_id]=saved
        return saved[1]


def _notify(node_id: str):
    with _WAIT_LOCK:
        saved=_ASYNC_WAITERS.get(node_id)
    if not saved:return
    loop,event=saved
    try:loop.call_soon_threadsafe(event.set)
    except RuntimeError:pass



class AgentError(ValueError):
    pass


def initialize():
    with storage.connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS manager_agents(
          node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
          token_hash TEXT NOT NULL,
          version TEXT NOT NULL DEFAULT '',
          last_seen INTEGER NOT NULL DEFAULT 0,
          last_status_json TEXT NOT NULL DEFAULT '{}',
          enabled INTEGER NOT NULL DEFAULT 1,
          enrolled_at INTEGER NOT NULL DEFAULT 0,
          auto_update INTEGER NOT NULL DEFAULT 0,
          last_update_check INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS manager_agent_jobs(
          id TEXT PRIMARY KEY,
          node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
          action TEXT NOT NULL,
          payload_json TEXT NOT NULL DEFAULT '{}',
          result_json TEXT NOT NULL DEFAULT '{}',
          status TEXT NOT NULL DEFAULT 'queued',
          error TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS manager_agent_jobs_node
          ON manager_agent_jobs(node_id,status,created_at);
        """)
        cols={row["name"] for row in db.execute("PRAGMA table_info(manager_agents)")}
        if "auto_update" not in cols:
            db.execute("ALTER TABLE manager_agents ADD COLUMN auto_update INTEGER NOT NULL DEFAULT 0")
        if "last_update_check" not in cols:
            db.execute("ALTER TABLE manager_agents ADD COLUMN last_update_check INTEGER NOT NULL DEFAULT 0")


def issue_token(node_id: str) -> str:
    """Only for a user-authorized first SSH setup or one-time migration."""
    storage.get_node(node_id)
    token = secrets.token_urlsafe(48)
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())
    with storage.transaction() as db:
        db.execute("""INSERT INTO manager_agents
          (node_id,token_hash,enrolled_at,enabled,last_seen)
          VALUES(?,?,?,1,0)
          ON CONFLICT(node_id) DO UPDATE SET
          token_hash=excluded.token_hash,enrolled_at=excluded.enrolled_at,
          enabled=1,last_seen=0,version='',last_status_json='{}'""",
          (node_id,digest,now))
        # Discard old jobs for revoked/replaced agent identity.
        db.execute("UPDATE manager_agent_jobs SET status='failed',error='Agent credentials rotated' "
                   "WHERE node_id=? AND status IN ('queued','leased')",(node_id,))
        storage.event(db,"agent.enroll",node_id,"Node agent credentials issued")
    return token


def authenticate(node_id: str, auth_header: str) -> bool:
    if not isinstance(node_id,str) or not re.fullmatch(r"[0-9a-fA-F-]{36}",node_id):
        return False
    if not isinstance(auth_header,str) or not auth_header.startswith("Bearer "):
        return False
    token=auth_header[7:]
    if not 32 <= len(token) <= 192:
        return False
    with storage.connect() as db:
        row=db.execute("SELECT token_hash,enabled FROM manager_agents WHERE node_id=?",
                       (node_id,)).fetchone()
    return bool(row and row["enabled"] and hmac.compare_digest(
        row["token_hash"],hashlib.sha256(token.encode()).hexdigest()))


def heartbeat(node_id: str, data: dict) -> dict:
    if not isinstance(data,dict):
        raise AgentError("Неверный heartbeat")
    version=str(data.get("version",""))[:40]
    metrics=data.get("metrics",{})
    if not isinstance(metrics,dict) or len(json.dumps(metrics)) > 4000:
        raise AgentError("Слишком большой heartbeat")
    now=int(time.time())
    with storage.transaction() as db:
        db.execute("UPDATE manager_agents SET last_seen=?,version=?,last_status_json=? WHERE node_id=?",
                   (now,version,json.dumps(metrics,separators=(",",":")),node_id))
    # First TLS verification is queued immediately on the first ready heartbeat.
    from . import node_cert_sync
    node_cert_sync.queue_initial_check(node_id)
    try:
        from . import agent_updates
        agent_updates.auto_schedule(node_id,version,metrics)
    except Exception:
        # Auto-updates must never interfere with the node's normal heartbeat.
        pass
    return {"ok":True,"next_heartbeat_seconds":storage.monitoring_interval()}


def enqueue(node_id: str, action: str, payload: dict | None = None,
            ttl: int = 300, internal: bool = False) -> dict:
    if action not in ALLOWED:
        raise AgentError("Неподдерживаемая операция агента")
    if action.startswith("security.fail2ban") and not internal:
        raise AgentError("SSH-защита разрешена только через отдельные подтверждаемые действия")
    if action.startswith("node.cleanup") and not internal:
        raise AgentError("Удаление VPS разрешено только через мастер удаления")
    node=storage.get_node(node_id)
    with storage.connect() as chk:
        active=chk.execute("SELECT phase FROM node_lifecycle WHERE node_id=?",(node_id,)).fetchone()
    if active and active["phase"] and not (internal and action.startswith("node.cleanup")):
        raise AgentError("Нода проходит удаление; обычные задания временно запрещены")
    if node["status"] != "ready":
        raise AgentError("Нода должна быть установлена")
    payload=payload or {}
    if not isinstance(payload,dict) or len(json.dumps(payload)) > 50000:
        raise AgentError("Некорректные параметры задания")
    if not 30 <= ttl <= 900:
        raise AgentError("Недопустимое время ожидания")
    now=int(time.time())
    with storage.transaction() as db:
        agent=db.execute("SELECT enabled FROM manager_agents WHERE node_id=?",
                         (node_id,)).fetchone()
        if not agent or not agent["enabled"]:
            raise AgentError("На VPS ещё не установлен агент")
        outstanding=db.execute("""SELECT COUNT(*) FROM manager_agent_jobs
                       WHERE node_id=? AND status IN ('queued','leased')""",(node_id,)).fetchone()[0]
        if outstanding>=8:
            raise AgentError("Очередь задач ноды заполнена")
        jid=str(uuid.uuid4())
        db.execute("""INSERT INTO manager_agent_jobs
             (id,node_id,action,payload_json,created_at,updated_at,expires_at)
             VALUES(?,?,?,?,?,?,?)""",
             (jid,node_id,action,json.dumps(payload,separators=(",",":")),now,now,now+ttl))
        storage.event(db,"agent.task",node_id,"Queued "+action)
    _notify(node_id)
    return {"id":jid,"node_id":node_id,"action":action,"status":"queued"}


def poll(node_id: str) -> dict:
    now=int(time.time())
    with storage.transaction() as db:
        db.execute("UPDATE manager_agent_jobs SET status='expired',updated_at=? "
                   "WHERE node_id=? AND status='queued' AND expires_at<?",
                   (now,node_id,now))
        # Leased jobs are NOT retried: execution could already have happened.
        db.execute("UPDATE manager_agent_jobs SET status='failed',error='Agent result timeout',"
                   "updated_at=? WHERE node_id=? AND status='leased' AND updated_at<?",
                   (now,node_id,now-LEASE_SECONDS))
        row=db.execute("""SELECT id,action,payload_json FROM manager_agent_jobs
                          WHERE node_id=? AND status='queued' ORDER BY created_at,id LIMIT 1""",
                       (node_id,)).fetchone()
        if not row:
            return {"job":None}
        db.execute("UPDATE manager_agent_jobs SET status='leased',updated_at=? WHERE id=?",
                   (now,row["id"]))
    return {"job":{"id":row["id"],"action":row["action"],
                   "payload":json.loads(row["payload_json"])}}



async def long_poll(node_id: str, timeout: float=25.0) -> dict:
    timeout=max(1.0,min(float(timeout),30.0))
    event=_async_waiter(node_id)
    deadline=time.monotonic()+timeout
    while True:
        result=poll(node_id)
        if result.get("job") is not None:return result
        remaining=deadline-time.monotonic()
        if remaining<=0:return {"job":None}
        event.clear()
        result=poll(node_id)
        if result.get("job") is not None:return result
        try:
            await asyncio.wait_for(event.wait(),timeout=remaining)
        except asyncio.TimeoutError:
            return {"job":None}


def report(node_id: str, body: dict) -> dict:
    if not isinstance(body,dict):
        raise AgentError("Неверный отчёт агента")
    jid=body.get("id")
    if not isinstance(jid,str) or not re.fullmatch(r"[0-9a-f-]{36}",jid):
        raise AgentError("Неверный идентификатор задания")
    ok=body.get("ok")
    result=body.get("result",{})
    if not isinstance(ok,bool) or not isinstance(result,dict):
        raise AgentError("Неверный результат задания")
    with storage.connect() as db:
        row=db.execute("SELECT action,status FROM manager_agent_jobs WHERE id=? AND node_id=?",
                       (jid,node_id)).fetchone()
    if row is None or row["status"]!="leased":
        raise AgentError("Задание уже завершено или неизвестно")
    # Certificates are processed in memory and NEVER written to DB.
    if row["action"] in ("cert.export","cert.status"):
        from . import node_cert_sync
        # Never propagate arbitrary helper errors or Remnawave API bodies:
        # they might contain PEM or other secrets.
        if ok:
            try:
                if row["action"]=="cert.export":
                    raise node_cert_sync.CertificateSyncError(
                        "Передача приватных TLS ключей отключена")
                outcome=node_cert_sync.apply_agent_status(node_id,result)
                # Save only validated, non-sensitive metadata for a
                # same-node, short-lived migration preflight. Never store PEM.
                result={"expires_at":outcome["expires_at"],"updated":outcome["updated"],
                        "fingerprint":outcome["fingerprint"],
                        "mode":outcome.get("mode",""),
                        "domain":storage.get_node(node_id)["domain"],
                        "node_tls_mount_verified":result.get("node_tls_mount_verified") is True}
                error=""
            except node_cert_sync.CertificateSyncError as exc:
                ok=False
                result={}
                error=str(exc)[:220]  # This class uses fixed, secret-free messages.
            except Exception:
                ok=False
                result={}
                error="Внутренняя ошибка синхронизации TLS; профиль оставлен без автоматических изменений"
        else:
            error="Агент не смог проверить TLS-файлы на VPS. Проверь Certbot и права файлов"
            result={}
        if not ok:
            with storage.transaction() as db:
                db.execute("""INSERT INTO node_tls_sync(node_id,last_error)
                    VALUES(?,?) ON CONFLICT(node_id)
                    DO UPDATE SET last_error=excluded.last_error""",(node_id,error))
    else:
        error=str(body.get("error",""))[:250]
        if "key" in result or "certificate" in result or "chain" in result:
            raise AgentError("Секретные данные запрещены в журнале задания")
        if len(json.dumps(result)) > MAX_RESULT:
            result={"truncated":True}
    now=int(time.time())
    with storage.transaction() as db:
        db.execute("""UPDATE manager_agent_jobs SET status=?,result_json=?,error=?,
                      updated_at=? WHERE id=? AND node_id=? AND status='leased'""",
                   ("done" if ok else "failed",json.dumps(result,separators=(",",":")),
                    "" if ok else error,now,jid,node_id))
        storage.event(db,"agent.result",node_id,row["action"]+(" completed" if ok else " failed"))
    return {"ok":True}


def nodes_status() -> list[dict]:
    now=int(time.time())
    with storage.connect() as db:
        rows=db.execute("""SELECT n.id,n.code,n.domain,a.enabled,a.version,a.last_seen,
                           a.last_status_json,a.auto_update FROM nodes n
                           LEFT JOIN manager_agents a ON n.id=a.node_id
                           ORDER BY n.code""").fetchall()
    return [{"id":r["id"],"code":r["code"],"domain":r["domain"],
            "installed":r["enabled"] is not None,
            "revoked":bool(r["enabled"] is not None and not r["enabled"]),
            "online":bool(r["enabled"] and r["last_seen"] and now-r["last_seen"]<45),
            "version":r["version"] or "", "last_seen":r["last_seen"] or 0,
            "metrics":json.loads(r["last_status_json"] or "{}"),
            "auto_update":bool(r["auto_update"])}
            for r in rows]


def job_status(node_id: str, job_id: str) -> dict:
    with storage.connect() as db:
        row=db.execute("""SELECT id,action,status,result_json,error,created_at,updated_at
                          FROM manager_agent_jobs WHERE node_id=? AND id=?""",
                       (node_id,job_id)).fetchone()
    if not row:raise LookupError("Задание не найдено")
    return {"id":row["id"],"action":row["action"],"status":row["status"],
            "result":json.loads(row["result_json"] or "{}"),
            "error":row["error"],"created_at":row["created_at"],
            "updated_at":row["updated_at"]}


def revoke(node_id: str):
    with storage.transaction() as db:
        db.execute("UPDATE manager_agents SET enabled=0 WHERE node_id=?",(node_id,))
        db.execute("UPDATE manager_agent_jobs SET status='failed',error='Agent revoked' "
                   "WHERE node_id=? AND status IN ('queued','leased')",(node_id,))
        storage.event(db,"agent.revoked",node_id,"Agent credential revoked")
    return {"revoked":True,"node_id":node_id}
