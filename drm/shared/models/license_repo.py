import sqlite3
import secrets
import datetime
from shared.config.env import env

_conn = sqlite3.connect(env()["DB_PATH"], check_same_thread=False)
_conn.row_factory = sqlite3.Row

def _exec(sql, params=()):
    cur = _conn.execute(sql, params)
    _conn.commit()
    return cur

def log_usage(license_id, status, ip, details=""):
    _exec(
        """INSERT INTO logs(license_id, timestamp, ip_address, status, details)
           VALUES(?,?,?,?,?)""",
        (license_id, datetime.datetime.utcnow().isoformat(), ip, status, details),
    )

def deactivate_old_keys(client_id, addon_id):
    _exec("UPDATE licenses SET active=0 WHERE client_id=? AND addon_id=?", (client_id, addon_id))

def deactivate_license(license_id):
    _exec("UPDATE licenses SET active=0 WHERE id=?", (license_id,))
    log_usage(license_id, "deactivated", "system", "manually deactivated by admin")

def _insert_license(client_id, addon_id):
    key = secrets.token_urlsafe(32)
    now = datetime.datetime.utcnow()
    expiration = now + datetime.timedelta(days=30)
    cur = _conn.execute(
        """INSERT INTO licenses(key, client_id, addon_id, generated_at, last_regen, expiration, active)
           VALUES(?,?,?,?,?,?,1) RETURNING *""",
        (key, client_id, addon_id, now.isoformat(), now.isoformat(), expiration.isoformat()),
    )
    row = cur.fetchone()
    _conn.commit()
    return dict(row)

def generate_license(client_id, addon_id):
    deactivate_old_keys(client_id, addon_id)
    lic = _insert_license(client_id, addon_id)
    log_usage(lic["id"], "valid", "system", "license generated")
    return lic

def regenerate_license(client_id, addon_id):
    deactivate_old_keys(client_id, addon_id)
    lic = _insert_license(client_id, addon_id)
    log_usage(lic["id"], "regened_key", "system", "license regenerated")
    return lic

def _recent_ips(license_id):
    rows = _exec(
        """SELECT ip_address FROM logs
           WHERE license_id=? AND ip_address IS NOT NULL
           ORDER BY timestamp DESC LIMIT 5""",
        (license_id,),
    ).fetchall()
    return {r["ip_address"] for r in rows}

def validate_license(key, ip):
    row = _exec("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
    if not row:
        log_usage(None, "invalid_key", ip, "unknown key")
        return False, "invalid", None, None
    lic = dict(row)
    now = datetime.datetime.utcnow()
    if not lic["active"]:
        log_usage(lic["id"], "regened_key", ip, "old key reuse")
        return False, "regen", lic["addon_id"], lic["client_id"]
    if now > datetime.datetime.fromisoformat(lic["expiration"]):
        log_usage(lic["id"], "expired", ip, "expired key")
        return False, "expired", lic["addon_id"], lic["client_id"]
    recent_ips = _recent_ips(lic["id"])
    if len(recent_ips) >= 3 and ip not in recent_ips:
        log_usage(lic["id"], "suspicious", ip, "frequent IP change")
        return False, "invalid", lic["addon_id"], lic["client_id"]
    log_usage(lic["id"], "valid", ip, "license accepted")
    return True, "ok", lic["addon_id"], lic["client_id"]

def get_license(license_id):
    row = _conn.execute(
        """SELECT licenses.*, clients.name AS client_name, addons.name AS addon_name
           FROM licenses
           LEFT JOIN clients ON clients.id=licenses.client_id
           LEFT JOIN addons ON addons.id=licenses.addon_id
           WHERE licenses.id=?""",
        (license_id,)
    ).fetchone()
    return dict(row) if row else None

def list_all():
    rows = _conn.execute(
        """SELECT licenses.*, clients.name AS client_name, addons.name AS addon_name
           FROM licenses
           LEFT JOIN clients ON clients.id=licenses.client_id
           LEFT JOIN addons ON addons.id=licenses.addon_id
           ORDER BY licenses.generated_at DESC"""
    ).fetchall()
    return [dict(r) for r in rows]

def for_client(client_id):
    rows = _conn.execute(
        """SELECT licenses.*, addons.name AS addon_name
           FROM licenses
           LEFT JOIN addons ON addons.id=licenses.addon_id
           WHERE client_id=?
           ORDER BY generated_at DESC""",
        (client_id,),
    ).fetchall()
    return [dict(r) for r in rows]