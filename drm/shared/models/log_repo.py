import sqlite3
from shared.config.env import env

_conn = sqlite3.connect(env()["DB_PATH"], check_same_thread=False)
_conn.row_factory = sqlite3.Row

def _exec(sql, params=()):
    cur = _conn.execute(sql, params)
    _conn.commit()
    return cur

def latest(limit: int = 50):
    rows = _exec(
        """SELECT logs.*, clients.name AS client_name, addons.name AS addon_name
           FROM logs
           LEFT JOIN licenses ON licenses.id = logs.license_id
           LEFT JOIN clients ON clients.id = licenses.client_id
           LEFT JOIN addons  ON addons.id  = licenses.addon_id
           ORDER BY logs.timestamp DESC
           LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]

def list_for_license(license_id):
    rows = _exec(
        "SELECT * FROM logs WHERE license_id=? ORDER BY timestamp DESC",
        (license_id,),
    ).fetchall()
    return [dict(r) for r in rows]