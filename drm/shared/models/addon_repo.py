import sqlite3
from shared.config.env import env

_conn = sqlite3.connect(env()["DB_PATH"], check_same_thread=False)
_conn.row_factory = sqlite3.Row

def _exec(sql, params=()):
    cur = _conn.execute(sql, params)
    _conn.commit()
    return cur

def all():
    rows = _exec("SELECT * FROM addons ORDER BY name ASC").fetchall()
    return [dict(r) for r in rows]

def get(addon_id: int):
    row = _exec("SELECT * FROM addons WHERE id=?", (addon_id,)).fetchone()
    return dict(row) if row else None

def create(name: str, version: str, description: str = ""):
    cur = _conn.execute(
        "INSERT INTO addons(name, version, description) VALUES(?,?,?) RETURNING *",
        (name, version, description),
    )
    row = cur.fetchone()
    _conn.commit()
    return dict(row)