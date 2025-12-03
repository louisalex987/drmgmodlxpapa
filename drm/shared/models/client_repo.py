import sqlite3
from shared.config.env import env

_conn = sqlite3.connect(env()["DB_PATH"], check_same_thread=False)
_conn.row_factory = sqlite3.Row

def _exec(sql, params=()):
    cur = _conn.execute(sql, params)
    _conn.commit()
    return cur

def all():
    rows = _exec("SELECT * FROM clients ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]

def get(client_id: int):
    row = _exec("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    return dict(row) if row else None

def create(name: str, email: str):
    cur = _conn.execute(
        "INSERT INTO clients(name, email) VALUES(?, ?) RETURNING *",
        (name, email),
    )
    row = cur.fetchone()
    _conn.commit()
    return dict(row)