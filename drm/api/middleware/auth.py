from flask import request, abort
from shared.config.env import env

_API_TOKEN = env()["API_KEY"]

def require_token():
    header = request.headers.get("Authorization", "")
    if not _API_TOKEN or header != f"Bearer {_API_TOKEN}":
        abort(401, description="Unauthorized")