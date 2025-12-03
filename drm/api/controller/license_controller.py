from api.models import license_repo

def check(key: str, ip: str):
    if not key:
        return {"valid": False, "reason": "unknown", "addon_id": None, "client_id": None}
    ok, status, addon_id, client_id = license_repo.validate_license(key, ip)
    reason = status if status in {"ok", "regen", "expired"} else "invalid"
    return {"valid": ok, "reason": reason, "addon_id": addon_id, "client_id": client_id}

def create(data: dict):
    return license_repo.generate_license(data["client_id"], data["addon_id"])

def regen(data: dict):
    return license_repo.regenerate_license(data["client_id"], data["addon_id"])

def fetch(license_id: int):
    return license_repo.get_license(license_id)