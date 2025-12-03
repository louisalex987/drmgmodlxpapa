from flask import Blueprint, request, jsonify
from api.controller import license_controller
from api.middleware.auth import require_token
from shared.models import log_repo

bp = Blueprint("license", __name__)

@bp.get("/check")
def check():
    payload = license_controller.check(request.args.get("key"), request.remote_addr)
    return jsonify(payload), 200 if payload["valid"] else 403

@bp.post("/generate_license")
def generate():
    require_token()
    lic = license_controller.create(request.get_json(force=True))
    return jsonify(lic), 201

@bp.post("/regenerate_license")
def regenerate():
    require_token()
    lic = license_controller.regen(request.get_json(force=True))
    return jsonify(lic), 200

@bp.get("/license/<int:license_id>")
def get_license(license_id):
    require_token()
    lic = license_controller.fetch(license_id)
    return (jsonify(lic), 200) if lic else (jsonify({"error": "not_found"}), 404)

@bp.get("/logs")
def logs():
    require_token()
    data = log_repo.list_for_license(request.args.get("license_id"))
    return jsonify(data), 200