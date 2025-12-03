from flask import Flask, render_template, request, redirect, session, url_for, flash
from shared.config.env import env
from shared.config.security import verify_password
from shared.models import client_repo, addon_repo, license_repo, log_repo

settings = env()
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = settings["FLASK_SECRET"]

def _guard():
    if not session.get("admin"):
        return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        password = request.form.get("password", "")
        if verify_password(settings["ADMIN_HASH"], password):
            session["admin"] = True
            return redirect(url_for("dashboard"))
        flash("Accès refusé", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    guard = _guard()
    if guard:
        return guard
    return render_template(
        "dashboard.html",
        clients=client_repo.all(),
        addons=addon_repo.all(),
        licenses=license_repo.list_all(),
        logs=log_repo.latest(),
    )

@app.post("/clients/create")
def create_client():
    guard = _guard()
    if guard:
        return guard
    name = request.form.get("name")
    email = request.form.get("email")
    if name and email:
        client_repo.create(name, email)
        flash("Client créé avec succès", "success")
    else:
        flash("Erreur: Nom et Email requis", "error")
    return redirect(url_for("dashboard"))

@app.post("/addons/create")
def create_addon():
    guard = _guard()
    if guard:
        return guard
    name = request.form.get("name")
    version = request.form.get("version")
    description = request.form.get("description", "")
    if name and version:
        addon_repo.create(name, version, description)
        flash("Addon ajouté avec succès", "success")
    else:
        flash("Erreur: Nom et Version requis", "error")
    return redirect(url_for("dashboard"))

@app.post("/licenses/generate")
def dash_generate():
    guard = _guard()
    if guard:
        return guard
    client_id = int(request.form["client_id"])
    addon_id = int(request.form["addon_id"])
    license_repo.generate_license(client_id, addon_id)
    return redirect(url_for("dashboard"))

@app.post("/licenses/<int:license_id>/regen")
def dash_regen(license_id):
    guard = _guard()
    if guard:
        return guard
    lic = license_repo.get_license(license_id)
    if lic:
        license_repo.regenerate_license(lic["client_id"], lic["addon_id"])
    return redirect(url_for("license_detail", license_id=license_id))

@app.post("/licenses/<int:license_id>/deactivate")
def dash_deactivate(license_id):
    guard = _guard()
    if guard:
        return guard
    license_repo.deactivate_license(license_id)
    flash("Licence désactivée.", "success")
    return redirect(request.referrer or url_for("dashboard"))

@app.get("/clients/<int:client_id>")
def client_detail(client_id):
    guard = _guard()
    if guard:
        return guard
    return render_template(
        "client_detail.html",
        client=client_repo.get(client_id),
        licenses=license_repo.for_client(client_id),
    )

@app.get("/licenses/<int:license_id>")
def license_detail(license_id):
    guard = _guard()
    if guard:
        return guard
    return render_template(
        "license_detail.html",
        license=license_repo.get_license(license_id),
        logs=log_repo.list_for_license(license_id),
    )

if __name__ == "__main__":
    app.run("0.0.0.0", 5000, ssl_context="adhoc")