from flask import Flask
from api.routes.license_routes import bp
from shared.config.env import env

app = Flask(__name__)
app.secret_key = env()["FLASK_SECRET"]
app.register_blueprint(bp, url_prefix="/api")

@app.route("/")
def index():
    return {"status": "online", "message": "DRM API is running"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, ssl_context="adhoc", debug=True)