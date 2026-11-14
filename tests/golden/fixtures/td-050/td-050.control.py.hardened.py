# Control — a non-webhook Flask route reading request.json must stay silent.
from flask import Flask, request

app = Flask(__name__)


@app.route("/api/profile", methods=["POST"])
def update_profile():
    name = request.json.get("name")
    return {"ok": True, "name": name}
