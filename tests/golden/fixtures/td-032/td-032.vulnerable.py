from flask import Flask, request

app = Flask(__name__)


@app.route("/profile", methods=["POST"])
def update_profile():
    user_id = request.form["user_id"]  # ← client-supplied identity
    return {"ok": True}
