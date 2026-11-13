from flask import Flask, request, session

app = Flask(__name__)


@app.route("/profile", methods=["POST"])
def update_profile():
    user_id = session["user_id"]  # ← session identity
    return {"ok": True}
