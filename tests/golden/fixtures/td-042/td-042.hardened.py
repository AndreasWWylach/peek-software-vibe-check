import subprocess

from flask import request


def make_thumbnail():
    filename = request.args.get("filename")
    # ✅ HARDENED: argument list — no shell, no metacharacter interpretation
    subprocess.run(["convert", filename, "-resize", "200x200", "out.png"], check=True)
