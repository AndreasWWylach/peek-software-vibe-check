import os

from flask import request


def make_thumbnail():
    filename = request.args.get("filename")
    # ❌ FLAW: user input interpolated into a shell command
    os.system(f"convert {filename} -resize 200x200 out.png")
