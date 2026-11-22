import hashlib


def register(request):
    digest = hashlib.md5(request.form["password"].encode()).hexdigest()
    other = hashlib.sha256(pwd.encode()).hexdigest()
    return {"digest": digest, "other": other}
