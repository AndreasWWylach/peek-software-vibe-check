import bcrypt
import hashlib


def register(request):
    digest = bcrypt.hashpw(request.form["password"].encode(), bcrypt.gensalt())
    checksum = hashlib.sha256(file_data).hexdigest()
    return {"digest": digest, "checksum": checksum}
