import hashlib

def hash_password(password):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        b"example-salt",
        100000
    ).hex()