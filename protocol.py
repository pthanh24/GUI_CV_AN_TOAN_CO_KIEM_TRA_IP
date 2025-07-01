import json, base64, hashlib

def compute_hash(iv, ciphertext):
    return hashlib.sha512(iv + ciphertext).hexdigest()

def package_full(enc_session_key, metadata, iv, ciphertext, hash_value, signature):
    return json.dumps({
        "key": base64.b64encode(enc_session_key).decode(),
        "meta": base64.b64encode(metadata).decode(),
        "iv":  base64.b64encode(iv).decode(),
        "cipher": base64.b64encode(ciphertext).decode(),
        "hash": hash_value,
        "sig": base64.b64encode(signature).decode()
    }).encode()

def parse_full(raw):
    obj = json.loads(raw.decode())
    return (
        base64.b64decode(obj["key"]),
        base64.b64decode(obj["meta"]),
        base64.b64decode(obj["iv"]),
        base64.b64decode(obj["cipher"]),
        obj["hash"],
        base64.b64decode(obj["sig"])
    )
