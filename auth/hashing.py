import hashlib

def sha3_256_hex(text: str) -> str: #sha256 hashing helper function for rtrerieval
    return hashlib.sha3_256(text.encode("utf-8")).hexdigest()