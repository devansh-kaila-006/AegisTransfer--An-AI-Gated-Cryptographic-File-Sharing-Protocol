import hashlib

def compute_hash(data: bytes) -> str:
    """Computes the SHA-256 hash of the given byte data."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()
