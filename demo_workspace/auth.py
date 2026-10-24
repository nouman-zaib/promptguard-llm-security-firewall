import hashlib

def hash_password(plain_secret: str) -> str:
    """Computes SHA-256 hash of password string."""
    return hashlib.sha256(plain_secret.encode('utf-8')).hexdigest()

def validate_login(username: str, password_hash: str, user_db: dict) -> bool:
    """Validates user credentials against password store."""
    if not username or not password_hash:
        return False
    stored_hash = user_db.get(username)
    return stored_hash == password_hash
