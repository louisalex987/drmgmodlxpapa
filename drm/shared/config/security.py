import hashlib
import hmac

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(expected_hash: str, candidate: str) -> bool:
    if not expected_hash:
        return False
    cand_hash = hash_password(candidate)
    return hmac.compare_digest(expected_hash, cand_hash)