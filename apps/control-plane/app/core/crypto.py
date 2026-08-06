"""Cryptographic helpers for API key hashing and verification."""

import hashlib
import secrets


def hash_api_key(raw_key: str) -> str:
    """Hash an API key with a random salt using PBKDF2."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", raw_key.encode(), salt, iterations=100_000)
    return f"{salt.hex()}:{dk.hex()}"


def verify_api_key(raw_key: str, stored_hash: str) -> bool:
    """Verify a raw API key against a stored hash."""
    try:
        salt_hex, dk_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", raw_key.encode(), salt, iterations=100_000)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except (ValueError, AttributeError):
        return False
