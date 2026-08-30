"""AEAD framing for the bonding tunnel and password hashing for sign-in.

The tunnel uses ChaCha20-Poly1305 with a 12-byte nonce built from the sender's
link id and a per-link monotonic counter, which gives us replay detection for
free and never reuses a nonce for a given key.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from turbobond.errors import BondError

NONCE_LEN = 12
KEY_LEN = 32
TAG_LEN = 16


def derive_key(psk_hex: str, *, label: str = "turbobond-tunnel-v1") -> bytes:
    """Turn the configured hex PSK into a 32-byte AEAD key."""

    try:
        psk = bytes.fromhex(psk_hex)
    except ValueError as exc:
        raise BondError("concentrator PSK must be hex encoded") from exc
    if len(psk) < 16:
        raise BondError("concentrator PSK must be at least 16 bytes (32 hex chars)")
    return hashlib.blake2b(psk, digest_size=KEY_LEN, person=label.encode()[:16]).digest()


def generate_psk() -> str:
    return secrets.token_hex(32)


class Sealer:
    """Encrypt/decrypt tunnel datagrams."""

    __slots__ = ("_aead", "_key")

    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_LEN:
            raise BondError(f"tunnel key must be {KEY_LEN} bytes, got {len(key)}")
        self._key = key
        self._aead = ChaCha20Poly1305(key)

    @classmethod
    def from_psk(cls, psk_hex: str) -> Sealer:
        return cls(derive_key(psk_hex))

    @staticmethod
    def nonce(link_id: int, counter: int) -> bytes:
        """12-byte nonce: 4-byte link id || 8-byte counter."""

        return link_id.to_bytes(4, "big") + (counter & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")

    def seal(self, plaintext: bytes, *, link_id: int, counter: int, aad: bytes = b"") -> bytes:
        return self._aead.encrypt(self.nonce(link_id, counter), plaintext, aad)

    def open(self, ciphertext: bytes, *, link_id: int, counter: int, aad: bytes = b"") -> bytes | None:
        """Return the plaintext, or ``None`` when authentication fails."""

        try:
            return self._aead.decrypt(self.nonce(link_id, counter), ciphertext, aad)
        except InvalidTag:
            return None
        except Exception:  # pragma: no cover - malformed input
            return None


def constant_time_eq(a: str | bytes, b: str | bytes) -> bool:
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)


def hash_password(password: str) -> str:
    """Argon2id hash, falling back to PBKDF2 if argon2 is unavailable."""

    try:
        from argon2 import PasswordHasher

        return PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2).hash(password)
    except Exception:  # pragma: no cover - only when argon2-cffi is missing
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
        return f"pbkdf2_sha256$600000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt_hex, digest_hex = stored.split("$")
            digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
            return hmac.compare_digest(digest.hex(), digest_hex)
        except (ValueError, TypeError):
            return False
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerificationError, VerifyMismatchError

        try:
            return PasswordHasher().verify(stored, password)
        except (VerifyMismatchError, VerificationError):
            return False
    except ImportError:  # pragma: no cover
        return False
