"""Cryptographic primitives for Ombra Vault.

Design summary
--------------
* Key derivation: Argon2id (memory-hard, GPU-resistant). Parameters meet
  OWASP 2024+ guidance (m=64 MiB, t=3, p=4) and produce a 32-byte key.
* Symmetric encryption: AES-256-GCM, an AEAD construction that provides
  confidentiality AND integrity in one step. A wrong master password is
  detected as an authentication tag failure on decrypt.
* Each encryption uses a fresh, cryptographically random 12-byte nonce.
  Reusing a nonce under the same key in GCM is catastrophic (it breaks
  both confidentiality and authenticity), so we generate a new nonce
  every single call.

Why not PBKDF2?
---------------
The original proposal specified PBKDF2-HMAC-SHA256 with 600,000 iterations
(NIST SP 800-63B-4). PBKDF2 is still acceptable but is *not* memory-hard,
so it offers little resistance against GPU/ASIC cracking rigs. Argon2id
won the 2015 Password Hashing Competition and is the current OWASP top
recommendation. Switching is a strict security improvement; the report
documents this deviation explicitly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import AuthenticationError

# --- Argon2id parameters (OWASP 2024+ recommendation) ---
# Tunable; defending these in the report is part of the assignment.
ARGON2_TIME_COST = 3            # iterations
ARGON2_MEMORY_COST = 65536      # KiB == 64 MiB
ARGON2_PARALLELISM = 4          # threads
ARGON2_KEY_LEN = 32             # 32 bytes == 256-bit key for AES-256
ARGON2_SALT_LEN = 16            # 128-bit salt is standard

# --- AES-GCM parameters ---
# 12-byte nonce is the GCM standard and what NIST SP 800-38D recommends.
AES_NONCE_LEN = 12


@dataclass(frozen=True)
class KdfParams:
    """Argon2id parameters stored alongside the vault.

    These are stored in plaintext in the vault header so the vault can
    still be opened years from now even if defaults are tuned upward.
    """
    time_cost: int = ARGON2_TIME_COST
    memory_cost: int = ARGON2_MEMORY_COST
    parallelism: int = ARGON2_PARALLELISM
    key_len: int = ARGON2_KEY_LEN

    def to_dict(self) -> dict:
        return {
            "algorithm": "argon2id",
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "key_len": self.key_len,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KdfParams":
        if data.get("algorithm") != "argon2id":
            raise ValueError(f"Unsupported KDF algorithm: {data.get('algorithm')!r}")
        return cls(
            time_cost=int(data["time_cost"]),
            memory_cost=int(data["memory_cost"]),
            parallelism=int(data["parallelism"]),
            key_len=int(data["key_len"]),
        )


def generate_salt() -> bytes:
    """Generate a fresh, cryptographically random salt."""
    return os.urandom(ARGON2_SALT_LEN)


def generate_nonce() -> bytes:
    """Generate a fresh nonce for AES-GCM. Never reused under the same key."""
    return os.urandom(AES_NONCE_LEN)


def derive_key(master_password: str, salt: bytes, params: KdfParams) -> bytes:
    """Derive a symmetric key from the master password using Argon2id.

    Parameters
    ----------
    master_password : str
        The user's master password. Encoded as UTF-8 before hashing.
    salt : bytes
        A unique random salt (16 bytes recommended). Must be stored
        alongside the vault so the same key can be re-derived later.
    params : KdfParams
        The Argon2id parameters. Stored with the vault so old vaults
        keep opening even if defaults are increased later.

    Returns
    -------
    bytes
        A 32-byte (256-bit) key suitable for AES-256-GCM.
    """
    if not isinstance(master_password, str) or master_password == "":
        raise ValueError("Master password must be a non-empty string.")
    if len(salt) < 8:
        raise ValueError("Salt must be at least 8 bytes.")

    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.key_len,
        type=Type.ID,
    )


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt plaintext under `key` using AES-256-GCM.

    Returns
    -------
    (nonce, ciphertext_with_tag) : tuple[bytes, bytes]
        The fresh 12-byte nonce and the ciphertext with the 16-byte GCM
        authentication tag appended (this is how the cryptography library
        returns it). Both must be stored to decrypt later.

    Notes
    -----
    `associated_data` (AAD) is authenticated but not encrypted. We use it
    to bind the ciphertext to its service name, so an attacker with file
    access cannot swap the ciphertext for one entry under a different
    service name without invalidating the auth tag.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key.")

    aesgcm = AESGCM(key)
    nonce = generate_nonce()
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt and authenticate `ciphertext` under `key`.

    Raises
    ------
    AuthenticationError
        If the tag check fails. This means *either* the master password
        is wrong *or* the vault has been tampered with. We deliberately
        don't distinguish: an attacker can't tell which.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    if len(nonce) != AES_NONCE_LEN:
        raise ValueError(f"Nonce must be {AES_NONCE_LEN} bytes.")

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise AuthenticationError(
            "Authentication failed: master password is incorrect "
            "or the vault has been tampered with."
        ) from exc
