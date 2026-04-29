"""Vault file format and operations.

Vault file format (JSON, on disk)
---------------------------------
{
  "version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4,
    "key_len": 32
  },
  "salt": "<base64-encoded random salt>",
  "verifier": {
    "nonce": "<base64>",
    "ciphertext": "<base64>"
  },
  "entries": {
    "<service_name>": {
      "username": "<plaintext username>",
      "nonce": "<base64>",
      "ciphertext": "<base64>"
    },
    ...
  }
}

Design notes
------------
* Service names and usernames are stored in plaintext. This is a deliberate
  trade-off: encrypting them would require either deriving a deterministic
  key per name (leaks equality) or scanning every entry on every lookup.
  Only *passwords* (the actual secret) are encrypted. The report should
  acknowledge this metadata leak as a known limitation.
* The "verifier" is a fixed plaintext string ("OMBRA-VERIFIER-v1") encrypted
  under the derived key. On open, we decrypt it first; if the auth tag fails,
  we know the password is wrong before touching any real entries. Without
  this, a wrong password would only fail on the *first entry decrypt*, which
  is a worse UX and fragile when the vault is empty.
* Each entry has its OWN nonce. AES-GCM nonce reuse under the same key is
  catastrophic, so per-entry random nonces are mandatory.
* The service name is bound to the ciphertext via AAD. An attacker with
  file write access can't swap entry payloads between service names.
* Writes are atomic (write-temp-then-rename) so a crash mid-write can
  never leave a half-written vault.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from . import crypto
from .errors import (
    EntryExistsError,
    EntryNotFoundError,
    VaultCorruptedError,
    VaultExistsError,
    VaultNotFoundError,
)

VAULT_VERSION = 1
VERIFIER_PLAINTEXT = b"OMBRA-VERIFIER-v1"


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    try:
        return base64.b64decode(data.encode("ascii"), validate=True)
    except (ValueError, TypeError) as exc:
        raise VaultCorruptedError(f"Vault contains invalid base64 data: {exc}") from exc


@dataclass
class Entry:
    """A single credential entry. Username is plaintext; password is encrypted."""
    username: str
    nonce: bytes
    ciphertext: bytes


@dataclass
class Vault:
    """An open, in-memory representation of a vault.

    Holds the derived key in memory while the vault is open. Callers
    should not persist this object to disk directly — use save().
    """
    path: Path
    kdf_params: crypto.KdfParams
    salt: bytes
    key: bytes  # the derived 256-bit key; kept in memory only
    entries: dict[str, Entry] = field(default_factory=dict)

    # ---- Entry operations ----

    def add(self, service: str, username: str, password: str) -> None:
        if service in self.entries:
            raise EntryExistsError(f"Entry for service {service!r} already exists.")
        nonce, ct = crypto.encrypt(
            self.key,
            password.encode("utf-8"),
            associated_data=service.encode("utf-8"),
        )
        self.entries[service] = Entry(username=username, nonce=nonce, ciphertext=ct)

    def get(self, service: str) -> tuple[str, str]:
        """Return (username, password) for the given service, decrypting on the fly."""
        if service not in self.entries:
            raise EntryNotFoundError(f"No entry for service {service!r}.")
        entry = self.entries[service]
        plaintext = crypto.decrypt(
            self.key,
            entry.nonce,
            entry.ciphertext,
            associated_data=service.encode("utf-8"),
        )
        return entry.username, plaintext.decode("utf-8")

    def delete(self, service: str) -> None:
        if service not in self.entries:
            raise EntryNotFoundError(f"No entry for service {service!r}.")
        del self.entries[service]

    def list_services(self) -> list[str]:
        return sorted(self.entries.keys())

    def __iter__(self) -> Iterator[str]:
        return iter(self.list_services())

    def __len__(self) -> int:
        return len(self.entries)

    # ---- Persistence ----

    def save(self) -> None:
        """Write the vault to disk atomically.

        Re-encrypts the verifier on every save with a fresh nonce so the
        verifier ciphertext changes between saves (avoids leaking that
        the password was unchanged via a fixed ciphertext).
        """
        ver_nonce, ver_ct = crypto.encrypt(self.key, VERIFIER_PLAINTEXT)

        document = {
            "version": VAULT_VERSION,
            "kdf": self.kdf_params.to_dict(),
            "salt": _b64e(self.salt),
            "verifier": {
                "nonce": _b64e(ver_nonce),
                "ciphertext": _b64e(ver_ct),
            },
            "entries": {
                service: {
                    "username": entry.username,
                    "nonce": _b64e(entry.nonce),
                    "ciphertext": _b64e(entry.ciphertext),
                }
                for service, entry in self.entries.items()
            },
        }

        _atomic_write_json(self.path, document)


def _atomic_write_json(path: Path, document: dict) -> None:
    """Write JSON atomically: temp-file in same dir, fsync, then os.replace.

    This guarantees the vault file is either fully the old version or
    fully the new version — never half-written, even if the process is
    killed mid-save. Permissions are set to 0600 (owner read/write only).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(document, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        # Tighten perms before exposing the file at its final name.
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except Exception:
        # Best-effort cleanup of the temp file on failure.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def create_vault(path: Path | str, master_password: str) -> Vault:
    """Create a brand-new vault at `path` and write it to disk."""
    path = Path(path)
    if path.exists():
        raise VaultExistsError(f"A vault already exists at {path}.")

    kdf_params = crypto.KdfParams()
    salt = crypto.generate_salt()
    key = crypto.derive_key(master_password, salt, kdf_params)

    vault = Vault(path=path, kdf_params=kdf_params, salt=salt, key=key, entries={})
    vault.save()
    return vault


def open_vault(path: Path | str, master_password: str) -> Vault:
    """Open and authenticate an existing vault.

    Raises AuthenticationError on a wrong password, VaultCorruptedError
    on a malformed file, VaultNotFoundError if no file exists.
    """
    path = Path(path)
    if not path.exists():
        raise VaultNotFoundError(f"No vault found at {path}.")

    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise VaultCorruptedError(f"Could not read vault: {exc}") from exc

    try:
        version = doc["version"]
        if version != VAULT_VERSION:
            raise VaultCorruptedError(f"Unsupported vault version: {version}")
        kdf_params = crypto.KdfParams.from_dict(doc["kdf"])
        salt = _b64d(doc["salt"])
        verifier_nonce = _b64d(doc["verifier"]["nonce"])
        verifier_ct = _b64d(doc["verifier"]["ciphertext"])
        raw_entries = doc["entries"]
    except (KeyError, ValueError) as exc:
        raise VaultCorruptedError(f"Vault is malformed: {exc}") from exc

    # Derive the key and verify the password by decrypting the verifier.
    # If the password is wrong, this raises AuthenticationError — which is
    # exactly what we want, and it leaves no entry data touched.
    key = crypto.derive_key(master_password, salt, kdf_params)
    crypto.decrypt(key, verifier_nonce, verifier_ct)  # raises on bad password

    entries: dict[str, Entry] = {}
    for service, raw in raw_entries.items():
        try:
            entries[service] = Entry(
                username=raw["username"],
                nonce=_b64d(raw["nonce"]),
                ciphertext=_b64d(raw["ciphertext"]),
            )
        except (KeyError, ValueError) as exc:
            raise VaultCorruptedError(
                f"Entry {service!r} is malformed: {exc}"
            ) from exc

    return Vault(
        path=path,
        kdf_params=kdf_params,
        salt=salt,
        key=key,
        entries=entries,
    )


def change_master_password(vault: Vault, new_password: str) -> None:
    """Re-key the vault to a new master password.

    Generates a fresh salt, derives a new key, then re-encrypts every
    entry under the new key with fresh per-entry nonces. The save() call
    at the end will also re-encrypt the verifier under the new key.
    """
    new_salt = crypto.generate_salt()
    new_key = crypto.derive_key(new_password, new_salt, vault.kdf_params)

    new_entries: dict[str, Entry] = {}
    for service, entry in vault.entries.items():
        # Decrypt with old key, re-encrypt with new key + fresh nonce.
        plaintext = crypto.decrypt(
            vault.key,
            entry.nonce,
            entry.ciphertext,
            associated_data=service.encode("utf-8"),
        )
        new_nonce, new_ct = crypto.encrypt(
            new_key,
            plaintext,
            associated_data=service.encode("utf-8"),
        )
        new_entries[service] = Entry(
            username=entry.username,
            nonce=new_nonce,
            ciphertext=new_ct,
        )

    vault.salt = new_salt
    vault.key = new_key
    vault.entries = new_entries
    vault.save()
