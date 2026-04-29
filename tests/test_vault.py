"""Tests for ombra.vault."""

import json
import os

import pytest

from ombra import crypto, vault as vault_mod
from ombra.errors import (
    AuthenticationError,
    EntryExistsError,
    EntryNotFoundError,
    VaultCorruptedError,
    VaultExistsError,
    VaultNotFoundError,
)


# Use cheap KDF params in tests so the suite doesn't take forever.
@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(crypto, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(crypto, "ARGON2_MEMORY_COST", 8)
    monkeypatch.setattr(crypto, "ARGON2_PARALLELISM", 1)


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "test_vault.json"


# ---- creation / open ----

def test_create_and_open_empty_vault(vault_path):
    v = vault_mod.create_vault(vault_path, "correct horse battery staple")
    assert vault_path.exists()
    assert len(v) == 0

    reopened = vault_mod.open_vault(vault_path, "correct horse battery staple")
    assert len(reopened) == 0


def test_create_fails_if_vault_exists(vault_path):
    vault_mod.create_vault(vault_path, "pw")
    with pytest.raises(VaultExistsError):
        vault_mod.create_vault(vault_path, "pw")


def test_open_fails_if_vault_missing(vault_path):
    with pytest.raises(VaultNotFoundError):
        vault_mod.open_vault(vault_path, "pw")


def test_open_with_wrong_password_raises(vault_path):
    vault_mod.create_vault(vault_path, "right-password")
    with pytest.raises(AuthenticationError):
        vault_mod.open_vault(vault_path, "wrong-password")


def test_vault_file_has_restrictive_permissions(vault_path):
    vault_mod.create_vault(vault_path, "pw")
    mode = os.stat(vault_path).st_mode & 0o777
    # On POSIX systems, expect 0600. On Windows the bits will look
    # different so we only assert on POSIX-ish systems.
    if os.name == "posix":
        assert mode == 0o600


# ---- entry CRUD ----

def test_add_get_delete_roundtrip(vault_path):
    v = vault_mod.create_vault(vault_path, "pw")
    v.add("github.com", "nick", "s3cret-pw!")
    v.save()

    v2 = vault_mod.open_vault(vault_path, "pw")
    user, pw = v2.get("github.com")
    assert user == "nick"
    assert pw == "s3cret-pw!"

    v2.delete("github.com")
    v2.save()

    v3 = vault_mod.open_vault(vault_path, "pw")
    assert v3.list_services() == []


def test_add_duplicate_service_raises(vault_path):
    v = vault_mod.create_vault(vault_path, "pw")
    v.add("github.com", "nick", "pw1")
    with pytest.raises(EntryExistsError):
        v.add("github.com", "nick", "pw2")


def test_get_missing_entry_raises(vault_path):
    v = vault_mod.create_vault(vault_path, "pw")
    with pytest.raises(EntryNotFoundError):
        v.get("nonexistent")


def test_delete_missing_entry_raises(vault_path):
    v = vault_mod.create_vault(vault_path, "pw")
    with pytest.raises(EntryNotFoundError):
        v.delete("nonexistent")


def test_list_services_returns_sorted(vault_path):
    v = vault_mod.create_vault(vault_path, "pw")
    v.add("zeta.com", "u", "p")
    v.add("alpha.com", "u", "p")
    v.add("mu.com", "u", "p")
    assert v.list_services() == ["alpha.com", "mu.com", "zeta.com"]


# ---- IV/nonce uniqueness ----

def test_each_entry_has_unique_nonce(vault_path):
    v = vault_mod.create_vault(vault_path, "pw")
    for i in range(50):
        v.add(f"service-{i}", "user", f"password-{i}")
    nonces = [e.nonce for e in v.entries.values()]
    assert len(set(nonces)) == len(nonces)


def test_saving_twice_changes_verifier_ciphertext(vault_path):
    """The verifier should re-encrypt on every save (fresh nonce each time)."""
    v = vault_mod.create_vault(vault_path, "pw")
    first = json.loads(vault_path.read_text())
    v.save()
    second = json.loads(vault_path.read_text())
    assert first["verifier"]["ciphertext"] != second["verifier"]["ciphertext"]
    assert first["verifier"]["nonce"] != second["verifier"]["nonce"]


# ---- corruption / tampering detection ----

def test_corrupted_json_raises_corruption_error(vault_path):
    vault_path.write_text("{ not valid json")
    with pytest.raises(VaultCorruptedError):
        vault_mod.open_vault(vault_path, "pw")


def test_unsupported_version_raises_corruption_error(vault_path):
    vault_mod.create_vault(vault_path, "pw")
    doc = json.loads(vault_path.read_text())
    doc["version"] = 999
    vault_path.write_text(json.dumps(doc))
    with pytest.raises(VaultCorruptedError):
        vault_mod.open_vault(vault_path, "pw")


def test_tampered_entry_ciphertext_fails_on_get(vault_path):
    v = vault_mod.create_vault(vault_path, "pw")
    v.add("github.com", "nick", "secret")
    v.save()

    # Flip a byte in the stored ciphertext.
    doc = json.loads(vault_path.read_text())
    import base64
    raw = bytearray(base64.b64decode(doc["entries"]["github.com"]["ciphertext"]))
    raw[0] ^= 0x01
    doc["entries"]["github.com"]["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    vault_path.write_text(json.dumps(doc))

    v2 = vault_mod.open_vault(vault_path, "pw")
    with pytest.raises(AuthenticationError):
        v2.get("github.com")


def test_swapping_entries_under_different_service_name_fails(vault_path):
    """AAD binds ciphertext to service name. Renaming an entry should break it."""
    v = vault_mod.create_vault(vault_path, "pw")
    v.add("github.com", "nick", "github-secret")
    v.add("evil.com", "nick", "decoy")
    v.save()

    doc = json.loads(vault_path.read_text())
    # Move the github.com encrypted blob under "evil.com".
    doc["entries"]["evil.com"] = doc["entries"]["github.com"]
    vault_path.write_text(json.dumps(doc))

    v2 = vault_mod.open_vault(vault_path, "pw")
    with pytest.raises(AuthenticationError):
        v2.get("evil.com")


# ---- master password change ----

def test_change_master_password_preserves_entries(vault_path):
    v = vault_mod.create_vault(vault_path, "old-pw")
    v.add("github.com", "nick", "secret-1")
    v.add("aws.com", "admin", "secret-2")
    v.save()

    v_open = vault_mod.open_vault(vault_path, "old-pw")
    vault_mod.change_master_password(v_open, "brand-new-pw")

    # Old password no longer works.
    with pytest.raises(AuthenticationError):
        vault_mod.open_vault(vault_path, "old-pw")

    # New one does, and entries are intact.
    v_new = vault_mod.open_vault(vault_path, "brand-new-pw")
    assert v_new.get("github.com") == ("nick", "secret-1")
    assert v_new.get("aws.com") == ("admin", "secret-2")


def test_change_master_password_changes_salt_and_ciphertext(vault_path):
    v = vault_mod.create_vault(vault_path, "old-pw")
    v.add("github.com", "nick", "secret-1")
    v.save()

    before = json.loads(vault_path.read_text())
    v_open = vault_mod.open_vault(vault_path, "old-pw")
    vault_mod.change_master_password(v_open, "new-pw")
    after = json.loads(vault_path.read_text())

    assert before["salt"] != after["salt"]
    assert (before["entries"]["github.com"]["ciphertext"]
            != after["entries"]["github.com"]["ciphertext"])
    assert (before["entries"]["github.com"]["nonce"]
            != after["entries"]["github.com"]["nonce"])


# ---- atomic write ----

def test_failed_save_does_not_corrupt_existing_vault(vault_path, monkeypatch):
    v = vault_mod.create_vault(vault_path, "pw")
    v.add("github.com", "nick", "good")
    v.save()
    snapshot = vault_path.read_bytes()

    # Force os.replace to fail mid-save.
    def boom(*args, **kwargs):
        raise OSError("simulated disk failure")

    monkeypatch.setattr("ombra.vault.os.replace", boom)
    v.add("aws.com", "admin", "new")
    with pytest.raises(OSError):
        v.save()

    # Original vault file should be untouched.
    assert vault_path.read_bytes() == snapshot
