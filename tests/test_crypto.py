"""Tests for ombra.crypto."""

import pytest

from ombra import crypto
from ombra.errors import AuthenticationError


def test_derive_key_is_deterministic_for_same_inputs():
    salt = b"\x00" * 16
    params = crypto.KdfParams(time_cost=1, memory_cost=8, parallelism=1)
    k1 = crypto.derive_key("hunter2", salt, params)
    k2 = crypto.derive_key("hunter2", salt, params)
    assert k1 == k2
    assert len(k1) == 32


def test_derive_key_different_password_yields_different_key():
    salt = b"\x00" * 16
    params = crypto.KdfParams(time_cost=1, memory_cost=8, parallelism=1)
    k1 = crypto.derive_key("hunter2", salt, params)
    k2 = crypto.derive_key("hunter3", salt, params)
    assert k1 != k2


def test_derive_key_different_salt_yields_different_key():
    params = crypto.KdfParams(time_cost=1, memory_cost=8, parallelism=1)
    k1 = crypto.derive_key("hunter2", b"\x00" * 16, params)
    k2 = crypto.derive_key("hunter2", b"\x01" * 16, params)
    assert k1 != k2


def test_derive_key_rejects_empty_password():
    salt = crypto.generate_salt()
    params = crypto.KdfParams(time_cost=1, memory_cost=8, parallelism=1)
    with pytest.raises(ValueError):
        crypto.derive_key("", salt, params)


def test_encrypt_decrypt_roundtrip():
    key = b"\x42" * 32
    plaintext = b"hunter2-secret-password"
    nonce, ct = crypto.encrypt(key, plaintext)
    assert crypto.decrypt(key, nonce, ct) == plaintext


def test_encrypt_uses_fresh_nonce_each_call():
    key = b"\x42" * 32
    nonce_a, _ = crypto.encrypt(key, b"same plaintext")
    nonce_b, _ = crypto.encrypt(key, b"same plaintext")
    assert nonce_a != nonce_b  # extremely unlikely to collide for random 12-byte values


def test_decrypt_with_wrong_key_raises_authentication_error():
    key = b"\x42" * 32
    wrong_key = b"\x43" * 32
    nonce, ct = crypto.encrypt(key, b"secret")
    with pytest.raises(AuthenticationError):
        crypto.decrypt(wrong_key, nonce, ct)


def test_decrypt_with_tampered_ciphertext_raises_authentication_error():
    key = b"\x42" * 32
    nonce, ct = crypto.encrypt(key, b"secret payload")
    # Flip a bit anywhere in the ciphertext.
    tampered = bytes([ct[0] ^ 0x01]) + ct[1:]
    with pytest.raises(AuthenticationError):
        crypto.decrypt(key, nonce, tampered)


def test_associated_data_is_authenticated():
    """If service-name AAD doesn't match, decrypt must fail."""
    key = b"\x42" * 32
    nonce, ct = crypto.encrypt(key, b"secret", associated_data=b"github.com")
    # Right key, right nonce, right ciphertext, WRONG AAD -> must fail.
    with pytest.raises(AuthenticationError):
        crypto.decrypt(key, nonce, ct, associated_data=b"evil.com")


def test_kdf_params_roundtrip_through_dict():
    p = crypto.KdfParams(time_cost=4, memory_cost=131072, parallelism=2, key_len=32)
    restored = crypto.KdfParams.from_dict(p.to_dict())
    assert restored == p


def test_kdf_params_rejects_unknown_algorithm():
    with pytest.raises(ValueError):
        crypto.KdfParams.from_dict({
            "algorithm": "scrypt",
            "time_cost": 3,
            "memory_cost": 65536,
            "parallelism": 4,
            "key_len": 32,
        })
