# Ombra Vault

> A local-only, zero-trust command-line password manager built in Python.
> Argon2id key derivation, AES-256-GCM authenticated encryption, no servers,
> no cloud, no telemetry.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

---

## Why

Most password managers ask you to trust a third party with the keys to every
account you own. Ombra Vault doesn't. Your master password never leaves your
machine, and the encrypted vault is a single JSON file you control.

It is built as a portfolio piece for a secure-coding course, with the design
goal of being **understandable end-to-end** — the entire cryptographic core is
one short, commented module.

## Features

- 🔐 **Argon2id** key derivation (memory-hard, GPU/ASIC-resistant, OWASP 2024+ params)
- 🛡️ **AES-256-GCM** authenticated encryption — wrong passwords and tampering both fail loudly
- 🎲 Per-entry **fresh random nonces** (no GCM nonce reuse, ever)
- 🪝 Service names bound to their ciphertext via **AAD** (entries can't be swapped on disk)
- 💾 **Atomic writes** so a crash during save can never corrupt your vault
- 🔒 Vault file written with **0600** permissions on POSIX systems
- 🎯 Strong **password generator** built in (`--generate`)
- 🚫 No network, no cloud, no telemetry

## Installation

```bash
git clone https://github.com/<your-username>/ombra-vault.git
cd ombra-vault
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -e .
```

## Usage

```bash
# Create a brand-new vault (default location: ~/.ombra/vault.json)
ombra init

# Add a credential, prompting for the password
ombra add github.com nick

# Add a credential with a generated 24-character password
ombra add aws.amazon.com nick --generate --length 24

# Retrieve a credential
ombra get github.com

# List all stored services (no passwords shown)
ombra list

# Delete an entry
ombra delete github.com

# Re-key the vault under a new master password (re-encrypts everything)
ombra change-password

# Use a custom vault location
ombra --vault ./work-vault.json init
```

You can also run without installing: `python -m ombra <command>`.

## Security design

### Key derivation

The master password is run through **Argon2id** with a fresh 16-byte random
salt to produce a 256-bit key. Default parameters are:

| Parameter | Value |
|-----------|-------|
| `time_cost` | 3 iterations |
| `memory_cost` | 64 MiB |
| `parallelism` | 4 threads |
| `key_len` | 32 bytes |

These match the OWASP Password Storage Cheat Sheet recommendation for
Argon2id (m=64 MiB, t=3, p=4) as of 2024. The parameters are stored in
the vault header so old vaults remain openable even if the defaults are
tuned upward in future versions.

### Encryption

Each credential's password is encrypted under **AES-256-GCM**:
- A fresh 12-byte random nonce is generated for every single encryption.
- The 16-byte GCM authentication tag is appended to the ciphertext.
- The service name is passed as **Additional Authenticated Data (AAD)**, binding
  the ciphertext to its entry. An attacker with file-write access can't move
  an encrypted blob from one service to another without invalidating the tag.

### Wrong-password detection

A fixed plaintext verifier (`OMBRA-VERIFIER-v1`) is encrypted under the derived
key and stored in the vault header. On open, we decrypt it first; if the GCM
auth tag fails, we raise `AuthenticationError` and refuse to touch any real
entries. This means a wrong password fails fast and uniformly, even on an
empty vault.

### Master password rotation

`change-password` generates a new salt, derives a new key, and re-encrypts
every entry under fresh nonces before atomically rewriting the file. The old
key and salt are no longer usable.

### What is NOT encrypted

For performance and lookup ergonomics, **service names and usernames are stored in
plaintext**. Only the password (the actual secret) is encrypted. An attacker
with read access to the vault file learns *which services you have accounts on*
and the corresponding usernames. If your threat model requires hiding even
this, this tool is not for you.

### What this tool does NOT defend against

- **Malware on your machine** (keyloggers, memory scrapers). The master
  password and decrypted entries necessarily exist in process memory while
  the tool runs.
- **A compromised Python install** or compromised dependencies.
- **Side-channel attacks** (timing, cache, electromagnetic). The underlying
  libraries (PyCA `cryptography`, `argon2-cffi`) take reasonable precautions
  but no Python program can fully mitigate these.
- **A weak master password.** Argon2id raises the cost of a brute-force attack
  but cannot rescue a 6-character password.

## Vault file format

```json
{
  "version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4,
    "key_len": 32
  },
  "salt": "<base64>",
  "verifier": {
    "nonce": "<base64>",
    "ciphertext": "<base64>"
  },
  "entries": {
    "github.com": {
      "username": "nick",
      "nonce": "<base64>",
      "ciphertext": "<base64>"
    }
  }
}
```

## Testing

```bash
pip install -e ".[dev]"
pytest
```

The suite covers the cryptographic primitives, vault persistence, tampering
detection (bit-flips and entry-swap attacks), atomic write recovery, and the
full CLI surface.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Ombra Vault is a coursework / portfolio project. It has not been audited.
For storing credentials whose loss would actually hurt you, use a battle-tested
manager (Bitwarden, 1Password, KeePassXC).
