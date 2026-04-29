# Ombra Vault — Security Design Notes

These notes are the design rationale, written as I built the project. They map
directly to the "design decisions" and "security analysis" sections of the
final report.

## 1. Threat model

**Who we defend against:**

- An attacker who steals the vault file (e.g., from a backup, a stolen laptop,
  or a misconfigured cloud sync). They get `vault.json` but not the master
  password and not access to the running process.
- An attacker who has write access to the vault file (e.g., shared filesystem,
  malicious sync app) but does not know the master password. They can mutate
  the file but every modification must be detected.

**Who we do NOT defend against:**

- An attacker with code execution on the machine while the vault is open.
- A weak or guessable master password.
- Side-channel attacks against the underlying libraries.
- Coercion / rubber-hose cryptanalysis. (Out of scope for software.)

## 2. Why Argon2id over PBKDF2

The original proposal specified PBKDF2-HMAC-SHA256 at 600,000 iterations
(NIST SP 800-63B-4, July 2025). PBKDF2 remains *acceptable* and is one of
NIST's allowed PRFs, but it has one important weakness: it is not memory-hard.
A modern GPU can compute PBKDF2-HMAC-SHA256 hundreds of millions of times per
second, and ASIC implementations are even faster.

Argon2id won the 2015 Password Hashing Competition. It is memory-hard by
design — increasing the memory cost forces an attacker to provision RAM,
which is expensive on GPUs and prohibitive on ASICs. OWASP's Password
Storage Cheat Sheet currently recommends Argon2id as the first choice for
new applications, with the parameters used here (`m=64 MiB, t=3, p=4`).

This deviation from the proposal is documented and is a strict security
improvement, not a regression.

## 3. Why AES-256-GCM

GCM is an Authenticated Encryption with Associated Data (AEAD) construction.
A single primitive provides both:

- **Confidentiality** — the ciphertext is indistinguishable from random
  without the key.
- **Integrity / authenticity** — the 128-bit tag detects any modification to
  the ciphertext OR the associated data.

The alternative, AES-CBC + HMAC ("encrypt-then-MAC"), provides the same
security properties but requires getting two primitives right, in the right
order. Many real-world vulnerabilities (BEAST, padding oracles) come from
mistakes in that hand-assembly. GCM removes the foot-guns and is the same
construction TLS 1.3 uses for its primary cipher suite.

NIST SP 800-38D specifies GCM and recommends a 12-byte nonce, which is what
we use. The PyCA `cryptography` library wraps the OpenSSL implementation,
so the actual hot path is the same audited C code that protects the entire
HTTPS web.

## 4. The single most dangerous mistake: nonce reuse

GCM is catastrophically broken if a nonce is ever reused under the same key.
Reusing a nonce twice not only leaks the XOR of the two plaintexts (a CTR-mode
weakness) — it also lets an attacker forge arbitrary ciphertexts under that
key (the GHASH-key recovery attack).

To eliminate the risk, **every** call to `encrypt()` generates a fresh random
12-byte nonce via `os.urandom()`. With a 96-bit nonce space and random
selection, the birthday-collision probability stays negligible for far more
than the lifetime of any practical vault. This includes:

- Adding entries (each entry has its own nonce)
- Saving the vault (the verifier is re-encrypted with a fresh nonce on
  every save)
- Re-keying via `change-password` (every entry gets a new nonce)

## 5. Binding ciphertext to its entry (AAD)

Each entry's password is encrypted with the entry's service name passed as
**Additional Authenticated Data**. The attacker scenario this defeats:

> Attacker has write access to `vault.json`. The user has entries for
> `bank.com` and `evil.com`. The attacker copies the encrypted blob from
> `evil.com` into the `bank.com` slot, hoping the user logs in to evil.com
> and types their bank password.

Without AAD, the GCM tag would still verify — the ciphertext is unchanged.
With AAD, the user's `bank.com` lookup attempts to decrypt with AAD
`b"bank.com"`, but the ciphertext was authenticated with AAD `b"evil.com"`,
so the tag check fails and we raise `AuthenticationError`.

## 6. Wrong-password detection

The naive approach is "try to decrypt the first entry; if the tag fails, the
password is wrong." That has two problems:

1. It fails on an empty vault — there is nothing to test against.
2. It conflates "wrong password" with "this specific entry was tampered with",
   making errors harder to reason about.

Instead, a fixed sentinel string (`b"OMBRA-VERIFIER-v1"`) is encrypted under
the derived key and stored in a `verifier` field in the header. On open, we
decrypt it first. If the GCM tag fails, the master password is wrong (or the
header itself was tampered with — either way, refuse to proceed) and no real
entry data is touched.

The verifier is re-encrypted with a fresh nonce on every save, so its
ciphertext changes between saves and cannot be used as a fingerprint.

## 7. Atomic writes

A naive `json.dump(open(path, "w"))` is not atomic. If the process is killed
between the truncate and the final flush, the vault is corrupted permanently.
That is unacceptable for a tool whose entire purpose is reliable storage.

`_atomic_write_json()` follows the standard POSIX recipe:

1. `mkstemp` in the same directory (so `os.replace` will be a same-filesystem
   rename, which POSIX guarantees is atomic).
2. Write the new contents, `flush()`, then `os.fsync()`.
3. `chmod 0600` on the temp file before exposing it.
4. `os.replace(tmp_path, path)` — this is atomic on POSIX and on modern
   Windows.

If anything fails before the `os.replace`, the temp file is unlinked and the
original vault is untouched. The test suite includes a fault-injection test
that confirms this.

## 8. Permissions

On vault creation, the file is written with mode `0600` (owner read/write,
no group, no world). This is verified in the test suite. On Windows, POSIX
permissions don't apply directly; the inherited NTFS ACL controls access.

## 9. Known limitations / future work

- **Metadata leak.** Service names and usernames are stored in plaintext.
  This is a deliberate trade-off (encrypted lookup keys would either leak
  equality via deterministic encryption or require linear scans). A future
  version could optionally encrypt the entire entry list.
- **Memory hygiene.** The master password and decrypted passwords exist as
  Python `str` objects in memory and cannot be reliably zeroed (Python
  strings are immutable and may be interned). Mitigations would require
  either C extensions or running in an environment with memory protection.
- **Clipboard integration / TTY scrubbing.** Currently `get` prints the
  password to stdout. A future version could copy to clipboard with an
  auto-clear timer.
- **Vault versioning / migrations.** The `version` field is in place but
  there is only one version. Future schema changes will need an explicit
  migration path.
- **No backup / sync.** The single-file design plays nicely with any
  user-chosen sync (Syncthing, restic, etc.) but provides nothing on its own.

## 10. References

- OWASP Password Storage Cheat Sheet — Argon2id parameter recommendations
- NIST SP 800-38D — Galois/Counter Mode of Operation
- NIST SP 800-63B-4 — Digital Identity Guidelines (cited in proposal)
- RFC 9106 — Argon2 Memory-Hard Function
- Bellare & Tackmann (CRYPTO 2016) — Multi-user security of AES-GCM in TLS 1.3
