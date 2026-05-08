# AES-256-GCM Python Tool

[![PyPI](https://img.shields.io/pypi/v/aes-secure-vault)](https://pypi.org/project/aes-secure-vault/)
[![Python](https://img.shields.io/pypi/pyversions/aes-secure-vault)](https://pypi.org/project/aes-secure-vault/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Reviewable AES-256-GCM authenticated encryption with Argon2id key derivation. Self-contained JSON payloads, plus a safe-mode streaming profile for file workflows. Published on PyPI as an educational and portfolio tool, not production vault software.

A symmetric encryption module implementing AES-256-GCM with Argon2id key derivation, following established envelope encryption patterns (similar to JWE/Fernet). The default payloads are self-contained JSON blobs. The Python CLI also supports a separate line-delimited streaming format for larger files.

Built to understand authenticated encryption, KDF parameter binding, and defensive input validation from first principles rather than wrapping a high-level library.

This is not a password manager, enterprise secrets vault, KMS replacement, backup system, or compliance-ready encryption product.

## Threat Model

### What this protects against

- **Confidentiality at rest.** An attacker with access to the encrypted blob but not the passphrase cannot recover plaintext. AES-256-GCM provides authenticated encryption with 256-bit key strength.
- **Ciphertext tampering.** GCM's authentication tag detects any modification to the ciphertext. Decryption fails rather than returning corrupted data.
- **Header tampering.** AAD binding means altering any unencrypted metadata field (version, KDF params, salt, nonce) also fails the authentication tag — even without touching the ciphertext itself.
- **KDF downgrade attacks.** Enforced minimum bounds on Argon2id parameters (ops ≥ 2, memory ≥ 32 MiB) prevent an attacker from forging a payload with trivially weak key derivation.
- **Offline brute-force (within reason).** Argon2id is memory-hard, making GPU/ASIC-based dictionary attacks significantly more expensive than with PBKDF2 or bcrypt. Effectiveness depends entirely on passphrase entropy — see limitations below.

### What this does NOT protect against

- **Weak passphrases.** Argon2id slows down brute-force but cannot compensate for a 4-character password. Passphrase entropy is the caller's responsibility. No strength meter, no enforcement.
- **Memory-scraping / cold boot attacks.** The derived key, plaintext, and intermediate buffers exist in process memory during encryption and decryption. An attacker with memory access (malware, memory dump, cold boot) can extract secrets. This module does not pin, zero, or mlock sensitive memory — Python's garbage collector makes this unreliable anyway.
- **Side-channel / timing attacks.** No constant-time comparisons beyond what the `cryptography` library provides internally. The Python runtime itself is not side-channel resistant. Do not use in contexts where an attacker can measure execution time or power consumption.
- **Quantum adversaries.** AES-256 offers ~128-bit post-quantum security via Grover's algorithm, which is still strong. However, the key exchange (passphrase → KDF → key) is not quantum-resistant in the broader cryptographic sense. This is a symmetric-only tool — no asymmetric components are exposed.
- **Production key lifecycle.** There is no KMS/HSM integration, access control, audit logging, recovery workflow, rotation schedule, or built-in mechanism to re-encrypt existing blobs under new keys. Each blob or stream is independent.
- **Compromised dependencies.** If the `cryptography` library or the underlying OpenSSL implementation has a vulnerability, this module inherits it. No independent verification of primitive correctness is performed.
- **Large-file operational risk.** Single-shot JSON mode peaks at roughly 3× payload size and is capped at 100 MiB. The Python safe-mode streaming profile keeps memory bounded by chunk size, but it is still local file encryption, not production vault storage.
- **Nonce reuse.** Each encryption generates a random 12-byte nonce. With random nonces, AES-GCM's birthday bound is approximately 2³² encryptions under the same key before collision risk becomes non-negligible. This module does not track nonce usage — it relies on `os.urandom` uniqueness.

## Security Properties

| Property | Detail |
|---|---|
| Cipher | AES-256-GCM (authenticated encryption) |
| Key derivation | Argon2id |
| KDF defaults | ops=3, memory=64 MiB, p=4, key_len=32 — exceeds OWASP 2023/2024 minimum baseline (19 MiB / 2 iterations). p=4 is not an OWASP recommendation; parallelism should be tuned to deployment hardware. |
| KDF floor (decrypt) | ops ≥ 2, memory ≥ 32 MiB, p ∈ [1, 16] — weaker than defaults; exists for backwards compatibility, not as a security target |
| Salt | 16 bytes, random per encryption |
| Nonce | 12 bytes, random per encryption (NIST standard) |
| Auth tag | 16 bytes, appended to ciphertext by GCM |
| AAD | Version + KDF params + salt + nonce bound to ciphertext |
| Payload limit | 100 MiB (enforced before encryption and after parsing) |
| Safe-mode stream | Line-delimited JSON header plus AES-GCM chunk records |
| Stream defaults | 1 MiB chunks, AES-256 only, temporary-output replacement in CLI |
| Stream compatibility tags | `not-compatible-with-json-v2`, `not-compatible-with-web-ui`, `chunked-aes-256-gcm` |

## Memory Usage

Peak RAM during a single-shot JSON encrypt/decrypt operation is roughly **3× the payload size** (~300 MiB for a 100 MiB payload) due to base64 encoding, intermediate string allocations, and ciphertext byte arrays existing simultaneously.

For file workflows, use the Python CLI safe-mode streaming commands. They process bounded chunks, tag each chunk with AAD-bound sequence and final flags, and write through a temporary output file before replacing the requested destination.

Repeat the local memory profile with:

```bash
python tools/benchmark_memory_profile.py
```

The benchmark reports Python allocation peaks for single-shot versus streaming mode. It does not include native Argon2 or OpenSSL allocations.

## Versioning

| Version | AAD includes `key_len` | Status |
|---|---|---|
| `1.0` | No | Supported (read-only) |
| `2.0` | Yes | Current |
| `stream-1.0` | Yes, plus stream profile, compatibility tags, chunk sequence, and final flag | Current safe-mode file profile |

New single-shot payloads are written as v2.0. v1.0 payloads can be decrypted without any migration step. Streaming payloads are separate `stream-1.0` line-delimited JSON files and are intentionally not interchangeable with the browser UI or single-shot JSON blobs.

## Requirements

**Web UI:** A modern browser. No install.

**Python CLI / library:**
- Python 3.8+
- `cryptography>=44.0.0` (installed automatically)

## Installation

```bash
pip install aes-secure-vault
```

For development (includes pytest and Hypothesis):

```bash
pip install aes-secure-vault[dev]
```

## Web UI

The recommended way to open it:

```bash
python -m http.server 8000
```

Then visit `http://localhost:8000` in your browser. This avoids browser security restrictions on WASM loaded via `file://`.

Alternatively, double-click `index.html` in File Explorer or run `start index.html` — this works in most browsers but may fail silently in some (Chrome in particular blocks WASM from `file://`).

- **Encrypt tab** — type a message, enter a passphrase, copy the encrypted blob
- **Decrypt tab** — paste a blob, enter the passphrase, read the original message
- Runs entirely client-side via the [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) and [argon2-browser](https://github.com/nicktindall/argon2-browser) (loaded from CDN with [SRI](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity) verification)
- Content Security Policy restricts script execution to trusted sources
- Payload size limits match the Python single-shot JSON path (100 MiB)
- Single-shot JSON blobs are **fully interchangeable** with the CLI: encrypt in the browser, decrypt with Python, and vice versa
- Limitation: binary payloads and file encryption require the CLI

## CLI Usage

```bash
# Encrypt a file (passphrase prompted securely via stdin, with confirmation)
secure-vault encrypt --file secret.txt --out secret.enc

# Encrypt inline text
secure-vault encrypt --text "my secret data" --out secret.enc

# Decrypt to stdout
secure-vault decrypt --file secret.enc

# Decrypt binary payload to file
secure-vault decrypt --file secret.enc --out recovered.bin --bytes

# Encrypt a larger file with the safe-mode streaming profile
secure-vault encrypt-stream --file large.bin --out large.svstream

# Decrypt a safe-mode stream to a temporary file first, then replace the output path
secure-vault decrypt-stream --file large.svstream --out large.recovered.bin
```

`python -m secure_vault` also works as an alternative to `secure-vault`.

Safe-mode streaming is file-only, binary-only, and intentionally tagged as incompatible with v2.0 JSON blobs and the browser UI. The CLI still prompts for passphrases via `getpass`; passphrases are never accepted as command-line arguments.

On encrypt, the CLI prompts for the passphrase twice to prevent typos. Ctrl+C exits cleanly at any prompt.

## Library Usage

```python
from secure_vault import SecureVault

vault = SecureVault()

# Encrypt (str or bytes)
blob = vault.encrypt("my secret data", "a-strong-passphrase-here")
blob = vault.encrypt(b"\x00\xFF binary data", "a-strong-passphrase-here")

# Decrypt to str (default)
plaintext = vault.decrypt(blob, "a-strong-passphrase-here")

# Decrypt to raw bytes
raw = vault.decrypt(blob, "a-strong-passphrase-here", return_bytes=True)

# Stream encrypt and decrypt files
with open("large.bin", "rb") as source, open("large.svstream", "wb") as destination:
    vault.encrypt_stream(source, destination, "a-strong-passphrase-here")

with open("large.svstream", "rb") as source, open("large.recovered.bin", "wb") as destination:
    vault.decrypt_stream(source, destination, "a-strong-passphrase-here")
```

When using `decrypt_stream()` directly, write to a temporary destination and only replace the final output after decryption returns successfully. The CLI does this automatically.

The encrypted blob is a JSON string safe to store or transmit:

```json
{
  "header": {
    "v": "2.0",
    "kdf": { "ops": 3, "mem": 65536, "p": 4, "key_len": 32 },
    "salt": "<base64>",
    "nonce": "<base64>"
  },
  "ciphertext": "<base64 ciphertext + auth tag>"
}
```

## Exceptions

| Exception | Cause |
|---|---|
| `ValueError` | Empty data, empty passphrase, payload too large, malformed structure, unsupported version, invalid KDF params, invalid streaming profile or compatibility tags |
| `DecryptionError` | Wrong passphrase, modified ciphertext, tampered header, or tampered streaming chunk (AAD failure) |
| `RuntimeError` | Insufficient memory for Argon2, unexpected crypto error, or decrypted data is not valid UTF-8 |

## Tests

```bash
# Full suite (includes Hypothesis fuzz tests — may take a few minutes)
pytest test_secure_vault.py -v

# Skip slow fuzz tests
pytest test_secure_vault.py -v -k "not arbitrary"
```

Coverage includes: roundtrip correctness, non-determinism verification, authentication/integrity failures, KDF boundary enforcement, type evasion guards, malformed payload rejection, OOM limits, MemoryError path, legacy v1.0 decryption, and property-based fuzzing with Hypothesis.

Streaming coverage includes safe-mode roundtrip, bounded read-size profiling, compatibility tag enforcement, single-shot/stream format misuse, tampered chunk sequence rejection, and wrong-passphrase failure.

## References

- [OWASP Password Storage Cheat Sheet — Argon2id](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — basis for KDF baseline claims
- [NIST SP 800-38D — Recommendation for GCM Mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final) — AES-GCM specification and 12-byte IV standard
- [RFC 7516 — JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516) — the established envelope encryption pattern this design resembles
- [cryptography library documentation](https://cryptography.io/en/latest/) — underlying implementation of AES-GCM and Argon2id
