# AES-256-GCM Secure Vault

A symmetric encryption module implementing AES-256-GCM with Argon2id key derivation, following established envelope encryption patterns (similar to JWE/Fernet). Payloads are self-contained JSON blobs — no shared state or config files required to decrypt.

Built to understand authenticated encryption, KDF parameter binding, and defensive input validation from first principles rather than wrapping a high-level library.

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
- **Key management and rotation.** There is no built-in mechanism to rotate passphrases, re-encrypt existing blobs under new keys, or expire old payloads. Each blob is independent.
- **Compromised dependencies.** If the `cryptography` library or the underlying OpenSSL implementation has a vulnerability, this module inherits it. No independent verification of primitive correctness is performed.
- **Multi-gigabyte files.** Peak RAM is ~3× payload size. The 100 MiB hard limit exists to prevent OOM. For large files, use chunked streaming (e.g., Tink or STREAM ciphers).
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

## Memory Usage

Peak RAM during a single encrypt/decrypt operation is roughly **3× the payload size** (~300 MiB for a 100 MiB payload) due to base64 encoding, intermediate string allocations, and ciphertext byte arrays existing simultaneously.

## Versioning

| Version | AAD includes `key_len` | Status |
|---|---|---|
| `1.0` | No | Supported (read-only) |
| `2.0` | Yes | Current |

New payloads are always written as v2.0. v1.0 payloads can be decrypted without any migration step.

## Requirements

- Python 3.8+
- Runtime: `cryptography>=44.0.0` — see [requirements.txt](requirements.txt)
- Development: `pytest>=7.0.0`, `hypothesis>=6.0.0` — see [requirements-dev.txt](requirements-dev.txt)

## Installation

```bash
pip install -r requirements.txt
```

## CLI Usage

```bash
# Encrypt a file (passphrase prompted securely via stdin)
python -m secure_vault encrypt --file secret.txt --out secret.enc

# Encrypt inline text
python -m secure_vault encrypt --text "my secret data" --out secret.enc

# Decrypt to stdout
python -m secure_vault decrypt --file secret.enc

# Decrypt binary payload to file
python -m secure_vault decrypt --file secret.enc --out recovered.bin --bytes
```

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
```

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
| `ValueError` | Empty data, empty passphrase, payload too large, malformed structure, unsupported version, invalid KDF params |
| `DecryptionError` | Wrong passphrase, modified ciphertext, or tampered header (AAD failure) |
| `RuntimeError` | Insufficient memory for Argon2, unexpected crypto error, or decrypted data is not valid UTF-8 |

## Tests

```bash
# Full suite (includes Hypothesis fuzz tests — may take a few minutes)
pytest test_secure_vault.py -v

# Skip slow fuzz tests
pytest test_secure_vault.py -v -k "not arbitrary"
```

Coverage includes: roundtrip correctness, non-determinism verification, authentication/integrity failures, KDF boundary enforcement, type evasion guards, malformed payload rejection, OOM limits, MemoryError path, legacy v1.0 decryption, and property-based fuzzing with Hypothesis.

## References

- [OWASP Password Storage Cheat Sheet — Argon2id](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — basis for KDF baseline claims
- [NIST SP 800-38D — Recommendation for GCM Mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final) — AES-GCM specification and 12-byte IV standard
- [RFC 7516 — JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516) — the established envelope encryption pattern this design resembles
- [cryptography library documentation](https://cryptography.io/en/latest/) — underlying implementation of AES-GCM and Argon2id
