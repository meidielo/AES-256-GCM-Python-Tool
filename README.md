# AES-256-GCM Secure Vault

A production-grade symmetric encryption tool using **AES-256-GCM** with **Argon2id** key derivation. Payloads are self-contained JSON blobs — no shared state or config files required to decrypt.

## Security Properties

| Property | Detail |
|---|---|
| Cipher | AES-256-GCM (authenticated encryption) |
| Key derivation | Argon2id |
| KDF defaults | ops=3, memory=64MB, p=4, key_len=32 — exceeds OWASP 2023/2024 minimum baseline (19 MiB / 2 iterations) |
| KDF floor (enforced on decrypt) | ops≥2, memory≥32MB, p∈[1,16] — weaker than defaults; exists for backwards compatibility |
| Salt | 16 bytes, random per encryption |
| Nonce | 12 bytes, random per encryption (NIST standard) |
| Auth tag | 16 bytes, appended to ciphertext by GCM |
| AAD | Version + KDF params + salt + nonce bound to ciphertext |
| Payload limit | 100 MiB (enforced before encryption and after parsing) |

**AAD binding** means any tampering with the unencrypted header fields (version, KDF params, salt, nonce) will cause decryption to fail — even without touching the ciphertext itself.

**KDF parameter serialization** means old payloads encrypted under different Argon2id parameters or format versions can still be decrypted correctly, since the parameters used are stored in the payload header.

## Memory Usage

Peak RAM during a single encrypt/decrypt operation is roughly **3× the payload size** (~300 MiB for a 100 MiB payload) due to base64 encoding, intermediate string allocations, and ciphertext byte arrays existing simultaneously. For multi-gigabyte files, use chunked streaming (e.g., Tink or STREAM ciphers).

## Versioning

| Version | AAD includes `key_len` | Status |
|---|---|---|
| `1.0` | No | Supported (read-only) |
| `2.0` | Yes | Current |

New payloads are always written as v2.0. v1.0 payloads can be decrypted without any migration step.

## Requirements

- Python 3.8+
- See [requirements.txt](requirements.txt)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

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
| `PermissionError` | Wrong passphrase, modified ciphertext, or tampered header (AAD failure) |
| `RuntimeError` | Unexpected decryption error, or decrypted data is not valid UTF-8 |

## Run the smoke tests

```bash
python secure_vault.py
```

Runs three tests: string encryption (v2.0), raw bytes encryption (v2.0), and legacy v1.0 decryption using a structurally constructed blob.
