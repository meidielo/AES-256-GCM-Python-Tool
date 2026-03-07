# AES-256-GCM Secure Vault

A production-grade symmetric encryption tool using **AES-256-GCM** with **Argon2id** key derivation. Payloads are self-contained JSON blobs — no shared state or config files required to decrypt.

## Security Properties

| Property | Detail |
|---|---|
| Cipher | AES-256-GCM (authenticated encryption) |
| Key derivation | Argon2id — OWASP 2023/2024 recommended params |
| KDF params | ops=3, memory=64MB, lanes=4 |
| Salt | 16 bytes, random per encryption |
| Nonce | 12 bytes, random per encryption (NIST standard) |
| Auth tag | 16 bytes, appended to ciphertext by GCM |
| AAD | Header (version + KDF params + salt + nonce) bound to ciphertext |

**AAD binding** means any tampering with the unencrypted header fields (version, KDF params, salt, nonce) will cause decryption to fail — even without touching the ciphertext itself.

**KDF parameter serialization** means old payloads encrypted under different Argon2id parameters can still be decrypted correctly, since the parameters used are stored in the payload header.

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

# Encrypt
blob = vault.encrypt("my secret data", "a-strong-passphrase-here")

# Decrypt
plaintext = vault.decrypt(blob, "a-strong-passphrase-here")
```

The encrypted blob is a JSON string safe to store or transmit:

```json
{
  "header": {
    "v": "1.0",
    "kdf": { "ops": 3, "mem": 65536, "p": 4 },
    "salt": "<base64>",
    "nonce": "<base64>"
  },
  "ciphertext": "<base64 ciphertext + auth tag>"
}
```

## Exceptions

| Exception | Cause |
|---|---|
| `ValueError` | Empty data, passphrase too short (<12 chars), or malformed payload |
| `PermissionError` | Wrong passphrase, modified ciphertext, or tampered header (AAD failure) |
| `RuntimeError` | Unexpected decryption error |

## Run the demo

```bash
python secure_vault.py
```

Demonstrates a standard encrypt/decrypt flow and AAD tamper detection.
