import os
import json
import base64
import binascii
from typing import Dict, Any, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag

class SecureVault:
    """
    A production-grade AES-256-GCM vault using Argon2id for key derivation.

    Security Properties:
    - Authenticated Encryption with Associated Data (AEAD) via AES-GCM.
    - Cryptographic binding of all metadata to the ciphertext via deterministic AAD.
    - Parameter versioning to ensure forward/backward compatibility.

    Note on Passphrases:
    This class does NOT enforce passphrase complexity. It is the caller's
    responsibility to ensure sufficient passphrase entropy.

    Note on Data Types:
    Plaintext can be `str` or `bytes`. Strings are encoded to UTF-8 before
    encryption. Decryption defaults to returning UTF-8 strings but can return
    raw bytes if requested.
    """

    # Current payload version — bumped when the format changes
    CURRENT_VERSION = "1.0"

    # Current recommended KDF defaults (OWASP 2023/2024)
    # Stored as a class-level constant to prevent accidental instance mutation.
    CURRENT_KDF_CONFIG = {
        "ops": 3,       # Iterations (time_cost)
        "mem": 65536,   # 64MB RAM (memory_cost)
        "p": 4,         # Parallelism (threads)
    }

    def _derive_key(self, passphrase: str, salt: bytes, config: Dict[str, int]) -> bytes:
        """Derives a 256-bit key using Argon2id with provided parameters."""
        kdf = Argon2id(
            salt=salt,
            length=32,                      # 256-bit key for AES-256
            iterations=config["ops"],
            lanes=config["p"],              # parallelism
            memory_cost=config["mem"],
        )
        return kdf.derive(passphrase.encode('utf-8'))

    def _build_aad(self, header: Dict[str, Any]) -> bytes:
        """
        Constructs a deterministic, version-locked canonical format for AAD.
        Avoids json.dumps() completely to prevent byte-drift across Python
        versions, OS platforms, or stdlib modifications.
        """
        return (
            f"v={header['v']};"
            f"ops={header['kdf']['ops']};"
            f"mem={header['kdf']['mem']};"
            f"p={header['kdf']['p']};"
            f"salt={header['salt']};"
            f"nonce={header['nonce']}"
        ).encode('ascii')

    def encrypt(self, plaintext: Union[str, bytes], passphrase: str) -> str:
        """Encrypts data and returns a structured JSON object with embedded KDF parameters."""
        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")
        if not plaintext:
            raise ValueError("Plaintext data cannot be empty.")

        # Handle binary vs string data explicitly
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext

        # 1. Generate unique 16-byte salt and 12-byte nonce (NIST Standard)
        salt = os.urandom(16)
        nonce = os.urandom(12)
        config = self.CURRENT_KDF_CONFIG

        # 2. Derive key from passphrase using current KDF config
        key = self._derive_key(passphrase, salt, config)

        # 3. Construct header using strict ascii-safe Base64
        # We store KDF params in the payload so future versions of this code
        # can still decrypt this specific packet.
        header = {
            "v": self.CURRENT_VERSION,
            "kdf": {"ops": config["ops"], "mem": config["mem"], "p": config["p"]},
            "salt": base64.b64encode(salt).decode('ascii'),
            "nonce": base64.b64encode(nonce).decode('ascii')
        }

        # 4. Build AAD (Additional Authenticated Data) — deterministic canonical string
        # Binding the version, salt, and KDF params to the ciphertext integrity
        # means any tampering with unencrypted metadata will fail the auth tag check.
        aad = self._build_aad(header)

        # 5. Encrypt using AES-GCM — encrypt() returns: ciphertext + 16-byte auth tag
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, aad)

        # 6. Construct transport object
        # Outer JSON dump is safe here, as it's only transport, not AAD
        payload = {
            "header": header,
            "ciphertext": base64.b64encode(ciphertext_with_tag).decode('ascii')
        }

        return json.dumps(payload)

    def decrypt(self, encrypted_json: str, passphrase: str, return_bytes: bool = False) -> Union[str, bytes]:
        """Decrypts the JSON payload, validates integrity, and verifies AAD."""
        if not passphrase:
            raise ValueError("Passphrase required for decryption.")

        try:
            full_packet = json.loads(encrypted_json)
            header = full_packet["header"]

            # 1. Explicit version validation — unsupported versions fail fast
            if header.get("v") != self.CURRENT_VERSION:
                raise ValueError(f"Unsupported payload version: {header.get('v')}")

            ciphertext_with_tag = base64.b64decode(full_packet["ciphertext"])

            # 2. Extract parameters FROM THE HEADER, not class defaults
            # This ensures old packets encrypted with different KDF params still decrypt.
            kdf_params = header["kdf"]
            salt = base64.b64decode(header["salt"])
            nonce = base64.b64decode(header["nonce"])

            # 3. Reconstruct the exact deterministic AAD — must match encryption exactly
            aad = self._build_aad(header)

            # 4. Re-derive the key using the parameters that were active during encryption
            key = self._derive_key(passphrase, salt, kdf_params)

            # 5. Decrypt and verify tag
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)

            if return_bytes:
                return decrypted_bytes
            return decrypted_bytes.decode('utf-8')

        # Catch specific structure/encoding errors
        except (KeyError, json.JSONDecodeError, binascii.Error) as e:
            raise ValueError(f"Decryption failed: Malformed payload structure. {e}") from e

        # Catch cryptographic integrity/password failures
        except InvalidTag as e:
            # This triggers if:
            # 1. Password is wrong
            # 2. Ciphertext was modified
            # 3. Any metadata field in the AAD was modified
            raise PermissionError("Decryption failed: Integrity check failed or incorrect password.") from e

        # Let explicit ValueErrors (like unsupported version) bubble up cleanly
        except ValueError:
            raise

        # Final catch-all preserves the stack trace for deep debugging
        except Exception as e:
            raise RuntimeError(f"An unexpected error occurred during decryption. {e}") from e

# --- Example Usage ---
if __name__ == "__main__":
    vault = SecureVault()
    secret_data = "Sensitive User Information: API_KEY_12345"
    password = "correct-horse-battery-staple"

    # 1. Standard encrypt/decrypt flow
    encrypted_packet = vault.encrypt(secret_data, password)
    print(f"Encrypted Payload (JSON):\n{encrypted_packet[:100]}...\n")

    try:
        decrypted_text = vault.decrypt(encrypted_packet, password)
        print(f"Decrypted Result: {decrypted_text}")
    except PermissionError as e:
        print(e)

    # 2. Demonstrate AAD Protection (Tampering with Metadata)
    import json as _json
    tampered_blob = _json.loads(encrypted_packet)
    tampered_blob["header"]["v"] = "2.0"  # Modify unencrypted metadata
    tampered_json = _json.dumps(tampered_blob)

    try:
        vault.decrypt(tampered_json, password)
    except (PermissionError, ValueError) as e:
        print(f"Success: AAD detected metadata tampering — {e}")
