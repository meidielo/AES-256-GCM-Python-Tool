import os
import json
import base64
import binascii
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag

class SecureVault:
    """
    A production-grade AES-256-GCM vault using Argon2id for key derivation.
    Implements AAD binding and KDF parameter serialization for forward compatibility.
    """

    # Current recommended KDF defaults (OWASP 2023/2024)
    # Stored as a class-level constant to prevent accidental instance mutation.
    CURRENT_KDF_CONFIG = {
        "ops": 3,       # Iterations (time_cost)
        "mem": 65536,   # 64MB RAM (memory_cost)
        "p": 4,         # Parallelism (threads)
        "version": "1.0"
    }

    def _validate_inputs(self, data: str, passphrase: str):
        """Validates passphrase strength and data presence before encryption."""
        if not passphrase or len(passphrase) < 12:
            raise ValueError("Passphrase must be at least 12 characters long.")
        if not data:
            raise ValueError("Plaintext data cannot be empty.")

    def _derive_key(self, passphrase: str, salt: bytes, config: Dict[str, Any]) -> bytes:
        """Derives a 256-bit key using Argon2id with provided parameters."""
        kdf = Argon2id(
            salt=salt,
            length=32,                      # 256-bit key for AES-256
            iterations=config["ops"],
            lanes=config["p"],              # parallelism
            memory_cost=config["mem"],
        )
        return kdf.derive(passphrase.encode())

    def encrypt(self, plaintext: str, passphrase: str) -> str:
        """Encrypts data and returns a structured JSON object with embedded KDF parameters."""
        self._validate_inputs(plaintext, passphrase)

        # 1. Generate unique 16-byte salt and 12-byte nonce (NIST Standard)
        salt = os.urandom(16)
        nonce = os.urandom(12)
        config = self.CURRENT_KDF_CONFIG

        # 2. Derive key from passphrase using current KDF config
        key = self._derive_key(passphrase, salt, config)

        # 3. Construct Metadata/Header
        # We store KDF params in the payload so future versions of this code
        # can still decrypt this specific packet.
        header = {
            "v": config["version"],
            "kdf": {"ops": config["ops"], "mem": config["mem"], "p": config["p"]},
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8')
        }

        # 4. Build AAD (Additional Authenticated Data) from the header
        # Binding the version, salt, and KDF params to the ciphertext integrity
        # means any tampering with unencrypted metadata will fail the auth tag check.
        aad = json.dumps(header, sort_keys=True).encode()

        # 5. Encrypt using AES-GCM — encrypt() returns: ciphertext + 16-byte auth tag
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode(), aad)

        # 6. Construct transport object
        payload = {
            "header": header,
            "ciphertext": base64.b64encode(ciphertext_with_tag).decode('utf-8')
        }

        return json.dumps(payload)

    def decrypt(self, encrypted_json: str, passphrase: str) -> str:
        """Decrypts the JSON payload, validates integrity, and verifies AAD."""
        if not passphrase:
            raise ValueError("Passphrase required for decryption.")

        try:
            full_packet = json.loads(encrypted_json)
            header = full_packet["header"]
            ciphertext_with_tag = base64.b64decode(full_packet["ciphertext"])

            # 1. Extract parameters FROM THE HEADER, not class defaults
            # This ensures old packets encrypted with different KDF params still decrypt.
            kdf_params = header["kdf"]
            salt = base64.b64decode(header["salt"])
            nonce = base64.b64decode(header["nonce"])

            # 2. Reconstruct AAD — must be identical to what was used during encryption
            aad = json.dumps(header, sort_keys=True).encode()

            # 3. Re-derive the key using the parameters that were active during encryption
            key = self._derive_key(passphrase, salt, kdf_params)

            # 4. Decrypt and verify tag
            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)

            return decrypted_data.decode('utf-8')

        except (KeyError, json.JSONDecodeError, binascii.Error) as e:
            raise ValueError(f"Decryption failed: Malformed payload structure. {e}")
        except InvalidTag:
            # This triggers if:
            # 1. Password is wrong
            # 2. Ciphertext was modified
            # 3. Any metadata field in the AAD was modified
            raise PermissionError("Decryption failed: Integrity check failed or incorrect password.")
        except Exception as e:
            raise RuntimeError(f"An unexpected error occurred during decryption. {e}")

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
    except PermissionError:
        print("Success: AAD detected metadata tampering (Version modification).")
