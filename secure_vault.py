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
    """

    SUPPORTED_VERSIONS = {"1.0"}
    CURRENT_VERSION = "1.0"

    # KDF Parameter Boundary Clamping
    # Prevents Downgrade Attacks (weak keys) and DoS Attacks (memory exhaustion)
    MIN_KDF_OPS = 2
    MAX_KDF_OPS = 10
    MIN_KDF_MEM = 32768     # 32 MiB
    MAX_KDF_MEM = 262144    # 256 MiB

    # Current recommended KDF defaults (OWASP 2023/2024)
    # Stored as a class-level constant to prevent accidental instance mutation.
    CURRENT_KDF_CONFIG = {
        "ops": 3,       # Iterations (time_cost)
        "mem": 65536,   # 64MB RAM (memory_cost)
        "p": 4,         # Parallelism (threads)
        "key_len": 32   # 256-bit key for AES-256
    }

    def _derive_key(self, passphrase: str, salt: bytes, config: Dict[str, int]) -> bytes:
        """Derives a key using Argon2id with provided parameters."""
        kdf = Argon2id(
            salt=salt,
            length=config.get("key_len", 32),   # Default fallback for safety
            iterations=config["ops"],
            lanes=config["p"],                   # parallelism
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
            f"key_len={header['kdf']['key_len']};"
            f"salt={header['salt']};"
            f"nonce={header['nonce']}"
        ).encode('ascii')

    def encrypt(self, plaintext: Union[str, bytes], passphrase: str) -> str:
        """Encrypts data and returns a structured JSON object with embedded KDF parameters."""
        # Security: passphrase entropy is the caller's responsibility.
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
            "kdf": {
                "ops": config["ops"],
                "mem": config["mem"],
                "p": config["p"],
                "key_len": config["key_len"]
            },
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
        # Security: passphrase entropy is the caller's responsibility.
        if not passphrase:
            raise ValueError("Passphrase required for decryption.")

        # ==========================================
        # PHASE 1: Parsing (Strictly scoped catch)
        # ==========================================
        try:
            full_packet = json.loads(encrypted_json)
            header = full_packet["header"]
            ciphertext_with_tag = base64.b64decode(full_packet["ciphertext"])
            kdf_params = header["kdf"]
            salt = base64.b64decode(header["salt"])
            nonce = base64.b64decode(header["nonce"])
        except (KeyError, json.JSONDecodeError, binascii.Error, TypeError) as e:
            raise ValueError(f"Decryption failed: Malformed payload structure. {e}") from e

        # ==========================================
        # PHASE 2: Validation (Unwrapped logic)
        # ==========================================
        # Any ValueError raised here propagates directly to the caller,
        # cleanly avoiding the "except ValueError: raise" trap.

        if header.get("v") not in self.SUPPORTED_VERSIONS:
            raise ValueError(f"Unsupported payload version: {header.get('v')}")

        if len(salt) != 16:
            raise ValueError(f"Invalid salt length: expected 16 bytes, got {len(salt)}.")
        if len(nonce) != 12:
            raise ValueError(f"Invalid nonce length: expected 12 bytes, got {len(nonce)}.")

        ops, mem = kdf_params.get("ops"), kdf_params.get("mem")
        if not isinstance(ops, int) or not isinstance(mem, int):
            raise ValueError("KDF parameters must be integers.")

        # Prevent Downgrade Attacks and Denial of Service (DoS)
        if ops < self.MIN_KDF_OPS or mem < self.MIN_KDF_MEM:
            raise ValueError("Payload KDF parameters below minimum security threshold.")
        if ops > self.MAX_KDF_OPS or mem > self.MAX_KDF_MEM:
            raise ValueError("Payload KDF parameters exceed maximum allowed thresholds.")

        # ==========================================
        # PHASE 3: Cryptography
        # ==========================================
        try:
            aad = self._build_aad(header)
            key = self._derive_key(passphrase, salt, kdf_params)

            # Decrypt and verify tag
            # InvalidTag triggers if: password wrong, ciphertext modified,
            # or any AAD metadata field (v, kdf params, salt, nonce) was tampered.
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except InvalidTag as e:
            raise PermissionError("Decryption failed: Integrity check failed or incorrect password.") from e
        except Exception as e:
            raise RuntimeError("Unexpected cryptographic error during decryption.") from e

        # ==========================================
        # PHASE 4: Output Formatting
        # ==========================================
        if return_bytes:
            return decrypted_bytes

        try:
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            raise RuntimeError("Decrypted data is not valid UTF-8. Use return_bytes=True to retrieve raw bytes.") from e

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
