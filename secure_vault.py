import os
import json
import base64
import binascii
from types import MappingProxyType
from typing import Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag


class DecryptionError(Exception):
    """Raised when decryption fails due to an incorrect passphrase or tampered data."""


class SecureVault:
    """
    A production-grade AES-GCM vault using Argon2id for key derivation.

    Security Notes:
    - Passphrase entropy is the caller's responsibility.
    - OOM Protection: Payloads are capped at 100 MiB.
      Note: Peak RAM usage during encryption/decryption is roughly 3x the
      payload size (~300 MiB) due to base64 encoding, intermediate string
      allocation, and ciphertext byte arrays existing simultaneously.
      Larger files require chunked streaming (e.g., via Tink or STREAM ciphers).
    """

    # ==========================================
    # AAD Registry & Versioning
    # ==========================================
    @staticmethod
    def _build_aad_v1(ops: int, mem: int, p: int, key_len: int, salt_b64: str, nonce_b64: str) -> bytes:
        """Legacy v1.0 AAD excludes key_len to preserve hash identicality."""
        return f"v=1.0;ops={ops};mem={mem};p={p};salt={salt_b64};nonce={nonce_b64}".encode('ascii')

    @staticmethod
    def _build_aad_v2(ops: int, mem: int, p: int, key_len: int, salt_b64: str, nonce_b64: str) -> bytes:
        """v2.0 natively binds key_len to the cryptographic authentication tag."""
        return f"v=2.0;ops={ops};mem={mem};p={p};key_len={key_len};salt={salt_b64};nonce={nonce_b64}".encode('ascii')

    # Extracting .__func__ safely registers the underlying function for < Python 3.10.
    # Prior to Python 3.10, staticmethod objects were not directly callable.
    _AAD_BUILDERS = MappingProxyType({
        "1.0": _build_aad_v1.__func__,
        "2.0": _build_aad_v2.__func__,
    })

    # SUPPORTED_VERSIONS is derived from the registry — not maintained separately.
    SUPPORTED_VERSIONS = frozenset(_AAD_BUILDERS.keys())
    CURRENT_VERSION = "2.0"

    # ==========================================
    # Cryptographic Boundaries & Configurations
    # ==========================================
    MIN_KDF_OPS, MAX_KDF_OPS = 2, 10
    MIN_KDF_MEM, MAX_KDF_MEM = 32768, 262144
    MIN_KDF_P,   MAX_KDF_P   = 1, 16

    MAX_PAYLOAD_SIZE = 100 * 1024 * 1024    # 100 MiB hard limit
    # Base64 inflates the 100 MiB ciphertext by ~33% (to ~133 MiB).
    # The * 2 multiplier is a permissive upper bound — it admits payloads
    # larger than expected to accommodate JSON overhead without false positives.
    MAX_JSON_STRING_SIZE = MAX_PAYLOAD_SIZE * 2

    # MappingProxyType protects the inner dictionary from runtime mutation.
    CURRENT_KDF_CONFIG = MappingProxyType({
        "ops": 3,       # Iterations (time_cost)
        "mem": 65536,   # 64MB RAM (memory_cost)
        "p": 4,         # Parallelism (threads)
        "key_len": 32   # 256-bit key for AES-256
    })

    def _derive_key(self, passphrase: str, salt: bytes, ops: int, mem: int, p: int, key_len: int) -> bytes:
        """Derives a key using Argon2id. No dictionary .get() fallbacks — strict args only."""
        kdf = Argon2id(
            salt=salt,
            length=key_len,
            iterations=ops,
            lanes=p,            # parallelism
            memory_cost=mem,
        )
        return kdf.derive(passphrase.encode('utf-8'))

    def encrypt(self, plaintext: Union[str, bytes], passphrase: str) -> str:
        """Encrypts data and returns a structured JSON object with embedded KDF parameters."""
        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")
        if not plaintext:  # Note: empty bytes b"" intentionally triggers this. b"\x00" will pass.
            raise ValueError("Plaintext data cannot be empty.")

        plaintext_bytes = plaintext.encode('utf-8') if isinstance(plaintext, str) else plaintext

        if len(plaintext_bytes) > self.MAX_PAYLOAD_SIZE:
            raise ValueError(f"Plaintext exceeds maximum allowed size ({self.MAX_PAYLOAD_SIZE} bytes).")

        salt  = os.urandom(16)
        nonce = os.urandom(12)
        config = self.CURRENT_KDF_CONFIG

        # Pre-encode to Base64 strings so both header and AAD use the identical value
        salt_b64  = base64.b64encode(salt).decode('ascii')
        nonce_b64 = base64.b64encode(nonce).decode('ascii')

        # MemoryError may propagate naturally here if Argon2 exhausts system RAM.
        key = self._derive_key(passphrase, salt, config["ops"], config["mem"], config["p"], config["key_len"])

        # KDF params are stored in the payload so future code versions can still
        # decrypt packets produced with different parameters.
        header = {
            "v": self.CURRENT_VERSION,
            "kdf": {
                "ops": config["ops"],
                "mem": config["mem"],
                "p": config["p"],
                "key_len": config["key_len"]
            },
            "salt": salt_b64,
            "nonce": nonce_b64
        }

        # Binding the version, salt, and KDF params to the ciphertext via AAD means
        # any tampering with unencrypted metadata will fail the auth tag check.
        builder = self._AAD_BUILDERS[self.CURRENT_VERSION]
        aad = builder(config["ops"], config["mem"], config["p"], config["key_len"], salt_b64, nonce_b64)

        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, aad)

        # Outer JSON dump is safe here — it's transport only, not part of AAD
        return json.dumps({
            "header": header,
            "ciphertext": base64.b64encode(ciphertext_with_tag).decode('ascii')
        })

    def decrypt(self, encrypted_json: Union[str, bytes], passphrase: str, return_bytes: bool = False) -> Union[str, bytes]:
        """Decrypts the JSON payload, validates integrity, and verifies AAD."""
        if not passphrase:
            raise ValueError("Passphrase required for decryption.")

        if not isinstance(encrypted_json, (str, bytes)):
            raise TypeError("Encrypted payload must be a string or bytes.")

        # ==========================================
        # PHASE 0: Pre-Parse Validation
        # Prevents OOM DoS attacks via multi-gigabyte JSON structures.
        # ==========================================
        if len(encrypted_json) > self.MAX_JSON_STRING_SIZE:
            raise ValueError(f"Payload input exceeds maximum allowed size ({self.MAX_JSON_STRING_SIZE} units).")

        # ==========================================
        # PHASE 1: Parsing
        # ==========================================
        try:
            full_packet = json.loads(encrypted_json)
            header = full_packet["header"]
            ciphertext_with_tag = base64.b64decode(full_packet["ciphertext"])

            kdf_params = header["kdf"]
            # Preserve raw Base64 strings — used verbatim in AAD reconstruction
            salt_b64  = header["salt"]
            nonce_b64 = header["nonce"]

            # Explicit type guard: non-string values would silently pass b64decode
            if not isinstance(salt_b64, str) or not isinstance(nonce_b64, str):
                raise TypeError("Salt and nonce must be strings.")

            salt  = base64.b64decode(salt_b64)
            nonce = base64.b64decode(nonce_b64)
        except (KeyError, json.JSONDecodeError, binascii.Error, TypeError) as e:
            raise ValueError(f"Malformed payload structure: {e}") from e

        # ==========================================
        # PHASE 2: Validation
        # ==========================================
        v = header.get("v")
        if not v:
            raise ValueError("Missing version field in payload header.")
        if v not in self.SUPPORTED_VERSIONS:
            raise ValueError(f"Unsupported payload version: {v}")

        if not isinstance(kdf_params, dict):
            raise ValueError("KDF parameters must be a JSON object.")

        if len(salt) != 16:
            raise ValueError(f"Invalid salt length: expected 16, got {len(salt)}.")
        if len(nonce) != 12:
            raise ValueError(f"Invalid nonce length: expected 12, got {len(nonce)}.")

        if len(ciphertext_with_tag) < 16:
            raise ValueError("Ciphertext too short to contain GCM authentication tag.")
        if len(ciphertext_with_tag) > self.MAX_PAYLOAD_SIZE + 16:  # +16 for GCM tag
            raise ValueError(f"Ciphertext exceeds maximum allowed size ({self.MAX_PAYLOAD_SIZE} bytes).")

        ops, mem, p = kdf_params.get("ops"), kdf_params.get("mem"), kdf_params.get("p")

        # Strict type check: type(x) is not int excludes booleans (isinstance(True, int) is True)
        if type(ops) is not int or type(mem) is not int or type(p) is not int:
            raise ValueError("KDF parameters (ops, mem, p) must be strict integers.")

        # Prevent Downgrade Attacks and Denial of Service (DoS)
        if not (self.MIN_KDF_OPS <= ops <= self.MAX_KDF_OPS):
            raise ValueError("Payload KDF operations out of acceptable bounds.")
        if not (self.MIN_KDF_MEM <= mem <= self.MAX_KDF_MEM):
            raise ValueError("Payload KDF memory out of acceptable bounds.")
        if not (self.MIN_KDF_P <= p <= self.MAX_KDF_P):
            raise ValueError("Payload KDF parallelism out of acceptable bounds.")

        if v == "1.0":
            key_len = 32  # Implicit fallback for legacy payloads
        else:
            key_len = kdf_params.get("key_len")
            if type(key_len) is not int or key_len not in {16, 24, 32}:
                raise ValueError("Invalid key_len: must be 16, 24, or 32.")

        # ==========================================
        # PHASE 2.5: AAD Construction
        # ==========================================
        # Lifted out of Phase 3 to ensure developer desync errors (missing builder)
        # crash loudly rather than getting masked by the generic Exception handler.
        builder = self._AAD_BUILDERS[v]
        aad = builder(ops, mem, p, key_len, salt_b64, nonce_b64)

        # ==========================================
        # PHASE 3: Cryptography
        # ==========================================
        try:
            key = self._derive_key(passphrase, salt, ops, mem, p, key_len)

            # InvalidTag triggers if: password wrong, ciphertext modified,
            # or any AAD metadata field (v, kdf params, salt, nonce) was tampered.
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except InvalidTag as e:
            raise DecryptionError("Integrity check failed. Incorrect password or tampered data.") from e
        except MemoryError as e:
            raise RuntimeError("Insufficient system memory to perform Argon2 key derivation.") from e
        except Exception as e:
            raise RuntimeError("Unexpected cryptographic error during decryption.") from e

        # ==========================================
        # PHASE 4: Output
        # ==========================================
        if return_bytes:
            return decrypted_bytes

        try:
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            raise RuntimeError("Decrypted data is not valid UTF-8. Use return_bytes=True to retrieve raw bytes.") from e


if __name__ == "__main__":
    vault = SecureVault()
    password = "correct-horse-battery-staple"

    print("--- 1. Standard String Encryption (v2.0) ---")
    secret_text = "Highly confidential production data."
    blob_v2 = vault.encrypt(secret_text, password)
    print(f"Encrypted Blob: {blob_v2[:80]}...")
    print(f"Decrypted Text: {vault.decrypt(blob_v2, password)}\n")

    print("--- 2. Raw Bytes Encryption (v2.0) ---")
    secret_bytes = b"\x00\xFF\x00\x11\x22\x33 Binary Payload"
    blob_bytes = vault.encrypt(secret_bytes, password)
    decrypted_bytes = vault.decrypt(blob_bytes, password, return_bytes=True)
    print(f"Decrypted Bytes Match: {secret_bytes == decrypted_bytes}")
