import os
import json
import base64
import binascii
from types import MappingProxyType
from typing import Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag

class SecureVault:
    """
    A production-grade AES-GCM vault using Argon2id for key derivation.

    Security Notes:
    - Passphrase entropy is the caller's responsibility.
    - OOM Protection: Payloads are capped at 100 MiB. Larger files require
      chunked streaming (e.g., via Tink or STREAM ciphers).
    """

    # __slots__ prevents instance-level dictionary creation (e.g., self.x = 1).
    __slots__ = ()

    # ==========================================
    # AAD Registry & Versioning (Single Source of Truth)
    # ==========================================
    @staticmethod
    def _build_aad_v1(ops: int, mem: int, p: int, key_len: int, salt_b64: str, nonce_b64: str) -> bytes:
        """Legacy v1.0 AAD excludes key_len to preserve hash identicality."""
        del key_len  # v1.0 does not bind key_len; present for registry signature parity
        return f"v=1.0;ops={ops};mem={mem};p={p};salt={salt_b64};nonce={nonce_b64}".encode('ascii')

    @staticmethod
    def _build_aad_v2(ops: int, mem: int, p: int, key_len: int, salt_b64: str, nonce_b64: str) -> bytes:
        """v2.0 natively binds key_len to the cryptographic authentication tag."""
        return f"v=2.0;ops={ops};mem={mem};p={p};key_len={key_len};salt={salt_b64};nonce={nonce_b64}".encode('ascii')

    # Note: Because these functions are referenced here at class definition time,
    # they are stored as unbound functions. When retrieved from this dict, they
    # bypass the descriptor protocol and behave exactly like plain functions.
    # DO NOT wrap them in staticmethod() here, or calling them will raise TypeError.
    _AAD_BUILDERS = MappingProxyType({
        "1.0": _build_aad_v1,
        "2.0": _build_aad_v2,
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
        # Security: passphrase entropy is the caller's responsibility.
        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")
        if not plaintext:  # Note: empty bytes b"" intentionally triggers this. b"\x00" will pass.
            raise ValueError("Plaintext data cannot be empty.")

        # Handle binary vs string data explicitly
        plaintext_bytes = plaintext.encode('utf-8') if isinstance(plaintext, str) else plaintext

        if len(plaintext_bytes) > self.MAX_PAYLOAD_SIZE:
            raise ValueError(f"Plaintext exceeds maximum allowed size ({self.MAX_PAYLOAD_SIZE} bytes).")

        # 1. Generate unique 16-byte salt and 12-byte nonce (NIST Standard)
        salt = os.urandom(16)
        nonce = os.urandom(12)
        config = self.CURRENT_KDF_CONFIG

        # Pre-encode to Base64 strings so both header and AAD use the identical value
        salt_b64  = base64.b64encode(salt).decode('ascii')
        nonce_b64 = base64.b64encode(nonce).decode('ascii')

        # 2. Derive key from passphrase using current KDF config
        # Parameters are explicitly passed; no dictionary .get() logic exists here.
        key = self._derive_key(passphrase, salt, config["ops"], config["mem"], config["p"], config["key_len"])

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
            "salt": salt_b64,
            "nonce": nonce_b64
        }

        # 4. Look up the correct AAD builder from the registry and build AAD
        # Binding the version, salt, and KDF params to the ciphertext integrity
        # means any tampering with unencrypted metadata will fail the auth tag check.
        builder = self._AAD_BUILDERS[self.CURRENT_VERSION]
        aad = builder(config["ops"], config["mem"], config["p"], config["key_len"], salt_b64, nonce_b64)

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

            salt  = base64.b64decode(salt_b64)
            nonce = base64.b64decode(nonce_b64)
        except (KeyError, json.JSONDecodeError, binascii.Error, TypeError) as e:
            raise ValueError(f"Decryption failed: Malformed payload structure. {e}") from e

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

        # Cryptographic field length checks
        if len(salt) != 16:
            raise ValueError(f"Invalid salt length: expected 16, got {len(salt)}.")
        if len(nonce) != 12:
            raise ValueError(f"Invalid nonce length: expected 12, got {len(nonce)}.")

        if len(ciphertext_with_tag) < 16:
            raise ValueError("Ciphertext too short to contain GCM authentication tag.")
        if len(ciphertext_with_tag) > self.MAX_PAYLOAD_SIZE + 16:  # +16 for GCM tag
            raise ValueError(f"Ciphertext exceeds maximum allowed size ({self.MAX_PAYLOAD_SIZE} bytes).")

        # KDF boundary validations
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

        # Version-specific key length logic
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
            # Parameters are explicitly passed; no dictionary .get() logic exists here.
            key = self._derive_key(passphrase, salt, ops, mem, p, key_len)

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
        # PHASE 4: Output
        # ==========================================
        if return_bytes:
            return decrypted_bytes

        try:
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            raise RuntimeError("Decrypted data is not valid UTF-8. Use return_bytes=True to retrieve raw bytes.") from e

# ==========================================
# Thread-Safe Smoke Tests & Validation
# ==========================================
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
    print(f"Decrypted Bytes Match: {secret_bytes == decrypted_bytes}\n")

    print("--- 3. Legacy v1.0 Decryption Test ---")
    # Structurally construct a genuine v1.0 blob without mutating class state
    salt_v1, nonce_v1 = os.urandom(16), os.urandom(12)
    s_b64 = base64.b64encode(salt_v1).decode('ascii')
    n_b64 = base64.b64encode(nonce_v1).decode('ascii')

    # Argon2 Parameters
    v1_ops, v1_mem, v1_p, v1_key_len = 3, 65536, 4, 32
    key_v1 = vault._derive_key(password, salt_v1, v1_ops, v1_mem, v1_p, v1_key_len)

    aad_v1 = SecureVault._build_aad_v1(v1_ops, v1_mem, v1_p, v1_key_len, s_b64, n_b64)
    ct_v1 = AESGCM(key_v1).encrypt(nonce_v1, b"Legacy data payload", aad_v1)

    blob_v1_dict = {
        "header": {
            "v": "1.0",
            "kdf": {"ops": v1_ops, "mem": v1_mem, "p": v1_p},  # No key_len in v1
            "salt": s_b64,
            "nonce": n_b64
        },
        "ciphertext": base64.b64encode(ct_v1).decode('ascii')
    }
    blob_v1 = json.dumps(blob_v1_dict)

    print(f"Constructed v1.0 Blob: {blob_v1[:80]}...")
    print(f"Decrypted v1.0 Text: {vault.decrypt(blob_v1, password)}")
