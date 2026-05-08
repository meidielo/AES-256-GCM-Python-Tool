from __future__ import annotations

__version__ = "1.1.0"

import argparse
import getpass
import os
import sys
import json
import base64
import binascii
import tempfile
from types import MappingProxyType
from typing import BinaryIO, Callable, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag


class DecryptionError(Exception):
    """Raised when decryption fails due to an incorrect passphrase or tampered data."""


# AAD builder type alias
_AadBuilder = Callable[[int, int, int, int, str, str], bytes]


# Module-level AAD builders — referenced directly in _AAD_BUILDERS to avoid
# accessing staticmethod.__func__, which mypy does not support.
def _build_aad_v1(ops: int, mem: int, p: int, key_len: int, salt_b64: str, nonce_b64: str) -> bytes:
    """Legacy v1.0 AAD excludes key_len to preserve hash identicality."""
    return f"v=1.0;ops={ops};mem={mem};p={p};salt={salt_b64};nonce={nonce_b64}".encode('ascii')


def _build_aad_v2(ops: int, mem: int, p: int, key_len: int, salt_b64: str, nonce_b64: str) -> bytes:
    """v2.0 natively binds key_len to the cryptographic authentication tag."""
    return f"v=2.0;ops={ops};mem={mem};p={p};key_len={key_len};salt={salt_b64};nonce={nonce_b64}".encode('ascii')


def _canonical_json_bytes(data: object) -> bytes:
    """Stable JSON encoding for AAD-bound metadata."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode('utf-8')


class SecureVault:
    """
    A compact AES-GCM learning tool using Argon2id for key derivation.

    Security Notes:
    - Passphrase entropy is the caller's responsibility.
    - Single-shot JSON payloads are capped at 100 MiB and peak at roughly
      3x payload size in RAM.
    - The safe-mode streaming format keeps memory bounded by chunk size, but
      it is not compatible with the browser UI or v2.0 JSON blobs.
    - This module does not provide production key lifecycle controls such as
      KMS/HSM storage, access control, audit logging, recovery, or rotation.
    """

    # ==========================================
    # AAD Registry & Versioning
    # ==========================================

    # Exposed as staticmethods so callers can invoke SecureVault._build_aad_v1(...)
    # The registry references the module-level functions directly (before the
    # staticmethod rebinding below), so _AAD_BUILDERS holds plain callables.
    _AAD_BUILDERS: MappingProxyType[str, _AadBuilder] = MappingProxyType({
        "1.0": _build_aad_v1,
        "2.0": _build_aad_v2,
    })
    _build_aad_v1 = staticmethod(_build_aad_v1)
    _build_aad_v2 = staticmethod(_build_aad_v2)

    # SUPPORTED_VERSIONS is derived from the registry — not maintained separately.
    SUPPORTED_VERSIONS: frozenset[str] = frozenset(_AAD_BUILDERS.keys())
    CURRENT_VERSION: str = "2.0"
    STREAM_FORMAT_VERSION: str = "stream-1.0"
    STREAM_PROFILE: str = "safe-mode"
    STREAM_COMPAT_TAGS: tuple[str, ...] = (
        "secure-vault-python>=1.1.0",
        "not-compatible-with-json-v2",
        "not-compatible-with-web-ui",
        "chunked-aes-256-gcm",
    )

    # ==========================================
    # Cryptographic Boundaries & Configurations
    # ==========================================
    MIN_KDF_OPS: int = 2
    MAX_KDF_OPS: int = 10
    MIN_KDF_MEM: int = 32768
    MAX_KDF_MEM: int = 262144
    MIN_KDF_P:   int = 1
    MAX_KDF_P:   int = 16

    MAX_PAYLOAD_SIZE: int = 100 * 1024 * 1024   # 100 MiB hard limit
    # Base64 inflates the 100 MiB ciphertext by ~33% (to ~133 MiB).
    # The * 2 multiplier is a permissive upper bound — it admits payloads
    # larger than expected to accommodate JSON overhead without false positives.
    MAX_JSON_STRING_SIZE: int = MAX_PAYLOAD_SIZE * 2
    STREAM_CHUNK_SIZE: int = 1024 * 1024
    MIN_STREAM_CHUNK_SIZE: int = 4096
    MAX_STREAM_CHUNK_SIZE: int = 16 * 1024 * 1024
    MAX_STREAM_HEADER_SIZE: int = 16 * 1024

    # MappingProxyType protects the inner dictionary from runtime mutation.
    #
    # These defaults exceed OWASP's 2023/2024 minimum baseline for Argon2id
    # (19 MiB / 2 iterations), but were not derived from that guidance directly.
    # p=4 is not an OWASP recommendation — parallelism should be tuned to the
    # CPU core count of the deployment target.
    #
    # Note: MIN_KDF_MEM (32 MiB) and MIN_KDF_OPS (2) define the security floor
    # enforced on decryption. Payloads encrypted with params at that floor are
    # weaker than these defaults — the floor exists for backwards compatibility,
    # not as a target.
    CURRENT_KDF_CONFIG: MappingProxyType[str, int] = MappingProxyType({
        "ops": 3,       # Iterations (time_cost)
        "mem": 65536,   # 64MB RAM (memory_cost)
        "p": 4,         # Parallelism (threads) — tune to deployment CPU core count
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

    @classmethod
    def _validate_stream_chunk_size(cls, chunk_size: int) -> int:
        if type(chunk_size) is not int:
            raise ValueError("Streaming chunk size must be a strict integer.")
        if not (cls.MIN_STREAM_CHUNK_SIZE <= chunk_size <= cls.MAX_STREAM_CHUNK_SIZE):
            raise ValueError(
                "Streaming chunk size out of acceptable bounds "
                f"({cls.MIN_STREAM_CHUNK_SIZE} to {cls.MAX_STREAM_CHUNK_SIZE} bytes)."
            )
        return chunk_size

    @staticmethod
    def _stream_nonce(nonce_prefix: bytes, sequence: int) -> bytes:
        if len(nonce_prefix) != 4:
            raise ValueError("Streaming nonce prefix must be exactly 4 bytes.")
        if sequence < 0 or sequence > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Streaming chunk sequence is out of nonce range.")
        return nonce_prefix + sequence.to_bytes(8, 'big')

    @staticmethod
    def _stream_chunk_aad(header_aad: bytes, sequence: int, final: bool) -> bytes:
        return header_aad + f";seq={sequence};final={1 if final else 0}".encode('ascii')

    def _build_stream_header(self, salt_b64: str, nonce_prefix_b64: str, chunk_size: int) -> dict[str, object]:
        config = self.CURRENT_KDF_CONFIG
        return {
            "type": "secure-vault-stream",
            "v": self.STREAM_FORMAT_VERSION,
            "profile": self.STREAM_PROFILE,
            "compat": list(self.STREAM_COMPAT_TAGS),
            "cipher": "AES-256-GCM",
            "kdf": {
                "ops": config["ops"],
                "mem": config["mem"],
                "p": config["p"],
                "key_len": config["key_len"],
            },
            "salt": salt_b64,
            "nonce_prefix": nonce_prefix_b64,
            "chunk_size": chunk_size,
        }

    def _parse_stream_header(self, line: bytes) -> tuple[dict[str, object], bytes, bytes, int, int, int, int, int, bytes]:
        if not isinstance(line, (bytes, bytearray)):
            raise TypeError("Streaming header must be bytes.")
        if not line:
            raise ValueError("Missing streaming header.")
        if len(line) > self.MAX_STREAM_HEADER_SIZE:
            raise ValueError("Streaming header exceeds maximum allowed size.")

        try:
            record = json.loads(line.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f"Malformed streaming header: {e}") from e

        if not isinstance(record, dict) or set(record.keys()) != {"secure_vault_stream"}:
            raise ValueError("Missing secure-vault streaming header.")

        header = record["secure_vault_stream"]
        if not isinstance(header, dict):
            raise ValueError("Streaming header must be a JSON object.")

        if header.get("type") != "secure-vault-stream":
            raise ValueError("Invalid streaming payload type.")
        if header.get("v") != self.STREAM_FORMAT_VERSION:
            raise ValueError("Unsupported streaming payload version.")
        if header.get("profile") != self.STREAM_PROFILE:
            raise ValueError("Unsupported streaming profile.")
        if header.get("cipher") != "AES-256-GCM":
            raise ValueError("Unsupported streaming cipher.")

        compat = header.get("compat")
        if not isinstance(compat, list) or not all(isinstance(tag, str) for tag in compat):
            raise ValueError("Streaming compatibility tags must be strings.")
        required_tags = {"not-compatible-with-json-v2", "not-compatible-with-web-ui", "chunked-aes-256-gcm"}
        if not required_tags.issubset(set(compat)):
            raise ValueError("Streaming payload is missing required compatibility tags.")

        chunk_size_raw = header.get("chunk_size")
        chunk_size = self._validate_stream_chunk_size(chunk_size_raw)  # type: ignore[arg-type]

        kdf_params = header.get("kdf")
        if not isinstance(kdf_params, dict):
            raise ValueError("Streaming KDF parameters must be a JSON object.")

        ops_raw = kdf_params.get("ops")
        mem_raw = kdf_params.get("mem")
        p_raw = kdf_params.get("p")
        key_len_raw = kdf_params.get("key_len")
        if (
            type(ops_raw) is not int
            or type(mem_raw) is not int
            or type(p_raw) is not int
            or type(key_len_raw) is not int
        ):
            raise ValueError("Streaming KDF parameters must be strict integers.")

        ops = ops_raw
        mem = mem_raw
        p = p_raw
        key_len = key_len_raw
        if not (self.MIN_KDF_OPS <= ops <= self.MAX_KDF_OPS):
            raise ValueError("Streaming KDF operations out of acceptable bounds.")
        if not (self.MIN_KDF_MEM <= mem <= self.MAX_KDF_MEM):
            raise ValueError("Streaming KDF memory out of acceptable bounds.")
        if not (self.MIN_KDF_P <= p <= self.MAX_KDF_P):
            raise ValueError("Streaming KDF parallelism out of acceptable bounds.")
        if key_len != 32:
            raise ValueError("Safe-mode streaming requires AES-256 key_len=32.")

        salt_b64 = header.get("salt")
        nonce_prefix_b64 = header.get("nonce_prefix")
        if not isinstance(salt_b64, str) or not isinstance(nonce_prefix_b64, str):
            raise ValueError("Streaming salt and nonce prefix must be strings.")

        try:
            salt = base64.b64decode(salt_b64, validate=True)
            nonce_prefix = base64.b64decode(nonce_prefix_b64, validate=True)
        except binascii.Error as e:
            raise ValueError(f"Malformed streaming salt or nonce prefix: {e}") from e

        if len(salt) != 16:
            raise ValueError(f"Invalid streaming salt length: expected 16, got {len(salt)}.")
        if len(nonce_prefix) != 4:
            raise ValueError(f"Invalid streaming nonce prefix length: expected 4, got {len(nonce_prefix)}.")

        header_aad = _canonical_json_bytes(header)
        return header, salt, nonce_prefix, ops, mem, p, key_len, chunk_size, header_aad

    def _parse_stream_chunk(self, line: bytes, expected_sequence: int, max_ciphertext_size: int) -> tuple[bool, bytes]:
        if not isinstance(line, (bytes, bytearray)):
            raise TypeError("Streaming chunk record must be bytes.")
        if not line:
            raise ValueError("Streaming payload ended before a final chunk.")

        max_record_size = ((max_ciphertext_size + 16) * 4 // 3) + 512
        if len(line) > max_record_size:
            raise ValueError("Streaming chunk record exceeds maximum allowed size.")

        try:
            record = json.loads(line.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f"Malformed streaming chunk: {e}") from e

        if not isinstance(record, dict) or set(record.keys()) != {"chunk"}:
            raise ValueError("Streaming chunk record must contain only a chunk object.")
        chunk = record["chunk"]
        if not isinstance(chunk, dict):
            raise ValueError("Streaming chunk must be a JSON object.")

        sequence_raw = chunk.get("seq")
        final_raw = chunk.get("final")
        ciphertext_b64 = chunk.get("ciphertext")
        if type(sequence_raw) is not int:
            raise ValueError("Streaming chunk sequence must be a strict integer.")
        if sequence_raw != expected_sequence:
            raise ValueError("Unexpected streaming chunk sequence.")
        if type(final_raw) is not bool:
            raise ValueError("Streaming chunk final flag must be a strict boolean.")
        if not isinstance(ciphertext_b64, str):
            raise ValueError("Streaming chunk ciphertext must be a string.")

        try:
            ciphertext_with_tag = base64.b64decode(ciphertext_b64, validate=True)
        except binascii.Error as e:
            raise ValueError(f"Malformed streaming chunk ciphertext: {e}") from e

        if len(ciphertext_with_tag) <= 16:
            raise ValueError("Streaming chunk ciphertext too short to contain plaintext and a GCM tag.")
        if len(ciphertext_with_tag) > max_ciphertext_size + 16:
            raise ValueError("Streaming chunk ciphertext exceeds configured chunk size.")

        return final_raw, ciphertext_with_tag

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
        header: dict[str, object] = {
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

        ops_raw = kdf_params.get("ops")
        mem_raw = kdf_params.get("mem")
        p_raw   = kdf_params.get("p")

        # Strict type check: type(x) is not int excludes booleans (isinstance(True, int) is True)
        if type(ops_raw) is not int or type(mem_raw) is not int or type(p_raw) is not int:
            raise ValueError("KDF parameters (ops, mem, p) must be strict integers.")

        ops = ops_raw
        mem = mem_raw
        p   = p_raw

        # Prevent Downgrade Attacks and Denial of Service (DoS)
        if not (self.MIN_KDF_OPS <= ops <= self.MAX_KDF_OPS):
            raise ValueError("Payload KDF operations out of acceptable bounds.")
        if not (self.MIN_KDF_MEM <= mem <= self.MAX_KDF_MEM):
            raise ValueError("Payload KDF memory out of acceptable bounds.")
        if not (self.MIN_KDF_P <= p <= self.MAX_KDF_P):
            raise ValueError("Payload KDF parallelism out of acceptable bounds.")

        key_len: int
        if v == "1.0":
            key_len = 32  # Implicit fallback for legacy payloads
        else:
            key_len_raw = kdf_params.get("key_len")
            if type(key_len_raw) is not int or key_len_raw not in {16, 24, 32}:
                raise ValueError("Invalid key_len: must be 16, 24, or 32.")
            key_len = key_len_raw

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

    def encrypt_stream(
        self,
        source: BinaryIO,
        destination: BinaryIO,
        passphrase: str,
        chunk_size: int = STREAM_CHUNK_SIZE,
    ) -> dict[str, int]:
        """
        Encrypt a binary stream with the safe-mode chunked profile.

        The output is line-delimited JSON. It is intentionally incompatible
        with v2.0 JSON blobs and the browser UI.
        """
        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")
        chunk_size = self._validate_stream_chunk_size(chunk_size)

        current = source.read(chunk_size)
        if not isinstance(current, (bytes, bytearray)):
            raise TypeError("Streaming source must yield bytes.")
        if not current:
            raise ValueError("Plaintext stream cannot be empty.")

        salt = os.urandom(16)
        nonce_prefix = os.urandom(4)
        config = self.CURRENT_KDF_CONFIG
        salt_b64 = base64.b64encode(salt).decode('ascii')
        nonce_prefix_b64 = base64.b64encode(nonce_prefix).decode('ascii')
        header = self._build_stream_header(salt_b64, nonce_prefix_b64, chunk_size)
        header_aad = _canonical_json_bytes(header)
        try:
            key = self._derive_key(passphrase, salt, config["ops"], config["mem"], config["p"], config["key_len"])
        except MemoryError as e:
            raise RuntimeError("Insufficient system memory to perform Argon2 key derivation.") from e
        aesgcm = AESGCM(key)

        header_record = json.dumps({"secure_vault_stream": header}, separators=(",", ":")).encode('utf-8')
        destination.write(header_record + b"\n")

        sequence = 0
        chunk_count = 0
        plaintext_bytes = 0
        ciphertext_bytes = 0

        while True:
            next_chunk = source.read(chunk_size)
            if not isinstance(next_chunk, (bytes, bytearray)):
                raise TypeError("Streaming source must yield bytes.")

            final = len(next_chunk) == 0
            plaintext_chunk = bytes(current)
            nonce = self._stream_nonce(nonce_prefix, sequence)
            aad = self._stream_chunk_aad(header_aad, sequence, final)
            ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_chunk, aad)
            chunk_record = {
                "chunk": {
                    "seq": sequence,
                    "final": final,
                    "ciphertext": base64.b64encode(ciphertext_with_tag).decode('ascii'),
                }
            }
            encoded = json.dumps(chunk_record, separators=(",", ":")).encode('utf-8') + b"\n"
            destination.write(encoded)

            chunk_count += 1
            plaintext_bytes += len(plaintext_chunk)
            ciphertext_bytes += len(encoded)

            if final:
                break

            current = next_chunk
            sequence += 1

        return {
            "chunks": chunk_count,
            "plaintext_bytes": plaintext_bytes,
            "encoded_bytes": ciphertext_bytes + len(header_record) + 1,
        }

    def decrypt_stream(self, source: BinaryIO, destination: BinaryIO, passphrase: str) -> dict[str, int]:
        """
        Decrypt a safe-mode streaming payload into a binary destination.

        Callers that write to a real file should use a temporary file and only
        replace the final path after this method returns successfully.
        """
        if not passphrase:
            raise ValueError("Passphrase required for decryption.")

        header_line = source.readline(self.MAX_STREAM_HEADER_SIZE + 1)
        if len(header_line) > self.MAX_STREAM_HEADER_SIZE:
            raise ValueError("Streaming header exceeds maximum allowed size.")
        _, salt, nonce_prefix, ops, mem, p, key_len, chunk_size, header_aad = self._parse_stream_header(header_line)
        try:
            key = self._derive_key(passphrase, salt, ops, mem, p, key_len)
        except MemoryError as e:
            raise RuntimeError("Insufficient system memory to perform Argon2 key derivation.") from e
        aesgcm = AESGCM(key)

        sequence = 0
        chunk_count = 0
        plaintext_bytes = 0
        max_record_size = ((chunk_size + 16) * 4 // 3) + 512

        while True:
            line = source.readline(max_record_size + 1)
            if len(line) > max_record_size:
                raise ValueError("Streaming chunk record exceeds maximum allowed size.")
            final, ciphertext_with_tag = self._parse_stream_chunk(line, sequence, chunk_size)

            try:
                nonce = self._stream_nonce(nonce_prefix, sequence)
                aad = self._stream_chunk_aad(header_aad, sequence, final)
                plaintext_chunk = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
            except InvalidTag as e:
                raise DecryptionError("Streaming integrity check failed. Incorrect password or tampered data.") from e
            except MemoryError as e:
                raise RuntimeError("Insufficient system memory to perform Argon2 key derivation.") from e
            except Exception as e:
                raise RuntimeError("Unexpected cryptographic error during streaming decryption.") from e

            destination.write(plaintext_chunk)
            chunk_count += 1
            plaintext_bytes += len(plaintext_chunk)

            if final:
                trailing = source.read(1)
                if trailing:
                    raise ValueError("Trailing data after final streaming chunk.")
                break

            sequence += 1

        return {"chunks": chunk_count, "plaintext_bytes": plaintext_bytes}


# ==========================================
# CLI
# ==========================================
def _cli_encrypt(args: argparse.Namespace, vault: SecureVault, passphrase: str) -> None:
    if args.file:
        with open(args.file, 'rb') as f:
            plaintext: Union[str, bytes] = f.read()
    else:
        plaintext = args.text

    blob = vault.encrypt(plaintext, passphrase)

    if args.out:
        with open(args.out, 'w') as f:
            f.write(blob)
        print(f"Encrypted payload written to: {args.out}")
    else:
        print(blob)


def _cli_decrypt(args: argparse.Namespace, vault: SecureVault, passphrase: str) -> None:
    if args.file:
        with open(args.file, 'r') as f:
            encrypted_json: str = f.read()
    else:
        encrypted_json = args.text

    result = vault.decrypt(encrypted_json, passphrase, return_bytes=args.bytes)

    if args.out:
        mode = 'wb' if isinstance(result, bytes) else 'w'
        with open(args.out, mode) as f:
            f.write(result)
        print(f"Decrypted output written to: {args.out}")
    else:
        if isinstance(result, bytes):
            sys.stdout.buffer.write(result)
        else:
            print(result)


def _write_temp_then_replace(out_path: str, writer: Callable[[BinaryIO], dict[str, int]]) -> dict[str, int]:
    out_abs = os.path.abspath(out_path)
    out_dir = os.path.dirname(out_abs) or "."
    fd, temp_path = tempfile.mkstemp(prefix=".secure-vault-", suffix=".tmp", dir=out_dir)
    try:
        with os.fdopen(fd, 'wb') as temp_file:
            stats = writer(temp_file)
        os.replace(temp_path, out_abs)
        return stats
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def _cli_encrypt_stream(args: argparse.Namespace, vault: SecureVault, passphrase: str) -> None:
    def writer(destination: BinaryIO) -> dict[str, int]:
        with open(args.file, 'rb') as source:
            return vault.encrypt_stream(source, destination, passphrase, chunk_size=args.chunk_size)

    stats = _write_temp_then_replace(args.out, writer)
    print(
        f"Safe-mode stream written to: {args.out} "
        f"({stats['chunks']} chunks, {stats['plaintext_bytes']} plaintext bytes)"
    )


def _cli_decrypt_stream(args: argparse.Namespace, vault: SecureVault, passphrase: str) -> None:
    def writer(destination: BinaryIO) -> dict[str, int]:
        with open(args.file, 'rb') as source:
            return vault.decrypt_stream(source, destination, passphrase)

    stats = _write_temp_then_replace(args.out, writer)
    print(
        f"Safe-mode stream decrypted to: {args.out} "
        f"({stats['chunks']} chunks, {stats['plaintext_bytes']} plaintext bytes)"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-vault",
        description="AES-256-GCM learning tool with Argon2id key derivation."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- encrypt ---
    enc = sub.add_parser("encrypt", help="Encrypt plaintext to a JSON blob.")
    src = enc.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", metavar="PATH", help="Path to plaintext file.")
    src.add_argument("--text", metavar="TEXT", help="Plaintext string.")
    enc.add_argument("--out", metavar="PATH", help="Write encrypted JSON to file (default: stdout).")

    # --- decrypt ---
    dec = sub.add_parser("decrypt", help="Decrypt a JSON blob to plaintext.")
    src2 = dec.add_mutually_exclusive_group(required=True)
    src2.add_argument("--file", metavar="PATH", help="Path to encrypted JSON file.")
    src2.add_argument("--text", metavar="TEXT", help="Encrypted JSON string.")
    dec.add_argument("--out", metavar="PATH", help="Write decrypted output to file (default: stdout).")
    dec.add_argument("--bytes", action="store_true", help="Return raw bytes (for binary payloads).")

    # --- encrypt-stream ---
    enc_stream = sub.add_parser(
        "encrypt-stream",
        help="Encrypt a file using the safe-mode streaming profile.",
    )
    enc_stream.add_argument("--file", metavar="PATH", required=True, help="Path to plaintext file.")
    enc_stream.add_argument("--out", metavar="PATH", required=True, help="Write stream payload to file.")
    enc_stream.add_argument(
        "--chunk-size",
        metavar="BYTES",
        type=int,
        default=SecureVault.STREAM_CHUNK_SIZE,
        help=f"Streaming chunk size (default: {SecureVault.STREAM_CHUNK_SIZE}).",
    )

    # --- decrypt-stream ---
    dec_stream = sub.add_parser(
        "decrypt-stream",
        help="Decrypt a safe-mode streaming payload to a file.",
    )
    dec_stream.add_argument("--file", metavar="PATH", required=True, help="Path to stream payload.")
    dec_stream.add_argument("--out", metavar="PATH", required=True, help="Write decrypted bytes to file.")

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        passphrase = getpass.getpass("Passphrase: ")
        if not passphrase:
            print("Error: passphrase cannot be empty.", file=sys.stderr)
            sys.exit(1)

        if args.command in {"encrypt", "encrypt-stream"}:
            confirm = getpass.getpass("Confirm passphrase: ")
            if passphrase != confirm:
                print("Error: passphrases do not match.", file=sys.stderr)
                sys.exit(1)

        vault = SecureVault()
        if args.command == "encrypt":
            _cli_encrypt(args, vault, passphrase)
        elif args.command == "decrypt":
            _cli_decrypt(args, vault, passphrase)
        elif args.command == "encrypt-stream":
            _cli_encrypt_stream(args, vault, passphrase)
        elif args.command == "decrypt-stream":
            _cli_decrypt_stream(args, vault, passphrase)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except (ValueError, TypeError, DecryptionError, RuntimeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
