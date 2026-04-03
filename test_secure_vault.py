import os
import pytest
import json
import base64
from unittest.mock import patch
from hypothesis import given, strategies as st, settings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secure_vault import SecureVault, DecryptionError

# ==========================================
# Test Helpers
# ==========================================
def _generate_mock_v1_blob(password: str, plaintext: bytes) -> str:
    """
    Constructs a genuine v1.0 payload without mutating class state.
    Accesses internal APIs for testing purposes only.
    """
    vault = SecureVault()
    salt, nonce = os.urandom(16), os.urandom(12)
    s_b64 = base64.b64encode(salt).decode('ascii')
    n_b64 = base64.b64encode(nonce).decode('ascii')

    ops, mem, p, key_len = 3, 65536, 4, 32
    key = vault._derive_key(password, salt, ops, mem, p, key_len)

    # Descriptor protocol unwraps staticmethod when accessed from outside the class body
    aad = SecureVault._build_aad_v1(ops, mem, p, key_len, s_b64, n_b64)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)

    return json.dumps({
        "header": {
            "v": "1.0",
            "kdf": {"ops": ops, "mem": mem, "p": p},  # v1.0 implicitly lacks key_len
            "salt": s_b64,
            "nonce": n_b64
        },
        "ciphertext": base64.b64encode(ct).decode('ascii')
    })

# ==========================================
# Fixtures
# ==========================================
@pytest.fixture
def vault():
    return SecureVault()

@pytest.fixture
def password():
    return "correct-horse-battery-staple"

@pytest.fixture
def standard_blob(vault, password):
    return vault.encrypt("Secret Plaintext", password)

# ==========================================
# 1. Core Functionality (Happy Paths)
# ==========================================
def test_roundtrip_string(vault, password):
    plaintext = "Hello, world! 🌍"
    blob = vault.encrypt(plaintext, password)
    assert vault.decrypt(blob, password) == plaintext

def test_roundtrip_bytes(vault, password):
    plaintext = b"\x00\xFF\xDE\xAD\xBE\xEF\x00"
    blob = vault.encrypt(plaintext, password)
    assert vault.decrypt(blob, password, return_bytes=True) == plaintext

def test_decrypt_accepts_bytes_input(vault, password):
    blob_bytes = vault.encrypt("hello", password).encode('utf-8')
    assert vault.decrypt(blob_bytes, password) == "hello"

def test_legacy_v1_decryption(vault, password):
    legacy_data = b"Legacy data payload"
    blob_v1 = _generate_mock_v1_blob(password, legacy_data)
    assert vault.decrypt(blob_v1, password) == legacy_data.decode('utf-8')

# ==========================================
# 2. Cryptographic Contract & Schema Validation
# ==========================================
def test_encryption_is_non_deterministic(vault, password):
    blob1 = vault.encrypt("same data", password)
    blob2 = vault.encrypt("same data", password)

    payload1 = json.loads(blob1)
    payload2 = json.loads(blob2)

    assert payload1["ciphertext"] != payload2["ciphertext"]
    assert payload1["header"]["nonce"] != payload2["header"]["nonce"]
    assert payload1["header"]["salt"] != payload2["header"]["salt"]

def test_payload_structure(vault, password):
    blob = vault.encrypt("data", password)
    payload = json.loads(blob)

    assert "header" in payload
    assert "ciphertext" in payload
    assert payload["header"]["v"] == "2.0"
    assert "salt" in payload["header"]
    assert "nonce" in payload["header"]
    assert all(k in payload["header"]["kdf"] for k in ("ops", "mem", "p", "key_len"))

# ==========================================
# 3. Authentication & Integrity (Negative Tests)
# ==========================================
def test_wrong_password_raises_decryption_error(vault, standard_blob):
    with pytest.raises(DecryptionError, match="Integrity check failed"):
        vault.decrypt(standard_blob, "wrong-password")

def test_tampered_metadata_fails_aad(vault, standard_blob, password):
    payload = json.loads(standard_blob)
    payload["header"]["kdf"]["ops"] += 1
    tampered_blob = json.dumps(payload)

    with pytest.raises(DecryptionError, match="Integrity check failed"):
        vault.decrypt(tampered_blob, password)

def test_tampered_ciphertext_fails_tag(vault, standard_blob, password):
    payload = json.loads(standard_blob)
    raw_ct = bytearray(base64.b64decode(payload["ciphertext"]))
    raw_ct[0] ^= 0xFF
    payload["ciphertext"] = base64.b64encode(raw_ct).decode('ascii')

    with pytest.raises(DecryptionError, match="Integrity check failed"):
        vault.decrypt(json.dumps(payload), password)

def test_v1_blob_rejected_by_v2_aad(vault, password):
    """Proves version AAD structures are cryptographically isolated from each other."""
    blob_v1 = _generate_mock_v1_blob(password, b"data")
    payload = json.loads(blob_v1)

    # Mutate to bypass Phase 2 structural validation and force Phase 3 AAD rejection
    payload["header"]["v"] = "2.0"
    payload["header"]["kdf"]["key_len"] = 32

    with pytest.raises(DecryptionError, match="Integrity check failed"):
        vault.decrypt(json.dumps(payload), password)

# ==========================================
# 4. Boundary & Type Evasion Enforcement
# ==========================================
@pytest.mark.parametrize("field,value,match", [
    ("ops", 1,      "operations out of acceptable bounds"),
    ("ops", 11,     "operations out of acceptable bounds"),
    ("mem", 16384,  "memory out of acceptable bounds"),
    ("mem", 524288, "memory out of acceptable bounds"),
    ("p",   0,      "parallelism out of acceptable bounds"),
    ("p",   17,     "parallelism out of acceptable bounds"),
    ("key_len", 15, r"Invalid key_len: must be 16, 24, or 32\."),
])
def test_kdf_boundary_enforcement(vault, standard_blob, password, field, value, match):
    payload = json.loads(standard_blob)
    payload["header"]["kdf"][field] = value
    with pytest.raises(ValueError, match=match):
        vault.decrypt(json.dumps(payload), password)

def test_boolean_type_evasion(vault, standard_blob, password):
    payload = json.loads(standard_blob)
    payload["header"]["kdf"]["ops"] = True
    with pytest.raises(ValueError, match="must be strict integers"):
        vault.decrypt(json.dumps(payload), password)

def test_decrypt_rejects_invalid_type(vault, password):
    with pytest.raises(TypeError, match="must be a string or bytes"):
        vault.decrypt(12345, password)

def test_tag_only_ciphertext_fails(vault, password):
    """Proves a 16-byte (tag-only, empty ciphertext) payload is rejected by AES-GCM."""
    payload = json.loads(vault.encrypt("x", password))
    payload["ciphertext"] = base64.b64encode(b"\x00" * 16).decode('ascii')
    with pytest.raises(DecryptionError, match="Integrity check failed"):
        vault.decrypt(json.dumps(payload), password)

# ==========================================
# 5. Malformed Payloads & Invalid Inputs
# ==========================================
@pytest.mark.parametrize("payload,expected_err", [
    ("not json at all", ValueError),
    ("{}", ValueError),
    (json.dumps({"header": {}, "ciphertext": "abc"}), ValueError),
    (json.dumps({"header": {"v": "1.0", "kdf": "not_a_dict", "salt": "a", "nonce": "b"}, "ciphertext": "abc"}), ValueError),
    (json.dumps({"header": {"v": "9.9", "kdf": {"ops": 3, "mem": 65536, "p": 4}, "salt": "a", "nonce": "b"}, "ciphertext": "abc"}), ValueError),
    (json.dumps({"header": {"v": "2.0", "kdf": {"ops": 3, "mem": 65536, "p": 4, "key_len": 32}, "salt": 12345, "nonce": "b"}, "ciphertext": "abc"}), ValueError),
])
def test_malformed_payloads_raise_value_error(vault, password, payload, expected_err):
    with pytest.raises(expected_err):
        vault.decrypt(payload, password)

@pytest.mark.parametrize("plaintext,passphrase,exc", [
    ("",  "valid-passphrase", ValueError),
    (b"", "valid-passphrase", ValueError),
    ("valid data", "", ValueError),
])
def test_invalid_inputs_rejected(vault, plaintext, passphrase, exc):
    with pytest.raises(exc):
        vault.encrypt(plaintext, passphrase)

def test_binary_data_returns_runtime_error_without_flag(vault, password):
    blob = vault.encrypt(b"\x00\xFF\xDE\xAD", password)
    with pytest.raises(RuntimeError, match="not valid UTF-8"):
        vault.decrypt(blob, password)

# ==========================================
# 6. OOM & Resource Limits
# ==========================================
def test_oversized_payload_rejection_encrypt(vault, password):
    oversized_data = b"\x00" * (SecureVault.MAX_PAYLOAD_SIZE + 1)
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        vault.encrypt(oversized_data, password)

def test_oversized_json_rejected_before_parse_decrypt(vault, password):
    giant_string = "x" * (SecureVault.MAX_JSON_STRING_SIZE + 1)
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        vault.decrypt(giant_string, password)

def test_argon2_memory_error_raises_runtime_error(vault, password):
    """Proves the MemoryError path in Phase 3 surfaces as RuntimeError."""
    blob = vault.encrypt("x", password)
    with patch.object(vault, "_derive_key", side_effect=MemoryError):
        with pytest.raises(RuntimeError, match="Insufficient system memory"):
            vault.decrypt(blob, password)

# ==========================================
# 7. Property-Based Fuzz Testing (Hypothesis)
# ==========================================
# We instantiate SecureVault locally to avoid pytest fixture scoping conflicts with hypothesis.
@given(st.binary(min_size=1, max_size=10000))
@settings(max_examples=100, deadline=None)  # deadline=None: Argon2 exceeds the 200ms default
def test_roundtrip_arbitrary_bytes(data):
    """Fuzzes binary encryption with arbitrary byte arrays including null bytes."""
    vault = SecureVault()
    blob = vault.encrypt(data, "passphrase")
    assert vault.decrypt(blob, "passphrase", return_bytes=True) == data

@given(st.text(min_size=1, max_size=10000, alphabet=st.characters(exclude_categories=("Cs",))))
@settings(max_examples=100, deadline=None)  # deadline=None: Argon2 exceeds the 200ms default
def test_roundtrip_arbitrary_strings(text_data):
    """Fuzzes string encryption with arbitrary unicode and control characters (surrogates excluded).
    st.text() excludes surrogates by default; the alphabet arg makes that contract explicit.
    """
    vault = SecureVault()
    blob = vault.encrypt(text_data, "passphrase")
    assert vault.decrypt(blob, "passphrase") == text_data

def test_surrogate_string_raises_cleanly(vault, password):
    """Proves surrogate characters (U+D800-U+DFFF) fail at encode() before reaching crypto.
    Constructed via chr() at runtime to avoid UnicodeEncodeError in pytest's assertion rewriter.
    """
    surrogate = chr(0xD800)
    with pytest.raises((UnicodeEncodeError, ValueError)):
        vault.encrypt(surrogate, password)
