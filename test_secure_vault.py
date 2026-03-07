import pytest
import json
import base64
from secure_vault import SecureVault, _generate_mock_v1_blob

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
    """Proves standard UTF-8 string encryption and decryption works."""
    plaintext = "Hello, world! 🌍"
    blob = vault.encrypt(plaintext, password)
    assert vault.decrypt(blob, password) == plaintext

def test_roundtrip_bytes(vault, password):
    """Proves raw binary encryption and decryption works."""
    plaintext = b"\x00\xFF\xDE\xAD\xBE\xEF\x00"
    blob = vault.encrypt(plaintext, password)
    assert vault.decrypt(blob, password, return_bytes=True) == plaintext

def test_legacy_v1_decryption(vault, password):
    """Proves the system can correctly parse and decrypt legacy payloads."""
    legacy_data = b"Legacy data payload"
    blob_v1 = _generate_mock_v1_blob(password, legacy_data)
    assert vault.decrypt(blob_v1, password) == legacy_data.decode('utf-8')

# ==========================================
# 2. Authentication & Integrity (Negative Tests)
# ==========================================
def test_wrong_password_raises_permission_error(vault, standard_blob):
    """Proves incorrect passwords fail cleanly without crashing the parser."""
    with pytest.raises(PermissionError, match="Integrity check failed"):
        vault.decrypt(standard_blob, "wrong-password")

def test_tampered_metadata_fails_aad(vault, standard_blob, password):
    """Proves that modifying an unencrypted JSON field breaks the AAD cryptographic bind."""
    payload = json.loads(standard_blob)
    payload["header"]["kdf"]["ops"] += 1  # Attacker alters derivation cost without touching ciphertext
    tampered_blob = json.dumps(payload)

    with pytest.raises(PermissionError, match="Integrity check failed"):
        vault.decrypt(tampered_blob, password)

def test_tampered_ciphertext_fails_tag(vault, standard_blob, password):
    """Proves that flipping a bit in the ciphertext triggers an InvalidTag."""
    payload = json.loads(standard_blob)
    raw_ct = bytearray(base64.b64decode(payload["ciphertext"]))
    raw_ct[0] ^= 0xFF  # Flip bits in the first byte
    payload["ciphertext"] = base64.b64encode(raw_ct).decode('ascii')

    with pytest.raises(PermissionError, match="Integrity check failed"):
        vault.decrypt(json.dumps(payload), password)

# ==========================================
# 3. Boundary & Type Evasion Enforcement
# ==========================================
@pytest.mark.parametrize("field,value,match", [
    ("ops", 1,      "operations out of acceptable bounds"),
    ("ops", 11,     "operations out of acceptable bounds"),
    ("mem", 16384,  "memory out of acceptable bounds"),
    ("mem", 524288, "memory out of acceptable bounds"),
    ("p",   0,      "parallelism out of acceptable bounds"),
    ("p",   17,     "parallelism out of acceptable bounds"),
    ("key_len", 15, "Invalid key_len: must be 16, 24, or 32"),
])
def test_kdf_boundary_enforcement(vault, standard_blob, password, field, value, match):
    """Proves KDF boundaries strictly prevent Downgrade and DoS attacks."""
    payload = json.loads(standard_blob)
    payload["header"]["kdf"][field] = value
    with pytest.raises(ValueError, match=match):
        vault.decrypt(json.dumps(payload), password)

def test_boolean_type_evasion(vault, standard_blob, password):
    """Proves that `type(x) is int` catches boolean evasions (isinstance(True, int) == True)."""
    payload = json.loads(standard_blob)
    payload["header"]["kdf"]["ops"] = True
    with pytest.raises(ValueError, match="must be strict integers"):
        vault.decrypt(json.dumps(payload), password)

# ==========================================
# 4. Malformed Payloads & Invalid Inputs
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
    """Proves structural JSON defects are caught before cryptographic execution."""
    with pytest.raises(expected_err):
        vault.decrypt(payload, password)

@pytest.mark.parametrize("plaintext,passphrase,exc", [
    ("",  "valid-passphrase", ValueError),
    (b"", "valid-passphrase", ValueError),
    ("valid data", "", ValueError),
])
def test_invalid_inputs_rejected(vault, plaintext, passphrase, exc):
    """Proves empty strings/bytes/passwords are caught at the entry point."""
    with pytest.raises(exc):
        vault.encrypt(plaintext, passphrase)

# ==========================================
# 5. OOM & Resource Limits
# ==========================================
def test_oversized_payload_rejection_encrypt(vault, password):
    """Proves that allocating > MAX_PAYLOAD_SIZE fails gracefully before encryption."""
    oversized_data = b"\x00" * (SecureVault.MAX_PAYLOAD_SIZE + 1)
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        vault.encrypt(oversized_data, password)

def test_oversized_json_rejected_before_parse_decrypt(vault, password):
    """Proves that giant JSON strings are rejected BEFORE json.loads builds the AST in memory."""
    giant_string = "x" * (SecureVault.MAX_JSON_STRING_SIZE + 1)
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        vault.decrypt(giant_string, password)
