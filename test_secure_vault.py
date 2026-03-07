import pytest
import json
from secure_vault import SecureVault

@pytest.fixture
def vault():
    return SecureVault()

@pytest.fixture
def standard_blob(vault):
    return vault.encrypt("Secret Plaintext", "correct-horse-battery-staple")

def test_tampered_metadata_fails_aad(vault, standard_blob):
    """Proves that modifying an unencrypted JSON field breaks the AAD cryptographic bind."""
    payload = json.loads(standard_blob)
    payload["header"]["kdf"]["ops"] += 1  # Attacker alters derivation cost
    tampered_blob = json.dumps(payload)
    
    with pytest.raises(PermissionError, match="Integrity check failed"):
        vault.decrypt(tampered_blob, "correct-horse-battery-staple")

def test_kdf_downgrade_attack_blocked(vault, standard_blob):
    """Proves that the system actively rejects maliciously weakened parameters."""
    payload = json.loads(standard_blob)
    payload["header"]["kdf"]["ops"] = 1  # Below MIN_KDF_OPS
    tampered_blob = json.dumps(payload)
    
    with pytest.raises(ValueError, match="operations out of acceptable bounds"):
        vault.decrypt(tampered_blob, "correct-horse-battery-staple")

def test_boolean_type_evasion(vault, standard_blob):
    """Proves that `type(x) is int` catches boolean evasions."""
    payload = json.loads(standard_blob)
    payload["header"]["kdf"]["ops"] = True 
    tampered_blob = json.dumps(payload)
    
    with pytest.raises(ValueError, match="must be strict integers"):
        vault.decrypt(tampered_blob, "correct-horse-battery-staple")

def test_oversized_payload_rejection(vault):
    """Proves that allocating > 100MB fails gracefully before OOM occurs."""
    oversized_data = b"\x00" * (SecureVault.MAX_PAYLOAD_SIZE + 1)
    
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        vault.encrypt(oversized_data, "correct-horse-battery-staple")