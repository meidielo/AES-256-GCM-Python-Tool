import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag

class SecureVault:
    def __init__(self):
        # Argon2id parameters (High Security)
        # These follow OWASP recommendations for key derivation
        self.kdf_ops = 3            # Iterations (time_cost)
        self.kdf_mem = 65536        # 64MB RAM (memory_cost)
        self.kdf_parallel = 4       # Parallelism (threads)
        self.key_len = 32           # 256-bit key for AES-256

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        """Derives a 256-bit key using Argon2id."""
        kdf = Argon2id(
            length=self.key_len,
            iterations=self.kdf_ops,
            memory_cost=self.kdf_mem,
            parallelism=self.kdf_parallel,
            salt=salt,
        )
        return kdf.derive(passphrase.encode())

    def encrypt(self, plaintext: str, passphrase: str) -> str:
        """Encrypts data and returns a structured JSON object (Base64)."""
        # 1. Generate unique 16-byte salt and 12-byte nonce (NIST Standard)
        salt = os.urandom(16)
        nonce = os.urandom(12)
        
        # 2. Derive key from passphrase
        key = self._derive_key(passphrase, salt)
        
        # 3. Encrypt using AES-GCM
        aesgcm = AESGCM(key)
        # encrypt() returns: ciphertext + 16-byte auth tag
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode(), None)
        
        # 4. Construct transport object
        payload = {
            "v": "1.0",
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext_with_tag).decode('utf-8')
        }
        
        return json.dumps(payload)

    def decrypt(self, encrypted_json: str, passphrase: str) -> str:
        """Decrypts the JSON payload and validates integrity."""
        try:
            payload = json.loads(encrypted_json)
            
            # Extract and decode components
            salt = base64.b64decode(payload['salt'])
            nonce = base64.b64decode(payload['nonce'])
            ciphertext_with_tag = base64.b64decode(payload['ciphertext'])
            
            # 1. Re-derive the key using the same salt
            key = self._derive_key(passphrase, salt)
            
            # 2. Decrypt and verify tag
            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            
            return decrypted_data.decode('utf-8')
            
        except InvalidTag:
            raise PermissionError("Decryption failed: Integrity check failed or incorrect password.")
        except Exception as e:
            raise ValueError(f"Decryption failed: Malformed payload or system error. {e}")

# --- Example Usage ---
if __name__ == "__main__":
    vault = SecureVault()
    secret_data = "Sensitive User Information: API_KEY_12345"
    password = "a-very-strong-and-unique-passphrase"

    # Encryption
    encrypted_packet = vault.encrypt(secret_data, password)
    print(f"Encrypted Payload (JSON):\n{encrypted_packet}\n")

    # Decryption
    try:
        decrypted_text = vault.decrypt(encrypted_packet, password)
        print(f"Decrypted Result: {decrypted_text}")
    except PermissionError as e:
        print(e)