from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from security_logger import SecurityLogger, SecurityEvent

class AESCipher:
    """
    AES encryption module using EAX mode.
    """
    def __init__(self, key: bytes = None):
        if key is None:
            self.key = get_random_bytes(16)  # Auto-generate 128-bit key
        else:
            if len(key) not in [16, 24, 32]:  # AES-128/192/256
                raise ValueError("Key must be 16, 24, or 32 bytes")
            self.key = key
            
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts plaintext using AES-EAX mode.
        Returns a byte string containing nonce, tag, and ciphertext.
        """
        cipher = AES.new(self.key, AES.MODE_EAX)  # Create EAX cipher with random nonce
        nonce = cipher.nonce  # 16-byte random nonce
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)  # Encrypt + compute auth tag
        result = nonce + tag + ciphertext  # Wire format: [nonce|tag|ciphertext]

        # Log encryption event
        logger = SecurityLogger()
        logger.log(SecurityEvent(
            event_type="AES-ENC",
            module="Block Cipher",
            description=f"Encrypted {len(plaintext)} bytes -> {len(result)} bytes (AES-128-EAX)",
            raw_data=result.hex(),
            details={
                "algorithm": "AES-128-EAX",
                "plaintext_size": len(plaintext),
                "nonce": nonce.hex(),
                "nonce_size": f"{len(nonce)} bytes",
                "tag": tag.hex(),
                "tag_size": f"{len(tag)} bytes",
                "ciphertext": ciphertext.hex(),
                "ciphertext_size": f"{len(ciphertext)} bytes",
                "total_output": f"{len(result)} bytes",
                "wire_format": f"[Nonce {len(nonce)}B] + [Tag {len(tag)}B] + [Ciphertext {len(ciphertext)}B]"
            }
        ))
        
        # Prepend the nonce and tag to the ciphertext
        return result
        
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypts data that was encrypted using the `encrypt` method.
        """
        # Extract nonce, tag, and ciphertext from wire format
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt + verify integrity

        # Log decryption event
        logger = SecurityLogger()
        logger.log(SecurityEvent(
            event_type="AES-DEC",
            module="Block Cipher",
            description=f"Decrypted {len(encrypted_data)} bytes -> {len(plaintext)} bytes (Tag verified OK)",
            raw_data=encrypted_data.hex(),
            details={
                "algorithm": "AES-128-EAX",
                "input_size": f"{len(encrypted_data)} bytes",
                "nonce": nonce.hex(),
                "tag": tag.hex(),
                "tag_verified": "PASSED - Integrity confirmed",
                "plaintext_size": f"{len(plaintext)} bytes",
            }
        ))

        return plaintext
