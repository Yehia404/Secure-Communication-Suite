from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class AESCipher:
    """
    AES encryption module using EAX mode.
    """
    def __init__(self, key: bytes = None):
        if key is None:
            self.key = get_random_bytes(16) # 16 bytes for AES-128
        else:
            if len(key) not in [16, 24, 32]:
                raise ValueError("Key must be 16, 24, or 32 bytes")
            self.key = key
            
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts plaintext using AES-EAX mode.
        Returns a byte string containing nonce, tag, and ciphertext.
        """
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        # Prepend the nonce and tag to the ciphertext
        return nonce + tag + ciphertext
        
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypts data that was encrypted using the `encrypt` method.
        """
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
