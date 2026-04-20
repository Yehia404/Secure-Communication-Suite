from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class RSACipher:
    """
    RSA asymmetric encryption module for secure key sharing.
    """
    @staticmethod
    def generate_keys(key_size=2048):
        """Generates an RSA keypair and returns private and public keys as bytes."""
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def encrypt(public_key: bytes, message: bytes) -> bytes:
        """Encrypts a message using a public RSA key."""
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.encrypt(message)
        
    @staticmethod
    def decrypt(private_key: bytes, ciphertext: bytes) -> bytes:
        """Decrypts a ciphertext using a private RSA key."""
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.decrypt(ciphertext)
