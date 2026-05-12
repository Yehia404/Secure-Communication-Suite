from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from security_logger import SecurityLogger, SecurityEvent

class RSACipher:
    """
    RSA asymmetric encryption module for secure key sharing.
    """
    @staticmethod
    def generate_keys(key_size=2048):
        """Generates an RSA keypair and returns private and public keys as bytes."""
        key = RSA.generate(key_size)  # Generate RSA keypair
        private_key = key.export_key()  # Export private key as PEM bytes
        public_key = key.publickey().export_key()  # Export public key as PEM bytes

        # Log key generation event
        logger = SecurityLogger()
        pub_fingerprint = SHA256.new(public_key).hexdigest()[:16]
        logger.log(SecurityEvent(
            event_type="RSA-KEYGEN",
            module="Public Key",
            description=f"Generated RSA-{key_size} keypair (fingerprint: {pub_fingerprint}…)",
            details={
                "algorithm": f"RSA-{key_size}",
                "public_key_fingerprint": pub_fingerprint,
                "private_key_size": f"{len(private_key)} bytes",
                "public_key_size": f"{len(public_key)} bytes",
            }
        ))

        return private_key, public_key

    @staticmethod
    def encrypt(public_key: bytes, message: bytes) -> bytes:
        """Encrypts a message using a public RSA key."""
        rsa_key = RSA.import_key(public_key)  # Import PEM-encoded public key
        cipher = PKCS1_OAEP.new(rsa_key)  # Create OAEP cipher with SHA-1 MGF
        result = cipher.encrypt(message)  # Encrypt plaintext (max 190 bytes for 2048-bit key)

        # Log RSA encryption event
        logger = SecurityLogger()
        pub_fingerprint = SHA256.new(public_key).hexdigest()[:16]
        logger.log(SecurityEvent(
            event_type="RSA-ENC",
            module="Public Key",
            description=f"RSA-OAEP encrypted {len(message)} bytes → {len(result)} bytes",
            raw_data=result.hex()[:64] + "…",
            details={
                "algorithm": "RSA-2048-OAEP",
                "padding": "PKCS1_OAEP",
                "input_size": f"{len(message)} bytes",
                "output_size": f"{len(result)} bytes",
                "public_key_fingerprint": pub_fingerprint,
            }
        ))

        return result
        
    @staticmethod
    def decrypt(private_key: bytes, ciphertext: bytes) -> bytes:
        """Decrypts a ciphertext using a private RSA key."""
        rsa_key = RSA.import_key(private_key)  # Import PEM-encoded private key
        cipher = PKCS1_OAEP.new(rsa_key)  # Create OAEP cipher for decryption
        result = cipher.decrypt(ciphertext)  # Decrypt and remove OAEP padding

        # Log RSA decryption event
        logger = SecurityLogger()
        logger.log(SecurityEvent(
            event_type="RSA-DEC",
            module="Public Key",
            description=f"RSA-OAEP decrypted {len(ciphertext)} bytes → {len(result)} bytes",
            details={
                "algorithm": "RSA-2048-OAEP",
                "padding": "PKCS1_OAEP",
                "input_size": f"{len(ciphertext)} bytes",
                "output_size": f"{len(result)} bytes",
            }
        ))

        return result
