import os
from crypto.public_key import RSACipher
from security_logger import SecurityLogger, SecurityEvent
from Crypto.Hash import SHA256

class KeyManager:
    """Secure methods for key generation, distribution, and storage."""
    
    @staticmethod
    def get_or_create_keys(user_id: str, key_dir="keys"):
        # Ensure key storage directory exists
        if not os.path.exists(key_dir):
            os.makedirs(key_dir)
            
        priv_path = os.path.join(key_dir, f"{user_id}_private.pem")
        pub_path = os.path.join(key_dir, f"{user_id}_public.pem")
        
        logger = SecurityLogger()

        # If keys already exist on disk, load and return them
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            with open(priv_path, "rb") as f:
                priv = f.read()
            with open(pub_path, "rb") as f:
                pub = f.read()

            fingerprint = SHA256.new(pub).hexdigest()[:16]
            logger.log(SecurityEvent(
                event_type="KEY-LOAD",
                module="Key Manager",
                description=f"Loaded existing RSA keypair for '{user_id}' from disk",
                details={
                    "user_id": user_id,
                    "private_key_path": priv_path,
                    "public_key_path": pub_path,
                    "public_key_fingerprint": fingerprint,
                }
            ))

            return priv, pub
            
        # Generate a fresh RSA-2048 keypair and persist to PEM files
        priv, pub = RSACipher.generate_keys()

        with open(priv_path, "wb") as f:
            f.write(priv)
        with open(pub_path, "wb") as f:
            f.write(pub)

        fingerprint = SHA256.new(pub).hexdigest()[:16]
        logger.log(SecurityEvent(
            event_type="KEY-GEN",
            module="Key Manager",
            description=f"Generated & saved new RSA-2048 keypair for '{user_id}'",
            details={
                "user_id": user_id,
                "private_key_path": priv_path,
                "public_key_path": pub_path,
                "public_key_fingerprint": fingerprint,
                "key_size": "2048 bits",
            }
        ))
            
        return priv, pub

    @staticmethod
    def save_partner_key(partner_id: str, pub_key: bytes, key_dir="keys"):
        # Save a received partner's public key to disk for future use
        if not os.path.exists(key_dir):
            os.makedirs(key_dir)
        path = os.path.join(key_dir, f"{partner_id}_public.pem")
        with open(path, "wb") as f:
            f.write(pub_key)

        logger = SecurityLogger()
        fingerprint = SHA256.new(pub_key).hexdigest()[:16]
        logger.log(SecurityEvent(
            event_type="KEY-SAVE",
            module="Key Manager",
            description=f"Saved partner '{partner_id}' public key to disk",
            details={
                "partner_id": partner_id,
                "path": path,
                "public_key_fingerprint": fingerprint,
            }
        ))
            
    @staticmethod
    def load_partner_key(partner_id: str, key_dir="keys") -> bytes:
        # Load a previously saved partner's public key from disk
        path = os.path.join(key_dir, f"{partner_id}_public.pem")
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            key_data = f.read()

        logger = SecurityLogger()
        fingerprint = SHA256.new(key_data).hexdigest()[:16]
        logger.log(SecurityEvent(
            event_type="KEY-LOAD",
            module="Key Manager",
            description=f"Loaded partner '{partner_id}' public key from disk",
            details={
                "partner_id": partner_id,
                "path": path,
                "public_key_fingerprint": fingerprint,
            }
        ))

        return key_data
