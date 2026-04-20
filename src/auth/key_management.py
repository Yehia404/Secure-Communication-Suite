import os
from crypto.public_key import RSACipher

class KeyManager:
    """Secure methods for key generation, distribution, and storage."""
    
    @staticmethod
    def get_or_create_keys(user_id: str, key_dir="keys"):
        if not os.path.exists(key_dir):
            os.makedirs(key_dir)
            
        priv_path = os.path.join(key_dir, f"{user_id}_private.pem")
        pub_path = os.path.join(key_dir, f"{user_id}_public.pem")
        
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            with open(priv_path, "rb") as f:
                priv = f.read()
            with open(pub_path, "rb") as f:
                pub = f.read()
            return priv, pub
            
        priv, pub = RSACipher.generate_keys()
        
        with open(priv_path, "wb") as f:
            f.write(priv)
        with open(pub_path, "wb") as f:
            f.write(pub)
            
        return priv, pub

    @staticmethod
    def save_partner_key(partner_id: str, pub_key: bytes, key_dir="keys"):
        if not os.path.exists(key_dir):
            os.makedirs(key_dir)
        path = os.path.join(key_dir, f"{partner_id}_public.pem")
        with open(path, "wb") as f:
            f.write(pub_key)
            
    @staticmethod
    def load_partner_key(partner_id: str, key_dir="keys") -> bytes:
        path = os.path.join(key_dir, f"{partner_id}_public.pem")
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            return f.read()
