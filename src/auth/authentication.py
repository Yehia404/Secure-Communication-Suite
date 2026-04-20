from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import json
import os

class AuthManager:
    """Implement password-based authentication mechanisms."""
    def __init__(self, db_path="users.json"):
        self.db_path = db_path
        self._load_users()
        
    def _load_users(self):
        if not os.path.exists(self.db_path):
            self.users = {}
            self._save_users()
        else:
            with open(self.db_path, "r") as f:
                self.users = json.load(f)
                
    def _save_users(self):
        with open(self.db_path, "w") as f:
            json.dump(self.users, f)
            
    def _hash_password(self, password: str, salt: str) -> str:
        h = SHA256.new()
        h.update((password + salt).encode('utf-8'))
        return h.hexdigest()
        
    def register(self, username: str, password: str) -> bool:
        if username in self.users:
            return False
            
        salt = get_random_bytes(16).hex()
        hashed = self._hash_password(password, salt)
        self.users[username] = {"salt": salt, "hash": hashed}
        self._save_users()
        return True
        
    def authenticate(self, username: str, password: str) -> bool:
        if username not in self.users:
            return False
            
        user_data = self.users[username]
        hashed = self._hash_password(password, user_data["salt"])
        return hashed == user_data["hash"]
