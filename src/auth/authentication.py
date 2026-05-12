from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from security_logger import SecurityLogger, SecurityEvent
import json
import os

class AuthManager:
    """Implement password-based authentication mechanisms."""
    def __init__(self, db_path="users.json"):
        self.db_path = db_path
        self._load_users()  # Load existing users from JSON on startup
        
    def _load_users(self):
        # Read user database from disk, or create empty one if missing
        if not os.path.exists(self.db_path):
            self.users = {}
            self._save_users()
        else:
            with open(self.db_path, "r") as f:
                self.users = json.load(f)
                
    def _save_users(self):
        # Persist current user dict to JSON file
        with open(self.db_path, "w") as f:
            json.dump(self.users, f)
            
    def _hash_password(self, password: str, salt: str) -> str:
        # Concatenate password + salt, then compute SHA-256 digest
        h = SHA256.new()
        h.update((password + salt).encode('utf-8'))
        return h.hexdigest()
        
    def register(self, username: str, password: str) -> bool:
        # Reject duplicate usernames
        if username in self.users:
            return False

        salt = get_random_bytes(16).hex()  # Generate 16-byte random salt
        hashed = self._hash_password(password, salt)  # Hash password with salt
        self.users[username] = {"salt": salt, "hash": hashed}  # Store credentials
        self._save_users()  # Write to disk

        # Log registration event
        logger = SecurityLogger()
        logger.log(SecurityEvent(
            event_type="AUTH-REGISTER",
            module="Authentication",
            description=f"New user '{username}' registered (password salted + hashed)",
            details={
                "username": username,
                "salt": salt,
                "hash_algorithm": "SHA-256",
                "password_hash": hashed[:16] + "…",
                "storage": self.db_path,
                "process": "password + salt → SHA-256 → stored in users.json",
            }
        ))

        return True
        
    def authenticate(self, username: str, password: str) -> bool:
        # Check if user exists
        if username not in self.users:
            logger = SecurityLogger()
            logger.log(SecurityEvent(
                event_type="AUTH-FAIL",
                module="Authentication",
                description=f"Authentication failed — user '{username}' not found",
                details={"username": username, "reason": "User not found"}
            ))
            return False

        user_data = self.users[username]
        hashed = self._hash_password(password, user_data["salt"])  # Recompute hash
        success = hashed == user_data["hash"]  # Compare with stored hash

        # Log authentication attempt
        logger = SecurityLogger()
        logger.log(SecurityEvent(
            event_type="AUTH-LOGIN" if success else "AUTH-FAIL",
            module="Authentication",
            description=f"Login {'succeeded' if success else 'failed'} for '{username}'",
            details={
                "username": username,
                "salt_used": user_data["salt"],
                "hash_algorithm": "SHA-256",
                "computed_hash": hashed[:16] + "…",
                "stored_hash": user_data["hash"][:16] + "…",
                "match": "Match" if success else "Mismatch",
                "process": "password + salt → SHA-256 → compare with stored hash",
            }
        ))

        return success
