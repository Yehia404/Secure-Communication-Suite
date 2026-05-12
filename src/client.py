import socket
import threading
from auth.key_management import KeyManager
from crypto.public_key import RSACipher
from crypto.block_cipher import AESCipher
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from security_logger import SecurityLogger, SecurityEvent

class SecureClient:
    def __init__(self, host='127.0.0.1', port=65432):
        self.host = host
        self.port = port
        self.socket = None
        self.aes_cipher = None
        self.connected = False
        self.username = None
        self.logger = SecurityLogger()
        
    def connect_and_auth(self, action, username, password):
        try:
            self.logger.clear()  # Reset logs for new session

            # Open TCP connection to server
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # --- Step 1: Authentication Pulse ---
            msg = f"{action}||{username}||{password}"
            self.socket.send(msg.encode())
            self.logger.log_handshake(1, "Authentication Pulse",
                f"Sent {action} request for '{username}' over TCP socket",
                details={
                    "action": action,
                    "username": username,
                    "protocol": "TCP",
                    "server": f"{self.host}:{self.port}",
                    "format": f"{action}||username||password",
                })
            
            # Wait for server auth response
            res = self.socket.recv(1024).decode()
            if res == "DUP":
                self.socket.close()
                self.logger.log(SecurityEvent("AUTH-REJECT", "Protocol", 
                    f"Server rejected: '{username}' already logged in (duplicate session)"))
                return False, "User is already logged in from another session."
            if res != "OK":
                self.socket.close()
                if action == "LOGIN":
                    fail_msg = "Incorrect username or password."
                else:
                    fail_msg = "Username already exists."
                self.logger.log(SecurityEvent("AUTH-REJECT", "Protocol", 
                    f"Server rejected {action} for '{username}': {fail_msg}"))
                return False, fail_msg

            self.logger.log(SecurityEvent("AUTH-OK", "Protocol", 
                f"Server accepted {action} for '{username}' ✅"))
                
            # --- Step 2: Asymmetric Key Provisioning ---
            # Receive server's RSA-2048 public key
            server_pub_key = self.socket.recv(2048)
            KeyManager.save_partner_key("server", server_pub_key)  # Persist for future sessions
            
            pub_fingerprint = SHA256.new(server_pub_key).hexdigest()[:16]
            self.logger.log_handshake(2, "RSA Public Key Received",
                f"Server sent its RSA-2048 public key ({len(server_pub_key)} bytes)",
                details={
                    "key_size": f"{len(server_pub_key)} bytes",
                    "key_fingerprint": pub_fingerprint,
                    "algorithm": "RSA-2048",
                    "stored_as": "server_public.pem",
                })
            
            # --- Step 3: AES Session Key Generation ---
            # Generate random AES-128 session key from OS CSPRNG
            aes_key = get_random_bytes(16)
            
            self.logger.log_handshake(3, "AES Session Key Generated",
                f"Generated random 16-byte AES-128 session key",
                details={
                    "key_hex": aes_key.hex(),
                    "key_size": "128 bits (16 bytes)",
                    "algorithm": "AES-128-EAX",
                    "source": "OS CSPRNG (Crypto.Random)",
                })

            # Store session info for dashboard
            self.logger.set_session_info("aes_key", aes_key.hex())
            self.logger.set_session_info("aes_algorithm", "AES-128-EAX")
            self.logger.set_session_info("rsa_algorithm", "RSA-2048-OAEP")
            self.logger.set_session_info("hash_algorithm", "SHA-256")
            self.logger.set_session_info("server_key_fingerprint", pub_fingerprint)
            self.logger.set_session_info("cipher_suite", "AES-128-EAX + RSA-2048-OAEP + SHA-256")
            self.logger.set_session_info("username", username)
            self.logger.set_session_info("server", f"{self.host}:{self.port}")
            
            # --- Step 4: Encrypted Key Upload ---
            # Encrypt AES key with server's RSA public key and send
            encrypted_aes_key = RSACipher.encrypt(server_pub_key, aes_key)
            self.socket.send(encrypted_aes_key)
            
            self.logger.log_handshake(4, "Encrypted Key Exchange",
                f"AES key encrypted with RSA-OAEP and sent to server ({len(encrypted_aes_key)} bytes)",
                details={
                    "encryption": "RSA-2048-OAEP",
                    "plaintext_size": "16 bytes (AES key)",
                    "ciphertext_size": f"{len(encrypted_aes_key)} bytes",
                    "status": "AES session key securely delivered to server",
                })
            
            # Wait for server confirmation that session is ready
            ready = self.socket.recv(1024)
            if ready == b"READY":
                self.aes_cipher = AESCipher(aes_key)  # Create cipher for this session
                self.connected = True
                self.username = username
                
                self.logger.log(SecurityEvent("SESSION-READY", "Protocol",
                    "🔒 Secure session established — all traffic now AES-128-EAX encrypted",
                    details={
                        "cipher_suite": "AES-128-EAX + RSA-2048-OAEP + SHA-256",
                        "session_key": aes_key.hex()[:8] + "••••••••" + aes_key.hex()[-8:],
                    }
                ))
                
                return True, "Successfully authenticated and established secure session."
            
            return False, "Failed to establish secure session."
        except Exception as e:
            if self.socket:
                self.socket.close()
            return False, f"Connection error: {e}"
        
    def send_message(self, message: str) -> bool:
        """Encrypt and send a message over the secure channel."""
        if not self.connected:
            return False
        try:
            encrypted = self.aes_cipher.encrypt(message.encode())  # AES-EAX encrypt
            self.socket.send(encrypted)
            return True
        except:
            self.connected = False
            return False
            
    def receive_message(self) -> str:
        """Receive and decrypt a message from the secure channel."""
        if not self.connected:
            return None
        try:
            encrypted = self.socket.recv(4096)
            if not encrypted:  # Connection closed
                self.connected = False
                return None
            plaintext = self.aes_cipher.decrypt(encrypted)  # AES-EAX decrypt + verify tag
            return plaintext.decode()
        except:
            self.connected = False
            return None
            
    def close(self):
        """Tear down the connection."""
        if self.socket:
            self.socket.close()
        self.connected = False
