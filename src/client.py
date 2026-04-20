import socket
import threading
from auth.key_management import KeyManager
from crypto.public_key import RSACipher
from crypto.block_cipher import AESCipher
from Crypto.Random import get_random_bytes

class SecureClient:
    def __init__(self, host='127.0.0.1', port=65432):
        self.host = host
        self.port = port
        self.socket = None
        self.aes_cipher = None
        self.connected = False
        self.username = None
        
    def connect_and_auth(self, action, username, password):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # 1. Auth Phase
            msg = f"{action}||{username}||{password}"
            self.socket.send(msg.encode())
            res = self.socket.recv(1024).decode()
            if res == "DUP":
                self.socket.close()
                return False, "User is already logged in from another session."
            if res != "OK":
                self.socket.close()
                return False, "Authentication failed. Incorrect username or password, or username already exists."
                
            # 2. Key Exchange Phase
            server_pub_key = self.socket.recv(2048)
            KeyManager.save_partner_key("server", server_pub_key)
            
            # Generate random AES session key (16 bytes)
            aes_key = get_random_bytes(16)
            encrypted_aes_key = RSACipher.encrypt(server_pub_key, aes_key)
            self.socket.send(encrypted_aes_key)
            
            ready = self.socket.recv(1024)
            if ready == b"READY":
                self.aes_cipher = AESCipher(aes_key)
                self.connected = True
                self.username = username
                return True, "Successfully authenticated and established secure session."
            
            return False, "Failed to establish secure session."
        except Exception as e:
            if self.socket:
                self.socket.close()
            return False, f"Connection error: {e}"
        
    def send_message(self, message: str) -> bool:
        if not self.connected:
            return False
        try:
            encrypted = self.aes_cipher.encrypt(message.encode())
            self.socket.send(encrypted)
            return True
        except:
            self.connected = False
            return False
            
    def receive_message(self) -> str:
        if not self.connected:
            return None
        try:
            encrypted = self.socket.recv(4096)
            if not encrypted:
                self.connected = False
                return None
            plaintext = self.aes_cipher.decrypt(encrypted)
            return plaintext.decode()
        except:
            self.connected = False
            return None
            
    def close(self):
        if self.socket:
            self.socket.close()
        self.connected = False
