import socket
import threading
from auth.authentication import AuthManager
from auth.key_management import KeyManager
from crypto.public_key import RSACipher
from crypto.block_cipher import AESCipher

class SecureServer:
    def __init__(self, host='127.0.0.1', port=65432):
        self.host = host
        self.port = port
        self.auth = AuthManager()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Allow port reuse
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        
        # Server's keypair for RSA
        self.priv_key, self.pub_key = KeyManager.get_or_create_keys("server")
        self.clients = {} # {socket: username}
        self.broadcast_ciphers = {} # {socket: AESCipher}
        
    def start(self):
        self.server_socket.listen()
        print(f"[*] Server listening on {self.host}:{self.port}")
        try:
            while True:
                conn, addr = self.server_socket.accept()
                thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                thread.start()
        except KeyboardInterrupt:
            print("[*] Server shutting down")
            self.server_socket.close()
            
    def broadcast(self, message_bytes: bytes, sender_conn):
        # Broadcast message to all connected clients
        for client_conn, cipher in self.broadcast_ciphers.items():
            if client_conn != sender_conn:
                try:
                    encrypted = cipher.encrypt(message_bytes)
                    client_conn.send(encrypted)
                except Exception as e:
                    print(f"[-] Broadcast error: {e}")

    def handle_client(self, conn, addr):
        print(f"[*] Connection accepted from {addr}")
        try:
            # 1. Authentication
            auth_msg = conn.recv(1024).decode()
            action, username, password = auth_msg.split('||')
            
            if action == 'REGISTER':
                success = self.auth.register(username, password)
                conn.send(b"OK" if success else b"ERR")
                if not success: return
            elif action == 'LOGIN':
                if username in self.clients.values():
                    conn.send(b"DUP")
                    return
                success = self.auth.authenticate(username, password)
                conn.send(b"OK" if success else b"ERR")
                if not success: return
            else:
                conn.send(b"ERR")
                return
            
            # 2. Key Exchange
            conn.send(self.pub_key) # Send server public key
            encrypted_aes_key = conn.recv(1024)
            aes_key = RSACipher.decrypt(self.priv_key, encrypted_aes_key)
            
            cipher = AESCipher(aes_key)
            
            self.clients[conn] = username
            self.broadcast_ciphers[conn] = cipher
            print(f"[*] User {username} securely connected with AES session key.")
            conn.send(b"READY")
            
            # Announce connection 
            self.broadcast(f"[SERVER] {username} joined the secure chat!".encode(), conn)
            
            # 3. Secure Communication Loop
            while True:
                encrypted_data = conn.recv(4096)
                if not encrypted_data:
                    break
                
                plaintext = cipher.decrypt(encrypted_data)
                print(f"[{username}] {plaintext.decode()}")
                
                formatted_msg = f"[{username}]: {plaintext.decode()}".encode()
                self.broadcast(formatted_msg, conn)
                
        except Exception as e:
            print(f"[-] Error handling {addr}: {e}")
        finally:
            username = self.clients.get(conn, "Unknown")
            if conn in self.clients:
                del self.clients[conn]
            if conn in self.broadcast_ciphers:
                del self.broadcast_ciphers[conn]
            conn.close()
            print(f"[*] Connection closed for {addr}")
            self.broadcast(f"[SERVER] {username} left.".encode(), None)

if __name__ == '__main__':
    server = SecureServer()
    server.start()
