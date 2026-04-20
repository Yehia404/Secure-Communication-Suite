import threading
import customtkinter as ctk
import tkinter.messagebox as messagebox
from client import SecureClient
from crypto.hashing import DeepHash

# Set up the appearance
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class SecureApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Communication Suite")
        self.geometry("900x600")
        
        self.client = SecureClient()
        self.receive_thread = None
        self.running = True
        
        # Grid config
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        self.show_auth_frame()
        
    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_auth_frame(self):
        self.clear_window()
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        auth_frame = ctk.CTkFrame(self, corner_radius=15)
        auth_frame.place(relx=0.5, rely=0.5, anchor=ctk.CENTER)
        
        title = ctk.CTkLabel(auth_frame, text="Secure Login", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(pady=(20, 10), padx=40)
        
        self.username_entry = ctk.CTkEntry(auth_frame, placeholder_text="Username", width=200)
        self.username_entry.pack(pady=10, padx=40)
        
        self.password_entry = ctk.CTkEntry(auth_frame, placeholder_text="Password", show="*", width=200)
        self.password_entry.pack(pady=10, padx=40)
        
        btn_frame = ctk.CTkFrame(auth_frame, fg_color="transparent")
        btn_frame.pack(pady=(10, 20))
        
        login_btn = ctk.CTkButton(btn_frame, text="Login", width=90, command=lambda: self.authenticate("LOGIN"))
        login_btn.pack(side="left", padx=5)
        
        register_btn = ctk.CTkButton(btn_frame, text="Register", width=90, command=lambda: self.authenticate("REGISTER"))
        register_btn.pack(side="right", padx=5)

    def authenticate(self, action):
        user = self.username_entry.get()
        pwd = self.password_entry.get()
        
        if not user or not pwd:
            messagebox.showwarning("Input Error", "Please provide both username and password")
            return
            
        success, msg = self.client.connect_and_auth(action, user, pwd)
        if success:
            self.show_main_interface()
            self.start_receiving()
        else:
            messagebox.showerror("Auth Error", msg)

    def show_main_interface(self):
        self.clear_window()
        
        # Setup sidebar layout
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)
        
        logo_label = ctk.CTkLabel(self.sidebar_frame, text="Suite Options", font=ctk.CTkFont(size=20, weight="bold"))
        logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        chat_btn = ctk.CTkButton(self.sidebar_frame, text="Secure Chat", command=self.show_chat_view)
        chat_btn.grid(row=1, column=0, padx=20, pady=10)
        
        hash_btn = ctk.CTkButton(self.sidebar_frame, text="Data Integrity", command=self.show_hash_view)
        hash_btn.grid(row=2, column=0, padx=20, pady=10)
        
        logout_btn = ctk.CTkButton(self.sidebar_frame, text="Disconnect", command=self.disconnect)
        logout_btn.grid(row=5, column=0, padx=20, pady=20)
        
        self.content_frame = ctk.CTkFrame(self, corner_radius=10)
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.grid_columnconfigure(1, weight=1)
        
        self.show_chat_view()

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def show_chat_view(self):
        self.clear_content()
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)
        
        self.chat_display = ctk.CTkTextbox(self.content_frame, state="disabled")
        self.chat_display.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        
        self.msg_entry = ctk.CTkEntry(self.content_frame, placeholder_text="Type a secure message...")
        self.msg_entry.grid(row=1, column=0, padx=(10, 5), pady=10, sticky="ew")
        self.msg_entry.bind("<Return>", lambda event: self.send_message())
        
        send_btn = ctk.CTkButton(self.content_frame, text="Send", width=80, command=self.send_message)
        send_btn.grid(row=1, column=1, padx=(5, 10), pady=10)

    def show_hash_view(self):
        self.clear_content()
        title = ctk.CTkLabel(self.content_frame, text="Crypto Tools (Hash & AES)", font=ctk.CTkFont(size=18, weight="bold"))
        title.pack(pady=(10, 5))
        
        # 1. Hashing
        hash_frame = ctk.CTkFrame(self.content_frame)
        hash_frame.pack(fill="x", padx=20, pady=5)
        
        ctk.CTkLabel(hash_frame, text="SHA-256 Integrity Verifier").pack(pady=5)
        self.hash_input = ctk.CTkEntry(hash_frame, placeholder_text="Message to hash...", width=350)
        self.hash_input.pack(padx=10, pady=5)
        
        ctk.CTkButton(hash_frame, text="Compute Digest", command=self.compute_hash).pack(pady=5)
        
        self.hash_result = ctk.CTkEntry(hash_frame, width=350)
        self.hash_result.pack(padx=10, pady=10)
        self.hash_result.insert(0, "Hash result will appear here")
        self.hash_result.configure(state="disabled")

        # 2. Manual AES Encrypt/Decrypt
        aes_frame = ctk.CTkFrame(self.content_frame)
        aes_frame.pack(fill="x", padx=20, pady=(15, 5))
        
        ctk.CTkLabel(aes_frame, text="AES Block Cipher Tool (Produces HEX)").pack(pady=5)
        
        self.aes_plain_input = ctk.CTkEntry(aes_frame, placeholder_text="Type plain text here...", width=350)
        self.aes_plain_input.pack(padx=10, pady=5)
        
        btn_frame = ctk.CTkFrame(aes_frame, fg_color="transparent")
        btn_frame.pack(pady=5)
        
        ctk.CTkButton(btn_frame, text="↓ Encrypt ↓", width=100, command=self.manual_encrypt).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="↑ Decrypt ↑", width=100, command=self.manual_decrypt).pack(side="left", padx=5)
        
        self.aes_cipher_input = ctk.CTkEntry(aes_frame, placeholder_text="Type encrypted HEX here...", width=350)
        self.aes_cipher_input.pack(padx=10, pady=10)

    def manual_encrypt(self):
        text = self.aes_plain_input.get()
        if text and self.client.aes_cipher:
            encrypted_bytes = self.client.aes_cipher.encrypt(text.encode('utf-8'))
            self.aes_cipher_input.delete(0, "end")
            self.aes_cipher_input.insert(0, encrypted_bytes.hex())
            
    def manual_decrypt(self):
        hex_text = self.aes_cipher_input.get()
        if hex_text and self.client.aes_cipher:
            try:
                encrypted_bytes = bytes.fromhex(hex_text)
                plaintext = self.client.aes_cipher.decrypt(encrypted_bytes).decode('utf-8')
                self.aes_plain_input.delete(0, "end")
                self.aes_plain_input.insert(0, plaintext)
            except Exception as e:
                messagebox.showerror("Decrypt Error", f"Failed to decrypt or altered data detected.\n{e}")

    def compute_hash(self):
        text = self.hash_input.get()
        hashed = DeepHash.hash_data(text.encode('utf-8'))
        self.hash_result.configure(state="normal")
        self.hash_result.delete(0, 'end')
        self.hash_result.insert(0, hashed)
        self.hash_result.configure(state="disabled")

    def append_chat(self, text):
        if hasattr(self, 'chat_display') and self.chat_display.winfo_exists():
            self.chat_display.configure(state="normal")
            self.chat_display.insert("end", text + "\n")
            self.chat_display.see("end")
            self.chat_display.configure(state="disabled")

    def send_message(self):
        msg = self.msg_entry.get()
        if msg:
            success = self.client.send_message(msg)
            if success:
                self.msg_entry.delete(0, 'end')
                self.append_chat(f"You: {msg}")
            else:
                messagebox.showerror("Error", "Failed to send. Lost connection.")
                self.disconnect()

    def start_receiving(self):
        self.receive_thread = threading.Thread(target=self.receive_loop, daemon=True)
        self.receive_thread.start()

    def receive_loop(self):
        while self.running and self.client.connected:
            msg = self.client.receive_message()
            if msg:
                self.after(0, self.append_chat, msg)
            else:
                if self.running:
                    self.after(0, lambda: messagebox.showerror("Disconnected", "Server connection closed."))
                    self.after(0, self.disconnect)
                break

    def disconnect(self):
        self.running = False
        self.client.close()
        self.show_auth_frame()

    def destroy(self):
        self.running = False
        self.client.close()
        super().destroy()

if __name__ == "__main__":
    app = SecureApp()
    app.mainloop()
