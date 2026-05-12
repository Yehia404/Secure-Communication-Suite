import threading
import customtkinter as ctk
import tkinter.messagebox as messagebox
from client import SecureClient
from crypto.hashing import DeepHash
from security_logger import SecurityLogger

ctk.set_appearance_mode("dark")   # Dark theme by default
ctk.set_default_color_theme("blue")

EVENT_COLORS = {
    "AES-ENC": "#22c55e", "AES-DEC": "#3b82f6", "RSA-ENC": "#f59e0b",
    "RSA-DEC": "#f97316", "RSA-KEYGEN": "#a855f7", "SHA-256": "#06b6d4",
    "SHA-256-VERIFY": "#14b8a6", "AUTH-REGISTER": "#ec4899", "AUTH-LOGIN": "#22c55e",
    "AUTH-FAIL": "#ef4444", "AUTH-REJECT": "#ef4444", "AUTH-OK": "#22c55e",
    "KEY-GEN": "#a855f7", "KEY-LOAD": "#8b5cf6", "KEY-SAVE": "#7c3aed",
    "HANDSHAKE": "#eab308", "SESSION-READY": "#10b981",
}
STEP_ICONS = {1: "1", 2: "2", 3: "3", 4: "4"}  # Handshake step numbers


class SecureApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Communication Suite")
        self.geometry("1100x700")
        self.minsize(900, 600)
        self.client = SecureClient()  # Network + crypto client
        self.logger = SecurityLogger()  # Shared event bus
        self.receive_thread = None
        self.running = True
        self.chat_messages = []  # Persist chat messages across view switches
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.show_auth_frame()  # Start on login screen

    def clear_window(self):
        for w in self.winfo_children():
            w.destroy()

    # ── Auth Screen ──
    def show_auth_frame(self):
        self.clear_window()
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        frame = ctk.CTkFrame(self, corner_radius=15)
        frame.place(relx=0.5, rely=0.5, anchor=ctk.CENTER)
        ctk.CTkLabel(frame, text="Secure Login", font=ctk.CTkFont(size=26, weight="bold")).pack(pady=(20, 10), padx=40)
        self.username_entry = ctk.CTkEntry(frame, placeholder_text="Username", width=220)
        self.username_entry.pack(pady=10, padx=40)
        self.password_entry = ctk.CTkEntry(frame, placeholder_text="Password", show="*", width=220)
        self.password_entry.pack(pady=10, padx=40)
        bf = ctk.CTkFrame(frame, fg_color="transparent")
        bf.pack(pady=(10, 20))
        ctk.CTkButton(bf, text="Login", width=100, command=lambda: self.authenticate("LOGIN")).pack(side="left", padx=5)
        ctk.CTkButton(bf, text="Register", width=100, command=lambda: self.authenticate("REGISTER")).pack(side="right", padx=5)

    def authenticate(self, action):
        user, pwd = self.username_entry.get(), self.password_entry.get()
        if not user or not pwd:
            messagebox.showwarning("Input Error", "Please provide both username and password")
            return
        success, msg = self.client.connect_and_auth(action, user, pwd)
        if success:
            self.chat_messages.clear()
            self.show_main_interface()  # Switch to chat view
            self.start_receiving()      # Start background message listener
        else:
            # Append security log to error message for debugging
            events = self.logger.get_events()
            if events:
                log_lines = "\n".join(f"[{e.event_type}] {e.description}" for e in events)
                msg = f"{msg}\n\n--- Security Log ---\n{log_lines}"
            messagebox.showerror("Auth Error", msg)

    # ── Main Interface ──
    def show_main_interface(self):
        self.clear_window()
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)

        sb = ctk.CTkFrame(self, width=150, corner_radius=0, fg_color="#1a1a2e")
        sb.grid(row=0, column=0, sticky="ns")
        sb.grid_propagate(False)

        ctk.CTkLabel(sb, text="Suite Options", font=ctk.CTkFont(size=15, weight="bold")).pack(pady=(15, 10))
        ctk.CTkButton(sb, text="Secure Chat", width=130, command=self.show_chat_view).pack(pady=4)
        ctk.CTkButton(sb, text="Crypto Tools", width=130, command=self.show_hash_view).pack(pady=4)
        ctk.CTkButton(sb, text="Security Dashboard", width=130, command=self.show_dashboard_view, fg_color="#16a34a", hover_color="#15803d").pack(pady=4)

        spacer = ctk.CTkFrame(sb, fg_color="transparent")
        spacer.pack(fill="both", expand=True)

        ctk.CTkButton(sb, text="Disconnect", width=130, command=self.disconnect, fg_color="#dc2626", hover_color="#b91c1c").pack(pady=(0, 15))

        self.content_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="#1e1e2e")
        self.content_frame.grid(row=0, column=1, sticky="nsew")
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.show_chat_view()  # Default to chat on login

    def clear_content(self):
        for w in self.content_frame.winfo_children():
            w.destroy()
        # Reset grid weights
        for i in range(5):
            self.content_frame.grid_rowconfigure(i, weight=0)

    # ── Chat View (bubble style, persistent) ──
    def show_chat_view(self):
        self.clear_content()
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)

        self.chat_scroll = ctk.CTkScrollableFrame(self.content_frame, fg_color="transparent")
        self.chat_scroll.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        self.chat_scroll._scrollbar.configure(height=0)

        # Re-render persisted messages
        for sender, text in self.chat_messages:
            self._render_bubble(sender, text)

        # Input bar
        input_bar = ctk.CTkFrame(self.content_frame, fg_color="transparent", height=45)
        input_bar.pack(fill="x", padx=8, pady=(0, 8))
        input_bar.grid_columnconfigure(0, weight=1)

        self.msg_entry = ctk.CTkEntry(input_bar, placeholder_text="Type a secure message...", height=38, font=ctk.CTkFont(size=13))
        self.msg_entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.msg_entry.bind("<Return>", lambda e: self.send_message())

        ctk.CTkButton(input_bar, text="Send", width=70, height=38, command=self.send_message).grid(row=0, column=1)

    def _render_bubble(self, sender, text):
        """Render a single chat bubble. sender='You' for right-aligned, else left."""
        is_me = (sender == "You")
        anchor = "e" if is_me else "w"
        bg = "#2563eb" if is_me else "#334155"
        name_color = "#93c5fd" if is_me else "#6ee7b7"

        wrapper = ctk.CTkFrame(self.chat_scroll, fg_color="transparent")
        wrapper.pack(fill="x", pady=2, padx=4)

        bubble = ctk.CTkFrame(wrapper, corner_radius=12, fg_color=bg)
        bubble.pack(anchor=anchor, padx=4)

        ctk.CTkLabel(bubble, text=sender, font=ctk.CTkFont(size=11, weight="bold"), text_color=name_color).pack(anchor="w", padx=10, pady=(6, 0))
        ctk.CTkLabel(bubble, text=text, font=ctk.CTkFont(size=13), text_color="#f1f5f9", wraplength=400, justify="left").pack(anchor="w", padx=10, pady=(2, 8))

    def append_chat(self, text):
        """Parse and store message, render bubble if chat view is active."""
        if text.startswith("You: "):
            sender, body = "You", text[5:]
        elif ": " in text:
            sender, body = text.split(": ", 1)
        else:
            sender, body = "System", text

        self.chat_messages.append((sender, body))

        # Render if chat scroll is currently visible
        if hasattr(self, 'chat_scroll') and self.chat_scroll.winfo_exists():
            self._render_bubble(sender, body)
            self.chat_scroll._parent_canvas.yview_moveto(1.0)

    # ── Crypto Tools View ──
    def show_hash_view(self):
        self.clear_content()
        ctk.CTkLabel(self.content_frame, text="Crypto Tools (Hash & AES)", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(12, 8))
        # SHA-256
        hf = ctk.CTkFrame(self.content_frame, corner_radius=8)
        hf.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(hf, text="SHA-256 Integrity Verifier", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(8, 4))
        self.hash_input = ctk.CTkEntry(hf, placeholder_text="Message to hash...", width=400)
        self.hash_input.pack(padx=12, pady=4)
        ctk.CTkButton(hf, text="Compute Digest", command=self.compute_hash).pack(pady=4)
        self.hash_result = ctk.CTkEntry(hf, width=400)
        self.hash_result.pack(padx=12, pady=(4, 10))
        self.hash_result.insert(0, "Hash result will appear here")
        self.hash_result.configure(state="disabled")
        # AES
        af = ctk.CTkFrame(self.content_frame, corner_radius=8)
        af.pack(fill="x", padx=15, pady=(10, 5))
        ctk.CTkLabel(af, text="AES Block Cipher Tool (Produces HEX)", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(8, 4))
        self.aes_plain_input = ctk.CTkEntry(af, placeholder_text="Type plain text here...", width=400)
        self.aes_plain_input.pack(padx=12, pady=4)
        bf = ctk.CTkFrame(af, fg_color="transparent")
        bf.pack(pady=4)
        ctk.CTkButton(bf, text="Encrypt", width=100, command=self.manual_encrypt).pack(side="left", padx=5)
        ctk.CTkButton(bf, text="Decrypt", width=100, command=self.manual_decrypt).pack(side="left", padx=5)
        self.aes_cipher_input = ctk.CTkEntry(af, placeholder_text="Type encrypted HEX here...", width=400)
        self.aes_cipher_input.pack(padx=12, pady=(4, 10))

    def manual_encrypt(self):
        # Encrypt plaintext with session AES key and show hex output
        text = self.aes_plain_input.get()
        if text and self.client.aes_cipher:
            encrypted_bytes = self.client.aes_cipher.encrypt(text.encode('utf-8'))
            self.aes_cipher_input.delete(0, "end")
            self.aes_cipher_input.insert(0, encrypted_bytes.hex())

    def manual_decrypt(self):
        # Decrypt hex ciphertext back to plaintext using session AES key
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

    # ── Security Dashboard View ──
    def show_dashboard_view(self):
        self.clear_content()
        self.content_frame.grid_rowconfigure(0, weight=1)

        tabs = ctk.CTkTabview(self.content_frame, corner_radius=8)
        tabs.pack(fill="both", expand=True, padx=6, pady=6)
        tabs.add("Handshake")
        tabs.add("Session Info")
        tabs.add("Crypto Log")

        self._build_handshake_tab(tabs.tab("Handshake"))
        self._build_session_tab(tabs.tab("Session Info"))
        self._build_log_tab(tabs.tab("Crypto Log"))

    def _build_handshake_tab(self, parent):
        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=2, pady=2)
        steps = self.logger.get_handshake_steps()
        if not steps:
            ctk.CTkLabel(scroll, text="No handshake recorded yet.", font=ctk.CTkFont(size=14), text_color="#888").pack(pady=40)
            return
        for s in steps:
            card = ctk.CTkFrame(scroll, corner_radius=10, fg_color="#1e293b", border_width=1, border_color="#334155")
            card.pack(fill="x", padx=4, pady=3)
            header = f"Step {s['step']}: {s['title']}"
            ctk.CTkLabel(card, text=header, font=ctk.CTkFont(size=13, weight="bold"), text_color="#facc15").pack(anchor="w", padx=10, pady=(6, 1))
            ctk.CTkLabel(card, text=s["description"], font=ctk.CTkFont(size=11), text_color="#cbd5e1", wraplength=550).pack(anchor="w", padx=10, pady=(0, 2))
            if s.get("details"):
                for k, v in s["details"].items():
                    row = ctk.CTkFrame(card, fg_color="transparent")
                    row.pack(fill="x", padx=14, pady=0)
                    ctk.CTkLabel(row, text=f"{k}:", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8", width=140, anchor="w").pack(side="left")
                    ctk.CTkLabel(row, text=str(v), font=ctk.CTkFont(size=10, family="Consolas"), text_color="#e2e8f0", wraplength=380, anchor="w").pack(side="left", fill="x", expand=True)
            ctk.CTkFrame(card, height=3, fg_color="transparent").pack()

    def _build_session_tab(self, parent):
        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=2, pady=2)
        info = self.logger.get_session_info()
        if not info:
            ctk.CTkLabel(scroll, text="No active session.", font=ctk.CTkFont(size=14), text_color="#888").pack(pady=40)
            return
        # Cipher suite banner
        suite = info.get("cipher_suite", "N/A")
        banner = ctk.CTkFrame(scroll, corner_radius=10, fg_color="#064e3b", border_width=1, border_color="#10b981")
        banner.pack(fill="x", padx=4, pady=(4, 8))
        ctk.CTkLabel(banner, text="Active Cipher Suite", font=ctk.CTkFont(size=13, weight="bold"), text_color="#6ee7b7").pack(anchor="w", padx=10, pady=(6, 1))
        ctk.CTkLabel(banner, text=suite, font=ctk.CTkFont(size=14, family="Consolas", weight="bold"), text_color="#ecfdf5").pack(anchor="w", padx=10, pady=(0, 6))
        # Detail cards
        labels = {
            "username": ("User", None), "server": ("Server", None),
            "aes_key": ("AES Session Key", "Symmetric key for message encryption"),
            "aes_algorithm": ("Symmetric Cipher", None), "rsa_algorithm": ("Asymmetric Cipher", None),
            "hash_algorithm": ("Hash Function", None),
            "server_key_fingerprint": ("Server Key Fingerprint", "SHA-256 of server RSA public key"),
        }
        for key, (label, subtitle) in labels.items():
            val = info.get(key)
            if not val:
                continue
            card = ctk.CTkFrame(scroll, corner_radius=8, fg_color="#1e293b")
            card.pack(fill="x", padx=4, pady=2)
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=11, weight="bold"), text_color="#94a3b8").pack(anchor="w", padx=10, pady=(5, 0))
            display = val[:8] + " ---- " + val[-8:] if key == "aes_key" else str(val)
            color = "#fbbf24" if key == "aes_key" else "#e2e8f0"
            ctk.CTkLabel(card, text=display, font=ctk.CTkFont(size=12, family="Consolas"), text_color=color).pack(anchor="w", padx=10, pady=(0, 1))
            if subtitle:
                ctk.CTkLabel(card, text=subtitle, font=ctk.CTkFont(size=9), text_color="#64748b").pack(anchor="w", padx=10, pady=(0, 5))
            else:
                ctk.CTkFrame(card, height=5, fg_color="transparent").pack()

    def _build_log_tab(self, parent):
        top = ctk.CTkFrame(parent, fg_color="transparent")
        top.pack(fill="x", padx=4, pady=(2, 0))
        ctk.CTkLabel(top, text="Cryptographic Event Log", font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")
        log_box = ctk.CTkTextbox(parent, font=ctk.CTkFont(size=11, family="Consolas"), state="disabled")
        log_box.pack(fill="both", expand=True, padx=4, pady=4)
        ctk.CTkButton(top, text="Refresh", width=80, height=28, command=lambda: self._refresh_log(log_box)).pack(side="right")
        self._refresh_log(log_box)

    def _refresh_log(self, log_box):
        log_box.configure(state="normal")
        log_box.delete("1.0", "end")
        events = self.logger.get_events()
        if not events:
            log_box.insert("end", "  No events recorded yet.\n")
        else:
            for ev in events:
                c = EVENT_COLORS.get(ev.event_type, "#888888")
                tag = f"t_{ev.event_type}"
                log_box.tag_config(tag, foreground=c)
                log_box.insert("end", f"[{ev.formatted_time()}] [{ev.event_type:15s}] {ev.description}\n", tag)
                if ev.details:
                    for k, v in ev.details.items():
                        log_box.insert("end", f"{'':>40s}{k}: {v}\n", tag)
                    log_box.insert("end", "\n")
        log_box.see("end")
        log_box.configure(state="disabled")

    # ── Chat helpers ──
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
        # Launch background thread to listen for incoming encrypted messages
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
        # Graceful teardown: stop listener, close socket, return to login
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
