import time
import threading

class SecurityEvent:
    """Represents a single cryptographic operation event."""
    def __init__(self, event_type: str, module: str, description: str, raw_data: str = "", details: dict = None):
        self.timestamp = time.time()  # Record event creation time
        self.event_type = event_type  # e.g. "AES-ENC", "RSA-DEC", "HANDSHAKE"
        self.module = module          # Source module name
        self.description = description  # Human-readable summary
        self.raw_data = raw_data      # Hex-encoded cryptographic data
        self.details = details or {}  # Structured key-value details

    def formatted_time(self):
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))

    def __str__(self):
        return f"[{self.formatted_time()}] [{self.event_type}] {self.description}"


class SecurityLogger:
    """Singleton event bus for crypto operation logging."""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        # Thread-safe singleton: only one logger instance exists
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._events = []           # All recorded events
                cls._instance._subscribers = []      # Callback listeners
                cls._instance._handshake_steps = []  # 4-step handshake protocol
                cls._instance._session_info = {}     # Active session metadata
            return cls._instance

    def log(self, event: SecurityEvent):
        """Log a security event and notify all subscribers."""
        self._events.append(event)
        for callback in self._subscribers:  # Notify GUI and other listeners
            try:
                callback(event)
            except Exception:
                pass  # Don't let subscriber errors crash the logger

    def log_handshake(self, step_num: int, title: str, description: str, details: dict = None):
        """Log a handshake step."""
        step = {
            "step": step_num,
            "title": title,
            "description": description,
            "details": details or {},
            "timestamp": time.time()
        }
        self._handshake_steps.append(step)
        event = SecurityEvent("HANDSHAKE", "Protocol", f"Step {step_num}: {title} — {description}", details=details)
        self.log(event)

    def set_session_info(self, key: str, value):
        """Store session-level security info (cipher suite, keys, etc.)."""
        self._session_info[key] = value

    def get_session_info(self) -> dict:
        return dict(self._session_info)

    def get_handshake_steps(self) -> list:
        return list(self._handshake_steps)

    def get_events(self) -> list:
        return list(self._events)

    def subscribe(self, callback):
        """Subscribe to receive new security events via callback."""
        self._subscribers.append(callback)

    def clear(self):
        """Clear all events and handshake data."""
        self._events.clear()
        self._handshake_steps.clear()
        self._session_info.clear()
