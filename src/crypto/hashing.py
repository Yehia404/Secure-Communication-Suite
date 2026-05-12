from Crypto.Hash import SHA256
from security_logger import SecurityLogger, SecurityEvent

class DeepHash:
    """
    Data integrity checking using SHA-256.
    """
    @staticmethod
    def hash_data(data: bytes) -> str:
        """Computes the SHA-256 hash of the given data."""
        h = SHA256.new()
        h.update(data)  # Feed data into SHA-256
        digest = h.hexdigest()  # Get 64-char hex digest

        # Log hashing event
        logger = SecurityLogger()
        logger.log(SecurityEvent(
            event_type="SHA-256",
            module="Hashing",
            description=f"SHA-256 digest computed for {len(data)} bytes of input",
            raw_data=digest,
            details={
                "algorithm": "SHA-256",
                "input_size": f"{len(data)} bytes",
                "digest": digest,
                "digest_size": "256 bits (32 bytes)",
            }
        ))

        return digest

    @staticmethod
    def verify(data: bytes, expected_hash: str) -> bool:
        """Verifies that the SHA-256 hash of the data matches the expected hash."""
        computed = DeepHash.hash_data(data)  # Compute fresh hash
        match = computed == expected_hash  # Compare with expected value

        # Log verification event
        logger = SecurityLogger()
        logger.log(SecurityEvent(
            event_type="SHA-256-VERIFY",
            module="Hashing",
            description=f"Integrity check {'✅ PASSED' if match else '❌ FAILED'}",
            details={
                "expected": expected_hash,
                "computed": computed,
                "match": "✅ PASSED" if match else "❌ FAILED",
            }
        ))

        return match
