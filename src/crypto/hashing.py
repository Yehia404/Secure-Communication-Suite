from Crypto.Hash import SHA256

class DeepHash:
    """
    Data integrity checking using SHA-256.
    """
    @staticmethod
    def hash_data(data: bytes) -> str:
        """Computes the SHA-256 hash of the given data."""
        h = SHA256.new()
        h.update(data)
        return h.hexdigest()

    @staticmethod
    def verify(data: bytes, expected_hash: str) -> bool:
        """Verifies that the SHA-256 hash of the data matches the expected hash."""
        return DeepHash.hash_data(data) == expected_hash
