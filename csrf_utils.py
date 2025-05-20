import hashlib
import time
import os

class CSRFUtils:
    def __init__(self, secret_key=None):
        self.secret_key = secret_key or os.urandom(24).hex()  # Default to random key if none provided

    def generate_token(self, user_id=None):
        """Generate a CSRF token based on user_id, secret_key, and timestamp."""
        timestamp = int(time.time()) // 3600  # Hourly rotation
        data = f"{user_id or 'guest'}{self.secret_key}{timestamp}".encode()
        return hashlib.md5(data).hexdigest()

    def validate_token(self, token, user_id=None):
        """Validate a CSRF token by regenerating and comparing."""
        generated_token = self.generate_token(user_id)
        return generated_token == token

# Example usage (uncomment to test)
if __name__ == "__main__":
    csrf = CSRFUtils()
    token = csrf.generate_token("user123")
    print(f"Generated Token: {token}")
    print(f"Validation Result: {csrf.validate_token(token, 'user123')}")