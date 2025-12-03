# Protection System (Système de Protection)

A comprehensive Python security and protection module that provides robust tools for input validation, authentication, rate limiting, encryption, and security headers management.

## Features

### 🛡️ Input Validation
- Email, username, and phone number validation
- SQL injection detection and prevention
- XSS (Cross-Site Scripting) detection
- HTML sanitization
- String sanitization with length limits

### 🔐 Authentication & Authorization
- Secure password hashing with SHA-256 and salt
- Password verification with timing-attack resistant comparison
- Token-based authentication with expiration
- Permission management system
- Token revocation

### ⏱️ Rate Limiting
- Sliding window rate limiting algorithm
- Per-identifier request tracking
- Configurable request limits and time windows
- Reset time tracking
- Support for multiple identifiers

### 🔒 Encryption
- Data encryption with XOR cipher and key strengthening
- Random initialization vectors for enhanced security
- Base64 encoding for safe data transport
- SHA-256 data hashing
- Hash verification utilities

### 🌐 Security Headers
- Pre-configured secure HTTP headers
- Content Security Policy (CSP) management
- CORS configuration
- Strict Transport Security (HSTS)
- XSS Protection headers
- Frame Options and more

## Installation

No external dependencies required! The system uses only Python standard library.

```bash
# Clone the repository
git clone https://github.com/louisalex987/drmgmodlxpapa.git
cd drmgmodlxpapa

# The system is ready to use
python examples.py
```

## Quick Start

```python
from protection_system import (
    InputValidator,
    AuthManager,
    RateLimiter,
    EncryptionManager,
    SecurityHeaders
)

# Validate user input
if InputValidator.validate_email("user@example.com"):
    print("Valid email!")

# Hash a password
auth = AuthManager()
pwd_hash, salt = auth.hash_password("my_password")

# Rate limit requests
limiter = RateLimiter(max_requests=100, window_seconds=60)
if limiter.is_allowed("user_id"):
    # Process request
    pass

# Encrypt sensitive data
encryption = EncryptionManager()
encrypted = encryption.encrypt("sensitive data")

# Apply security headers
headers = SecurityHeaders()
secure_headers = headers.get_headers()
```

## Usage Examples

### Input Validation

```python
from protection_system import InputValidator

# Email validation
InputValidator.validate_email("user@example.com")  # True

# Username validation (3-20 chars, alphanumeric, underscore, hyphen)
InputValidator.validate_username("john_doe")  # True

# SQL injection detection
InputValidator.check_sql_injection("'; DROP TABLE users--")  # True

# XSS detection
InputValidator.check_xss("<script>alert('xss')</script>")  # True

# HTML sanitization
InputValidator.sanitize_html("<script>alert(1)</script>")
# Returns: "&lt;script&gt;alert(1)&lt;/script&gt;"

# Complete validation and sanitization
is_valid, sanitized = InputValidator.validate_and_sanitize(
    user_input,
    max_length=100,
    check_sql=True,
    check_xss=True
)
```

### Authentication

```python
from protection_system import AuthManager

auth = AuthManager()

# Hash password
pwd_hash, salt = auth.hash_password("user_password")

# Verify password
is_valid = auth.verify_password("user_password", pwd_hash, salt)

# Generate authentication token (expires in 1 hour)
token = auth.generate_token("user123", expiry_seconds=3600)

# Validate token
user_id = auth.validate_token(token)

# Manage permissions
auth.add_permission("user123", "read")
auth.add_permission("user123", "write")
has_access = auth.has_permission("user123", "write")  # True

# Revoke token
auth.revoke_token(token)
```

### Rate Limiting

```python
from protection_system import RateLimiter

# Allow 100 requests per 60 seconds
limiter = RateLimiter(max_requests=100, window_seconds=60)

# Check if request is allowed
if limiter.is_allowed("user_ip_address"):
    # Process request
    pass
else:
    # Return rate limit error
    pass

# Get remaining requests
remaining = limiter.get_remaining_requests("user_ip_address")

# Get reset time
reset_time = limiter.get_reset_time("user_ip_address")

# Reset specific identifier
limiter.reset("user_ip_address")
```

### Encryption

```python
from protection_system import EncryptionManager

encryption = EncryptionManager()

# Encrypt data
encrypted = encryption.encrypt("sensitive information")

# Decrypt data
decrypted = encryption.decrypt(encrypted)

# Hash data
hash_value = encryption.hash_data("data to hash")

# Verify hash
is_valid = encryption.verify_hash("data to hash", hash_value)

# Generate new key
new_key = encryption.generate_new_key()
```

### Security Headers

```python
from protection_system import SecurityHeaders

headers = SecurityHeaders()

# Get all security headers
all_headers = headers.get_headers()

# Set custom CSP
headers.set_csp("default-src 'self'; script-src 'self' https://cdn.example.com")

# Configure CORS
headers.set_cors(
    origin='https://example.com',
    methods='GET, POST, PUT',
    headers='Content-Type, Authorization'
)

# Apply to response
response_headers = {'Content-Type': 'application/json'}
secure_headers = headers.apply_to_response(response_headers)

# Get strict headers for high-security environments
strict_headers = SecurityHeaders.get_strict_headers()
```

## Running Tests

```bash
# Run all tests
python -m unittest discover tests

# Run specific test module
python -m unittest tests.test_validator
python -m unittest tests.test_auth
python -m unittest tests.test_rate_limiter
python -m unittest tests.test_encryption
python -m unittest tests.test_security_headers
```

## Running Examples

```bash
# Run the comprehensive examples file
python examples.py
```

## Project Structure

```
drmgmodlxpapa/
├── protection_system/
│   ├── __init__.py          # Package initialization
│   ├── validator.py         # Input validation and sanitization
│   ├── auth.py              # Authentication and authorization
│   ├── rate_limiter.py      # Rate limiting functionality
│   ├── encryption.py        # Encryption and hashing
│   └── security_headers.py  # HTTP security headers
├── tests/
│   ├── __init__.py
│   ├── test_validator.py
│   ├── test_auth.py
│   ├── test_rate_limiter.py
│   ├── test_encryption.py
│   └── test_security_headers.py
├── examples.py              # Usage examples
├── requirements.txt         # Dependencies (none required)
└── README.md               # This file
```

## Security Considerations

- **Password Hashing**: Uses SHA-256 with random salt and timing-attack resistant comparison
- **Token Generation**: Uses cryptographically secure random token generation
- **Encryption**: Uses XOR cipher with key strengthening (10,000 iterations) and random IV
- **Input Validation**: Implements pattern matching for SQL injection and XSS detection
- **Rate Limiting**: Prevents abuse with sliding window algorithm

## Best Practices

1. **Always validate user input** before processing
2. **Hash passwords** before storing them
3. **Use tokens** with appropriate expiration times
4. **Implement rate limiting** on sensitive endpoints
5. **Encrypt sensitive data** at rest and in transit
6. **Apply security headers** to all HTTP responses

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Author

Protection System Team

---

**Note**: This is a demonstration protection system. For production use, consider using well-established security libraries and frameworks appropriate for your specific use case.