"""
Examples demonstrating the Protection System usage
"""

from protection_system import (
    InputValidator,
    AuthManager,
    RateLimiter,
    EncryptionManager,
    SecurityHeaders
)


def example_input_validation():
    """Example: Input validation and sanitization"""
    print("=== Input Validation Examples ===\n")
    
    # Validate email
    email = "user@example.com"
    if InputValidator.validate_email(email):
        print(f"✓ Valid email: {email}")
    
    # Validate username
    username = "john_doe"
    if InputValidator.validate_username(username):
        print(f"✓ Valid username: {username}")
    
    # Check for SQL injection
    suspicious_input = "admin' OR '1'='1"
    if InputValidator.check_sql_injection(suspicious_input):
        print(f"✗ SQL injection detected: {suspicious_input}")
    
    # Sanitize HTML
    html_input = "<script>alert('xss')</script>"
    sanitized = InputValidator.sanitize_html(html_input)
    print(f"✓ Sanitized HTML: {sanitized}")
    
    # Validate and sanitize in one step
    user_input = "Hello World!"
    is_valid, clean_input = InputValidator.validate_and_sanitize(user_input, max_length=50)
    if is_valid:
        print(f"✓ Clean input: {clean_input}")
    
    print()


def example_authentication():
    """Example: Authentication and authorization"""
    print("=== Authentication Examples ===\n")
    
    auth = AuthManager()
    
    # Hash a password
    password = "secure_password123"
    pwd_hash, salt = auth.hash_password(password)
    print(f"✓ Password hashed successfully")
    
    # Verify password
    if auth.verify_password(password, pwd_hash, salt):
        print(f"✓ Password verified successfully")
    
    # Generate authentication token
    user_id = "user123"
    token = auth.generate_token(user_id, expiry_seconds=3600)
    print(f"✓ Token generated: {token[:20]}...")
    
    # Validate token
    validated_user = auth.validate_token(token)
    if validated_user:
        print(f"✓ Token valid for user: {validated_user}")
    
    # Add permissions
    auth.add_permission(user_id, "read")
    auth.add_permission(user_id, "write")
    
    if auth.has_permission(user_id, "read"):
        print(f"✓ User has 'read' permission")
    
    permissions = auth.get_permissions(user_id)
    print(f"✓ User permissions: {permissions}")
    
    print()


def example_rate_limiting():
    """Example: Rate limiting"""
    print("=== Rate Limiting Examples ===\n")
    
    # Create rate limiter: 5 requests per 60 seconds
    limiter = RateLimiter(max_requests=5, window_seconds=60)
    
    user_ip = "192.168.1.100"
    
    # Simulate requests
    for i in range(7):
        if limiter.is_allowed(user_ip):
            print(f"✓ Request {i+1} allowed")
        else:
            print(f"✗ Request {i+1} denied (rate limit exceeded)")
        
        remaining = limiter.get_remaining_requests(user_ip)
        print(f"  Remaining requests: {remaining}")
    
    # Reset limit for user
    limiter.reset(user_ip)
    print(f"\n✓ Rate limit reset for {user_ip}")
    
    print()


def example_encryption():
    """Example: Data encryption"""
    print("=== Encryption Examples ===\n")
    
    encryption = EncryptionManager()
    
    # Encrypt sensitive data
    sensitive_data = "Credit Card: 1234-5678-9012-3456"
    encrypted = encryption.encrypt(sensitive_data)
    print(f"✓ Data encrypted: {encrypted[:40]}...")
    
    # Decrypt data
    decrypted = encryption.decrypt(encrypted)
    print(f"✓ Data decrypted: {decrypted}")
    
    # Hash data
    data = "Important document content"
    hash_value = encryption.hash_data(data)
    print(f"✓ Data hash: {hash_value[:40]}...")
    
    # Verify hash
    if encryption.verify_hash(data, hash_value):
        print(f"✓ Hash verified successfully")
    
    print()


def example_security_headers():
    """Example: Security headers for web applications"""
    print("=== Security Headers Examples ===\n")
    
    # Create security headers manager
    headers = SecurityHeaders()
    
    # Get all default headers
    all_headers = headers.get_headers()
    print("Default security headers:")
    for name, value in all_headers.items():
        print(f"  {name}: {value}")
    
    # Set custom CSP
    headers.set_csp("default-src 'self'; script-src 'self' https://cdn.example.com")
    print(f"\n✓ Custom CSP set")
    
    # Configure CORS
    headers.set_cors(
        origin='https://example.com',
        methods='GET, POST, PUT, DELETE',
        headers='Content-Type, Authorization'
    )
    print(f"✓ CORS configured")
    
    # Apply to response
    response_headers = {'Content-Type': 'application/json'}
    updated_headers = headers.apply_to_response(response_headers)
    print(f"\n✓ Security headers applied to response")
    print(f"  Total headers: {len(updated_headers)}")
    
    print()


def example_complete_workflow():
    """Example: Complete protection workflow"""
    print("=== Complete Protection Workflow ===\n")
    
    # Initialize all protection components
    validator = InputValidator()
    auth = AuthManager()
    limiter = RateLimiter(max_requests=10, window_seconds=60)
    encryption = EncryptionManager()
    headers = SecurityHeaders()
    
    # Simulated user registration
    print("1. User Registration:")
    username = "new_user123"
    email = "user@example.com"
    password = "SecurePass123!"
    
    # Validate input
    if validator.validate_username(username) and validator.validate_email(email):
        print(f"   ✓ Input validation passed")
        
        # Hash password
        pwd_hash, salt = auth.hash_password(password)
        print(f"   ✓ Password securely hashed")
        
        # Encrypt sensitive data
        encrypted_email = encryption.encrypt(email)
        print(f"   ✓ Email encrypted")
    
    # Simulated user login
    print("\n2. User Login:")
    user_ip = "192.168.1.100"
    
    # Check rate limit
    if limiter.is_allowed(user_ip):
        print(f"   ✓ Rate limit check passed")
        
        # Verify password
        if auth.verify_password(password, pwd_hash, salt):
            print(f"   ✓ Password verified")
            
            # Generate session token
            token = auth.generate_token(username, expiry_seconds=3600)
            print(f"   ✓ Session token generated")
            
            # Add permissions
            auth.add_permission(username, "read")
            auth.add_permission(username, "write")
            print(f"   ✓ Permissions assigned")
    
    # Simulated API request
    print("\n3. API Request:")
    
    # Validate token
    validated_user = auth.validate_token(token)
    if validated_user:
        print(f"   ✓ Token validated for user: {validated_user}")
        
        # Check rate limit
        if limiter.is_allowed(user_ip):
            print(f"   ✓ Rate limit check passed")
            
            # Check permissions
            if auth.has_permission(validated_user, "read"):
                print(f"   ✓ Permission check passed")
                
                # Apply security headers
                response_headers = {'Content-Type': 'application/json'}
                secure_headers = headers.apply_to_response(response_headers)
                print(f"   ✓ Security headers applied ({len(secure_headers)} headers)")
    
    print()


if __name__ == "__main__":
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║          Protection System - Usage Examples              ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print()
    
    example_input_validation()
    example_authentication()
    example_rate_limiting()
    example_encryption()
    example_security_headers()
    example_complete_workflow()
    
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║                    Examples Complete                      ║")
    print("╚═══════════════════════════════════════════════════════════╝")
