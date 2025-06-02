import logging
import structlog

logger = logging.getLogger(__name__)
struct_logger = structlog.get_logger()

def semgrep_test_cases():
    """
    Simple patterns that Semgrep should catch easily
    These test direct variable name matching
    """
    
    # Email variables (should be detected)
    user_email = "test@example.com"
    customer_email = "customer@company.com"
    admin_email = "admin@system.com"
    
    logging.info(f"User registered: {user_email}")
    logger.error(f"Email validation failed: {customer_email}")
    logging.warning(f"Admin notification sent to: {admin_email}")
    
    # SSN variables (should be detected)
    user_ssn = "123-45-6789"
    social_security_number = "987-65-4321"
    
    logging.debug(f"SSN verification: {user_ssn}")
    logger.info(f"Processing SSN: {social_security_number}")
    
    # Phone variables (should be detected)
    phone_number = "+1-555-123-4567"
    customer_phone = "555-999-0000"
    
    logging.info(f"SMS sent to: {phone_number}")
    logger.warning(f"Call failed to: {customer_phone}")
    
    # Credentials (should be detected)
    user_password = "secret123"
    api_key = "sk-1234567890"
    auth_token = "bearer_token_abc"
    
    logging.debug(f"Password validation: {user_password}")
    logger.error(f"API key invalid: {api_key}")
    logging.info(f"Token refresh: {auth_token}")
    
    # Structlog PII (should be detected)
    struct_logger.info(
        "User signup complete",
        user_email="new@user.com",
        phone_number="+1-555-000-1234",
        social_security="123-45-6789"
    )
    
    # Direct attribute access (should be detected)
    class User:
        def __init__(self):
            self.email = "direct@example.com"
            self.ssn = "111-22-3333"
            self.phone = "555-0123"
    
    user = User()
    logging.info(f"User created: {user.email}")
    logger.error(f"SSN mismatch: {user.ssn}")
    logging.warning(f"Phone verification: {user.phone}")

if __name__ == "__main__":
    semgrep_test_cases()