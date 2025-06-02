import logging
import structlog

def test_both_tools():
    """
    Cases that should be detected by both Semgrep and CodeQL
    """
    
    # Direct cases (both tools should catch)
    user_email = "both@example.com"
    logging.info(f"Email: {user_email}")  # BOTH should detect
    
    # Structlog cases (both tools should catch)
    structlog.get_logger().info(
        "Event", 
        user_email="struct@example.com"  # BOTH should detect
    )

def test_semgrep_only():
    """
    Cases that primarily test Semgrep's pattern matching
    """
    # Variable name patterns
    customer_email_address = "semgrep@test.com"
    logging.info(f"Customer: {customer_email_address}")
    
    # F-string patterns
    class Contact:
        email = "fstring@test.com"
    
    contact = Contact()
    logging.info(f"Contact email: {contact.email}")

def test_codeql_only():
    """
    Cases that primarily test CodeQL's data flow analysis
    """
    def get_sensitive_info():
        return "codeql@flow.com"
    
    def log_generic_data(data):
        logging.info(f"Data: {data}")
    
    # Indirect flow through functions
    sensitive = get_sensitive_info()
    log_generic_data(sensitive)  # CodeQL should trace this

if __name__ == "__main__":
    test_both_tools()
    test_semgrep_only()
    test_codeql_only()