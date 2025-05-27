import logging
import hashlib
import structlog

# Configure standard logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Use shared structlog configuration
from config.logging_config import setup_structlog
struct_logger = setup_structlog()

class SecureUserService:
    def __init__(self):
        self.users = {}
        self.log = structlog.get_logger()
    
    def process_user_registration(self, user_data):
        """Example with safe logging practices using both standard and structlog"""
        user_id = user_data.get('user_id')
        registration_timestamp = user_data.get('timestamp')
        
        # GOOD: Standard logging with non-PII identifier
        logger.info(f"Processing registration for user ID: {user_id}")
        
        # GOOD: Structlog with safe, non-PII fields
        self.log.info("User registration started", 
                     user_id=user_id, 
                     registration_type="standard",
                     timestamp=registration_timestamp)
        
        # GOOD: Structlog with aggregated/anonymized data
        struct_logger.info("Registration metrics",
                          total_fields_provided=len(user_data),
                          validation_step="initial",
                          success=True)
        
        # GOOD: Bind safe context only
        safe_logger = self.log.bind(
            user_id=user_id, 
            session_id="sess_123",
            registration_source="web"
        )
        safe_logger.info("User data validation completed")
        
        return {"status": "processed"}
    
    def authenticate_user(self, email, password):
        """Safe authentication logging with structlog"""
        # GOOD: Hash the email for logging
        email_hash = hashlib.sha256(email.encode()).hexdigest()[:8]
        
        # GOOD: Standard logging with hashed identifier
        logger.info(f"Authentication attempt for user hash: {email_hash}")
        
        # GOOD: Structlog with safe authentication context
        struct_logger.info("Authentication attempt",
                          user_hash=email_hash,
                          auth_method="email_password",
                          timestamp="2024-01-01",
                          ip_address_hash=self._hash_ip("192.168.1.1"))
        
        success = self._verify_credentials(email, password)
        
        # GOOD: Log outcome without credentials using structlog
        self.log.info("Authentication completed",
                     user_hash=email_hash,
                     success=success,
                     duration_ms=150)
        
        # GOOD: Bind safe context for subsequent operations
        if success:
            auth_logger = struct_logger.bind(
                authenticated_user_hash=email_hash,
                session_type="authenticated"
            )
            auth_logger.info("User session established")
        
        return success
    
    def _verify_credentials(self, email, password):
        """Private method for credential verification"""
        return True  # Simplified for demo
    
    def _hash_ip(self, ip_address):
        """Hash IP address for safe logging"""
        return hashlib.sha256(ip_address.encode()).hexdigest()[:8]
    
    def update_profile(self, user_id, profile_data):
        """Safe profile update logging with structlog"""
        # GOOD: Use user ID instead of PII
        logger.info(f"Profile update initiated for user ID: {user_id}")
        
        # GOOD: Structlog with safe metadata about the update
        updated_fields = list(profile_data.keys())
        struct_logger.info("Profile update started",
                          user_id=user_id,
                          fields_being_updated=updated_fields,
                          update_type="user_initiated")
        
        # GOOD: Log field counts and types, not values
        field_stats = {
            'total_fields': len(profile_data),
            'has_address': 'address' in profile_data,
            'has_phone': 'phone' in profile_data,
            'has_email': 'email' in profile_data
        }
        
        self.log.info("Profile update analysis",
                     user_id=user_id,
                     field_statistics=field_stats)
        
        # GOOD: Bind safe context for profile operations
        profile_logger = struct_logger.bind(
            user_id=user_id,
            operation="profile_update",
            timestamp="2024-01-01"
        )
        profile_logger.info("Profile validation completed")

def process_payment_safely_structlog(payment_method_id, amount, transaction_id):
    """Safe payment processing with structlog"""
    # GOOD: Use payment method ID instead of card details
    logger.info(f"Processing payment of ${amount} using method ID: {payment_method_id}")
    
    # GOOD: Structlog with safe payment context
    struct_logger.info("Payment processing initiated",
                      payment_method_id=payment_method_id,
                      amount=amount,
                      transaction_id=transaction_id,
                      currency="USD")
    
    # GOOD: Log business metrics safely with structlog
    struct_logger.info("Payment transaction metrics",
                      amount=amount,
                      payment_type="card",
                      processing_time_ms=250,
                      success=True)

def handle_user_error_safely_structlog(user_id, error_code, error_category):
    """Safe error handling with structlog"""
    # GOOD: Use user ID and error codes instead of PII
    logger.error(f"Error {error_code} occurred for user ID: {user_id}")
    
    # GOOD: Structlog with safe error context
    struct_logger.error("User error occurred",
                       user_id=user_id,
                       error_code=error_code,
                       error_category=error_category,
                       timestamp="2024-01-01",
                       requires_user_action=True)
    
    # GOOD: Bound logger with safe error tracking context
    error_logger = struct_logger.bind(
        affected_user_id=user_id,
        error_session="error_sess_456"
    )
    error_logger.error("Error analysis completed", 
                      severity="medium",
                      auto_resolution_attempted=True)

# Utility functions for safe logging
def mask_email(email):
    """Utility function to mask email for logging"""
    if '@' in email:
        local, domain = email.split('@', 1)
        masked_local = local[:2] + '*' * (len(local) - 2)
        return f"{masked_local}@{domain}"
    return "invalid_email"

def hash_pii(pii_value, salt="app_salt"):
    """Hash PII for safe logging"""
    return hashlib.sha256(f"{pii_value}{salt}".encode()).hexdigest()[:8]

def safe_structlog_example(user_data):
    """Example of safe structured logging with complex data"""
    user_id = user_data.get('user_id')
    
    # GOOD: Extract safe metadata only
    safe_metadata = {
        'user_id': user_id,
        'data_fields_present': list(user_data.keys()),
        'record_count': 1,
        'source': 'user_input',
        'validation_required': True
    }
    
    # GOOD: Log safe metadata with structlog
    struct_logger.info("User data processing",
                      **safe_metadata)
    
    # GOOD: Create masked/hashed versions for debugging if needed
    if user_data.get('email'):
        email_hash = hash_pii(user_data['email'])
        struct_logger.debug("Email validation",
                           user_id=user_id,
                           email_hash=email_hash,
                           validation_method="regex")
    
    # GOOD: Bind safe context for operations
    processing_logger = struct_logger.bind(
        user_id=user_id,
        operation_id="op_789",
        batch_size=1
    )
    processing_logger.info("Data processing completed successfully")

def complex_safe_structlog_scenario():
    """Complex but safe structlog usage patterns"""
    
    # GOOD: Create base logger with safe context
    base_logger = struct_logger.bind(
        component="user_service",
        version="1.2.3",
        environment="production"
    )
    
    # GOOD: Log safe system metrics
    base_logger.info("Service metrics",
                    active_users_count=150,
                    processing_queue_size=25,
                    system_health="healthy")
    
    # GOOD: Process data safely in loops
    user_ids = [1, 2, 3, 4, 5]
    for user_id in user_ids:
        base_logger.debug("Processing user record",
                         user_id=user_id,
                         processing_stage="validation")
    
    # GOOD: Conditional logging with safe data
    system_load = 0.75
    if system_load > 0.7:
        base_logger.warning("High system load detected",
                           cpu_usage=system_load,
                           alert_threshold=0.7,
                           auto_scaling_triggered=True)

# Safe alternatives for common PII logging scenarios
class SafeLoggingExamples:
    def __init__(self):
        self.log = structlog.get_logger()
    
    def safe_user_activity_logging(self, user_id, activity_type):
        """Log user activity without PII"""
        self.log.info("User activity recorded",
                     user_id=user_id,
                     activity_type=activity_type,
                     timestamp="2024-01-01")
    
    def safe_error_logging(self, user_id, error_details):
        """Log errors with context but no PII"""
        error_hash = hash_pii(str(error_details))
        self.log.error("User error occurred",
                      user_id=user_id,
                      error_hash=error_hash,
                      error_category="validation")
    
    def safe_performance_logging(self, operation_name, duration_ms, user_count):
        """Log performance metrics safely"""
        self.log.info("Operation performance",
                     operation=operation_name,
                     duration_ms=duration_ms,
                     affected_users=user_count,
                     success_rate=0.95)