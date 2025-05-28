import logging
import structlog

# Configure standard logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configure structlog (shared configuration)
from config.logging_config import setup_structlog
struct_logger = setup_structlog()

class UserService:
    def __init__(self):
        self.users = {}
        self.log = structlog.get_logger()
    
    def process_user_registration(self, user_data):
        """Example with multiple PII logging violations using both standard and structlog"""
        user_email = user_data.get('email')
        user_phone = user_data.get('phone')
        user_ssn = user_data.get('ssn')
        
        # BAD: Standard logging with PII
        logger.info(f"Processing registration for {user_email}")
        
        # BAD: Structlog with PII in structured fields
        self.log.info("User registration started", 
                     user_email=user_email, 
                     phone_number=user_phone)
        
        # BAD: Structlog with PII in message and fields
        struct_logger.info(f"Validating SSN for {user_email}",
                          ssn=user_ssn,
                          validation_step="ssn_check")
        
        # BAD: Structlog bind context with PII
        bound_logger = self.log.bind(user_email=user_email, phone=user_phone)
        bound_logger.info("Processing user data")
        
        # BAD: Structlog with nested PII data
        struct_logger.info("Registration data received",
                          user_data=user_data,  # Contains all PII
                          timestamp="2024-01-01")
        
        return {"status": "processed"}
    
    def authenticate_user(self, email, password):
        """More PII logging issues with structlog"""
        # BAD: Standard logging with email
        logger.info(f"Authentication attempt for user: {email}")
        
        # BAD: Structlog with PII parameters
        struct_logger.info("Authentication attempt",
                          email=email,
                          attempt_time="2024-01-01",
                          ip_address="192.168.1.1")
        
        # VERY BAD: Password in structlog
        self.log.debug("Credential check",
                      username=email,
                      password=password,
                      method="basic_auth")
        
        # BAD: Bind PII to logger context
        auth_logger = struct_logger.bind(user_email=email)
        auth_logger.info("Login process started")
        
        return True
    
    def update_profile(self, user_id, profile_data):
        """Complex PII logging scenarios with structlog"""
        first_name = profile_data.get('first_name')
        last_name = profile_data.get('last_name')
        address = profile_data.get('address')
        
        # BAD: Standard logging with PII
        logger.info(f"Updating profile for {first_name} {last_name}")
        
        # BAD: Structlog with individual PII fields
        struct_logger.info("Profile update initiated",
                          first_name=first_name,
                          last_name=last_name,
                          user_id=user_id)
        
        # BAD: Structlog with address data
        self.log.warning("Address validation needed",
                        address=address,
                        address_type="home")
        
        # BAD: Entire profile object in structlog
        struct_logger.debug("Full profile data",
                           profile=profile_data,
                           operation="update")
        
        # BAD: Using structlog's context binding with PII
        profile_logger = struct_logger.bind(
            full_name=f"{first_name} {last_name}",
            address=address
        )
        profile_logger.info("Profile validation completed")

def process_payment_with_structlog(card_data, amount):
    """Payment processing with structlog PII issues"""
    card_number = card_data.get('card_number')
    cvv = card_data.get('cvv')
    holder_name = card_data.get('holder_name')
    
    # BAD: Standard logging with card info
    logger.info(f"Processing payment of ${amount} for card ending in {card_number[-4:]}")
    
    # BAD: Structlog with payment PII
    struct_logger.info("Payment processing started",
                      card_number=card_number,
                      amount=amount,
                      holder_name=holder_name)
    
    # BAD: Structlog with CVV
    struct_logger.debug("Payment validation",
                       cvv=cvv,
                       card_type="visa")
    
    # BAD: Entire card data object
    struct_logger.info("Payment data received",
                      card_data=card_data,
                      merchant_id="12345")

def handle_user_error_structlog(user_email, error_details):
    """Error handling with structlog PII logging"""
    # BAD: Standard logging with email
    logger.error(f"Error occurred for user {user_email}: {error_details}")
    
    # BAD: Structlog with PII in error context
    struct_logger.error("User error occurred",
                       user_email=user_email,
                       error_message=error_details,
                       error_code="USR_001")
    
    # BAD: Bound logger with PII for error tracking
    error_logger = struct_logger.bind(affected_user=user_email)
    error_logger.error("Critical error detected", 
                      severity="high",
                      requires_investigation=True)

# Advanced structlog scenarios
def complex_structlog_scenario(user_data):
    """Complex data flows with structlog"""
    
    # Get PII from user data
    sensitive_info = {
        'email': user_data.get('email'),
        'phone': user_data.get('phone'),
        'personal_details': user_data.get('personal_details', {})
    }
    
    # BAD: Multiple levels of PII logging
    base_logger = struct_logger.bind(
        session_id="sess_123",
        user_email=sensitive_info['email']  # PII in bind
    )
    
    # BAD: Nested PII data
    base_logger.info("Processing complex user data",
                    personal_info=sensitive_info,
                    processing_stage="validation")
    
    # BAD: Loop with PII logging
    for key, value in sensitive_info.items():
        struct_logger.debug("Processing field",
                           field_name=key,
                           field_value=value)  # Could contain PII
    
    # BAD: Conditional PII logging
    if sensitive_info.get('email'):
        struct_logger.info("Email validation",
                          email_address=sensitive_info['email'],
                          validation_method="regex")

def structlog_with_custom_processor():
    """Structlog with custom processors that might leak PII"""
    
    # Create logger with custom context
    custom_logger = struct_logger.bind(
        component="user_service",
        sensitive_data="user@example.com"  # BAD: PII in context
    )
    
    # BAD: Log with PII in various ways
    custom_logger.info("Custom processing started")
    
    user_details = {
        'email': 'user@example.com',
        'phone': '555-1234',
        'metadata': {'last_login': '2024-01-01'}
    }
    
    # BAD: Using structlog's ability to log complex objects
    custom_logger.info("User details processing",
                      user_info=user_details,
                      extra_context={'source': 'database'})

# Function that gets PII from external source (same as before)
def get_user_personal_info(user_id):
    """Simulates getting PII from database"""
    return {
        'email': 'user@example.com',
        'phone': '555-123-4567',
        'ssn': '123-45-6789'
    }

def risky_structlog_function():
    """Data flow scenario - PII flows through function calls to structlog"""
    user_info = get_user_personal_info(123)
    
    # BAD: PII flows from function return to standard logging
    logger.info(f"Retrieved user info: {user_info['email']}")
    
    # BAD: PII flows to structlog
    struct_logger.info("User data retrieved",
                      email=user_info['email'],
                      phone=user_info['phone'])
    
    personal_data = user_info['phone']
    # BAD: PII assigned to variable then logged with structlog
    struct_logger.debug("Contact information",
                       contact_method="phone",
                       contact_value=personal_data)
    
    # BAD: Bind PII from function result
    user_logger = struct_logger.bind(user_email=user_info['email'])
    user_logger.info("User processing completed")