import logging
import structlog

# Configure standard logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Simple structlog setup (no external config needed)
structlog.configure()
struct_logger = structlog.get_logger()

class UserService:
    def __init__(self):
        self.users = {}
        self.log = structlog.get_logger()
    
    def process_user_registration(self, user_data):
        """Example with multiple PII logging violations"""
        user_email = user_data.get('email')
        user_phone = user_data.get('phone')
        user_ssn = user_data.get('ssn')
        
        # BAD: Standard logging with PII
        logger.info(f"Processing registration for {user_email}")
        logger.debug(f"User phone number: {user_phone}")
        logger.error(f"Validation failed for SSN: {user_ssn}")
        
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
        
        return {"status": "processed"}
    
    def authenticate_user(self, email, password):
        """More PII logging issues"""
        # BAD: Standard logging with email
        logger.info(f"Authentication attempt for user: {email}")
        
        # BAD: Structlog with PII parameters
        struct_logger.info("Authentication attempt",
                          email=email,
                          attempt_time="2024-01-01")
        
        # BAD: Password in structlog
        self.log.debug("Credential check",
                      username=email,
                      password=password)
        
        return True

def process_payment_with_structlog(card_data, amount):
    """Payment processing with structlog PII issues"""
    card_number = card_data.get('card_number')
    cvv = card_data.get('cvv')
    holder_name = card_data.get('holder_name')
    
    # BAD: Structlog with payment PII
    struct_logger.info("Payment processing started",
                      card_number=card_number,
                      amount=amount,
                      holder_name=holder_name)
    
    # BAD: Structlog with CVV
    struct_logger.debug("Payment validation",
                       cvv=cvv,
                       card_type="visa")

# Function that gets PII from external source
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