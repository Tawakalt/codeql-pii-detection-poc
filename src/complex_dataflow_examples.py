import logging
import structlog

logger = logging.getLogger(__name__)
struct_logger = structlog.get_logger()

class UserProcessor:
    """
    Complex data flow examples that CodeQL should catch
    but Semgrep might miss due to indirect flows
    """
    
    def __init__(self):
        self.user_cache = {}
    
    def process_user_registration(self, user_input):
        """
        Multi-step data flow: CodeQL should trace PII from input to logging
        """
        # Step 1: Extract PII (CodeQL source)
        extracted_data = self.extract_user_info(user_input)
        
        # Step 2: Transform through multiple functions
        processed_data = self.validate_and_transform(extracted_data)
        
        # Step 3: Log the result (CodeQL sink)
        self.log_processing_result(processed_data)
    
    def extract_user_info(self, raw_data):
        """Extract sensitive information from raw input"""
        return {
            'contact': raw_data.get('email'),  # PII flows here
            'identifier': raw_data.get('ssn'),  # PII flows here
            'communication': raw_data.get('phone')  # PII flows here
        }
    
    def validate_and_transform(self, user_info):
        """
        Transform data through multiple steps
        CodeQL should track PII flow, Semgrep won't see variable names as suspicious
        """
        validation_result = {}
        
        # Indirect PII flow - variable names don't look suspicious
        contact_method = user_info.get('contact')
        unique_id = user_info.get('identifier')
        comm_channel = user_info.get('communication')
        
        if contact_method:
            validation_result['primary_contact'] = contact_method
        if unique_id:
            validation_result['user_identifier'] = unique_id
        if comm_channel:
            validation_result['notification_channel'] = comm_channel
            
        return validation_result
    
    def log_processing_result(self, result):
        """
        Final logging - CodeQL should detect PII flow to here
        Semgrep won't detect because variable names are generic
        """
        # This logging contains PII but Semgrep can't tell from variable names
        logging.info(f"User processing completed: {result}")
        
        # Log individual fields with generic names
        for field_name, field_value in result.items():
            logger.debug(f"Processed {field_name}: {field_value}")

def complex_inheritance_flow():
    """
    Test complex object-oriented PII flows
    """
    class PersonalData:
        def __init__(self, email, ssn):
            self.contact_info = email  # PII stored with different name
            self.gov_id = ssn         # PII stored with different name
    
    class DataProcessor:
        def process(self, personal_data):
            # Extract with generic variable names
            contact = personal_data.contact_info
            identifier = personal_data.gov_id
            
            # Log with generic context - CodeQL should still detect
            self.log_results(contact, identifier)
        
        def log_results(self, contact, identifier):
            logging.info(f"Processing contact: {contact}")
            logging.info(f"Validating ID: {identifier}")
    
    # Flow PII through the system
    data = PersonalData("complex@example.com", "999-88-7777")
    processor = DataProcessor()
    processor.process(data)  # CodeQL should trace this flow

def obfuscated_logging_patterns():
    """
    Test cases that challenge pattern-based detection
    """
    # Dynamic attribute access
    sensitive_data = type('Data', (), {
        'user_contact': 'hidden@email.com',
        'tax_id': '555-44-3333'
    })()
    
    # Get attribute dynamically
    contact_attr = 'user_contact'
    id_attr = 'tax_id'
    
    contact_value = getattr(sensitive_data, contact_attr)
    id_value = getattr(sensitive_data, id_attr)
    
    # Log with no obvious PII variable names
    logging.info(f"Retrieved value: {contact_value}")
    logging.info(f"Validation data: {id_value}")
    
    # Dictionary iteration with PII
    sensitive_fields = {
        'primary_contact': 'dict@example.com',
        'government_id': '777-66-5555',
        'communication_number': '555-0199'
    }
    
    # Log all fields - hard for pattern matching to detect
    for key, value in sensitive_fields.items():
        logging.debug(f"Field {key} contains: {value}")

if __name__ == "__main__":
    # Test data
    test_user_input = {
        'email': 'complex.flow@company.com',
        'ssn': '123-45-6789',
        'phone': '+1-555-123-4567'
    }
    
    processor = UserProcessor()
    processor.process_user_registration(test_user_input)
    
    complex_inheritance_flow()
    obfuscated_logging_patterns()