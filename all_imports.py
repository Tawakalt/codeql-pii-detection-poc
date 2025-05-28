# This file ensures CodeQL analyzes all subdirectory files
import sys
import os

# Add all subdirectories to path
for root, dirs, files in os.walk('.'):
    if '__pycache__' not in root and '.git' not in root:
        sys.path.append(root)

# Import all Python files (this forces CodeQL to analyze them)
try:
    from src.python import bad_examples, good_examples
except ImportError:
    pass

try:
    from config import logging_config  
except ImportError:
    pass

# Create variables that will trigger PII detection
test_user_email = "test@example.com"
test_user_phone = "555-1234"
print(f"Test: {test_user_email}")