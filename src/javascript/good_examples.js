const winston = require('winston');
const crypto = require('crypto');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.Console()
    ]
});

class SecureUserController {
    async registerUser(userData) {
        const userId = userData.id;
        
        // GOOD: Using non-PII identifier
        logger.info(`New user registration - ID: ${userId}`);
        
        // GOOD: Logging success without PII
        logger.info('User registration completed successfully');
        
        return { success: true };
    }
    
    async loginUser(credentials) {
        const { username } = credentials;
        
        // GOOD: Hash username for logging
        const userHash = crypto.createHash('sha256').update(username).digest('hex').substring(0, 8);
        logger.info(`Login attempt for user hash: ${userHash}`);
        
        // GOOD: Log outcome without credentials
        const success = await this.verifyCredentials(credentials);
        logger.info(`Login ${success ? 'successful' : 'failed'}`);
        
        return { token: success ? 'abc123' : null };
    }
    
    async verifyCredentials(credentials) {
        // Simplified verification
        return true;
    }
    
    async updateUserProfile(userId, profileData) {
        // GOOD: Use user ID instead of PII
        logger.info(`Profile update initiated for user: ${userId}`);
        
        // GOOD: Log field names being updated, not values
        const updatedFields = Object.keys(profileData);
        logger.info(`Updating fields: ${updatedFields.join(', ')}`);
        
        // GOOD: Log completion without PII
        logger.info('Profile update completed successfully');
    }
}

// Safe payment processing
function processPaymentSecurely(paymentData) {
    const { amount, paymentMethodId } = paymentData;
    
    // GOOD: Use payment method ID instead of card details
    logger.info(`Processing payment: $${amount} via method ${paymentMethodId}`);
    
    // GOOD: Log transaction success
    logger.info(`Payment transaction completed - Amount: $${amount}`);
}

// Safe error handling
function handleErrorSecurely(userId, errorCode) {
    // GOOD: Use user ID and error codes
    logger.error(`Error ${errorCode} for user ID: ${userId}`);
    
    // GOOD: Log error patterns for debugging
    logger.warning(`Error pattern detected: ${errorCode}`);
}

// Utility functions
function maskEmail(email) {
    if (email.includes('@')) {
        const [local, domain] = email.split('@');
        const maskedLocal = local.substring(0, 2) + '*'.repeat(local.length - 2);
        return `${maskedLocal}@${domain}`;
    }
    return 'invalid_email';
}

function hashUserId(userId) {
    return crypto.createHash('sha256').update(userId.toString()).digest('hex').substring(0, 8);
}

module.exports = { 
    SecureUserController, 
    processPaymentSecurely, 
    handleErrorSecurely,
    maskEmail,
    hashUserId
};