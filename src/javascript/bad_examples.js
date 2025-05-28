const winston = require('winston');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.Console()
    ]
});

class UserController {
    async registerUser(userData) {
        const { email, phone, ssn } = userData;
        
        // BAD: Logging PII directly
        logger.info(`New user registration: ${email}`);
        
        // BAD: Logging phone number
        console.log(`User phone: ${phone}`);
        
        // BAD: Logging sensitive data
        logger.debug(`SSN provided: ${ssn}`);
        
        return { success: true };
    }
    
    async loginUser(credentials) {
        const { username, password } = credentials;
        
        // BAD: Logging username (could be email)
        logger.info(`Login attempt for: ${username}`);
        
        // VERY BAD: Logging password
        logger.debug(`Password: ${password}`);
        
        return { token: 'abc123' };
    }
    
    async updateUserProfile(userId, profileData) {
        // BAD: Logging entire profile object with PII
        logger.info(`Profile update: ${JSON.stringify(profileData)}`);
        
        const { firstName, lastName, address } = profileData;
        
        // BAD: Logging name components
        console.log(`Updating profile for ${firstName} ${lastName}`);
        
        // BAD: Logging address
        logger.debug(`New address: ${address}`);
    }
}

// Payment processing with PII issues
function processPayment(paymentData) {
    const { cardNumber, cvv, holderName } = paymentData;
    
    // BAD: Logging card details
    logger.info(`Processing payment for card: ${cardNumber}`);
    
    // BAD: Logging cardholder name
    console.log(`Cardholder: ${holderName}`);
    
    // BAD: Logging CVV
    logger.debug(`CVV: ${cvv}`);
}

// Error handling with PII
function handleError(userEmail, errorMessage) {
    // BAD: Including email in error logs
    logger.error(`Error for user ${userEmail}: ${errorMessage}`);
    
    // BAD: Template literal with PII
    console.error(`User error - ${userEmail} encountered: ${errorMessage}`);
}

// Data flow scenario
async function getUserData(userId) {
    return {
        email: 'user@example.com',
        personalInfo: {
            phone: '555-123-4567',
            address: '123 Main St'
        }
    };
}

async function processUserData(userId) {
    const userData = await getUserData(userId);
    
    // BAD: PII flows from function return to logging
    logger.info(`Processing data for: ${userData.email}`);
    
    const contactInfo = userData.personalInfo.phone;
    // BAD: PII assigned to variable then logged
    console.log(`Contact: ${contactInfo}`);
}

module.exports = { UserController, processPayment, handleError, processUserData };