const express = require('express');
const {expressjwt: jwt} = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const axios = require('axios');
const crypto = require('crypto');

require('dotenv').config();

// Environment variables for the API key and Admin token
const API_KEY = process.env.API_KEY;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

const app = express();

app.use(express.json({limit: '100kb'}));
// Basic Helmet setup for general security headers
app.use(helmet());

// Additional CSP for preventing XSS attacks
// Tailor the CSP according to what your specific POST API requires
app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"], // Default policy for loading content (only from the same origin)
            scriptSrc: ["'self'"], // Allow scripts execution from self origin
            objectSrc: ["'none'"], // Prevents the use of plugins (like Flash and Java)
            upgradeInsecureRequests: [], // Upgrade HTTP requests to HTTPS
        },
    })
);

app.use(compression());

// Apply rate limiting to all requests
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

app.use(limiter);

const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
    }),
    audience: process.env.AUTH0_AUDIENCE,
    issuer: `https://${process.env.AUTH0_DOMAIN}/`,
    algorithms: ['RS256']
});


// Error handling middleware
app.use((err, req, res, next) => {
    if (err.name === 'UnauthorizedError') {
        res.status(401).json({
            success: false,
            message: 'Invalid token, or no token supplied. Please make sure your request has a valid authorization token.'
        });
    } else {
        console.error(err.stack);
        res.status(500).json({
            success: false,
            message: 'An unexpected error occurred.'
        });
    }
});

// Now, add middleware to reject any request with a content-type other than 'application/json'
app.use((req, res, next) => {
    if (req.is('json')) {
        next();
    } else {
        res.status(415).send({success: false, message: 'Server only accepts application/json'});
    }
});

// Function to get the OAuth configuration based on the provider
function getOauthConfig(provider) {
    // Construct environment variable names dynamically
    const urlEnvVar = `${provider.toUpperCase()}_URL`;
    const clientIdEnvVar = `${provider.toUpperCase()}_CLIENT_ID`;
    const clientSecretEnvVar = `${provider.toUpperCase()}_CLIENT_SECRET`;
    const audienceEnvVar = `${provider.toUpperCase()}_AUDIENCE`;
    const grantTypeEnvVar = `${provider.toUpperCase()}_GRANT_TYPE`;

    // Use the constructed variable names to access the environment variables
    const config = {
        url: process.env[urlEnvVar] || `https://${provider}.your-domain.com/oauth/token`,
        clientId: process.env[clientIdEnvVar],
        clientSecret: process.env[clientSecretEnvVar],
        audience: process.env[audienceEnvVar],
        grantType: process.env[grantTypeEnvVar] || 'client_credentials'
    };

    // Check if all required configurations are available
    if (!config.clientId || !config.clientSecret) {
        throw new Error(`Missing configuration for ${provider}. Please set the environment variables appropriately.`);
    }

    return config;
}

// Generate a strong, random 64-character length API key
function generateApiKey() {
    return crypto.randomBytes(64).toString('hex');
}

function checkApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== API_KEY) {
        return res.status(401).json({ success: false, message: 'Invalid or missing API key' });
    }
    next();
}

function ensureAdmin(req, res, next) {
    const adminToken = req.headers['admin-token'];
    if (!adminToken || adminToken !== ADMIN_TOKEN) {
        return res.status(403).json({ success: false, message: 'Not authorized' });
    }
    next();
}

// Endpoint to get the token from OAuth
app.post('/get-token', checkApiKey, async (req, res) => {
    const provider = process.env.PROVIDER; // Default to 'auth0' if not specified
    const oauthConfig = getOauthConfig(provider);

    if (!oauthConfig) {
        return res.status(400).json({
            success: false,
            message: `OAuth configuration for provider '${provider}' not found.`
        });
    }

    try {
        const response = await axios.post(oauthConfig.url, {
            client_id: oauthConfig.clientId,
            client_secret: oauthConfig.clientSecret,
            audience: oauthConfig.audience,
            grant_type: oauthConfig.grantType
        });

        res.json({
            success: true,
            token: response.data.access_token
        });
    } catch (error) {
        console.log(error);
        res.status(error.response?.status || 500).json({
            success: false,
            message: error.response?.data || 'An error occurred while retrieving the token'
        });
    }
});


// Protected endpoint to generate a new API key
app.get('/generate-api-key', ensureAdmin, (req, res) => {
    const newApiKey = generateApiKey();
    res.json({ apiKey: newApiKey });
});

app.post('/concatenate', checkJwt, async (req, res, next) => {
    try {
        const {firstname, lastname} = req.body;
        if (firstname && lastname) {
            res.json({success: true, fullname: `${firstname} ${lastname}`});
        } else {
            res.status(400).json({success: false, message: 'Bad Request - firstname and lastname are required.'});
        }
    } catch (error) {
        next(error); // Pass errors to the error handling middleware
    }
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}!`);
});