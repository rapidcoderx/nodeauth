const express = require('express');
const bodyParser = require('body-parser');
const {expressjwt: jwt} = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');

require('dotenv').config();

const app = express();

app.use(bodyParser.json({limit: '100kb'}));
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