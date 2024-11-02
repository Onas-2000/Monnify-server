require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const sha512 = require('js-sha512').sha512;
const axios = require('axios');  // Include axios for HTTP requests

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_SECRET = process.env.MONNIFY_CLIENT_SECRET;
const MONNIFY_IP = '35.242.133.146'; // Whitelisted Monnify IP
const GOOGLE_APPS_SCRIPT_URL = 'https://script.google.com/macros/library/d/1sm7_XYK-yIwL2XW5FCggLFyPpwModEHBHKWkNP7jCcTViiqEaCqHSYwg/1'; // Replace with your actual Google Apps Script URL

// Middleware to parse JSON
app.use(bodyParser.json());

// Utility function to compute the hash
function computeHash(requestBody) {
    return sha512.hmac(CLIENT_SECRET, JSON.stringify(requestBody));
}

// Function to send data to Google Apps Script
async function postToGoogleAppsScript(data) {
    try {
        await axios.post(GOOGLE_APPS_SCRIPT_URL, data);
        console.log('Data successfully posted to Google Apps Script');
    } catch (error) {
        console.error('Error posting to Google Apps Script:', error.message);
    }
}

// Webhook route
app.post('/monnify-webhook', async (req, res) => {
    const requestBody = req.body;
    const monnifySignature = req.headers['monnify-signature'];
    const computedHash = computeHash(requestBody);

    // Verify request origin and hash
    if (req.ip !== MONNIFY_IP || computedHash !== monnifySignature) {
        return res.status(400).send('Unauthorized request');
    }

    const { eventType, eventData } = requestBody;

    // Process based on event type
    switch (eventType) {
        case 'SUCCESSFUL_TRANSACTION':
            console.log('Successful Transaction:', eventData);
            await postToGoogleAppsScript({
                transactionReference: eventData.transactionReference,
                paymentStatus: 'SUCCESSFUL',
                amountPaid: eventData.amountPaid,
                customerEmail: eventData.customer.email,
            });
            break;

        case 'FAILED_TRANSACTION':
            console.log('Failed Transaction:', eventData);
            await postToGoogleAppsScript({
                transactionReference: eventData.transactionReference,
                paymentStatus: 'FAILED',
                amountPaid: eventData.amountPaid,
                customerEmail: eventData.customer.email,
            });
            break;

        default:
            console.log('Unknown Event Type:', eventType);
    }

    // Acknowledge receipt to prevent Monnify from retrying
    res.status(200).send('Received');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
