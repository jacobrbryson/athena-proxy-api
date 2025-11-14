const express = require("express");
const proxy = require("../../../proxy/httpProxy");
const { API_TARGET } = require("../../../config");
// CRITICAL: We need to assign the required module to the GoogleAuth class
const { GoogleAuth } = require("google-auth-library");

const router = express.Router();
// We use the full API_TARGET URL as the audience for the token.
// targetUrl is mainly used for reference, but API_TARGET is used as the audience.
const auth = new GoogleAuth();

// CRITICAL: A variable to hold the Identity Token client
let tokenClient;

// Async function to initialize the token client on startup
async function initializeAuth() {
	try {
		// getIdTokenClient automatically finds credentials (Service Account) and handles refreshing tokens.
		// It uses the API_TARGET as the audience, which is required by Cloud Run.
		tokenClient = await auth.getIdTokenClient(API_TARGET);
		console.log("Authentication client initialized successfully.");
	} catch (error) {
		console.error("Failed to initialize Google Auth client:", error);
		// Crash the app if auth fails, as it cannot proceed securely.
		process.exit(1);
	}
}

// Immediately call the initialization function
initializeAuth();

router.use(async (req, res) => {
	// Check if the auth client is ready
	if (!tokenClient) {
		return res
			.status(503)
			.send(
				"Authentication client is not yet ready. Please wait a moment."
			);
	}

	let token;
	try {
		// Fetch the ID token. The client handles caching/expiry.
		token = await tokenClient.fetchIdToken(API_TARGET);
	} catch (error) {
		console.error("Failed to fetch ID token:", error);
		return res
			.status(500)
			.send(
				"Internal Server Error: Authentication failure during token fetch."
			);
	}

	// Add the Authorization header to the request before forwarding
	// Cloud Run requires the 'Bearer' prefix
	req.headers.authorization = `Bearer ${token}`;

	// Forwarding logic (now with Auth header)
	console.log("--- PROXY REQUEST START (Authenticated) ---");
	console.log(`Method: ${req.method} | Target: ${API_TARGET}${req.url}`);

	proxy.web(req, res, {
		target: API_TARGET,
		// Crucial for telling the target (Cloud Run) who the intended host is
		changeOrigin: true,
	});
});

module.exports = router;
