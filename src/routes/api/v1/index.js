const express = require("express");
const proxy = require("../../../proxy/httpProxy");
const { API_TARGET } = require("../../../config");
// CRITICAL: We need to assign the required module to the GoogleAuth class
const { GoogleAuth } = require("google-auth-library");

const router = express.Router();
// Initialize the GoogleAuth instance once.
const auth = new GoogleAuth();

// CRITICAL: Check if we are running in a Google Cloud environment (like Cloud Run)
const IS_CLOUD_RUN = !!process.env.K_SERVICE;

router.use(async (req, res) => {
	// --- AUTHENTICATION BYPASS FOR LOCAL DEV ---
	if (!IS_CLOUD_RUN) {
		console.log(
			"--- LOCAL DEV MODE: Skipping token generation and forwarding unauthenticated request. ---"
		);
		// If local, just forward the request without the Authorization header.
		proxy.web(req, res, {
			target: API_TARGET,
			changeOrigin: true,
		});
		return;
	}
	// -------------------------------------------

	// --- CLOUD RUN MODE: Authentication Required ---
	let headers;
	try {
		// FIX: Use the stable and reliable getRequestHeaders() method.
		// This handles token generation and header formatting (Authorization: Bearer <token>)
		// in one call, eliminating the 'fetchIdToken is not a function' error.
		headers = await auth.getRequestHeaders({
			url: API_TARGET, // Use the target URL as the audience for the token
		});
	} catch (error) {
		console.error(
			"Failed to fetch ID token via getRequestHeaders:",
			error.message
		);
		// This error usually means the Service Account lacks the Token Creator role.
		return res
			.status(500)
			.send(
				"Internal Server Error: Authentication failure during token fetch. (Check Token Creator IAM Role)"
			);
	}

	// Check if the authorization header exists before assigning it.
	if (!headers.authorization) {
		// This is the error you were seeing after the TypeError was fixed,
		// confirming a hard IAM permission failure.
		console.error(
			"CRITICAL: Token generation failed. Authorization header is missing in response from GoogleAuth."
		);
		return res
			.status(500)
			.send(
				"Internal Server Error: Token generation failed. Check permissions."
			);
	}

	// Assign the retrieved header value (which is now guaranteed to be 'Authorization: Bearer <token>')
	req.headers.authorization = headers.authorization;

	// Logging the success state for debugging
	console.log(`Token Status: Authorization header successfully set.`);

	// Forwarding logic (now with Auth header)
	console.log("--- PROXY REQUEST START (Authenticated) ---");
	console.log(`Method: ${req.method} | Target: ${API_TARGET}${req.url}`);

	proxy.web(req, res, {
		target: API_TARGET,
		changeOrigin: true,
	});
});

module.exports = router;
