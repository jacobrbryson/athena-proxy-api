const express = require("express");
const proxy = require("../../../proxy/httpProxy");
const { API_TARGET } = require("../../../config");
// CRITICAL: We need to assign the required module to the GoogleAuth class
const { GoogleAuth } = require("google-auth-library");

const router = express.Router();
// Initialize the GoogleAuth instance once.
const auth = new GoogleAuth();

// READ THE SERVICE ACCOUNT EMAIL (used for local testing and explicit identity)
const PROXY_SA_EMAIL = process.env.PROXY_SA_EMAIL;
// If you are running locally, PROXY_SA_EMAIL must be set in your .env file
// and you must have run 'gcloud auth application-default login'.

router.use(async (req, res) => {
	// --- AUTHENTICATION FIX: Use getRequestHeaders for direct ID token retrieval ---
	let headers;
	try {
		// This is the simplest and most robust way to get the necessary
		// Authorization: Bearer <ID_TOKEN> header for a Cloud Run audience.
		// It handles the identity inference (SA on Cloud Run, ADC locally).
		headers = await auth.getRequestHeaders({
			url: API_TARGET,
			// Explicitly pass the Service Account Email if available.
			// This is useful for testing locally with a specific identity.
			targetPrincipal: PROXY_SA_EMAIL,
		});
	} catch (error) {
		console.error(
			"Failed to fetch ID token via getRequestHeaders:",
			error.message
		);
		// This confirms the underlying identity (local user or deployed SA)
		// lacks the Service Account Token Creator role.
		return res
			.status(500)
			.send(
				"Internal Server Error: Authentication failure during token fetch. (Check Token Creator IAM Role or local ADC)"
			);
	}

	// CRITICAL FIX: Check if the authorization header exists before assigning it.
	// If headers.authorization is undefined, it means token generation failed
	// but didn't throw an error in the try/catch block.
	if (!headers.authorization) {
		console.error(
			"CRITICAL: Token generation failed. Authorization header is missing in response from GoogleAuth."
		);
		return res
			.status(500)
			.send(
				"Internal Server Error: Token generation failed. Check permissions."
			);
	}

	// Assign the retrieved header value (which is now guaranteed to be a string)
	req.headers.authorization = headers.authorization;

	// Logging the success state for debugging
	console.log(`Token Status: Authorization header successfully set.`);

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
