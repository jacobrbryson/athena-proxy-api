const express = require("express");
const proxy = require("../../../proxy/httpProxy");
const { API_TARGET } = require("../../../config");
// GoogleAuth is not strictly needed for this debug version, but we leave the import for consistency
const { GoogleAuth } = require("google-auth-library");

const router = express.Router();
const auth = new GoogleAuth();

const IS_CLOUD_RUN = !!process.env.K_SERVICE;
const METADATA_URL =
	"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity";

router.use(async (req, res) => {
	// --- AUTHENTICATION BYPASS FOR LOCAL DEV ---
	if (!IS_CLOUD_RUN) {
		console.log("--- LOCAL DEV MODE: Skipping token generation. ---");
		proxy.web(req, res, { target: API_TARGET, changeOrigin: true });
		return;
	}
	// -------------------------------------------

	// --- CLOUD RUN MODE: Debugging Token Generation ---
	let token;
	try {
		// Construct the URL to fetch the ID token from the metadata server
		const tokenFetchUrl = `${METADATA_URL}?audience=${API_TARGET}&format=full`;

		// Attempt to fetch the token directly
		const tokenResponse = await fetch(tokenFetchUrl, {
			headers: {
				"Metadata-Flavor": "Google", // Required header for metadata server access
			},
		});

		// Check for non-200 responses (which would be an error from the metadata server)
		if (tokenResponse.status !== 200) {
			const errorText = await tokenResponse.text();
			console.error(
				`METADATA ERROR [${tokenResponse.status}]: ${errorText}`
			);
			return res
				.status(500)
				.send(
					`Internal Server Error: Metadata server token fetch failed. Status: ${tokenResponse.status}`
				);
		}

		// If successful, the body is the raw ID token
		token = await tokenResponse.text();
	} catch (error) {
		console.error("Failed to fetch ID token (Raw Fetch):", error.message);
		return res
			.status(500)
			.send(
				"Internal Server Error: Authentication failure during raw token fetch."
			);
	}

	// Check if the token was successfully retrieved
	if (!token) {
		console.error(
			"CRITICAL: Token generation failed via raw metadata server access."
		);
		return res
			.status(500)
			.send(
				"Internal Server Error: Token generation failed. Check permissions."
			);
	}

	// Assign the retrieved header value
	req.headers.authorization = `Bearer ${token}`;

	// Logging the success state for debugging
	console.log(`Token Status: Raw token successfully retrieved and set.`);

	// Forwarding logic (now with Auth header)
	console.log("--- PROXY REQUEST START (Authenticated) ---");
	proxy.web(req, res, {
		target: API_TARGET,
		changeOrigin: true,
	});
});

module.exports = router;
