// src/utils/auth.js

const { API_TARGET } = require("../config");
const METADATA_URL =
	"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity";

// 1. Caching Variables
let cachedToken = null;
let tokenExpiry = 0; // Epoch time in milliseconds
const { OAuth2Client } = require("google-auth-library");
const config = require("../config");
const client = new OAuth2Client(config.GOOGLE_CLIENT_ID);

// Set a max cache duration (e.g., 55 minutes) to ensure a refresh buffer
const TOKEN_MAX_LIFETIME_MS = 55 * 60 * 1000;

/**
 * Fetches the Google ID token, utilizing a cache to avoid repeated metadata server calls.
 * @returns {Promise<string>} The ID token.
 */
async function getAuthToken() {
	const now = Date.now(); // 2. Check cache: If a token exists and its expiry is in the future, return it.

	if (cachedToken && now < tokenExpiry) {
		console.log("Auth: Returning cached token.");
		return cachedToken;
	} // 3. Fetch a new token if cache is empty or expired
	console.log(
		"Auth: Cache miss or expiry. Fetching new token from metadata server."
	);
	const tokenFetchUrl = `${METADATA_URL}?audience=${API_TARGET}&format=full`;

	try {
		const tokenResponse = await fetch(tokenFetchUrl, {
			headers: {
				"Metadata-Flavor": "Google",
			},
		});

		if (tokenResponse.status !== 200) {
			const errorText = await tokenResponse.text();
			throw new Error(
				`METADATA ERROR [${tokenResponse.status}]: ${errorText}`
			);
		}

		const newToken = await tokenResponse.text(); // 4. Update cache

		cachedToken = newToken;
		tokenExpiry = now + TOKEN_MAX_LIFETIME_MS; // Set new expiry time
		console.log(
			`Auth: New token fetched. Expires in ${Math.round(TOKEN_MAX_LIFETIME_MS / 60000)} minutes.`
		);
		return newToken;
	} catch (error) {
		console.error(
			"Failed to fetch ID token (Cached Auth):",
			error.message
		); // Critical: Clear cache on failure to force a fresh fetch next time
		cachedToken = null;
		tokenExpiry = 0;
		throw new Error("Authentication failure during token fetch.");
	}
}

/**
 * Helper function to verify the Google ID token.
 * @param {string} token - The JWT ID token from the frontend.
 * @returns {object|null} The verified payload, or null if verification fails.
 */
async function verifyGoogleToken(token) {
	try {
		const ticket = await client.verifyIdToken({
			idToken: token,
			audience: config.GOOGLE_CLIENT_ID,
		});
		// The payload contains user info (sub, email, name, picture, etc.)
		return ticket.getPayload();
	} catch (error) {
		console.error("Google token verification failed:", error.message);
		return null;
	}
}

module.exports = {
	getAuthToken,
	IS_CLOUD_RUN: !!process.env.K_SERVICE,
	verifyGoogleToken,
};
