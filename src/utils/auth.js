// src/utils/auth.js

const { API_TARGET } = require("../config"); // Assuming you can import config
const METADATA_URL =
	"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity";

/**
 * Fetches the Google ID token for the API_TARGET audience from the metadata server.
 * @returns {Promise<string>} The ID token.
 */
async function getAuthToken() {
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

		return tokenResponse.text();
	} catch (error) {
		console.error("Failed to fetch ID token:", error.message);
		throw new Error("Authentication failure during raw token fetch.");
	}
}

module.exports = {
	getAuthToken,
	IS_CLOUD_RUN: !!process.env.K_SERVICE,
};
