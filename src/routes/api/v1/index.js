const express = require("express");
const proxy = require("../../../proxy/httpProxy");
const { API_TARGET } = require("../../../config");
const { getAuthToken, IS_CLOUD_RUN } = require("../../../utils/auth");

const router = express.Router();

router.use(async (req, res) => {
	// --- AUTHENTICATION BYPASS FOR LOCAL DEV ---
	if (!IS_CLOUD_RUN) {
		console.log("--- LOCAL DEV MODE: Skipping token generation. ---");
		proxy.web(req, res, { target: API_TARGET, changeOrigin: true });
		return;
	} // -------------------------------------------
	// --- CLOUD RUN MODE: Authenticated Proxying ---
	let token;
	try {
		// Use the shared utility function
		token = await getAuthToken();
	} catch (error) {
		// The utility logs the error, just send the response
		return res
			.status(500)
			.send("Internal Server Error: Authentication failure.");
	} // Assign the retrieved header value

	req.headers.authorization = `Bearer ${token}`; // Logging the success state for debugging

	console.log(
		`Token Status: Shared utility token successfully retrieved and set.`
	); // Forwarding logic (now with Auth header)

	console.log("--- PROXY REQUEST START (Authenticated) ---");
	proxy.web(req, res, {
		target: API_TARGET,
		changeOrigin: true,
	});
});

module.exports = router;
