const express = require("express");
// --- UPDATED IMPORT: Import jsonParser utility along with proxy ---
const { proxy, jsonParser } = require("../../../proxy/httpProxy");
const { API_TARGET } = require("../../../config");
const { getAuthToken, IS_CLOUD_RUN } = require("../../../utils/auth");
const config = require("../../../config");
const { verifyGoogleToken } = require("../../../utils/auth");
const jwt = require("jsonwebtoken");
const verifyAppToken = require("../../../middleware/auth");

const router = express.Router();

// -------------------------------------------------------------------
// 1. LOCAL AUTH ROUTE (Requires Body Parsing)
// -------------------------------------------------------------------

// Apply jsonParser middleware ONLY to this specific route.
// This populates req.body for local logic AND prepares the body for re-streaming
// via the 'onProxyReq' handler you added to httpProxy.js.
router.post("/auth/google", jsonParser, async (req, res) => {
	console.log(
		`[PROXY] Handling POST /auth/google locally and parsing body.`
	);

	// Original logic remains the same, body is now parsed
	const googleToken = req.body.token;

	if (!googleToken)
		return res
			.status(400)
			.json({ error: "Missing token in request body" });

	// NOTE: This route needs to either return the JWT or proxy a response.
	// Since it's generating a JWT, it seems it should handle the full request here.

	const googlePayload = await verifyGoogleToken(googleToken);

	if (!googlePayload)
		return res
			.status(401)
			.json({ error: "Invalid or expired Google token" });

	const { sub: google_id, email, name: full_name, picture } = googlePayload;
	const client_ip = req.ip; // trust proxy is enabled in server.js

	const appJwt = jwt.sign(
		{
			google_id,
			email,
			full_name,
			picture,
			client_ip,
		},
		config.JWT_SECRET,
		{ expiresIn: "7d" }
	);

	res.json({ jwt: appJwt });
});

// -------------------------------------------------------------------
// 2. PROXY MIDDLEWARE (Handles all other routes)
// -------------------------------------------------------------------

// This middleware runs on all subsequent requests that didn't match /auth/google
router.use(verifyAppToken);

router.use(async (req, res) => {
	// Check if req.user exists (optional, but good for clarity)
	if (req.user) {
		console.log(`Authenticated user: ${req.user.email}`);
	}

	// Preserve the original Authorization header for downstream app use
	if (req.headers.authorization) {
		req.headers["x-user-authorization"] = req.headers.authorization;
	}

	// --- AUTHENTICATION BYPASS FOR LOCAL DEV ---
	if (!IS_CLOUD_RUN) {
		console.log("--- LOCAL DEV MODE: Skipping token generation. ---");
		// No jsonParser here: The raw stream is available for all other requests.
		proxy.web(req, res, { target: API_TARGET, changeOrigin: true });
		return;
	}

	// --- CLOUD RUN MODE: Authenticated Proxying ---
	let token;
	try {
		token = await getAuthToken();
	} catch (error) {
		return res
			.status(500)
			.send("Internal Server Error: Cloud Run Authentication failure.");
	}

	req.headers.authorization = `Bearer ${token}`;

	console.log(
		`Token Status: Shared utility token successfully retrieved and set.`
	);
	console.log("--- PROXY REQUEST START (Authenticated) ---");

	proxy.web(req, res, {
		target: API_TARGET,
		changeOrigin: true,
	});
});

module.exports = router;
