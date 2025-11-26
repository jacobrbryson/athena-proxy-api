const express = require("express");
const proxy = require("../../../proxy/httpProxy");
const { API_TARGET } = require("../../../config");
const { getAuthToken, IS_CLOUD_RUN } = require("../../../utils/auth");
const config = require("../../../config");
const { verifyGoogleToken } = require("../../../utils/auth");
const jwt = require("jsonwebtoken");
const verifyAppToken = require("../../../middleware/auth");

const router = express.Router();

router.post("/auth/google", async (req, res) => {
	const googleToken = req.body.token;

	if (!googleToken)
		return res
			.status(400)
			.json({ error: "Missing token in request body" });

	const googlePayload = await verifyGoogleToken(googleToken);

	if (!googlePayload)
		return res
			.status(401)
			.json({ error: "Invalid or expired Google token" });

	const { sub: googleId, email } = googlePayload;

	const appJwt = jwt.sign(
		{
			googleId: googleId,
			email: email,
		},
		config.JWT_SECRET,
		{ expiresIn: "7d" }
	);

	res.json({ jwt: appJwt });
});

router.use(verifyAppToken);

router.use(async (req, res) => {
	// Check if req.user exists (optional, but good for clarity)
	if (req.user) {
		console.log(`Authenticated user: ${req.user.email}`);
	}

	// --- AUTHENTICATION BYPASS FOR LOCAL DEV ---
	if (!IS_CLOUD_RUN) {
		console.log("--- LOCAL DEV MODE: Skipping token generation. ---");
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
