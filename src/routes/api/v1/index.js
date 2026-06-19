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
// 1b. CHILD LOGIN ROUTE (QR / friendly-code redemption)
// -------------------------------------------------------------------
// Validates the child's login code against the core API, then mints a
// child session JWT. Issued here (not in core_api) so the token is bound
// to the real client IP, mirroring the Google flow above.
router.post("/auth/child", jsonParser, async (req, res) => {
	const code = req.body?.code;
	if (!code) {
		return res.status(400).json({ error: "Missing login code" });
	}

	const client_ip = req.ip; // trust proxy is enabled in server.js

	try {
		const headers = { "Content-Type": "application/json" };
		// In Cloud Run the core API requires service-to-service auth.
		if (IS_CLOUD_RUN) {
			const serviceToken = await getAuthToken();
			headers.authorization = `Bearer ${serviceToken}`;
		}

		const validateResp = await fetch(`${API_TARGET}/auth/child/validate`, {
			method: "POST",
			headers,
			body: JSON.stringify({ code }),
		});

		if (!validateResp.ok) {
			const data = await validateResp.json().catch(() => ({}));
			return res
				.status(401)
				.json({ error: data.message || "Invalid login code" });
		}

		const { child } = await validateResp.json();

		const appJwt = jwt.sign(
			{
				kind: "child",
				profile_uuid: child.profile_uuid,
				child_profile_id: child.child_profile_id,
				family_id: child.family_id,
				display_name: child.display_name,
				client_ip,
			},
			config.JWT_SECRET,
			{ expiresIn: "30d" }
		);

		res.json({
			jwt: appJwt,
			child: {
				profile_uuid: child.profile_uuid,
				child_uuid: child.child_uuid,
				display_name: child.display_name,
			},
		});
	} catch (err) {
		console.error("[PROXY] Child auth failed:", err.message);
		res.status(500).json({ error: "Child authentication failed" });
	}
});

// -------------------------------------------------------------------
// 1c. FAMILY CHORES PARTNER ENDPOINTS (public, server-to-server)
// -------------------------------------------------------------------
// The Family Chores backend calls connect / disconnect / suggest-chores with
// its own API token + the shared partner secret (X-Partner-Key). These are
// authorized by that secret, not by an Athena user JWT, so they are declared
// before verifyAppToken. We forward to the core API, attaching the Cloud Run
// service token when running in Cloud Run (mirrors the child-auth flow above).
function forwardPartnerRequest(path) {
	return async (req, res) => {
		try {
			const headers = { "Content-Type": "application/json" };
			// Forward the partner secret so core_api can authorize the request.
			if (req.headers["x-partner-key"]) {
				headers["x-partner-key"] = req.headers["x-partner-key"];
			}
			if (IS_CLOUD_RUN) {
				const serviceToken = await getAuthToken();
				headers.authorization = `Bearer ${serviceToken}`;
			}

			const upstream = await fetch(`${API_TARGET}${path}`, {
				method: "POST",
				headers,
				body: JSON.stringify(req.body || {}),
			});

			const data = await upstream.json().catch(() => ({}));
			return res.status(upstream.status).json(data);
		} catch (err) {
			console.error(`[PROXY] Family Chores ${path} failed:`, err.message);
			return res
				.status(502)
				.json({ success: false, message: "Failed to reach Athena API" });
		}
	};
}

router.post(
	"/integrations/family-chores/connect",
	jsonParser,
	forwardPartnerRequest("/integrations/family-chores/connect")
);
router.post(
	"/integrations/family-chores/disconnect",
	jsonParser,
	forwardPartnerRequest("/integrations/family-chores/disconnect")
);
router.post(
	"/integrations/family-chores/suggest-chores",
	jsonParser,
	forwardPartnerRequest("/integrations/family-chores/suggest-chores")
);
router.post(
	"/integrations/family-chores/suggest-ghost-chores",
	jsonParser,
	forwardPartnerRequest("/integrations/family-chores/suggest-ghost-chores")
);
router.post(
	"/integrations/family-chores/remember",
	jsonParser,
	forwardPartnerRequest("/integrations/family-chores/remember")
);
router.post(
	"/integrations/family-chores/children",
	jsonParser,
	forwardPartnerRequest("/integrations/family-chores/children")
);
router.post(
	"/integrations/family-chores/connect-child",
	jsonParser,
	forwardPartnerRequest("/integrations/family-chores/connect-child")
);
router.post(
	"/integrations/family-chores/disconnect-child",
	jsonParser,
	forwardPartnerRequest("/integrations/family-chores/disconnect-child")
);

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
