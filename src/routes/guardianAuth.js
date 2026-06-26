const express = require("express");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const config = require("../config");
const { API_TARGET } = require("../config");
const { getAuthToken, IS_CLOUD_RUN } = require("../utils/auth");

/**
 * Guardian authentication routes (Lake Norman Guardians / Rescue Ratatouille).
 *
 *   POST /auth/guardian-login   validate credentials -> set httpOnly session cookie
 *   GET  /auth/me               return the current Guardian from the cookie
 *   POST /auth/logout           clear the session cookie
 *
 * Credentials are validated against the core API (which holds the hashed
 * secrets and logs every attempt). The JWT is minted HERE so it can be bound
 * to the real client IP (mirroring the Google and child flows) and the same
 * IP-binding check in the proxy/core middleware applies. The token is stored
 * in an httpOnly, secure, sameSite cookie rather than localStorage.
 */

const router = express.Router();
const jsonParser = express.json();

const GENERIC_ERROR = "Guardian credentials not recognized.";
const SESSION_TTL_SECONDS = config.GUARDIAN_SESSION_TTL_HOURS * 3600;

/**
 * Cookie attributes. In Cloud Run (production) we serve over HTTPS and the
 * Guardians frontend lives on a different *.run.app site, so the cookie must
 * be SameSite=None; Secure to be sent on cross-site fetch / WebSocket. Locally
 * (typically same-site via a dev proxy) we use Lax and drop Secure so it works
 * over http.
 */
function cookieOptions() {
	const base = {
		httpOnly: true,
		path: "/",
		maxAge: SESSION_TTL_SECONDS * 1000,
	};
	if (IS_CLOUD_RUN) {
		return { ...base, secure: true, sameSite: "none" };
	}
	return { ...base, secure: false, sameSite: "lax" };
}

/**
 * Per-IP throttle for repeated FAILED Guardian logins. Successful logins do
 * not count against the limit (skipSuccessfulRequests), so a legitimate
 * Guardian is never locked out by their own success.
 */
const loginLimiter = rateLimit({
	windowMs: config.GUARDIAN_LOGIN_WINDOW_MS,
	max: config.GUARDIAN_LOGIN_MAX_FAILURES,
	standardHeaders: true,
	legacyHeaders: false,
	skipSuccessfulRequests: true,
	message: { success: false, message: "Too many attempts. Please wait and try again." },
});

/**
 * POST a Guardian auth request to the core API and return the guardian identity
 * (or null on any non-2xx). Shared by the password and QR-token flows — only the
 * core endpoint and body differ.
 */
async function postToCoreApi(path, body) {
	const headers = { "Content-Type": "application/json" };
	if (IS_CLOUD_RUN) {
		const serviceToken = await getAuthToken();
		headers.authorization = `Bearer ${serviceToken}`;
	}

	const resp = await fetch(`${API_TARGET}${path}`, {
		method: "POST",
		headers,
		body: JSON.stringify(body),
	});

	if (!resp.ok) return null;
	const data = await resp.json().catch(() => ({}));
	return data.guardian || null;
}

/** Call the core API to validate Guardian credentials. */
function validateAgainstCoreApi({ guardianId, guardianSecret, ip, userAgent }) {
	return postToCoreApi("/auth/guardian/validate", {
		guardian_id: guardianId,
		guardian_secret: guardianSecret,
		ip,
		user_agent: userAgent,
	});
}

/**
 * Call the core API to redeem a QR login token.
 * Returns the full response body (not just the guardian) so the route handler
 * can distinguish a redirect_to_gate response from a real auth success/failure.
 */
async function redeemTokenFromCoreApi({ token, ip, userAgent }) {
	const headers = { "Content-Type": "application/json" };
	if (IS_CLOUD_RUN) {
		const serviceToken = await getAuthToken();
		headers.authorization = `Bearer ${serviceToken}`;
	}
	const resp = await fetch(`${API_TARGET}/auth/guardian/redeem-token`, {
		method: "POST",
		headers,
		body: JSON.stringify({ token, ip, user_agent: userAgent }),
	});
	if (!resp.ok) return null;
	return resp.json().catch(() => null);
}

/**
 * Mint the Guardian session JWT (bound to the client IP) and set it as the
 * httpOnly session cookie. Shared by every successful Guardian auth path.
 */
function issueGuardianSession(res, guardian, client_ip) {
	const token = jwt.sign(
		{
			kind: "guardian",
			credential_id: guardian.credential_id,
			guardian_id: guardian.guardian_id,
			display_name: guardian.display_name,
			adventure_key: guardian.adventure_key,
			participant_type: guardian.participant_type,
			client_ip,
		},
		config.JWT_SECRET,
		{ expiresIn: SESSION_TTL_SECONDS }
	);
	res.cookie(config.GUARDIAN_SESSION_COOKIE, token, cookieOptions());
}

function sanitizeGuardian(payload) {
	return {
		credential_id: payload.credential_id,
		guardian_id: payload.guardian_id,
		display_name: payload.display_name,
		adventure_key: payload.adventure_key,
		participant_type: payload.participant_type,
	};
}

// -------------------------------------------------------------------
// POST /auth/guardian-login
// -------------------------------------------------------------------
router.post("/guardian-login", loginLimiter, jsonParser, async (req, res) => {
	if (!config.JWT_SECRET) {
		return res
			.status(500)
			.json({ success: false, message: "Server auth not configured." });
	}

	const guardianId = String(req.body?.guardian_id || "").trim();
	const guardianSecret = String(req.body?.guardian_secret || "").trim();
	const client_ip = req.ip; // trust proxy is enabled in server.js
	const userAgent = req.headers["user-agent"] || null;

	try {
		const guardian = await validateAgainstCoreApi({
			guardianId,
			guardianSecret,
			ip: client_ip,
			userAgent,
		});

		if (!guardian) {
			// Generic message — do not reveal which field was wrong.
			return res.status(401).json({ success: false, message: GENERIC_ERROR });
		}

		issueGuardianSession(res, guardian, client_ip);
		// is_first_login is transient (drives the new-vs-returning arrival
		// greeting) and deliberately NOT stored in the JWT — a page reload
		// should read as a returning session, not a first contact.
		return res.json({
			success: true,
			guardian: sanitizeGuardian(guardian),
			is_first_login: !!guardian.is_first_login,
		});
	} catch (err) {
		console.error("[PROXY] Guardian login failed:", err.message);
		return res
			.status(502)
			.json({ success: false, message: "Failed to reach Guardian network." });
	}
});

// -------------------------------------------------------------------
// POST /auth/guardian-qr-login  — redeem a single-use QR login token
// -------------------------------------------------------------------
router.post("/guardian-qr-login", loginLimiter, jsonParser, async (req, res) => {
	if (!config.JWT_SECRET) {
		return res
			.status(500)
			.json({ success: false, message: "Server auth not configured." });
	}

	const token = String(req.body?.token || "").trim();
	const client_ip = req.ip; // trust proxy is enabled in server.js
	const userAgent = req.headers["user-agent"] || null;

	try {
		const data = await redeemTokenFromCoreApi({
			token,
			ip: client_ip,
			userAgent,
		});

		if (!data) {
			return res.status(401).json({ success: false, message: GENERIC_ERROR });
		}

		// Permanent QR already used — redirect to the manual gate (no session issued).
		if (data.redirect_to_gate) {
			return res.json({
				success: false,
				redirect_to_gate: true,
				guardian_id: data.guardian_id,
			});
		}

		if (!data.guardian) {
			return res.status(401).json({ success: false, message: GENERIC_ERROR });
		}

		issueGuardianSession(res, data.guardian, client_ip);
		return res.json({
			success: true,
			guardian: sanitizeGuardian(data.guardian),
			is_first_login: !!data.guardian.is_first_login,
		});
	} catch (err) {
		console.error("[PROXY] Guardian QR login failed:", err.message);
		return res
			.status(502)
			.json({ success: false, message: "Failed to reach Guardian network." });
	}
});

// -------------------------------------------------------------------
// GET /auth/me  — who is the current Guardian?
// -------------------------------------------------------------------
router.get("/me", (req, res) => {
	const token = req.cookies?.[config.GUARDIAN_SESSION_COOKIE];
	if (!token || !config.JWT_SECRET) {
		return res.status(401).json({ success: false, message: "Not authenticated" });
	}
	try {
		const decoded = jwt.verify(token, config.JWT_SECRET);
		if (decoded.kind !== "guardian") {
			return res.status(401).json({ success: false, message: "Not authenticated" });
		}
		return res.json({ success: true, guardian: sanitizeGuardian(decoded) });
	} catch {
		return res.status(401).json({ success: false, message: "Not authenticated" });
	}
});

// -------------------------------------------------------------------
// POST /auth/logout — clear the session cookie
// -------------------------------------------------------------------
router.post("/logout", (req, res) => {
	// clearCookie must use matching attributes to actually delete the cookie.
	const { maxAge, ...clearOpts } = cookieOptions();
	res.clearCookie(config.GUARDIAN_SESSION_COOKIE, clearOpts);
	return res.json({ success: true });
});

module.exports = router;
