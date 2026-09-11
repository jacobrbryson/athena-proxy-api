const express = require("express");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const config = require("../config");
const { verifyGoogleToken, getAuthToken, IS_CLOUD_RUN } = require("../utils/auth");

/**
 * Companion app authentication (Google sign-in, httpOnly cookie).
 *
 *   POST /auth/companion/google      Google ID token -> session cookie
 *   GET  /auth/companion/me          current user from the cookie
 *   GET  /auth/companion/ws-ticket   60s WebSocket ticket (Safari/ITP-safe)
 *   POST /auth/companion/logout      clear the cookie
 *
 * Mirrors the Guardian cookie flow (see guardianAuth.js): the JWT is minted
 * here, bound to the client IP, and carries the SAME claims as the marketing
 * app's bearer JWT (google_id, email, full_name, picture) — so core_api treats
 * a Companion user exactly like a signed-in parent, with no new identity type.
 * It lives in its own cookie so being signed into both the Guardians app and
 * Companion in one browser never mixes identities; the client says which app
 * it is with `X-Athena-Client: companion`.
 */

const router = express.Router();
const jsonParser = express.json();

const SESSION_TTL_SECONDS = config.COMPANION_SESSION_TTL_HOURS * 3600;
const WS_TICKET_TTL_SECONDS = 60;

function cookieOptions() {
	const base = { httpOnly: true, path: "/", maxAge: SESSION_TTL_SECONDS * 1000 };
	return IS_CLOUD_RUN
		? { ...base, secure: true, sameSite: "none" }
		: { ...base, secure: false, sameSite: "lax" };
}

const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 30,
	standardHeaders: true,
	legacyHeaders: false,
	skipSuccessfulRequests: true,
	message: { success: false, message: "Too many attempts. Please wait and try again." },
});

function publicUser(p) {
	return { email: p.email || null, full_name: p.full_name || null, picture: p.picture || null };
}

function readSession(req) {
	const token = req.cookies?.[config.COMPANION_SESSION_COOKIE];
	if (!token || !config.JWT_SECRET) return null;
	try {
		const decoded = jwt.verify(token, config.JWT_SECRET);
		return decoded.app === "companion" && decoded.google_id ? decoded : null;
	} catch {
		return null;
	}
}

router.post("/companion/google", loginLimiter, jsonParser, async (req, res) => {
	if (!config.JWT_SECRET || !config.GOOGLE_CLIENT_ID) {
		return res.status(500).json({ success: false, message: "Server auth not configured." });
	}
	const googleToken = typeof req.body?.credential === "string" ? req.body.credential : null;
	if (!googleToken) return res.status(400).json({ success: false, message: "Missing Google credential" });

	const payload = await verifyGoogleToken(googleToken);
	if (!payload || payload.email_verified !== true) return res.status(401).json({ success: false, message: "A verified Google email is required." });

	const { sub: google_id, email, name: full_name, picture } = payload;
	const token = jwt.sign(
		{ app: "companion", google_id, email, email_verified: true, full_name, picture, client_ip: req.ip },
		config.JWT_SECRET,
		{ expiresIn: SESSION_TTL_SECONDS }
	);
	// Audit at sign-in itself, even if the visitor never loads the frontend.
	// A DB/API outage must not produce an unlogged usable session.
	let access;
	try {
		const headers = { "x-user-authorization": `Bearer ${token}`, "x-forwarded-for": req.ip };
		if (IS_CLOUD_RUN) headers.authorization = `Bearer ${await getAuthToken()}`;
		const upstream = await fetch(`${config.API_TARGET}/access`, { headers, signal: AbortSignal.timeout(10000) });
		if (!upstream.ok) throw new Error("Access verification failed");
		access = await upstream.json();
		if (typeof access.allowed !== "boolean") throw new Error("Invalid access response");
	} catch {
		return res.status(503).json({ success: false, message: "Access verification is unavailable. Please retry." });
	}
	res.cookie(config.COMPANION_SESSION_COOKIE, token, cookieOptions());
	return res.json({ success: true, user: publicUser({ email, full_name, picture }), access });
});

router.get("/companion/me", (req, res) => {
	const s = readSession(req);
	if (!s) return res.status(401).json({ success: false, message: "Not authenticated" });
	return res.json({ success: true, user: publicUser(s) });
});

router.get("/companion/ws-ticket", (req, res) => {
	const s = readSession(req);
	if (!s) return res.status(401).json({ success: false, message: "Not authenticated" });
	const ticket = jwt.sign(
		{
			app: "companion",
			purpose: "ws",
			google_id: s.google_id,
			email: s.email,
			email_verified: s.email_verified === true,
			full_name: s.full_name,
			picture: s.picture,
			client_ip: req.ip,
		},
		config.JWT_SECRET,
		{ expiresIn: WS_TICKET_TTL_SECONDS }
	);
	return res.json({ success: true, ticket, expires_in: WS_TICKET_TTL_SECONDS });
});

router.post("/companion/logout", (req, res) => {
	const { maxAge, ...clearOpts } = cookieOptions();
	res.clearCookie(config.COMPANION_SESSION_COOKIE, clearOpts);
	return res.json({ success: true });
});

module.exports = router;
