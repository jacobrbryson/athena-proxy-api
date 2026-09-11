const jwt = require("jsonwebtoken");
const config = require("../config");
const APP_SECRET_KEY = config.JWT_SECRET;

function normalizeIp(ip) {
	if (!ip) return null;
	if (ip.startsWith("::ffff:")) return ip.slice(7);
	if (ip === "::1") return "127.0.0.1";
	return ip;
}

/**
 * Which session cookie to use for a cookie-authenticated request. Each app
 * that authenticates by cookie has its own, so a browser signed into both the
 * Guardians app and Companion never mixes identities: the Companion client
 * identifies itself with `X-Athena-Client: companion`.
 */
function sessionCookieToken(req) {
	const cookies = req.cookies || {};
	if (req.headers["x-athena-client"] === "companion") {
		return cookies[config.COMPANION_SESSION_COOKIE] || null;
	}
	return cookies[config.GUARDIAN_SESSION_COOKIE] || cookies[config.COMPANION_SESSION_COOKIE] || null;
}

/**
 * Middleware to verify the custom application JWT.
 * It ensures the user is authenticated with a valid token issued by the proxy.
 */
const verifyAppToken = (req, res, next) => {
	const authHeader = req.headers.authorization;

	// Primary: bearer header (marketing app, service-to-service).
	// Fallback: app session cookie (the Guardians and Companion apps keep their
	// JWT in an httpOnly cookie, so the browser can't attach a header).
	let token =
		authHeader && authHeader.startsWith("Bearer ")
			? authHeader.split(" ")[1]
			: null;

	if (!token) {
		const cookieToken = sessionCookieToken(req);
		if (cookieToken) {
			token = cookieToken;
			// Re-expose as a bearer header so the downstream forwarding logic
			// (copy to x-user-authorization) treats it like any other token.
			req.headers.authorization = `Bearer ${token}`;
		}
	}

	// Paired devices (phone / car) send an opaque device token instead of an
	// IP-pinned JWT — phones change IPs constantly. It is forwarded untouched;
	// core_api verifies it against paired_device (hash lookup, revocable) on
	// every request, and only on routes that explicitly accept devices.
	if (!token) {
		const deviceToken = req.headers["x-athena-device-token"];
		if (typeof deviceToken === "string" && /^athd_[A-Za-z0-9_-]{20,200}$/.test(deviceToken)) {
			req.user = { kind: "device" };
			return next();
		}
	}

	if (!token) {
		return res.status(401).json({ error: "Access denied. JWT required." });
	}

	try {
		const decodedPayload = jwt.verify(token, APP_SECRET_KEY);

		const tokenIp = normalizeIp(decodedPayload.client_ip);
		const requestIp = normalizeIp(req.ip);
		if (!tokenIp || tokenIp !== requestIp) {
			return res
				.status(401)
				.json({ error: "IP mismatch for provided token." });
		}

		req.user = decodedPayload;

		next();
	} catch (error) {
		console.error("JWT verification failed:", error.message);
		return res.status(401).json({ error: "Invalid or expired token." });
	}
};

module.exports = verifyAppToken;
