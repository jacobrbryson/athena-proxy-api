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
 * Middleware to verify the custom application JWT.
 * It ensures the user is authenticated with a valid token issued by the proxy.
 */
const verifyAppToken = (req, res, next) => {
	const authHeader = req.headers.authorization;

	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		return res.status(401).json({ error: "Access denied. JWT required." });
	}

	const token = authHeader.split(" ")[1];

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
