const { CORS_ALLOWED_ORIGINS } = require("../config");

/**
 * CORS middleware.
 *
 * The marketing app authenticates with a bearer header and works fine with a
 * wildcard origin. The Guardians app authenticates with an httpOnly cookie, so
 * its requests are credentialed — and browsers reject `Access-Control-Allow-
 * Origin: *` together with credentials. For any origin in CORS_ALLOWED_ORIGINS
 * we therefore echo the specific origin and allow credentials; otherwise we
 * fall back to the legacy wildcard (no credentials).
 */
module.exports = function corsMiddleware(req, res, next) {
	const origin = req.headers.origin;

	if (origin && CORS_ALLOWED_ORIGINS.includes(origin)) {
		res.setHeader("Access-Control-Allow-Origin", origin);
		res.setHeader("Access-Control-Allow-Credentials", "true");
		res.setHeader("Vary", "Origin");
	} else {
		res.setHeader("Access-Control-Allow-Origin", "*");
	}

	res.setHeader(
		"Access-Control-Allow-Methods",
		"GET, POST, PUT, DELETE, OPTIONS"
	);
	res.setHeader(
		"Access-Control-Allow-Headers",
		"Content-Type, Authorization"
	);

	if (req.method === "OPTIONS") {
		return res.sendStatus(200);
	}

	next();
};
