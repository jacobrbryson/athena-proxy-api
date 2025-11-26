const jwt = require("jsonwebtoken");
const config = require("../config");
const APP_SECRET_KEY = config.JWT_SECRET;

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

		req.user = decodedPayload;

		next();
	} catch (error) {
		console.error("JWT verification failed:", error.message);
		return res.status(401).json({ error: "Invalid or expired token." });
	}
};

module.exports = verifyAppToken;
