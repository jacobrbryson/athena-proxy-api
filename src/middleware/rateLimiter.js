const rateLimit = require("express-rate-limit");
const config = require("../config");

/**
 * A flood guard, not a usage limit: login, pairing and access have their own
 * tight limits. One Companion launch is about 40 requests, and a whole home
 * network counts as one caller (IPv6 is keyed by /56), so the ceiling has to
 * clear several launches on several devices inside one window.
 */
const rateLimiter = rateLimit({
	windowMs: config.RATE_LIMIT_WINDOW_MS,
	max: config.RATE_LIMIT_MAX_REQUESTS,
	standardHeaders: true,
	legacyHeaders: false,
	message: { success: false, message: "Too many requests. Please wait a moment and try again." },
});

module.exports = rateLimiter;
