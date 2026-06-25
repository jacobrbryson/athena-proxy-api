// Comma-separated allowlist of browser origins permitted to send credentialed
// (cookie-bearing) requests. Required for the Guardians app, which authenticates
// with an httpOnly cookie. When empty, CORS falls back to the legacy "*" (no
// credentials) behavior used by the marketing app.
const CORS_ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || "")
	.split(",")
	.map((o) => o.trim())
	.filter(Boolean);

module.exports = {
	PORT: process.env.PORT || 8080,
	API_TARGET: process.env.API_TARGET || "http://localhost:3002",
	API_AUDIENCE: process.env.API_AUDIENCE || process.env.API_TARGET || "http://localhost:3002",
	RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS || 60000,
	RATE_LIMIT_MAX_REQUESTS: process.env.RATE_LIMIT_MAX_REQUESTS || 100,
	GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || "",
	JWT_SECRET: process.env.JWT_SECRET || null,

	// --- Guardian (Lake Norman Guardians / Rescue Ratatouille) auth ---
	// Name of the httpOnly cookie that carries the Guardian session JWT.
	GUARDIAN_SESSION_COOKIE:
		process.env.GUARDIAN_SESSION_COOKIE || "guardian_session",
	// Session lifetime in hours (spec: 24h).
	GUARDIAN_SESSION_TTL_HOURS: Number(
		process.env.GUARDIAN_SESSION_TTL_HOURS || 24
	),
	// Failed-login throttling for /auth/guardian-login (per IP).
	GUARDIAN_LOGIN_WINDOW_MS: Number(
		process.env.GUARDIAN_LOGIN_WINDOW_MS || 15 * 60 * 1000
	),
	GUARDIAN_LOGIN_MAX_FAILURES: Number(
		process.env.GUARDIAN_LOGIN_MAX_FAILURES || 10
	),

	CORS_ALLOWED_ORIGINS,
};
