module.exports = {
	PORT: process.env.PORT || 8080,
	API_TARGET: process.env.API_TARGET || "http://localhost:3001",
	RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS || 60000,
	RATE_LIMIT_MAX_REQUESTS: process.env.RATE_LIMIT_MAX_REQUESTS || 100,
	GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || "",
	JWT_SECRET: process.env.JWT_SECRET || null,
};
