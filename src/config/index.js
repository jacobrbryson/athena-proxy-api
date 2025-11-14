module.exports = {
	PROXY_PORT: process.env.PROXY_PORT || 3000,
	API_TARGET: process.env.API_TARGET || "http://localhost:3001",
	RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS || 60000,
	RATE_LIMIT_MAX_REQUESTS: process.env.RATE_LIMIT_MAX_REQUESTS || 100,
};
