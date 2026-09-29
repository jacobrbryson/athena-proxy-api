const httpProxy = require("http-proxy");
const { API_TARGET } = require("../config");
const { trustedClientIp } = require("../utils/clientIp");
const bodyParser = require("body-parser"); // <-- Make sure to install: npm install body-parser

const proxy = httpProxy.createProxyServer({
	target: API_TARGET,
	ws: true,
});

// Create a parser instance to be used by the router (e.g., for /auth/google)
const jsonParser = bodyParser.json();

// --- 1. PROXY REQUEST MODIFICATION (The POST Body Fix) ---
// This handles requests where the body was read by the jsonParser
// in the router (like /auth/google) and re-inserts the data into the stream.
proxy.on("proxyReq", (proxyReq, req, res, options) => {
	// core_api reads the client IP from X-Forwarded-For. Forward only the
	// address Google vouched for (req.ip under trust proxy 1) — never the
	// entries the client wrote itself. See utils/clientIp.
	const clientIp = req.ip || trustedClientIp(req);
	if (clientIp) proxyReq.setHeader("x-forwarded-for", clientIp);
	else proxyReq.removeHeader("x-forwarded-for");

	// Check if the request has a parsed body and is a method that needs one
	if (
		req.body &&
		(req.method === "POST" ||
			req.method === "PUT" ||
			req.method === "PATCH")
	) {
		// Serialize the body back into a JSON string
		const bodyData = JSON.stringify(req.body);

		// Update the headers for the outgoing request
		proxyReq.setHeader("Content-Type", "application/json");
		proxyReq.setHeader("Content-Length", Buffer.byteLength(bodyData));

		// Write the body data to the new request stream and end it
		proxyReq.write(bodyData);
		proxyReq.end();
	}
});

// Export an object containing both the proxy instance and the parser utility
module.exports = {
	proxy,
	jsonParser,
};
