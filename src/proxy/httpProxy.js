const httpProxy = require("http-proxy");
const { API_TARGET } = require("../config");
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

// --- 2. PROXY ERROR HANDLING (Optional but Recommended) ---
// Add a listener to catch errors when the proxy fails to connect to the target API
proxy.on("error", (err, req, res) => {
	console.error(
		"*** HTTP PROXY FAILED TO FORWARD REQUEST ***",
		err.message
	);
	if (!res.headersSent) {
		res.writeHead(502, { "Content-Type": "text/plain" });
		res.end("Proxy Error: Bad Gateway.");
	}
});

// Export an object containing both the proxy instance and the parser utility
module.exports = {
	proxy,
	jsonParser,
};
