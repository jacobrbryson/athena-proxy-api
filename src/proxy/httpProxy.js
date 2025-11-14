const httpProxy = require("http-proxy");
const { API_TARGET } = require("../config");

const proxy = httpProxy.createProxyServer({
	target: API_TARGET,
	ws: true,
});

proxy.on("error", (err, req, res) => {
	console.error("*** PROXY FAILED TO FORWARD ***");
	console.error(`Error for request: ${req.method} ${req.url}`);
	console.error("Error details:", err.message);

	// Important: If the error happens before sending headers, you must send a response
	if (!res.headersSent) {
		res.writeHead(500, { "Content-Type": "text/plain" });
		res.end("Proxy Error: Could not reach target API.");
	}
});

module.exports = proxy;
