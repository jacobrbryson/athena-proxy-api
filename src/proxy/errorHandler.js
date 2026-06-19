module.exports = function attachProxyErrorHandler(proxy) {
	proxy.on("error", (err, req, res) => {
		console.error("Proxy Error:", err.message);

		if (res && typeof res.writeHead === "function") {
			if (!res.headersSent) {
				res.writeHead(502, { "Content-Type": "text/plain" });
			}
			res.end("Proxy Error: Could not reach API service.");
			return;
		}

		if (res && typeof res.destroy === "function") {
			res.destroy();
			return;
		}

		console.warn("Cannot send proxy error response; response target is not writable.");
	});
};
