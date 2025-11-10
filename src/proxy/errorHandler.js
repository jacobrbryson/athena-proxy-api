module.exports = function attachProxyErrorHandler(proxy) {
  proxy.on("error", (err, req, res) => {
    console.error("Proxy Error:", err);
		
    if (res && typeof res.writeHead === "function" && !res.headersSent) {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("Proxy Error: Could not reach API service.");
    } else {
      console.warn("Cannot send error response, 'res' is not writable.");
    }
  });
};