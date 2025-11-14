const { getAuthToken, IS_CLOUD_RUN } = require("../utils/auth");

module.exports = function wsProxy(server, proxy) {
	server.on("upgrade", async (req, socket, head) => {
		// NOTE: Use 'async' here!
		console.log(`WS upgrade: ${req.url}`);

		if (!req.url.startsWith("/ws")) {
			socket.destroy();
			return;
		} // --- AUTHENTICATION LOGIC START ---
		if (IS_CLOUD_RUN) {
			try {
				const token = await getAuthToken(); // Modify the request headers to include the ID token
				req.headers.authorization = `Bearer ${token}`;
				console.log("WS Auth: Token successfully added to headers.");
			} catch (error) {
				console.error("WS Auth Failure:", error.message); // Fail the connection if authentication fails
				socket.destroy();
				return;
			}
		} else {
			console.log("WS Auth: Skipping token generation for local dev.");
		} // --- AUTHENTICATION LOGIC END ---
		// Proxy the connection with the new header
		proxy.ws(req, socket, head);
	});
};
