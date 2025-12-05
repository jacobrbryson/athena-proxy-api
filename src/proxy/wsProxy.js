const jwt = require("jsonwebtoken");
const { API_TARGET, JWT_SECRET } = require("../config");

function normalizeIp(ip) {
	if (!ip) return null;
	if (ip.startsWith("::ffff:")) return ip.slice(7);
	if (ip === "::1") return "127.0.0.1";
	return ip;
}

module.exports = function wsProxy(server, proxy) {
	server.on("upgrade", async (req, socket, head) => {
		// NOTE: Use 'async' here!
		console.log(`WS upgrade: ${req.url}`);

		if (!req.url.startsWith("/ws")) {
			socket.destroy();
			return;
		}

		const authHeader =
			req.headers["x-user-authorization"] || req.headers.authorization;
		if (!authHeader || !authHeader.startsWith("Bearer ")) {
			console.warn("WS Auth: Missing bearer token");
			socket.destroy();
			return;
		}

		try {
			const token = authHeader.slice("Bearer ".length);
			const decoded = jwt.verify(token, JWT_SECRET);

			const tokenIp = normalizeIp(decoded.client_ip);
			const requestIp = normalizeIp(req.socket.remoteAddress);
			if (!tokenIp || tokenIp !== requestIp) {
				console.warn(
					`WS Auth: IP mismatch token=${tokenIp} request=${requestIp}`
				);
				socket.destroy();
				return;
			}

			// forward the validated user token to the API service
			req.headers.authorization = `Bearer ${token}`;
			req.headers["x-user-authorization"] = `Bearer ${token}`;
		} catch (error) {
			console.error("WS Auth: token verification failed", error.message);
			socket.destroy();
			return;
		}

		// Proxy the connection with the new header
		proxy.ws(req, socket, head, {
			target: API_TARGET,
			ws: true, // Crucial for telling http-proxy it's a WebSocket
			changeOrigin: true,
		});
	});
};
