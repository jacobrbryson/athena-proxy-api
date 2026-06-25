const jwt = require("jsonwebtoken");
const { API_TARGET, JWT_SECRET, GUARDIAN_SESSION_COOKIE } = require("../config");
const { getAuthToken, IS_CLOUD_RUN } = require("../utils/auth");

/** Read a single cookie value from a raw Cookie header (no cookie-parser on upgrades). */
function getCookie(cookieHeader, name) {
	if (!cookieHeader) return null;
	for (const part of cookieHeader.split(";")) {
		const idx = part.indexOf("=");
		if (idx === -1) continue;
		if (part.slice(0, idx).trim() === name) {
			return decodeURIComponent(part.slice(idx + 1).trim());
		}
	}
	return null;
}

function normalizeIp(ip) {
	if (!ip) return null;
	if (ip.startsWith("::ffff:")) return ip.slice(7);
	if (ip === "::1") return "127.0.0.1";
	return ip;
}

function extractRequestIp(req) {
	const forwarded = req.headers["x-forwarded-for"];
	if (forwarded) {
		const forwardedList = Array.isArray(forwarded)
			? forwarded
			: String(forwarded)
					.split(",")
					.map((ip) => ip.trim())
					.filter(Boolean);

		const clientIp = normalizeIp(forwardedList[0] || null);
		if (clientIp) return clientIp;
	}

	return normalizeIp(req.socket.remoteAddress);
}

function redactWsUrl(reqUrl) {
	const url = new URL(reqUrl, "http://localhost");
	if (url.searchParams.has("token")) {
		url.searchParams.set("token", "[REDACTED]");
	}
	return `${url.pathname}${url.search}`;
}

module.exports = function wsProxy(server, proxy) {
	server.on("upgrade", async (req, socket, head) => {
		// NOTE: Use 'async' here!
		console.log(`WS upgrade: ${redactWsUrl(req.url)}`);

		if (!req.url.startsWith("/ws")) {
			socket.destroy();
			return;
		}

		const authHeader =
			req.headers["x-user-authorization"] || req.headers.authorization;
		const url = new URL(req.url, "http://localhost");
		const queryToken = url.searchParams.get("token");

		let token =
			authHeader && authHeader.startsWith("Bearer ")
				? authHeader.slice("Bearer ".length)
				: null;

		// Fallback: allow token via query param (since browsers can't set WS headers)
		if (!token && queryToken) {
			token = queryToken.startsWith("Bearer ")
				? queryToken.slice("Bearer ".length)
				: queryToken;
		}

		// Fallback: Guardian session cookie (sent automatically on the upgrade
		// request by the browser when the Guardians app opens its WebSocket).
		if (!token) {
			token = getCookie(req.headers.cookie, GUARDIAN_SESSION_COOKIE);
		}

		if (!token) {
			console.warn("WS Auth: Missing bearer token");
			socket.destroy();
			return;
		}

		try {
			const decoded = jwt.verify(token, JWT_SECRET);

			const tokenIp = normalizeIp(decoded.client_ip);
			const requestIp = extractRequestIp(req);
			if (!tokenIp || tokenIp !== requestIp) {
				console.warn(
					`WS Auth: IP mismatch token=${tokenIp} request=${requestIp}`,
				);
				socket.destroy();
				return;
			}

			// Preserve the validated user token for downstream app auth.
			req.headers["x-user-authorization"] = `Bearer ${token}`;

			// In Cloud Run, the upstream service also needs an invoker token.
			if (IS_CLOUD_RUN) {
				const serviceToken = await getAuthToken();
				req.headers.authorization = `Bearer ${serviceToken}`;
			} else {
				req.headers.authorization = `Bearer ${token}`;
			}
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
