const jwt = require("jsonwebtoken");
const {
	API_TARGET,
	JWT_SECRET,
	GUARDIAN_SESSION_COOKIE,
	COMPANION_SESSION_COOKIE,
} = require("../config");
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

// The rightmost X-Forwarded-For hop — see utils/clientIp. The leftmost one is
// whatever the client wrote, and was enough to pass the IP pin below.
const { trustedClientIp, normalizeIp } = require("../utils/clientIp");

/**
 * Reject an upgrade with a real HTTP response before closing. A bare
 * socket.destroy() reads as a network failure in the browser (Safari in
 * particular retry-loops on it), whereas a 401 fails fast and is visible in
 * devtools — which also makes auth issues debuggable from the field.
 */
function rejectUpgrade(socket, status, reason) {
	try {
		if (socket.writable) {
			socket.write(
				`HTTP/1.1 ${status}\r\n` +
					"Connection: close\r\n" +
					"Content-Length: 0\r\n" +
					`X-WS-Reject-Reason: ${reason}\r\n` +
					"\r\n"
			);
		}
	} catch {
		// Socket already gone — nothing to write to.
	}
	socket.destroy();
}

const PROTOCOL = "athena.v1";
const TICKET_PREFIX = "athena.ticket.";

function parseProtocols(header) {
	if (!header) return [];
	return String(header)
		.split(",")
		.map((p) => p.trim())
		.filter(Boolean);
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

		let token =
			authHeader && authHeader.startsWith("Bearer ")
				? authHeader.slice("Bearer ".length)
				: null;

		// Browsers can't set headers on a WebSocket, so the ticket rides in the
		// subprotocol list instead: new WebSocket(url, ["athena.v1",
		// "athena.ticket.<jwt>"]). Never in the URL — Cloud Run's request log
		// records every URL, and a ticket there is a credential in a log.
		const offered = parseProtocols(req.headers["sec-websocket-protocol"]);
		if (!token) {
			const entry = offered.find((p) => p.startsWith(TICKET_PREFIX));
			if (entry) token = entry.slice(TICKET_PREFIX.length);
		}

		// Fallback: Guardian session cookie (sent automatically on the upgrade
		// request by the browser when the Guardians app opens its WebSocket).
		if (!token) {
			token = getCookie(req.headers.cookie, GUARDIAN_SESSION_COOKIE);
		}

		if (!token) {
			console.warn("WS Auth: Missing bearer token");
			rejectUpgrade(socket, "401 Unauthorized", "missing-token");
			return;
		}

		try {
			const decoded = jwt.verify(token, JWT_SECRET);

			const tokenIp = normalizeIp(decoded.client_ip);
			const requestIp = trustedClientIp(req);
			if (!tokenIp || tokenIp !== requestIp) {
				console.warn(
					`WS Auth: IP mismatch token=${tokenIp} request=${requestIp}`,
				);
				rejectUpgrade(socket, "401 Unauthorized", "ip-mismatch");
				return;
			}

			// The ticket stops here. core_api answers with the plain protocol,
			// which the browser requires when it offered any.
			if (offered.length) {
				req.headers["sec-websocket-protocol"] = offered.includes(PROTOCOL) ? PROTOCOL : undefined;
				if (!req.headers["sec-websocket-protocol"]) delete req.headers["sec-websocket-protocol"];
			}

			// core_api reads the client IP from this header: hand it exactly
			// the one we verified, never the client's own.
			req.headers["x-forwarded-for"] = requestIp;

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
			rejectUpgrade(socket, "401 Unauthorized", "invalid-token");
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
