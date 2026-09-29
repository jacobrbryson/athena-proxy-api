/**
 * The caller's real IP, and the only X-Forwarded-For core_api ever sees.
 *
 * Cloud Run's front end APPENDS the address it received the connection from
 * to whatever X-Forwarded-For the client sent. So the rightmost entry is the
 * one Google vouches for, and everything to its left is whatever the client
 * chose to write — including somebody else's IP. That is what
 * `app.set("trust proxy", 1)` means for req.ip, and it is the rule here too.
 *
 * Reading the LEFTMOST entry (as the WebSocket check and core_api did) let a
 * client claim any IP it liked: enough to pass the IP pin on a stolen token,
 * or to read an anonymous session "from" its owner's address.
 *
 * The proxy is the only way in (core_api is invoker-only), so it strips the
 * client's header and forwards exactly one trusted address. core_api's own
 * front end then appends the proxy's address after it, and its leftmost entry
 * is this one.
 */

function normalizeIp(ip) {
	if (!ip) return null;
	const s = String(ip).trim();
	if (s.startsWith("::ffff:")) return s.slice(7);
	if (s === "::1") return "127.0.0.1";
	return s || null;
}

/**
 * The trusted client IP for any request — Express or a raw upgrade request.
 * Mirrors trust proxy 1: the last X-Forwarded-For hop, else the socket peer.
 */
function trustedClientIp(req) {
	const header = req.headers?.["x-forwarded-for"];
	if (header) {
		const hops = (Array.isArray(header) ? header.join(",") : String(header))
			.split(",")
			.map((ip) => ip.trim())
			.filter(Boolean);
		const last = normalizeIp(hops[hops.length - 1]);
		if (last) return last;
	}
	return normalizeIp(req.socket?.remoteAddress);
}

module.exports = { trustedClientIp, normalizeIp };
