const { trustedClientIp } = require("./clientIp");
const { proxy } = require("../proxy/httpProxy");

describe("trustedClientIp", () => {
	it("takes the hop Google appended, not what the client wrote", () => {
		// Client sent "X-Forwarded-For: 9.9.9.9" (a victim's IP); Cloud Run
		// appended the address it actually saw.
		expect(trustedClientIp({ headers: { "x-forwarded-for": "9.9.9.9, 203.0.113.7" } })).toBe("203.0.113.7");
	});

	it("is the only hop when the client sent none", () => {
		expect(trustedClientIp({ headers: { "x-forwarded-for": "203.0.113.7" } })).toBe("203.0.113.7");
	});

	it("falls back to the socket peer, normalized", () => {
		expect(trustedClientIp({ headers: {}, socket: { remoteAddress: "::ffff:10.0.0.5" } })).toBe("10.0.0.5");
		expect(trustedClientIp({ headers: {}, socket: { remoteAddress: "::1" } })).toBe("127.0.0.1");
	});
});

describe("forwarding to core_api", () => {
	function forward(req) {
		const headers = { "x-forwarded-for": req.headers["x-forwarded-for"] };
		const proxyReq = {
			setHeader: (k, v) => (headers[k.toLowerCase()] = v),
			removeHeader: (k) => delete headers[k.toLowerCase()],
			write: () => {},
			end: () => {},
		};
		proxy.emit("proxyReq", proxyReq, req, {}, {});
		return headers["x-forwarded-for"];
	}

	it("replaces the client's X-Forwarded-For with the one trusted address", () => {
		expect(forward({ ip: "203.0.113.7", method: "GET", headers: { "x-forwarded-for": "9.9.9.9, 203.0.113.7" } })).toBe(
			"203.0.113.7"
		);
	});

	it("uses the same rule when Express has no req.ip", () => {
		expect(forward({ method: "GET", headers: { "x-forwarded-for": "9.9.9.9, 203.0.113.7" } })).toBe("203.0.113.7");
	});
});
