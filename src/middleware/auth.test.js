process.env.JWT_SECRET = "test-secret";
const jwt = require("jsonwebtoken");
const verifyAppToken = require("./auth");

function run(req) {
	const res = {
		statusCode: 200,
		body: null,
		status(c) {
			this.statusCode = c;
			return this;
		},
		json(b) {
			this.body = b;
			return this;
		},
	};
	let nextCalled = false;
	req.headers ||= {};
	req.cookies ||= {};
	req.ip ||= "1.2.3.4";
	verifyAppToken(req, res, () => (nextCalled = true));
	return { res, nextCalled };
}

const sign = (claims) => jwt.sign({ client_ip: "1.2.3.4", ...claims }, "test-secret");

describe("verifyAppToken", () => {
	test("Companion requests use the companion cookie even when a guardian cookie exists", () => {
		const req = {
			headers: { "x-athena-client": "companion" },
			cookies: {
				guardian_session: sign({ kind: "guardian", guardian_id: "12345678" }),
				companion_session: sign({ app: "companion", google_id: "g-1" }),
			},
		};
		const { nextCalled } = run(req);
		expect(nextCalled).toBe(true);
		expect(req.user).toMatchObject({ app: "companion", google_id: "g-1" });
	});

	test("Guardians requests keep using the guardian cookie", () => {
		const req = {
			cookies: {
				guardian_session: sign({ kind: "guardian", guardian_id: "12345678" }),
				companion_session: sign({ app: "companion", google_id: "g-1" }),
			},
		};
		run(req);
		expect(req.user).toMatchObject({ kind: "guardian" });
	});

	test("well-formed device tokens pass through for core_api to verify", () => {
		const req = { headers: { "x-athena-device-token": `athd_${"a".repeat(43)}` } };
		const { nextCalled } = run(req);
		expect(nextCalled).toBe(true);
		expect(req.user).toEqual({ kind: "device" });
	});

	test("malformed device tokens are rejected at the proxy", () => {
		const { res, nextCalled } = run({ headers: { "x-athena-device-token": "not-a-device-token" } });
		expect(nextCalled).toBe(false);
		expect(res.statusCode).toBe(401);
	});

	test("the IP pin still applies to cookie JWTs", () => {
		const req = { ip: "9.9.9.9", cookies: { companion_session: sign({ app: "companion", google_id: "g-1" }) }, headers: { "x-athena-client": "companion" } };
		const { res, nextCalled } = run(req);
		expect(nextCalled).toBe(false);
		expect(res.statusCode).toBe(401);
	});
});
