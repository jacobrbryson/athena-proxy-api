const http = require("http");
const express = require("express");

function serve(max) {
	process.env.RATE_LIMIT_MAX_REQUESTS = String(max);
	let rateLimiter;
	jest.isolateModules(() => {
		rateLimiter = require("./rateLimiter");
	});
	const app = express();
	app.use(rateLimiter);
	app.get("/", (req, res) => res.json({ ok: true }));
	return new Promise((resolve) => {
		const server = http.createServer(app).listen(0, "127.0.0.1", () => resolve(server));
	});
}

afterEach(() => {
	delete process.env.RATE_LIMIT_MAX_REQUESTS;
});

it("clears three Companion launches inside one window", () => {
	let config;
	jest.isolateModules(() => {
		config = require("../config");
	});
	expect(config.RATE_LIMIT_MAX_REQUESTS).toBeGreaterThan(3 * 40);
});

it("answers a refusal in JSON so the app can show its message", async () => {
	const server = await serve(1);
	try {
		const url = `http://127.0.0.1:${server.address().port}/`;
		expect((await fetch(url)).status).toBe(200);
		const refused = await fetch(url);
		expect(refused.status).toBe(429);
		expect(await refused.json()).toEqual({ success: false, message: "Too many requests. Please wait a moment and try again." });
	} finally {
		await new Promise((resolve) => server.close(resolve));
	}
});
