/**
 * The WebSocket upgrade pins a token to the IP it was issued to. That pin is
 * only worth anything if the IP can't be written by the client.
 */
process.env.JWT_SECRET = process.env.JWT_SECRET || "test-secret";
const { EventEmitter } = require("events");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config");
const wsProxy = require("./wsProxy");

const VICTIM = "203.0.113.7";
const ATTACKER = "198.51.100.1";

function upgrade(xff) {
	const server = new EventEmitter();
	const proxy = { ws: jest.fn() };
	wsProxy(server, proxy);
	const token = jwt.sign({ google_id: "g-1", client_ip: VICTIM }, JWT_SECRET);
	const req = {
		url: `/ws?sessionId=s-1&token=${token}`,
		headers: { "x-forwarded-for": xff },
		socket: { remoteAddress: "10.0.0.1" },
	};
	const socket = { writable: true, write: jest.fn(), destroy: jest.fn() };
	server.emit("upgrade", req, socket, Buffer.alloc(0));
	return new Promise((r) => setImmediate(r)).then(() => ({ req, socket, proxy }));
}

beforeEach(() => {
	jest.spyOn(console, "log").mockImplementation(() => {});
	jest.spyOn(console, "warn").mockImplementation(() => {});
	jest.spyOn(console, "error").mockImplementation(() => {});
});

it("refuses a stolen token when the attacker writes the victim's IP into X-Forwarded-For", async () => {
	const { socket, proxy } = await upgrade(`${VICTIM}, ${ATTACKER}`);
	expect(proxy.ws).not.toHaveBeenCalled();
	expect(socket.write.mock.calls[0][0]).toMatch(/401[\s\S]*ip-mismatch/);
});

it("accepts the owner, and forwards only their verified IP to core_api", async () => {
	const { req, proxy } = await upgrade(`9.9.9.9, ${VICTIM}`);
	expect(proxy.ws).toHaveBeenCalled();
	expect(req.headers["x-forwarded-for"]).toBe(VICTIM);
});
