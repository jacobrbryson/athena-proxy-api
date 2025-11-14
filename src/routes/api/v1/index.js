const express = require("express");
const proxy = require("../../../proxy/httpProxy");
const { API_TARGET } = require("../../../config");

const router = express.Router();

router.use((req, res) => {
	// Enhanced logging of the request details before forwarding
	console.log("--- PROXY REQUEST START (Debugging 404) ---");
	console.log(`Method: ${req.method}`);
	console.log(`Target Base: ${API_TARGET}`);
	console.log(`Path: ${req.url}`);
	console.log(`Full Target URL: ${API_TARGET}${req.url}`);

	// Log selected headers to check for issues like incorrect host or authorization
	console.log("Relevant Headers:");
	console.log(`  Host: ${req.headers.host}`);
	console.log(
		`  Authorization: ${req.headers.authorization ? "Present" : "Absent"}`
	);
	console.log(`  User-Agent: ${req.headers["user-agent"]}`);
	console.log("-------------------------------------------");

	proxy.web(req, res, { target: API_TARGET });
});

module.exports = router;
