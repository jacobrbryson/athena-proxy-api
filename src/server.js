const http = require("http");
const express = require("express");

const cors = require("./middleware/cors");
const router = require("./routes/index");
const attachProxyErrorHandler = require("./proxy/errorHandler");
const wsProxy = require("./proxy/wsProxy");
const proxy = require("./proxy/httpProxy");
const { PROXY_PORT } = require("./config");

const app = express();

// Attach middleware
app.use(cors);

// Attach API proxy routing
app.use("/", router);

// Initialize proxy error handling
attachProxyErrorHandler(proxy);

// Create raw HTTP server
const server = http.createServer(app);

// Enable websocket upgrades
wsProxy(server, proxy);

// Start
server.listen(PROXY_PORT, () => {
	console.log(`Proxy listening on http://localhost:${PROXY_PORT}`);
});
