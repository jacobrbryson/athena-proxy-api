require("dotenv").config();
const http = require("http");
const express = require("express");
const cors = require("./middleware/cors");
const rateLimiter = require("./middleware/rateLimiter");
const router = require("./routes/index");
const attachProxyErrorHandler = require("./proxy/errorHandler");
const wsProxy = require("./proxy/wsProxy");
const proxy = require("./proxy/httpProxy");
const { PORT } = require("./config");

const app = express();

app.set("trust proxy", 1);

app.use(cors);
app.use(rateLimiter);
app.use(express.json());
app.use("/", router);

attachProxyErrorHandler(proxy);

const server = http.createServer(app);

wsProxy(server, proxy);

server.listen(PORT, () => {
	console.log(`Proxy listening on http://localhost:${PORT}`);
});
