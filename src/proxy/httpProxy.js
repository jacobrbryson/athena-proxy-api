const httpProxy = require("http-proxy");
const { API_TARGET } = require("../config");

const proxy = httpProxy.createProxyServer({
	target: API_TARGET,
	ws: true,
});

module.exports = proxy;
