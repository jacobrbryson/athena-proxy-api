const express = require("express");
const proxy = require("../../../proxy/httpProxy");
const { API_TARGET } = require("../../../config");

const router = express.Router();

router.use((req, res) => {
	console.log(`Proxying ${req.method} ${API_TARGET}${req.url}`);
	proxy.web(req, res);
});

module.exports = router;
