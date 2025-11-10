const express = require("express");
const proxy = require("../../../proxy/httpProxy");

const router = express.Router();

router.use((req, res) => {
	console.log(`Proxying ${req.method} ${req.url}`);
	proxy.web(req, res);
});

module.exports = router;
