const express = require("express");
const apiV1 = require("./api/v1");

const router = express.Router();

router.use("/api/v1", apiV1);

module.exports = router;
