const express = require("express");
const apiV1 = require("./api/v1");
const guardianAuth = require("./guardianAuth");

const router = express.Router();

// Health check for Cloud Run / uptime probes.
router.get("/healthz", (req, res) => res.json({ status: "ok" }));

// Guardian session auth (httpOnly-cookie based):
//   /auth/guardian-login, /auth/guardian-qr-login, /auth/me, /auth/logout
router.use("/auth", guardianAuth);

router.use("/api/v1", apiV1);

module.exports = router;
