const express = require("express");
const apiV1 = require("./api/v1");
const guardianAuth = require("./guardianAuth");
const companionAuth = require("./companionAuth");

const router = express.Router();

// Health check for Cloud Run / uptime probes.
router.get("/healthz", (req, res) => res.json({ status: "ok" }));

// Guardian session auth (httpOnly-cookie based):
//   /auth/guardian-login, /auth/guardian-qr-login, /auth/me, /auth/logout
router.use("/auth", guardianAuth);

// Companion session auth (Google sign-in, httpOnly cookie):
//   /auth/companion/google, /auth/companion/me, /auth/companion/ws-ticket, /auth/companion/logout
router.use("/auth", companionAuth);

router.use("/api/v1", apiV1);

module.exports = router;
