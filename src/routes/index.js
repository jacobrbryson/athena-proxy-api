const express = require("express");
const apiV1 = require("./api/v1");
const guardianAuth = require("./guardianAuth");
const companionAuth = require("./companionAuth");

const router = express.Router();

// Health check for Cloud Run / uptime probes. Both spellings on purpose: the
// Google frontend answers a bare `/healthz` itself with its own 404 page and
// never forwards it, so an external probe on that path reports the service
// down while it is perfectly healthy. `/health` reaches us; `/healthz` still
// works locally and behind any other proxy.
router.get(["/healthz", "/health"], (req, res) => res.json({ status: "ok" }));

// Guardian session auth (httpOnly-cookie based):
//   /auth/guardian-login, /auth/guardian-qr-login, /auth/me, /auth/logout
router.use("/auth", guardianAuth);

// Companion session auth (Google sign-in, httpOnly cookie):
//   /auth/companion/google, /auth/companion/me, /auth/companion/ws-ticket, /auth/companion/logout
router.use("/auth", companionAuth);

router.use("/api/v1", apiV1);

module.exports = router;
