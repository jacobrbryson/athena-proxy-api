const { test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
let payload, upstream, fetchCount, fetchOptions;
const authPath = require.resolve('../utils/auth');
require.cache[authPath] = { id: authPath, filename: authPath, loaded: true, exports: {
  IS_CLOUD_RUN: false, verifyGoogleToken: async () => payload,
} };
const config = require('../config');
config.JWT_SECRET = 'test-only-secret';
config.GOOGLE_CLIENT_ID = 'test-client';
const router = require('./companionAuth');
const route = router.stack.find((layer) => layer.route?.path === '/companion/google').route;
const login = route.stack[route.stack.length - 1].handle;
beforeEach(() => {
  payload = { sub: 'google-123', email: 'visitor@example.test', email_verified: true };
  upstream = { ok: true, json: async () => ({ allowed: false, requested: false }) };
  fetchCount = 0;
});
async function signIn() {
  const result = { status: 200, cookie: null };
  const res = { status(s) { result.status = s; return this; }, json(body) { result.body = body; return this; }, cookie(name, value) { result.cookie = value; } };
  const previousFetch = global.fetch;
  global.fetch = async (_url, opts) => { fetchCount++; fetchOptions = opts; if (upstream instanceof Error) throw upstream; return upstream; };
  try { await login({ body: { credential: 'google-credential' }, ip: '127.0.0.1' }, res); }
  finally { global.fetch = previousFetch; }
  return result;
}
test('non-Guardian login is audited before issuing a locked session', async () => {
  const result = await signIn();
  assert.equal(result.status, 200);
  assert.equal(result.body.access.allowed, false);
  assert.equal(fetchCount, 1);
  const claims = jwt.verify(result.cookie, config.JWT_SECRET);
  assert.equal(claims.email_verified, true);
  assert.equal(fetchOptions.headers['x-user-authorization'], `Bearer ${result.cookie}`);
});
test('failed audit/access lookup issues no session', async () => {
  upstream = new Error('database unavailable');
  const result = await signIn();
  assert.equal(result.status, 503);
  assert.equal(result.cookie, null);
});
test('unverified Google email never reaches access lookup', async () => {
  payload.email_verified = false;
  const result = await signIn();
  assert.equal(result.status, 401);
  assert.equal(fetchCount, 0);
  assert.equal(result.cookie, null);
});

// --- POST /companion/refresh -------------------------------------------------
// A session left open overnight comes back on a different IP. The cookie is
// still valid, but the IP pin makes every /api/v1 call 401 (see
// middleware/auth.js), which used to read to the user as "access revoked".
const refreshRoute = router.stack.find((layer) => layer.route?.path === '/companion/refresh').route;
const refresh = refreshRoute.stack[refreshRoute.stack.length - 1].handle;

function callRefresh(cookieValue, ip) {
  const result = { status: 200, cookie: null, cookieOptions: null };
  const res = {
    status(s) { result.status = s; return this; },
    json(body) { result.body = body; return this; },
    cookie(name, value, opts) { result.cookie = value; result.cookieOptions = opts; },
  };
  refresh(
    { cookies: cookieValue ? { [config.COMPANION_SESSION_COOKIE]: cookieValue } : {}, ip },
    res
  );
  return result;
}

const sessionCookie = (claims = {}, options = {}) =>
  jwt.sign(
    { app: 'companion', google_id: 'google-123', email: 'visitor@example.test', email_verified: true, client_ip: '1.2.3.4', ...claims },
    config.JWT_SECRET,
    { expiresIn: 3600, ...options }
  );

test('refresh re-pins the session to the new client IP', async () => {
  const before = sessionCookie();
  const result = callRefresh(before, '5.6.7.8');
  assert.equal(result.status, 200);
  const claims = jwt.verify(result.cookie, config.JWT_SECRET);
  assert.equal(claims.client_ip, '5.6.7.8');
  assert.equal(claims.google_id, 'google-123');
  assert.equal(claims.email, 'visitor@example.test');
  assert.equal(claims.email_verified, true);
  assert.equal(claims.app, 'companion');
  assert.equal(result.body.user.email, 'visitor@example.test');
});

test('refresh cannot extend a session past its original expiry', async () => {
  const before = sessionCookie({}, { expiresIn: 120 });
  const beforeExp = jwt.decode(before).exp;
  const result = callRefresh(before, '5.6.7.8');
  const afterExp = jwt.verify(result.cookie, config.JWT_SECRET).exp;
  // Same absolute deadline (allowing a second of clock movement mid-test).
  assert.ok(Math.abs(afterExp - beforeExp) <= 1, `exp moved: ${beforeExp} -> ${afterExp}`);
  assert.ok(result.cookieOptions.maxAge <= 120_000);
  assert.equal(result.cookieOptions.httpOnly, true);
});

test('refresh without a session issues nothing', async () => {
  const result = callRefresh(null, '5.6.7.8');
  assert.equal(result.status, 401);
  assert.equal(result.body.code, 'SESSION_EXPIRED');
  assert.equal(result.cookie, null);
});

test('refresh rejects an expired or foreign-app cookie', async () => {
  const expired = sessionCookie({}, { expiresIn: -10 });
  assert.equal(callRefresh(expired, '1.2.3.4').status, 401);
  const guardian = jwt.sign({ app: 'guardian', google_id: 'g' }, config.JWT_SECRET, { expiresIn: 3600 });
  assert.equal(callRefresh(guardian, '1.2.3.4').status, 401);
  const forged = jwt.sign({ app: 'companion', google_id: 'g' }, 'wrong-secret', { expiresIn: 3600 });
  assert.equal(callRefresh(forged, '1.2.3.4').status, 401);
});
