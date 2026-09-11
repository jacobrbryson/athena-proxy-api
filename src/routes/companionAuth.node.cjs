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
