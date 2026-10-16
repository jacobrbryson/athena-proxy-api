jest.mock('../../../proxy/httpProxy', () => ({ proxy: { web: jest.fn() } }));
jest.mock('../../../config', () => ({ API_TARGET: 'https://core.example' }));
jest.mock('../../../utils/auth', () => ({ getAuthToken: jest.fn(), IS_CLOUD_RUN: true }));
const { proxy } = require('../../../proxy/httpProxy');
const { getAuthToken } = require('../../../utils/auth');
const forward = require('./nestWebhook');
beforeEach(() => { jest.clearAllMocks(); getAuthToken.mockResolvedValue('iam-service-token'); });
test('moves the Pub/Sub token aside, strips caller identities and a forged push header', async () => {
  const req = { headers: { authorization: 'Bearer pubsub-oidc', 'x-pubsub-authorization': 'Bearer forged', 'x-user-authorization': 'forged', 'x-athena-device-token': 'forged' }, pipe: jest.fn() };
  await forward(req, {});
  expect(req.headers.authorization).toBe('Bearer iam-service-token');
  expect(req.headers['x-pubsub-authorization']).toBe('Bearer pubsub-oidc');
  expect(req.headers['x-user-authorization']).toBeUndefined();
  expect(req.headers['x-athena-device-token']).toBeUndefined();
  expect(proxy.web).toHaveBeenCalledWith(req, {}, { target: 'https://core.example', changeOrigin: true });
});
test('no push token means no push header — a forged one is not passed on', async () => {
  const req = { headers: { 'x-pubsub-authorization': 'Bearer forged' } };
  await forward(req, {});
  expect(req.headers['x-pubsub-authorization']).toBeUndefined();
});
test('IAM failure asks Pub/Sub to retry rather than acknowledging lost work', async () => {
  getAuthToken.mockRejectedValue(new Error('unavailable'));
  const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
  await forward({ headers: {} }, res);
  expect(res.status).toHaveBeenCalledWith(503); expect(proxy.web).not.toHaveBeenCalled();
});
