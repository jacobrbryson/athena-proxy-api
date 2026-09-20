jest.mock('../../../proxy/httpProxy', () => ({ proxy: { web: jest.fn() } }));
jest.mock('../../../config', () => ({ API_TARGET: 'https://core.example' }));
jest.mock('../../../utils/auth', () => ({ getAuthToken: jest.fn(), IS_CLOUD_RUN: true }));
const { proxy } = require('../../../proxy/httpProxy');
const { getAuthToken } = require('../../../utils/auth');
const forward = require('./whoopWebhook');
beforeEach(() => { jest.clearAllMocks(); getAuthToken.mockResolvedValue('iam-service-token'); });
test('strips caller identities while forwarding the untouched stream and WHOOP signature', async () => {
  const req = { headers: { authorization: 'Bearer forged', 'x-user-authorization': 'forged', 'x-athena-device-token': 'forged', 'x-whoop-signature': 'signature', 'x-whoop-signature-timestamp': '123' }, pipe: jest.fn() };
  await forward(req, {});
  expect(req.headers.authorization).toBe('Bearer iam-service-token');
  expect(req.headers['x-user-authorization']).toBeUndefined();
  expect(req.headers['x-athena-device-token']).toBeUndefined();
  expect(req.headers['x-whoop-signature']).toBe('signature');
  expect(req.body).toBeUndefined();
  expect(proxy.web).toHaveBeenCalledWith(req, {}, { target: 'https://core.example', changeOrigin: true });
});
test('IAM failure asks provider to retry rather than acknowledging lost work', async () => {
  getAuthToken.mockRejectedValue(new Error('unavailable'));
  const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
  await forward({ headers: {} }, res);
  expect(res.status).toHaveBeenCalledWith(503); expect(proxy.web).not.toHaveBeenCalled();
});
