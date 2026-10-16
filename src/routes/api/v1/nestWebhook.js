const { proxy } = require('../../../proxy/httpProxy');
const { API_TARGET } = require('../../../config');
const { getAuthToken, IS_CLOUD_RUN } = require('../../../utils/auth');

// Pub/Sub push for Google Nest. The caller is Google, not an Athena session:
// its proof is the OIDC token in Authorization, which core_api verifies. That
// header is needed for our own IAM hop, so the push token travels on in
// X-Pubsub-Authorization instead — always overwritten from the real header,
// never taken from the caller.
module.exports = async (req, res) => {
  try {
    const pushToken = req.headers.authorization;
    delete req.headers['x-user-authorization'];
    delete req.headers['x-athena-device-token'];
    delete req.headers['x-pubsub-authorization'];
    delete req.headers.authorization;
    if (pushToken) req.headers['x-pubsub-authorization'] = pushToken;
    if (IS_CLOUD_RUN) req.headers.authorization = `Bearer ${await getAuthToken()}`;
    proxy.web(req, res, { target: API_TARGET, changeOrigin: true });
  } catch {
    res.status(503).json({ message: 'Webhook forwarding unavailable; retry delivery' });
  }
};
