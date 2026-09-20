const { proxy } = require('../../../proxy/httpProxy');
const { API_TARGET } = require('../../../config');
const { getAuthToken, IS_CLOUD_RUN } = require('../../../utils/auth');

// The caller is a provider, not an Athena session. Core authenticates the
// exact body with WHOOP's signature; this hop uses only our existing IAM token.
module.exports = async (req, res) => {
  try {
    delete req.headers['x-user-authorization'];
    delete req.headers['x-athena-device-token'];
    delete req.headers.authorization;
    if (IS_CLOUD_RUN) req.headers.authorization = `Bearer ${await getAuthToken()}`;
    proxy.web(req, res, { target: API_TARGET, changeOrigin: true });
  } catch {
    res.status(503).json({ message: 'Webhook forwarding unavailable; retry delivery' });
  }
};
