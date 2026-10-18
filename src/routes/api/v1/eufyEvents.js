const { proxy } = require('../../../proxy/httpProxy');
const { API_TARGET } = require('../../../config');
const { getAuthToken, IS_CLOUD_RUN } = require('../../../utils/auth');

// Events from the household Eufy bridge, each with at most one camera frame,
// for the sightings log. The caller is the bridge, not an Athena session: its
// proof is the shared bridge token, which core_api checks. Authorization is
// needed for our own IAM hop, so the bridge token travels on in
// X-Eufy-Bridge-Authorization — always overwritten from the real header,
// never taken from the caller. The body is streamed, never parsed here.
module.exports = async (req, res) => {
  try {
    const bridgeToken = req.headers.authorization;
    delete req.headers['x-user-authorization'];
    delete req.headers['x-athena-device-token'];
    delete req.headers['x-eufy-bridge-authorization'];
    delete req.headers.authorization;
    if (bridgeToken) req.headers['x-eufy-bridge-authorization'] = bridgeToken;
    if (IS_CLOUD_RUN) req.headers.authorization = `Bearer ${await getAuthToken()}`;
    proxy.web(req, res, { target: API_TARGET, changeOrigin: true });
  } catch {
    res.status(503).json({ message: 'Event forwarding unavailable' });
  }
};
