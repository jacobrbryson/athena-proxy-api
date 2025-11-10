module.exports = function wsProxy(server, proxy) {
	server.on("upgrade", (req, socket, head) => {
		console.log(`WS upgrade: ${req.url}`);

		if (req.url.startsWith("/ws")) {
			proxy.ws(req, socket, head);
		} else {
			socket.destroy();
		}
	});
};
