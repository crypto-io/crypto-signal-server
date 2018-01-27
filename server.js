'use strict';

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var ipMonitor = require('ip-monitor');
var http = require('http');
var express = _interopDefault(require('express'));
var _io = _interopDefault(require('socket.io'));
var ecdh = _interopDefault(require('crypto-ecdh'));
var swarmKey = _interopDefault(require('js-ipfs-swarm-key-gen'));
var cryptoIoFs = require('crypto-io-fs');
var path = require('path');
var os = require('os');
var cryptoLogger = require('crypto-logger');

const app = express();
const server = http.Server(app);
const io = _io(server);
const store = {};
const bootstrap = new Map();
const connections = new Map();
swarmKey().then(() => cryptoLogger.info('key Initialized: ready for connections'));
const address = ip => `/ip4/${ip}/tcp/80/ipfs/QmPgX72kLV9Gopq77tMFAQfMZWBGp6Va3AFcmJyeQawTCm`;
class SecureConnection {
  constructor(socket, pair) {
    this.id = socket.id;
    this.pair = pair;
    this.socket = socket;
    this.handshake = this.handshake.bind(this);
    this.shake();
  }
  shake() {
    this.socket.on('_handshake', this.handshake);
    this.socket.emit('handshake', this.pair.public);
    this.socket.on('request-key', this.keyRequest);
  }
  handshake(key) {
    (async () => {
      try {
        this.pair.derive(key);
        const pair = ecdh('hex');
        const cipher = await this.pair.encrypt(pair.public);
        this.socket.on('_secure-connection', async cipher => {
          try {
            const key = await this.pair.decrypt(cipher);
            this.pair = pair;
            this.pair.derive(key);
            const encrypted = await this.pair.encrypt(address(store.ip));
            this.socket.emit('network', encrypted.toString());
            this.socket.on('address', data => console.log(data));
          } catch (e) {
            console.error(e);
          } finally {}
        });
        this.socket.emit('secure-connection', cipher.toString());
      } catch (e) {
        console.error(e);
      }
    })();
  }
  async keyRequest() {
    const key = await cryptoIoFs.read(path.join(os.homedir(), '.ipfs', 'swarm.key'), 'string');
    const cipher = await this.pair.encrypt(key);
    this.socket.emit('_request-key', cipher.toString());
  }
}
io.on('connection', socket => {
  socket.join('network');
  connections.set(socket.id, { status: 'pending' });
  new SecureConnection(socket, ecdh('hex'));
});
io.on('disconnect', socket => {
  const address = connections.get(socket.id);
  connections.remove(socket.id);
  bootstrap.remove(address);
});
const announceAddress = ip => {
  store.ip = ip;
  io.to('network', { address: address(ip) });
};
const watcher = ipMonitor.createWatcher();
watcher.on('IP:change', (oldIP, newIP) => {
  if (oldIP !== newIP) announceAddress(newIP);
});
watcher.start();
server.listen(9090, () => cryptoLogger.info('listening on 9090'));
//# sourceMappingURL=server.js.map
