import {createWatcher} from 'ip-monitor';
import { Server } from 'http';
import _io from 'socket.io';
import ecdh from 'crypto-ecdh';
import swarmKey from 'js-ipfs-swarm-key-gen';
import { read } from 'crypto-io-fs';
import { join } from 'path';
import { homedir } from 'os';
import { info } from 'crypto-logger';

const server = Server();
const io = _io(server);
const store = {};
const bootstrap = new Map();
const connections = new Map();

swarmKey().then(() => info('key Initialized: ready for connections'));
/**
 * Main peernet address
 * @param {string} ip The ip for the running daemon
 * @return {string} The address as a MultiAddress /protocolversion/ip/protocol/port/ipfs/peerID
 */
const address = ip => `/ip4/${ip}/tcp/80/ipfs/QmPgX72kLV9Gopq77tMFAQfMZWBGp6Va3AFcmJyeQawTCm`;

/**
 * @important
 * hardcoded privateKey, the key is used for network identification so that only our nodes are on it...
 * this key IS NOT used for any security services!
 */

class SecureConnection {
  constructor(socket, pair) {
    // declare properties
    this.id = socket.id;
    this.pair = pair;
    this.socket = socket;
    // bind methods
    this.handshake = this.handshake.bind(this);
    // init listeners & emitters
    this.shake();
  }
  /**
   * Initialize double handshake
   *
   * Info: Even when a public key is leaked the attacker doesn't get the time to even think about bruteforcing
   */
  shake() {
    this.socket.on('_handshake', this.handshake);
    this.socket.emit('handshake', this.pair.public);
    this.socket.on('request-key', this.keyRequest);
  }

  /**
   * @param {string} key The public key used for encypting/decrypting
   */
  async handshake(key) {
    try {
      this.pair.derive(key);
      // prepare the new keys
      const pair = ecdh('hex');
      const cipher = await this.pair.encrypt(pair.public);
      // retrieve the encrypted key
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
        }
      })
      // send our encrypted key to the client
      this.socket.emit('secure-connection', cipher.toString());
    } catch (e) {
      console.error(e);
    }
  }
  async keyRequest() {
    const key = await read(join(homedir(), '.ipfs', 'swarm.key'), 'string');
    const cipher = await this.pair.encrypt(key);
    this.socket.emit('_request-key', cipher.toString())
  }
}

io.on('connection', socket => {
  socket.join('network');
  connections.set(socket.id, {status: 'pending'});
  new SecureConnection(socket, ecdh('hex'));
});

io.on('disconnect', socket => {
  const address = connections.get(socket.id);
  connections.remove(socket.id);
  bootstrap.remove(address);
});

// TODO: check if needed when a peer is connected already...
const announceAddress = ip => {
  store.ip = ip;
  io.to('network', {address: address(ip)});
}

// create ip watcher
const watcher = createWatcher();

// announceAddress everytime a change is detected
watcher.on('IP:change', (oldIP, newIP) => {
  if (oldIP !== newIP) announceAddress(newIP);
});

// start ip watcher
watcher.start();

server.listen(4040, () => info('listening on 4040'));
