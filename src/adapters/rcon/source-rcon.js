import net from 'node:net';

export const RCON_PACKET_TYPE = Object.freeze({ RESPONSE_VALUE: 0, EXECCOMMAND: 2, AUTH_RESPONSE: 2, AUTH: 3 });
const MAX_PACKET_SIZE = 16 * 1024 * 1024;
let nextRequestId = 73_000;

export function isPrivateNetworkAddress(value) {
  const address = String(value ?? '').trim().toLocaleLowerCase('en-US').split('%', 1)[0];
  if (!address) return false;
  if (address.startsWith('::ffff:')) return isPrivateNetworkAddress(address.slice(7));
  if (net.isIPv4(address)) {
    const parts = address.split('.').map(Number);
    return parts[0] === 10
      || parts[0] === 127
      || (parts[0] === 169 && parts[1] === 254)
      || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
      || (parts[0] === 192 && parts[1] === 168);
  }
  if (!net.isIPv6(address)) return false;
  return address === '::1' || address.startsWith('fc') || address.startsWith('fd')
    || /^fe[89ab]/.test(address);
}

export function encodePacket(id, type, body = '') {
  const payload = Buffer.from(String(body), 'utf8');
  const size = 4 + 4 + payload.length + 2;
  const packet = Buffer.allocUnsafe(4 + size);
  packet.writeInt32LE(size, 0);
  packet.writeInt32LE(id, 4);
  packet.writeInt32LE(type, 8);
  payload.copy(packet, 12);
  packet.writeUInt8(0, 12 + payload.length);
  packet.writeUInt8(0, 13 + payload.length);
  return packet;
}

export function decodePackets(input, { maxPacketSize = MAX_PACKET_SIZE } = {}) {
  let buffer = Buffer.from(input);
  const packets = [];
  while (buffer.length >= 4) {
    const size = buffer.readInt32LE(0);
    if (size < 10 || size > maxPacketSize) throw new Error(`Invalid RCON packet size ${size}`);
    const total = 4 + size;
    if (buffer.length < total) break;
    const id = buffer.readInt32LE(4);
    const type = buffer.readInt32LE(8);
    const bodyEnd = total - 2;
    if (buffer[bodyEnd] !== 0 || buffer[bodyEnd + 1] !== 0) throw new Error('Malformed RCON packet terminator');
    packets.push({ id, type, body: buffer.subarray(12, bodyEnd).toString('utf8') });
    buffer = buffer.subarray(total);
  }
  return { packets, rest: buffer };
}

export class SourceRconClient {
  constructor({
    host, port, password, connectTimeoutMs = 3_000, commandTimeoutMs = 5_000, fragmentIdleMs = 100,
    allowPublicRcon = false, socketFactory = net.createConnection,
  } = {}) {
    if (typeof allowPublicRcon !== 'boolean') throw new TypeError('allowPublicRcon must be true or false');
    this.host = host;
    this.port = port;
    this.password = password;
    this.connectTimeoutMs = connectTimeoutMs;
    this.commandTimeoutMs = commandTimeoutMs;
    this.fragmentIdleMs = fragmentIdleMs;
    this.allowPublicRcon = allowPublicRcon === true;
    this.socketFactory = socketFactory;
  }

  execute(command) {
    const authId = nextRequestId += 3;
    const commandId = authId + 1;
    return new Promise((resolve, reject) => {
      const socket = this.socketFactory({ host: this.host, port: this.port });
      let phase = 'connecting';
      let buffer = Buffer.alloc(0);
      const fragments = [];
      let responseBytes = 0;
      let settled = false;
      let connectTimer;
      let commandTimer;
      let idleTimer;

      const cleanup = () => {
        clearTimeout(connectTimer); clearTimeout(commandTimer); clearTimeout(idleTimer);
        socket.removeAllListeners();
        if (!socket.destroyed) socket.destroy();
      };
      const fail = (error) => {
        if (settled) return;
        settled = true; cleanup(); reject(error instanceof Error ? error : new Error(String(error)));
      };
      const finish = () => {
        if (settled) return;
        settled = true; const result = fragments.join(''); cleanup(); resolve(result);
      };
      const armIdle = () => {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(finish, this.fragmentIdleMs);
      };
      const beginCommand = () => {
        if (phase === 'command') return;
        phase = 'command';
        clearTimeout(connectTimer);
        commandTimer = setTimeout(() => fail(new Error(`RCON command timed out after ${this.commandTimeoutMs}ms`)), this.commandTimeoutMs);
        socket.write(encodePacket(commandId, RCON_PACKET_TYPE.EXECCOMMAND, command));
      };
      const handlePacket = (packet) => {
        if (phase === 'authenticating') {
          if (packet.type === RCON_PACKET_TYPE.AUTH_RESPONSE) {
            if (packet.id === -1) return fail(new Error('RCON authentication failed'));
            if (packet.id === authId) beginCommand();
          }
          return;
        }
        if (phase !== 'command') return;
        if (packet.id !== commandId) return;
        responseBytes += Buffer.byteLength(packet.body);
        if (responseBytes > MAX_PACKET_SIZE) return fail(new Error('RCON response exceeded safety limit'));
        fragments.push(packet.body);
        armIdle();
      };

      connectTimer = setTimeout(() => fail(new Error(`RCON connection timed out after ${this.connectTimeoutMs}ms`)), this.connectTimeoutMs);
      socket.once('connect', () => {
        if (!this.allowPublicRcon && !isPrivateNetworkAddress(socket.remoteAddress)) {
          fail(new Error('RCON refused a non-private network address before authentication'));
          return;
        }
        phase = 'authenticating';
        socket.write(encodePacket(authId, RCON_PACKET_TYPE.AUTH, this.password));
      });
      socket.on('data', (chunk) => {
        try {
          buffer = Buffer.concat([buffer, chunk]);
          const decoded = decodePackets(buffer);
          buffer = decoded.rest;
          for (const packet of decoded.packets) handlePacket(packet);
        } catch (error) { fail(error); }
      });
      socket.once('error', fail);
      socket.once('close', () => {
        if (settled) return;
        if (phase === 'authenticating' || phase === 'connecting') fail(new Error('RCON connection closed during authentication'));
        else if (fragments.length) finish();
        else fail(new Error('RCON connection closed before a command response'));
      });
    });
  }
}
