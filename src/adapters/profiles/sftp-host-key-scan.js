import SftpClient from 'ssh2-sftp-client';
import { isPrivateNetworkAddress } from '../rcon/source-rcon.js';
import { normalizeSshSha256Fingerprint, opensshSshSha256Fingerprint } from '../../core/ssh-fingerprint.js';
import { MODERN_SSH_ALGORITHMS } from './sftp-profile-source.js';

export class SftpHostKeyScanError extends Error {
  constructor(message, code = 'SFTP_HOST_KEY_SCAN_FAILED', options) {
    super(message, options); this.name = 'SftpHostKeyScanError'; this.code = code;
  }
}

export async function scanSftpHostKey({ host, port = 22, timeoutMs = 5_000 } = {}, {
  clientFactory = () => new SftpClient('asa-host-key-scan', {}),
} = {}) {
  const address = String(host ?? '').trim();
  if (!isPrivateNetworkAddress(address)) {
    throw new SftpHostKeyScanError('SFTP key scan requires the map\'s private or loopback IP address.', 'SFTP_SCAN_HOST_REFUSED');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new SftpHostKeyScanError('SFTP port must be a whole number from 1 to 65535.', 'SFTP_SCAN_INVALID_PORT');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 500 || timeoutMs > 30_000) {
    throw new SftpHostKeyScanError('SFTP scan timeout is invalid.', 'SFTP_SCAN_INVALID_TIMEOUT');
  }
  const client = clientFactory(); let fingerprint = '';
  try {
    await client.connect({
      host: address, port, username: 'host-key-scan', password: 'not-used',
      readyTimeout: timeoutMs, hostHash: 'sha256',
      algorithms: MODERN_SSH_ALGORITHMS,
      hostVerifier: (candidate) => {
        fingerprint = normalizeSshSha256Fingerprint(candidate) ?? '';
        return false;
      },
    });
  } catch (error) {
    if (!fingerprint) {
      throw new SftpHostKeyScanError('Could not read an SSH host key from that private address and port.', 'SFTP_HOST_KEY_SCAN_FAILED', { cause: error });
    }
  } finally {
    try { await client.end?.(); } catch { /* A rejected host key normally closes the connection first. */ }
    try { client?.client?.destroy?.(); } catch { /* Best-effort cleanup of the underlying SSH socket. */ }
  }
  return { fingerprint, openssh: opensshSshSha256Fingerprint(fingerprint) };
}
