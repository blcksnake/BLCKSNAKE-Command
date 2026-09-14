import crypto from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { isLoopbackHost } from '../core/network.js';
import { redactText } from '../core/redaction.js';
import { AdminApi, AdminApiError } from './admin-api.js';
import { renderDashboard } from './dashboard.js';

const DASHBOARD_CSS = readFileSync(new URL('./dashboard.css', import.meta.url));
const BRAND_ASSETS = new Map([
  ['/favicon.ico', { file: 'assets/favicon.ico', type: 'image/x-icon' }],
  ['/brand/favicon-32.png', { file: 'assets/favicon-32.png', type: 'image/png' }],
  ['/brand/app-icon-192.png', { file: 'assets/app-icon-192.png', type: 'image/png' }],
  ['/brand/app-icon-512.png', { file: 'assets/app-icon-512.png', type: 'image/png' }],
  ['/brand/blcksnake-mark.png', { file: 'assets/blcksnake-mark.png', type: 'image/png' }],
  ['/brand/site.webmanifest', { file: 'assets/site.webmanifest', type: 'application/manifest+json; charset=utf-8' }],
]);
const BRAND_ASSET_CONTENT = new Map([...BRAND_ASSETS].map(([route, asset]) => [
  route,
  { body: readFileSync(new URL(asset.file, import.meta.url)), type: asset.type },
]));
let dashboardClient = null;
const CLIENT_REJECTION_WINDOW_MS = 5 * 60_000;
const CLIENT_REJECTION_LOG_LIMIT = 1;
const ROUTINE_CLIENT_ERROR_CODES = new Set([
  'ECONNABORTED', 'ECONNRESET', 'EPIPE', 'ERR_STREAM_PREMATURE_CLOSE',
  // OpenSSL 3 reports a peer that closes without TLS close_notify as an
  // unexpected EOF. Browsers and local probes can do this after a completed
  // response, so retain it as disconnect telemetry instead of an alarm.
  'ERR_SSL_UNEXPECTED_EOF_WHILE_READING',
]);
const TLS_CLIENT_ERROR_PATTERN = /^(?:ERR_SSL_|ERR_TLS_)/u;
const ROUTINE_TLS_CLIENT_ALERT_PATTERN = /ALERT_(?:BAD_CERTIFICATE|CERTIFICATE_UNKNOWN|UNKNOWN_CA)$/u;
// A loopback plaintext request is a common stale-bookmark or health-probe
// mistake and is safe to keep out of the warning feed because TLS still
// rejects it. Unknown TLS/protocol failures remain warnings even on loopback:
// their origin cannot be proven benign merely from the peer address.
const LOCAL_TRANSPORT_NOISE_REASONS = new Set(['plaintext_http']);
const ADMIN_API_REPORTED_SECURITY_CODES = new Set([
  'action_forbidden', 'administrator_required', 'authentication_required', 'challenge_failed',
  'confirmation_expired', 'csrf_rejected', 'idempotency_conflict', 'invalid_credentials', 'invalid_current_password',
  'loopback_required', 'origin_rejected', 'player_selection_expired', 'rate_limited',
  'secure_origin_required', 'secure_transport_required', 'setup_authorization_required',
  'settings_conflict',
]);

const SECURITY_HEADERS = Object.freeze({
  'Cache-Control': 'no-store',
  Pragma: 'no-cache',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
});

function clientErrorCode(error) {
  try {
    return typeof error?.code === 'string' ? error.code.slice(0, 64).toLocaleUpperCase('en-US') : '';
  } catch { return ''; }
}

function clientErrorReason(stage, error) {
  const code = clientErrorCode(error);
  // Node can emit a TLS failure through clientError before tlsClientError.
  // Derive the stage from its controlled error code so callback order cannot
  // turn a known TLS condition into a misleading generic protocol warning.
  const effectiveStage = stage === 'tls_handshake' || TLS_CLIENT_ERROR_PATTERN.test(code)
    ? 'tls_handshake' : 'protocol';
  if (ROUTINE_CLIENT_ERROR_CODES.has(code)) {
    return { stage: effectiveStage, routine: true, reasonCode: 'peer_disconnect' };
  }
  if (ROUTINE_TLS_CLIENT_ALERT_PATTERN.test(code)) {
    return { stage: 'tls_handshake', routine: true, reasonCode: 'client_certificate_rejected' };
  }
  if (code === 'ERR_SSL_HTTP_REQUEST') {
    return { stage: 'tls_handshake', routine: false, reasonCode: 'plaintext_http' };
  }
  if (effectiveStage === 'tls_handshake') {
    return { stage: effectiveStage, routine: false, reasonCode: 'tls_handshake_failed' };
  }
  if (code === 'HPE_HEADER_OVERFLOW') return { stage: effectiveStage, routine: false, reasonCode: 'header_overflow' };
  if (code.startsWith('HPE_')) return { stage: effectiveStage, routine: false, reasonCode: 'malformed_http' };
  if (code === 'ERR_HTTP_REQUEST_TIMEOUT') return { stage: effectiveStage, routine: false, reasonCode: 'request_timeout' };
  return { stage: effectiveStage, routine: false, reasonCode: 'client_protocol_error' };
}

function send(response, status, payload, contentType, headers = {}) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload));
  const transportHeaders = response.socket?.encrypted ? { 'Strict-Transport-Security': 'max-age=31536000' } : {};
  response.writeHead(status, { ...SECURITY_HEADERS, ...transportHeaders, ...headers, 'Content-Type': contentType, 'Content-Length': body.length });
  response.end(body);
}

function json(response, status, body, headers = {}) {
  send(response, status, `${JSON.stringify(body)}\n`, 'application/json; charset=utf-8', headers);
}

function redirect(response, location) {
  const transportHeaders = response.socket?.encrypted ? { 'Strict-Transport-Security': 'max-age=31536000' } : {};
  response.writeHead(302, { ...SECURITY_HEADERS, ...transportHeaders, Location: location, 'Content-Length': 0 }); response.end();
}

function plaintextHttpsRedirect(socket, port) {
  if (!socket?.writable) return false;
  const authority = Number(port) === 443 ? 'localhost' : `localhost:${port}`;
  const location = `https://${authority}/dashboard`;
  const body = `Open ${location}\n`;
  socket.end([
    'HTTP/1.1 308 Permanent Redirect',
    `Location: ${location}`,
    'Cache-Control: no-store',
    'Content-Type: text/plain; charset=utf-8',
    `Content-Length: ${Buffer.byteLength(body)}`,
    'Connection: close',
    '',
    body,
  ].join('\r\n'));
  return true;
}

export function publicStatus(status, secrets = []) {
  const source = status && typeof status === 'object' ? status : {};
  const safe = (value) => redactText(value, secrets);
  const profile = (value = {}) => ({
    enabled: value.enabled,
    state: value.state == null ? undefined : safe(value.state),
    eligiblePlayers: value.eligiblePlayers,
    mappedPlayers: value.mappedPlayers,
    verifiedPlayers: value.verifiedPlayers,
    pendingPlayers: value.pendingPlayers,
    failedPlayers: value.failedPlayers,
    lastAttemptAt: value.lastAttemptAt,
    lastSuccessAt: value.lastSuccessAt,
    lastErrorAt: value.lastErrorAt,
    lastErrorCode: value.lastErrorCode == null ? undefined : safe(value.lastErrorCode),
    retryAt: value.retryAt,
  });
  const servers = Array.isArray(source.servers) ? source.servers.map((server = {}) => ({
    serverId: server.serverId == null ? undefined : safe(server.serverId),
    serverName: server.serverName == null ? undefined : safe(server.serverName),
    connected: server.connected,
    polling: server.polling,
    playerCount: server.playerCount,
    consecutiveFailures: server.consecutiveFailures,
    lastSuccessAt: server.lastSuccessAt,
    lastErrorAt: server.lastErrorAt,
    lastErrorCode: server.lastErrorCode == null ? undefined : safe(server.lastErrorCode),
    connectedSinceAt: server.connectedSinceAt,
    lastLatencyMs: server.lastLatencyMs,
    lastPlayerRefreshAt: server.lastPlayerRefreshAt,
    players: Array.isArray(server.players) ? server.players.map((player) => ({ name: safe(player?.name ?? '') })) : [],
    profileImport: profile(server.profileImport),
  })) : [];
  const discordSource = source.discord && typeof source.discord === 'object' && !Array.isArray(source.discord)
    ? source.discord : {};
  const discord = {
    enabled: discordSource.enabled,
    started: discordSource.started,
    ready: discordSource.ready,
    user: discordSource.user == null ? undefined : safe(discordSource.user),
    sessionActive: Boolean(discordSource.sessionId || discordSource.sessionActive),
  };
  const scheduledRestarts = Array.isArray(source.scheduledRestarts) ? source.scheduledRestarts.map((restart = {}) => ({
    serverId: restart.serverId == null ? undefined : safe(restart.serverId),
    deadline: restart.deadline,
    reason: restart.reason == null ? undefined : safe(restart.reason),
  })) : [];
  return {
    clusterName: source.clusterName == null ? undefined : safe(source.clusterName),
    started: source.started,
    uptimeSeconds: source.uptimeSeconds,
    ready: source.ready,
    discord,
    servers,
    activeMutes: source.activeMutes,
    linkedAccounts: source.linkedAccounts,
    scheduledRestarts,
  };
}

function authorized(request, expected) {
  if (!expected) return false;
  const match = String(request.headers.authorization ?? '').match(/^Bearer ([^\s]+)$/i);
  if (!match) return false;
  const supplied = Buffer.from(match[1]); const configured = Buffer.from(expected);
  return supplied.length === configured.length && crypto.timingSafeEqual(supplied, configured);
}

function hasJsonContentType(request) {
  return String(request.headers['content-type'] ?? '').split(';', 1)[0].trim().toLocaleLowerCase('en-US') === 'application/json';
}

function logRoute(pathname) {
  const known = new Set([
    '/', '/healthz', '/readyz', '/status', '/metrics', '/dashboard', '/dashboard.css',
    '/favicon.ico', '/brand/favicon-32.png', '/brand/app-icon-192.png', '/brand/app-icon-512.png',
    '/brand/blcksnake-mark.png', '/brand/site.webmanifest',
    '/dashboard-client.js', '/admin/announce', '/admin/api/auth-mode', '/admin/api/session',
    '/admin/api/setup', '/admin/api/session/password', '/admin/api/session/reauthenticate', '/admin/api/operators',
    '/dashboard-ca.pem', '/admin/api/settings', '/admin/api/settings/automation-token/ack',
    '/admin/api/settings/sftp-host-key', '/admin/api/settings/restart',
    '/admin/api/bootstrap', '/admin/api/players', '/admin/api/players/record', '/admin/api/players/notes', '/admin/api/players/identifiers', '/admin/api/items', '/admin/api/packages', '/admin/api/activity',
    '/admin/api/diagnostics', '/admin/api/actions/preview', '/admin/api/actions/execute',
  ]);
  if (known.has(pathname)) return pathname;
  if (/^\/admin\/api\/operators\/[A-Za-z0-9_-]{16,64}(?:\/reset-password)?$/u.test(pathname)) {
    return pathname.endsWith('/reset-password') ? '/admin/api/operators/:id/reset-password' : '/admin/api/operators/:id';
  }
  if (/^\/admin\/api\/packages\/pkg_[A-Za-z0-9_-]{22}$/u.test(pathname)) return '/admin/api/packages/:id';
  return pathname.startsWith('/admin/api/') ? '/admin/api/unmatched' : 'unmatched';
}

async function readJson(request, maximum = 65_536) {
  const chunks = []; let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maximum) throw new AdminApiError(413, 'payload_too_large', 'Request body is too large.');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new AdminApiError(400, 'invalid_json', 'Request body must be valid JSON.'); }
}

function readTlsFile(file, label) {
  try {
    const details = statSync(file);
    if (!details.isFile() || details.size < 1 || details.size > 1024 * 1024) throw new Error('invalid TLS file');
    return readFileSync(file);
  } catch (error) {
    const wrapped = new Error(`${label} could not be read as a bounded regular file`); wrapped.cause = error; throw wrapped;
  }
}

function readTlsPassphrase(file) {
  const value = readTlsFile(file, 'HTTP TLS passphrase').toString('utf8').replace(/[\r\n]+$/u, '');
  if (!value || value.length > 4_096 || /[\r\n\u0000]/u.test(value)) {
    throw new Error('HTTP TLS passphrase file must contain one bounded non-empty line');
  }
  return value;
}

export class HttpService {
  constructor({
    config, bridge, state = null, metrics, logger = null, settingsService = null, onOwnerSetupCompleted = null,
    sftpHostKeyScanner = undefined, onRestartRequested = null,
  } = {}) {
    this.config = config; this.bridge = bridge; this.metrics = metrics; this.logger = logger;
    this.settingsService = settingsService; this.onRestartRequested = onRestartRequested; this.server = null; this.requestServer = null;
    this.clientSockets = new Set();
    this.rejectedClientSockets = new WeakSet();
    this.clientRejectionWindows = new Map();
    this.adminApi = new AdminApi({
      config, bridge, state: state ?? bridge?.state, metrics, logger, statusProjector: publicStatus,
      settingsService, onOwnerSetupCompleted, onRestartRequested,
      ...(sftpHostKeyScanner ? { sftpHostKeyScanner } : {}),
    });
  }

  recordClientRejection(socket, stage, error = null) {
    if (socket && typeof socket === 'object') {
      if (this.rejectedClientSockets.has(socket)) return;
      this.rejectedClientSockets.add(socket);
    }
    const callbackStage = stage === 'tls_handshake' ? 'tls_handshake' : 'protocol';
    const classification = clientErrorReason(callbackStage, error);
    const safeStage = classification.stage;
    if (classification.routine) {
      this.metrics?.increment?.('http_client_disconnects_total', {
        stage: safeStage, reason: classification.reasonCode,
      });
      return;
    }
    this.metrics?.increment?.('http_client_rejections_total', { stage: safeStage });
    const localPeer = !this.config.allowRemoteHttp && isLoopbackHost(socket?.remoteAddress);
    const localTransportNoise = localPeer && LOCAL_TRANSPORT_NOISE_REASONS.has(classification.reasonCode);
    const localPlaintext = localPeer && classification.reasonCode === 'plaintext_http';
    const level = localTransportNoise ? 'info' : 'warn';
    const windowKey = `${safeStage}\u001f${classification.reasonCode}\u001f${level}`;
    const now = Date.now();
    const window = this.clientRejectionWindows.get(windowKey)
      ?? {
        stage: safeStage, reasonCode: classification.reasonCode, level,
        localPlaintext, localTransportNoise, startedAt: now, logged: 0, suppressed: 0,
      };
    this.clientRejectionWindows.set(windowKey, window);
    if (now < window.startedAt || now - window.startedAt >= CLIENT_REJECTION_WINDOW_MS) {
      this.writeClientRejectionSummary(window);
      window.startedAt = now; window.logged = 0; window.suppressed = 0;
    }
    if (window.logged < CLIENT_REJECTION_LOG_LIMIT) {
      window.logged += 1;
      this.logger?.security?.('http.client_protocol_rejected', {
        component: 'http', stage: safeStage, outcome: 'denied', reasonCode: classification.reasonCode,
      }, level, localPlaintext
        ? 'A local client used plaintext HTTP on the HTTPS listener; TLS remained enforced.'
        : localTransportNoise
          ? 'A local client ended an invalid HTTPS negotiation; the connection was blocked and TLS remained enforced.'
        : classification.reasonCode === 'plaintext_http'
          ? 'A client used plaintext HTTP on the HTTPS listener; the connection was blocked.'
        : 'A non-routine client protocol or TLS error reached the HTTPS listener; the connection was blocked.');
    } else {
      window.suppressed += 1;
    }
  }

  writeClientRejectionSummary(window) {
    if (window.suppressed < 1) return;
    this.logger?.security?.('http.client_protocol_suppressed', {
      component: 'http', stage: window.stage, outcome: 'summarized', reasonCode: window.reasonCode, count: window.suppressed,
      windowMs: CLIENT_REJECTION_WINDOW_MS,
    }, window.level, window.localTransportNoise
      ? 'Repeated local HTTPS negotiation errors were summarized; TLS remained enforced.'
      : 'Repeated rejected HTTPS client connections were summarized to protect logging capacity.');
    window.suppressed = 0;
  }

  flushClientRejectionSummaries() {
    for (const window of this.clientRejectionWindows.values()) this.writeClientRejectionSummary(window);
    this.clientRejectionWindows.clear();
  }

  tlsOptions() {
    const tls = this.config.tls;
    if (!tls?.enabled) return null;
    const options = { minVersion: 'TLSv1.2', honorCipherOrder: true };
    if (Buffer.isBuffer(tls.pfx) && tls.pfx.length) options.pfx = tls.pfx;
    else if (tls.pfxFile) options.pfx = readTlsFile(tls.pfxFile, 'HTTP TLS PFX');
    else {
      options.key = tls.key || readTlsFile(tls.keyFile, 'HTTP TLS private key');
      options.cert = tls.cert || readTlsFile(tls.certFile, 'HTTP TLS certificate');
    }
    if (tls.ca) options.ca = tls.ca;
    else if (tls.caFile) options.ca = readTlsFile(tls.caFile, 'HTTP TLS CA chain');
    if (tls.passphraseFile) options.passphrase = readTlsPassphrase(tls.passphraseFile);
    else if (tls.passphrase) options.passphrase = tls.passphrase;
    return options;
  }

  writeAdminResult(response, result) {
    json(response, result?.status ?? 200, result?.body ?? result ?? {}, result?.headers ?? {});
  }

  writeAdminError(response, error) {
    if (error?.code === 'ERR_OPERATOR_PASSWORD_BUSY') {
      this.logger?.warn?.('Operator password service is at capacity', {
        event: 'auth.password_service_busy', component: 'http', outcome: 'rejected', reasonCode: 'capacity_exhausted',
      });
      return json(response, 503, {
        ok: false, error: 'authentication_busy', message: 'Authentication is temporarily busy. Try again shortly.',
      }, { 'Retry-After': '1' });
    }
    if (error instanceof AdminApiError) {
      if ([401, 403, 409, 429].includes(error.status)
        && error.securityReported !== true && !ADMIN_API_REPORTED_SECURITY_CODES.has(error.code)) {
        this.logger?.security?.('http.admin_request_denied', {
          component: 'http', outcome: 'denied', reasonCode: error.code, statusCode: error.status,
        });
      }
      return json(response, error.status, { ok: false, error: error.code, message: redactText(error.message, this.config.redactionSecrets) }, error.headers);
    }
    this.logger?.error?.('Admin API request failed', { error: redactText(error?.message, this.config.redactionSecrets) });
    return json(response, 500, { ok: false, error: 'internal_error', message: 'The admin request could not be completed.' });
  }

  async handleAdminApi(request, response, url) {
    try {
      if (request.method === 'GET' && url.pathname === '/admin/api/auth-mode') {
        return this.writeAdminResult(response, {
          body: { ...this.adminApi.authMode(), authenticated: this.adminApi.hasCurrentSession(request) },
        });
      }
      if (request.method === 'POST' && url.pathname === '/admin/api/setup') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 8_192); return this.writeAdminResult(response, await this.adminApi.setupOwner(request, body));
      }
      if (request.method === 'POST' && url.pathname === '/admin/api/session') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 8_192); return this.writeAdminResult(response, await this.adminApi.createSession(request, body));
      }
      if (request.method === 'DELETE' && url.pathname === '/admin/api/session') {
        this.adminApi.assertJson(request);
        await readJson(request, 2_048); return this.writeAdminResult(response, this.adminApi.closeSession(request));
      }
      if (request.method === 'POST' && url.pathname === '/admin/api/session/password') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 16_384); return this.writeAdminResult(response, await this.adminApi.changePassword(request, body));
      }
      if (request.method === 'POST' && url.pathname === '/admin/api/session/reauthenticate') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 8_192); return this.writeAdminResult(response, {
          body: await this.adminApi.reauthenticateSession(request, body),
        });
      }
      if (request.method === 'GET' && url.pathname === '/admin/api/bootstrap') return this.writeAdminResult(response, { body: this.adminApi.bootstrap(request) });
      if (request.method === 'GET' && url.pathname === '/admin/api/players') return this.writeAdminResult(response, { body: this.adminApi.players(request, url) });
      if (request.method === 'POST' && url.pathname === '/admin/api/players/record') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 2_048);
        return this.writeAdminResult(response, await this.adminApi.playerRecord(request, body));
      }
      if (request.method === 'DELETE' && url.pathname === '/admin/api/players/notes') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 2_048);
        return this.writeAdminResult(response, { body: await this.adminApi.deletePlayerNote(request, body) });
      }
      if (request.method === 'POST' && url.pathname === '/admin/api/players/identifiers') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 2_048);
        return this.writeAdminResult(response, this.adminApi.playerIdentifiers(request, body));
      }
      if (request.method === 'GET' && url.pathname === '/admin/api/items') return this.writeAdminResult(response, { body: this.adminApi.items(request, url) });
      if (request.method === 'POST' && url.pathname === '/admin/api/packages') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 64 * 1024);
        return this.writeAdminResult(response, await this.adminApi.createPackage(request, body));
      }
      const packageRoute = url.pathname.match(/^\/admin\/api\/packages\/(pkg_[A-Za-z0-9_-]{22})$/u);
      if (packageRoute && request.method === 'PUT') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 64 * 1024);
        return this.writeAdminResult(response, await this.adminApi.updatePackage(request, packageRoute[1], body));
      }
      if (packageRoute && request.method === 'DELETE') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 2_048);
        return this.writeAdminResult(response, await this.adminApi.deletePackage(request, packageRoute[1], body));
      }
      if (request.method === 'GET' && url.pathname === '/admin/api/activity') return this.writeAdminResult(response, { body: this.adminApi.activityLog(request) });
      if (request.method === 'GET' && url.pathname === '/admin/api/diagnostics') return this.writeAdminResult(response, { body: this.adminApi.diagnostics(request, url) });
      if (request.method === 'GET' && url.pathname === '/admin/api/operators') return this.writeAdminResult(response, { body: this.adminApi.operators(request) });
      if (request.method === 'GET' && url.pathname === '/admin/api/settings') return this.writeAdminResult(response, { body: this.adminApi.settings(request) });
      if (request.method === 'PUT' && url.pathname === '/admin/api/settings') {
        this.adminApi.authorizeUpdateSettings(request);
        const body = await readJson(request, 1024 * 1024);
        return this.writeAdminResult(response, { body: await this.adminApi.updateSettings(request, body) });
      }
      if (request.method === 'POST' && url.pathname === '/admin/api/settings/sftp-host-key') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 2_048);
        return this.writeAdminResult(response, { body: await this.adminApi.scanSftpFingerprint(request, body) });
      }
      if (request.method === 'POST' && url.pathname === '/admin/api/settings/restart') {
        this.adminApi.assertJson(request);
        await readJson(request, 512);
        const body = this.adminApi.restartApplication(request);
        response.once('finish', () => { setTimeout(() => { void this.onRestartRequested?.(); }, 150); });
        return this.writeAdminResult(response, { status: 202, body });
      }
      if (request.method === 'POST' && url.pathname === '/admin/api/settings/automation-token/ack') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 2_048);
        return this.writeAdminResult(response, {
          body: await this.adminApi.acknowledgeAutomationToken(request, body),
        });
      }
      if (request.method === 'POST' && url.pathname === '/admin/api/operators') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 4_096); return this.writeAdminResult(response, await this.adminApi.createOperator(request, body));
      }
      const operatorRoute = url.pathname.match(/^\/admin\/api\/operators\/([A-Za-z0-9_-]{16,64})(\/reset-password)?$/u);
      if (operatorRoute && request.method === 'PATCH' && !operatorRoute[2]) {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 4_096);
        return this.writeAdminResult(response, { body: await this.adminApi.updateOperator(request, operatorRoute[1], body) });
      }
      if (operatorRoute && request.method === 'POST' && operatorRoute[2]) {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 2_048);
        return this.writeAdminResult(response, { body: await this.adminApi.resetOperatorPassword(request, operatorRoute[1], body) });
      }
      if (request.method === 'POST' && url.pathname === '/admin/api/actions/preview') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 32_768); return this.writeAdminResult(response, { body: this.adminApi.preview(request, body) });
      }
      if (request.method === 'POST' && url.pathname === '/admin/api/actions/execute') {
        this.adminApi.assertJson(request);
        const body = await readJson(request, 32_768); return this.writeAdminResult(response, await this.adminApi.execute(request, body));
      }
      return json(response, 404, { error: 'not_found' });
    } catch (error) { return this.writeAdminError(response, error); }
  }

  async handle(request, response) {
    const url = new URL(request.url, 'http://localhost');
    if (request.method === 'GET' && url.pathname === '/') return redirect(response, '/dashboard');
    if (request.method === 'GET' && url.pathname === '/healthz') return json(response, 200, { ok: true });
    if (request.method === 'GET' && url.pathname === '/readyz') {
      const status = this.bridge.status();
      // An intentionally unconfigured managed instance is ready for first-run
      // administration. Once map configuration exists, readiness must reflect
      // the data plane even if an owner account still needs to be recovered.
      const managedControlPlaneReady = Boolean(this.config.managedInstance?.enabled)
        && !this.config.managedInstance.configured;
      const ready = (status.ready || managedControlPlaneReady) && this.logger?.healthy !== false;
      return json(response, ready ? 200 : 503, { ready });
    }
    // The dashboard document and assets contain no operational data. In remote
    // mode the HttpOnly session still gates every status and action API call.
    if (request.method === 'GET' && url.pathname === '/dashboard') return send(response, 200, renderDashboard(), 'text/html; charset=utf-8');
    if (request.method === 'GET' && url.pathname === '/dashboard.css') return send(response, 200, DASHBOARD_CSS, 'text/css; charset=utf-8');
    if (request.method === 'GET' && BRAND_ASSET_CONTENT.has(url.pathname)) {
      const asset = BRAND_ASSET_CONTENT.get(url.pathname);
      return send(response, 200, asset.body, asset.type, { 'Cache-Control': 'public, max-age=86400' });
    }
    if (request.method === 'GET' && url.pathname === '/dashboard-client.js') {
      dashboardClient ??= readFileSync(new URL('./dashboard-client.js', import.meta.url));
      return send(response, 200, dashboardClient, 'text/javascript; charset=utf-8');
    }
    if (request.method === 'GET' && url.pathname === '/dashboard-ca.pem') {
      const ca = this.settingsService?.publicCa?.() || this.config.tls?.ca;
      if (!this.config.tls?.enabled || typeof ca !== 'string' || !ca.includes('BEGIN CERTIFICATE')) {
        return json(response, 404, { error: 'not_found' });
      }
      return send(response, 200, ca, 'application/x-pem-file; charset=utf-8', {
        'Content-Disposition': 'attachment; filename="blcksnake-command-ca.pem"',
      });
    }
    if (url.pathname.startsWith('/admin/api/')) return this.handleAdminApi(request, response, url);
    if (this.config.allowRemoteHttp && request.method === 'GET'
      && ['/status', '/metrics'].includes(url.pathname) && !authorized(request, this.config.adminToken)) {
      this.logger?.security?.('http.bearer_rejected', { component: 'http', outcome: 'denied', route: url.pathname });
      return json(response, 401, { error: 'unauthorized' });
    }
    if (request.method === 'GET' && url.pathname === '/status') return json(response, 200, publicStatus(this.bridge.status(), this.config.redactionSecrets));
    if (request.method === 'GET' && url.pathname === '/metrics') return send(response, 200, this.metrics.toPrometheus(), 'text/plain; version=0.0.4; charset=utf-8');
    // Backward-compatible automation endpoint. The dashboard uses the
    // session, exact preview, and idempotency API above.
    if (request.method === 'POST' && url.pathname === '/admin/announce') {
      if (!authorized(request, this.config.adminToken)) {
        this.logger?.security?.('http.bearer_rejected', { component: 'http', outcome: 'denied', route: '/admin/announce' });
        return json(response, 401, { error: 'unauthorized' });
      }
      if (!hasJsonContentType(request)) return json(response, 415, { error: 'unsupported_media_type' });
      try {
        const body = await readJson(request);
        await this.bridge.broadcastAnnouncement(body.message, 'http-api', body.server);
        return json(response, 200, { accepted: true });
      } catch (error) { return json(response, 400, { error: redactText(error.message, this.config.redactionSecrets) }); }
    }
    return json(response, 404, { error: 'not_found' });
  }

  async start() {
    if (!this.config.enabled || this.server) return this.address();
    if (!this.config.allowRemoteHttp && !isLoopbackHost(this.config.host)) {
      throw new Error('HTTP listener refused a non-loopback bind; explicitly enable remote HTTPS administration first');
    }
    if (String(this.config.adminToken ?? '').length > 0 && String(this.config.adminToken).length < 32) {
      throw new Error('Configured HTTP admin token must contain at least 32 characters');
    }
    if (String(this.config.adminToken ?? '').length > 256) {
      throw new Error('Configured HTTP admin token must contain at most 256 characters');
    }
    if (this.config.allowRemoteHttp && String(this.config.adminToken ?? '').length < 32) {
      throw new Error('Remote HTTPS requires an admin token containing at least 32 characters');
    }
    if (this.config.allowRemoteHttp && !this.config.tls?.enabled) throw new Error('Remote administration requires native HTTPS');
    const tls = this.tlsOptions();
    const requestServer = tls
      ? https.createServer(tls, (request, response) => this.dispatch(request, response))
      : http.createServer((request, response) => this.dispatch(request, response));
    this.requestServer = requestServer;
    this.server = tls
      ? net.createServer((socket) => {
        this.clientSockets.add(socket);
        socket.once('close', () => this.clientSockets.delete(socket));
        socket.once('data', (firstChunk) => {
          const prefix = firstChunk.subarray(0, 5).toString('ascii').toUpperCase();
          if (prefix.startsWith('GET ') || prefix.startsWith('HEAD ')) {
            const error = Object.assign(new Error('Plaintext HTTP request'), { code: 'ERR_SSL_HTTP_REQUEST' });
            this.recordClientRejection(socket, 'tls_handshake', error);
            plaintextHttpsRedirect(socket, this.address()?.port ?? this.config.port);
            return;
          }
          socket.pause();
          socket.unshift(firstChunk);
          requestServer.emit('connection', socket);
        });
        socket.setTimeout(this.config.headersTimeoutMs ?? 10_000, () => socket.destroy());
      })
      : requestServer;
    this.rejectedClientSockets = new WeakSet();
    this.clientRejectionWindows = new Map();
    requestServer.on('clientError', (error, socket) => {
      this.recordClientRejection(socket, 'protocol', error);
      socket?.destroy();
    });
    requestServer.on('tlsClientError', (error, socket) => this.recordClientRejection(socket, 'tls_handshake', error));
    requestServer.requestTimeout = this.config.requestTimeoutMs ?? 15_000;
    requestServer.headersTimeout = this.config.headersTimeoutMs ?? 10_000;
    requestServer.keepAliveTimeout = this.config.keepAliveTimeoutMs ?? 5_000;
    requestServer.maxRequestsPerSocket = this.config.maxRequestsPerSocket ?? 100;
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.config.port, this.config.host, () => {
        this.server.off('error', reject); resolve(this.address());
      });
    });
  }

  dispatch(request, response) {
    const requestId = crypto.randomUUID(); const startedAt = Date.now();
    try { response.setHeader('X-Request-ID', requestId); } catch { /* response lifecycle will report the failure */ }
    response.once('finish', () => {
      let pathname = 'invalid';
      try { pathname = logRoute(new URL(request.url, 'http://localhost').pathname); } catch { /* keep bounded label */ }
      this.logger?.info?.('HTTP request completed', {
        event: 'http.request_completed', component: 'http', requestId, method: request.method,
        path: pathname, statusCode: response.statusCode, durationMs: Math.max(0, Date.now() - startedAt),
        transport: request.socket?.encrypted ? 'https' : 'http',
      });
    });
    this.handle(request, response).catch((error) => {
      this.logger?.error?.('HTTP request failed', { event: 'http.request_failed', requestId, error: redactText(error.message, this.config.redactionSecrets) });
      if (!response.headersSent) json(response, 500, { error: 'internal_error' }); else response.destroy();
    });
  }

  address() { return this.server?.address() ?? null; }
  stop() {
    this.adminApi.close();
    if (!this.server) {
      this.flushClientRejectionSummaries();
      return Promise.resolve();
    }
    const current = this.server; this.server = null; this.requestServer = null;
    for (const socket of this.clientSockets) socket.destroy();
    this.clientSockets.clear();
    return new Promise((resolve, reject) => current.close((error) => {
      this.flushClientRejectionSummaries();
      if (error) reject(error); else resolve();
    }));
  }
}
