import { X509Certificate } from 'node:crypto';
import net from 'node:net';
import { pathToFileURL } from 'node:url';
import { managedPaths, openRuntimeContext } from '../managed-instance.js';
import { readFirstRunSetupFile } from '../security/managed-keystore.js';

function setupPort(environment) {
  const value = String(environment.CROSSCHAT_HTTP_PORT || '8787');
  if (!/^\d{1,5}$/u.test(value)) throw new Error('invalid managed HTTPS port');
  const port = Number(value);
  if (port < 1 || port > 65_535) throw new Error('invalid managed HTTPS port');
  return port;
}

function dashboardAddress(config, environment) {
  const rawHost = String(config?.http?.host || environment.CROSSCHAT_HTTP_HOST || 'localhost').trim();
  const host = rawHost.startsWith('[') && rawHost.endsWith(']') ? rawHost.slice(1, -1) : rawHost;
  const port = config?.http?.port ?? setupPort(environment);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error('invalid managed HTTPS port');
  if (host === '0.0.0.0') return `https://localhost:${port}/dashboard`;
  if (host === '::') return `https://[::1]:${port}/dashboard`;
  if (net.isIP(host) === 6) return `https://[${host}]:${port}/dashboard`;
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/iu.test(host)
    && net.isIP(host) !== 4) throw new Error('invalid managed HTTPS host');
  return `https://${host}:${port}/dashboard`;
}

export function setupHelp() {
  return [
    'Usage: npm run setup:show',
    '',
    'Shows the one-time first-owner setup token from the protected managed keystore.',
    'Run it locally on the installation host. Do not paste its output into logs or support messages.',
    '',
  ].join('\n');
}

export async function showFirstRunSetup({
  environment = process.env,
  rootDirectory = process.cwd(),
  write = (value) => process.stdout.write(value),
  openContext = openRuntimeContext,
} = {}) {
  const paths = managedPaths({ rootDirectory, environment });
  const setup = await readFirstRunSetupFile(paths.setupFile);
  let runtime = null;
  let token = setup.token;
  try {
    try { runtime = await openContext({ rootDirectory, environment, initialize: false }); }
    catch { /* The protected setup artifact remains usable during state recovery. */ }
    const lines = [
      'BLCKSNAKE Command first-run owner setup',
      '',
      `Dashboard: ${dashboardAddress(runtime?.config, environment)}`,
    ];
    if (setup.caPem) {
      const certificate = new X509Certificate(setup.caPem);
      lines.push(
        `HTTPS CA SHA-256: ${setup.caFingerprint}`,
        'HTTPS CA certificate (public trust anchor; install this before opening the dashboard):',
        certificate.toString().trimEnd(),
      );
    } else {
      lines.push('HTTPS CA certificate: not available (the imported identity must already be trusted).');
    }
    lines.push(
      `Setup token: ${token}`,
      '',
      'Create the server-owner account, then configure maps and integrations in Settings.',
      'The setup token is single-purpose and its protected file is removed after owner creation.',
      '',
    );
    write(lines.join('\n'));
  } finally {
    token = '';
    await runtime?.close?.().catch(() => undefined);
  }
}

async function main(argv = process.argv.slice(2)) {
  if (argv.length === 1 && argv[0] === '--help') {
    process.stdout.write(setupHelp());
    return;
  }
  if (argv.length) throw new Error('unsupported setup command arguments');
  await showFirstRunSetup();
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) main().catch(() => {
  process.stderr.write('First-run setup information is unavailable. Start the managed service first, or sign in if setup is already complete.\n');
  process.exitCode = 1;
});
