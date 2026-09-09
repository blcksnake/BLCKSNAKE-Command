import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ManagedSettingsService } from '../core/managed-settings.js';
import { openRuntimeContext } from '../managed-instance.js';

function usage() {
  return [
    'Usage:',
    '  npm run tls:show-ca',
    '  npm run tls:export-ca -- --out <new-file>',
    '  npm run tls:rotate -- [--name <dns-or-ip>]...',
  ].join('\n');
}

function parseArguments(argv) {
  const [command = '', ...rest] = argv;
  if (!['show-ca', 'export-ca', 'rotate'].includes(command)) throw new Error('Unsupported HTTPS maintenance command');
  const result = { command, names: null, outputFile: '' };
  for (let index = 0; index < rest.length; index += 1) {
    const option = rest[index]; const value = rest[index + 1];
    if (option === '--name' && command === 'rotate' && value) {
      result.names ??= [];
      result.names.push(value); index += 1;
    } else if (option === '--out' && command === 'export-ca' && value) {
      result.outputFile = value; index += 1;
    } else throw new Error('Unsupported or incomplete HTTPS maintenance option');
  }
  if ((result.names?.length ?? 0) > 16) throw new Error('HTTPS rotation accepts at most 16 additional names');
  if (command === 'export-ca' && !result.outputFile) throw new Error('HTTPS CA export requires --out');
  return result;
}

function caDetails(caPem) {
  const certificate = new crypto.X509Certificate(caPem);
  if (!certificate.ca) throw new Error('Managed HTTPS trust anchor is invalid');
  return {
    pem: certificate.toString(),
    fingerprint: certificate.fingerprint256.replaceAll(':', '').toLocaleLowerCase('en-US'),
    expiresAt: new Date(certificate.validTo).toISOString(),
  };
}

async function writeNewPublicCa(file, pem) {
  const target = path.resolve(file); let handle = null;
  try {
    handle = await fs.open(target, 'wx', 0o644);
    await handle.writeFile(pem, { encoding: 'utf8' });
    await handle.sync();
  } finally { await handle?.close(); }
  return target;
}

export async function runTlsMaintenance(argv = process.argv.slice(2), {
  rootDirectory = process.cwd(), stdout = (line) => console.log(line), stderr = (line) => console.error(line),
  openContext = openRuntimeContext, environment = process.env,
} = {}) {
  let context = null;
  try {
    const options = parseArguments(argv);
    context = await openContext({
      rootDirectory,
      environment,
      initialize: options.command === 'rotate',
      requireExisting: options.command === 'rotate',
    });
    if (!context.managed) throw new Error('HTTPS maintenance requires a managed installation');
    const service = new ManagedSettingsService({ context, state: context.state, paths: context.paths });
    if (options.command === 'rotate') {
      await service.rotateTlsLocally({ subjectAltNames: options.names });
    }
    const details = caDetails(service.publicCa());
    if (options.command === 'export-ca') {
      const target = await writeNewPublicCa(options.outputFile, details.pem);
      stdout(`Managed HTTPS CA exported to ${target}`);
      stdout(`CA SHA-256: ${details.fingerprint}`);
    } else {
      stdout(`CA SHA-256: ${details.fingerprint}`);
      stdout(`CA expires: ${details.expiresAt}`);
      stdout('----- MANAGED HTTPS PUBLIC CA (SAFE TO DISTRIBUTE) -----');
      stdout(details.pem.trimEnd());
      stdout('----- END MANAGED HTTPS PUBLIC CA -----');
      if (options.command === 'rotate') stdout('HTTPS identity staged. Restart the application before using the new certificate.');
    }
    return 0;
  } catch (error) {
    stderr('HTTPS maintenance failed safely. The managed installation was not unlocked or private material displayed.');
    if (error?.code === 'tls_rotation_explicit_names_required') {
      stderr('This imported certificate cannot be rotated implicitly. Repeat rotate with one or more --name <dns-or-ip> options.');
    }
    stderr(usage());
    return 1;
  } finally { await context?.close?.().catch(() => undefined); }
}

export async function main() { return runTlsMaintenance(); }

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (isMain) process.exitCode = await main();
