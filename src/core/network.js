export function isLoopbackHost(value) {
  const host = String(value ?? '').trim().toLocaleLowerCase('en-US').replace(/^\[|\]$/gu, '');
  return host === 'localhost' || host === '::1' || host === '0:0:0:0:0:0:0:1'
    || /^127(?:\.\d{1,3}){3}$/u.test(host) || host.startsWith('::ffff:127.');
}
