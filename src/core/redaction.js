import { isIP } from 'node:net';

export const REDACTED = '[REDACTED]';

const DISCORD_TOKEN_PATTERN = /(?:Bot\s+)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{20,}/g;
const DISCORD_ROUTE_TOKEN_PATTERN = /(\/(?:interactions|webhooks)\/[^/\s?#]+\/)[^/\s?#]+/gi;
const URL_USERINFO_PATTERN = /\b([a-z][a-z0-9+.-]*:\/\/)[^@\s/]+@/gi;
const AUTHORIZATION_PATTERN = /\b(authorization\s*[:=]\s*)(?:"(?:(?:bearer|bot|basic)\s+)?[^"\r\n]*"|'(?:(?:bearer|bot|basic)\s+)?[^'\r\n]*'|(?:(?:bearer|bot|basic)\s+)?[^\s,;&#}\]]+)/gi;
const URL_QUERY_CREDENTIAL_PATTERN = /([?&](?:access[_-]?token|refresh[_-]?token|api[_-]?key|x[_-]?api[_-]?key|token|password|passwd|secret)=)[^&#\s"'<>]*/gi;
const JSON_SCALAR_PROPERTY_PATTERN = /("((?:\\.|[^"\\])*)"\s*:\s*)("(?:\\.|[^"\\])*"|true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
const LABELED_SECRET_PATTERN = /\b(x[_-]?api[_-]?key|api[_-]?key|access[_-]?key[_-]?id|secret[_-]?access[_-]?key|access[_-]?token|refresh[_-]?token|interaction[_-]?token|webhook[_-]?token|client[_-]?secret|csrf(?:[_-]?(?:token|secret))?|xsrf(?:[_-]?(?:token|secret))?|session(?:[_-]?(?:id|key|token|secret))?|password(?:[_-]?(?:hash|verifier|salt))?|credential[_-]?verifier|salt|token|passwd|secret|cookie|private[_-]?key|passphrase)\b(\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&#}\]]+)/gi;
const LABELED_IDENTIFIER_PATTERN = /\b(remote[_-]?(?:address|ip)|client[_-]?ip|peer[_-]?address|player[_-]?id|platform(?:[_-]?(?:id|user[_-]?id|account[_-]?id))?|eos(?:[_-]?(?:id|account[_-]?id|product[_-]?user[_-]?id))?|product[_-]?user[_-]?id|epic[_-]?account[_-]?id|email(?:[_-]?address)?)\b(\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&#}\]]+)/gi;
const PEM_PRIVATE_KEY_PATTERN = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)/gi;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\b/g;
const AWS_ACCESS_KEY_PATTERN = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;
const PROFILE_PATH_PATTERN = /(?:[A-Za-z]:)?[\\/](?:[^\s"'`()\[\]{},;]+[\\/])*[^\s"'`()\[\]{},;]*\.arkprofile\b/gi;
const OPENSSH_FINGERPRINT_PATTERN = /\bSHA256:[A-Za-z0-9+/]{43}=?(?![A-Za-z0-9+/=])/g;
const HEX_FINGERPRINT_PATTERN = /\b[a-f0-9]{64}\b/gi;
const EOS_ID_PATTERN = /\b[a-f0-9]{32}\b/gi;
const EOS_PREFIXED_ID_PATTERN = /\bEOS[_:-][A-Za-z0-9_-]{4,128}\b/gi;
const PLAYER_DATA_ID_PATTERN = /(\b(?:player\s*data\s*id|playerdataid|player\s*id)\b\s*[:=#-]?\s*)\d{1,10}\b/gi;
const LABELED_ACCOUNT_ID_PATTERN = /(\b(?:eos(?:\s*id)?|account\s*id)\b\s*[:=]\s*)[A-Za-z0-9:_-]{1,128}/gi;
const PLAYER_ASSIGNMENT_PATTERN = /(\bplayer\s*=\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}\]]+)/gi;
const GAME_ACTOR_PATTERN = /(\bgame:)[A-Za-z0-9:_-]{1,128}/gi;
const DISCORD_SNOWFLAKE_PATTERN = /\b\d{17,20}\b/g;
const EMAIL_PATTERN = /\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)*\b/gi;
const IPV6_CANDIDATE_PATTERN = /\[?[A-Fa-f0-9:.]+(?:%[A-Za-z0-9_.-]+)?\]?/g;
const IPV4_CANDIDATE_PATTERN = /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g;

const SENSITIVE_KEYS = new Set([
  'id', 'token', 'accesstoken', 'refreshtoken', 'interactiontoken', 'webhooktoken',
  'password', 'passwd', 'secret', 'authorization', 'cookie', 'setcookie', 'apikey', 'xapikey',
  'accesskeyid', 'secretaccesskey', 'clientsecret', 'csrf', 'csrftoken', 'xsrf', 'xsrftoken',
  'privatekey', 'passphrase', 'session', 'sessionid', 'sessionkey', 'sessiontoken', 'sessionsecret',
  'passwordhash', 'passwordverifier', 'passwordsalt', 'credentialverifier', 'salt',
  'remoteaddress', 'remoteip', 'clientip', 'peeraddress', 'socketaddress',
  'eos', 'eosid', 'eosaccountid', 'eosproductuserid', 'productuserid', 'epicaccountid',
  'accountid', 'playerid', 'playerdataid', 'arkplayerid', 'gameplayerid',
  'platform', 'platformid', 'platformuserid', 'platformaccountid',
  'discorduserid', 'userid', 'guildid', 'channelid', 'applicationid', 'interactionid',
  'webhookid', 'hostkey', 'hostkeysha256', 'fingerprint', 'email', 'emailaddress', 'useremail',
]);

function normalizedKey(key) {
  return String(key ?? '').replace(/[^a-z0-9]/gi, '').toLocaleLowerCase('en-US');
}

export function isSensitiveKey(key) {
  const normalized = normalizedKey(key);
  return SENSITIVE_KEYS.has(normalized)
    || /(?:remoteaddress|remoteip|clientip|peeraddress|socketaddress)$/u.test(normalized)
    || /(?:player(?:data|account|user)?id|eos(?:account|productuser)?id|platform(?:account|user)?id|accountid|userid)$/u.test(normalized)
    || /(?:accesskeyid|secretaccesskey|apikey)$/u.test(normalized)
    || /(?:csrf|xsrf)(?:token|secret|value|key)?$/u.test(normalized)
    || /session(?:id|key|token|secret)$/u.test(normalized)
    || /(?:email|emailaddress)$/u.test(normalized)
    || normalized.endsWith('password')
    || normalized.endsWith('passwordhash')
    || normalized.endsWith('passwordverifier')
    || normalized.endsWith('credentialverifier')
    || normalized.endsWith('passwordsalt')
    || normalized.endsWith('token')
    || normalized.endsWith('secret')
    || normalized.endsWith('privatekey');
}

function redactIpAddresses(value) {
  const withoutIpv6 = value.replace(IPV6_CANDIDATE_PATTERN, (candidate) => {
    if (!candidate.includes(':')) return candidate;
    const bracketed = candidate.startsWith('[') && candidate.endsWith(']');
    const unwrapped = bracketed ? candidate.slice(1, -1) : candidate;
    const zoneIndex = unwrapped.indexOf('%');
    const address = zoneIndex < 0 ? unwrapped : unwrapped.slice(0, zoneIndex);
    return isIP(address) === 6 ? '[IP ADDRESS REDACTED]' : candidate;
  });
  return withoutIpv6.replace(IPV4_CANDIDATE_PATTERN, (candidate) => (
    isIP(candidate) === 4 ? '[IP ADDRESS REDACTED]' : candidate
  ));
}

function redactJsonScalarProperties(value) {
  return value.replace(JSON_SCALAR_PROPERTY_PATTERN, (match, prefix, encodedKey) => {
    let key;
    try { key = JSON.parse(`"${encodedKey}"`); } catch { return match; }
    return isSensitiveKey(key) ? `${prefix}${JSON.stringify(REDACTED)}` : match;
  });
}

/** Collect configured values that must never cross an outbound text boundary. */
export function configuredRedactionSecrets(config = {}) {
  const persistence = config.persistence ?? {};
  const logging = config.logging ?? {};
  const values = [
    config.discord?.token,
    config.analytics?.token,
    config.analytics?.tokenFile,
    config.http?.adminToken,
    config.http?.ownerSetupToken,
    config.http?.tls?.key,
    config.http?.tls?.keyFile,
    config.http?.tls?.certFile,
    config.http?.tls?.caFile,
    config.http?.tls?.pfxFile,
    config.http?.tls?.passphrase,
    config.http?.tls?.passphraseFile,
    persistence.encryptionKey,
    persistence.encryptionKeyFile,
    persistence.file,
    persistence.legacyJsonFile,
    logging.encryptionKey,
    logging.encryptionKeyFile,
    logging.directory,
  ];
  for (const server of Array.isArray(config.servers) ? config.servers : []) {
    const profile = server?.profileImport ?? {};
    values.push(
      server?.host,
      server?.password,
      profile.host,
      profile.username,
      profile.password,
      profile.hostKeySha256,
      profile.directory,
      ...(Array.isArray(profile.directories) ? profile.directories : []),
    );
  }
  return [...new Set(values.filter((value) => typeof value === 'string' && value.length > 0))];
}

/**
 * Remove credential material and stable player/platform identifiers from text
 * before it crosses a logging, Discord, or public-HTTP boundary.
 */
export function redactText(value, secrets = []) {
  let text = String(value ?? '');
  const literals = [...new Set((Array.isArray(secrets) ? secrets : [])
    .filter((secret) => typeof secret === 'string' && secret.length > 0))]
    .sort((left, right) => right.length - left.length);
  for (const secret of literals) text = text.split(secret).join(REDACTED);
  text = redactJsonScalarProperties(text
    .replace(PEM_PRIVATE_KEY_PATTERN, '[PRIVATE KEY REDACTED]')
    .replace(DISCORD_ROUTE_TOKEN_PATTERN, `$1${REDACTED}`)
    .replace(URL_USERINFO_PATTERN, `$1${REDACTED}@`)
    .replace(AUTHORIZATION_PATTERN, `$1${REDACTED}`))
    .replace(URL_QUERY_CREDENTIAL_PATTERN, `$1${REDACTED}`)
    .replace(LABELED_SECRET_PATTERN, (_match, key, separator) => `${key}${separator}${REDACTED}`)
    .replace(LABELED_IDENTIFIER_PATTERN, (_match, key, separator) => `${key}${separator}[IDENTIFIER REDACTED]`)
    .replace(PROFILE_PATH_PATTERN, '[PROFILE PATH REDACTED]')
    .replace(JWT_PATTERN, '[TOKEN REDACTED]')
    .replace(DISCORD_TOKEN_PATTERN, REDACTED)
    .replace(AWS_ACCESS_KEY_PATTERN, '[ACCESS KEY REDACTED]')
    .replace(OPENSSH_FINGERPRINT_PATTERN, '[FINGERPRINT REDACTED]')
    .replace(HEX_FINGERPRINT_PATTERN, '[FINGERPRINT REDACTED]')
    .replace(PLAYER_DATA_ID_PATTERN, '$1[PLAYER ID REDACTED]')
    .replace(LABELED_ACCOUNT_ID_PATTERN, '$1[ACCOUNT ID REDACTED]')
    .replace(PLAYER_ASSIGNMENT_PATTERN, '$1[PLAYER ID REDACTED]')
    .replace(GAME_ACTOR_PATTERN, '$1[ACCOUNT ID REDACTED]')
    .replace(EOS_PREFIXED_ID_PATTERN, '[ACCOUNT ID REDACTED]')
    .replace(EOS_ID_PATTERN, '[ACCOUNT ID REDACTED]')
    .replace(DISCORD_SNOWFLAKE_PATTERN, '[PLATFORM ID REDACTED]')
    .replace(EMAIL_PATTERN, '[EMAIL REDACTED]');
  return redactIpAddresses(text);
}
