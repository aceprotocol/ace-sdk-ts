import { isHttpsUrl } from './encoding.js';
import { ACEError } from './errors.js';

/** 02 § Relay URL: the length bound of a canonical relay URL. */
const MAX_RELAY_URL_LENGTH = 2048;

const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

/**
 * A canonical relay URL (02 § Relay URL): `https`, at most 2048 characters, equal to its own normalization, its host in
 * the ACE HTTPS URL grammar (labels of `[A-Za-z0-9-]` not starting or ending with `-`, no empty label or trailing `.`,
 * no IP literal). `allowLoopback` (local development) also admits `http` to a loopback host; production verifiers reject it.
 */
export function isCanonicalRelayUrl(value: unknown, o: { allowLoopback: boolean }): value is string {
  if (typeof value !== 'string' || value.length > MAX_RELAY_URL_LENGTH) return false;
  try {
    if (normalizeRelayUrl(value) !== value) return false;
  } catch {
    return false;
  }
  const u = new URL(value);
  if (u.protocol === 'https:') return isHttpsUrl(value);
  return o.allowLoopback && LOOPBACK_HOSTS.includes(u.hostname);
}

/**
 * Normalize a relay base URL (02 § Relay URLs): scheme `http`/`https`
 * written lowercase; no `?`, `#`, userinfo, or character <= U+0020 or U+007F (nothing is
 * trimmed); host ASCII `[A-Za-z0-9.-]+` or a bracketed IPv6 literal, written lowercase; port
 * 1..65535 without leading zeros, the scheme's default port removed; path kept verbatim
 * except that all trailing `/` are removed. Anything else is `invalid_argument`.
 */
export function normalizeRelayUrl(url: string): string {
  const bad = (why: string) => new ACEError('invalid_argument', `relay URL ${why}`);
  if (typeof url !== 'string') throw bad('must be a string');
  if (/[\u0000-\u0020\u007f?#]/.test(url)) throw bad('must not contain whitespace, control characters, "?" or "#"');
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/]*)(.*)$/s.exec(url);
  if (m === null) throw bad('must be an absolute http(s) URL');
  const scheme = m[1].toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') throw bad('scheme must be http or https');
  const authority = m[2];
  if (authority.includes('@')) throw bad('must not contain userinfo');
  let host: string;
  let port: string | undefined;
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']');
    if (end < 0) throw bad('has an invalid IPv6 host');
    host = authority.slice(0, end + 1);
    const rest = authority.slice(end + 1);
    if (rest !== '') {
      if (!rest.startsWith(':')) throw bad('has an invalid authority');
      port = rest.slice(1);
    }
    // an IPv6 literal (the WHATWG parser rejects anything else, including a zone)
    if (!/^\[[0-9A-Fa-f:.]+\]$/.test(host)) throw bad('has an invalid IPv6 host');
    try {
      new URL(`http://${host}/`);
    } catch {
      throw bad('has an invalid IPv6 host');
    }
  } else {
    const colon = authority.indexOf(':');
    host = colon < 0 ? authority : authority.slice(0, colon);
    if (colon >= 0) port = authority.slice(colon + 1);
    if (!/^[A-Za-z0-9.-]+$/.test(host)) throw bad('host must be ASCII [A-Za-z0-9.-]');
  }
  host = host.toLowerCase();
  if (port !== undefined) {
    if (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535) throw bad('has an invalid port');
    if ((scheme === 'https' && port === '443') || (scheme === 'http' && port === '80')) port = undefined;
  }
  return `${scheme}://${host}${port !== undefined ? `:${port}` : ''}${m[3].replace(/\/+$/, '')}`;
}

