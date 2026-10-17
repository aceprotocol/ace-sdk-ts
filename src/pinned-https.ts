/**
 * Outbound-request safety: the SSRF blocklist, bounded body reads and one HTTPS request connected only to an already
 * validated address (DNS pinning). The only copy of these rules (used by `publicRelay`).
 */

import { concat } from './encoding.js';
import { ACEError } from './errors.js';

export type HttpsModule = Pick<typeof import('node:https'), 'request'>;

export interface PinnedResponse {
  status: number;
  contentType: string;
  /** At most `limit` bytes of the body. */
  body: () => Promise<Uint8Array>;
}

export interface PinnedRequest {
  /** Host name for the Host header, SNI and certificate validation. */
  host: string;
  /** The validated address the connection goes to. */
  addr: { address: string; family: number };
  port: number;
  path: string;
  method: 'GET' | 'POST';
  headers: Record<string, string>;
  body?: Uint8Array;
  timeoutMs: number;
  limit: number;
  /** Whether the body of a response with this status will be read (otherwise it is discarded). */
  readBody: (status: number) => boolean;
  /** The error for a network failure, timeout or read failure. */
  fail: (message: string) => ACEError;
}

const IP_LITERAL = /^(?:[0-9.]+|.*:.*)$/;

/** One request pinned to `o.addr`; redirects are never followed (Node's https does not). */
export function pinnedRequest(https: HttpsModule, o: PinnedRequest): Promise<PinnedResponse> {
  return new Promise((resolve, reject) => {
    const fail = (e: unknown) => reject(e instanceof ACEError ? e : o.fail(`request failed: ${e instanceof Error ? e.message : String(e)}`));
    const pinned = (_host: string, opts: unknown, cb: (...args: unknown[]) => void) => {
      const all = typeof opts === 'object' && opts !== null && (opts as { all?: boolean }).all === true;
      if (all) cb(null, [{ address: o.addr.address, family: o.addr.family }]);
      else cb(null, o.addr.address, o.addr.family);
    };
    const timer = setTimeout(() => {
      req.destroy(o.fail(`timed out after ${o.timeoutMs} ms`));
    }, o.timeoutMs);
    (timer as { unref?: () => void }).unref?.();
    const req = https.request({
      host: o.host, ...(IP_LITERAL.test(o.host) ? {} : { servername: o.host }), port: o.port, path: o.path, method: o.method,
      headers: o.headers, lookup: pinned as never, agent: false,
    }, (msg) => {
      const status = msg.statusCode ?? 0;
      const contentType = String(msg.headers['content-type'] ?? '');
      const body = () => new Promise<Uint8Array>((res2, rej2) => {
        const chunks: Buffer[] = [];
        let total = 0;
        let done = false;
        const finish = () => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          res2(new Uint8Array(Buffer.concat(chunks).subarray(0, o.limit)));
        };
        msg.on('data', (c: Buffer) => {
          chunks.push(c);
          total += c.length;
          if (total >= o.limit) {
            finish();
            msg.destroy();
          }
        });
        msg.on('end', finish);
        msg.on('error', (e) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          rej2(o.fail(`read failed: ${e.message}`));
        });
      });
      if (!o.readBody(status)) {
        clearTimeout(timer);
        msg.resume();
      }
      resolve({ status, contentType, body });
    });
    req.on('error', (e) => {
      clearTimeout(timer);
      fail(e);
    });
    req.end(o.body);
  });
}

// --- blocked addresses ---------------------------------------------------------------------

const V4_BLOCKED: Array<[number, number]> = ([
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
] as Array<[string, number]>).map(([a, p]) => [parseV4(a)!, p]);

const V6_BLOCKED: Array<[Uint8Array, number]> = ([
  // Transition ranges that embed an IPv4 address are blocked whole (fail closed): IPv4-compatible
  // ::/96 (includes :: and ::1), SIIT ::ffff:0:0:0/96, local-use NAT64 64:ff9b:1::/48, 6to4 2002::/16; and the IETF
  // protocol assignments 2001::/23 (Teredo included), documentation 3fff::/20, SRv6 SIDs 5f00::/16, site-local fec0::/10.
  ['::', 96], ['::ffff:0:0:0', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23], ['2001:db8::', 32],
  ['2002::', 16], ['3fff::', 20], ['5f00::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8],
] as Array<[string, number]>).map(([a, p]) => [parseV6(a)!, p]);
/** IPv4-mapped ::ffff:0:0/96 and NAT64 64:ff9b::/96: judged by the embedded IPv4. */
const V6_MAPPED = parseV6('::ffff:0:0')!;
const V6_NAT64 = parseV6('64:ff9b::')!;

function parseV4(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^[0-9]{1,3}$/.test(p) || Number(p) > 255) return null;
    n = n * 256 + Number(p);
  }
  return n;
}

function parseV6(ip: string): Uint8Array | null {
  if (!ip.includes(':')) return null;
  let s = ip.split('%')[0].toLowerCase(); // a %zone is ignored
  let tail: number[] = [];
  if (s.includes('.')) {
    const i = s.lastIndexOf(':');
    const v4 = parseV4(s.slice(i + 1));
    if (i < 0 || v4 === null) return null;
    tail = [(v4 >>> 16) & 0xffff, v4 & 0xffff];
    s = s.slice(0, i + 1);
    if (!s.endsWith('::')) s = s.slice(0, -1);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parse = (h: string) => (h === '' ? [] : h.split(':').map((x) => (/^[0-9a-f]{1,4}$/.test(x) ? parseInt(x, 16) : NaN)));
  const head = parse(halves[0]);
  const back = halves.length === 2 ? parse(halves[1]) : [];
  const groups = halves.length === 2
    ? [...head, ...new Array(8 - head.length - back.length - tail.length).fill(0), ...back, ...tail]
    : [...head, ...tail];
  if (groups.length !== 8 || groups.some((g) => Number.isNaN(g) || g < 0 || g > 0xffff)) return null;
  const out = new Uint8Array(16);
  groups.forEach((g, i) => { out[2 * i] = g >> 8; out[2 * i + 1] = g & 0xff; });
  return out;
}

function inV6(addr: Uint8Array, net: Uint8Array, prefix: number): boolean {
  for (let bit = 0; bit < prefix; bit++) {
    const byte = bit >> 3;
    const mask = 0x80 >> (bit & 7);
    if ((addr[byte] & mask) !== (net[byte] & mask)) return false;
  }
  return true;
}

function v4Blocked(n: number): boolean {
  return V4_BLOCKED.some(([net, p]) => Math.floor(n / 2 ** (32 - p)) === Math.floor(net / 2 ** (32 - p)));
}

/**
 * SSRF blocklist (07 § Client rules, Blocked addresses): true for any blocked address, or an input that is not an IP
 * literal. IPv4-mapped and 64:ff9b::/96 are judged by the embedded IPv4; other IPv4-embedding transition ranges
 * (::/96, ::ffff:0:0:0/96, 64:ff9b:1::/48, 2001::/32, 2002::/16) are blocked whole. Exported so hosts that open their
 * own connections apply the same policy.
 */
export function isBlockedAddress(ip: string): boolean {
  const v4 = parseV4(ip);
  if (v4 !== null) return v4Blocked(v4);
  const v6 = parseV6(ip);
  if (v6 === null) return true;
  if (inV6(v6, V6_MAPPED, 96) || inV6(v6, V6_NAT64, 96)) {
    return v4Blocked(((v6[12] << 24) >>> 0) + (v6[13] << 16) + (v6[14] << 8) + v6[15]);
  }
  return V6_BLOCKED.some(([net, p]) => inV6(v6, net, p));
}

/** A parsed IP literal; an IPv4-mapped IPv6 address (`::ffff:0:0/96`) is its IPv4 address. */
export interface ParsedIp { family: 4 | 6; bytes: Uint8Array }

/** Parse an IPv4 (dotted quad) or IPv6 literal without a zone; anything else is null. */
export function parseIp(ip: string): ParsedIp | null {
  if (typeof ip !== 'string') return null;
  const v4 = parseV4(ip);
  if (v4 !== null) return { family: 4, bytes: new Uint8Array([v4 >>> 24, (v4 >>> 16) & 255, (v4 >>> 8) & 255, v4 & 255]) };
  if (ip.includes('%')) return null;
  const v6 = parseV6(ip);
  if (v6 === null) return null;
  return inV6(v6, V6_MAPPED, 96) ? { family: 4, bytes: v6.slice(12) } : { family: 6, bytes: v6 };
}

/**
 * The client network of an address, for relay quotas: its IPv4 /`v4Prefix` (default /24; IPv4-mapped IPv6 included) or
 * IPv6 /`v6Prefix` (default /56), written `203.0.113.0/24` or `2001:db8:1234:5600::/56`. `invalid_argument` for an
 * input that is not an IP literal.
 */
export function networkKey(ip: string, o: { v4Prefix?: number; v6Prefix?: number } = {}): string {
  const p = parseIp(ip);
  if (p === null) throw new ACEError('invalid_argument', 'not an IP address');
  const prefix = p.family === 4 ? o.v4Prefix ?? 24 : o.v6Prefix ?? 56;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > p.bytes.length * 8) throw new ACEError('invalid_argument', 'invalid network prefix');
  const b = p.bytes.map((x, i) => (i * 8 >= prefix ? 0 : i * 8 + 8 <= prefix ? x : x & (0xff << (8 - (prefix - i * 8))) & 0xff));
  if (p.family === 4) return `${b.join('.')}/${prefix}`;
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((b[i] << 8) | b[i + 1]).toString(16));
  let end = groups.length;   // compress the trailing zero groups only: a stable, readable key
  while (end > 0 && groups[end - 1] === '0') end--;
  return `${end === 8 ? groups.join(':') : `${groups.slice(0, end).join(':')}::`}/${prefix}`;
}

/** Internal: read at most `limit` bytes of a response body, cancelling the rest. */
export async function readLimited(res: Response, limit: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (res.body === null) return new Uint8Array(0);
  const reader = res.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const take = value.subarray(0, Math.max(0, limit - total));
      chunks.push(take);
      total += take.length;
      if (total >= limit) {
        await reader.cancel().catch(() => {});
        break;
      }
    }
  } finally {
    reader.releaseLock();
  }
  return concat(chunks);
}

