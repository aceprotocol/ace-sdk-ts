/**
 * Relay request authentication (07 § Authentication): the client's headers and the relay-side verifier. The signed
 * payload is `encodePayload(audience, nonce, actionPayload)` with ctx = action, as a delegated signature.
 */

import { ACEError } from './errors.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { isCanonicalRelayUrl } from './relay-url.js';
import { decimal, isACEId, isHex64, isObj, isPlainObject, isStreamId, nowOf, wireInt } from './encoding.js';
import { MAX_INBOX_PAGE, TIMESTAMP_WINDOW_SECONDS } from './limits.js';
import { encodePayload } from './signing.js';
import { signOperational, type ACEIdentity } from './identity.js';
import { isUsable, verifyOperationalSignature, type KelState } from './kel.js';

/** Authenticated relay calls and their action payloads (02 § Signing actions). */
export type RelayAuthRequest =
  /** payload (sinceOrDash) */
  | { action: 'listen'; since: string }
  /** payload (sinceOrDash, decimal(limit)) */
  | { action: 'inbox'; since: string; limit: number }
  /** payload (through): delete inbox entries up to and including this stream ID */
  | { action: 'inbox-ack'; through: string }
  | { action: 'unregister' }
  /** payload (peer, "block" | "unblock", decimal(revision)); revision strictly increases per (owner, peer) */
  | { action: 'block'; peer: string; blocked: boolean; revision: number }
  /** payload (gateway, token) for `PUT /v1/wake`; both omitted (empty payload) for `DELETE /v1/wake` */
  | { action: 'wake'; gateway?: string; token?: string };

/** A wake token (07 § Wake hints): opaque, issued by the gateway. */
export const WAKE_TOKEN_RE = /^[A-Za-z0-9_-]{22,512}$/;

export interface AuthHeaders {
  'X-ACE-Audience': string;
  'X-ACE-Nonce': string;
  'X-ACE-Id': string;
  'X-ACE-Timestamp': string;
  'X-ACE-Seq': string;
  'X-ACE-Signature': string;
}

/** Parsed auth headers. */
export interface RelayAuth {
  audience: string;
  nonce: string;
  aceId: string;
  timestamp: number;
  /** The signing delegation's `seq` (`X-ACE-Seq`). */
  seq: number;
  signature: string;
}

const AUTH_HEADERS = ['x-ace-id', 'x-ace-timestamp', 'x-ace-seq', 'x-ace-signature', 'x-ace-audience', 'x-ace-nonce'] as const;
/** Canonical Base64 of a 3309-byte ML-DSA-65 signature. */
const SIGNATURE_CHARS = 4412;
const TS_RE = /^(0|[1-9][0-9]{0,15})$/;

function bad(msg: string): ACEError {
  return new ACEError('invalid_argument', msg);
}

/** A canonical decimal header in [0, 2^53−1], or null. */
function parseDecimal(s: string | undefined): number | null {
  if (s === undefined || !TS_RE.test(s)) return null;
  return wireInt(Number(s));
}

/** Internal: `stale_timestamp` when `|now − ts| > TIMESTAMP_WINDOW_SECONDS`. */
export function assertFresh(ts: number, now: number, what: string): void {
  if (Math.abs(now - ts) > TIMESTAMP_WINDOW_SECONDS) throw new ACEError('stale_timestamp', `${what} is outside the freshness window`);
}

/** Internal: validate a RelayAuthRequest and return its action payload. */
export function authPayload(req: RelayAuthRequest): Uint8Array {
  if (typeof req !== 'object' || req === null) throw bad('expected a RelayAuthRequest');
  switch (req.action) {
    case 'listen':
      if (req.since !== '-' && !isStreamId(req.since)) throw bad("since must be '-' or '<ms>-<seq>'");
      return encodePayload(req.since);
    case 'inbox-ack':
      if (!isStreamId(req.through)) throw bad("through must be '<ms>-<seq>'");
      return encodePayload(req.through);
    case 'inbox':
      if (req.since !== '-' && !isStreamId(req.since)) throw bad("since must be '-' or '<ms>-<seq>'");
      if (!Number.isSafeInteger(req.limit) || req.limit < 1 || req.limit > MAX_INBOX_PAGE) {
        throw bad(`limit must be an integer in 1..${MAX_INBOX_PAGE}`);
      }
      return encodePayload(req.since, decimal(req.limit));
    case 'block':
      if (!isACEId(req.peer) || typeof req.blocked !== 'boolean' || wireInt(req.revision) === null) throw bad('invalid block');
      return encodePayload(req.peer, req.blocked ? 'block' : 'unblock', decimal(req.revision));
    case 'unregister':
      return new Uint8Array(0);
    case 'wake':
      if (req.gateway === undefined && req.token === undefined) return new Uint8Array(0);
      // Loopback HTTP is a development gateway; the caller applies its own loopback policy.
      if (typeof req.gateway !== 'string' || !isCanonicalRelayUrl(req.gateway, { allowLoopback: true }) || typeof req.token !== 'string' || !WAKE_TOKEN_RE.test(req.token)) {
        throw bad('wake needs a canonical https gateway and a token');
      }
      return encodePayload(req.gateway, req.token);
    default:
      throw bad('unknown action');
  }
}

/** `encodePayload(audience, nonce, actionPayload)`: what a header-authenticated action signs. */
function headerPayload(req: RelayAuthRequest, audience: string, nonce: string): Uint8Array {
  // The audience is a relay's own configured URL: loopback HTTP is its development setup.
  if (!isCanonicalRelayUrl(audience, { allowLoopback: true })) throw bad('audience must be a canonical relay URL');
  if (!isHex64(nonce)) throw bad('nonce must be 32 random bytes in lowercase hex');
  return encodePayload(audience, nonce, authPayload(req));
}

/** The six `X-ACE-*` headers of one relay call; `identity_unavailable` when the identity cannot sign at `timestamp`. */
export async function createAuthHeaders(identity: ACEIdentity, req: RelayAuthRequest, timestamp: number, options: { audience: string; nonce?: string }): Promise<AuthHeaders> {
  const nonce = options?.nonce ?? bytesToHex(randomBytes(32));
  const audience = options?.audience;
  const payload = headerPayload(req, audience, nonce);
  if (wireInt(timestamp) === null) throw bad('timestamp must be an integer in [0, 2^53-1]');
  const sig = await signOperational(identity, timestamp, payload, req.action);
  return {
    'X-ACE-Audience': audience,
    'X-ACE-Nonce': nonce,
    'X-ACE-Id': identity.getACEId(),
    'X-ACE-Timestamp': decimal(timestamp),
    'X-ACE-Seq': decimal(sig.seq),
    'X-ACE-Signature': sig.value,
  };
}

/**
 * Relay side: parse the auth headers (case-insensitive, first value of a list); any missing or malformed header is
 * `invalid_argument`. `headers` must be a plain object (e.g. node's `IncomingMessage.headers`).
 */
export function parseAuthHeaders(headers: Record<string, string | string[] | undefined>): RelayAuth {
  if (!isObj(headers) || !isPlainObject(headers)) throw bad('headers must be a plain object');
  const found: Record<string, string> = {};
  for (const [k, raw] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (!(AUTH_HEADERS as readonly string[]).includes(key) || Object.hasOwn(found, key)) continue;
    const v = Array.isArray(raw) ? raw[0] : raw;
    if (typeof v === 'string') found[key] = v;
  }
  const [aceId, ts, seqText, sig, audience, nonce] = AUTH_HEADERS.map((h) => (Object.hasOwn(found, h) ? found[h] : undefined));
  headerPayload({ action: 'unregister' }, audience!, nonce!);
  if (!isACEId(aceId)) throw bad('X-ACE-Id is missing or not an ACE ID');
  const timestamp = parseDecimal(ts);
  if (timestamp === null) throw bad('X-ACE-Timestamp is missing or malformed');
  const seq = parseDecimal(seqText);
  if (seq === null) throw bad('X-ACE-Seq is missing or malformed');
  if (typeof sig !== 'string' || sig.length !== SIGNATURE_CHARS) throw bad(`X-ACE-Signature must be ${SIGNATURE_CHARS} characters`);
  return { aceId, timestamp, seq, signature: sig, audience: audience!, nonce: nonce! };
}

/**
 * Relay side, after `parseAuthHeaders` and the registration lookup (`not_registered`), in 07 order: a registered KEL
 * that delegates no signing key is `stale_peer_binding`; `X-ACE-Seq` against
 * the registered delegation (lower `stale_seq`, higher `future_seq`); the relay's own audience (`invalid_signature`);
 * `|now - timestamp| <= TIMESTAMP_WINDOW_SECONDS` (`stale_timestamp`); signed while live and the registered KEL usable
 * at `now` (`stale_peer_binding`); the signature (`invalid_signature`). `registered` is the verified state of the
 * registered KEL. Stateless: the caller then reserves the nonce once (`409 replay`).
 */
export function verifyAuthHeaders(auth: RelayAuth, req: RelayAuthRequest, registered: KelState, opts: { audience: string; clock?: () => number }): void {
  if (!isObj(auth) || !isObj(registered) || typeof auth.aceId !== 'string' || wireInt(auth.timestamp) === null || wireInt(auth.seq) === null) {
    throw bad('expected a RelayAuth and the registered KEL state');
  }
  const payload = headerPayload(req, auth.audience, auth.nonce);
  if (auth.aceId !== registered.aceId) throw bad('X-ACE-Id is not the registered identity');
  if (registered.signing === null) throw new ACEError('stale_peer_binding', 'the registered KEL delegates no signing key');
  const current = registered.signing.seq;
  if (auth.seq < current) throw new ACEError('stale_seq', 'X-ACE-Seq names a superseded signing delegation');
  if (auth.seq > current) throw new ACEError('future_seq', 'X-ACE-Seq is ahead of the registered KEL');
  if (opts?.audience !== auth.audience) throw new ACEError('invalid_signature', 'relay audience mismatch');
  const now = nowOf(opts.clock);
  assertFresh(auth.timestamp, now, 'X-ACE-Timestamp');
  if (!isUsable(registered, now)) throw new ACEError('stale_peer_binding', 'the registered KEL is not usable now');
  const signature = { scheme: 'ml-dsa-65', seq: auth.seq, value: auth.signature };
  verifyOperationalSignature(registered, req.action, auth.timestamp, payload, signature, now, 'invalid_signature');
}
