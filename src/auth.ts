/** Relay request authentication headers (08-relay § Authentication). */

import { ACEError } from './errors.js';
import { codePointLength, CONTROL_CHAR_RE, decimal, decodeSignature, encodeSignature, isACEId, isHttpsUrl, MAX_SAFE_INTEGER, wireInt } from './encoding.js';
import { MAX_INBOX_PAGE, TIMESTAMP_WINDOW_SECONDS } from './limits.js';
import { buildSignData, encodePayload, verifySignature } from './signing.js';
import type { ACEIdentity, SigningScheme } from './types.js';
import { isSigningScheme } from './types.js';

export type WebhookMethod = 'PUT' | 'GET' | 'DELETE';

export type RelayAuthRequest =
  | { action: 'listen'; since: string }
  | { action: 'inbox'; since: string; limit: number }
  | { action: 'unregister' }
  | { action: 'intent'; need: string; tags: string[]; maxPrice: string | null; currency: string | null; ttl: number }
  | { action: 'webhook'; method: WebhookMethod; url: string; secret: string };

export const WEBHOOK_SECRET_MIN = 16;
export const WEBHOOK_SECRET_MAX = 128;

/** A webhook secret: 16..128 code points, no control characters (08-relay § Webhooks). */
export function isWebhookSecret(v: unknown): v is string {
  if (typeof v !== 'string' || CONTROL_CHAR_RE.test(v)) return false;
  const n = codePointLength(v);
  return n >= WEBHOOK_SECRET_MIN && n <= WEBHOOK_SECRET_MAX;
}

export interface AuthHeaders {
  'X-ACE-Id': string;
  'X-ACE-Timestamp': string;
  'X-ACE-Signature': string;
}

export interface RelayAuth {
  aceId: string;
  timestamp: number;
  signature: string;
}

const SINCE_RE = /^(-|[0-9]+-[0-9]+)$/;
const TS_RE = /^(0|[1-9][0-9]{0,15})$/;

function bad(msg: string): ACEError {
  return new ACEError('invalid_argument', msg);
}

/** Validate a RelayAuthRequest and return its signed payload. */
export function authPayload(req: RelayAuthRequest): Uint8Array {
  if (typeof req !== 'object' || req === null) throw bad('expected a RelayAuthRequest');
  switch (req.action) {
    case 'listen':
      if (typeof req.since !== 'string' || !SINCE_RE.test(req.since)) throw bad("since must be '-' or '<ms>-<seq>'");
      return encodePayload(req.since);
    case 'inbox':
      if (typeof req.since !== 'string' || !SINCE_RE.test(req.since)) throw bad("since must be '-' or '<ms>-<seq>'");
      if (!Number.isSafeInteger(req.limit) || req.limit < 1 || req.limit > MAX_INBOX_PAGE) {
        throw bad(`limit must be an integer in 1..${MAX_INBOX_PAGE}`);
      }
      return encodePayload(req.since, decimal(req.limit));
    case 'unregister':
      return new Uint8Array(0);
    case 'intent': {
      if (typeof req.need !== 'string') throw bad('need must be a string');
      if (!Array.isArray(req.tags) || !req.tags.every((t) => typeof t === 'string' && !t.includes(','))) {
        throw bad("tags must be strings without ','");
      }
      for (const v of [req.maxPrice, req.currency]) {
        if (v !== null && v !== undefined && typeof v !== 'string') throw bad('maxPrice and currency must be strings or null');
      }
      if (wireInt(req.ttl) === null) throw bad('ttl must be an integer in [0, 2^53-1]');
      return encodePayload(req.need, req.tags.join(','), req.maxPrice ?? '', req.currency ?? '', decimal(req.ttl));
    }
    case 'webhook': {
      if (req.method !== 'PUT' && req.method !== 'GET' && req.method !== 'DELETE') throw bad('method must be PUT, GET or DELETE');
      if (typeof req.url !== 'string' || typeof req.secret !== 'string') throw bad('url and secret must be strings');
      if (req.method === 'PUT') {
        if (!isHttpsUrl(req.url)) throw bad('url must match the ACE HTTPS URL grammar');
        if (!isWebhookSecret(req.secret)) throw bad(`secret must be ${WEBHOOK_SECRET_MIN}..${WEBHOOK_SECRET_MAX} characters without control characters`);
      } else if (req.url !== '' || req.secret !== '') {
        throw bad(`${req.method} takes no url or secret`);
      }
      return encodePayload(req.method, req.url, req.secret);
    }
    default:
      throw bad('unknown action');
  }
}

/** `X-ACE-Id` / `X-ACE-Timestamp` / `X-ACE-Signature` for one relay call. */
export async function createAuthHeaders(identity: ACEIdentity, req: RelayAuthRequest, timestamp: number): Promise<AuthHeaders> {
  const payload = authPayload(req);
  if (wireInt(timestamp) === null) throw bad('timestamp must be an integer in [0, 2^53-1]');
  const aceId = identity.getACEId();
  const sig = await identity.sign(buildSignData(req.action, aceId, timestamp, payload));
  return {
    'X-ACE-Id': aceId,
    'X-ACE-Timestamp': decimal(timestamp),
    'X-ACE-Signature': encodeSignature(sig, identity.getSigningScheme()),
  };
}

/** Case-insensitive lookup, first value of a list; `invalid_argument` on bad input. */
export function parseAuthHeaders(headers: Record<string, string | string[] | undefined>): RelayAuth {
  if (typeof headers !== 'object' || headers === null) throw bad('headers must be an object');
  const found: Record<string, string> = {};
  for (const [k, raw] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if ((key !== 'x-ace-id' && key !== 'x-ace-timestamp' && key !== 'x-ace-signature') || key in found) continue;
    const v = Array.isArray(raw) ? raw[0] : raw;
    if (typeof v === 'string') found[key] = v;
  }
  const aceId = found['x-ace-id'];
  const ts = found['x-ace-timestamp'];
  const sig = found['x-ace-signature'];
  if (!isACEId(aceId)) throw bad('X-ACE-Id is missing or not an ACE ID');
  if (ts === undefined || !TS_RE.test(ts) || Number(ts) > MAX_SAFE_INTEGER) throw bad('X-ACE-Timestamp is missing or malformed');
  if (!sig || sig.length > 512) throw bad('X-ACE-Signature is missing');
  return { aceId, timestamp: Number(ts), signature: sig };
}

/**
 * Stateless: this only checks freshness and the signature. The caller (a relay) MUST also
 * enforce once-only acceptance of each `(action, aceId, signature)` while its timestamp is inside
 * the window, rejecting repeats with 409 `replay` (08-relay § Authentication).
 *
 * Check order: `auth.aceId !== signer.aceId` → `invalid_argument`; `|now - ts| > window` →
 * `stale_timestamp`; bad encoding or signature → `invalid_signature`.
 */
export function verifyAuthHeaders(
  auth: RelayAuth,
  req: RelayAuthRequest,
  signer: { aceId: string; scheme: SigningScheme; signingPublicKey: Uint8Array },
  opts: { clock?: () => number; windowSeconds?: number } = {},
): void {
  if (typeof auth !== 'object' || auth === null || typeof signer !== 'object' || signer === null || !isSigningScheme(signer.scheme)) {
    throw bad('expected RelayAuth, RelayAuthRequest and a signer');
  }
  const payload = authPayload(req);
  const windowSeconds = opts.windowSeconds ?? TIMESTAMP_WINDOW_SECONDS;
  if (!Number.isSafeInteger(windowSeconds) || windowSeconds < 0) throw bad('windowSeconds must be a non-negative integer');
  if (auth.aceId !== signer.aceId) throw bad('X-ACE-Id does not match the signer');
  const now = Math.floor(opts.clock ? opts.clock() : Date.now() / 1000);
  if (Math.abs(now - auth.timestamp) > windowSeconds) {
    throw new ACEError('stale_timestamp', 'X-ACE-Timestamp is outside the freshness window');
  }
  const sig = decodeSignature(auth.signature, signer.scheme, 'invalid_signature');
  if (!verifySignature(buildSignData(req.action, auth.aceId, auth.timestamp, payload), sig, signer.scheme, signer.signingPublicKey)) {
    throw new ACEError('invalid_signature', 'X-ACE-Signature does not verify');
  }
}
