/** Webhook notifications (08-relay § Webhooks): signing (relay side) and verification (agent side). */

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { ACEError } from './errors.js';
import { assertFresh, freshnessWindow, parseTimestamp } from './auth.js';
import { decimal, isACEId, isStreamId, utf8, wireInt } from './encoding.js';

const SIG_RE = /^sha256=[0-9a-f]{64}$/;
const bodyDecoder = new TextDecoder('utf-8', { fatal: true });

export interface WebhookNotification { aceId: string; streamId: string }

export interface WebhookNotificationInput {
  secret: string;
  /** The `X-ACE-Webhook-Timestamp` header. */
  timestamp: string;
  /** The `X-ACE-Webhook-Signature` header. */
  signature: string;
  /** The raw request body. */
  body: Uint8Array | string;
  clock?: () => number;
  windowSeconds?: number;
}

/** `sha256=<hex HMAC-SHA256(secret, decimal(timestamp) || "." || body)>`. */
export function signWebhookNotification(secret: string, timestamp: number, body: Uint8Array | string): string {
  if (typeof secret !== 'string') throw new ACEError('invalid_argument', 'secret must be a string');
  if (wireInt(timestamp) === null) throw new ACEError('invalid_argument', 'timestamp must be a wire integer');
  return 'sha256=' + bytesToHex(webhookMac(secret, timestamp, body));
}

function webhookMac(secret: string, timestamp: number, body: Uint8Array | string): Uint8Array {
  return hmac.create(sha256, utf8(secret))
    .update(utf8(`${decimal(timestamp)}.`))
    .update(typeof body === 'string' ? utf8(body) : body)
    .digest();
}

/** Constant-time comparison of a MAC with lowercase hex `expected` (length already checked). */
function macEquals(mac: Uint8Array, expectedHex: string): boolean {
  const got = bytesToHex(mac);
  if (got.length !== expectedHex.length) return false;
  let diff = 0;
  for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ expectedHex.charCodeAt(i);
  return diff === 0;
}

/**
 * Check order: `secret`/`timestamp`/`signature` not strings → `invalid_argument`; malformed
 * timestamp (not canonical decimal, or above 2^53−1) → `invalid_argument`; malformed signature
 * (not `sha256=` + 64 lowercase hex) → `invalid_signature`; `windowSeconds` not a non-negative
 * safe integer → `invalid_argument`; freshness (`|now − ts| > windowSeconds`) →
 * `stale_timestamp`; HMAC (constant time) → `invalid_signature`; body not UTF-8 JSON of shape
 * `{event: "message", aceId, streamId}` → `invalid_argument`.
 */
export function verifyWebhookNotification(o: WebhookNotificationInput): WebhookNotification {
  if (typeof o !== 'object' || o === null || typeof o.secret !== 'string' || typeof o.timestamp !== 'string' || typeof o.signature !== 'string') {
    throw new ACEError('invalid_argument', 'secret, timestamp and signature must be strings');
  }
  const ts = parseTimestamp(o.timestamp);
  if (ts === null) throw new ACEError('invalid_argument', 'X-ACE-Webhook-Timestamp is malformed');
  if (!SIG_RE.test(o.signature)) throw new ACEError('invalid_signature', 'X-ACE-Webhook-Signature is malformed');
  assertFresh(ts, freshnessWindow(o.windowSeconds), o.clock, 'X-ACE-Webhook-Timestamp');
  if (typeof o.body !== 'string' && !(o.body instanceof Uint8Array)) throw new ACEError('invalid_argument', 'body must be bytes or a string');
  if (!macEquals(webhookMac(o.secret, ts, o.body), o.signature.slice('sha256='.length))) {
    throw new ACEError('invalid_signature', 'X-ACE-Webhook-Signature does not verify');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(typeof o.body === 'string' ? o.body : bodyDecoder.decode(o.body));
  } catch {
    throw new ACEError('invalid_argument', 'notification body is not JSON');
  }
  const n = parsed as { event?: unknown; aceId?: unknown; streamId?: unknown };
  if (typeof n !== 'object' || n === null || n.event !== 'message' || !isACEId(n.aceId) || !isStreamId(n.streamId)) {
    throw new ACEError('invalid_argument', 'notification body must be {event: "message", aceId, streamId}');
  }
  return { aceId: n.aceId, streamId: n.streamId };
}
