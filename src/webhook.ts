/** Webhook notifications (08-relay § Webhooks): signing (relay side) and verification (agent side). */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { ACEError } from './errors.js';
import { decimal, isACEId, utf8, wireInt } from './encoding.js';
import { TIMESTAMP_WINDOW_SECONDS } from './limits.js';

const TS_RE = /^(0|[1-9][0-9]{0,15})$/;
const SIG_RE = /^sha256=[0-9a-f]{64}$/;
const STREAM_RE = /^[0-9]{1,20}-[0-9]{1,20}$/;

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
  if (wireInt(timestamp) === null) throw new ACEError('invalid_argument', 'timestamp must be a wire integer');
  const raw = typeof body === 'string' ? utf8(body) : body;
  return 'sha256=' + createHmac('sha256', secret).update(`${decimal(timestamp)}.`).update(raw).digest('hex');
}

/**
 * Check order: malformed timestamp → `invalid_argument`; malformed signature →
 * `invalid_signature`; freshness → `stale_timestamp`; HMAC (constant time) →
 * `invalid_signature`; body shape → `invalid_argument`.
 */
export function verifyWebhookNotification(o: WebhookNotificationInput): WebhookNotification {
  if (typeof o !== 'object' || o === null || typeof o.secret !== 'string' || typeof o.timestamp !== 'string' || typeof o.signature !== 'string') {
    throw new ACEError('invalid_argument', 'secret, timestamp and signature must be strings');
  }
  if (!TS_RE.test(o.timestamp)) throw new ACEError('invalid_argument', 'X-ACE-Webhook-Timestamp is malformed');
  if (!SIG_RE.test(o.signature)) throw new ACEError('invalid_signature', 'X-ACE-Webhook-Signature is malformed');
  const ts = Number(o.timestamp);
  const window = o.windowSeconds ?? TIMESTAMP_WINDOW_SECONDS;
  if (!Number.isSafeInteger(window) || window < 0) throw new ACEError('invalid_argument', 'windowSeconds must be a non-negative integer');
  const now = Math.floor(o.clock ? o.clock() : Date.now() / 1000);
  if (Math.abs(now - ts) > window) throw new ACEError('stale_timestamp', 'X-ACE-Webhook-Timestamp is outside the freshness window');
  const expected = signWebhookNotification(o.secret, ts, o.body);
  if (!timingSafeEqual(Buffer.from(expected), Buffer.from(o.signature))) {
    throw new ACEError('invalid_signature', 'X-ACE-Webhook-Signature does not verify');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(typeof o.body === 'string' ? o.body : new TextDecoder('utf-8', { fatal: true }).decode(o.body));
  } catch {
    throw new ACEError('invalid_argument', 'notification body is not JSON');
  }
  const n = parsed as { event?: unknown; aceId?: unknown; streamId?: unknown };
  if (typeof n !== 'object' || n === null || n.event !== 'message' || !isACEId(n.aceId) || typeof n.streamId !== 'string' || !STREAM_RE.test(n.streamId)) {
    throw new ACEError('invalid_argument', 'notification body must be {event: "message", aceId, streamId}');
  }
  return { aceId: n.aceId, streamId: n.streamId };
}
