/** The single ACE SDK error type (06-security § SDK Error Codes). */

export type ACEErrorCategory = 'permanent' | 'transient' | 'local';

export type ACEErrorCode =
  // permanent
  | 'invalid_argument' | 'invalid_envelope' | 'unsupported_version' | 'wrong_recipient'
  | 'invalid_signature' | 'invalid_authorization' | 'scheme_mismatch' | 'stale_timestamp'
  | 'replay' | 'decryption_failed' | 'invalid_body' | 'transition_not_allowed' | 'wrong_role'
  | 'wrong_party' | 'bad_reference' | 'limit_exceeded' | 'invalid_key' | 'invalid_registration'
  | 'invalid_profile' | 'invalid_principal' | 'wrong_principal' | 'invalid_peer' | 'stale_peer_binding' | 'unknown_peer' | 'not_registered'
  | 'relay_rejected' | 'envelope_expired' | 'pending_send_conflict' | 'blocked_address' | 'direct_rejected'
  // transient
  | 'relay_unavailable' | 'relay_protocol_error' | 'fetch_failed' | 'direct_unavailable'
  // local
  | 'storage_failed' | 'identity_unavailable' | 'handler_failed' | 'receiver_busy' | 'lock_busy';

const TRANSIENT: ReadonlySet<string> = new Set(['relay_unavailable', 'relay_protocol_error', 'fetch_failed', 'direct_unavailable']);
const LOCAL: ReadonlySet<string> = new Set(['storage_failed', 'identity_unavailable', 'handler_failed', 'receiver_busy', 'lock_busy']);
const ALL: ReadonlySet<string> = new Set([
  'invalid_argument', 'invalid_envelope', 'unsupported_version', 'wrong_recipient',
  'invalid_signature', 'invalid_authorization', 'scheme_mismatch', 'stale_timestamp',
  'replay', 'decryption_failed', 'invalid_body', 'transition_not_allowed', 'wrong_role',
  'wrong_party', 'bad_reference', 'limit_exceeded', 'invalid_key', 'invalid_registration',
  'invalid_profile', 'invalid_principal', 'wrong_principal', 'invalid_peer', 'stale_peer_binding', 'unknown_peer', 'not_registered',
  'relay_rejected', 'envelope_expired', 'pending_send_conflict', 'blocked_address', 'direct_rejected',
  ...TRANSIENT, ...LOCAL,
]);

export interface ACEErrorOptions {
  status?: number;
  relayCode?: string;
  /** `direct_rejected`: the receiver's `error` string (08-relay § Direct Delivery). */
  remoteCode?: string;
  retryAfterSeconds?: number;
  cause?: unknown;
}

let detailOf: (e: ACEError) => string;

/** Internal: the fixed category of a code. */
export function categoryOf(code: ACEErrorCode): ACEErrorCategory {
  if (TRANSIENT.has(code)) return 'transient';
  if (LOCAL.has(code)) return 'local';
  return 'permanent';
}

/**
 * Every SDK-originated failure. `category` is a fixed function of `code`;
 * `isTransient` is `category !== 'permanent'` (transient and local failures are retryable).
 */
export class ACEError extends Error {
  readonly code: ACEErrorCode;
  readonly status?: number;
  readonly relayCode?: string;
  readonly remoteCode?: string;
  readonly retryAfterSeconds?: number;
  readonly #detail: string;

  static {
    detailOf = (e) => e.#detail;
  }

  constructor(code: ACEErrorCode, message?: string, opts: ACEErrorOptions = {}) {
    if (!ALL.has(code)) throw new TypeError(`unknown ACEError code: ${String(code)}`);
    super(message ? `${code}: ${message}` : code, opts.cause !== undefined ? { cause: opts.cause } : undefined);
    this.name = 'ACEError';
    this.code = code;
    this.#detail = message ?? '';
    if (opts.status !== undefined) this.status = opts.status;
    if (opts.relayCode !== undefined) this.relayCode = opts.relayCode;
    if (opts.remoteCode !== undefined) this.remoteCode = opts.remoteCode;
    if (opts.retryAfterSeconds !== undefined) this.retryAfterSeconds = opts.retryAfterSeconds;
  }

  get category(): ACEErrorCategory {
    return categoryOf(this.code);
  }

  get isTransient(): boolean {
    return this.category !== 'permanent';
  }
}

/** Internal: wrap a non-ACE failure into `code`, passing ACE errors through. */
export function asACEError(err: unknown, code: ACEErrorCode, message: string): ACEError {
  if (err instanceof ACEError) return err;
  const detail = err instanceof Error ? err.message : String(err);
  return new ACEError(code, `${message}: ${detail}`.slice(0, 500), { cause: err });
}

/** Internal: the message an error was created with, without the `code: ` prefix. */
export function errorDetail(e: ACEError): string {
  return detailOf(e);
}
