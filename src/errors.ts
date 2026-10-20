/** The single ACE SDK error type and its code table (the only copy). */

export type ACEErrorCategory = 'permanent' | 'transient' | 'local';

/**
 * The code table of 06 § Error codes, plus the codes of the relay-side verifiers (07 § Errors) and the commerce rule
 * codes (profiles/commerce.md § Check order).
 */
const CODES = {
  permanent: [
    'invalid_argument', 'invalid_packet', 'unsupported_version', 'wrong_recipient', 'invalid_signature',
    'invalid_authorization', 'stale_timestamp', 'stale_peer_binding', 'decryption_failed', 'unknown_prekey',
    'unsupported_schema', 'invalid_body', 'replay_horizon', 'invalid_kel', 'kel_conflict', 'unknown_peer',
    'not_registered', 'not_permitted', 'relay_rejected', 'blocked_address', 'delivery_rejected', 'expired',
    // relay-side verifiers (07)
    'invalid_registration', 'stale_seq', 'future_seq',
    // relay-side and client-side no-rollback of descriptors and card records (04, 07)
    'stale_descriptor',
    // commerce rule codes
    'wrong_party', 'transition_not_allowed', 'wrong_role', 'bad_reference', 'limit_exceeded',
  ],
  transient: ['relay_unavailable', 'relay_protocol_error', 'fetch_failed'],
  local: ['storage_failed', 'identity_unavailable', 'lock_busy', 'receiver_capacity', 'thread_busy'],
} as const;

export type ACEErrorCode = (typeof CODES)[ACEErrorCategory][number];

const CATEGORY = new Map<string, ACEErrorCategory>(
  (Object.entries(CODES) as Array<[ACEErrorCategory, readonly string[]]>).flatMap(([cat, codes]) => codes.map((c) => [c, cat] as [string, ACEErrorCategory])),
);

export interface ACEErrorOptions {
  status?: number;
  relayCode?: string;
  retryAfterSeconds?: number;
  cause?: unknown;
}

const OUTCOME_CODE_RE = /^[a-z0-9_]{1,64}$/;

/** The outcome-code grammar (02 § Identifiers): receipt codes and further permanent codes raised by profile rules. */
export function isOutcomeCode(v: unknown): v is string {
  return typeof v === 'string' && OUTCOME_CODE_RE.test(v);
}

/** The fixed category of a code; a profile rule's own code (outcome-code grammar) is permanent (06 § Error codes). */
export function categoryOf(code: ACEErrorCode): ACEErrorCategory {
  return CATEGORY.get(code) ?? 'permanent';
}

/** Every SDK-originated failure. `isTransient` means "retry later" (transient and local categories). */
export class ACEError extends Error {
  readonly code: ACEErrorCode;
  readonly detail: string;
  readonly status?: number;
  readonly relayCode?: string;
  readonly retryAfterSeconds?: number;

  constructor(code: ACEErrorCode, message?: string, opts: ACEErrorOptions = {}) {
    if (!CATEGORY.has(code) && !isOutcomeCode(code)) throw new TypeError(`invalid ACEError code: ${String(code)}`);
    super(message ? `${code}: ${message}` : code, opts.cause !== undefined ? { cause: opts.cause } : undefined);
    this.name = 'ACEError';
    this.code = code;
    this.detail = message ?? '';
    if (opts.status !== undefined) this.status = opts.status;
    if (opts.relayCode !== undefined) this.relayCode = opts.relayCode;
    if (opts.retryAfterSeconds !== undefined) this.retryAfterSeconds = opts.retryAfterSeconds;
  }

  get category(): ACEErrorCategory { return categoryOf(this.code); }
  get isTransient(): boolean { return this.category !== 'permanent'; }
}

/** `e` as an ACEError; anything else becomes `fallback` (never a permanent code for an unknown failure). */
export function asACEError(e: unknown, fallback: ACEErrorCode = 'storage_failed'): ACEError {
  return e instanceof ACEError ? e : new ACEError(fallback, e instanceof Error ? e.message.slice(0, 200) : 'unexpected failure', { cause: e });
}
