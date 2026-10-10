/** Principal binding (09-principal): records, the `principal` signing context, same-account rules and the `requests/` ledger. */

import {
  CONTROL_CHAR_RE, MAX_SAFE_INTEGER, canonicalStateBytes, codePointLength, decodeB64, decodeSignature, encodeSignature, isACEId,
  isConversationId, isMessageId, isObj, nowOf, pairKey, parseStateBytes, toBase64, wireInt,
} from './encoding.js';
import { ACEError } from './errors.js';

import { PRINCIPAL_MAX_LIFETIME_SECONDS, TIMESTAMP_WINDOW_SECONDS } from './limits.js';
import { buildSignData, computeACEId, encodePayload, isValidSigningPublicKey, signingAddress, verifySignature } from './signing.js';
import type { ACEStore } from './store.js';
import {
  isPrincipalType, isSigningScheme,
  type ACEIdentity, type ACEMessage, type JSONObject, type ParsedMessage, type PrincipalKey, type PrincipalRecord,
  type PrincipalRole, type SigningScheme,
} from './types.js';

/** Compare authenticated statements, independently of randomized signature bytes. */
export function samePrincipalClaims(a: PrincipalRecord, b: PrincipalRecord): boolean {
  return a.account === b.account && a.issuedAt === b.issuedAt && a.expiresAt === b.expiresAt
    && a.scope === b.scope && a.signer.scheme === b.signer.scheme && a.signer.publicKey === b.signer.publicKey
    && a.roles.length === b.roles.length && a.roles.every((role, i) => role === b.roles[i]);
}

/** Canonical order: `controller` (approves) before `delegate` (acts). */
export const PRINCIPAL_ROLES: readonly PrincipalRole[] = ['controller', 'delegate'];
const CAIP10_RE = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/;
const ALLOWED_ROLES: ReadonlyArray<readonly string[]> = [['controller'], ['delegate'], ['controller', 'delegate']];
const EIP155_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const WRONG_DECIDER = 'decision from a different controller than the request was sent to';

/**
 * `openRequestTo(conversationId, requestId, now)`: the ACE ID the receiver sent that `request` to, if it was sent in
 * that conversation, no `decision` for it was accepted and it is not expired at `now`; otherwise null.
 */
export type OpenRequestTo = (conversationId: string, requestId: string, now: number) => string | null | Promise<string | null>;

export function isCaip10(v: unknown): v is string {
  return typeof v === 'string' && CAIP10_RE.exec(v)?.[0] === v;
}

const bad = (m: string) => new ACEError('invalid_principal', m);

/**
 * Strict wire parse (09 § Validation rule 1); any type error is `invalid_principal`. A `null` optional member is
 * absent; unknown members are dropped.
 */
export function parsePrincipalRecord(d: unknown): PrincipalRecord {
  if (!isObj(d)) throw bad('principal must be a JSON object');
  const s = d.signer;
  if (!isObj(s)) throw bad('principal.signer must be an object');
  if (typeof s.scheme !== 'string' || typeof s.publicKey !== 'string') throw bad('principal.signer must be {scheme, publicKey} strings');
  if (!Array.isArray(d.roles) || !d.roles.every((r) => typeof r === 'string')) throw bad('principal.roles must be an array of strings');
  const issuedAt = wireInt(d.issuedAt);
  if (issuedAt === null) throw bad('principal.issuedAt must be a wire integer');
  const expiresAt = wireInt(d.expiresAt);
  if (expiresAt === null) throw bad('principal.expiresAt must be a wire integer');
  if (typeof d.account !== 'string') throw bad('principal.account must be a string');
  if (typeof d.signature !== 'string') throw bad('principal.signature must be a string');
  const out: PrincipalRecord = {
    account: d.account,
    roles: [...(d.roles as PrincipalRole[])],
    signer: { scheme: s.scheme as SigningScheme, publicKey: s.publicKey },
    issuedAt,
    expiresAt,
    signature: d.signature,
  };
  if (d.scope !== undefined && d.scope !== null) {
    if (typeof d.scope !== 'string') throw bad('principal.scope must be a string');
    out.scope = d.scope;
  }
  return out;
}

/**
 * The key that signs a principal record: `sign(digest32)` returns the signature bytes (ed25519: 64 bytes; secp256k1:
 * r‖s‖v, low-S). Any key source works (PRF, Secure Enclave, HSM).
 */
export interface PrincipalSigner {
  scheme: SigningScheme;
  publicKey: Uint8Array;
  sign(digest: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export function principalSignerFromIdentity(identity: ACEIdentity): PrincipalSigner {
  return { scheme: identity.getSigningScheme(), publicKey: identity.getSigningPublicKey(), sign: (d) => identity.sign(d) };
}

/**
 * `encodePayload(account, join(roles), signer.scheme, signer.publicKey, subjectKeyB64, scopeOrEmpty,
 * decimal(expiresAt))` (09 § Signing Context).
 */
export function principalPayload(r: PrincipalRecord, subjectSigningPublicKey: Uint8Array): Uint8Array {
  return encodePayload(
    r.account, r.roles.join(','), r.signer.scheme, r.signer.publicKey, toBase64(subjectSigningPublicKey),
    r.scope ?? '', String(r.expiresAt ?? 0),
  );
}

/** The 32-byte digest the signer signs (no validation). */
export function principalSignData(r: PrincipalRecord, subjectSigningPublicKey: Uint8Array): Uint8Array {
  return buildSignData('principal', computeACEId(subjectSigningPublicKey), r.issuedAt, principalPayload(r, subjectSigningPublicKey));
}

function rolesAllowed(roles: readonly string[]): boolean {
  return ALLOWED_ROLES.some((a) => a.length === roles.length && a.every((v, i) => v === roles[i]));
}

/** 09 § Validation rules 2-7 on a parsed record; returns the decoded signer key. */
function checkFields(r: PrincipalRecord, now: number): Uint8Array {
  if (!isCaip10(r.account)) throw bad('principal.account must be a CAIP-10 account'); // 2
  if (!rolesAllowed(r.roles)) throw bad('principal.roles must be ["controller"], ["delegate"] or ["controller","delegate"]'); // 3
  if (!isSigningScheme(r.signer.scheme)) throw bad('principal.signer.scheme is unsupported'); // 4
  const signerKey = decodeB64(r.signer.publicKey, 'invalid_principal', 'principal.signer.publicKey', 64);
  if (!isValidSigningPublicKey(r.signer.scheme, signerKey)) throw bad('principal.signer.publicKey is not a valid key for its scheme');
  if (r.issuedAt > now + TIMESTAMP_WINDOW_SECONDS) throw bad('principal.issuedAt is in the future'); // 5
  if (!(r.issuedAt < r.expiresAt && r.expiresAt - r.issuedAt <= PRINCIPAL_MAX_LIFETIME_SECONDS)) { // 6
    throw bad('principal.expiresAt must be after issuedAt and at most 366 days later');
  }
  if (r.scope !== undefined) { // 7
    const n = codePointLength(r.scope);
    if (n < 1 || n > 256 || CONTROL_CHAR_RE.test(r.scope)) throw bad('principal.scope must be 1-256 characters without control characters');
  }
  return signerKey;
}

/**
 * 09 § Validation, rules 1-10 in order; every failure is `invalid_principal`. `allowExpired` skips only rule 10
 * (expiry), so a caller can tell an expired-only record from an invalid one (R-P40). `subjectSigningPublicKey` is
 * the key the caller has verified, never the record's.
 */
export function validatePrincipalRecord(
  record: unknown, subjectSigningPublicKey: Uint8Array, now: number, o: { allowExpired?: boolean } = {},
): PrincipalRecord {
  const r = parsePrincipalRecord(record); // 1
  const signerKey = checkFields(r, now); // 2-7
  const sig = decodeSignature(r.signature, r.signer.scheme, 'invalid_principal'); // 8
  if (!verifySignature(principalSignData(r, subjectSigningPublicKey), sig, r.signer.scheme, signerKey)) { // 9
    throw bad('principal.signature does not verify for this subject');
  }
  if (r.expiresAt <= now && !o.allowExpired) throw bad('principal record has expired'); // 10
  return r;
}

/**
 * Sign a principal record for a subject key. Roles are canonicalized (deduplicated, `controller` first); an unknown
 * role is `invalid_argument`. Rules 1-7 run before the signer is asked to sign; the result is validated at `issuedAt`
 * (`invalid_principal` for invalid inputs). `expiresAt` is required (09 § Principal Record); `scope: null` is absent.
 */
export async function createPrincipalRecord(signer: PrincipalSigner, o: {
  subjectSigningPublicKey: Uint8Array;
  account: string;
  roles: readonly PrincipalRole[];
  expiresAt: number;
  scope?: string | null;
  issuedAt?: number;
}): Promise<PrincipalRecord> {
  if (!Array.isArray(o.roles) || o.roles.some((r) => !(PRINCIPAL_ROLES as readonly unknown[]).includes(r))) {
    throw new ACEError('invalid_argument', "roles must contain only 'controller' and 'delegate'");
  }
  const issuedAt = o.issuedAt ?? nowOf();
  const draft: PrincipalRecord = {
    account: o.account,
    roles: PRINCIPAL_ROLES.filter((r) => o.roles.includes(r)),
    signer: { scheme: signer.scheme, publicKey: toBase64(signer.publicKey) },
    issuedAt,
    expiresAt: o.expiresAt,
    signature: '',
  };
  if (o.scope !== undefined && o.scope !== null) draft.scope = o.scope;
  // Rules 1-7 before asking the (possibly hardware) signer to sign.
  checkFields(parsePrincipalRecord(draft), issuedAt);
  const sig = await signer.sign(principalSignData(draft, o.subjectSigningPublicKey));
  return validatePrincipalRecord({ ...draft, signature: encodeSignature(sig, signer.scheme) }, o.subjectSigningPublicKey, issuedAt);
}

/**
 * Step-7 inputs from the receiver: its own principal `account`; the keys accepted as authorities of that account
 * (`selfSigner`, the signer of the receiver's own record — absent fails closed — and host-provided `trustedSigners`,
 * e.g. read from chain); and the ledger lookup `openRequestTo`.
 */
export interface PrincipalContext {
  account: string;
  openRequestTo: OpenRequestTo;
  selfSigner?: PrincipalKey;
  trustedSigners?: readonly PrincipalKey[];
}

const sameKey = (a: PrincipalKey, b: PrincipalKey | undefined) => b !== undefined && a.scheme === b.scheme && a.publicKey === b.publicKey;

/**
 * 09 step 4: `p.signer` is an authority of `p.account` when it is the receiver's own attesting key, a host-trusted
 * key, or (`eip155`) the secp256k1 key whose address is the account address (case-insensitive). `p` is valid.
 */
function isAccountAuthority(p: PrincipalRecord, selfSigner: PrincipalKey | undefined, trustedSigners: readonly PrincipalKey[]): boolean {
  if (sameKey(p.signer, selfSigner) || trustedSigners.some((k) => sameKey(p.signer, k))) return true;
  const [namespace, , address] = p.account.split(':', 3);
  if (namespace !== 'eip155' || p.signer.scheme !== 'secp256k1' || !EIP155_ADDRESS_RE.test(address)) return false;
  const key = decodeB64(p.signer.publicKey, 'invalid_principal', 'principal.signer.publicKey');
  return signingAddress('secp256k1', key).toLowerCase() === address.toLowerCase();
}

/**
 * 09 § Same-Account Rules, steps 1-7 in order (first failure wins). Pure apart from the injected `openRequestTo`, so a
 * caller may refresh the sender's peer binding and call it again (R-P20). `body` has already passed `validateBody`.
 */
export async function checkPrincipalRules(type: string, body: JSONObject, o: {
  conversationId: string;
  senderPrincipal: unknown;
  senderSigningPublicKey: Uint8Array;
  selfAccount: string | null;
  openRequestTo?: OpenRequestTo;
  now: number;
  selfSigner?: PrincipalKey;
  trustedSigners?: readonly PrincipalKey[];
}): Promise<void> {
  if (!isPrincipalType(type)) throw new ACEError('invalid_argument', 'not a principal message type');
  if (o.selfAccount === null || o.selfAccount === undefined) throw new ACEError('wrong_principal', 'the receiver has no principal'); // 1
  const p = senderPrincipal(o.senderPrincipal, o.senderSigningPublicKey, o.selfAccount, o.selfSigner, o.trustedSigners, o.now);
  if (p instanceof ACEError) throw p;
  if (type === 'decision') {
    if (!p.roles.includes('controller')) throw new ACEError('wrong_principal', 'only a controller may send a decision'); // 6
    const recipient = o.openRequestTo ? await o.openRequestTo(o.conversationId, body.requestId as string, o.now) : null;
    if (recipient === null || recipient === undefined) { // 7 (unknown, decided or expired request)
      throw new ACEError('bad_reference', 'decision.requestId names no open request in this conversation');
    }
    if (recipient !== computeACEId(o.senderSigningPublicKey)) throw new ACEError('wrong_principal', WRONG_DECIDER); // 7 (decider)
  }
}

/**
 * True when the pinned sender principal passes 09 steps 2-5 for `ctx` (present, valid, signed by an authority of the
 * account, same account). False means a peer refresh may help (R-P20).
 */
export function senderPrincipalUsable(
  principal: unknown, senderSigningPublicKey: Uint8Array, ctx: PrincipalContext, now: number,
): boolean {
  return !(senderPrincipal(principal, senderSigningPublicKey, ctx.account, ctx.selfSigner, ctx.trustedSigners, now) instanceof ACEError);
}

/** 09 steps 2-5 (and scope): the sender's valid principal, or the first `wrong_principal` failure. Other errors throw. */
function senderPrincipal(
  principal: unknown, signingPublicKey: Uint8Array, selfAccount: string, selfSigner: PrincipalKey | undefined,
  trustedSigners: readonly PrincipalKey[] | undefined, now: number,
): PrincipalRecord | ACEError {
  if (principal === null || principal === undefined) return new ACEError('wrong_principal', 'the sender has no principal'); // 2
  let p: PrincipalRecord;
  try { // 3
    p = validatePrincipalRecord(principal, signingPublicKey, now);
  } catch (e) {
    if (e instanceof ACEError && e.code === 'invalid_principal') {
      return new ACEError('wrong_principal', `the sender's principal is invalid: ${e.message}`);
    }
    throw e;
  }
  if (!isAccountAuthority(p, selfSigner, trustedSigners ?? [])) { // 4
    return new ACEError('wrong_principal', 'signer is not an authority of the account');
  }
  if (p.account !== selfAccount) return new ACEError('wrong_principal', 'the sender belongs to another account'); // 5
  if (p.scope !== undefined) return new ACEError('wrong_principal', 'unsupported principal scope');
  return p;
}

// --- requests/ ledger (09 § Persistence, 06 Appendix A) ----------------------------------------------------------

/** One record per sent `request` (`version: 1` on disk). */
export interface RequestRecord {
  conversationId: string;
  decision: null | { messageId: string; outcome: 'approve' | 'deny'; timestamp: number };
  /** Request timestamp + `ttl`; null when the request had no `ttl`. */
  expiresAt: number | null;
  messageId: string;
  sentAt: number;
  /** The ACE ID the request was sent to. */
  to: string;
}

/** `requests/<sha256(conversationId ‖ 0x00 ‖ messageId)>.json`. */
export function requestKey(conversationId: string, messageId: string): string {
  return `requests/${pairKey(conversationId, messageId)}.json`;
}

function validDecision(dec: unknown): boolean {
  return dec === null || (isObj(dec) && isMessageId(dec.messageId) && (dec.outcome === 'approve' || dec.outcome === 'deny')
    && wireInt(dec.timestamp) !== null);
}

/** The ledger entry of a sent `request`, or null; a malformed entry is `storage_failed`. */
export async function loadRequestRecord(store: ACEStore, conversationId: string, messageId: string): Promise<RequestRecord | null> {
  const key = requestKey(conversationId, messageId);
  const raw = await store.read(key);
  if (raw === null) return null;
  const d = parseStateBytes(raw, key);
  if (!isObj(d)) throw new ACEError('storage_failed', `${key} is not a JSON object`);
  if (d.version !== 1) throw new ACEError('storage_failed', `${key} has an unknown version`);
  const expiresAt = d.expiresAt ?? null;
  if (
    d.conversationId !== conversationId || d.messageId !== messageId || !isACEId(d.to) || wireInt(d.sentAt) === null
    || !(expiresAt === null || wireInt(expiresAt) !== null) || !validDecision(d.decision)
  ) {
    throw new ACEError('storage_failed', `${key}: invalid request record`);
  }
  const dec = d.decision as RequestRecord['decision'];
  return {
    conversationId, messageId, to: d.to, sentAt: d.sentAt as number, expiresAt: expiresAt as number | null,
    decision: dec === null ? null : { messageId: dec.messageId, outcome: dec.outcome, timestamp: dec.timestamp },
  };
}

async function writeRequestRecord(store: ACEStore, r: RequestRecord): Promise<void> {
  await store.write(requestKey(r.conversationId, r.messageId), canonicalStateBytes({ ...r, version: 1 }));
}

/**
 * The `to` of a sent, undecided, unexpired request (expired when `timestamp + ttl < now`), else null (09 § Same-Account
 * Rules step 7). Bind `store` to get an `OpenRequestTo`.
 */
export async function openRequestTo(store: ACEStore, conversationId: string, messageId: string, now: number): Promise<string | null> {
  const rec = await loadRequestRecord(store, conversationId, messageId);
  if (rec === null || rec.decision !== null) return null;
  return rec.expiresAt === null || now <= rec.expiresAt ? rec.to : null;
}

/**
 * Write the ledger entry of a delivered `request` (idempotent: an existing entry is kept); `ttl` is the body's `ttl`.
 * Caller holds lock `requests`.
 */
export async function recordRequest(
  store: ACEStore,
  message: Pick<ACEMessage, 'conversationId' | 'messageId' | 'to' | 'timestamp'>,
  sentAt: number,
  ttl?: number | null,
): Promise<void> {
  if (!isConversationId(message.conversationId)) throw new ACEError('invalid_argument', 'invalid conversationId');
  if (!isMessageId(message.messageId)) throw new ACEError('invalid_argument', 'invalid messageId');
  if (!isACEId(message.to)) throw new ACEError('invalid_argument', 'invalid to');
  if (wireInt(sentAt) === null) throw new ACEError('invalid_argument', 'sentAt must be a wire integer');
  let expiresAt: number | null = null;
  if (ttl !== undefined && ttl !== null) {
    if (wireInt(ttl) === null) throw new ACEError('invalid_argument', 'ttl must be a wire integer');
    if (wireInt(message.timestamp) === null) throw new ACEError('invalid_argument', 'timestamp must be a wire integer');
    expiresAt = Math.min(message.timestamp + ttl, MAX_SAFE_INTEGER);
  }
  if ((await loadRequestRecord(store, message.conversationId, message.messageId)) !== null) return;
  await writeRequestRecord(store, {
    conversationId: message.conversationId, decision: null, expiresAt, messageId: message.messageId, sentAt, to: message.to,
  });
}

/**
 * Mark the request of an accepted `decision` decided. Replaying the recorded decision (same `messageId`) is a no-op
 * and an unknown request is a no-op; a second, different decision is `bad_reference` (a request has at most one
 * accepted decision, R-P25); a decision from anyone but the request's `to` is `wrong_principal` (09 step 7). The
 * record is unchanged on failure. Caller holds lock `requests`.
 */
export async function fillDecision(store: ACEStore, m: ParsedMessage): Promise<void> {
  const requestId = m.body.requestId as string;
  const rec = await loadRequestRecord(store, m.conversationId, requestId);
  if (rec === null) return;
  if (rec.decision !== null) {
    if (rec.decision.messageId === m.messageId) return;
    throw new ACEError('bad_reference', 'the request already has an accepted decision');
  }
  if (m.from !== rec.to) throw new ACEError('wrong_principal', WRONG_DECIDER);
  await writeRequestRecord(store, {
    ...rec, decision: { messageId: m.messageId, outcome: m.body.outcome as 'approve' | 'deny', timestamp: m.timestamp },
  });
}
