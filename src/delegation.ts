/**
 * Optional `ace:delegation:1` profile (profiles/delegation.md): credentials by which an issuer declares that a subject
 * acts on its behalf, the descriptor extension that publishes them and the message that hands one over.
 *
 * A credential grants no execution, payment or communication right; the issuer revokes it by not renewing. Descriptor
 * verification checks the extension's shape only: a client that needs to know whether `subject` acts for `issuer` pins
 * the issuer (`NetworkClient.verifyDelegation`) and verifies the credential under that pin (`verifyDelegationCredential`).
 * A `NetworkClient` with the profile installed (`profiles: [..., 'delegation']`) runs `delegationRules` itself.
 */
import { ACEError } from './errors.js';
import { canonicalStateBytes, closedKeys, isACEId, nowOf, wireInt } from './encoding.js';
import { signClaims, type ACEIdentity } from './identity.js';
import { atLogTail, checkSignatureShape, verifyOperationalSignature, type KelState, type OperationalSignature } from './kel.js';
import { TIMESTAMP_WINDOW_SECONDS } from './limits.js';
import type { PeerStore } from './peer-store.js';
import type { ProfileRules } from './rules.js';

export const DELEGATION_PROFILE_ID = 'ace:delegation:1';
/** The hand-over message type; also the action credentials are signed with (02 § Signing actions). */
export const DELEGATION_TYPE = 'ace:delegation:1';
/** Credentials in one descriptor extension. */
export const MAX_DELEGATION_CREDENTIALS = 4;
/** Upper bound of `expiresAt - issuedAt`. */
export const MAX_DELEGATION_CREDENTIAL_LIFETIME = 604_800;

/** `issuer` declares that `subject` acts on its behalf. Grants no execution, payment or communication right. */
export interface DelegationCredential { issuer: string; subject: string; issuedAt: number; expiresAt: number; signature: OperationalSignature }

const bad = (m: string) => new ACEError('invalid_authorization', m);

/**
 * A credential from `issuer` declaring that `subject` acts on its behalf, issued at `max(now, ts of the issuer's last
 * KEL event)` for `o.ttl` seconds (default and maximum 7 days; `invalid_argument` outside 1..max).
 */
export async function createDelegationCredential(issuer: ACEIdentity, subject: string, o: { now?: number; ttl?: number } = {}): Promise<DelegationCredential> {
  if (!isACEId(subject) || subject === issuer.getACEId()) throw new ACEError('invalid_argument', 'subject must be another ACE ID');
  const ttl = o.ttl ?? MAX_DELEGATION_CREDENTIAL_LIFETIME;
  if (wireInt(ttl) === null || ttl < 1 || ttl > MAX_DELEGATION_CREDENTIAL_LIFETIME) {
    throw new ACEError('invalid_argument', `ttl must be 1..${MAX_DELEGATION_CREDENTIAL_LIFETIME}`);
  }
  const issuedAt = atLogTail(issuer.getKel(), o.now ?? nowOf());
  return signClaims(issuer, DELEGATION_TYPE, { issuer: issuer.getACEId(), subject, issuedAt, expiresAt: issuedAt + ttl });
}

/**
 * Internal. The closed credential and its field grammar: ACE IDs with `issuer != subject`, `issuedAt <= now + 300`,
 * `issuedAt < expiresAt <= issuedAt + 7 days`, a delegated signature's shape. No expiry, no signature check
 * (`invalid_authorization`).
 */
export function checkCredential(value: unknown, now: number): DelegationCredential {
  if (!closedKeys(value, ['issuer', 'subject', 'issuedAt', 'expiresAt', 'signature'])
    || !isACEId(value.issuer) || !isACEId(value.subject) || value.issuer === value.subject) {
    throw bad('credential must be {issuer, subject, issuedAt, expiresAt, signature} with issuer != subject');
  }
  const i = wireInt(value.issuedAt), e = wireInt(value.expiresAt);
  if (i === null || e === null || i > now + TIMESTAMP_WINDOW_SECONDS || i >= e || e - i > MAX_DELEGATION_CREDENTIAL_LIFETIME) {
    throw bad('invalid credential lifetime');
  }
  checkSignatureShape(value.signature, 'invalid_authorization');
  return value as unknown as DelegationCredential;
}

/**
 * Descriptor `ext["ace:delegation:1"]`: the closed `{credentials}` with 1-4 credentials of distinct issuers, each naming
 * `subject` (the descriptor's `aceId`). Shape only: no expiry and no signature (`invalid_authorization`). Returns a copy.
 */
export function validateDelegationExt(value: unknown, subject: string, now: number): DelegationCredential[] {
  if (!closedKeys(value, ['credentials'])) throw bad('delegation ext must be {credentials}');
  const items = value.credentials;
  if (!Array.isArray(items) || items.length < 1 || items.length > MAX_DELEGATION_CREDENTIALS) {
    throw bad(`delegation ext must hold 1-${MAX_DELEGATION_CREDENTIALS} credentials`);
  }
  for (const c of items) {
    if (checkCredential(c, now).subject !== subject) throw bad('a delegation credential must name the descriptor\'s aceId');
  }
  if (new Set(items.map((c: DelegationCredential) => c.issuer)).size !== items.length) throw bad('delegation credential issuers must be distinct');
  return structuredClone(items) as DelegationCredential[];
}

/**
 * A copy of `value` if it is a live credential of `issuer` (the issuer's pinned KEL state): its shape, `now < expiresAt`
 * and an operational signature of `issuer` with action `ace:delegation:1`. `stale_peer_binding` from the signature check
 * passes through; any other failure is `invalid_authorization`.
 */
export function verifyDelegationCredential(value: unknown, issuer: KelState, now: number): DelegationCredential {
  const c = checkCredential(value, now);
  if (c.issuer !== issuer.aceId) throw bad('the credential names another issuer');
  if (c.expiresAt <= now) throw bad('credential expired');
  const { signature, ...claims } = c;
  verifyOperationalSignature(issuer, DELEGATION_TYPE, c.issuedAt, canonicalStateBytes(claims), signature, now, 'invalid_authorization');
  return structuredClone(c);
}

/**
 * The `ace:delegation:1` message rule: the issuer hands a credential to its subject. `check` requires the credential to
 * be the sender's, about the recipient and live, and on receive signed under the sender's pin in `peers` (no pin is a
 * failure); any failure is `invalid_body`. `commit` changes no state: the application stores the credential and
 * publishes it in its `ext`. `peers` also supplies the clock; `localAceId` is the identity the rule runs for.
 */
export function delegationRules(peers: PeerStore, localAceId: string): ProfileRules {
  return {
    types: [DELEGATION_TYPE],
    async check(e, body) {
      const now = peers.now();
      try {
        const c = checkCredential(body.credential, now);
        if (c.issuer !== e.from || c.subject !== e.to) throw bad('the credential must be from the sender about the recipient');
        if (c.expiresAt <= now) throw bad('credential expired');
        if (e.direction === 'receive') {
          const pinned = await peers.get(e.from);
          if (pinned === null) throw bad('the sender is not pinned');
          verifyDelegationCredential(c, pinned, now);
        }
      } catch (err) {
        if (err instanceof ACEError && err.code === 'storage_failed') throw err;
        throw new ACEError('invalid_body', `delegation: ${err instanceof Error ? err.message : 'invalid credential'}`, { cause: err });
      }
    },
    commit() {},
  };
}
