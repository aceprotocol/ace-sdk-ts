/**
 * The card record (04 § Card record): an agent's durable identity facts — its set-once handle, card, payment accounts,
 * whether strangers may request contact and whether it is listed — published as the closed CardBundle `{kel, card}`
 * and signed with action `card-record` over `canonicalStateBytes(claims)`. It has no expiry.
 */
import { claimsOf, validateCard, validateNetworkRelay, type AgentCard, type VerifyOptions } from './descriptor.js';
import { ACEError } from './errors.js';
import { canonicalStateBytes, checkJsonValue, closedKeys, isACEId, isCaip10, isHandle, nowOf, wireInt } from './encoding.js';
import { signClaims, type ACEIdentity } from './identity.js';
import {
  atLogTail, checkSignedAfterDelegation, checkSignatureShape, isUsable, reconcileKel, verifyKel, verifyOperationalSignature, type KelEvent, type KelState, type OperationalSignature,
} from './kel.js';
import { MAX_CARD_RECORD_BYTES, MAX_PAY_ACCOUNTS, MAX_PUBLISHED_AGENT_BYTES, TIMESTAMP_WINDOW_SECONDS } from './limits.js';

/** Whether strangers' contact requests are processed (05 § Flow). No card record means `closed`. */
export type Contact = 'open' | 'closed';

export interface CardRecord {
  aceId: string;
  issuedAt: number;
  /** The canonical relay URL holding the record; `handle` is in its namespace. */
  home: string;
  /** Set once: every later record of this identity carries the same handle. */
  handle?: string;
  card: AgentCard;
  /** 1..MAX_PAY_ACCOUNTS distinct CAIP-10 accounts the agent asks to be paid at (claimed, not proven). */
  pay?: string[];
  contact: Contact;
  listed: boolean;
  signature: OperationalSignature;
}

/** The publication unit: `{kel, card}`. */
export interface CardBundle { kel: KelEvent[]; card: CardRecord }

/**
 * A verified card record. `kelLive` (required): whether a live descriptor confirmed the KEL it verified under, in this
 * lookup or an earlier one recorded with the pin (`NetworkClient.lookupCard`); false when only a bundle's own KEL vouches
 * for it: from `verifyCardBundle` alone, or a lookup of an identity that has had no live descriptor since it was pinned
 * that way (04 § Card record).
 */
export interface VerifiedCard { aceId: string; kelState: KelState; record: CardRecord; bundle: CardBundle; kelLive: boolean }

const R_REQUIRED = ['aceId', 'issuedAt', 'home', 'card', 'contact', 'listed', 'signature'];
const R_OPTIONAL = ['handle', 'pay'];

/** A CAIP-10 account id (`namespace:reference:address`). */
export const isCaip10Account: (s: unknown) => s is string = isCaip10;

/** Create and sign this identity's CardBundle (verified before it is returned); `issuedAt` is never before the log's last event. */
export async function createCardRecord(identity: ACEIdentity, o: {
  home: string; handle?: string; card?: AgentCard; pay?: string[]; contact: Contact; listed: boolean; now?: number;
} & Pick<VerifyOptions, 'allowLoopbackRelays'>): Promise<CardBundle> {
  const issuedAt = atLogTail(identity.getKel(), o.now ?? nowOf());
  const claims = {
    aceId: identity.getACEId(), issuedAt, home: o.home, card: structuredClone(o.card ?? {}), contact: o.contact, listed: o.listed,
    ...(o.handle !== undefined ? { handle: o.handle } : {}),
    ...(o.pay !== undefined ? { pay: [...o.pay] } : {}),
  };
  const bundle: CardBundle = { kel: identity.getKel(), card: await signClaims(identity, 'card-record', claims) as CardRecord };
  verifyCardBundle(bundle, issuedAt, { allowLoopbackRelays: o.allowLoopbackRelays });
  return bundle;
}

/**
 * Verify a CardBundle at `now`, in order (04 § Card record): shape (the signature's included), both size bounds and
 * field rules (`invalid_authorization`); KEL usable at `now` (`invalid_kel` / `invalid_signature`) naming `aceId`
 * (`invalid_authorization`); the signature as an operational signature of the KEL reconciled with `o.pinned`, signed
 * no earlier than its delegation's `dlg` (`stale_peer_binding` / `invalid_authorization`). No expiry check.
 */
export function verifyCardBundle(value: unknown, now: number = nowOf(), o: VerifyOptions = {}): VerifiedCard {
  const bad = (m: string) => new ACEError('invalid_authorization', m);
  if (!closedKeys(value, ['kel', 'card'])) throw bad('card bundle must be {kel, card}');
  checkJsonValue(value, 'invalid_authorization'); // bounds the depth before anything recurses
  if (canonicalStateBytes(value).length > MAX_PUBLISHED_AGENT_BYTES) throw bad(`card bundle exceeds ${MAX_PUBLISHED_AGENT_BYTES} bytes`);
  const r = value.card;
  if (!closedKeys(r, R_REQUIRED, R_OPTIONAL) || !isACEId(r.aceId)) throw bad('invalid card record shape');
  checkSignatureShape(r.signature, 'invalid_authorization');
  if (canonicalStateBytes(r).length > MAX_CARD_RECORD_BYTES) throw bad(`card record exceeds ${MAX_CARD_RECORD_BYTES} bytes`);
  const issuedAt = wireInt(r.issuedAt);
  if (issuedAt === null || issuedAt > now + TIMESTAMP_WINDOW_SECONDS) throw bad('invalid card record issuedAt');
  validateNetworkRelay(r.home, o);
  if (r.handle !== undefined) {
    if (!isHandle(r.handle)) throw bad('handle must match [a-z][a-z0-9]*(-[a-z0-9]+)*, 3-32 characters');
    if (new URL(r.home as string).pathname !== '/') throw bad('a handle needs a home without a path (it resolves at https://host)');
  }
  validateCard(r.card);
  if (r.pay !== undefined && (!Array.isArray(r.pay) || r.pay.length < 1 || r.pay.length > MAX_PAY_ACCOUNTS
    || new Set(r.pay).size !== r.pay.length || !r.pay.every(isCaip10))) {
    throw bad(`pay must hold 1-${MAX_PAY_ACCOUNTS} distinct CAIP-10 accounts`);
  }
  if (r.contact !== 'open' && r.contact !== 'closed') throw bad('contact must be open or closed');
  if (typeof r.listed !== 'boolean') throw bad('listed must be a boolean');
  let state = verifyKel(value.kel, now);
  if (!isUsable(state, now)) throw new ACEError('invalid_kel', 'identity has no live signing delegation');
  if (state.aceId !== r.aceId) throw bad('kel does not derive aceId');
  if (o.pinned) state = reconcileKel(o.pinned, state).state;
  checkSignedAfterDelegation(state, issuedAt);
  verifyOperationalSignature(state, 'card-record', issuedAt, canonicalStateBytes(claimsOf(r)), r.signature, now, 'invalid_authorization');
  const bundle = structuredClone(value) as unknown as CardBundle;
  return { aceId: r.aceId, kelState: state, record: bundle.card, bundle, kelLive: false };
}
