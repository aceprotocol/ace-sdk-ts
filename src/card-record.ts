/**
 * The card record (04 § Card record): an agent's durable identity facts — its set-once handle, card, payment and
 * ERC-8004 accounts, whether strangers may request contact and whether it is listed — published as the closed CardBundle `{kel, card}`
 * and signed with action `card-record` over `canonicalStateBytes(claims)`. It has no expiry.
 */
import { validateCard, validateNetworkRelay, type AgentCard, type VerifyOptions } from './descriptor.js';
import { ACEError } from './errors.js';
import { canonicalStateBytes, checkJsonValue, closedKeys, isACEId, isCaip10, isHandle, isObj, nowOf, parseJSONBytes, utf8, wireInt } from './encoding.js';
import { claimsOf, signClaims, type ACEIdentity } from './identity.js';
import {
  atLogTail, checkSignatureShape, isUsable, reconcileKel, verifyKel, verifyOperationalSignature, type KelEvent, type KelState, type OperationalSignature,
} from './kel.js';
import { MAX_CARD_ERC8004, MAX_CARD_RECORD_BYTES, MAX_PAY_ACCOUNTS, MAX_PUBLISHED_AGENT_BYTES, TIMESTAMP_WINDOW_SECONDS } from './limits.js';

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
  /** 1..MAX_CARD_ERC8004 distinct ERC-8004 registrations of the agent (claimed, not proven: `verifyErc8004Registration`). */
  erc8004?: Erc8004Binding[];
  contact: Contact;
  listed: boolean;
  signature: OperationalSignature;
}

/** The publication unit: `{kel, card}`. */
export interface CardBundle { kel: KelEvent[]; card: CardRecord }

/**
 * A verified card record. `kelLive` (required): whether the KEL it verified under is a pin a live descriptor confirmed
 * (`NetworkClient.lookupCard`); false from `verifyCardBundle` alone, where only the bundle's own KEL vouches for it. Rely
 * on `pay` or `erc8004` only when it is true (04 § Card record).
 */
export interface VerifiedCard { aceId: string; kelState: KelState; record: CardRecord; bundle: CardBundle; kelLive: boolean }

const R_REQUIRED = ['aceId', 'issuedAt', 'home', 'card', 'contact', 'listed', 'signature'];
const R_OPTIONAL = ['handle', 'pay', 'erc8004'];
/** A CAIP-10 account id (`namespace:reference:address`). */
export const isCaip10Account: (s: unknown) => s is string = isCaip10;

/**
 * A card record `erc8004` entry `{agentRegistry: <CAIP-10 registry address>, agentId}`: for an `eip155` registry a
 * decimal of at most 78 digits; for any other CAIP-2 namespace 1-128 characters of `[A-Za-z0-9]` (a chain-native
 * identifier, e.g. a Solana address).
 */
export interface Erc8004Binding { agentRegistry: string; agentId: string }

export function validateErc8004Binding(value: unknown): Erc8004Binding {
  if (!closedKeys(value, ['agentRegistry', 'agentId']) || !isCaip10(value.agentRegistry) || typeof value.agentId !== 'string') {
    throw new ACEError('invalid_authorization', 'erc8004 entries must be {agentRegistry: CAIP-10, agentId}');
  }
  const eip155 = value.agentRegistry.split(':', 1)[0] === 'eip155';
  if (!(eip155 ? /^(0|[1-9][0-9]{0,77})$/ : /^[A-Za-z0-9]{1,128}$/).test(value.agentId)) {
    throw new ACEError('invalid_authorization', 'erc8004 agentId must be decimal (eip155) or 1-128 [A-Za-z0-9]');
  }
  return { agentRegistry: value.agentRegistry, agentId: value.agentId };
}

/**
 * Whether the claim of a card record `erc8004` entry holds: the agent's registration file (its tokenURI document; an
 * object or JSON text) is a JSON object whose `services` array lists `{"name": "ACE", "endpoint": <aceId>}`. Reading
 * the chain and the tokenURI is the host's job.
 */
export function verifyErc8004Registration(registrationJson: unknown, aceId: string): boolean {
  let doc = registrationJson;
  if (typeof doc === 'string') {
    try { doc = parseJSONBytes(utf8(doc), 'invalid_argument', 'registration'); } catch { return false; }
  }
  if (!isObj(doc) || !isACEId(aceId)) return false;
  return Array.isArray(doc.services) && doc.services.some((s) => isObj(s) && s.name === 'ACE' && s.endpoint === aceId);
}

/** Create and sign this identity's CardBundle (verified before it is returned); `issuedAt` is never before the log's last event. */
export async function createCardRecord(identity: ACEIdentity, o: {
  home: string; handle?: string; card?: AgentCard; pay?: string[]; erc8004?: Erc8004Binding[]; contact: Contact; listed: boolean; now?: number;
} & Pick<VerifyOptions, 'allowLoopbackRelays'>): Promise<CardBundle> {
  const issuedAt = atLogTail(identity.getKel(), o.now ?? nowOf());
  const claims = {
    aceId: identity.getACEId(), issuedAt, home: o.home, card: structuredClone(o.card ?? {}), contact: o.contact, listed: o.listed,
    ...(o.handle !== undefined ? { handle: o.handle } : {}),
    ...(o.pay !== undefined ? { pay: [...o.pay] } : {}),
    ...(o.erc8004 !== undefined ? { erc8004: structuredClone(o.erc8004) } : {}),
  };
  const bundle: CardBundle = { kel: identity.getKel(), card: await signClaims(identity, 'card-record', claims) as CardRecord };
  verifyCardBundle(bundle, issuedAt, { allowLoopbackRelays: o.allowLoopbackRelays });
  return bundle;
}

/**
 * Verify a CardBundle at `now`, in order (04 § Card record): shape (the signature's included), both size bounds and
 * field rules (`invalid_authorization`); KEL usable at `now` (`invalid_kel` / `invalid_signature`) naming `aceId`
 * (`invalid_authorization`); the signature as an operational signature of the KEL reconciled with `o.pinned`
 * (`stale_peer_binding` / `invalid_authorization`). No expiry check.
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
  if (r.erc8004 !== undefined) {
    if (!Array.isArray(r.erc8004) || r.erc8004.length < 1 || r.erc8004.length > MAX_CARD_ERC8004) throw bad(`erc8004 must hold 1-${MAX_CARD_ERC8004} entries`);
    const seen = new Set(r.erc8004.map((b) => { const v = validateErc8004Binding(b); return `${v.agentRegistry}#${v.agentId}`; }));
    if (seen.size !== r.erc8004.length) throw bad('erc8004 entries must be distinct');
  }
  if (r.contact !== 'open' && r.contact !== 'closed') throw bad('contact must be open or closed');
  if (typeof r.listed !== 'boolean') throw bad('listed must be a boolean');
  let state = verifyKel(value.kel, now);
  if (!isUsable(state, now)) throw new ACEError('invalid_kel', 'identity has no live signing delegation');
  if (state.aceId !== r.aceId) throw bad('kel does not derive aceId');
  if (o.pinned) state = reconcileKel(o.pinned, state).state;
  verifyOperationalSignature(state, 'card-record', issuedAt, canonicalStateBytes(claimsOf(r)), r.signature, now, 'invalid_authorization');
  const bundle = structuredClone(value) as unknown as CardBundle;
  return { aceId: r.aceId, kelState: state, record: bundle.card, bundle, kelLive: false };
}
