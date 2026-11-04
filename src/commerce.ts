/**
 * Optional commerce profile module (`ace:commerce:1`): `commerceRules()` (thread state machine, references and
 * settlement shapes) and its `ThreadStore`. Outside the core pipeline: install it as a `ProfileRules` entry. A
 * commerce message never authorizes a payment; whether to pay is the application's decision.
 */
import { DELEGATION_PROFILE_ID, validateDelegationExt } from './delegation.js';
import { ACEError } from './errors.js';
import { canonicalStateBytes, closedKeys, conversationKey, isACEId, isHttpsUrl, isMessageId, isObj, isThreadId, pairKey, sha256Hex, wireInt } from './encoding.js';
import type { ProfileRules, RuleEvent } from './rules.js';
import { readAll, readState, withLock, type ACEStore } from './store.js';
import type { JSONObject } from './types.js';

export const COMMERCE_PROFILE_ID = 'ace:commerce:1';
export const COMMERCE_TYPES = [
  'ace:commerce:rfq:1', 'ace:commerce:offer:1', 'ace:commerce:accept:1', 'ace:commerce:reject:1',
  'ace:commerce:invoice:1', 'ace:commerce:payment:1', 'ace:commerce:deliver:1', 'ace:commerce:confirm:1',
] as const;
export type CommerceType = (typeof COMMERCE_TYPES)[number];
export type ThreadState = 'idle' | 'requested' | 'offered' | 'accepted' | 'rejected' | 'invoiced' | 'paid' | 'delivered' | 'confirmed';
type Role = 'buyer' | 'seller';

const T = (s: string) => `ace:commerce:${s}:1` as CommerceType;
const TRANSITIONS: ReadonlyArray<[ThreadState, CommerceType, ThreadState, Role]> = [
  ['idle', T('rfq'), 'requested', 'buyer'],
  ['requested', T('offer'), 'offered', 'seller'],
  ['requested', T('reject'), 'rejected', 'seller'],
  ['offered', T('offer'), 'offered', 'seller'],
  ['offered', T('accept'), 'accepted', 'buyer'],
  ['offered', T('reject'), 'rejected', 'buyer'],
  ['accepted', T('invoice'), 'invoiced', 'seller'],
  ['accepted', T('payment'), 'paid', 'buyer'],
  ['accepted', T('deliver'), 'delivered', 'seller'],
  ['invoiced', T('payment'), 'paid', 'buyer'],
  ['paid', T('deliver'), 'delivered', 'seller'],
  ['delivered', T('confirm'), 'confirmed', 'buyer'],
];
const TERMINAL: ReadonlySet<ThreadState> = new Set(['rejected', 'confirmed']);
/** Reference field → offset from the head (1 = the head, 2 = the entry before it). */
const REFERENCES: Partial<Record<CommerceType, [string, number]>> = {
  [T('accept')]: ['offerId', 1], [T('invoice')]: ['offerId', 2], [T('payment')]: ['referenceId', 1], [T('confirm')]: ['deliverId', 1],
};
export const MAX_OPEN_THREADS_PER_PEER = 1000;
const MAX_THREAD_HISTORY = 1000;

export interface ThreadHistoryEntry { type: CommerceType; messageId: string; timestamp: number; from: string }
export interface ThreadSnapshot {
  /** `conversationKey(local, peer)`. */
  conversation: string;
  threadId: string;
  localAceId: string;
  peerAceId: string;
  state: ThreadState;
  history: ThreadHistoryEntry[];
}

const CAIP19_RE = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}\/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}$/;

/** A CAIP-19 asset ID (the commerce settlement asset grammar). */
export function isCaip19(v: unknown): v is string {
  return typeof v === 'string' && CAIP19_RE.test(v);
}

/** `ext["ace:commerce:1"]`: the closed `{settlement}` with 1-10 distinct `{method: "stablecoin", asset}` / `{method: "stripe-link"}`. */
export function validateCommerceExt(v: unknown): void {
  const bad = () => new ACEError('invalid_authorization', 'ext["ace:commerce:1"] must be {settlement: [{method: "stablecoin", asset} | {method: "stripe-link"}]} (1-10 distinct)');
  if (!closedKeys(v, ['settlement']) || !Array.isArray(v.settlement) || v.settlement.length < 1 || v.settlement.length > 10) throw bad();
  for (const s of v.settlement) {
    const ok = closedKeys(s, ['method', 'asset']) ? s.method === 'stablecoin' && isCaip19(s.asset) : closedKeys(s, ['method']) && s.method === 'stripe-link';
    if (!ok) throw bad();
  }
  if (new Set(v.settlement.map((s) => sha256Hex(canonicalStateBytes(s)))).size !== v.settlement.length) throw bad();
}

/**
 * Official profiles that define a descriptor `ext` value, with its check (04 § Extensions), called with the value, the
 * descriptor's `aceId` and the verification time.
 */
export const OFFICIAL_EXT: Readonly<Record<string, ((v: unknown, aceId: string, now: number) => unknown) | undefined>> = {
  [COMMERCE_PROFILE_ID]: validateCommerceExt, [DELEGATION_PROFILE_ID]: validateDelegationExt,
};

const nonEmpty = (v: unknown) => typeof v === 'string' && v.length > 0;
/** The thread opener (the first `rfq` sender) is the buyer. */
const roleOf = (s: ThreadSnapshot, sender: string): Role => sender === s.history[0].from ? 'buyer' : 'seller';
const peerOf = (local: string, e: RuleEvent) => local === e.from ? e.to : e.from;

/** Rule-level shapes the manifest schema cannot express (`invalid_body`). */
export function checkCommerceBody(type: string, body: JSONObject): void {
  const bad = (m: string) => new ACEError('invalid_body', m);
  if (type === T('invoice')) {
    const s = body.settlement;
    const ok = closedKeys(s, ['method', 'asset', 'recipient'], ['memo'])
      ? s.method === 'stablecoin' && isCaip19(s.asset) && nonEmpty(s.recipient)
      : closedKeys(s, ['method', 'url']) && s.method === 'stripe-link' && isHttpsUrl(s.url);
    if (!ok) throw bad('invoice.settlement must be {method: "stablecoin", asset, recipient, memo?} or {method: "stripe-link", url}');
  } else if (type === T('payment')) {
    const s = body.settlement;
    const ok = closedKeys(s, ['method', 'proof']) && (s.method === 'stablecoin'
      ? closedKeys(s.proof, ['txHash']) && nonEmpty(s.proof.txHash)
      : s.method === 'stripe-link' && closedKeys(s.proof, ['paymentId']) && nonEmpty(s.proof.paymentId));
    if (!ok) throw bad('payment.settlement must be {method, proof: {txHash}} (stablecoin) or {method, proof: {paymentId}} (stripe-link)');
  } else if (type === T('deliver')) {
    if (body.type === 'inline' ? typeof body.content !== 'string' : typeof body.uri !== 'string') throw bad('deliver inline requires content, reference requires uri');
  }
}

const STATES: ReadonlySet<unknown> = new Set(TRANSITIONS.map(([, , to]) => to));
const TYPES: ReadonlySet<unknown> = new Set(COMMERCE_TYPES);

/** A stored thread snapshot of `local` held under `key`; anything malformed is `storage_failed`. */
function checkThread(v: unknown, key: string, local: string): ThreadSnapshot {
  const ok = isObj(v) && isThreadId(v.threadId) && v.localAceId === local && isACEId(v.peerAceId)
    && v.conversation === conversationKey(local, v.peerAceId) && ThreadStore.key(v.conversation, v.threadId) === key
    && STATES.has(v.state) && Array.isArray(v.history) && v.history.length > 0
    && v.history.every((h) => isObj(h) && TYPES.has(h.type) && isMessageId(h.messageId) && wireInt(h.timestamp) !== null && isACEId(h.from));
  if (!ok) throw new ACEError('storage_failed', `${key} is not a valid commerce thread`);
  return v as unknown as ThreadSnapshot;
}

/** The open-thread index of a peer: thread keys. */
function checkIndex(v: unknown, key: string): string[] {
  if (!Array.isArray(v) || !v.every((k) => typeof k === 'string')) throw new ACEError('storage_failed', `${key} is not a valid thread index`);
  return v;
}

/** Persistent commerce threads, keyed by (conversation key, threadId); per-peer open-thread index. */
export class ThreadStore {
  readonly store: ACEStore;
  readonly localAceId: string;
  constructor(store: ACEStore, localAceId: string) { this.store = store; this.localAceId = localAceId; }

  static key(conversation: string, threadId: string): string { return `commerce/threads/${pairKey(conversation, threadId)}.json`; }
  static #index(peer: string): string { return `commerce/open/${sha256Hex(peer)}.json`; }

  async get(peer: string, threadId: string): Promise<ThreadSnapshot | null> {
    const key = ThreadStore.key(conversationKey(this.localAceId, peer), threadId);
    return readState(this.store, key, (v) => checkThread(v, key, this.localAceId));
  }

  async list(): Promise<ThreadSnapshot[]> {
    return (await readAll(this.store, 'commerce/threads/')).map(([k, v]) => checkThread(v, k, this.localAceId));
  }

  async openCount(peer: string): Promise<number> {
    const key = ThreadStore.#index(peer);
    return (await readState(this.store, key, (v) => checkIndex(v, key)))?.length ?? 0;
  }

  async save(s: ThreadSnapshot): Promise<void> {
    const key = ThreadStore.key(s.conversation, s.threadId);
    await this.store.write(key, canonicalStateBytes(s));
    const ikey = ThreadStore.#index(s.peerAceId);
    const open = new Set(await readState(this.store, ikey, (v) => checkIndex(v, ikey)));
    if (TERMINAL.has(s.state)) open.delete(key); else open.add(key);
    await this.store.write(ikey, canonicalStateBytes([...open].sort()));
  }

  /** Allowed next commerce types for `sender` in a thread (empty when terminal). */
  static allowedTypes(s: ThreadSnapshot | null, sender: string): CommerceType[] {
    if (s === null) return [T('rfq')];
    if (TERMINAL.has(s.state)) return [];
    const role = roleOf(s, sender);
    return TRANSITIONS.filter(([st, , , r]) => st === s.state && r === role).map(([, t]) => t);
  }
}

/**
 * Decide `event` against `snapshot` in the profile's check order; returns the next snapshot. Pure.
 */
export function decideCommerce(local: string, snapshot: ThreadSnapshot | null, e: RuleEvent, body: JSONObject, openThreads = 0): ThreadSnapshot {
  if (!isThreadId(e.threadId)) throw new ACEError('invalid_body', 'commerce messages require a threadId');
  checkCommerceBody(e.type, body);
  if ((local !== e.from && local !== e.to) || e.from === e.to) throw new ACEError('wrong_party', 'the local agent is not exactly one party');
  const peer = peerOf(local, e);
  if (snapshot !== null && snapshot.peerAceId !== peer) throw new ACEError('wrong_party', 'message is not between the thread parties');
  const state: ThreadState = snapshot?.state ?? 'idle';
  const rule = TERMINAL.has(state) ? undefined : TRANSITIONS.find(([s, t]) => s === state && t === e.type);
  if (rule === undefined) throw new ACEError('transition_not_allowed', `${e.type} is not allowed in state ${state}`);
  const [, , next, role] = rule;
  if (snapshot !== null && roleOf(snapshot, e.from) !== role) throw new ACEError('wrong_role', `${e.type} must come from the ${role}`);
  const ref = REFERENCES[e.type as CommerceType];
  if (ref !== undefined) {
    const h = snapshot!.history;
    if (body[ref[0]] !== h[h.length - ref[1]]?.messageId) throw new ACEError('bad_reference', `${e.type}.${ref[0]} does not reference the required message`);
  }
  if (snapshot === null ? openThreads >= MAX_OPEN_THREADS_PER_PEER : snapshot.history.length >= MAX_THREAD_HISTORY) throw new ACEError('limit_exceeded', 'commerce thread bound reached');
  const entry: ThreadHistoryEntry = { type: e.type as CommerceType, messageId: e.messageId, timestamp: e.timestamp, from: e.from };
  return {
    conversation: conversationKey(local, peer), threadId: e.threadId, localAceId: local, peerAceId: peer, state: next,
    history: [...(snapshot?.history ?? []), entry],
  };
}

/** The commerce `ProfileRules`: `check` reads thread state, `commit` applies the transition (lock `commerce`). */
export function commerceRules(threads: ThreadStore): ProfileRules {
  const local = threads.localAceId;
  const load = async (e: RuleEvent) => {
    const peer = peerOf(local, e);
    const snapshot = isThreadId(e.threadId) ? await threads.get(peer, e.threadId) : null;
    return { snapshot, open: snapshot === null ? await threads.openCount(peer) : 0 };
  };
  return {
    types: COMMERCE_TYPES,
    async check(e, body) {
      const { snapshot, open } = await load(e);
      decideCommerce(local, snapshot, e, body, open);
    },
    async commit(e, body) {
      await withLock(threads.store, 'commerce', async () => {
        const { snapshot, open } = await load(e);
        if (snapshot?.history.some((h) => h.messageId === e.messageId && h.from === e.from)) return; // already applied
        await threads.save(decideCommerce(local, snapshot, e, body, open));
      });
    },
  };
}

