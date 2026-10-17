/**
 * The networked agent: publish (with prekey rotation, registering on demand), discover, import, connect via contact
 * packets, accept, block, descriptor refresh, permit renewal through receipts, and delivery through the Outbox and
 * Inbox. Local configuration, never a remote message, controls admission.
 */
import { AdmissionBook, type ContactRequest, type PeerRecord } from './admission.js';
import { commerceRules, ThreadStore } from './commerce.js';
import { contactContent, receiptContent, type ContactBody, type ReceiptBody } from './core-messages.js';
import {
  createDescriptor, createPermit, delegationIssuers, documentDigest, isBoundTo, isCachedUsable, verifyDelegation, verifyPermit, verifyPublishedAgent,
  type AgentCard, type DelegationCredential, type DeliveryPermit, type DescriptorDelegation, type Erc8004Binding, type PublishedAgent, type Visibility,
} from './descriptor.js';
import { ACEError } from './errors.js';
import { canonicalStateBytes, isACEId, isHandle, isObj, nowOf, parseStateBytes, sha256Hex } from './encoding.js';
import type { KelEvent, KelState } from './kel.js';
import { checkUsable, type ACEIdentity } from './identity.js';
import { Inbox, type ContactEvent, type ReceiveOutcome } from './inbox.js';
import { verifyInvitation, type Invitation } from './invitation.js';
import { MAX_PERMIT_LIFETIME, PERMIT_RENEWAL_SECONDS, PREKEY_ROTATION_SECONDS } from './limits.js';
import { ProfileSet, type ProfileManifest } from './manifest.js';
import { MessageLog } from './message-log.js';
import { FileStore, publicRelay } from './node.js';
import { Outbox, type OutboxEntry } from './outbox.js';
import { createPacket } from './packet.js';
import { PeerStore } from './peer-store.js';
import { StorePrekeyVault, type PrekeyVault } from './prekey.js';
import { RelayClient } from './relay.js';
import type { ProfileRules } from './rules.js';
import { withLock, type ACEStore } from './store.js';
import type { JSONObject, ParsedMessage, PrivateContent } from './types.js';

export interface NetworkClientOptions {
  identity: ACEIdentity;
  /** An ACEStore, or a directory for a `FileStore`. */
  store: ACEStore | string;
  /** The home relay URL: registration, inbox, publication. Its RelayClient gets `fetch`, `clock`, `allowLoopbackRelays` and the store. */
  relayUrl?: string;
  /** Or a ready home RelayClient (e.g. one routing through a proxy); takes precedence over `relayUrl`. */
  relay?: RelayClient;
  /** Installed profiles: bundled names or manifests (default `['text']`). `'commerce'` also installs `commerceRules` and `threads`. */
  profiles?: Array<'text' | 'commerce' | ProfileManifest>;
  /** Further profile rules (third-party profiles). */
  rules?: ProfileRules[];
  /** Prekey vault (default: a StorePrekeyVault in `store`). */
  vault?: PrekeyVault;
  /** Client for a peer-advertised relay; must enforce the host's outbound policy (default `publicRelay` with this client's clock and loopback policy). */
  foreignRelay?: (url: string) => RelayClient;
  /** `fetch` of the home RelayClient built from `relayUrl`. */
  fetch?: typeof fetch;
  visibility?: Visibility;
  handle?: string;
  card?: AgentCard;
  ext?: Record<string, JSONObject>;
  /** Delegation entries naming this identity; only the live ones are published. */
  delegations?: DescriptorDelegation[];
  erc8004?: Erc8004Binding[];
  /** Profiles whose contact requests are accepted without an explicit `accept` (equal digest required). */
  acceptProfiles?: string[];
  /** Log delivered messages in the store (default on): the client's `messages`. */
  messageLog?: false | { maxUnread?: number; retentionSeconds?: number };
  /** Called with each delivered message, after it is logged. Throwing defers the packet. */
  onMessage?: (m: ParsedMessage) => void | Promise<void>;
  /** An effect-free capacity check besides the message log's; throw `receiver_capacity` to leave the packet on the relay. */
  checkCapacity?: (m: ParsedMessage) => void | Promise<void>;
  /** Observes contact events after the client handled them. */
  onContact?: (e: ContactEvent) => void | Promise<void>;
  /** Observes each receipt after the Outbox applied it: `entry` is the settled Outbox entry, or null when none matched. */
  onReceipt?: (from: string, body: ReceiptBody, entry: OutboxEntry | null) => void | Promise<void>;
  /** Development only: accept loopback `http://` relays in descriptors and as foreign relays. */
  allowLoopbackRelays?: boolean;
  /**
   * At most this many pending incoming contact requests are held (default 16): one per sender, each expiring after
   * 24 h, the oldest evicted when full (05 § Flow).
   */
  maxPendingRequests?: number;
  /**
   * Open the receive role (default true). `false` gives a send-only client: no Inbox, so it never takes the exclusive
   * `receive` lock nor reads or writes inbox/replay state, and can run beside a receiving process on the same store
   * (Outbox writes are coordinated by store locks). `pull`, `follow` and `inbox` are unavailable.
   */
  receive?: boolean;
  clock?: () => number;
}

interface SelfRecord { agent: PublishedAgent; params: string }
const SELF_KEY = 'network/self.json';
const agentKey = (id: string) => `network/agents/${sha256Hex(id)}.json`;

const blockedPeer = () => new ACEError('not_permitted', 'the peer is blocked; unblock it first');

/** The record an explicit admission starts from: the old one without its block sync state. */
function unblocked(old: PeerRecord | null, aceId: string): Omit<PeerRecord, 'status' | 'updatedAt'> {
  if (old === null) return { aceId };
  const { unsyncedRevision: _, status: _s, updatedAt: _u, ...rest } = old;
  return rest;
}

export class NetworkClient {
  readonly identity: ACEIdentity;
  readonly store: ACEStore;
  readonly relay: RelayClient;
  readonly profiles: ProfileSet;
  readonly vault: PrekeyVault;
  readonly peers: PeerStore;
  readonly admission: AdmissionBook;
  readonly outbox: Outbox;
  /** The delivered-message log (null with `messageLog: false`). */
  readonly messages: MessageLog | null;
  /** Commerce threads (null unless the commerce profile is installed). */
  readonly threads: ThreadStore | null;
  readonly options: Readonly<NetworkClientOptions>;
  #inbox: Inbox | null = null;

  private constructor(o: NetworkClientOptions, store: ACEStore) {
    if (o.relay === undefined && o.relayUrl === undefined) throw new ACEError('invalid_argument', 'relayUrl or relay is required');
    this.options = o;
    this.identity = o.identity;
    this.store = store;
    this.relay = o.relay ?? new RelayClient(o.relayUrl!, { fetch: o.fetch, clock: o.clock, allowLoopbackRelays: o.allowLoopbackRelays, store });
    const names = o.profiles ?? ['text'];
    this.profiles = new ProfileSet(names);
    this.threads = names.includes('commerce') ? new ThreadStore(store, o.identity.getACEId()) : null;
    this.messages = o.messageLog === false ? null : new MessageLog(store, { ...(o.messageLog ?? {}), clock: o.clock });
    this.vault = o.vault ?? new StorePrekeyVault(store, { clock: o.clock });
    this.peers = new PeerStore({ store, clock: o.clock });
    this.admission = new AdmissionBook(store, { clock: o.clock, maxRequests: o.maxPendingRequests });
    for (const p of o.acceptProfiles ?? []) if (!this.profiles.has(p)) throw new ACEError('invalid_argument', `acceptProfiles entry ${p} is not installed`);
    this.outbox = new Outbox({
      identity: o.identity, store, profiles: this.profiles, rules: this.#rules(), clock: o.clock,
      transport: ({ to, content, messageId, refresh, avoidPrekey }) => this.#post(to, content, { messageId, refresh, avoidPrekey, needPermit: true }),
      // A cached descriptor (even a stale one: attempts refresh it) suffices; otherwise one must resolve now.
      resolvePeer: async (to) => { if (await this.#read<PublishedAgent>(agentKey(to)) === null) await this.agent(to); },
    });
  }

  #rules(): ProfileRules[] {
    return [...(this.threads ? [commerceRules(this.threads)] : []), ...(this.options.rules ?? [])];
  }

  /** Build the client from configuration and open its Inbox (one receiver per store) unless `receive: false`. */
  static async open(o: NetworkClientOptions): Promise<NetworkClient> {
    const c = new NetworkClient(o, typeof o.store === 'string' ? new FileStore(o.store) : o.store);
    if (o.receive === false) return c;
    const messages = c.messages;
    c.#inbox = await Inbox.open({
      identity: o.identity, store: c.store, vault: c.vault, profiles: c.profiles, peers: c.peers, admission: c.admission,
      rules: c.#rules(), clock: o.clock, allowLoopbackRelays: o.allowLoopbackRelays,
      onMessage: async (m) => { if (messages) await messages.save(m); await o.onMessage?.(m); },
      checkCapacity: async (m) => { await messages?.checkCapacity(m); await o.checkCapacity?.(m); },
      visibility: () => c.options.visibility ?? 'private',
      onReceipt: (from, body) => c.#onReceipt(from, body),
      onContact: (e) => c.#onContact(e),
      sendReceipt: (to, body) => c.#sendReceipt(to, body),
      refreshPeer: async (id) => { await c.agent(id, { refresh: true }); },
      threadBusy: async (peer, threadId) => (await c.outbox.busy(peer, threadId)) !== null,
    });
    return c;
  }

  /** The receive pipeline (unavailable on a send-only client). */
  get inbox(): Inbox {
    if (this.#inbox === null) throw new ACEError('invalid_argument', 'this client was opened without the receive role');
    return this.#inbox;
  }

  #now(): number { return nowOf(this.options.clock); }
  #verifyOpts(): { allowLoopbackRelays?: boolean } { return { allowLoopbackRelays: this.options.allowLoopbackRelays }; }
  #relayFor(url: string): RelayClient {
    if (url === this.relay.baseUrl) return this.relay;
    const { foreignRelay, clock, allowLoopbackRelays } = this.options;
    return foreignRelay ? foreignRelay(url) : publicRelay(url, { clock, allowLoopbackRelays });
  }
  async #read<T>(key: string): Promise<T | null> {
    const raw = await this.store.read(key);
    return raw === null ? null : parseStateBytes(raw, key) as T;
  }

  // --- publication ---------------------------------------------------------------------------

  /**
   * Publish this identity's descriptor: rotates the prekey when none exists or it is older than 24 h (pruning
   * expired retained prekeys), and reuses an unchanged descriptor with more than an hour left unless `force` (which
   * posts it again). When the home relay holds no registration or an older KEL (`not_registered` / `kel_conflict`),
   * the current KEL is registered and the descriptor posted once more.
   */
  async publish(o: { force?: boolean } = {}): Promise<PublishedAgent> {
    return withLock(this.store, 'network-self', async () => {
      const now = this.#now();
      await this.vault.prune(now);
      let prekey = await this.vault.current();
      if (prekey === null || prekey.createdAt + PREKEY_ROTATION_SECONDS <= now) prekey = await this.vault.rotate(now);
      const opts = this.options;
      const params = {
        relays: [this.relay.baseUrl], prekey: { id: prekey.id, publicKey: prekey.publicKey }, profiles: this.profiles.descriptors(),
        visibility: opts.visibility ?? 'private', card: opts.card ?? {}, ...(opts.handle ? { handle: opts.handle } : {}),
        ...(opts.ext ? { ext: opts.ext } : {}), ...(opts.erc8004 ? { erc8004: opts.erc8004 } : {}),
        ...await this.#liveDelegations(now),
      };
      const digest = sha256Hex(canonicalStateBytes({ params, lastHash: checkUsable(this.identity, now).lastHash }));
      const old = await this.#read<SelfRecord>(SELF_KEY);
      if (old && old.params === digest && old.agent.descriptor.expiresAt > now + 3600) {
        if (o.force) await this.#postDescriptor(old.agent);
        return old.agent;
      }
      const agent = await createDescriptor(this.identity, { ...params, now: Math.max(now, (old?.agent.descriptor.issuedAt ?? -1) + 1), ...this.#verifyOpts() });
      await this.#postDescriptor(agent);
      await this.store.write(SELF_KEY, canonicalStateBytes({ agent, params: digest }));
      return agent;
    });
  }

  /**
   * The configured delegations that verify at `now`. One that expired (the issuer stopped renewing) or whose issuer KEL
   * is no longer usable drops out of the next descriptor instead of making it unverifiable.
   */
  async #liveDelegations(now: number): Promise<{ delegations?: DescriptorDelegation[] }> {
    const all = this.options.delegations ?? [];
    const ok = await Promise.all(all.map((d) => this.#checkDelegation(d, now).then((v) => v !== null, () => false)));
    const live = all.filter((_, i) => ok[i]);
    return live.length ? { delegations: live } : {};
  }

  /**
   * Verify a delegation entry naming this identity as subject, reconciling its issuer KEL with our pin for the issuer
   * (01 § Pinning). Null when expired; `invalid_authorization` when it does not verify.
   */
  verifyDelegation(entry: unknown): Promise<{ issuer: string; credential: DelegationCredential } | null> {
    return this.#checkDelegation(entry, this.#now());
  }

  async #checkDelegation(entry: unknown, now: number): Promise<{ issuer: string; credential: DelegationCredential } | null> {
    const issuer = isObj(entry) && isObj(entry.credential) ? entry.credential.issuer : undefined;
    const pinned = isACEId(issuer) ? await this.peers.get(issuer) : null;
    return verifyDelegation(entry, this.identity.getACEId(), now, { pinned });
  }

  /** Post `agent` to the home relay, registering the current KEL first when the relay lacks it. */
  async #postDescriptor(agent: PublishedAgent): Promise<void> {
    try {
      await this.relay.publishDescriptor(agent);
    } catch (e) {
      if (!(e instanceof ACEError && (e.code === 'not_registered' || e.relayCode === 'kel_conflict'))) throw e;
      await this.relay.register(this.identity);
      await this.relay.publishDescriptor(agent);
    }
  }

  // --- discovery ----------------------------------------------------------------------------

  /** The public directory of the home relay (every entry verified). */
  discover(o: { profile?: string; cursor?: string; limit?: number } = {}): Promise<{ agents: PublishedAgent[]; cursor: string | null }> {
    return this.relay.listDescriptors(o);
  }

  /**
   * Verify and cache a PublishedAgent and pin its KEL. Grants no admission. Under an unchanged KEL an older revision
   * never replaces a newer one (even an expired one: no rollback); an entry signed under a superseded KEL is replaced.
   */
  async importAgent(value: unknown): Promise<PublishedAgent> {
    const d = isObj(value) ? value.descriptor : undefined;
    if (!isObj(d) || !isACEId(d.aceId)) throw new ACEError('invalid_authorization', 'published agent must be {kel, descriptor}');
    const id = d.aceId;
    // 01 § Pinning: the descriptor must verify under the KEL state that ends up pinned, never under an older prefix.
    const now = this.#now();
    const [pinned, delegationPins] = await Promise.all([this.peers.get(id), this.peers.pins(delegationIssuers(value))]);
    const { agent, state } = verifyPublishedAgent(value, now, { ...this.#verifyOpts(), pinned, delegationPins });
    // The pin and the cached descriptor change together, under the `peers` lock.
    return this.peers.adopt(structuredClone(state.events), async ({ state: pin }) => {
      // Another path advanced the pin past the state the descriptor verified under (it was read before the lock).
      if (pin.lastHash !== state.lastHash) throw new ACEError('stale_peer_binding', 'the pin advanced past the descriptor');
      const old = await this.#read<PublishedAgent>(agentKey(id));
      // Under the same KEL, only a newer issuedAt (or an equal one with identical claims) replaces the entry. The kept
      // entry is returned only while usable: an older candidate never stands in for it, and a stale one is never returned.
      if (old && isBoundTo(old, pin) && (old.descriptor.issuedAt > agent.descriptor.issuedAt
        || (old.descriptor.issuedAt === agent.descriptor.issuedAt && documentDigest(old.descriptor) !== documentDigest(agent.descriptor)))) {
        const oldPins = await this.peers.pins(delegationIssuers(old));
        if (isCachedUsable(old, now, { pinned: pin, delegationPins: oldPins })) return old;
        throw new ACEError('stale_peer_binding', 'an older descriptor revision cannot replace the cached one');
      }
      const stored: PublishedAgent = { kel: structuredClone(state.events) as KelEvent[], descriptor: agent.descriptor };
      await this.store.write(agentKey(id), canonicalStateBytes(stored));
      return stored;
    });
  }

  /** Resolve `@name@relay-host` (or a bare ACE ID) to a verified, imported PublishedAgent. */
  async lookup(target: string): Promise<PublishedAgent> {
    if (isACEId(target)) return this.agent(target);
    const m = typeof target === 'string' ? /^@([^@]+)@([a-z0-9.-]+(?::[0-9]+)?)$/.exec(target) : null;
    if (!m || !isHandle(m[1])) throw new ACEError('invalid_argument', 'use an ACE ID or @name@relay-host');
    const home = new URL(this.relay.baseUrl);
    const relay = m[2] === home.host ? this.relay : this.#relayFor(`https://${m[2]}`);
    return this.importAgent(await relay.resolveHandle(m[1]));
  }

  /**
   * The peer's descriptor: the cached one while usable, else refreshed from its routes (public: `GET`; with a permit
   * it issued us: `resolve`). A failed refresh throws; a stale descriptor is never returned.
   */
  async agent(aceId: string, o: { refresh?: boolean } = {}): Promise<PublishedAgent> {
    const cached = await this.#read<PublishedAgent>(agentKey(aceId));
    const [pinned, delegationPins] = await Promise.all([this.peers.get(aceId), cached ? this.peers.pins(delegationIssuers(cached)) : new Map<string, KelState>()]);
    if (cached && !o.refresh && isCachedUsable(cached, this.#now(), { pinned, delegationPins })) return cached;
    // A permit is a bearer credential: present it only to routes from a descriptor signed under the issuer's current
    // pin. A KEL-stale descriptor (signed under a superseded, possibly compromised key) may name attacker relays: its
    // routes and the home relay get only the anonymous public lookup, as when nothing is cached.
    if (cached !== null && isBoundTo(cached, pinned)) return this.#fetchAgent(aceId, cached.descriptor.relays, this.#live(await this.admission.heldPermit(aceId), pinned));
    return this.#fetchAgent(aceId, [...new Set([...cached?.descriptor.relays ?? [], this.relay.baseUrl])]);
  }

  /** Fetch and import the peer's descriptor from the first of `routes` that serves it (`resolve` with `permit`). */
  async #fetchAgent(aceId: string, routes: readonly string[], permit?: DeliveryPermit): Promise<PublishedAgent> {
    let error: unknown = new ACEError('unknown_peer', 'no route to the peer');
    for (const route of routes) {
      try {
        const relay = this.#relayFor(route);
        return await this.importAgent(permit ? await relay.resolveDescriptor(aceId, permit) : await relay.getDescriptor(aceId));
      } catch (e) {
        error = e;
      }
    }
    throw error;
  }

  /** The permit `aceId` issued us, only while it verifies under its current pin: the one `send` presents. */
  permitFrom(aceId: string): Promise<DeliveryPermit | undefined> {
    return this.#theirPermit(aceId);
  }

  /**
   * The permit the peer issued us (held, or `explicit`, e.g. one carried by its contact request), only while it
   * verifies under the peer's current pin: a permit is a bearer credential, never presented from a superseded key.
   */
  async #theirPermit(aceId: string, explicit?: DeliveryPermit): Promise<DeliveryPermit | undefined> {
    const [state, held] = await Promise.all([this.peers.get(aceId), explicit ?? this.admission.heldPermit(aceId)]);
    return this.#live(held, state);
  }

  /** `permit` if it verifies under the issuer's pinned `state` now (issued to this identity), else undefined. */
  #live(permit: DeliveryPermit | null | undefined, state: KelState | null): DeliveryPermit | undefined {
    if (!permit || state === null) return undefined;
    try { return verifyPermit(permit, state, this.identity.getACEId(), this.#now()); } catch { return undefined; }
  }

  /**
   * Hold a permit the issuer gave us (already verified under its current pin). The held one is kept instead only while
   * it is newer and still verifies under that pin: a permit from a superseded key never shadows a valid one.
   */
  async #hold(permit: DeliveryPermit, when?: (record: PeerRecord | null) => boolean): Promise<void> {
    const state = await this.peers.get(permit.issuer);
    await this.admission.holdPermit(permit, { when, keep: (old) => old.issuedAt > permit.issuedAt && this.#live(old, state) !== undefined });
  }

  // --- invitations (05 § Invitations) --------------------------------------------------------

  /**
   * Invite one peer (ACE ID, `@handle@host`, or its PublishedAgent shared out of band) to contact this identity:
   * imports the peer, records it `admitted` (an explicit local decision; clears a block) and returns this identity's
   * PublishedAgent with a delivery permit issued to the peer. Share it privately: the permit is a bearer credential.
   */
  async createInvitation(peer: string | PublishedAgent, o: { profile?: string } = {}): Promise<Invitation> {
    if (o.profile !== undefined && !this.profiles.has(o.profile)) throw new ACEError('invalid_argument', `${o.profile} is not installed`);
    const agent = typeof peer === 'string' ? await this.lookup(peer) : await this.importAgent(peer);
    const id = agent.descriptor.aceId;
    if (id === this.identity.getACEId()) throw new ACEError('invalid_argument', 'cannot invite this identity');
    await this.#unblockAtRelay(await this.admission.get(id));
    const permit = await this.#createPermit(id);
    await this.admission.update(id, (old) => ({
      ...unblocked(old, id), status: 'admitted', ...(o.profile !== undefined ? { profile: o.profile } : {}), updatedAt: this.#now(),
    }));
    const invitation = { agent: await this.publish(), permit };
    await this.#noteIssued(id, permit); // handing the invitation to the host is the send
    return invitation;
  }

  /**
   * Import an invitation `{agent, permit}` addressed to this identity: verify and pin the agent, hold its permit (so
   * `connect` can reach a private inviter). Never admits the inviter. Returns the imported PublishedAgent.
   */
  async importInvitation(value: unknown): Promise<PublishedAgent> {
    const { agent, permit } = verifyInvitation(value, this.identity.getACEId(), this.#now(), this.#verifyOpts());
    const stored = await this.importAgent(agent.agent);
    // Re-verified under the pin now held: holding the inviter's permit lets us reach it, never admits it.
    const state = await this.peers.get(permit.issuer);
    if (state === null) throw new ACEError('unknown_peer', 'the inviter is not pinned');
    await this.#hold(verifyPermit(permit, state, this.identity.getACEId(), this.#now()));
    return stored;
  }

  // --- sending ------------------------------------------------------------------------------

  /**
   * Encrypt `content` to the peer's current prekey and post it to its routes (single attempt). `needPermit` (every
   * Outbox attempt, 06 § Outbox step 3): without a permit valid under the peer's current pin the attempt fails
   * `not_permitted` and nothing is posted; it never falls back to the stranger path.
   */
  async #post(to: string, content: PrivateContent, o: { messageId?: string; refresh: boolean; avoidPrekey?: string; permit?: DeliveryPermit; needPermit?: boolean }): Promise<{ prekey: string }> {
    const agent = await this.agent(to, { refresh: o.refresh });
    const prekey = agent.descriptor.prekey;
    if (o.avoidPrekey !== undefined && prekey.id === o.avoidPrekey) throw new ACEError('unknown_prekey', 'the peer still publishes the rejected prekey');
    const [packet, permit] = await Promise.all([
      createPacket({ identity: this.identity, to, prekey, content, ...(o.messageId ? { messageId: o.messageId } : {}), timestamp: this.#now() }),
      this.#theirPermit(to, o.permit),
    ]);
    if (o.needPermit && permit === undefined) throw new ACEError('not_permitted', 'no permit from this peer valid under its current pin');
    let error: unknown;
    for (const route of agent.descriptor.relays) {
      try {
        await this.#relayFor(route).send(packet, permit);
        return { prekey: prekey.id };
      } catch (e) {
        error = e;
        if (e instanceof ACEError && !e.isTransient && e.code !== 'unknown_peer') throw e;
      }
    }
    throw error;
  }

  /** Send a contact packet of `kind` carrying our current descriptor (single attempt, no refresh). */
  async #sendContact(to: string, body: Omit<ContactBody, 'note' | 'source'> & { note?: string; source?: PublishedAgent }, o: { messageId?: string; permit?: DeliveryPermit } = {}): Promise<void> {
    const source = body.source ?? await this.publish();
    await this.#post(to, contactContent({ ...body, note: body.note ?? '', source }), { refresh: false, ...o });
  }

  /** One receipt attempt, carrying a permit renewal when due; the renewal counts as issued once the receipt was sent. */
  async #sendReceipt(to: string, body: ReceiptBody): Promise<void> {
    const permit = await this.#renewal(to);
    await this.#post(to, receiptContent(permit ? { ...body, permit } : body), { refresh: false });
    if (permit) await this.#noteIssued(to, permit);
  }

  /**
   * Queue an application message and try it once now. Delivery is confirmed only by a receipt. Without a permit from
   * `to` valid under its current pin the send fails with `not_permitted` and nothing is stored (06 § Outbox).
   */
  async send(to: string, type: string, body: JSONObject, o: { threadId?: string } = {}): Promise<OutboxEntry> {
    if (!isACEId(to)) throw new ACEError('invalid_argument', 'to must be an ACE ID');
    if (!(await this.#theirPermit(to))) throw new ACEError('not_permitted', 'no valid permit from this peer');
    const entry = await this.outbox.enqueue({ to, type, body, ...(o.threadId !== undefined ? { threadId: o.threadId } : {}) });
    return (await this.outbox.attempt(entry.messageId)) ?? entry;
  }

  /** Attempt every due Outbox entry. */
  flush(): Promise<OutboxEntry[]> { return this.outbox.flush(); }

  /** Pull and process one inbox page from the home relay. */
  pull(o: { limit?: number } = {}): Promise<ReceiveOutcome[]> { return this.inbox.pull(this.relay, o); }

  /** Follow the home relay's listen stream; each consumed packet is acknowledged. */
  follow(o: { signal?: AbortSignal } = {}): AsyncGenerator<ReceiveOutcome, void, undefined> { return this.inbox.follow(this.relay, o); }

  /**
   * Periodic upkeep: publish (renews descriptor and prekey, registers on demand), push fresh permits after a
   * signing-key change, register blocks the relay has not confirmed, retry due Outbox entries and prune settled ones.
   */
  async maintain(): Promise<void> {
    const steps: Array<() => Promise<unknown>> = [
      () => this.publish(),
      () => this.#refreshPermits(),
      async () => {
        for (const rec of await this.admission.list()) {
          if (rec.status === 'blocked' && rec.unsyncedRevision !== undefined) await this.#syncBlock(rec.aceId, rec.unsyncedRevision);
        }
      },
      () => this.flush(),
      () => this.outbox.prune(),
    ];
    // Every step runs even when an earlier one fails (an unreachable home relay must not stop Outbox retries to
    // peers' relays); the first failure is reported at the end.
    let failure: { error: unknown } | undefined;
    for (const step of steps) {
      try { await step(); } catch (error) { failure ??= { error }; }
    }
    if (failure !== undefined) throw failure.error;
  }

  /**
   * After a signing-key change (05 § Delivery permits): re-send a contact request carrying a fresh permit to every
   * admitted peer that holds no permit from us under the current delegation. The peer accepts it automatically and
   * answers `accepted`, which refreshes the permit we hold. A peer whose send fails is retried at the next upkeep.
   */
  async #refreshPermits(): Promise<void> {
    const seq = this.identity.getSigningSeq();
    let source: PublishedAgent | undefined;
    for (const rec of await this.admission.list()) {
      if (rec.status !== 'admitted' || rec.issued?.seq === seq) continue;
      try {
        const agent = await this.agent(rec.aceId);
        const shared = agent.descriptor.profiles.filter((p) => this.profiles.shares(p)).map((p) => p.id);
        const profile = rec.profile !== undefined && shared.includes(rec.profile) ? rec.profile : shared[0];
        if (profile === undefined) continue;
        const permit = await this.#createPermit(rec.aceId);
        source ??= await this.publish();
        await this.#sendContact(rec.aceId, { kind: 'request', profile, source, permit });
        await this.#noteIssued(rec.aceId, permit);
      } catch { /* best effort: not recorded, so retried at the next upkeep */ }
    }
  }

  // --- admission ----------------------------------------------------------------------------

  #createPermit(peer: string): Promise<DeliveryPermit> {
    return createPermit(this.identity, peer, { now: this.#now(), ttl: MAX_PERMIT_LIFETIME });
  }

  /** Record `permit` as the newest one issued to `peer`, once the packet (or invitation) carrying it was sent. */
  async #noteIssued(peer: string, permit: DeliveryPermit): Promise<void> {
    await this.admission.update(peer, (old) => old && { ...old, issued: { expiresAt: permit.expiresAt, seq: permit.signature.seq } });
  }

  /** A fresh permit for a receipt to `peer` when the newest one issued to it is due for renewal (05 § Renewal). */
  async #renewal(peer: string): Promise<DeliveryPermit | undefined> {
    const rec = await this.admission.get(peer);
    if (rec === null || rec.status === 'blocked') return undefined;
    const i = rec.issued;
    if (i && i.expiresAt - this.#now() >= PERMIT_RENEWAL_SECONDS && i.seq === this.identity.getSigningSeq()) return undefined;
    return this.#createPermit(peer);
  }

  /** Relay-first: register `blocked: false` before an explicit admission of a blocked peer. */
  async #unblockAtRelay(rec: PeerRecord | null): Promise<void> {
    if (rec?.status === 'blocked') await this.relay.setBlock(this.identity, rec.aceId, false, await this.admission.nextBlockRevision(rec.aceId));
  }

  #sharedProfile(agent: PublishedAgent, profile: string): void {
    const theirs = agent.descriptor.profiles.find((p) => p.id === profile);
    if (!theirs || !this.profiles.shares(theirs)) throw new ACEError('invalid_argument', `no common installed profile ${profile}`);
  }

  /**
   * Send a contact request for `profile` to `target` (ACE ID, `@handle@host` or a PublishedAgent shared out of band).
   * Records the target as `pending`. A non-public target needs a permit it issued us. A blocked peer is
   * `not_permitted`: only `unblock` (or an invitation) lifts a block (05 § Blocks). Returns the request's messageId.
   */
  async connect(target: string | PublishedAgent, o: { profile: string; note?: string }): Promise<string> {
    const agent = typeof target === 'string' ? await this.lookup(target) : await this.importAgent(target);
    const id = agent.descriptor.aceId;
    this.#sharedProfile(agent, o.profile);
    if ((await this.admission.get(id))?.status === 'blocked') throw blockedPeer();
    if (agent.descriptor.visibility !== 'public' && !(await this.#theirPermit(id))) throw new ACEError('not_permitted', 'a private agent needs a permit it issued');
    const permit = await this.#createPermit(id);
    await this.admission.update(id, (old) => ({
      ...(old ?? { aceId: id }), status: old?.status === 'admitted' ? 'admitted' : 'pending', profile: o.profile, updatedAt: this.#now(),
    }));
    const messageId = crypto.randomUUID();
    await this.#sendContact(id, { kind: 'request', profile: o.profile, note: o.note, permit }, { messageId });
    await this.#noteIssued(id, permit);
    return messageId;
  }

  /** Pending incoming contact requests, oldest first. */
  requests(): Promise<ContactRequest[]> { return this.admission.requests(); }

  /**
   * Accept a pending request: pin, store the requester's permit, admit, reply `accepted`. A blocked peer is
   * `not_permitted`, also when blocked meanwhile: accept never clears a block (05 § Blocks).
   */
  async accept(aceId: string): Promise<void> {
    const req = await this.admission.request(aceId);
    if (req === null) throw new ACEError('invalid_argument', 'no pending request from this peer');
    await this.#acceptRequest(req);
  }

  async #acceptRequest(req: ContactRequest): Promise<void> {
    if ((await this.admission.get(req.from))?.status === 'blocked') throw blockedPeer();
    if (req.source.descriptor.expiresAt > this.#now()) {
      await this.importAgent(req.source);
    } else {
      // The held request (24 h) outlived its source descriptor: pin the source's KEL (05 § Flow step 3) and refresh the
      // descriptor, from the source's routes with the requester's permit while the source is bound to the pin.
      const { state } = await this.peers.adopt(structuredClone(req.source.kel));
      if (isBoundTo(req.source, state)) await this.#fetchAgent(req.from, req.source.descriptor.relays, this.#live(req.permit, state));
      else await this.agent(req.from, { refresh: true });
    }
    const permit = await this.#createPermit(req.from);
    await this.admission.update(req.from, (old) => {
      if (old?.status === 'blocked') throw blockedPeer();
      return { ...(old ?? { aceId: req.from }), status: 'admitted', profile: req.profile, updatedAt: this.#now() };
    });
    await this.#hold(req.permit);
    await this.admission.deleteRequest(req.from);
    await this.#sendContact(req.from, { kind: 'accepted', profile: req.profile, permit });
    await this.#noteIssued(req.from, permit);
  }

  /** Decline a pending request (best-effort `rejected` reply). */
  async reject(aceId: string): Promise<void> {
    const req = await this.admission.request(aceId);
    if (req === null) return;
    await this.admission.deleteRequest(aceId);
    await this.importAgent(req.source).catch(() => undefined);
    try {
      await this.#sendContact(aceId, { kind: 'rejected', profile: req.profile }, { permit: req.permit });
    } catch { /* best effort: the requester's pending entry simply lapses */ }
  }

  /**
   * Block a peer: locally first (the endpoint is the authoritative enforcement point; its held request is discarded),
   * allocating the relay revision with the local record, then at the home relay. If the relay is unreachable the record
   * keeps that revision as `unsyncedRevision` and `maintain` re-sends exactly it. Survives restart.
   */
  async block(aceId: string): Promise<void> {
    if (!isACEId(aceId) || aceId === this.identity.getACEId()) throw new ACEError('invalid_argument', 'peer must be another ACE ID');
    const revision = await this.admission.block(aceId, this.#now());
    await this.#syncBlock(aceId, revision);
  }

  /**
   * Register a local block at the relay with its allocated `revision`. Confirmed, or refused `stale_revision` (a later
   * unblock or admission already holds a higher revision there), it is settled; any other failure leaves it for
   * `maintain`.
   */
  async #syncBlock(aceId: string, revision: number): Promise<void> {
    try {
      await this.relay.setBlock(this.identity, aceId, true, revision);
    } catch (e) {
      if (!(e instanceof ACEError && e.relayCode === 'stale_revision')) return;
    }
    await this.admission.update(aceId, (old) => {
      if (old?.unsyncedRevision !== revision) return old;
      const { unsyncedRevision: _, ...synced } = old;
      return synced;
    });
  }

  /** Remove a block, relay first (the peer becomes a stranger again until contact is re-established). */
  async unblock(aceId: string): Promise<void> {
    const old = await this.admission.get(aceId);
    if (old?.status !== 'blocked') return;
    const revision = await this.admission.nextBlockRevision(aceId);
    await this.relay.setBlock(this.identity, aceId, false, revision);
    // Only if nothing allocated a later revision meanwhile (a concurrent block keeps its record and its re-sync).
    await this.admission.clearBlock(aceId, revision);
  }

  // --- inbox hooks --------------------------------------------------------------------------

  async #onReceipt(from: string, body: ReceiptBody): Promise<void> {
    if (body.permit) await this.#hold(body.permit, (r) => r !== null && r.status !== 'blocked');
    const entry = await this.outbox.onReceipt(from, body);
    await this.options.onReceipt?.(from, body, entry);
  }

  async #onContact(e: ContactEvent): Promise<void> {
    const rec = await this.admission.get(e.from);
    const { kind, profile } = e.body;
    if (kind === 'request') {
      const req: ContactRequest = { from: e.from, messageId: e.messageId, profile, note: e.body.note, source: e.source.agent, permit: e.permit!, receivedAt: this.#now() };
      const theirs = e.source.agent.descriptor.profiles.find((p) => p.id === profile);
      const shared = theirs !== undefined && this.profiles.shares(theirs);
      if (shared && (rec?.status === 'admitted' || (this.options.acceptProfiles ?? []).includes(profile))) {
        await this.#acceptRequest(req);
      } else if (shared) {
        await this.admission.saveRequest(req);
      }
    } else if (rec?.status === 'admitted' && kind === 'accepted') {
      // The answer to a permit refresh (05 § Delivery permits): only the held permit changes.
      await this.importAgent(e.source.agent);
      await this.#hold(e.permit!, (r) => r?.status === 'admitted');
    } else if (rec?.status === 'pending' && rec.profile === profile) {
      if (kind === 'accepted') {
        await this.importAgent(e.source.agent);
        await this.admission.update(e.from, (old) => old && { ...old, status: 'admitted', updatedAt: this.#now() });
        await this.#hold(e.permit!);
      } else {
        await this.admission.update(e.from, () => null);
      }
    }
    await this.options.onContact?.(e);
  }

  async close(): Promise<void> { await this.#inbox?.close(); }
}
