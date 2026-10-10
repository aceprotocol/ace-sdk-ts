import {
  ACEError, Inbox, MemoryStore, Outbox, PeerStore, SoftwareIdentity, createRegistrationFile, type ACEStore, type ParsedMessage,
  type RelayClient, type SigningScheme, type VerifiedPeer,
} from '../src/index.js';

export class Clock {
  constructor(public t = 1_800_000_000) {}
  readonly fn = () => this.t;
}

/** An idempotent host effect store keyed by (from, messageId), plus a raw call log. */
export class Host {
  calls: Array<[string, string]> = [];
  effects = new Map<string, ParsedMessage>();
  fail = false;
  readonly fn = (m: ParsedMessage) => {
    if (this.fail) throw new Error('host down');
    this.calls.push([m.from, m.messageId]);
    const k = `${m.from}|${m.messageId}`;
    if (!this.effects.has(k)) this.effects.set(k, m);
  };
}

/** Wraps a store; `failAt` makes the Nth write throw storage_failed (not applied). */
export class CountingStore implements ACEStore {
  writes: string[] = [];
  lists: string[] = [];
  constructor(readonly inner: ACEStore, public failAt: number | null = null) {}
  read(k: string) { return this.inner.read(k); }
  async write(k: string, v: Uint8Array) {
    this.writes.push(k);
    if (this.failAt !== null && this.writes.length === this.failAt) {
      throw new ACEError('storage_failed', `injected failure on write ${this.failAt} (${k})`);
    }
    await this.inner.write(k, v);
  }
  delete(k: string) { return this.inner.delete(k); }
  list(p: string) {
    this.lists.push(p);
    return this.inner.list(p);
  }
  lock(n: string, o?: { timeoutMs?: number }) { return this.inner.lock(n, o); }
}

export async function cloneStore(src: ACEStore, dst: ACEStore = new MemoryStore()): Promise<ACEStore> {
  for (const k of await src.list('')) await dst.write(k, (await src.read(k))!);
  return dst;
}

export class Agent {
  identity!: SoftwareIdentity;
  id!: string;
  peers!: PeerStore;
  outbox!: Outbox;
  host = new Host();
  relay?: RelayClient;

  private constructor(readonly name: string, readonly clock: Clock, public store: ACEStore) {}

  static async create(name: string, scheme: SigningScheme, clock: Clock, store: ACEStore = new MemoryStore(), relay?: RelayClient): Promise<Agent> {
    const a = new Agent(name, clock, store);
    a.identity = await SoftwareIdentity.generate(scheme);
    a.id = a.identity.getACEId();
    a.relay = relay;
    a.peers = new PeerStore({ store, relay, clock: clock.fn });
    a.outbox = await Outbox.open({ commerce: true, identity: a.identity, store, clock: clock.fn });
    return a;
  }

  open(o: { store?: ACEStore; offlineWindowSeconds?: number; capacity?: number; onMessage?: Host['fn'] } = {}): Promise<Inbox> {
    const store = o.store ?? this.store;
    return Inbox.open({ commerce: true,
      identity: this.identity, store, peers: new PeerStore({ store, relay: this.relay, clock: this.clock.fn }),
      onMessage: o.onMessage ?? this.host.fn, clock: this.clock.fn, offlineWindowSeconds: o.offlineWindowSeconds, capacity: o.capacity,
    });
  }

  async registration() {
    return await createRegistrationFile(this.identity, { name: this.name, endpoint: `https://${this.name}.example/ace`, timestamp: 0 });
  }

  async pin(other: Agent): Promise<VerifiedPeer> {
    return this.peers.pinRegistrationFile(await other.registration());
  }

  async peer(other: Agent): Promise<VerifiedPeer> {
    return (await this.peers.get(other.id))!;
  }
}

export function json(raw: Uint8Array | null): any {
  return raw === null ? null : JSON.parse(new TextDecoder().decode(raw));
}
