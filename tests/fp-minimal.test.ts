// Review-focus regressions of the fp-minimal revision (A4-A6, A12; review I3, I4, I9, P2-1).
import {
  CONTACT_REQUEST_TTL_SECONDS, CONTACT_TYPE, CONTACT_SCHEMA_DIGEST, Inbox, MemoryStore, NetworkClient, OFFLINE_WINDOW_SECONDS,
  RelayClient, canonicalStateBytes, contactContent, createAuthHeaders, createDescriptor, createPermit, isBlockedAddress, networkKey, parseAuthHeaders,
  parseIp, verifyAuthHeaders, verifyKel,
  type OutboxEntry, type ReceiptBody,
} from './sdk.js';
import * as sdk from '../src/index.js';
import { vi } from 'vitest';
import { Clock, FakeRelay, NOW, RELAY, agent, identity } from './helpers.js';
import { inboxWorld, msg } from './helpers2.js';

const TEXT = 'ace:text:1';

/** An admitted pair over one FakeRelay: alice public and auto-accepting text, bob connected to her. */
async function pair(o: { bob?: object } = {}) {
  const clock = new Clock(), relay = new FakeRelay(clock.now);
  const alice = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: [TEXT] });
  const bob = await agent(relay, clock, o.bob ?? {});
  await bob.client.connect(alice.id.getACEId(), { profile: TEXT });
  await alice.client.pull();
  await bob.client.pull();
  return { clock, relay, alice, bob, a: alice.id.getACEId(), b: bob.id.getACEId() };
}

describe('A4: beyond the replay horizon is dropped and never receipted', () => {
  it('two relays delivering out of order: the late old copy is dropped, a retry is delivered', async () => {
    const w = await inboxWorld({ capacity: 16 }); // sender quota Q = 1
    const first = await w.pack(w.sender, msg('one'), w.clock.t - 20);
    const second = await w.pack(w.sender, msg('two'), w.clock.t - 10);
    expect((await w.inbox.receive(first)).kind).toBe('delivered');
    expect((await w.inbox.receive(second)).kind).toBe('delivered'); // evicts `first`: H[sender] = t - 20
    w.receipts.length = 0;
    const late = await w.inbox.receive(first); // the copy through a second relay
    expect(late).toMatchObject({ kind: 'dropped', error: { code: 'replay_horizon' } });
    expect(w.receipts).toEqual([]);
    expect((await w.inbox.receive(second)).kind).toBe('duplicate'); // a duplicate is receipted
    const retry = await w.pack(w.sender, msg('one'), w.clock.t, first.messageId); // re-signed with a fresh timestamp
    expect((await w.inbox.receive(retry)).kind).toBe('delivered');
    expect(w.receipts.map(([, r]) => [r.messageId, r.outcome])).toEqual([[second.messageId, 'delivered'], [first.messageId, 'delivered']]);
    await w.inbox.close();
  });
});

describe('A5: contact requests', () => {
  it('a public agent offline for hours still receives and accepts the request', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true });
    const bob = await agent(relay, clock);
    const a = alice.id.getACEId(), b = bob.id.getACEId();
    await bob.client.connect(a, { profile: TEXT });
    clock.advance(3 * 3600);
    await alice.client.pull();
    expect((await alice.client.requests()).map((r) => r.from)).toEqual([b]);
    clock.advance(3 * 3600);
    await alice.client.accept(b);
    await bob.client.pull();
    expect((await bob.client.admission.get(a))?.status).toBe('admitted');
    expect((await alice.client.admission.get(b))?.status).toBe('admitted');
  });

  it('an outgoing pending entry expires, and a late accepted is ignored', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open', listed: true });
    const bob = await agent(relay, clock);
    const a = alice.id.getACEId(), b = bob.id.getACEId();
    await bob.client.connect(a, { profile: TEXT });
    await alice.client.pull();
    clock.advance(CONTACT_REQUEST_TTL_SECONDS - 10);
    await alice.client.accept(b);
    clock.advance(OFFLINE_WINDOW_SECONDS - CONTACT_REQUEST_TTL_SECONDS + 20); // the requester's entry lives the relay's retention
    expect(await bob.client.admission.get(a)).toBeNull();
    await bob.client.pull();
    expect(await bob.client.admission.get(a)).toBeNull();
  });
});

describe('A6: usable at now', () => {
  it('a packet signed before notAfter but received after it is dropped stale_peer_binding, without a receipt', async () => {
    const clock = new Clock();
    const sender = await identity(clock);
    await sender.delegate({ now: clock.t, notAfter: clock.t + 100 });
    const w = await inboxWorld({ sender, world: clock });
    const packet = await w.pack(w.sender, msg('late'), clock.t + 50);
    clock.advance(200);
    expect(await w.inbox.receive(packet)).toMatchObject({ kind: 'dropped', error: { code: 'stale_peer_binding' } });
    expect(w.receipts).toEqual([]);
    await w.inbox.close();
  });
});

describe('I3: a permit counts as issued only after the packet carrying it was sent', () => {
  it('refreshPermits after a signing-key change is retried by the next maintain after a 503', async () => {
    const { clock, relay, alice, bob, a, b } = await pair();
    clock.advance(10);
    await bob.id.delegate({ now: clock.t });
    const seq = bob.id.getSigningSeq();
    relay.inject.push({ path: '/v1/send', status: 503, code: 'internal_error' });
    await bob.client.maintain(); // the permit push hits the 503
    expect((await bob.client.admission.get(a))?.issued?.seq).not.toBe(seq);
    await bob.client.maintain(); // retried
    expect((await bob.client.admission.get(a))?.issued?.seq).toBe(seq);
    await alice.client.pull();
    expect((await alice.client.admission.heldPermit(b))?.signature.seq).toBe(seq);
  });

  it('a receipt renewal is recorded only once the receipt was sent', async () => {
    const { clock, relay, alice, bob, a, b } = await pair();
    clock.advance(16 * 86400); // the permit alice issued bob has less than PERMIT_RENEWAL_SECONDS left
    await alice.client.maintain();
    await bob.client.maintain();
    const before = (await alice.client.admission.get(b))!.issued!;
    await bob.client.send(a, TEXT, { message: 'hi' });
    relay.inject.push({ path: '/v1/send', status: 503, code: 'internal_error' });
    expect((await alice.client.pull()).map((o) => o.kind)).toEqual(['deferred']); // the receipt failed
    expect((await alice.client.admission.get(b))!.issued).toEqual(before);
    expect((await alice.client.pull()).map((o) => o.kind)).toEqual(['duplicate']);
    expect((await alice.client.admission.get(b))!.issued!.expiresAt).toBeGreaterThan(before.expiresAt);
    await bob.client.pull();
    expect((await bob.client.admission.heldPermit(a))!.expiresAt).toBeGreaterThan(before.expiresAt);
  });
});

describe('I4: block is local-first', () => {
  it('while the relay is down the block holds locally, drops the peer, and maintain syncs it', async () => {
    const { relay, alice, bob, a, b } = await pair();
    relay.inject.push({ path: '/v1/blocks', status: 503, code: 'internal_error' });
    await alice.client.block(b);
    expect(await alice.client.admission.get(b)).toMatchObject({ status: 'blocked', unsyncedRevision: 1 });
    expect(relay.blocks.get(`${a}|${b}`)).toBeUndefined();
    await bob.client.send(a, TEXT, { message: 'blocked?' });
    expect(await alice.client.pull()).toMatchObject([{ kind: 'dropped', error: { code: 'not_permitted' } }]);
    await alice.client.maintain();
    expect(relay.blocks.get(`${a}|${b}`)?.blocked).toBe(true);
    expect((await alice.client.admission.get(b))?.unsyncedRevision).toBeUndefined();
  });

  it('unblock stays relay-first: a relay failure leaves the block in place', async () => {
    const { relay, alice, b } = await pair();
    await alice.client.block(b);
    relay.inject.push({ path: '/v1/blocks', status: 503, code: 'internal_error' });
    await expect(alice.client.unblock(b)).rejects.toMatchObject({ code: 'relay_unavailable' });
    expect((await alice.client.admission.get(b))?.status).toBe('blocked');
    await alice.client.unblock(b);
    expect(await alice.client.admission.get(b)).toBeNull();
    await alice.client.block(b); // a later block needs a higher revision than the one the relay kept
    expect(relay.blocks.get(`${alice.id.getACEId()}|${b}`)?.blocked).toBe(true);
  });
});

describe('A12: the NetworkClient surface', () => {
  it('publish registers on demand, also after a signing-key change', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock);
    clock.advance(10);
    await alice.id.delegate({ now: clock.t });
    await alice.client.publish({ force: true });
    expect(relay.kels.get(alice.id.getACEId())?.signing?.seq).toBe(alice.id.getSigningSeq());
    expect(relay.descriptors.get(alice.id.getACEId())?.kel).toEqual(alice.id.getKel());
    expect('register' in alice.client).toBe(false);
    expect('refreshPermits' in alice.client).toBe(false);
    expect('now' in alice.client).toBe(false);
  });

  it('open builds the store, message log and commerce threads; onReceipt sees the settled entry', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const seen: Array<[string, ReceiptBody, OutboxEntry | null]> = [];
    const alice = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: [TEXT], profiles: ['text', 'commerce'] });
    const bob = await agent(relay, clock, { onReceipt: (from: string, body: ReceiptBody, entry: OutboxEntry | null) => { seen.push([from, body, entry]); } });
    expect(alice.client.threads).not.toBeNull();
    expect(bob.client.threads).toBeNull();
    const a = alice.id.getACEId();
    await bob.client.connect(a, { profile: TEXT });
    await alice.client.pull();
    await bob.client.pull();
    const sent = await bob.client.send(a, TEXT, { message: 'hi' });
    await alice.client.pull();
    expect((await alice.client.messages!.list()).map((m) => m.body)).toEqual([{ message: 'hi' }]);
    await bob.client.pull();
    expect(seen.map(([from, body, entry]) => [from, body.outcome, entry?.messageId, entry?.status])).toEqual([[a, 'delivered', sent.messageId, 'delivered']]);
  });

  it('maintain keeps a settled entry visible for the offline window; prune then deletes it', async () => {
    const { clock, alice, bob, a } = await pair();
    const sent = await bob.client.send(a, TEXT, { message: 'hi' });
    await alice.client.pull();
    await bob.client.pull();
    const t = clock.t;
    clock.advance(60);
    await bob.client.maintain();
    expect((await bob.client.outbox.get(sent.messageId))?.status).toBe('delivered');
    clock.t = t + OFFLINE_WINDOW_SECONDS;
    expect(await bob.client.outbox.prune()).toBe(1);
    expect(await bob.client.outbox.get(sent.messageId)).toBeNull();
  });

  it('the default foreign relay inherits the clock and the loopback policy', async () => {
    const clock = new Clock();
    const home = new FakeRelay(clock.now, 'http://127.0.0.1:1'), other = new FakeRelay(clock.now, 'http://127.0.0.1:2');
    const bob = await agent(other, clock, { allowLoopbackRelays: true, contact: 'open', listed: true });
    const alice = await NetworkClient.open({
      identity: await identity(clock), store: new MemoryStore(), relay: home.client(), allowLoopbackRelays: true, clock: clock.now, receive: false,
    });
    const b = bob.id.getACEId();
    await alice.importAgent(await bob.client.publish());
    vi.stubGlobal('fetch', other.fetch); // the default factory uses the global fetch for a loopback development relay
    try {
      // verified at the client's (test) clock, with loopback routes allowed: neither holds without inheriting them
      expect((await alice.agent(b, { refresh: true })).descriptor.aceId).toBe(b);
    } finally {
      vi.unstubAllGlobals();
    }
    await alice.close();
  });
});

describe('I9: receive pipeline', () => {
  it('step 3 without a refresh hook continues as a contact candidate', async () => {
    const contacts: unknown[] = [];
    const w = await inboxWorld({ refreshPeer: undefined, onContact: (e) => { contacts.push(e); } });
    w.clock.advance(10);
    await w.sender.delegate({ now: w.clock.t });
    const source = await createDescriptor(w.sender, { relays: ['https://relay.test'], prekey: w.prekey, profiles: [], now: w.clock.t });
    const permit = await createPermit(w.sender, w.me.getACEId(), { now: w.clock.t });
    const content = contactContent({ kind: 'request', profile: TEXT, note: '', source, permit });
    expect(content.schemaDigest).toBe(CONTACT_SCHEMA_DIGEST);
    const out = await w.inbox.receive(await w.pack(w.sender, content));
    expect(out.kind).toBe('contact');
    expect(contacts).toHaveLength(1);
    expect(CONTACT_TYPE).toBe(content.type);
    await w.inbox.close();
  });

  it('a corrupt journal entry is storage_failed, never read as done', async () => {
    const w = await inboxWorld();
    expect((await w.inbox.receive(await w.pack(w.sender, msg('x')))).kind).toBe('delivered');
    const [key] = await w.store.list('inbox/journal/');
    await w.inbox.close();
    await w.store.write(key, canonicalStateBytes({ status: 'done' }));
    await expect(Inbox.open(w.options)).rejects.toMatchObject({ code: 'storage_failed' });
  });

  it('a missing seen store beside existing journal entries is storage_failed, not a new store', async () => {
    const w = await inboxWorld();
    expect((await w.inbox.receive(await w.pack(w.sender, msg('x')))).kind).toBe('delivered');
    const [key] = await w.store.list('inbox/journal/');
    const journal = (await w.store.read(key))!;
    await w.inbox.close(); // as after a crash before the next snapshot: the journal entry is still there
    await w.store.write(key, journal);
    await w.store.delete('inbox/replay.json');
    await expect(Inbox.open(w.options)).rejects.toMatchObject({ code: 'storage_failed' });
  });
});

describe('relay helpers', () => {
  it('parseIp, networkKey (/24, /56, IPv4-mapped as IPv4) and isBlockedAddress', () => {
    expect(parseIp('203.0.113.7')).toEqual({ family: 4, bytes: new Uint8Array([203, 0, 113, 7]) });
    expect(parseIp('::ffff:203.0.113.7')).toEqual({ family: 4, bytes: new Uint8Array([203, 0, 113, 7]) });
    expect(parseIp('2001:db8::1')?.family).toBe(6);
    expect(parseIp('not an ip')).toBeNull();
    expect(parseIp('1.2.3.4%eth0')).toBeNull();
    expect(networkKey('203.0.113.7')).toBe('203.0.113.0/24');
    expect(networkKey('::ffff:203.0.113.7')).toBe('203.0.113.0/24');
    expect(networkKey('::ffff:cb00:7107')).toBe('203.0.113.0/24');
    expect(networkKey('2001:db8:1234:56ff:1::1')).toBe('2001:db8:1234:5600::/56');
    expect(networkKey('2001:db8:1234:5601::9')).toBe(networkKey('2001:db8:1234:56aa::1'));
    expect(() => networkKey('nope')).toThrow();
    expect(isBlockedAddress('127.0.0.1')).toBe(true);
    expect(isBlockedAddress('::ffff:8.8.8.8')).toBe(false);
  });
});

describe('P2: deleted surface', () => {
  it('no webhook, ml-dsa-87, legacy signing or dead exports remain', () => {
    const names = Object.keys(sdk);
    for (const gone of [
      'signWebhookNotification', 'verifyWebhookNotification', 'isWebhookSecret', 'createNetworkClient', 'openPacket', 'buildSignBody',
      'retryDelay', 'matchesFilter', 'profileDescriptor', 'isErrorCode', 'SIGNING_SCHEMES', 'isSigningScheme', 'MAX_PAYLOAD_BYTES',
      'CONTACT_WINDOW_SECONDS', 'AUTH_REPLAY_SECONDS', 'DESCRIPTOR_MAX_LIFETIME', 'PERMIT_RENEW_BEFORE', 'MAX_CONTACT_NOTE_BYTES',
      'relayAuthPayload', 'STRANGER_ALLOWANCE_ENTRIES', 'DEFAULT_DIRECTORY_LIMIT', 'PACKET_VERSION',
      // internals no host imports (fix round 1)
      'checkStrangerSource', 'eventBytes', 'computeACEId', 'checkUsable', 'signOperational', 'parseSSE', 'encodePrivateContent',
      'decodePrivateContent', 'ReplayDetector', 'categoryOf', 'prekeyId', 'decodePrekey', 'MemoryPrekeyVault', 'isCaip19',
      'validateCommerceExt', 'decideCommerce', 'checkCommerceBody', 'checkContactBody', 'isUsable', 'createInception',
      'createRotation', 'createDelegation', 'isCaip10', 'isStreamId', 'validateNetworkRelay', 'verifyInvitation',
    ]) expect(names, gone).not.toContain(gone);
    expect(names).toEqual(expect.arrayContaining(['signingMessage', 'verifyAuthHeaders', 'verifyRegistrationRequest', 'parseIp', 'networkKey', 'STRANGER_ALLOWANCE']));
  });
});

describe('fix round 1', () => {
  /** Alice's home relay through a fetch that logs every block request and can hold the next one matching `hold`. */
  async function gatedBlocks() {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const log: Array<{ blocked: boolean; revision: number; status: number; error?: string }> = [];
    let hold: { when: (body: { blocked: boolean }) => boolean; held: Promise<void>; reached: () => void } | null = null;
    /** Hold the next block request matching `when` until `release()`; `atGate` resolves once it is held. */
    const arm = (when: (body: { blocked: boolean }) => boolean) => {
      let release!: () => void, reached!: () => void;
      const held = new Promise<void>((r) => { release = r; });
      const atGate = new Promise<void>((r) => { reached = r; });
      hold = { when, held, reached };
      return { atGate: () => atGate, release };
    };
    const fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      if (new URL(String(input)).pathname !== '/v1/blocks') return relay.fetch(input, init);
      const body = JSON.parse(String(init?.body));
      const h = hold;
      if (h !== null && h.when(body)) {
        hold = null;
        h.reached();
        await h.held;
      }
      const res = await relay.fetch(input, init);
      const error = res.status === 200 ? undefined : (await res.clone().json()).error;
      log.push({ blocked: body.blocked, revision: body.revision, status: res.status, ...(error ? { error } : {}) });
      return res;
    };
    const alice = await agent(relay, clock, { relay: new RelayClient(relay.baseUrl, { fetch, clock: clock.now }) });
    const bob = await agent(relay, clock);
    return { relay, alice, a: alice.id.getACEId(), b: bob.id.getACEId(), log, arm };
  }

  it('a late block retry (revision 1) sent after an unblock (revision 2) is refused stale_revision and leaves the peer unblocked', async () => {
    const { relay, alice, a, b, log, arm } = await gatedBlocks();
    relay.inject.push({ path: '/v1/blocks', status: 503, code: 'internal_error' });
    await alice.client.block(b); // the relay is down: revision 1 stays unsynced
    expect(await alice.client.admission.get(b)).toMatchObject({ status: 'blocked', unsyncedRevision: 1 });
    const g = arm((body) => body.blocked === true);
    const upkeep = alice.client.maintain(); // the block re-sync is held in flight
    await g.atGate();
    await alice.client.unblock(b); // relay first, revision 2
    g.release();
    await upkeep;
    expect(log.slice(1)).toEqual([
      { blocked: false, revision: 2, status: 200 },
      { blocked: true, revision: 1, status: 409, error: 'stale_revision' },
    ]);
    expect(await alice.client.admission.get(b)).toBeNull(); // no unsyncedRevision left behind
    expect(relay.blocks.get(`${a}|${b}`)).toEqual({ blocked: false, revision: 2 });
    await alice.client.maintain();
    expect(log).toHaveLength(3);
  });

  it('a block during an in-flight unblock keeps its record, and maintain registers it after the unblock', async () => {
    const { relay, alice, a, b, arm } = await gatedBlocks();
    await alice.client.block(b); // revision 1, synced
    const g = arm((body) => body.blocked === false);
    const unblocking = alice.client.unblock(b); // revision 2, held in flight
    await g.atGate();
    relay.inject.push({ path: '/v1/blocks', status: 503, code: 'internal_error' });
    await alice.client.block(b); // revision 3, relay down: unsynced
    g.release();
    await unblocking;
    expect(await alice.client.admission.get(b)).toMatchObject({ status: 'blocked', unsyncedRevision: 3 }); // not wiped
    expect(relay.blocks.get(`${a}|${b}`)).toEqual({ blocked: false, revision: 2 });
    await alice.client.maintain();
    expect(relay.blocks.get(`${a}|${b}`)).toEqual({ blocked: true, revision: 3 });
    expect((await alice.client.admission.get(b))?.unsyncedRevision).toBeUndefined();
  });

  it('maintain runs every step even when an earlier one fails, then reports the first failure', async () => {
    const { clock, relay, alice, bob, a } = await pair();
    relay.inject.push({ path: '/v1/send', status: 503, code: 'internal_error' });
    const sent = await bob.client.send(a, TEXT, { message: 'hi' });
    expect(sent.status).toBe('pending');
    clock.advance(86_400); // descriptors need republishing
    await alice.client.maintain();
    relay.inject.push({ path: '/v1/descriptor', status: 503, code: 'internal_error' });
    await expect(bob.client.maintain()).rejects.toMatchObject({ code: 'relay_unavailable' }); // publish failed ...
    expect((await bob.client.outbox.get(sent.messageId))!.attempts).toBe(2); // ... and flush still ran
    expect((await alice.client.pull()).map((o) => o.kind)).toEqual(['delivered']);
  });

  it('auth against a registered KEL without a signing delegation is stale_peer_binding, before the seq comparison', async () => {
    const id = await identity();
    const h = await createAuthHeaders(id, { action: 'unregister' }, NOW, { audience: RELAY });
    const st = { ...verifyKel(id.getKel(), NOW), signing: null };
    expect(() => verifyAuthHeaders(parseAuthHeaders({ ...h, 'X-ACE-Seq': '7' }), { action: 'unregister' }, st, { audience: RELAY, clock: () => NOW }))
      .toThrow(expect.objectContaining({ code: 'stale_peer_binding' }));
  });

  it('the client advertises only its home relay (the multi-relay option is gone)', async () => {
    const clock = new Clock();
    const relay = new FakeRelay(clock.now);
    const home = relay.client().baseUrl;
    const alice = await agent(relay, clock, { relays: [home, 'https://other.test'] } as Partial<sdk.NetworkClientOptions>);
    expect((await alice.client.publish()).descriptor.relays).toEqual([home]);
  });
});
