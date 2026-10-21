// Security review 2026-10-21 (docs/review-2026-10-21-security.md): one regression per decision.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  ACEError, AdmissionBook, FileStore, Inbox, MemoryStore, OFFLINE_WINDOW_SECONDS, ReplayDetector, SoftwareIdentity, SoftwareKey, StorePrekeyVault,
  canonicalStateBytes, contactContent, createCardRecord, createDelegation, createDelegationCredential, createDescriptor, createPermit, createRotation, generateSoftwareKey, keyDigest,
  receiptContent, relayErrorFor, validateNetworkRelay, verifiedCacheUsage, verifyCardBundle, verifyKel, verifyPublishedAgent,
  type ACEStore,
} from './sdk.js';
import { Clock, FakeRelay, NOW, RELAY, agent, stateOf } from './helpers.js';
import { inboxWorld, msg } from './helpers2.js';

const code = (c: string) => expect.objectContaining({ code: c });
const rootOf = (id: SoftwareIdentity) => new SoftwareKey(Buffer.from(id.exportPrivateKey().rootSeed, 'base64'));

describe('C1: relay URL host grammar (02 § Relay URLs)', () => {
  it.each(['https://[::1]', 'https://a..b', 'https://-a.example', 'https://a-.example', 'https://example.com.'])('%s is not a canonical relay URL', (url) => {
    expect(() => validateNetworkRelay(url)).toThrow(code('invalid_authorization'));
  });

  it('hosts in the ACE HTTPS URL grammar stay valid', () => {
    for (const url of ['https://relay.test', 'https://a-b.example:8443/ace', 'https://127.0.0.1']) expect(validateNetworkRelay(url)).toBe(url);
    expect(validateNetworkRelay('http://[::1]:8080', { allowLoopbackRelays: true })).toBe('http://[::1]:8080');
  });
});

describe('C2: receipts pass step 9 and commit the seen entry', () => {
  it('a replayed receipt is a duplicate, handed over once', async () => {
    const onReceipt = vi.fn();
    const w = await inboxWorld({ onReceipt });
    const packet = await w.pack(w.sender, receiptContent({ messageId: crypto.randomUUID(), outcome: 'delivered' }));
    expect((await w.inbox.receive(packet)).kind).toBe('receipt');
    expect(await w.inbox.receive(packet)).toMatchObject({ kind: 'duplicate', from: w.sender.getACEId() });
    expect(onReceipt).toHaveBeenCalledTimes(1);
    expect(w.receipts).toEqual([]);
  });

  /** The process died after the hand-over, before any snapshot: a restart is a new view of the same data, unlocked. */
  const restart = (data: MemoryStore): ACEStore => {
    const locks = new MemoryStore();
    return { read: (k) => data.read(k), write: (k, v) => data.write(k, v), delete: (k) => data.delete(k), list: (p) => data.list(p), lock: (n, o) => locks.lock(n, o) };
  };

  it('a receipt\'s seen entry survives a crash before the snapshot (journal, as for messages)', async () => {
    const onReceipt = vi.fn();
    const w = await inboxWorld({ onReceipt });
    const packet = await w.pack(w.sender, receiptContent({ messageId: crypto.randomUUID(), outcome: 'delivered' }));
    expect((await w.inbox.receive(packet)).kind).toBe('receipt');
    const reopened = await Inbox.open({ ...w.options, store: restart(w.store) });
    expect(await reopened.receive(packet)).toMatchObject({ kind: 'duplicate', from: w.sender.getACEId() });
    expect(onReceipt).toHaveBeenCalledTimes(1);
  });

  it('a contact\'s seen entry survives a crash before the snapshot', async () => {
    const onContact = vi.fn();
    const w = await inboxWorld({ refreshPeer: undefined, onContact });
    w.clock.advance(10);
    await w.sender.delegate({ now: w.clock.t });
    const source = await createDescriptor(w.sender, { relays: ['https://relay.test'], prekey: w.prekey, profiles: [], now: w.clock.t });
    const permit = await createPermit(w.sender, w.me.getACEId(), { now: w.clock.t });
    const packet = await w.pack(w.sender, contactContent({ kind: 'request', profile: 'ace:text:1', note: '', source, permit }));
    expect((await w.inbox.receive(packet)).kind).toBe('contact');
    const reopened = await Inbox.open({ ...w.options, store: restart(w.store) });
    expect(await reopened.receive(packet)).toMatchObject({ kind: 'dropped', error: { code: 'invalid_packet' } });
    expect(onContact).toHaveBeenCalledTimes(1);
  });
});

describe('C3: a delivered packet whose receipt cannot be sent', () => {
  it('is acknowledged after the fetch budget without a quarantine record', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const w = await inboxWorld({ world: clock, sendReceipt: async () => { throw new ACEError('relay_unavailable', 'down'); } });
    const rc = relay.client();
    await rc.register(w.me);
    relay.queues.set(w.me.getACEId(), [{ streamId: '1-0', packet: await w.pack(w.sender, msg('once')), raw: '' }]);
    for (let i = 0; i < 2; i++) expect((await w.inbox.pull(rc))[0].kind).toBe('deferred');
    expect(relay.pending(w.me.getACEId())).toBe(1);
    expect((await w.inbox.pull(rc))[0].kind).toBe('duplicate');
    expect(relay.pending(w.me.getACEId())).toBe(0);
    expect(w.delivered).toHaveLength(1);
    expect(await w.store.list('inbox/quarantine/')).toEqual([]);
    expect(await w.store.list('inbox/attempts/')).toEqual([]);
  });
});

describe('C4: relay error strings', () => {
  it('lose their control characters before they enter the error', () => {
    const e = relayErrorFor(400, null, JSON.stringify({ error: 'bad\u0007code\n', message: 'line\r\nFORGED\u009b\u0000 entry' }));
    expect(e.relayCode).toBe('badcode');
    expect(e.message).toBe('relay_rejected: HTTP 400 badcode: lineFORGED entry');
    expect(e.message).not.toMatch(/\p{Cc}/u);
  });
});

describe('C5: ReplayDetector defaults (06 § Deduplication)', () => {
  it('a new detector starts at H = F - 1 and commits with floor F', () => {
    const F = NOW - 2 * OFFLINE_WINDOW_SECONDS;
    const d = new ReplayDetector({ clock: () => NOW });
    expect(d.exportState().horizon).toBe(F - 1);
    expect(d.covers('s', F - 1)).toBe(true);
    const id = crypto.randomUUID();
    expect(d.commit(id, 's', F)).toBe(true);
    expect(d.commit(crypto.randomUUID(), 's', NOW - 3600)).toBe(true);
    expect(d.hasSeen(id, 's')).toBe(true); // at the floor, not below it
  });
});

describe('C6: signer refusals (01 § Rotation and recovery)', () => {
  it('a next root committing to a revealed signing key is refused', async () => {
    const id = await SoftwareIdentity.generate({ now: NOW });
    const signing = keyDigest('ml-dsa-65', id.getSigningPublicKey());
    await expect(id.rotate({ now: NOW, nextRootDigest: signing })).rejects.toThrow(code('invalid_argument'));
    expect(id.getKel()).toHaveLength(2);
  });

  it('a dlg key equal to the current root is refused', async () => {
    const id = await SoftwareIdentity.generate({ now: NOW });
    const root = rootOf(id);
    await expect(createDelegation(stateOf(id), root, root.publicKey(), NOW)).rejects.toThrow(code('invalid_argument'));
  });

  it('a dlg key committed as the next root is refused', async () => {
    const next = generateSoftwareKey();
    const id = await SoftwareIdentity.generate({ now: NOW, nextRootDigest: keyDigest(next.scheme, next.publicKey()) });
    await expect(createDelegation(stateOf(id), rootOf(id), next.publicKey(), NOW)).rejects.toThrow(code('invalid_argument'));
  });
});

describe('C7: shape before KEL work (04 § Verification, § Card record)', () => {
  it('a malformed signature or delegation entry is invalid_authorization even when the KEL is invalid too', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { handle: 'alice' });
    const published = await alice.client.publish();
    const d = published.descriptor, short = { ...d.signature, value: 'AAAA' };
    expect(() => verifyPublishedAgent({ kel: [], descriptor: { ...d, signature: short } }, clock.t)).toThrow(code('invalid_authorization'));
    expect(() => verifyPublishedAgent({ kel: [], descriptor: { ...d, delegations: [{ kel: [] }] } }, clock.t)).toThrow(code('invalid_authorization'));
    const card = relay.cards.get(alice.id.getACEId())!;
    expect(() => verifyCardBundle({ kel: [], card: { ...card.card, signature: { ...card.card.signature, value: 'AAAA' } } }, clock.t))
      .toThrow(code('invalid_authorization'));
  });

  it('a delegation credential of the wrong shape is step 1 (invalid_authorization) even with kel = [] (py/swift parity)', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { handle: 'alice' }), dave = await agent(relay, clock, { handle: 'dave' });
    const credential = await createDelegationCredential(dave.id, alice.id.getACEId(), { now: clock.t });
    const d = (await alice.client.publish()).descriptor;
    const withEntry = (c: object) => ({ kel: [], descriptor: { ...d, delegations: [{ kel: [], credential: c }] } });
    const badIssuer = withEntry({ ...credential, issuer: 'x' });
    const shortSig = withEntry({ ...credential, signature: { ...credential.signature, value: 'AAAA' } });
    expect(() => verifyPublishedAgent(badIssuer, clock.t)).toThrow(code('invalid_authorization'));
    expect(() => verifyPublishedAgent(shortSig, clock.t)).toThrow(code('invalid_authorization'));
    // A well-formed entry with kel = [] still reaches step 2: the descriptor's own kel = [] is invalid_kel.
    expect(() => verifyPublishedAgent(withEntry(credential), clock.t)).toThrow(code('invalid_kel'));
  });
});

describe('C8: step 3 refresh rate', () => {
  it('a transient refresh failure counts: at most one attempt per sender per 30 s', async () => {
    const w = await inboxWorld();
    w.refreshPeer.mockRejectedValue(new ACEError('relay_unavailable', 'down'));
    await w.sender.delegate({ now: w.clock.t });
    expect((await w.inbox.receive(await w.pack(w.sender, msg('1')))).kind).toBe('deferred');
    w.clock.advance(10);
    expect((await w.inbox.receive(await w.pack(w.sender, msg('2')))).kind).toBe('deferred');
    expect(w.refreshPeer).toHaveBeenCalledTimes(1);
    w.clock.advance(21);
    await w.inbox.receive(await w.pack(w.sender, msg('3')));
    expect(w.refreshPeer).toHaveBeenCalledTimes(2);
  });
});

describe('C9: handle lookups report the pin\'s kelLive', () => {
  it('a relay-served descriptor that does not confirm the pin is reported as not live', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { handle: 'alice' }), bob = await agent(relay, clock);
    const adopt = bob.client.peers.adopt.bind(bob.client.peers);
    vi.spyOn(bob.client.peers, 'adopt').mockImplementation((events, o) => adopt(events, { ...o, live: false }));
    try {
      expect((await bob.client.lookupWithCard('@alice@relay.test')).card?.kelLive).toBe(false);
      expect((await bob.client.lookupCard(alice.id.getACEId())).kelLive).toBe(false);
    } finally { await alice.client.close(); await bob.client.close(); }
  });
});

describe('C10: verified-KEL cache', () => {
  it('never caches an unusable log', async () => {
    const id = await SoftwareIdentity.generate({ now: NOW });
    const before = verifiedCacheUsage();
    verifyKel(id.getKel().slice(0, 1), NOW); // icp only: no signing delegation
    expect(verifiedCacheUsage()).toEqual(before);
  });

  it('holds at most 16 MiB of logs', async () => {
    const id = await SoftwareIdentity.generate({ now: NOW });
    for (let i = 0; i < 90; i++) await id.delegate({ now: NOW });
    const kel = id.getKel();
    let total = 0;
    for (let n = 2; n <= kel.length; n++) {
      verifyKel(kel.slice(0, n), NOW);
      total += kel.slice(0, n).reduce((sum, ev) => sum + canonicalStateBytes(ev).length, 0);
    }
    expect(total).toBeGreaterThan(16 * 1024 * 1024);
    expect(verifiedCacheUsage().bytes).toBeLessThanOrEqual(16 * 1024 * 1024);
  }, 60_000); // 90 root signatures
});

describe('C11: list prefixes are validated like keys', () => {
  const stores = [['MemoryStore', () => new MemoryStore()], ['FileStore', () => new FileStore(join(mkdtempSync(join(tmpdir(), 'ace-')), 's'))]] as const;
  it.each(stores)('%s', async (_, make) => {
    const store = make();
    await store.write('inbox/journal/a.json', new Uint8Array([1]));
    for (const bad of ['../', 'inbox/../', '/inbox', 'inbox//', 'Inbox/', 'inbox/journal/.x']) {
      await expect(store.list(bad)).rejects.toThrow(code('invalid_argument'));
    }
    expect(await store.list('inbox/journal/')).toEqual(['inbox/journal/a.json']);
    expect(await store.list('inbox/jo')).toEqual(['inbox/journal/a.json']);
    expect(await store.list('')).toEqual(['inbox/journal/a.json']);
  });
});

describe('sdk-ts: admission request lock', () => {
  it('saveRequest takes only the admission lock', async () => {
    const store = new MemoryStore(), book = new AdmissionBook(store, { clock: () => NOW });
    const lock = vi.spyOn(store, 'lock');
    const bob = await SoftwareIdentity.generate({ now: NOW });
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const a = await agent(relay, clock);
    try {
      await book.saveRequest({ from: a.id.getACEId(), messageId: crypto.randomUUID(), profile: 'ace:text:1', note: '', source: await a.client.publish(),
        permit: await createPermit(a.id, bob.getACEId(), { now: clock.t }), receivedAt: NOW });
      expect(lock.mock.calls.map(([name]) => name)).toEqual(['admission']);
      expect(await book.requests()).toHaveLength(1);
    } finally { await a.client.close(); }
  });
});

describe('SP12: a document is signed no earlier than its dlg (04)', () => {
  async function prekey() {
    const pk = await new StorePrekeyVault(new MemoryStore(), { clock: () => NOW }).rotate(NOW);
    return { id: pk.id, publicKey: pk.publicKey };
  }

  it('a fork recovery re-delegating the same key at the same seq does not revive the old branch\'s documents', async () => {
    const next = generateSoftwareKey(), key = generateSoftwareKey();
    const id = await SoftwareIdentity.generate({ now: NOW, nextRootDigest: keyDigest(next.scheme, next.publicKey()) });
    const [icp, dlg1] = id.getKel(), root = rootOf(id);
    // The abandoned branch: icp, dlg(1), dlg(2, key); a descriptor and a card record signed under seq 2.
    const old = [icp, dlg1, await createDelegation(verifyKel([icp, dlg1], NOW), root, key.publicKey(), NOW + 10)];
    const oldId = SoftwareIdentity.fromExport({ rootSeed: id.exportPrivateKey().rootSeed, signingSeed: Buffer.from(key.seed).toString('base64'), kel: old }, NOW + 10);
    const descriptor = (await createDescriptor(oldId, { relays: [RELAY], prekey: await prekey(), profiles: [], now: NOW + 20 })).descriptor;
    const card = (await createCardRecord(oldId, { home: RELAY, contact: 'closed', listed: false, now: NOW + 20 })).card;
    // The recovery: icp, rot(1) by the next root, dlg(2) of the same key, later than both documents.
    const rot = await createRotation(verifyKel([icp], NOW), next, keyDigest(generateSoftwareKey().scheme, generateSoftwareKey().publicKey()), NOW + 100);
    const recovered = [icp, rot, await createDelegation(verifyKel([icp, rot], NOW + 100), next, key.publicKey(), NOW + 100)];
    expect(verifyKel(recovered, NOW + 100).signing?.seq).toBe(descriptor.signature.seq);
    expect(() => verifyPublishedAgent({ kel: recovered, descriptor }, NOW + 200)).toThrow(code('stale_peer_binding'));
    expect(() => verifyCardBundle({ kel: recovered, card }, NOW + 200)).toThrow(code('stale_peer_binding'));
  });

  it('a clock behind the last KEL event still signs valid documents, dated at that event', async () => {
    const id = await SoftwareIdentity.generate({ now: NOW });
    await id.delegate({ now: NOW + 100 });
    const agent = await createDescriptor(id, { relays: [RELAY], prekey: await prekey(), profiles: [], now: NOW });
    expect(agent.descriptor.issuedAt).toBe(NOW + 100);
    expect(verifyPublishedAgent(agent, NOW + 100).state.aceId).toBe(id.getACEId());
    const bundle = await createCardRecord(id, { home: RELAY, contact: 'closed', listed: false, now: NOW });
    expect(bundle.card.issuedAt).toBe(NOW + 100);
    expect(verifyCardBundle(bundle, NOW + 100).aceId).toBe(id.getACEId());
  });
});
