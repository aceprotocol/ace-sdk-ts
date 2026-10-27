import { describe, expect, it, vi } from 'vitest';
import { NetworkClient, ReplayDetector, canonicalStateBytes, contactContent, createCardRecord, createPacket, createPermit, sha256Hex } from './sdk.js';
import { Clock, FakeRelay, NOW, RELAY, agent } from './helpers.js';
import { withPrekey } from './helpers2.js';

// Insert a local block at the await between a network operation's admission read and its locked update.
async function blockBeforeNextUpdate(client: NetworkClient, peer: string) {
  const update = client.admission.update.bind(client.admission);
  vi.spyOn(client.admission, 'update').mockImplementationOnce(async (...args) => {
    await client.block(peer);
    return update(...args);
  });
}

describe('security review regressions', () => {
  it('a contact request cannot recreate its held request after a concurrent block', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock), bob = await agent(relay, clock, { contact: 'open' });
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    try {
      const packet = await createPacket({ identity: alice.id, to: B, timestamp: clock.t,
        prekey: (await bob.client.publish()).descriptor.prekey,
        content: withPrekey(contactContent({ kind: 'request', profile: 'ace:text:1', note: '', source: await alice.client.publish(),
          permit: await createPermit(alice.id, B, { now: clock.t }) })) });
      const save = bob.client.admission.saveRequest.bind(bob.client.admission);
      vi.spyOn(bob.client.admission, 'saveRequest').mockImplementationOnce(async (request) => {
        await bob.client.block(A);
        await save(request);
      });
      await bob.client.inbox.receive(packet);
      expect((await bob.client.admission.get(A))?.status).toBe('blocked');
      expect(await bob.client.requests()).toEqual([]);
    } finally { await alice.client.close(); await bob.client.close(); }
  });

  it('a block waits for an in-flight request write and then removes that request', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock), bob = await agent(relay, clock);
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    let resume!: () => void, entered!: () => void;
    const barrier = new Promise<void>((resolve) => { resume = resolve; });
    const paused = new Promise<void>((resolve) => { entered = resolve; });
    try {
      const list = bob.store.list.bind(bob.store);
      vi.spyOn(bob.store, 'list').mockImplementationOnce(async (prefix) => {
        entered();
        await barrier;
        return list(prefix);
      });
      const saving = bob.client.admission.saveRequest({ from: A, messageId: crypto.randomUUID(), profile: 'ace:text:1', note: '',
        source: await alice.client.publish(), permit: await createPermit(alice.id, B, { now: clock.t }), receivedAt: clock.t });
      await paused;
      const blocking = bob.client.block(A);
      // Let the block reach the shared lock while saveRequest is paused inside its storage operation.
      await new Promise<void>((resolve) => { setImmediate(resolve); });
      resume();
      await Promise.all([saving, blocking]);
      expect((await bob.client.admission.get(A))?.status).toBe('blocked');
      expect(await bob.client.requests()).toEqual([]);
    } finally { resume(); await alice.client.close(); await bob.client.close(); }
  });

  it.each(['accepted', 'rejected'] as const)('a remote %s reply cannot replace a concurrent local block', async (kind) => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open' }), bob = await agent(relay, clock);
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    try {
      await bob.client.connect(A, { profile: 'ace:text:1' });
      const source = await alice.client.publish();
      const permit = kind === 'accepted' ? await createPermit(alice.id, B, { now: clock.t }) : undefined;
      const packet = await createPacket({ identity: alice.id, to: B, timestamp: clock.t,
        prekey: (await bob.client.publish()).descriptor.prekey,
        content: withPrekey(contactContent({ kind, profile: 'ace:text:1', note: '', source, ...(permit ? { permit } : {}) })) });
      await blockBeforeNextUpdate(bob.client, A);
      await bob.client.inbox.receive(packet);
      expect((await bob.client.admission.get(A))?.status).toBe('blocked');
      expect(await bob.client.admission.heldPermit(A)).toBeNull();
      expect(relay.blocks.get(`${B}|${A}`)?.blocked).toBe(true);
    } finally { await alice.client.close(); await bob.client.close(); }
  });

  it.each(['connect', 'invite'] as const)('%s cannot overwrite a block applied while it was preparing admission', async (action) => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { contact: 'open' }), bob = await agent(relay, clock);
    const A = alice.id.getACEId();
    try {
      await blockBeforeNextUpdate(bob.client, A);
      const result = action === 'connect' ? bob.client.connect(A, { profile: 'ace:text:1' }) : bob.client.createInvitation(A);
      await expect(result).rejects.toMatchObject({ code: 'not_permitted' });
      expect((await bob.client.admission.get(A))?.status).toBe('blocked');
    } finally { await alice.client.close(); await bob.client.close(); }
  });

  it('an invitation can clear its original block but cannot clear a newer block during the relay unblock', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock), bob = await agent(relay, clock);
    const A = alice.id.getACEId(), B = bob.id.getACEId();
    try {
      await bob.client.block(A);
      await bob.client.createInvitation(A);
      expect((await bob.client.admission.get(A))?.status).toBe('admitted');
      expect(relay.blocks.get(`${B}|${A}`)).toEqual({ blocked: false, revision: NOW + 1 });
      await bob.client.block(A);
      const setBlock = bob.client.relay.setBlock.bind(bob.client.relay);
      vi.spyOn(bob.client.relay, 'setBlock').mockImplementationOnce(async (...args) => {
        await setBlock(...args);
        await bob.client.block(A);
      });
      await expect(bob.client.createInvitation(A)).rejects.toMatchObject({ code: 'not_permitted' });
      expect((await bob.client.admission.get(A))?.status).toBe('blocked');
      expect(relay.blocks.get(`${B}|${A}`)).toEqual({ blocked: true, revision: NOW + 4 });
    } finally { await alice.client.close(); await bob.client.close(); }
  });

  it('preserves every home handle across migration, returning homes and restart', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { handle: 'alice' }), bob = await agent(relay, clock);
    const A = alice.id.getACEId(), key = `network/handles/${sha256Hex(A)}.json`, elsewhere = 'https://other.test';
    let reopened: NetworkClient | undefined;
    try {
      await bob.client.lookupCard(A);
      const initial = JSON.parse(new TextDecoder().decode((await bob.store.read(key))!));
      const { handles: _, ...legacy } = initial;
      await bob.store.write(key, canonicalStateBytes(legacy));
      clock.advance(1);
      relay.cards.set(A, await createCardRecord(alice.id, { home: elsewhere, handle: 'elsewhere', contact: 'closed', listed: false, now: clock.t }));
      await bob.client.lookupCard(A);
      expect(JSON.parse(new TextDecoder().decode((await bob.store.read(key))!)).handles).toEqual({ [RELAY]: 'alice', [elsewhere]: 'elsewhere' });
      await bob.client.close();
      reopened = await NetworkClient.open({ identity: bob.id, store: bob.store, relay: relay.client(), clock: clock.now });
      for (const handle of ['renamed', undefined]) {
        clock.advance(1);
        relay.cards.set(A, await createCardRecord(alice.id, { home: RELAY, ...(handle ? { handle } : {}), contact: 'closed', listed: false, now: clock.t }));
        await expect(reopened.lookupCard(A)).rejects.toMatchObject({ code: 'invalid_authorization' });
      }
      clock.advance(1);
      relay.cards.set(A, await createCardRecord(alice.id, { home: RELAY, handle: 'alice', contact: 'closed', listed: false, now: clock.t }));
      expect((await reopened.lookupCard(A)).record.handle).toBe('alice');
      const good = JSON.parse(new TextDecoder().decode((await bob.store.read(key))!));
      for (const handles of [{ [RELAY]: 'other' }, { [RELAY]: 'alice', [elsewhere]: 'Bad!' }, { [RELAY]: 'alice', 'file:///tmp': 'bad' },
        { [RELAY]: 'alice', [`${elsewhere}/path`]: 'bad' }]) {
        await bob.store.write(key, canonicalStateBytes({ ...good, handles }));
        await expect(reopened.lookupCard(A)).rejects.toMatchObject({ code: 'storage_failed' });
      }
    } finally { await alice.client.close(); await bob.client.close(); await reopened?.close(); }
  });

  it('rejects malformed legacy pins and a missing legacy handle that conflicts with the map', async () => {
    const clock = new Clock(), relay = new FakeRelay(clock.now);
    const alice = await agent(relay, clock, { handle: 'alice' }), bob = await agent(relay, clock);
    const A = alice.id.getACEId(), key = `network/handles/${sha256Hex(A)}.json`;
    try {
      await bob.client.lookupCard(A);
      const good = JSON.parse(new TextDecoder().decode((await bob.store.read(key))!));
      const { handles: _, ...legacy } = good;
      for (const pin of [{ ...legacy, issuedAt: -1 }, { ...legacy, digest: 'bad' }, { ...legacy, home: 'file:///tmp' },
        { ...legacy, home: `${RELAY}/path` }, { ...legacy, handle: 'Bad!' }, { ...legacy, handle: null },
        { home: good.home, issuedAt: good.issuedAt, digest: good.digest, handles: good.handles }]) {
        await bob.store.write(key, canonicalStateBytes(pin));
        await expect(bob.client.lookupCard(A)).rejects.toMatchObject({ code: 'storage_failed' });
      }
    } finally { await alice.client.close(); await bob.client.close(); }
  });

  it('bounds lazy replay heaps while preserving entries and horizon decisions', () => {
    const detector = new ReplayDetector({ capacity: 16, horizon: 0 });
    let reference = new ReplayDetector({ capacity: 16, horizon: 0 });
    const id = (n: number) => `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
    detector.commit(id(0), 'review-anchor', 1, 0);
    reference.commit(id(0), 'review-anchor', 1, 0);
    let largestHeap = 0;
    for (let n = 1; n <= 20_000; n++) {
      detector.commit(id(n), 'review-sender', n + 1, 0);
      reference.commit(id(n), 'review-sender', n + 1, 0);
      // Rebuilding from canonical state is an independent reference with no stale heap entries.
      reference = ReplayDetector.fromState(reference.exportState(), { capacity: 16 });
      largestHeap = Math.max(largestHeap, ...Object.values(detector.heapSizes));
    }
    expect(largestHeap).toBeLessThanOrEqual(64);
    expect(detector.exportState()).toEqual(reference.exportState());
    expect(detector.accepts(id(1), 'review-sender', 2)).toBe(false);
    expect(detector.hasSeen(id(0), 'review-anchor')).toBe(true);
  });

  it('bounds sender heaps when floor eviction leaves one live entry without exceeding its quota', () => {
    const detector = new ReplayDetector({ capacity: 32, horizon: 0 });
    let largestHeap = 0;
    for (let n = 1; n <= 20_000; n++) {
      detector.commit(`review-id-${n}`, 'sender', n, n);
      largestHeap = Math.max(largestHeap, ...Object.values(detector.heapSizes));
    }
    expect(largestHeap).toBeLessThanOrEqual(64);
    expect(detector.hasSeen('review-id-20000', 'sender')).toBe(true);
    expect(detector.exportState().entries).toHaveLength(1);
  });
});
