// Admission races: a local block applied at any await of a concurrent admission path wins.
import { describe, expect, it, vi } from 'vitest';
import { NetworkClient, contactContent, createPacket, createPermit } from './sdk.js';
import { Clock, FakeRelay, NOW, agent, withPrekey } from './helpers.js';

// Insert a local block at the await between a network operation's admission read and its locked update.
async function blockBeforeNextUpdate(client: NetworkClient, peer: string) {
  const update = client.admission.update.bind(client.admission);
  vi.spyOn(client.admission, 'update').mockImplementationOnce(async (...args) => {
    await client.block(peer);
    return update(...args);
  });
}

describe('a local block wins every admission race', () => {
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
});
