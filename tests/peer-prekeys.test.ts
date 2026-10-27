// Peer prekeys end to end (04 § Peer prekeys, 06 § Outbox, § Receipts, § Receive pipeline): every packet offers the
// receiver a peer prekey; a first-attempt application message goes to the key the peer offered, every retry, receipt
// and contact packet to the published prekey.
import {
  MemoryStore, NetworkClient, ACEError, canonicalStateBytes, createPacket, decodePacket, decryptPacket, prekeyId,
  prekeyPublicKey, toBase64, fromBase64, type PrivateContent, type Packet,
  checkUsable, checkXWingPublicKey, padPlaintext, packetHeader, packetSignPayload, sealPayload, signingMessage, type Prekey, type SoftwareIdentity,
} from './sdk.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { Clock, FakeRelay, agent, type TestAgent } from './helpers.js';
import { inboxWorld, msg } from './helpers2.js';
import { vi } from 'vitest';

const TEXT = 'ace:text:1';
const RECEIPT = 'ace:receipt:1';
const idOf = (t: TestAgent) => t.id.getACEId();

/** alice connects to bob (open, auto-accepting text): both admitted and pinned, nothing held (contacts hold nothing). */
async function pair() {
  const clock = new Clock(), relay = new FakeRelay(clock.now);
  const bob = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: [TEXT] });
  const alice = await agent(relay, clock);
  await alice.client.connect(idOf(bob), { profile: TEXT });
  await bob.client.pull();
  await alice.client.pull();
  expect((await alice.client.admission.get(idOf(bob)))?.status).toBe('admitted');
  expect((await bob.client.admission.get(idOf(alice)))?.status).toBe('admitted');
  return { clock, relay, alice, bob, a: idOf(alice), b: idOf(bob) };
}
type Pair = Awaited<ReturnType<typeof pair>>;

/** Packets the relay accepted since index `n`, from `from` to `to`. */
const since = (relay: FakeRelay, n: number, from: TestAgent, to: TestAgent): Packet[] =>
  relay.sent.slice(n).map((s) => decodePacket(s.packet)).filter((p) => p.from === idOf(from) && p.to === idOf(to));
/** A packet's private content, decrypted by its recipient (`prekey` included). */
const contentOf = (p: Packet, recipient: TestAgent): Promise<PrivateContent> => decryptPacket(p, recipient.client.vault);
/** The ID of the peer prekey a packet offers its recipient. */
const offeredBy = async (p: Packet, recipient: TestAgent) => prekeyId(fromBase64((await contentOf(p, recipient)).prekey!));
const published = async (t: TestAgent) => (await t.client.vault.current())!.id;
const pinOf = async (holder: TestAgent, peer: string) => (await holder.client.peers.get(peer))!.lastHash;

/** m1 alice→bob, its receipt, m2 alice→bob (to the key bob offered), its receipt. */
async function ratchet({ clock, relay, alice, bob, b }: Pair) {
  const start = relay.sent.length;
  const m1 = await alice.client.send(b, TEXT, { message: 'm1' });
  const [p1] = since(relay, start, alice, bob);
  expect(p1.encryption.prekey).toBe(await published(bob)); // alice holds nothing yet
  let n = relay.sent.length;
  expect(await bob.client.pull()).toMatchObject([{ kind: 'delivered' }]);
  const [r1] = since(relay, n, bob, alice);
  expect((await contentOf(r1, alice)).type).toBe(RECEIPT);
  expect(r1.encryption.prekey).toBe(await published(alice));
  const offered = await offeredBy(r1, alice);
  expect(offered).not.toBe(await published(bob));
  await alice.client.pull();
  expect((await alice.client.outbox.get(m1.messageId))!.status).toBe('delivered');
  expect((await alice.client.vault.held(b, await pinOf(alice, b), clock.t))?.id).toBe(offered);
  n = relay.sent.length;
  const m2 = await alice.client.send(b, TEXT, { message: 'm2' });
  const [p2] = since(relay, n, alice, bob);
  expect(p2.encryption.prekey).toBe(offered);
  expect(await bob.client.pull()).toMatchObject([{ kind: 'delivered' }]);
  await alice.client.pull();
  expect((await alice.client.outbox.get(m2.messageId))!.status).toBe('delivered');
  expect(bob.received.filter((m) => m.type === TEXT).map((m) => m.body.message)).toEqual(['m1', 'm2']);
  expect(bob.received.every((m) => !('prekey' in m))).toBe(true);
  return { start, offered };
}

describe('04 § Peer prekeys end to end', () => {
  it('ratchet ping-pong: the first attempt goes to the key the peer offered, which then opens for that peer only', async () => {
    const w = await pair();
    const { offered } = await ratchet(w);
    const { bob, a, clock } = w;
    expect(await bob.client.vault.open(offered, a)).not.toBeNull(); // in use
    expect(await bob.client.vault.open(offered, idOf(bob))).toBeNull();
    expect((await bob.client.vault.offer(a, clock.t)).id).not.toBe(offered); // a fresh offer
  });

  it('every receipt is encrypted to the recipient\'s published prekey', async () => {
    const w = await pair();
    const { start } = await ratchet(w);
    const { relay, alice, bob, a } = w;
    const reply = await bob.client.send(a, TEXT, { message: 'back' }); // bob holds alice's offered key now
    expect(since(relay, relay.sent.length - 1, bob, alice)[0].encryption.prekey).not.toBe(await published(alice));
    await alice.client.pull();
    await bob.client.pull();
    expect((await bob.client.outbox.get(reply.messageId))!.status).toBe('delivered');
    let receipts = 0;
    for (const [from, to] of [[alice, bob], [bob, alice]] as const) {
      for (const p of since(relay, start, from, to)) {
        const c = await contentOf(p, to);
        expect(c.prekey).toBeDefined(); // every packet offers a key
        if (c.type !== RECEIPT) continue;
        receipts++;
        expect(p.encryption.prekey).toBe(await published(to));
      }
    }
    expect(receipts).toBe(3);
  });

  it('a retry goes to the published prekey and carries admission', async () => {
    const w = await pair();
    const { offered } = await ratchet(w);
    const { clock, relay, alice, bob, b } = w;
    const n = relay.sent.length;
    await alice.client.send(b, TEXT, { message: 'm3' }); // bob offline: nothing pulled
    clock.advance(61);
    await alice.client.flush();
    const [first, second] = since(relay, n, alice, bob);
    expect(first.encryption.prekey).not.toBe(await published(bob)); // the held key (bob's newest offer)
    expect(first.encryption.prekey).toBe(offered); // still in use at bob; m2's receipt (same timestamp) replaced nothing
    expect(await contentOf(first, bob)).not.toHaveProperty('admission');
    expect(second.encryption.prekey).toBe(await published(bob));
    expect(await contentOf(second, bob)).toHaveProperty('admission');
  });

  it('a reinstalled peer recovers on the second attempt and holds the sender\'s offer', async () => {
    const w = await pair();
    await ratchet(w);
    const { clock, relay, alice, a, b } = w;
    await w.bob.client.close();
    clock.advance(5);
    const bob = await reinstall(w.bob, relay, clock);
    expect(await bob.client.peers.get(a)).toBeNull();
    const m3 = await alice.client.send(b, TEXT, { message: 'm3' });
    let n = relay.sent.length;
    expect(await bob.client.pull()).toMatchObject([{ kind: 'dropped' }]);
    expect(since(relay, n, bob, alice)).toEqual([]); // no receipt
    clock.advance(61);
    n = relay.sent.length;
    expect(await alice.client.flush()).toMatchObject([{ status: 'pending', attempts: 2 }]);
    const [second] = since(relay, n, alice, bob);
    expect(second.encryption.prekey).toBe(await published(bob));
    const carried = await offeredBy(second, bob);
    expect(await bob.client.pull()).toMatchObject([{ kind: 'delivered' }]);
    expect((await bob.client.admission.get(a))?.status).toBe('admitted');
    expect((await bob.client.vault.held(a, await pinOf(bob, a), clock.t))?.id).toBe(carried); // recorded by the recovery path
    await alice.client.pull();
    expect((await alice.client.outbox.get(m3.messageId))!.status).toBe('delivered');
  });

  it('reordered packets keep the newer held key', async () => {
    const { clock, alice, bob, a, b } = await pair();
    const t = clock.t;
    const keys = [1, 2].map((i) => toBase64(prekeyPublicKey(new Uint8Array(32).fill(i))));
    for (const [ts, key] of [[t + 10, keys[0]], [t + 5, keys[1]]] as const) {
      const { id, publicKey } = (await bob.client.vault.current())!;
      const p = await createPacket({ identity: alice.id, to: b, prekey: { id, publicKey }, content: { ...msg('x'), prekey: key }, timestamp: ts });
      expect(await bob.client.inbox.receive(p)).toMatchObject({ kind: 'delivered' });
    }
    expect((await bob.client.vault.held(a, await pinOf(bob, a), t))?.id).toBe(prekeyId(fromBase64(keys[0])));
  });

  it('unknown_prekey on a held key: the retry goes to the published prekey; a rejection naming the held key drops it', async () => {
    const w = await pair();
    await ratchet(w);
    const { clock, relay, alice, bob, b } = w;
    const held = (await alice.client.vault.held(b, await pinOf(alice, b), clock.t))!;
    expect(held).not.toBeNull();
    // bob loses its peer prekey state
    const doc = JSON.parse(new TextDecoder().decode((await bob.store.read('prekeys.json'))!)) as { peers: object };
    await bob.store.write('prekeys.json', canonicalStateBytes({ ...doc, peers: {} }));
    clock.advance(1);
    let n = relay.sent.length;
    const m3 = await alice.client.send(b, TEXT, { message: 'm3' });
    const [first] = since(relay, n, alice, bob);
    expect(first.encryption.prekey).toBe(held.id);
    const [out] = await bob.client.pull();
    expect(out).toMatchObject({ kind: 'rejected' });
    expect(out.kind === 'rejected' && out.error.code).toBe('unknown_prekey');
    await alice.client.pull();
    expect(await alice.client.outbox.get(m3.messageId)).toMatchObject({ status: 'pending', rejectedPrekey: held.id });
    // The rejection carried bob's new offer, which replaced the rejected key.
    expect((await alice.client.vault.held(b, await pinOf(alice, b), clock.t))?.id).not.toBe(held.id);
    n = relay.sent.length;
    await alice.client.flush();
    const [retry] = since(relay, n, alice, bob);
    expect(retry.encryption.prekey).toBe(await published(bob));
    await bob.client.pull();
    await alice.client.pull();
    expect((await alice.client.outbox.get(m3.messageId))!.status).toBe('delivered');

    // A rejection naming the key still held drops it before the retry chooses.
    n = relay.sent.length;
    const m4 = await alice.client.send(b, TEXT, { message: 'm4' });
    const [again] = since(relay, n, alice, bob);
    const still = (await alice.client.vault.held(b, await pinOf(alice, b), clock.t))!;
    expect(again.encryption.prekey).toBe(still.id);
    await alice.client.outbox.onReceipt(b, { messageId: m4.messageId, outcome: 'rejected', code: 'unknown_prekey', prekey: still.id });
    n = relay.sent.length;
    await alice.client.flush();
    const [retry2] = since(relay, n, alice, bob);
    expect(retry2.encryption.prekey).toBe(await published(bob));
    expect(await alice.client.vault.held(b, await pinOf(alice, b), clock.t)).toBeNull();
  });

  it('a held key noble cannot encapsulate to (all-zero X25519 half) is dropped; the same attempt goes to the published prekey', async () => {
    const w = await pair();
    await ratchet(w);
    const { clock, relay, alice, bob, b } = w;
    const pin = await pinOf(alice, b);
    const real = fromBase64((await alice.client.vault.held(b, pin, clock.t))!.publicKey);
    const lowOrder = real.slice();
    lowOrder.fill(0, 1184); // valid ML-KEM-768 half, all-zero X25519 half
    expect(() => checkXWingPublicKey(lowOrder)).not.toThrow(); // receivers accept it (03 § X-Wing)
    expect(() => ml_kem768_x25519.encapsulate(lowOrder)).toThrow(); // noble refuses to encapsulate to it
    await alice.client.vault.dropHeld(b);
    await alice.client.vault.hold(b, { id: prekeyId(lowOrder), publicKey: toBase64(lowOrder) }, clock.t, pin);
    expect((await alice.client.vault.held(b, pin, clock.t))?.id).toBe(prekeyId(lowOrder));
    const n = relay.sent.length;
    const m = await alice.client.send(b, TEXT, { message: 'm3' });
    expect(m).toMatchObject({ status: 'pending', attempts: 1, lastPrekey: await published(bob) });
    const [first] = since(relay, n, alice, bob);
    expect(first.encryption.prekey).toBe(await published(bob));
    expect(await alice.client.vault.held(b, pin, clock.t)).toBeNull();
    expect(await bob.client.pull()).toMatchObject([{ kind: 'delivered' }]);
    await alice.client.pull();
    expect((await alice.client.outbox.get(m.messageId))!.status).toBe('delivered');
  });

  it('block drops the held key', async () => {
    const w = await pair();
    await ratchet(w);
    const { clock, alice, b } = w;
    const pin = await pinOf(alice, b);
    expect(await alice.client.vault.held(b, pin, clock.t)).not.toBeNull();
    await alice.client.block(b);
    expect(await alice.client.vault.held(b, pin, clock.t)).toBeNull();
  });

  it('contact packets offer a key but record no held key', async () => {
    const { clock, relay, alice, bob, a, b } = await pair();
    expect(await alice.client.vault.held(b, await pinOf(alice, b), clock.t)).toBeNull();
    expect(await bob.client.vault.held(a, await pinOf(bob, a), clock.t)).toBeNull();
    const contacts = [...since(relay, 0, alice, bob), ...since(relay, 0, bob, alice)];
    expect(contacts.length).toBeGreaterThan(0);
    for (const p of contacts) {
      const to = p.to === a ? alice : bob;
      expect((await contentOf(p, to)).type).toBe('ace:contact:1');
      expect(p.encryption.prekey).toBe(await published(to));
      expect(await contentOf(p, to)).toHaveProperty('prekey');
    }
  });
});

/** `t` reinstalled: the same identity over an empty store, its descriptor republished with a new prekey. */
async function reinstall(t: TestAgent, relay: FakeRelay, clock: Clock): Promise<TestAgent> {
  const store = new MemoryStore();
  const received: TestAgent['received'] = [];
  const client = await NetworkClient.open({
    identity: t.id, store, relay: relay.client(), clock: clock.now, contact: 'open', listed: true, acceptProfiles: [TEXT],
    onMessage: (m) => { received.push(m); }, foreignRelay: () => { throw new ACEError('blocked_address', 'no foreign relays in tests'); },
  });
  await client.publish();
  return { id: t.id, client, store, received };
}

describe('06 § Receive pipeline: peer prekeys at step 6', () => {
  it('a transient vault failure recording the opened key defers the packet (retried, never dropped)', async () => {
    const w = await inboxWorld();
    const used = vi.spyOn(w.vault, 'used').mockRejectedValueOnce(new ACEError('storage_failed', 'disk'));
    const p = await w.pack(w.sender, msg('x'));
    expect(await w.inbox.receive(p)).toMatchObject({ kind: 'deferred', error: { code: 'storage_failed' } });
    expect(w.delivered).toEqual([]);
    expect(await w.inbox.receive(p)).toMatchObject({ kind: 'delivered' });
    expect(used).toHaveBeenCalledTimes(2);
    expect(w.delivered[0]).not.toHaveProperty('prekey');
    expect(w.delivered[0].body).toEqual({ message: 'x' });
  });

  it('a rejected packet (step 8) and a duplicate still record the held key', async () => {
    const w = await inboxWorld();
    const pin = (await w.peers.get(w.sender.getACEId()))!.lastHash;
    const bad = await w.pack(w.sender, { ...msg('x'), body: { nope: 1 } }, w.clock.t);
    expect(await w.inbox.receive(bad)).toMatchObject({ kind: 'rejected' });
    expect(await w.vault.held(w.sender.getACEId(), pin, w.clock.t)).not.toBeNull();
    await w.vault.dropHeld(w.sender.getACEId());
    const ok = await w.pack(w.sender, msg('y'), w.clock.t + 1);
    expect(await w.inbox.receive(ok)).toMatchObject({ kind: 'delivered' });
    await w.vault.dropHeld(w.sender.getACEId());
    expect(await w.inbox.receive(ok)).toMatchObject({ kind: 'duplicate' });
    expect(await w.vault.held(w.sender.getACEId(), pin, w.clock.t)).not.toBeNull();
  });
});

/**
 * A correctly signed packet whose private content is `content` verbatim (createPacket would refuse a malformed one):
 * what a faulty or hostile sender can put on the wire.
 */
async function forgedPacket(
  from: SoftwareIdentity, to: string, prekey: Prekey, content: object, timestamp: number,
  plaintext: Uint8Array = padPlaintext(canonicalStateBytes(content)),
): Promise<Packet> {
  const messageId = crypto.randomUUID(), seq = checkUsable(from, timestamp).signing!.seq;
  const { cipherText, sharedSecret } = ml_kem768_x25519.encapsulate(fromBase64(prekey.publicKey));
  const header = packetHeader(from.getACEId(), to, messageId, timestamp, prekey.id, cipherText);
  const payload = await sealPayload(sharedSecret, header, plaintext);
  const packet: Packet = {
    ace: '1', messageId, from: from.getACEId(), to, timestamp,
    encryption: { prekey: prekey.id, kemCiphertext: toBase64(cipherText), payload: toBase64(payload) },
    signature: { scheme: 'ml-dsa-65', seq, value: '' },
  };
  packet.signature.value = toBase64(await from.sign(signingMessage(from.getACEId(), timestamp, seq, packetSignPayload(packet)), 'packet'));
  return decodePacket(JSON.parse(JSON.stringify(packet)));
}

describe('03 § Private content: a prekey that is not an X-Wing public key', () => {
  it('a pinned sender\'s packet offering one is rejected invalid_body (step 7) and nothing is held', async () => {
    const w = await inboxWorld();
    const peer = w.sender.getACEId(), pin = (await w.peers.get(peer))!.lastHash;
    const notXWing = toBase64(new Uint8Array(1216).fill(0xff));
    const p = await forgedPacket(w.sender, w.me.getACEId(), w.prekey, { ...msg('x'), prekey: notXWing }, w.clock.t);
    const out = await w.inbox.receive(p);
    expect(out).toMatchObject({ kind: 'rejected', error: { code: 'invalid_body' } });
    expect(w.receipts).toEqual([[peer, expect.objectContaining({ messageId: p.messageId, outcome: 'rejected', code: 'invalid_body' })]]);
    expect(w.delivered).toEqual([]);
    expect(await w.vault.held(peer, pin, w.clock.t)).toBeNull();
    // the same forgery with a real key is delivered and held: the check is what kept the dead key out
    const ok = await forgedPacket(w.sender, w.me.getACEId(), w.prekey, msg('y'), w.clock.t);
    expect(await w.inbox.receive(ok)).toMatchObject({ kind: 'delivered' });
    expect(await w.vault.held(peer, pin, w.clock.t)).not.toBeNull();
  });
});

describe('06 § Receive pipeline: step 6 (padding) drops, step 7 (content shape) rejects non-core packets', () => {
  const notXWing = toBase64(new Uint8Array(1216).fill(0xff));

  it('a malformed prekey in a pinned peer\'s message is rejected invalid_body with a receipt; nothing is held', async () => {
    const w = await inboxWorld();
    const peer = w.sender.getACEId(), pin = (await w.peers.get(peer))!.lastHash;
    const p = await forgedPacket(w.sender, w.me.getACEId(), w.prekey, { ...msg('x'), prekey: 'not base64!' }, w.clock.t);
    expect(await w.inbox.receive(p)).toMatchObject({ kind: 'rejected', error: { code: 'invalid_body' } });
    expect(w.receipts).toEqual([[peer, expect.objectContaining({ messageId: p.messageId, outcome: 'rejected', code: 'invalid_body' })]]);
    expect(w.delivered).toEqual([]);
    expect(await w.vault.held(peer, pin, w.clock.t)).toBeNull();
  });

  it('the same with receipt-typed content is dropped, never receipted', async () => {
    const w = await inboxWorld();
    const peer = w.sender.getACEId(), pin = (await w.peers.get(peer))!.lastHash;
    const content = { type: RECEIPT, schemaDigest: '0'.repeat(64), body: { messageId: crypto.randomUUID(), status: 'delivered' }, prekey: notXWing };
    const p = await forgedPacket(w.sender, w.me.getACEId(), w.prekey, content, w.clock.t);
    expect(await w.inbox.receive(p)).toMatchObject({ kind: 'dropped', error: { code: 'invalid_body' } });
    expect(w.receipts).toEqual([]);
    expect(await w.vault.held(peer, pin, w.clock.t)).toBeNull();
  });

  it('non-zero padding is a step-6 failure: dropped, no receipt', async () => {
    const w = await inboxWorld();
    const peer = w.sender.getACEId(), pin = (await w.peers.get(peer))!.lastHash;
    const plaintext = padPlaintext(canonicalStateBytes(msg('x')));
    plaintext[plaintext.length - 1] = 1;
    const p = await forgedPacket(w.sender, w.me.getACEId(), w.prekey, msg('x'), w.clock.t, plaintext);
    expect(await w.inbox.receive(p)).toMatchObject({ kind: 'dropped', error: { code: 'invalid_body' } });
    expect(w.receipts).toEqual([]);
    expect(w.delivered).toEqual([]);
    expect(await w.vault.held(peer, pin, w.clock.t)).toBeNull();
  });
});
