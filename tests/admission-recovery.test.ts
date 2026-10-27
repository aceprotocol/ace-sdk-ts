// Admission recovery (05 § Admission recovery, 06 § Outbox / Recovery candidates, 03 § Private content): an endpoint
// that lost its admission table, pins, held permits and prekeys but kept its identity re-admits a peer from the permit
// and PublishedAgent that peer's next Outbox retry presents, without any network lookup.
import { vi } from 'vitest';
import {
  ACEError, AdmissionBook, MemoryStore, NetworkClient, MAX_PLAINTEXT_BYTES, canonicalStateBytes, createDescriptor,
  createPermit, decodePacket, decodePrivateContent, decryptPacket, encodePrivateContent, receiptContent, contactContent,
  encodePayload, signingMessage, toBase64, type Prekey, type SoftwareIdentity,
  type DeliveryPermit, type InboxOptions, type JSONObject, type NetworkClientOptions, type PrivateContent, type ProfileManifest,
} from './sdk.js';
import { Clock, FakeRelay, NOW, RELAY, agent, type TestAgent } from './helpers.js';
import { inboxWorld, msg, text, withPrekey } from './helpers2.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { packetHeader, padPlaintext, sealPayload } from '../src/packet.js';
import { decodePrekey } from '../src/prekey.js';

/** A signed packet whose plaintext is `content` as is (`createPacket` refuses content its decoding would refuse). */
async function packRaw(from: SoftwareIdentity, to: string, prekey: Prekey, content: unknown, timestamp: number) {
  const { cipherText, sharedSecret } = ml_kem768_x25519.encapsulate(decodePrekey(prekey));
  const messageId = crypto.randomUUID(), sender = from.getACEId(), seq = from.getSigningSeq();
  const payload = await sealPayload(sharedSecret, packetHeader(sender, to, messageId, timestamp, prekey.id, cipherText), padPlaintext(canonicalStateBytes(content)));
  const m = signingMessage(sender, timestamp, seq, encodePayload(to, messageId, prekey.id, cipherText, payload));
  return {
    ace: '1', messageId, from: sender, to, timestamp,
    encryption: { prekey: prekey.id, kemCiphertext: toBase64(cipherText), payload: toBase64(payload) },
    signature: { scheme: 'ml-dsa-65', seq, value: toBase64(await from.sign(m, 'packet')) },
  };
}

const TEXT = 'ace:text:1';
const enc = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));
const asJson = (p: DeliveryPermit) => p as unknown as JSONObject;

describe('03 § Private content: admission', () => {
  const content = msg('hi');
  const adm = { proof: { issuer: 'x' }, permit: { issuer: 'y' }, source: { kel: [] } }; // decoding checks the shape only; 05 the contents

  it('decodes and encodes the closed {proof, permit} object', () => {
    const c = decodePrivateContent(enc({ ...content, admission: adm }));
    expect(c.admission).toEqual(adm);
    expect(decodePrivateContent(encodePrivateContent(c))).toEqual(c);
    expect(decodePrivateContent(enc(content))).not.toHaveProperty('admission');
  });

  it.each([
    ['null', null],
    ['without permit', { proof: adm.proof, source: adm.source }],
    ['without source', { proof: adm.proof, permit: adm.permit }],
    ['source not an object', { ...adm, source: 'agent' }],
    ['with an unknown member', { ...adm, extra: {} }],
    ['proof not an object', { ...adm, proof: 'permit' }],
    ['permit an array', { ...adm, permit: [] }],
  ])('admission %s is invalid_body', (_n, admission) => {
    expect(() => decodePrivateContent(enc({ ...content, admission }))).toThrow(expect.objectContaining({ code: 'invalid_body' }));
    expect(() => encodePrivateContent({ ...content, admission } as unknown as PrivateContent)).toThrow(expect.objectContaining({ code: 'invalid_body' }));
  });
});

/** An admitted pair over one FakeRelay (alice public and auto-accepting text, bob closed and connected to her). */
async function pair(o: { profiles?: Array<'text' | ProfileManifest> } = {}) {
  const clock = new Clock(), relay = new FakeRelay(clock.now);
  const alice = await agent(relay, clock, { contact: 'open', listed: true, acceptProfiles: [TEXT], ...o });
  const bob = await agent(relay, clock, o);
  await bob.client.connect(alice.id.getACEId(), { profile: TEXT });
  await alice.client.pull();
  await bob.client.pull();
  return { clock, relay, alice, bob, a: alice.id.getACEId(), b: bob.id.getACEId() };
}

/** `t` reinstalled: the same identity over an empty store, its descriptor republished with a new prekey. */
async function reinstall(t: TestAgent, relay: FakeRelay, clock: Clock, o: Partial<NetworkClientOptions> = {}): Promise<TestAgent> {
  await t.client.close();
  const store = new MemoryStore();
  const received: TestAgent['received'] = [];
  const client = await NetworkClient.open({
    identity: t.id, store, relay: relay.client(), clock: clock.now, onMessage: (m) => { received.push(m); },
    foreignRelay: () => { throw new ACEError('blocked_address', 'no foreign relays in tests'); }, ...o,
  });
  await client.publish();
  return { id: t.id, client, store, received };
}

/** The private content of a packet the relay accepted, decrypted with `t`'s vault. */
async function sentContent(relay: FakeRelay, index: number, t: TestAgent): Promise<PrivateContent> {
  return decryptPacket(decodePacket(relay.sent[index].packet), t.client.vault);
}

describe('05 § Admission recovery: a reinstalled endpoint', () => {
  it('re-admits an admitted peer from its Outbox retry, which is delivered, receipted and answerable', async () => {
    const { clock, relay, alice, bob, a, b } = await pair();
    await bob.client.send(a, TEXT, { message: 'before' });
    expect(await alice.client.pull()).toMatchObject([{ kind: 'delivered' }]);
    expect(await bob.client.pull()).toMatchObject([{ kind: 'receipt', body: { outcome: 'delivered' } }]);

    clock.advance(10);
    const bob2 = await reinstall(bob, relay, clock);
    expect(await bob2.client.admission.get(a)).toBeNull();

    // Attempt 1 encrypts to the prekey alice cached: bob2 cannot decrypt it and drops it (no receipt).
    const first = await alice.client.send(b, TEXT, { message: 'after reinstall' });
    expect(first).toMatchObject({ status: 'pending', attempts: 1 });
    const n1 = relay.sent.length - 1;
    expect(await bob2.client.pull()).toMatchObject([{ kind: 'dropped' }]);
    expect(await bob2.client.admission.get(a)).toBeNull();
    expect(await alice.client.pull()).toEqual([]);

    // Attempt 2 refreshes bob's descriptor (new prekey) and carries `admission`.
    clock.advance(60);
    const [second] = await alice.client.flush();
    expect(second).toMatchObject({ status: 'pending', attempts: 2 });
    expect((await alice.client.outbox.get(first.messageId))!.content).not.toHaveProperty('admission'); // never stored
    const n2 = relay.sent.length - 1;
    expect(n2).toBeGreaterThan(n1);
    const retried = await sentContent(relay, n2, bob2);
    expect(retried.admission?.proof).toEqual(relay.sent[n2].permit); // the permit presented to the relay
    expect(retried.admission?.permit).toMatchObject({ issuer: a, subject: b });
    expect(retried.admission?.source).toEqual(await alice.client.publish()); // alice's current PublishedAgent
    // The reply permit is alice's newest issued one, still valid: reused, not re-issued.
    expect(retried.admission?.permit).toEqual((await alice.client.admission.get(b))!.issued);

    const out = await bob2.client.pull();
    expect(out).toMatchObject([{ kind: 'delivered', message: { from: a, body: { message: 'after reinstall' } } }]);
    expect(bob2.received).toHaveLength(1);
    expect(bob2.received[0]).not.toHaveProperty('admission');
    const rec = await bob2.client.admission.get(a);
    expect(rec).toMatchObject({ aceId: a, status: 'admitted' });
    expect(rec).not.toHaveProperty('profile');
    expect(await bob2.client.admission.heldPermit(a)).toEqual(retried.admission!.permit);

    // alice gets the `delivered` receipt; bob2 can reply with the permit it now holds.
    expect(await alice.client.pull()).toMatchObject([{ kind: 'receipt', body: { messageId: first.messageId, outcome: 'delivered' } }]);
    expect((await alice.client.outbox.get(first.messageId))!.status).toBe('delivered');
    const reply = await bob2.client.send(a, TEXT, { message: 'welcome back' });
    expect(reply.status).toBe('pending');
    expect(await alice.client.pull()).toMatchObject([{ kind: 'delivered', message: { from: b, body: { message: 'welcome back' } } }]);
    expect(await bob2.client.pull()).toMatchObject([{ kind: 'receipt', body: { messageId: reply.messageId, outcome: 'delivered' } }]);

    // The restored row records no profile: the permit refresh after a signing-key change falls back to a shared one.
    clock.advance(10);
    await bob2.id.delegate({ now: clock.t });
    await bob2.client.maintain();
    expect((await bob2.client.admission.get(a))!.issued!.signature.seq).toBe(bob2.id.getSigningSeq());
    expect(await alice.client.pull()).toMatchObject([{ kind: 'contact', event: { body: { kind: 'request', profile: TEXT } } }]);
    await alice.client.close(); await bob2.client.close();
  });

  it('across relays (no federation): recovery needs no lookup, and the reply reaches the sender through its source', async () => {
    const clock = new Clock();
    const relayA = new FakeRelay(clock.now), relayB = new FakeRelay(clock.now, 'https://relay-b.test');
    const routes: Record<string, FakeRelay> = { [relayA.baseUrl]: relayA, [relayB.baseUrl]: relayB };
    const foreignRelay = (url: string) => routes[url].client();
    const alice = await agent(relayA, clock, { contact: 'open', acceptProfiles: [TEXT], foreignRelay });
    const bob = await agent(relayB, clock, { foreignRelay });
    const a = alice.id.getACEId(), b = bob.id.getACEId();
    await bob.client.connect(await alice.client.publish(), { profile: TEXT });
    await alice.client.pull();
    await bob.client.pull();
    expect((await bob.client.admission.get(a))?.status).toBe('admitted');
    expect(relayB.descriptors.has(a)).toBe(false); // bob's home relay cannot look alice up

    clock.advance(10);
    const bob2 = await reinstall(bob, relayB, clock, { foreignRelay });
    await alice.client.send(b, TEXT, { message: 'x' });
    expect(await bob2.client.pull()).toMatchObject([{ kind: 'dropped' }]);
    clock.advance(60);
    await alice.client.flush();
    expect(await bob2.client.pull()).toMatchObject([{ kind: 'delivered', message: { from: a } }]);
    expect((await bob2.client.admission.get(a))?.status).toBe('admitted');
    expect(await alice.client.pull()).toMatchObject([{ kind: 'receipt', body: { outcome: 'delivered' } }]);
    await bob2.client.send(a, TEXT, { message: 'back' });
    expect(await alice.client.pull()).toMatchObject([{ kind: 'delivered', message: { from: b, body: { message: 'back' } } }]);
    await alice.client.close(); await bob2.client.close();
  });

  it('our source is local: the stored PublishedAgent while unexpired, else the retry goes without admission', async () => {
    const { clock, relay, alice, bob, b } = await pair();
    const published = await alice.client.publish();
    const publish = vi.spyOn(alice.client, 'publish');
    const retry = async (message: string) => {
      relay.inject.push({ path: '/v1/send', status: 503, code: 'internal_error' });
      const e = await alice.client.send(b, TEXT, { message });
      clock.advance(60);
      await alice.client.outbox.attempt(e.messageId);
      expect(await alice.client.outbox.get(e.messageId)).toMatchObject({ attempts: 2, status: 'pending' });
      return sentContent(relay, relay.sent.length - 1, bob);
    };
    expect((await retry('one')).admission?.source).toEqual(published);
    // An expired stored descriptor is never sent (not re-verified, only its expiry checked).
    const self = JSON.parse(new TextDecoder().decode((await alice.store.read('network/self.json'))!));
    self.agent.descriptor.expiresAt = clock.t;
    await alice.store.write('network/self.json', new TextEncoder().encode(JSON.stringify(self)));
    expect(await retry('two')).not.toHaveProperty('admission');
    await alice.store.delete('network/self.json');
    expect(await retry('three')).not.toHaveProperty('admission');
    expect(publish).not.toHaveBeenCalled(); // attempts never publish
    expect((await bob.client.pull()).map((o) => o.kind)).toEqual(['delivered', 'delivered', 'delivered']);
    await alice.client.close(); await bob.client.close();
  });

  it('a fresh reply permit counts as issued only after the attempt carrying it was sent', async () => {
    const { clock, relay, alice, bob, a, b } = await pair();
    clock.advance(16 * 86400); // alice's issued permit has less than PERMIT_RENEWAL_SECONDS left; bob's to alice is still valid
    await bob.client.publish();
    await alice.client.publish(); // upkeep keeps our own source fresh
    const before = (await alice.client.admission.get(b))!.issued!;
    relay.inject.push({ path: '/v1/send', status: 503, code: 'internal_error' }, { path: '/v1/send', status: 503, code: 'internal_error' });
    const e = await alice.client.send(b, TEXT, { message: 'x' }); // attempt 1 fails at the relay
    clock.advance(60);
    await alice.client.flush(); // attempt 2 creates a fresh reply permit, but its post fails
    expect((await alice.client.admission.get(b))!.issued).toEqual(before);
    clock.advance(120);
    await alice.client.flush(); // attempt 3 is sent
    const sent = await sentContent(relay, relay.sent.length - 1, bob);
    const issued = (await alice.client.admission.get(b))!.issued!;
    expect(issued.expiresAt).toBeGreaterThan(before.expiresAt);
    expect(sent.admission?.permit).toEqual(issued);
    // bob is pinned: the proof is ignored and the reply permit held like a receipt renewal.
    expect(await bob.client.pull()).toMatchObject([{ kind: 'delivered', message: { messageId: e.messageId } }]);
    expect(await bob.client.admission.heldPermit(a)).toEqual(issued);
    await alice.client.close(); await bob.client.close();
  });

  it('admission is left out when the content with it would exceed MAX_PLAINTEXT_BYTES', async () => {
    const BIG: ProfileManifest = {
      id: 'test:big:1',
      messages: [{
        type: 'test:big:1',
        schema: {
          type: 'object', additionalProperties: false, required: [],
          properties: Object.fromEntries(['a', 'b', 'c', 'd', 'e'].map((k) => [k, { type: 'string', maxLength: 262144 }])),
        },
      }],
    };
    const profiles: Array<'text' | ProfileManifest> = ['text', BIG];
    const { clock, relay, alice, bob, b } = await pair({ profiles });
    const digest = alice.client.profiles.digestOf('test:big:1')!;
    const small = canonicalStateBytes(withPrekey({ type: 'test:big:1', schemaDigest: digest, body: { a: '' } })).length;
    let left = MAX_PLAINTEXT_BYTES - 200 - small;
    const body: Record<string, string> = {};
    for (const k of ['a', 'b', 'c', 'd', 'e']) { const n = Math.min(left, 262144); body[k] = 'x'.repeat(n); left -= n + 8; }
    relay.inject.push({ path: '/v1/send', status: 503, code: 'internal_error' });
    await alice.client.send(b, 'test:big:1', body);
    clock.advance(60);
    await alice.client.flush();
    const sent = await sentContent(relay, relay.sent.length - 1, bob);
    expect(sent.body).toEqual(body);
    expect(sent).not.toHaveProperty('admission');
    await alice.client.close(); await bob.client.close();
  });

  it('a block decided after the records were lost still outranks the earlier one at the relay', async () => {
    const { clock, relay, alice, bob, a, b } = await pair();
    await bob.client.block(a);
    expect(relay.blocks.get(`${b}|${a}`)).toEqual({ blocked: true, revision: clock.t });
    await bob.client.unblock(a);
    expect(relay.blocks.get(`${b}|${a}`)).toEqual({ blocked: false, revision: clock.t + 1 });
    clock.advance(10);
    const bob2 = await reinstall(bob, relay, clock);
    await bob2.client.block(a); // no local revision any more: max(0 + 1, now) is still newer
    expect(relay.blocks.get(`${b}|${a}`)).toEqual({ blocked: true, revision: clock.t });
    expect(await bob2.client.admission.get(a)).toMatchObject({ status: 'blocked' });
    expect(await bob2.client.admission.get(a)).not.toHaveProperty('unsyncedRevision');
    await alice.client.close(); await bob2.client.close();
  });

  it('block revisions are max(previous + 1, now)', async () => {
    const clock = new Clock(), store = new MemoryStore();
    const book = new AdmissionBook(store, { clock: clock.now });
    const peer = (await agent(new FakeRelay(clock.now), clock)).id.getACEId();
    expect(await book.block(peer, clock.t)).toBe(NOW);
    expect(await book.nextBlockRevision(peer)).toBe(NOW + 1); // within one second: previous + 1
    clock.advance(100);
    expect(await book.block(peer, clock.t)).toBe(NOW + 100);
    expect(await book.blockRevision(peer)).toBe(NOW + 100);
  });
});

describe('06 § Recovery candidates: the receiver', () => {
  /** An Inbox for `me` without the sender admitted or pinned; `source` is the sender's PublishedAgent. */
  async function world(o: Partial<InboxOptions> = {}) {
    const w = await inboxWorld({ admit: false, ...o });
    const from = w.sender.getACEId(), me = w.me.getACEId();
    const proof = await createPermit(w.me, from, { now: w.clock.t, ttl: 86400 });
    const reply = await createPermit(w.sender, me, { now: w.clock.t, ttl: 86400 });
    const source = await createDescriptor(w.sender, { relays: [RELAY], prekey: w.prekey, profiles: text.descriptors(), now: w.clock.t });
    const recovering = (a: { proof?: unknown; permit?: unknown; source?: unknown } = {}, body = msg('hi')) =>
      ({ ...body, admission: { proof: asJson(proof), permit: asJson(reply), source: asJson(source), ...a } as PrivateContent['admission'] }) as PrivateContent;
    return { ...w, from, mine: me, proof, reply, source, recovering };
  }
  type World = Awaited<ReturnType<typeof world>>;
  /** Nothing admitted, pinned or held for the sender, and nothing answered. */
  async function untouched(w: World) {
    expect(await w.admission.get(w.from)).toBeNull();
    expect(await w.peers.get(w.from)).toBeNull();
    expect(await w.admission.heldPermit(w.from)).toBeNull();
    expect(w.receipts).toEqual([]);
    expect(w.refreshPeer).not.toHaveBeenCalled();
  }

  it('a valid proof restores the sender from its source without a lookup: admitted (no profile), pinned, permit held', async () => {
    const w = await world();
    const out = await w.inbox.receive(await w.pack(w.sender, w.recovering()));
    expect(out).toMatchObject({ kind: 'delivered', message: { from: w.from, body: { message: 'hi' } } });
    expect(w.refreshPeer).not.toHaveBeenCalled();
    expect((await w.peers.get(w.from))?.lastHash).toBeDefined();
    expect(await w.admission.get(w.from)).toEqual({ aceId: w.from, status: 'admitted', issued: w.proof, updatedAt: w.clock.t });
    expect(await w.admission.heldPermit(w.from)).toEqual(w.reply);
    expect(w.delivered[0]).not.toHaveProperty('admission');
    expect(w.receipts).toEqual([[w.from, { messageId: (out as { message: { messageId: string } }).message.messageId, outcome: 'delivered' }]]);
    for (const k of await w.store.list('inbox/journal/')) expect(new TextDecoder().decode((await w.store.read(k))!)).not.toContain('admission');
  });

  it('an uninstalled type is dropped before the source is checked; a body schema failure after restore is answered', async () => {
    const w = await world();
    const alien = { ...msg('x'), type: 'test:alien:1' } as PrivateContent;
    expect(await w.inbox.receive(await w.pack(w.sender, w.recovering({ source: {} }, alien)))).toMatchObject({ kind: 'dropped', error: { code: 'unsupported_schema' } });
    await untouched(w);
    const bad = { ...msg('x'), body: { nope: 1 } } as PrivateContent;
    expect(await w.inbox.receive(await w.pack(w.sender, w.recovering({}, bad)))).toMatchObject({ kind: 'rejected', error: { code: 'invalid_body' } });
    expect((await w.admission.get(w.from))?.status).toBe('admitted');
  });

  it.each([
    ['issued by the sender', async (w: World) => createPermit(w.sender, w.mine, { now: w.clock.t })],
    ['issued to someone else', async (w: World) => createPermit(w.me, (await inboxWorld()).me.getACEId(), { now: w.clock.t })],
    ['with a forged expiry', async (w: World) => ({ ...w.proof, expiresAt: w.proof.expiresAt + 1 })],
    ['expired', async (w: World) => createPermit(w.me, w.from, { now: w.clock.t - 100, ttl: 50 })],
  ])('a proof %s is dropped, nothing admitted or pinned', async (_n, make) => {
    const w = await world();
    const out = await w.inbox.receive(await w.pack(w.sender, w.recovering({ proof: await make(w) })));
    expect(out).toMatchObject({ kind: 'dropped', error: { code: 'not_permitted' } });
    await untouched(w);
  });

  it('a stranger without admission is dropped as before', async () => {
    const w = await world();
    expect(await w.inbox.receive(await w.pack(w.sender, msg('hi')))).toMatchObject({ kind: 'dropped', error: { code: 'not_permitted' } });
    await untouched(w);
  });

  it('a leaked proof on packets the subject did not sign: every one dropped, no pin; the genuine one delivered', async () => {
    const w = await world();
    const good = await w.pack(w.sender, w.recovering());
    const sig = Buffer.from(good.signature.value, 'base64');
    sig[0] ^= 1;
    const forged = { ...good, signature: { ...good.signature, value: sig.toString('base64') } };
    for (let i = 0; i < 3; i++) expect(await w.inbox.receive(forged)).toMatchObject({ kind: 'dropped', error: { code: 'invalid_signature' } });
    await untouched(w);
    expect(await w.inbox.receive(good)).toMatchObject({ kind: 'delivered' });
  });

  it('a source naming another identity is dropped, nothing pinned', async () => {
    const w = await world();
    const other = await inboxWorld();
    const theirs = await createDescriptor(other.me, { relays: [RELAY], prekey: other.prekey, profiles: text.descriptors(), now: w.clock.t });
    expect(await w.inbox.receive(await w.pack(w.sender, w.recovering({ source: theirs })))).toMatchObject({ kind: 'dropped', error: { code: 'invalid_authorization' } });
    await untouched(w);
    expect(await w.peers.get(other.me.getACEId())).toBeNull();
  });

  it('a source older than the pin is refused, the pin unchanged', async () => {
    const w = await world();
    w.clock.advance(10);
    await w.sender.delegate({ now: w.clock.t });
    await w.peers.adopt(w.sender.getKel()); // pinned past the KEL the source was signed under
    const pin = await w.peers.get(w.from);
    const reply = await createPermit(w.sender, w.mine, { now: w.clock.t });
    const out = await w.inbox.receive(await w.pack(w.sender, w.recovering({ permit: reply })));
    expect(out.kind).toBe('dropped');
    expect(await w.peers.get(w.from)).toEqual(pin);
    expect(await w.admission.get(w.from)).toBeNull();
  });

  it('the proof replaces the recorded issued permit only when it is newer', async () => {
    const w = await world();
    const newer = await createPermit(w.me, w.from, { now: w.clock.t + 1, ttl: 86400 });
    await w.admission.update(w.from, () => ({ aceId: w.from, status: 'pending', issued: newer, updatedAt: w.clock.t }));
    expect((await w.inbox.receive(await w.pack(w.sender, w.recovering()))).kind).toBe('delivered');
    expect((await w.admission.get(w.from))!.issued).toEqual(newer);
  });

  it('an invalid admission.permit is dropped invalid_authorization, nothing admitted, pinned or held', async () => {
    const w = await world();
    const other = await createPermit(w.sender, (await inboxWorld()).me.getACEId(), { now: w.clock.t });
    expect(await w.inbox.receive(await w.pack(w.sender, w.recovering({ permit: other })))).toMatchObject({ kind: 'dropped', error: { code: 'invalid_authorization' } });
    await untouched(w);
  });

  it('a blocked sender is dropped and changes no pin (the block is checked, under lock, before the source is pinned)', async () => {
    const w = await world();
    await w.admission.block(w.from, w.clock.t);
    expect(await w.inbox.receive(await w.pack(w.sender, w.recovering()))).toMatchObject({ kind: 'dropped', error: { code: 'not_permitted' } });
    expect(await w.peers.get(w.from)).toBeNull();
    expect((await w.admission.get(w.from))?.status).toBe('blocked');
    expect(await w.admission.heldPermit(w.from)).toBeNull();
    expect(w.delivered).toEqual([]);
  });

  it('a pending row without a pin is restored to admitted, keeping its profile', async () => {
    const w = await world();
    await w.admission.update(w.from, () => ({ aceId: w.from, status: 'pending', profile: TEXT, updatedAt: w.clock.t - 5 }));
    expect((await w.inbox.receive(await w.pack(w.sender, w.recovering()))).kind).toBe('delivered');
    expect(await w.admission.get(w.from)).toEqual({ aceId: w.from, status: 'admitted', profile: TEXT, issued: w.proof, updatedAt: w.clock.t });
  });

  it('a pinned sender: the proof is ignored, a valid permit held, an invalid one ignored', async () => {
    const w = await inboxWorld();
    const from = w.sender.getACEId(), me = w.me.getACEId();
    const reply = await createPermit(w.sender, me, { now: w.clock.t });
    const junk = { issuer: 'nobody' };
    const out = await w.inbox.receive(await w.pack(w.sender, { ...msg('a'), admission: { proof: junk, permit: asJson(reply), source: junk } }));
    expect(out.kind).toBe('delivered');
    expect(await w.admission.heldPermit(from)).toEqual(reply);
    const other = await createPermit(w.me, from, { now: w.clock.t }); // wrong issuer: ignored
    expect((await w.inbox.receive(await w.pack(w.sender, { ...msg('b'), admission: { proof: junk, permit: asJson(other), source: junk } }))).kind).toBe('delivered');
    expect(await w.admission.heldPermit(from)).toEqual(reply);
    expect(w.delivered.map((m) => Object.keys(m).includes('admission'))).toEqual([false, false]);
  });

  it('receipts and contact packets carrying admission are dropped invalid_body (decoding refuses them)', async () => {
    const w = await inboxWorld();
    const adm = { proof: {}, permit: {}, source: {} };
    const receipt = withPrekey({ ...receiptContent({ messageId: crypto.randomUUID(), outcome: 'delivered' }), admission: adm });
    const contact = withPrekey({ ...contactContent({ kind: 'rejected', profile: TEXT, note: '', source: {} as never }), admission: adm });
    for (const c of [receipt, contact]) {
      expect(() => encodePrivateContent(c as PrivateContent)).toThrow(expect.objectContaining({ code: 'invalid_body' }));
      expect(() => decodePrivateContent(canonicalStateBytes(c))).toThrow(expect.objectContaining({ code: 'invalid_body' }));
      expect(await w.inbox.receive(await packRaw(w.sender, w.me.getACEId(), w.prekey, c, w.clock.t))).toMatchObject({ kind: 'dropped', error: { code: 'invalid_body' } });
    }
    // Unpinned: a contact candidate with admission is dropped too, nothing pinned.
    const v = await world();
    expect(await v.inbox.receive(await packRaw(v.sender, v.mine, v.prekey, contact, v.clock.t))).toMatchObject({ kind: 'dropped', error: { code: 'invalid_body' } });
    await untouched(v);
  });
});

describe('Outbox: retries refresh the descriptor and are flagged', () => {
  it('the first attempt neither refreshes nor recovers; every later one does both', async () => {
    const { Outbox, ProfileSet } = await import('./sdk.js');
    const clock = new Clock(), me = (await agent(new FakeRelay(clock.now), clock)).id;
    const to = (await agent(new FakeRelay(clock.now), clock)).id.getACEId();
    const calls: Array<{ refresh: boolean; retry: boolean; content: PrivateContent }> = [];
    let fail = true;
    const ob = new Outbox({
      identity: me, store: new MemoryStore(), profiles: new ProfileSet(['text']), clock: clock.now,
      transport: async (a) => { calls.push({ refresh: a.refresh, retry: a.retry, content: a.content }); if (fail) throw new ACEError('relay_unavailable', 'x'); return { prekey: 'a'.repeat(64) }; },
    });
    const e = await ob.enqueue({ to, type: TEXT, body: { message: 'm' } });
    await ob.attempt(e.messageId);
    clock.advance(60);
    fail = false;
    await ob.attempt(e.messageId);
    expect(calls.map((c) => [c.refresh, c.retry])).toEqual([[false, false], [true, true]]);
    expect(calls.every((c) => c.content.admission === undefined)).toBe(true);
  });
});
