// The shared conformance vectors (ace-spec/test-vectors.json, copied to tests/fixtures; check-sdk-artifacts.py keeps
// the copy byte-identical). Every section that applies to this SDK is verified here.
import { readFileSync } from 'node:fs';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
  ACEError, AdmissionBook, BUNDLED_MANIFESTS, Inbox, MemoryStore, NetworkClient, Outbox, PeerStore, ProfileSet, ReplayDetector, RelayClient,
  SoftwareIdentity, StorePrekeyVault, ThreadStore, canonicalStateBytes, checkPacketTime, checkReceiptBody, checkStrangerSource, commerceRules,
  conversationKey, createAuthHeaders, createPacket, decodePacket, decodePrivateContent, decryptPacket, encodePayload, eventBytes, extendKel,
  fromBase64, isACEId, isBlockedAddress, isCaip10, isCaip19, isHandle, isHex64, isHttpsUrl, isMessageId, isMessageType, isOutcomeCode,
  isStreamId, isThreadId, isUsable, messageDigest, normalizeRelayUrl, parseAuthHeaders, profileDigest, signingMessage, validateCommerceExt,
  toBase64, validateErc8004Binding, validateProfileManifest, verifyAuthHeaders, verifyDelegation, verifyErc8004Registration, verifyKel,
  verifyOperationalSignature, verifyPacketSignature, verifyPermit, verifyPublishedAgent, verifyRegistrationRequest, verifySignature,
  type KelState, type Packet, type PrekeyVault, type ReceiptBody, type ReceiveOutcome, type RelayAuthRequest,
} from './sdk.js';
import { authPayload } from '../src/auth.js';
import { checkJsonValue, parseJSONBytes, wireInt } from '../src/encoding.js';
import { packetHeader, sealPayload } from '../src/packet.js';
import { relayErrorFor } from '../src/relay.js';
import { openPacket } from './helpers2.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any;
const V: Any = JSON.parse(readFileSync(new URL('./fixtures/test-vectors.json', import.meta.url), 'utf8'));
const NOW: number = V.now;
const enc = new TextEncoder();
const kelOf = (name: string) => V.agents[name].export.kel;
const stateOf = (name: string, now = NOW): KelState => verifyKel(kelOf(name), now);
const idOf = (name: string): string => V.agents[name].aceId;

async function codeOf(fn: () => unknown): Promise<string | null> {
  try { await fn(); } catch (e) {
    if (e instanceof ACEError) return e.code;
    throw e;
  }
  return null;
}

describe('vectors: agents', () => {
  it('load from their exports', () => {
    for (const [name, a] of Object.entries<Any>(V.agents)) expect(SoftwareIdentity.fromExport(a.export, NOW).getACEId(), name).toBe(a.aceId);
  });
});

describe('vectors: encoding', () => {
  const e = V.encoding;
  it('base64', async () => {
    for (const c of e.base64) {
      if (c.valid) expect(bytesToHex(fromBase64(c.text))).toBe(c.hex);
      else expect(await codeOf(() => fromBase64(c.text)), c.text).toBe('invalid_argument');
    }
  });
  it.each(e.canonicalJson.map((c: Any) => [c.name, c]))('canonical JSON: %s', (_n, c: Any) => {
    const run = () => {
      const v = parseJSONBytes(enc.encode(c.input), 'invalid_argument', 'input');
      checkJsonValue(v, 'invalid_argument');
      return new TextDecoder().decode(canonicalStateBytes(v));
    };
    if (c.error) expect(run).toThrow();
    else expect(run()).toBe(c.canonical);
  });
  it('wire integers', () => {
    for (const c of e.wireInts) expect(wireInt(JSON.parse(c.json)), c.json).toBe(c.value);
  });
  it('identifiers', () => {
    const preds: Record<string, (v: unknown) => boolean> = {
      aceId: isACEId, messageId: isMessageId, hexDigest: isHex64, namespacedId: isMessageType, threadId: isThreadId, handle: isHandle,
      streamId: isStreamId, outcomeCode: isOutcomeCode, caip10: isCaip10, caip19: isCaip19,
    };
    expect(Object.keys(e.identifiers).sort()).toEqual(Object.keys(preds).sort());
    for (const [kind, cases] of Object.entries<Any[]>(e.identifiers)) {
      for (const c of cases) expect(preds[kind](c.value), `${kind} ${JSON.stringify(c.value)}`).toBe(c.valid);
    }
  });
  it('HTTPS URLs, relay URLs, blocked addresses, pair key', async () => {
    for (const c of e.httpsUrls) expect(isHttpsUrl(c.url), c.url).toBe(c.valid);
    for (const c of e.relayUrls) {
      if (c.error) expect(await codeOf(() => normalizeRelayUrl(c.input)), c.input).toBe(c.error);
      else expect(normalizeRelayUrl(c.input)).toBe(c.normalized);
    }
    for (const c of e.blockedAddresses) expect(isBlockedAddress(c.address), c.address).toBe(c.blocked);
    const k = e.conversationKey;
    expect(conversationKey(k.a, k.b)).toBe(k.key);
    expect(conversationKey(k.b, k.a)).toBe(k.key);
  });
});

describe('vectors: signing', () => {
  it('encodePayload, the message M, action separation', () => {
    const s = V.signing;
    for (const c of s.encodePayload) expect(bytesToHex(encodePayload(...c.fields.map((f: Any) => (f.text !== undefined ? f.text : hexToBytes(f.hex)))))).toBe(c.hex);
    for (const c of s.message) expect(bytesToHex(signingMessage(c.aceId, c.timestamp, c.seq, hexToBytes(c.payloadHex)))).toBe(c.messageHex);
    for (const a of s.actionSeparation) {
      const st = stateOf(a.signer), msg = hexToBytes(a.messageHex);
      if (a.claims) expect(bytesToHex(signingMessage(st.aceId, a.claims.issuedAt, st.signing!.seq, canonicalStateBytes(a.claims)))).toBe(a.messageHex);
      for (const [action, ok] of Object.entries(a.actions)) expect(verifySignature(msg, action, fromBase64(a.signature), st.signing!.publicKey), action).toBe(ok);
    }
  });
});

describe('vectors: KEL', () => {
  const k = V.kel;
  it('valid logs', () => {
    for (const c of k.valid) {
      const st = verifyKel(kelOf(c.agent).slice(0, c.events ?? undefined), c.now);
      expect([st.aceId, st.seq, st.lastHash, st.rootScheme, st.next]).toEqual([c.aceId, c.seq, c.lastHash, c.rootScheme, c.next]);
      expect(st.signing === null ? null : { seq: st.signing.seq, notAfter: st.signing.notAfter }).toEqual(c.signing);
      expect(isUsable(st, c.now)).toBe(c.usable);
    }
  });
  it.each(k.invalid.map((c: Any) => [c.name, c]))('invalid: %s', async (_n, c: Any) => {
    expect(await codeOf(() => verifyKel(c.kel, c.now))).toBe(c.error);
  });
  it('event bytes, forks, operational signatures', async () => {
    for (const c of k.eventBytes) expect(bytesToHex(eventBytes(c.event))).toBe(c.hex);
    for (const c of k.forks) {
      const pinned = c.pinned === null ? null : verifyKel(c.pinned, c.now);
      if (c.error) expect(await codeOf(() => extendKel(pinned, c.candidate, c.now)), c.name).toBe(c.error);
      else {
        const r = extendKel(pinned, c.candidate, c.now);
        expect([r.outcome, r.state.seq], c.name).toEqual([c.outcome, c.seq]);
      }
    }
    for (const c of k.operational) {
      const st = stateOf(c.signer, c.now);
      expect(await codeOf(() => verifyOperationalSignature(st, c.action, c.timestamp, hexToBytes(c.payloadHex), c.signature, c.now)), c.name).toBe(c.error);
    }
  });
});

describe('vectors: X-Wing (draft-11)', () => {
  it('public key, decapsulation and derandomized encapsulation', () => {
    for (const c of V.xwing.cases) {
      const seed = hexToBytes(c.seed);
      expect(bytesToHex(ml_kem768_x25519.getPublicKey(seed))).toBe(c.publicKey);
      expect(bytesToHex(ml_kem768_x25519.decapsulate(hexToBytes(c.ciphertext), seed))).toBe(c.sharedSecret);
      const e = ml_kem768_x25519.encapsulate(hexToBytes(c.publicKey), hexToBytes(c.eseed));
      expect([bytesToHex(e.sharedSecret), bytesToHex(e.cipherText)]).toEqual([c.sharedSecret, c.ciphertext]);
    }
  });
});

/** A vault holding only the vector prekey seed, through the vault's store document. */
async function bobVault(): Promise<StorePrekeyVault> {
  const d = V.packet.deterministic;
  const store = new MemoryStore();
  await store.write('prekeys.json', canonicalStateBytes({ version: 1, current: { id: d.prekey.id, seed: toBase64(hexToBytes(d.prekeySeed)), createdAt: 0 }, retained: [] }));
  return new StorePrekeyVault(store, { clock: () => NOW });
}

describe('vectors: packet', () => {
  const p = V.packet;
  it('deterministic header, key, payload, packet and signature', async () => {
    const d = p.deterministic;
    const kem = hexToBytes(d.kemCiphertext), ss = hexToBytes(d.sharedSecret), nonce = hexToBytes(d.nonce);
    const from = idOf(d.sender), to = idOf(d.recipient);
    const header = packetHeader(from, to, d.messageId, d.timestamp, d.prekey.id, kem);
    expect(bytesToHex(header)).toBe(d.headerHex);
    expect(d.saltHex).toBe(''); // 03: the HKDF salt is the empty string
    expect(bytesToHex(hkdf(sha256, ss, new Uint8Array(0), header, 32))).toBe(d.keyHex);
    expect(bytesToHex(canonicalStateBytes(d.content))).toBe(d.plaintextHex);
    const payload = await sealPayload(ss, header, canonicalStateBytes(d.content), nonce);
    expect(bytesToHex(payload)).toBe(d.payloadHex);
    expect(bytesToHex(encodePayload(to, d.messageId, d.prekey.id, kem, payload))).toBe(d.signPayloadHex);
    const m = signingMessage(from, d.timestamp, d.packet.signature.seq, hexToBytes(d.signPayloadHex));
    expect(bytesToHex(m)).toBe(d.messageHex);
    expect(verifySignature(m, 'packet', fromBase64(d.packet.signature.value), stateOf('alice').signing!.publicKey)).toBe(true);
    const made = await createPacket({
      identity: SoftwareIdentity.fromExport(V.agents.alice.export, NOW), to, prekey: d.prekey, content: d.content, messageId: d.messageId,
      timestamp: d.timestamp, _deterministic: { kemCiphertext: kem, sharedSecret: ss, nonce },
    });
    expect(made.encryption).toEqual(d.packet.encryption);
    for (const pkt of [made, d.packet as Packet]) {
      const { content } = await openPacket(pkt, { recipient: to, sender: stateOf('alice'), vault: await bobVault(), now: NOW });
      expect(content).toEqual(d.content);
    }
  });
  it.each(p.decode.map((c: Any) => [c.name, c]))('decode: %s', async (_n, c: Any) => {
    const value = c.json !== undefined ? JSON.parse(c.json) : c.packet;
    expect(await codeOf(() => decodePacket(value))).toBe(c.error);
  });
  it.each(p.open.map((c: Any) => [c.name, c]))('open: %s', async (_n, c: Any) => {
    expect(await codeOf(async () => openPacket(c.packet, { recipient: idOf(c.recipient), sender: stateOf(c.sender, c.now), vault: await bobVault(), now: c.now }))).toBe(c.error);
  });
  it.each(V.privateContent.cases.map((c: Any) => [c.name, c]))('private content: %s', async (_n, c: Any) => {
    const raw = c.text !== undefined ? enc.encode(c.text) : hexToBytes(c.hex);
    expect(await codeOf(() => decodePrivateContent(raw))).toBe(c.error);
  });
});

describe('vectors: descriptor, delegation, permit, ERC-8004', () => {
  const d = V.descriptor;
  it.each(d.valid.map((c: Any) => [c.name, c]))('valid: %s', (_n, c: Any) => {
    expect(verifyPublishedAgent(c.publishedAgent, c.now).delegations.map((x) => x.issuer)).toEqual(c.delegations);
  });
  it.each(d.invalid.map((c: Any) => [c.name, c]))('invalid: %s', async (_n, c: Any) => {
    expect(await codeOf(() => verifyPublishedAgent(c.publishedAgent, c.now))).toBe(c.error);
  });
  it.each(d.pinned.map((c: Any) => [c.name, c]))('against the pin: %s', async (_n, c: Any) => {
    const pinned = stateOf(c.pinned, c.now);
    expect(await codeOf(() => verifyPublishedAgent(c.publishedAgent, c.now, { pinned }))).toBe(c.error);
    // importAgent of a client holding the pin behaves the same (no prekey substitution by a superseded key).
    const store = new MemoryStore();
    const client = await NetworkClient.open({
      identity: SoftwareIdentity.fromExport(V.agents.alice.export, NOW), store, relay: new RelayClient('https://relay.example', { fetch: () => { throw new Error('offline'); } }),
      receive: false, clock: () => c.now,
    });
    await client.peers.adopt(kelOf(c.pinned));
    expect(await codeOf(() => client.importAgent(c.publishedAgent))).toBe(c.error);
    if (c.error === null) expect((await client.agent(idOf(c.pinned))).descriptor.prekey.id).toBe(c.publishedAgent.descriptor.prekey.id);
    await client.close();
  });
  it('delegations', async () => {
    for (const c of V.delegation.cases) {
      const run = () => (verifyDelegation(c.entry, c.subject, c.now) === null ? 'expired' : 'live');
      if (c.result) expect(run(), c.name).toBe(c.result);
      else expect(await codeOf(run), c.name).toBe(c.error);
    }
    for (const c of V.delegation.pinned) {
      const run = () => (verifyDelegation(c.entry, c.subject, c.now, { pinned: stateOf(c.pinned, c.now) }) === null ? 'expired' : 'live');
      if (c.result) expect(run(), c.name).toBe(c.result);
      else expect(await codeOf(run), c.name).toBe(c.error);
    }
    for (const c of V.delegation.descriptors) {
      const pins = new Map<string, KelState>(c.delegationPins.map((x: string) => [idOf(x), stateOf(x, c.now)]));
      expect(await codeOf(() => verifyPublishedAgent(c.publishedAgent, c.now, { delegationPins: pins })), c.name).toBe(c.error);
      expect(await codeOf(() => verifyPublishedAgent(c.publishedAgent, c.now))).toBeNull();
      // a client holding the issuer pin refuses it on import
      const client = await NetworkClient.open({
        identity: SoftwareIdentity.fromExport(V.agents.carol.export, NOW), store: new MemoryStore(),
        relay: new RelayClient('https://relay.example', { fetch: () => { throw new Error('offline'); } }),
        receive: false, clock: () => c.now,
      });
      for (const x of c.delegationPins) await client.peers.adopt(kelOf(x));
      expect(await codeOf(() => client.importAgent(c.publishedAgent)), c.name).toBe(c.error);
      await client.close();
    }
  });
  it('core rules: receipts and stranger sources', async () => {
    for (const c of V.coreRules.receipts) expect(await codeOf(() => checkReceiptBody(c.body)), c.name).toBe(c.error);
    for (const c of V.coreRules.strangerSources) expect(await codeOf(() => checkStrangerSource(c.source)), c.name).toBe(c.error);
  });
  it('permits', async () => {
    for (const c of V.permit.cases) expect(await codeOf(() => verifyPermit(c.permit, stateOf(c.issuer, c.now), c.subject, c.now)), c.name).toBe(c.error);
  });
  it('ERC-8004', async () => {
    for (const c of V.erc8004.shapes) expect((await codeOf(() => validateErc8004Binding(c.entry))) === null).toBe(c.valid);
    for (const c of V.erc8004.registrations) expect(verifyErc8004Registration(c.registration, c.aceId)).toBe(c.result);
  });
});

describe('vectors: manifests', () => {
  const m = V.manifests;
  it('official digests', () => {
    const bundled = Object.values(BUNDLED_MANIFESTS);
    for (const o of m.official) {
      const b = bundled.find((x) => x.id === o.id)!;
      expect(profileDigest(b)).toBe(o.digest);
      expect(Object.fromEntries(b.messages.map((x) => [x.type, messageDigest(x.type, x.schema)]))).toEqual(o.messages);
    }
  });
  it.each(m.thirdParty.map((c: Any) => [c.name, c]))('third party: %s', async (_n, c: Any) => {
    if (c.valid) {
      const v = validateProfileManifest(c.manifest);
      expect(profileDigest(v)).toBe(c.digest);
      expect(Object.fromEntries(v.messages.map((x) => [x.type, messageDigest(x.type, x.schema)]))).toEqual(c.messages);
    } else {
      expect(await codeOf(() => validateProfileManifest(c.manifest))).toBe('invalid_argument');
    }
  });
  it('bodies', async () => {
    const set = new ProfileSet(['text', 'commerce']);
    for (const c of m.bodies) expect(await codeOf(() => set.validate(c.type, c.schemaDigest, c.body)), c.name).toBe(c.error);
  });
});

describe('vectors: replay', () => {
  it.each(V.replay.cases.map((c: Any) => [c.name, c]))('%s', (_n, c: Any) => {
    const det = c.initialState ? ReplayDetector.fromState(c.initialState, { capacity: c.capacity }) : new ReplayDetector({ capacity: c.capacity, horizon: c.horizon });
    for (const op of c.ops) {
      if (op.op === 'commit') expect(det.commit(op.messageId, op.sender, op.timestamp, op.floor), JSON.stringify(op)).toBe(op.expect);
      else {
        const got = det.hasSeen(op.messageId, op.sender) ? 'duplicate' : det.covers(op.sender, op.timestamp) ? 'replay_horizon' : 'new';
        expect(got, JSON.stringify(op)).toBe(op.expect);
      }
    }
    expect(new TextDecoder().decode(canonicalStateBytes(det.exportState()))).toBe(new TextDecoder().decode(canonicalStateBytes(c.finalState)));
  });
});

describe('vectors: commerce', () => {
  const parties = Object.fromEntries(Object.entries<string>(V.commerce.parties).map(([role, name]) => [role, idOf(name)]));
  it.each(V.commerce.transitions.map((c: Any) => [c.name, c]))('%s', async (_n, c: Any) => {
    const local = parties[c.local];
    const threads = new ThreadStore(new MemoryStore(), local);
    const rules = commerceRules(threads);
    for (const st of c.steps) {
      const from = parties[st.from], to = parties[st.to];
      const e = { direction: from === local ? 'send' as const : 'receive' as const, messageId: st.messageId, from, to, timestamp: st.timestamp, type: st.type, ...(st.threadId ? { threadId: st.threadId } : {}) };
      let got: string;
      try {
        await rules.check(e, st.body);
        await rules.commit(e, st.body);
        got = (await threads.get(from === local ? to : from, st.threadId))!.state;
      } catch (err) {
        if (!(err instanceof ACEError)) throw err;
        got = err.code;
      }
      expect(got, JSON.stringify(st)).toBe(st.expect);
    }
  });
  it.each(V.commerce.sender.map((c: Any) => [c.name, c]))('sender: %s', async (_n, c: Any) => {
    const A = idOf('alice'), B = idOf('bob');
    let t = V.now;
    const store = new MemoryStore();
    const threads = new ThreadStore(store, A);
    const rules = commerceRules(threads);
    const ob = new Outbox({
      identity: { getACEId: () => A } as never, store, profiles: new ProfileSet(['text', 'commerce']), rules: [rules],
      transport: async () => { throw new Error('no transport'); }, clock: () => t,
    });
    for (const [i, st] of (c.steps as Any[]).entries()) {
      t = V.now + i;
      const threadId = st.threadId ?? 't1';
      let got = 'ok';
      try {
        if (st.op === 'send') await ob.enqueue({ to: B, type: st.type, body: st.body, threadId, messageId: st.messageId });
        else if (st.op === 'receipt') await ob.onReceipt(B, { messageId: st.messageId, outcome: st.outcome, ...(st.code ? { code: st.code } : {}) });
        else if (st.op === 'abandon') await ob.abandon(st.messageId);
        else {
          const e = { direction: 'receive' as const, messageId: st.messageId, from: B, to: A, timestamp: t, type: st.type, threadId };
          if (await ob.busy(B, threadId) !== null) throw new ACEError('thread_busy', 'busy');
          await rules.check(e, st.body);
          await rules.commit(e, st.body);
        }
      } catch (err) {
        if (!(err instanceof ACEError)) throw err;
        got = err.code;
      }
      expect(got, JSON.stringify(st)).toBe(st.expect);
      expect((await threads.get(B, 't1'))?.state ?? null, JSON.stringify(st)).toBe(st.state);
      expect((await ob.busy(B, 't1')) !== null, JSON.stringify(st)).toBe(st.busy);
    }
  });
  it('descriptor extension', async () => {
    for (const c of V.commerce.ext) expect((await codeOf(() => validateCommerceExt(c.value))) === null, JSON.stringify(c.value)).toBe(c.valid);
  });
});

describe('vectors: receive pipeline', () => {
  const names: Record<ReceiveOutcome['kind'], string> = {
    delivered: 'delivered', contact: 'delivered', duplicate: 'duplicate', dropped: 'drop', rejected: 'reject', receipt: 'delivered', deferred: 'retry',
  };
  it.each(V.pipeline.cases.map((c: Any) => [c.name, c]))('%s', async (_n, c: Any) => {
    let t = NOW;
    const clock = () => t;
    const me = SoftwareIdentity.fromExport(V.agents[c.receiver].export, NOW);
    const store = new MemoryStore();
    const peers = new PeerStore({ store, clock }), admission = new AdmissionBook(store, { clock });
    for (const [name, agent] of Object.entries<Any>(c.admitted)) {
      verifyPublishedAgent(agent, NOW);
      await peers.adopt(agent.kel);
      await admission.update(idOf(name), () => ({ aceId: idOf(name), status: 'admitted', updatedAt: NOW }));
    }
    const receipts: ReceiptBody[] = [];
    const inbox = await Inbox.open({
      identity: me, store, vault: await bobVault(), profiles: new ProfileSet(['text', 'commerce']), peers, admission, clock,
      capacity: c.capacity, visibility: () => (c.public ? 'public' : 'private'), onMessage: () => {}, sendReceipt: async (_to, b) => { receipts.push(b); },
    });
    for (const step of c.steps) {
      t = step.now;
      receipts.length = 0;
      const out = await inbox.receive(new TextEncoder().encode(JSON.stringify(step.packet)));
      const label = `${step.packet.messageId} at ${step.now}`;
      expect(names[out.kind], label).toBe(step.expect.disposition);
      expect('error' in out ? out.error.code : null, label).toBe(step.expect.code);
      expect(receipts.map((r) => r.outcome), label).toEqual(step.expect.receipt === null ? [] : [step.expect.receipt]);
    }
    await inbox.close();
  });
});

describe('vectors: auth, registration, relay errors', () => {
  /** The relay side: a relay holding agents[agent]'s KEL verifies the headers at clock `now`. */
  const verify = (headers: Record<string, string>, request: RelayAuthRequest, agent: string, now: number, audience: string) => {
    verifyAuthHeaders(parseAuthHeaders(headers), request, stateOf(agent, now), { audience, clock: () => now });
  };
  it('auth headers', async () => {
    const a = V.auth;
    for (const c of a.cases) {
      const st = stateOf(c.agent, c.timestamp);
      expect(bytesToHex(authPayload(c.request))).toBe(c.payloadHex);
      expect(bytesToHex(encodePayload(c.audience, c.nonce, hexToBytes(c.payloadHex)))).toBe(c.authPayloadHex);
      const m = signingMessage(st.aceId, c.timestamp, st.signing!.seq, hexToBytes(c.authPayloadHex));
      expect(bytesToHex(m)).toBe(c.messageHex);
      expect(verifySignature(m, c.request.action, fromBase64(c.headers['X-ACE-Signature']), st.signing!.publicKey)).toBe(true);
      verify(c.headers, c.request, c.agent, c.timestamp, c.audience);
      // this SDK reproduces the headers' signed content (only the hedged signature differs)
      const mine = await createAuthHeaders(SoftwareIdentity.fromExport(V.agents[c.agent].export, NOW), c.request, c.timestamp, { audience: c.audience, nonce: c.nonce });
      const { 'X-ACE-Signature': _a, ...rest } = mine;
      const { 'X-ACE-Signature': _b, ...want } = c.headers;
      expect(rest).toEqual(want);
    }
    for (const c of a.negative) expect(await codeOf(() => verify(c.headers, c.request, c.agent, c.now, 'https://relay.example')), c.name).toBe(c.error);
  });
  it('registration', async () => {
    const r = V.auth.registration;
    const v = verifyRegistrationRequest(r.request, { audience: r.audience, clock: () => r.now });
    expect(v.state.lastHash).toBe(r.lastHashHex);
    expect(bytesToHex(encodePayload(r.lastHashHex, r.audience))).toBe(r.payloadHex);
    expect(bytesToHex(signingMessage(v.state.aceId, r.request.timestamp, v.state.signing!.seq, hexToBytes(r.payloadHex)))).toBe(r.messageHex);
    expect(v.requestDigest).toBe(r.requestDigest);
    for (const n of r.negative) {
      expect(await codeOf(() => verifyRegistrationRequest(n.request, { audience: n.audience, clock: () => n.now })), n.name).toBe(n.error);
    }
  });
  it('wake registration bodies', async () => {
    const w = V.auth.wake;
    const sent: unknown[] = [];
    const fetch = async (_u: unknown, init?: RequestInit) => {
      sent.push(JSON.parse(String(init!.body)));
      return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const client = new RelayClient('https://relay.example', { fetch: fetch as typeof globalThis.fetch, clock: () => NOW });
    const me = SoftwareIdentity.fromExport(V.agents.bob.export, NOW);
    for (const b of w.valid) await client.setWake(me, b.gateway, b.token);
    expect(sent).toEqual(w.valid);
    for (const c of w.invalid) {
      if (Object.keys(c.body).sort().join() !== 'gateway,token') continue; // closed-object cases: the typed call cannot build them
      expect(await codeOf(() => client.setWake(me, c.body.gateway, c.body.token)), c.name).toBe(c.error);
    }
  });
  it.each(V.relayErrors.cases.map((c: Any) => [c.name, c]))('relay error: %s', (_n, c: Any) => {
    const retry = Object.entries<string>(c.headers).find(([k]) => k.toLowerCase() === 'retry-after')?.[1] ?? null;
    const e = relayErrorFor(c.status, retry, c.body);
    expect([e.code, e.category, e.relayCode ?? null, e.retryAfterSeconds ?? null, e.status]).toEqual([c.code, c.category, c.relayCode, c.retryAfterSeconds, c.status]);
  });
});
