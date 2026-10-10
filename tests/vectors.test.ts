// Shared cross-language vectors (ace-spec/test-vectors.json, version 4).
import { describe, expect, it } from 'vitest';
import {
  ACEError, ReplayDetector, ThreadStateMachine, computeACEId, computeConversationId, decodeEnvelope,
  decryptWithSeed, envelopeFingerprint, fromBase64, kemPublicKeyFromSeed, parseMessage, verifyPeerRecord,
  verifyRegistrationFile, verifyRegistrationRequest, createAuthHeaders, parseAuthHeaders, verifyAuthHeaders,
  type RelayAuthRequest, type ThreadEvent,
} from '../src/index.js';
import { canonicalStateBytes, decodeSignature, isHttpsUrl, toBase64 } from '../src/encoding.js';
import { ACE_KEM_SALT, xwingDecapsulate } from '../src/encryption.js';
import { buildSignData, encodePayload, verifySignature } from '../src/signing.js';
import { adoptDecision, type VerifiedPeer } from '../src/discovery.js';
import { authPayload } from '../src/auth.js';
import { decodeBody } from '../src/messages.js';
import {
  Inbox, MAX_DIRECT_BODY_BYTES, MemoryStore, PeerStore, RelayClient, isBlockedAddress, signWebhookNotification, verifyWebhookNotification,
} from '../src/index.js';
import { SecureMailbox } from '../src/secure-mailbox.js';
import { SecureTransport } from '../src/secure-transport.js';
import { normalizeRelayUrl, relayErrorFor } from '../src/relay.js';
import {
  checkPrincipalRules, createPrincipalRecord, principalPayload, principalSignData, principalSignerFromIdentity, validatePrincipalRecord,
} from '../src/principal.js';
import { VECTORS, V, agent, peerOf, hex, unhex, b64, codeOf } from './helpers.js';
import { createHash } from 'node:crypto';

describe('vectors', () => {
  it('version and sections', () => {
    expect(VECTORS.version).toBe('4');
    expect(V.auth).toHaveLength(22);
    for (const k of ['envelopes', 'bodies', 'transitions', 'replay', 'signatures', 'auth', 'registrations',
      'registrationErrors', 'urls', 'base64', 'peerBinding', 'webhooks', 'relayUrls', 'blockedAddresses', 'relayErrors',
      'directReceive', 'principal', 'principalRules']) expect(V).toHaveProperty(k);
  });

  it.each(['alice', 'bob'] as const)('agent %s', (name) => {
    const a = VECTORS.agents[name];
    const id = agent(name);
    expect(toBase64(id.getSigningPublicKey())).toBe(a.signingPublicKey);
    expect(toBase64(id.getEncryptionPublicKey())).toBe(a.encryptionPublicKey);
    expect(id.getACEId()).toBe(a.aceId);
    expect(computeACEId(id.getSigningPublicKey())).toBe(a.aceId);
    expect(id.getAddress()).toBe(a.address);
    expect(id.exportPrivateKey()).toEqual({ scheme: a.scheme, signingPrivateKey: a.signingPrivateKey, encryptionPrivateKey: a.encryptionPrivateKey });
  });

  it.each([0, 1, 2])('xwing KAT %i', (i) => {
    const v = VECTORS.xwing[i];
    const seed = unhex(v.seed);
    expect(hex(kemPublicKeyFromSeed(seed))).toBe(v.publicKey);
    expect(hex(xwingDecapsulate(unhex(v.ciphertext), seed))).toBe(v.sharedSecret);
  });

  it('salt, conversationId, signData and signature', async () => {
    const alice = agent('alice');
    const bob = agent('bob');
    expect(hex(ACE_KEM_SALT)).toBe(V.aceKemSalt);
    expect(computeConversationId(alice.getEncryptionPublicKey(), bob.getEncryptionPublicKey())).toBe(V.conversationId);
    const sd = V.signData;
    const mp = sd.messagePayload;
    const payload = encodePayload(mp.to, mp.conversationId, mp.messageId, b64(mp.kemCiphertext), b64(mp.ciphertext));
    const data = buildSignData(sd.action, sd.aceId, sd.timestamp, payload);
    expect(hex(data)).toBe(sd.signDataHex);
    expect(toBase64(await alice.sign(data))).toBe(V.signature.signatureValue);
  });

  it('encrypted message', async () => {
    const alice = agent('alice');
    const bob = agent('bob');
    const em = V.encryptedMessage;
    const ts = em.envelope.timestamp;
    const parsed = await parseMessage(decodeEnvelope(em.envelope), bob, peerOf(alice), {
      threads: new ThreadStateMachine({ localAceId: bob.getACEId() }), replay: new ReplayDetector({ horizon: ts - 1 }), clock: () => ts,
    });
    expect(parsed.body).toEqual(em.expectedBody);
    const env = em.envelope;
    const raw = await decryptWithSeed(b64(env.encryption.kemCiphertext), b64(env.encryption.payload),
      b64(VECTORS.agents.bob.encryptionPrivateKey), env.conversationId);
    expect(JSON.parse(new TextDecoder().decode(raw)).body).toEqual(em.expectedBody);
  });

  it.each(V.envelopes.map((v: { name: string }) => [v.name, v]))('envelope: %s', (_name, v: any) => {
    const obj = JSON.parse(v.json);
    if (v.valid) {
      expect(envelopeFingerprint(decodeEnvelope(obj))).toBe(v.fingerprint);
    } else {
      try {
        decodeEnvelope(obj);
        throw new Error('expected failure');
      } catch (e) {
        expect((e as ACEError).code).toBe(v.error);
      }
    }
  });

  it.each(V.bodies.map((v: { name: string }) => [v.name, v]))('body: %s', (_name, v: any) => {
    const raw = v.bodyHex !== undefined ? unhex(v.bodyHex) : new TextEncoder().encode(v.bodyJson);
    if (v.valid) {
      decodeBody(v.type, raw);
    } else {
      try {
        decodeBody(v.type, raw);
        throw new Error('expected failure');
      } catch (e) {
        expect((e as ACEError).code).toBe('invalid_body');
      }
    }
  });
});

// --- transitions ---------------------------------------------------------------------------

const T = V.transitions;
const ROLES: Record<string, string> = { buyer: T.buyer, seller: T.seller, third: T.third };
const mid = (i: number) => `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`;
const other = (r: string) => (r === 'buyer' ? 'seller' : 'buyer');

function step(sm: ThreadStateMachine, i: number, type: string, from: string, to: string, body: unknown): string {
  const e: ThreadEvent = {
    conversationId: T.conversationId, threadId: T.threadId, type: type as ThreadEvent['type'], messageId: mid(i),
    timestamp: 1741000000 + i, from: ROLES[from], to: ROLES[to],
  };
  try {
    return sm.apply(e, body);
  } catch (err) {
    if (err instanceof ACEError) return `error:${err.code}`;
    throw err;
  }
}

function synth(type: string, ids: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(T.bodyTemplates[type] as Record<string, unknown>)) {
    out[k] = v === '$head' ? (ids[ids.length - 1] ?? '') : v === '$beforeHead' ? (ids[ids.length - 2] ?? '') : v;
  }
  return out;
}

describe('transitions', () => {
  it.each(['buyer', 'seller'])('matrix with local = %s', (local) => {
    let checked = 0;
    for (const [state, row] of Object.entries(T.matrix as Record<string, Record<string, Record<string, string>>>)) {
      for (const [type, cell] of Object.entries(row)) {
        for (const [sender, expected] of Object.entries(cell)) {
          const sm = new ThreadStateMachine({ localAceId: ROLES[local] });
          const ids: string[] = [];
          (T.paths[state] as string[]).forEach((s, idx) => {
            const [t, frm] = s.split(':');
            expect(step(sm, idx + 1, t, frm, other(frm), synth(t, ids))).not.toMatch(/^error/);
            ids.push(mid(idx + 1));
          });
          const before = JSON.stringify(sm.exportState());
          const got = step(sm, ids.length + 1, type, sender, other(sender), synth(type, ids));
          expect(got, `${state} ${type} ${sender}`).toBe(expected);
          if (got.startsWith('error')) expect(JSON.stringify(sm.exportState())).toBe(before);
          checked++;
        }
      }
    }
    expect(checked).toBeGreaterThan(100);
  });

  it.each(T.cases.map((c: { name: string }) => [c.name, c]))('case: %s', (_n, c: any) => {
    const sm = new ThreadStateMachine({ localAceId: ROLES[c.local] });
    c.steps.forEach((s: any, idx: number) => {
      expect(step(sm, idx + 1, s.type, s.from, s.to, s.body), `step ${idx + 1}`).toBe(s.expect);
    });
  });
});

// --- replay ---------------------------------------------------------------------------------

describe('replay', () => {
  it.each(V.replay.map((v: { name: string }) => [v.name, v]))('%s', (_n, v: any) => {
    const det = v.initialStateJson !== undefined
      ? ReplayDetector.fromState(JSON.parse(v.initialStateJson), { capacity: v.capacity })
      : new ReplayDetector({ capacity: v.capacity, horizon: v.horizon });
    for (const op of v.ops) {
      const got = op.op === 'commit'
        ? det.commit(op.messageId, op.sender, op.timestamp, op.floor)
        : det.accepts(op.messageId, op.sender, op.timestamp);
      expect(got, JSON.stringify(op)).toBe(op.expect);
    }
    expect(new TextDecoder().decode(canonicalStateBytes(det.exportState()))).toBe(v.finalStateJson);
    // clone and fromState round-trip preserve the canonical bytes
    const again = ReplayDetector.fromState(JSON.parse(v.finalStateJson), { capacity: v.capacity });
    expect(new TextDecoder().decode(canonicalStateBytes(again.exportState()))).toBe(v.finalStateJson);
    expect(new TextDecoder().decode(canonicalStateBytes(det.clone().exportState()))).toBe(v.finalStateJson);
  });
});

// --- signatures / auth / registrations -------------------------------------------------------

describe('signatures', () => {
  it.each(['ed25519', 'secp256k1'])('%s', (scheme) => {
    for (const v of V.signatures[scheme]) {
      let ok: boolean;
      try {
        const sig = decodeSignature(v.signature, scheme, 'invalid_signature');
        ok = verifySignature(unhex(v.signDataHex), sig, scheme, fromBase64(v.publicKey));
      } catch (e) {
        if (!(e instanceof ACEError)) throw e;
        ok = false;
      }
      expect(ok, v.name).toBe(v.valid);
    }
  });
});

function authRequest(r: any): RelayAuthRequest {
  if (r.action === 'listen') return { action: 'listen', since: r.since };
  if (r.action === 'inbox') return { action: 'inbox', since: r.since, limit: r.limit };
  if (r.action === 'unregister') return { action: 'unregister' };
  if (r.action === 'webhook') return { action: 'webhook', method: r.method, url: r.url, secret: r.secret };
  return { action: 'intent', need: r.need, tags: r.tags, ext: r.ext ?? null, ttl: r.ttl };
}

describe('auth', () => {
  it.each(V.auth.filter((v: any) => v.action !== 'principal').map((v: any, i: number) => [`${i}-${v.agent}-${v.action}`, v]))('%s', async (_n, v: any) => {
    const id = agent(v.agent);
    const req = authRequest(v.request);
    expect(hex(authPayload(req))).toBe(v.payloadHex);
    expect(hex(buildSignData(v.action, id.getACEId(), v.timestamp, authPayload(req)))).toBe(v.signDataHex);
    if (!v.verifyOnly) expect(await createAuthHeaders(id, req, v.timestamp)).toEqual(v.headers);
    const auth = parseAuthHeaders(v.headers);
    const signer = { aceId: id.getACEId(), scheme: id.getSigningScheme(), signingPublicKey: id.getSigningPublicKey() };
    verifyAuthHeaders(auth, req, signer, { clock: () => v.timestamp });
  });
});

describe('registrations', () => {
  it.each(V.registrations.map((v: any) => [`${v.agent}-${v.mode}`, v]))('%s', (_n, v: any) => {
    const r = verifyRegistrationRequest(v.request, { clock: () => v.now });
    const digest = createHash('sha256').update(unhex(v.signDataHex)).digest('hex');
    expect(r.requestDigest).toBe(v.requestDigest);
    expect(r.requestDigest).toBe(digest);
    expect(r.peer.aceId).toBe(v.request.aceId);
    expect(r.request).toEqual(v.request);
  });

  it.each(V.registrationErrors.map((v: any) => [v.name, v]))('error: %s', (_n, v: any) => {
    try {
      verifyRegistrationRequest(v.request, { clock: () => v.now });
      throw new Error('expected failure');
    } catch (e) {
      expect((e as ACEError).code).toBe(v.error);
    }
  });
});

describe('urls and base64', () => {
  it('urls', () => {
    for (const v of V.urls) expect(isHttpsUrl(v.url), v.url).toBe(v.valid);
  });

  it('base64', () => {
    for (const v of V.base64) {
      try {
        const raw = fromBase64(v.text);
        expect(v.valid, v.text).toBe(true);
        expect(hex(raw)).toBe(v.hex);
      } catch (e) {
        if (!(e instanceof ACEError)) throw e;
        expect(v.valid, v.text).toBe(false);
        expect(e.code).toBe('invalid_argument');
      }
    }
  });
});

describe('peer binding', () => {
  it.each(V.peerBinding.map((c: any) => [c.name, c]))('%s', (_n, c: any) => {
    let pin: VerifiedPeer | null = null;
    for (const s of c.sequence) {
      let got: string;
      try {
        const cand = s.record !== undefined
          ? verifyPeerRecord(s.record)
          : verifyRegistrationFile(s.registrationFile);
        const d = adoptDecision(pin, cand, c.now);
        pin = d.peer;
        got = d.outcome;
      } catch (e) {
        if (!(e instanceof ACEError)) throw e;
        got = `error:${e.code}`;
      }
      expect(got).toBe(s.expect);
      if (s.pinRegisteredAt !== undefined) {
        expect(pin!.registeredAt).toBe(s.pinRegisteredAt);
        expect(toBase64(pin!.encryptionPublicKey)).toBe(s.pinEncryptionPublicKey);
      }
    }
  });
});

// --- webhooks / relay URLs / blocked addresses / relay errors / direct receive -------------

function codeOrResult(fn: () => unknown): unknown {
  try {
    return { result: fn() };
  } catch (e) {
    if (!(e instanceof ACEError)) throw e;
    return { error: e.code };
  }
}

describe('webhooks', () => {
  it.each(V.webhooks.cases.map((c: any) => [c.name, c]))('%s', (_n, c: any) => {
    const got = codeOrResult(() => verifyWebhookNotification({
      secret: c.secret, timestamp: c.timestamp, signature: c.signature, body: new TextEncoder().encode(c.body), clock: () => c.now,
    }));
    expect(got).toEqual(c.result !== undefined ? { result: c.result } : { error: c.error });
    if (c.result !== undefined) expect(signWebhookNotification(c.secret, Number(c.timestamp), c.body)).toBe(c.signature);
  });
});

describe('relayUrls', () => {
  it.each(V.relayUrls.cases.map((c: any) => [JSON.stringify(c.input), c]))('%s', (_n, c: any) => {
    const got = codeOrResult(() => normalizeRelayUrl(c.input));
    expect(got).toEqual(c.normalized !== undefined ? { result: c.normalized } : { error: c.error });
  });
});

describe('blockedAddresses', () => {
  it.each(V.blockedAddresses.cases.map((c: any) => [c.address, c]))('%s', (_n, c: any) => {
    expect(isBlockedAddress(c.address)).toBe(c.blocked);
  });
});

describe('relayErrors', () => {
  it.each(V.relayErrors.cases.map((c: any) => [c.name, c]))('%s', (_n, c: any) => {
    const headers = new Headers(c.headers);
    const e = relayErrorFor(c.status, headers.get('retry-after'), c.body);
    expect([e.code, e.category, e.relayCode ?? null, e.retryAfterSeconds ?? null, e.status])
      .toEqual([c.code, c.category, c.relayCode, c.retryAfterSeconds, c.status]);
  });
});

describe('directReceive', () => {
  it('maxDirectBodyBytes', () => {
    expect(V.directReceive.maxDirectBodyBytes).toBe(MAX_DIRECT_BODY_BYTES);
  });

  it.each(V.directReceive.cases.map((c: any) => [c.name, c]))('%s', async (_n, c: any) => {
    const store = new MemoryStore(), peers = new PeerStore({ store }), identity = agent('bob');
    const inbox = await Inbox.open({ commerce: true, identity, store, peers, onMessage: () => {} });
    // every case fails before any MLS work: the engine is never reached
    const mailbox = await SecureMailbox.open({
      identity, store, peers, relay: new RelayClient('https://relay.example'), secure: new SecureTransport(identity, null as never, store), inbox,
    });
    try {
      let raw = c.bodyHex !== undefined ? unhex(c.bodyHex) : new TextEncoder().encode(c.body);
      if (c.padTo !== undefined) {
        const padded = new Uint8Array(c.padTo).fill(0x20);
        padded.set(raw);
        raw = padded;
      }
      const reply = await mailbox.receiveDirect(raw);
      expect([reply.status, reply.body]).toEqual([c.status, { ok: false, error: c.error }]);
    } finally {
      await mailbox.close();
    }
  });
});

// --- principal (09) -------------------------------------------------------------------------

describe('principal vectors', () => {
  it('four principal auth entries', () => {
    expect(V.auth.filter((v: any) => v.action === 'principal')).toHaveLength(4);
  });

  it.each(V.auth.filter((v: any) => v.action === 'principal').map((v: any, i: number) => [`${i}-${v.agent}`, v]))('auth %s', async (_n, v: any) => {
    const r = v.request;
    const spk = b64(v.subjectSigningPublicKey);
    expect(r.subjectSigningPublicKey).toBe(v.subjectSigningPublicKey);
    const payload = encodePayload(r.account, r.roles.join(','), r.signerScheme, r.signerPublicKey, r.subjectSigningPublicKey, r.scope ?? '', String(r.expiresAt));
    expect(hex(payload)).toBe(v.payloadHex);
    expect(hex(buildSignData('principal', r.subjectAceId, v.timestamp, payload))).toBe(v.signDataHex);
    const rec = validatePrincipalRecord(v.record, spk, v.now);
    expect(rec.signature).toBe(v.signature);
    expect(hex(principalSignData(rec, spk))).toBe(v.signDataHex);
    if (!v.verifyOnly) {
      const mine = await createPrincipalRecord(principalSignerFromIdentity(agent(v.agent)), {
        subjectSigningPublicKey: spk, account: r.account, roles: r.roles, scope: r.scope, expiresAt: r.expiresAt, issuedAt: v.timestamp,
      });
      expect(mine).toEqual(v.record);
    }
  });

  it.each(V.principal.valid.map((v: any) => [v.name, v]))('valid: %s', (_n, v: any) => {
    const spk = b64(v.subjectSigningPublicKey);
    const r = validatePrincipalRecord(v.record, spk, V.principal.now);
    expect(hex(principalPayload(r, spk))).toBe(v.payloadHex);
    expect(hex(principalSignData(r, spk))).toBe(v.signDataHex);
  });

  it.each(V.principal.invalid.map((v: any) => [v.name, v]))('invalid: %s', (_n, v: any) => {
    expect(codeOf(() => validatePrincipalRecord(v.record, b64(v.subjectSigningPublicKey), v.now))).toBe(v.error);
  });

  it('principalRules has 28 cases', () => {
    expect(V.principalRules.cases).toHaveLength(28);
  });

  it.each(V.principalRules.cases.map((c: any) => [c.name, c]))('rules: %s', async (_n, c: any) => {
    const pr = V.principalRules;
    const now: number = c.now ?? pr.now;
    const open = new Map<string, { to: string; expiresAt: number | null }>(Object.entries(c.openRequests));
    const openRequestTo = (conv: string, rid: string, at: number): string | null => {
      const e = open.get(rid);
      if (conv !== pr.conversationId || e === undefined) return null;
      return e.expiresAt === null || e.expiresAt === undefined || at <= e.expiresAt ? e.to : null;
    };
    for (const s of c.steps) {
      const snd = pr.senders[s.sender];
      let got = 'ok';
      try {
        await checkPrincipalRules(s.type, s.body, {
          conversationId: pr.conversationId, senderPrincipal: snd.principal, senderSigningPublicKey: b64(snd.signingPublicKey),
          selfAccount: c.selfAccount, openRequestTo, now,
          selfSigner: c.selfSigner ?? undefined, trustedSigners: c.trustedSigners,
        });
      } catch (e) {
        if (!(e instanceof ACEError)) throw e;
        got = `error:${e.code}`;
      }
      expect(got, JSON.stringify(s)).toBe(s.expect);
      if (got === 'ok' && s.type === 'decision') open.delete(s.body.requestId);
    }
  });
});
