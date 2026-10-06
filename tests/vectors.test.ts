// Shared cross-language vectors (ace-spec/test-vectors.json, version 2).
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
import { VECTORS, V, agent, peerOf, hex, unhex, b64 } from './helpers.js';
import { createHash } from 'node:crypto';

describe('vectors', () => {
  it('version and sections', () => {
    expect(VECTORS.version).toBe('2');
    for (const k of ['envelopes', 'bodies', 'transitions', 'replay', 'signatures', 'auth', 'registrations',
      'registrationErrors', 'urls', 'base64', 'peerBinding']) expect(V).toHaveProperty(k);
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
    const payload = encodePayload(mp.type, mp.to, mp.conversationId, mp.messageId, mp.threadId, b64(mp.kemCiphertext), b64(mp.ciphertext));
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
    expect(JSON.parse(new TextDecoder().decode(raw))).toEqual(em.expectedBody);
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
  return { action: 'intent', need: r.need, tags: r.tags, maxPrice: r.maxPrice, currency: r.currency, ttl: r.ttl };
}

describe('auth', () => {
  it.each(V.auth.map((v: any, i: number) => [`${i}-${v.agent}-${v.action}`, v]))('%s', async (_n, v: any) => {
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
          : verifyRegistrationFile(s.registrationFile, { pinnedAt: s.pinnedAt });
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
