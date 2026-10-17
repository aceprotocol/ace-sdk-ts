import { readFileSync, existsSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  ACEError, BUNDLED_MANIFESTS, ProfileSet, SoftwareIdentity, canonicalStateBytes, categoryOf, conversationKey, messageDigest,
  profileDigest, validateProfileManifest, verifyKel, verifyOperationalSignature, signingMessage, toBase64, eventBytes, MAX_PLAINTEXT_BYTES,
  OFFLINE_WINDOW_SECONDS,
} from './sdk.js';
import { NOW } from './helpers.js';

const dec = (b: Uint8Array) => new TextDecoder().decode(b);
const spec = new URL('../../ace-spec/', import.meta.url);

describe('canonical JSON', () => {
  it('sorts by code point, escapes minimally, rejects lone surrogates', () => {
    expect(dec(canonicalStateBytes({ b: 1, a: [true, null, 'x/\u007fé'], '': 1, '\u{1F600}': 2 }))).toBe('{"a":[true,null,"x/\u007fé"],"b":1,"":1,"\u{1F600}":2}');
    expect(dec(canonicalStateBytes('\b\t\n\f\r\u0001"\\'))).toBe('"\\b\\t\\n\\f\\r\\u0001\\"\\\\"');
    expect(dec(canonicalStateBytes([-0, 1e21, 0.1]))).toBe('[0,1e+21,0.1]');
    expect(() => canonicalStateBytes('\uD800')).toThrow(ACEError);
  });
  it('conversation key is symmetric', () => {
    const a = `ace:sha256:${'a'.repeat(64)}`, b = `ace:sha256:${'b'.repeat(64)}`;
    expect(conversationKey(a, b)).toBe(conversationKey(b, a));
    expect(conversationKey(a, b)).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('limits and errors', () => {
  it('match the revision', () => {
    expect(MAX_PLAINTEXT_BYTES).toBe(1_179_648);
    expect(OFFLINE_WINDOW_SECONDS).toBe(604_800);
    expect(categoryOf('receiver_capacity')).toBe('local');
    expect(categoryOf('relay_unavailable')).toBe('transient');
    // profile rules may raise further permanent codes matching the outcome-code grammar (06 § Error codes)
    expect(new ACEError('invalid_envelope' as never).category).toBe('permanent');
    expect(() => new ACEError('Not-A-Code' as never)).toThrow(TypeError);
  });
});

describe('profile manifests', () => {
  it('bundled manifests equal ace-spec/profiles and their digests', () => {
    for (const [name, m] of Object.entries(BUNDLED_MANIFESTS)) {
      const file = new URL(`profiles/${name}.json`, spec);
      if (existsSync(file)) expect(m).toEqual(JSON.parse(readFileSync(file, 'utf8')));
    }
    const contract = new URL('protocol-contract.json', spec);
    if (existsSync(contract)) {
      const profiles = JSON.parse(readFileSync(contract, 'utf8')).profiles;
      for (const m of Object.values(BUNDLED_MANIFESTS)) expect(profileDigest(m)).toBe(profiles[m.id]);
    }
    const text = BUNDLED_MANIFESTS.text.messages[0];
    expect(messageDigest(text.type, text.schema)).toBe('e91541145d670369cf651d062e6bb8a94ce2605d4a9f2261ceef1d8a29c2e7da');
  });
  it('third-party manifests cannot use reserved prefixes', () => {
    const schema = { type: 'object', properties: {}, required: [], additionalProperties: false };
    expect(() => validateProfileManifest({ id: 'ace:mine:1', messages: [{ type: 'x:y:1', schema }] })).toThrow(/reserved/);
    expect(() => validateProfileManifest({ id: 'x:y:1', messages: [{ type: 'ace:z:1', schema }] })).toThrow(/reserved/);
    expect(validateProfileManifest({ id: 'x:y:1', messages: [{ type: 'urn:ace:z', schema }] }).id).toBe('x:y:1'); // only ace: is reserved
    expect(() => validateProfileManifest({ version: 1, id: 'x:y:1', messages: [{ type: 'x:y:msg:1', schema }] })).toThrow(/invalid profile manifest/);
  });
  it('ProfileSet: core always installed, unknown digest is unsupported_schema', () => {
    const set = new ProfileSet(['text']);
    expect(set.descriptors().map((p) => p.id)).toEqual(['ace:text:1']);
    expect(set.has('ace:core:1')).toBe(true);
    const digest = set.digestOf('ace:text:1')!;
    expect(() => set.validate('ace:text:1', digest, { message: 'hi' })).not.toThrow();
    expect(() => set.validate('ace:text:1', 'f'.repeat(64), { message: 'hi' })).toThrow(expect.objectContaining({ code: 'unsupported_schema' }));
    expect(() => set.validate('ace:text:1', digest, { message: 1 })).toThrow(expect.objectContaining({ code: 'invalid_body' }));
    expect(() => set.validate('ace:commerce:rfq:1', set.digestOf('ace:text:1')!, { need: 'x' })).toThrow(expect.objectContaining({ code: 'unsupported_schema' }));
  });
});

describe('KEL and identity', () => {
  it('signing-only dlg without role; export carries no encryption seed', async () => {
    const id = await SoftwareIdentity.generate({ now: NOW });
    const kel = id.getKel();
    expect(kel.map((e) => e.t)).toEqual(['icp', 'dlg']);
    expect(Object.keys(kel[1]).sort()).toEqual(['key', 'prev', 'seq', 'sig', 't', 'ts']);
    expect(() => eventBytes({ ...kel[1], role: 'signing' })).toThrow(/unknown or missing/);
    const exp = id.exportPrivateKey();
    expect(Object.keys(exp).sort()).toEqual(['kel', 'nextRootSeed', 'rootSeed', 'signingSeed']);
    const back = SoftwareIdentity.fromExport(exp, NOW);
    expect(back.getACEId()).toBe(id.getACEId());
    await id.rotate({ now: NOW + 10 });
    expect(verifyKel(id.getKel(), NOW + 10).signing!.seq).toBe(3);
  });
  it('operational signatures: current delegation only, signed while live', async () => {
    const id = await SoftwareIdentity.generate({ now: NOW });
    const payload = new TextEncoder().encode('p');
    const sig = { scheme: 'ml-dsa-65', seq: 1, value: toBase64(await id.sign(signingMessage(id.getACEId(), NOW, 1, payload), 'packet')) };
    const state = verifyKel(id.getKel(), NOW);
    expect(() => verifyOperationalSignature(state, 'packet', NOW, payload, sig, NOW)).not.toThrow();
    expect(() => verifyOperationalSignature(state, 'delegation', NOW, payload, sig, NOW)).toThrow(expect.objectContaining({ code: 'invalid_signature' }));
    expect(() => verifyOperationalSignature(state, 'packet', NOW, payload, { ...sig, seq: 0 }, NOW)).toThrow(expect.objectContaining({ code: 'stale_peer_binding' }));
    await id.delegate({ now: NOW + 1, notAfter: NOW + 100 });
    const s2 = verifyKel(id.getKel(), NOW + 1);
    const late = { scheme: 'ml-dsa-65', seq: 2, value: toBase64(await id.sign(signingMessage(id.getACEId(), NOW + 100, 2, payload), 'packet')) };
    expect(() => verifyOperationalSignature(s2, 'packet', NOW + 100, payload, late, NOW + 1)).toThrow(expect.objectContaining({ code: 'stale_peer_binding' }));
    // signed while live, verified once the key is no longer usable (01 rule 5)
    const live = { scheme: 'ml-dsa-65', seq: 2, value: toBase64(await id.sign(signingMessage(id.getACEId(), NOW + 50, 2, payload), 'packet')) };
    expect(() => verifyOperationalSignature(s2, 'packet', NOW + 50, payload, live, NOW + 60)).not.toThrow();
    expect(() => verifyOperationalSignature(s2, 'packet', NOW + 50, payload, live, NOW + 100)).toThrow(expect.objectContaining({ code: 'stale_peer_binding' }));
  });
});
