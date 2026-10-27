import { describe, expect, it } from 'vitest';
import {
  MemoryStore, ProfileSet, StorePrekeyVault, canonicalStateBytes, createPacket, decodePacket, decodePrivateContent, decryptPacket,
  encodePrivateContent, fromBase64, signingMessage, toBase64, parsePacket,
  MAX_PACKET_BYTES, MAX_PLAINTEXT_BYTES, OFFLINE_WINDOW_SECONDS, type PrivateContent,
} from './sdk.js';
import { packetSignPayload } from '../src/packet.js';
import { NOW, identity, stateOf } from './helpers.js';
import { openPacket, somePrekey } from './helpers2.js';

const text = new ProfileSet(['text']);
const PEER_PREKEY = somePrekey();
/** The packet sender `open` is asked for (peer prekeys are looked up under it). */
const SENDER = `ace:sha256:${'a'.repeat(64)}`;
const content = (message: string): PrivateContent => ({ type: 'ace:text:1', schemaDigest: text.digestOf('ace:text:1')!, body: { message }, prekey: PEER_PREKEY });
const code = (fn: () => unknown): string | null => {
  try { fn(); } catch (e) { return (e as { code?: string }).code ?? String(e); }
  return null;
};

async function setup() {
  const alice = await identity(), bob = await identity(), mallory = await identity();
  const vault = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
  const pk = await vault.rotate(NOW);
  return { alice, bob, mallory, vault, prekey: { id: pk.id, publicKey: pk.publicKey } };
}

describe('packet', () => {
  it('round-trips', async () => {
    const { alice, bob, vault, prekey } = await setup();
    const p = await createPacket({ identity: alice, to: bob.getACEId(), prekey, content: { ...content('hi'), threadId: 't1' }, timestamp: NOW });
    expect(Object.keys(p).sort()).toEqual(['ace', 'encryption', 'from', 'messageId', 'signature', 'timestamp', 'to']);
    expect(p.ace).toBe('1');
    const { content: c } = await openPacket(JSON.parse(JSON.stringify(p)), { recipient: bob.getACEId(), sender: stateOf(alice), vault, now: NOW });
    expect(c).toEqual({ ...content('hi'), threadId: 't1' });
  });

  it('a re-signed packet under another identity fails to decrypt (header binds from)', async () => {
    const { alice, bob, mallory, vault, prekey } = await setup();
    const p = await createPacket({ identity: alice, to: bob.getACEId(), prekey, content: content('secret'), timestamp: NOW });
    const forged = { ...p, from: mallory.getACEId(), signature: { ...p.signature } };
    forged.signature.value = toBase64(await mallory.sign(signingMessage(forged.from, forged.timestamp, forged.signature.seq, packetSignPayload(forged)), 'packet'));
    await expect(openPacket(forged, { recipient: bob.getACEId(), sender: stateOf(mallory), vault, now: NOW })).rejects.toMatchObject({ code: 'decryption_failed' });
    await expect(openPacket(p, { recipient: bob.getACEId(), sender: stateOf(mallory), vault, now: NOW })).rejects.toMatchObject({ code: 'invalid_signature' });
  });

  it('decoding is closed and versioned', async () => {
    const { alice, bob, prekey } = await setup();
    const p = await createPacket({ identity: alice, to: bob.getACEId(), prekey, content: content('x'), timestamp: NOW });
    expect(() => decodePacket({ ...p, conversationId: 'a'.repeat(64) })).toThrow(expect.objectContaining({ code: 'invalid_packet' }));
    expect(() => decodePacket({ ...p, encryption: { ...p.encryption, extra: 1 } })).toThrow(expect.objectContaining({ code: 'invalid_packet' }));
    expect(() => decodePacket({ ...p, ace: '2.0' })).toThrow(expect.objectContaining({ code: 'unsupported_version' }));
    expect(() => decodePacket({ ...p, ace: '3' })).toThrow(expect.objectContaining({ code: 'unsupported_version' }));
    expect(() => decodePacket({ ...p, to: p.from })).toThrow(expect.objectContaining({ code: 'invalid_packet' }));
    // 03 § Decoding: an oversize packet or payload is invalid_packet, never limit_exceeded
    const huge = 'A'.repeat(4 * Math.ceil((MAX_PLAINTEXT_BYTES + 29) / 3));
    expect(() => decodePacket({ ...p, encryption: { ...p.encryption, payload: huge } })).toThrow(expect.objectContaining({ code: 'invalid_packet' }));
    expect(() => parsePacket(new Uint8Array(2 * MAX_PACKET_BYTES + 1))).toThrow(expect.objectContaining({ code: 'invalid_packet' }));
    await expect(openPacket(p, { recipient: alice.getACEId(), sender: stateOf(alice), vault: new StorePrekeyVault(new MemoryStore(), { clock: () => NOW }), now: NOW })).rejects.toMatchObject({ code: 'wrong_recipient' });
    await expect(openPacket(p, { recipient: bob.getACEId(), sender: stateOf(alice), vault: new StorePrekeyVault(new MemoryStore(), { clock: () => NOW }), now: NOW + OFFLINE_WINDOW_SECONDS + 1 })).rejects.toMatchObject({ code: 'stale_timestamp' });
  });

  it('a deleted prekey is unknown_prekey', async () => {
    const { alice, bob, prekey } = await setup();
    const p = await createPacket({ identity: alice, to: bob.getACEId(), prekey, content: content('x'), timestamp: NOW });
    await expect(decryptPacket(p, new StorePrekeyVault(new MemoryStore(), { clock: () => NOW }))).rejects.toMatchObject({ code: 'unknown_prekey' });
  });
});

describe('payload bounds (03 § Decoding)', () => {
  it('a decoded payload is at least nonce + tag (invalid_packet)', async () => {
    const { alice, bob, prekey } = await setup();
    const p = await createPacket({ identity: alice, to: bob.getACEId(), prekey, content: content('x'), timestamp: NOW });
    expect(decodePacket(JSON.parse(JSON.stringify(p))).encryption.payload).toBe(p.encryption.payload);
    const withPayload = (n: number) => ({ ...p, encryption: { ...p.encryption, payload: toBase64(new Uint8Array(n)) } });
    expect(code(() => decodePacket(withPayload(27)))).toBe('invalid_packet');
    expect(code(() => decodePacket(withPayload(28)))).toBeNull();
  });

  it('the payload is the content plus nonce and tag', async () => {
    const { alice, bob, prekey } = await setup();
    const p = await createPacket({ identity: alice, to: bob.getACEId(), prekey, content: content('x'), timestamp: NOW });
    expect(fromBase64(p.encryption.payload).length).toBe(encodePrivateContent(content('x')).length + 28);
  });

  it('the largest content fits MAX_PACKET_BYTES', async () => {
    const { alice, bob, vault, prekey } = await setup();
    const base = content('');
    const c = content('x'.repeat(MAX_PLAINTEXT_BYTES - canonicalStateBytes(base).length));
    expect(encodePrivateContent(c).length).toBe(MAX_PLAINTEXT_BYTES);
    const p = await createPacket({ identity: alice, to: bob.getACEId(), prekey, content: c, timestamp: NOW });
    expect(canonicalStateBytes(p).length).toBeLessThanOrEqual(MAX_PACKET_BYTES);
    expect(decodePrivateContent(await decryptPacket(decodePacket(JSON.parse(JSON.stringify(p))), vault))).toEqual(c);
  });
});

describe('private content prekey (04 § Peer prekeys)', () => {
  const { prekey: _p, ...without } = content('x');
  it('round-trips the offered prekey', () => {
    expect(decodePrivateContent(encodePrivateContent(content('x')))).toEqual(content('x'));
  });
  it('encoding content without a prekey, or with a malformed one, is invalid_argument', () => {
    expect(code(() => encodePrivateContent(without as PrivateContent))).toBe('invalid_argument');
    expect(code(() => encodePrivateContent({ ...without, prekey: 'QQ==' }))).toBe('invalid_argument');
    expect(code(() => encodePrivateContent({ ...without, prekey: toBase64(new Uint8Array(1215)) }))).toBe('invalid_argument');
  });
  it('createPacket refuses content without a prekey (invalid_argument)', async () => {
    const { alice, bob, prekey } = await setup();
    await expect(createPacket({ identity: alice, to: bob.getACEId(), prekey, content: without as PrivateContent, timestamp: NOW })).rejects.toMatchObject({ code: 'invalid_argument' });
  });
  it('decoding content without a prekey, or with a malformed one, is invalid_body', () => {
    expect(code(() => decodePrivateContent(canonicalStateBytes(without)))).toBe('invalid_body');
    expect(code(() => decodePrivateContent(canonicalStateBytes({ ...without, prekey: 'QQ==' })))).toBe('invalid_body');
    expect(code(() => decodePrivateContent(canonicalStateBytes({ ...without, prekey: null })))).toBe('invalid_body');
  });
  it('a prekey in non-canonical Base64 is invalid_body', () => {
    // 1216 bytes leave one byte in the last quantum: its second character carries 4 zero bits.
    const pk = new Uint8Array(1216).fill(0x41), b64 = toBase64(pk);
    expect(b64.endsWith('QQ==')).toBe(true);
    for (const bad of [`${b64.slice(0, -4)}QR==`, b64.slice(0, -2), `${b64.slice(0, -4)}QQ=`, `${b64.slice(0, -4)}Q Q==`]) {
      expect(code(() => decodePrivateContent(canonicalStateBytes({ ...without, prekey: bad })))).toBe('invalid_body');
    }
    expect(decodePrivateContent(canonicalStateBytes({ ...without, prekey: b64 })).prekey).toBe(b64);
  });
});

describe('PrekeyVault', () => {
  it('rotates, retains superseded seeds for the offline window, keeps at most 16', async () => {
    const vault = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    expect(await vault.current()).toBeNull();
    const first = await vault.rotate(NOW);
    const second = await vault.rotate(NOW + 10);
    expect((await vault.current())!.id).toBe(second.id);
    expect(await vault.open(first.id, SENDER)).not.toBeNull();
    expect(await vault.prune(NOW + 10 + OFFLINE_WINDOW_SECONDS - 1)).toBe(0);
    expect(await vault.prune(NOW + 10 + OFFLINE_WINDOW_SECONDS)).toBe(1);
    expect(await vault.open(first.id, SENDER)).toBeNull();
    const ids: string[] = [];
    for (let i = 0; i < 20; i++) ids.push((await vault.rotate(NOW + 100 + i)).id);
    expect(await vault.open(ids[0], SENDER)).toBeNull();
    expect(await vault.open(ids[2], SENDER)).toBeNull();
    expect(await vault.open(ids[3], SENDER)).not.toBeNull();
  });

  it('persists through a store, optionally sealed', async () => {
    const store = new MemoryStore();
    const seal = { seal: async (b: Uint8Array) => b.map((x) => x ^ 0x5a), open: async (b: Uint8Array) => b.map((x) => x ^ 0x5a) };
    const a = new StorePrekeyVault(store, { protect: seal, clock: () => NOW });
    const k = await a.rotate(NOW);
    expect(new TextDecoder().decode((await store.read('prekeys.json'))!)).not.toContain(k.id);
    expect((await new StorePrekeyVault(store, { protect: seal, clock: () => NOW }).current())!.id).toBe(k.id);
  });
});
