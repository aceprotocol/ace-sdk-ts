import { describe, expect, it } from 'vitest';
import {
  MemoryStore, ProfileSet, StorePrekeyVault, createPacket, decodePacket, decryptPacket,
  signingMessage, toBase64, parsePacket, MAX_PACKET_BYTES, MAX_PLAINTEXT_BYTES, OFFLINE_WINDOW_SECONDS, type PrivateContent,
} from './sdk.js';
import { packetSignPayload } from '../src/packet.js';
import { NOW, identity, stateOf } from './helpers.js';
import { openPacket } from './helpers2.js';

const text = new ProfileSet(['text']);
const content = (message: string): PrivateContent => ({ type: 'ace:text:1', schemaDigest: text.digestOf('ace:text:1')!, body: { message } });

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

describe('PrekeyVault', () => {
  it('rotates, retains superseded seeds for the offline window, keeps at most 16', async () => {
    const vault = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    expect(await vault.current()).toBeNull();
    const first = await vault.rotate(NOW);
    const second = await vault.rotate(NOW + 10);
    expect((await vault.current())!.id).toBe(second.id);
    expect(await vault.open(first.id)).not.toBeNull();
    expect(await vault.prune(NOW + 10 + OFFLINE_WINDOW_SECONDS - 1)).toBe(0);
    expect(await vault.prune(NOW + 10 + OFFLINE_WINDOW_SECONDS)).toBe(1);
    expect(await vault.open(first.id)).toBeNull();
    const ids: string[] = [];
    for (let i = 0; i < 20; i++) ids.push((await vault.rotate(NOW + 100 + i)).id);
    expect(await vault.open(ids[0])).toBeNull();
    expect(await vault.open(ids[2])).toBeNull();
    expect(await vault.open(ids[3])).not.toBeNull();
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
