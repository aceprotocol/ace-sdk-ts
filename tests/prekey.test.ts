// PrekeyVault lifecycle (ace-spec/04 § Prekey), mirroring sdk-py tests/test_packet.py prekey cases.
import { describe, expect, it } from 'vitest';
import { MemoryStore, OFFLINE_WINDOW_SECONDS, StorePrekeyVault, MAX_RETAINED_PREKEYS } from './sdk.js';
import { NOW } from './helpers.js';

const enc = new TextEncoder();

describe('PrekeyVault lifecycle', () => {
  it('retention runs from the moment of supersession, not creation', async () => {
    const v = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    const a = await v.rotate(NOW);
    await v.rotate(NOW + OFFLINE_WINDOW_SECONDS); // a was current for a whole window
    expect(await v.prune(NOW + OFFLINE_WINDOW_SECONDS + 10)).toBe(0);
    expect(await v.open(a.id)).not.toBeNull();
    expect(await v.prune(NOW + 2 * OFFLINE_WINDOW_SECONDS)).toBe(1);
    expect(await v.open(a.id)).toBeNull();
  });

  it('the current prekey is never pruned', async () => {
    const v = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    const a = await v.rotate(NOW);
    expect(await v.prune(NOW + 10 * OFFLINE_WINDOW_SECONDS)).toBe(0);
    expect((await v.current())!.id).toBe(a.id);
    expect(await v.open(a.id)).not.toBeNull();
  });

  it(`keeps at most ${MAX_RETAINED_PREKEYS} superseded seeds, deleting the oldest first`, async () => {
    const v = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    const ids: string[] = [];
    for (let i = 0; i < MAX_RETAINED_PREKEYS + 2; i++) ids.push((await v.rotate(NOW + i)).id);
    // current = last; superseded = the 17 before it, of which only the newest 16 are kept
    expect(await v.open(ids[0])).toBeNull();
    for (const id of ids.slice(1)) expect(await v.open(id)).not.toBeNull();
  });

  it('unknown or malformed IDs open to null; rotate validates its clock', async () => {
    const v = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    await v.rotate(NOW);
    expect(await v.open('f'.repeat(64))).toBeNull();
    expect(await v.open('NOT-HEX')).toBeNull();
    expect(await v.open('A'.repeat(64))).toBeNull();
    await expect(v.rotate(-1)).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(v.rotate(1.5)).rejects.toMatchObject({ code: 'invalid_argument' });
  });

  it('opened secrets decapsulate only 1120-byte ciphertexts', async () => {
    const v = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    const a = await v.rotate(NOW);
    const s = (await v.open(a.id))!;
    expect(s.id).toBe(a.id);
    expect(() => s.decapsulate(new Uint8Array(10))).toThrow(expect.objectContaining({ code: 'decryption_failed' }));
    expect(s.decapsulate(crypto.getRandomValues(new Uint8Array(1120)))).toHaveLength(32); // implicit rejection: a pseudorandom secret
  });

  it('persists superseded seeds and rejects a corrupt document as storage_failed', async () => {
    const store = new MemoryStore();
    const v = new StorePrekeyVault(store, { clock: () => NOW });
    const a = await v.rotate(NOW);
    const b = await v.rotate(NOW + 1);
    const again = new StorePrekeyVault(store, { clock: () => NOW });
    expect((await again.current())!.id).toBe(b.id);
    expect(await again.open(a.id)).not.toBeNull();
    await store.write('prekeys.json', enc.encode('{not json'));
    await expect(again.current()).rejects.toMatchObject({ code: 'storage_failed' });
    // a seed that does not derive its id
    const doc = { version: 1, current: { id: 'a'.repeat(64), seed: btoa('x'.repeat(32)), createdAt: NOW }, retained: [] };
    await store.write('prekeys.json', enc.encode(JSON.stringify(doc)));
    await expect(again.open('a'.repeat(64))).rejects.toMatchObject({ code: 'storage_failed' });
  });
});
