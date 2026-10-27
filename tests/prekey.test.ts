// PrekeyVault lifecycle (ace-spec/04 § Prekey), mirroring sdk-py tests/test_packet.py prekey cases.
import { describe, expect, it } from 'vitest';
import { MemoryStore, OFFLINE_WINDOW_SECONDS, StorePrekeyVault, MAX_RETAINED_PREKEYS, prekeyId, prekeyPublicKey, toBase64, type Prekey } from './sdk.js';
import { NOW } from './helpers.js';

const enc = new TextEncoder();
const W = OFFLINE_WINDOW_SECONDS;
/** Senders: open() looks for peer prekeys only under the packet's sender. */
const A = `ace:sha256:${'a'.repeat(64)}`, B = `ace:sha256:${'b'.repeat(64)}`, C = `ace:sha256:${'c'.repeat(64)}`;
const PIN = '1'.repeat(64), OTHER_PIN = '2'.repeat(64);
const somePeerKey = (): Prekey => {
  const pk = prekeyPublicKey(crypto.getRandomValues(new Uint8Array(32)));
  return { id: prekeyId(pk), publicKey: toBase64(pk) };
};
/** A vault on its own store whose `open` clock is `t.now`. */
const vaultAt = () => {
  const t = { now: NOW }, store = new MemoryStore();
  return { t, store, v: new StorePrekeyVault(store, { clock: () => t.now }) };
};
const docOf = async (store: MemoryStore) => JSON.parse(new TextDecoder().decode((await store.read('prekeys.json'))!));

describe('PrekeyVault lifecycle', () => {
  it('retention runs from the moment of supersession, not creation', async () => {
    const v = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    const a = await v.rotate(NOW);
    await v.rotate(NOW + OFFLINE_WINDOW_SECONDS); // a was current for a whole window
    expect(await v.prune(NOW + OFFLINE_WINDOW_SECONDS + 10)).toBe(0);
    expect(await v.open(a.id, A)).not.toBeNull();
    expect(await v.prune(NOW + 2 * OFFLINE_WINDOW_SECONDS)).toBe(1);
    expect(await v.open(a.id, A)).toBeNull();
  });

  it('the current prekey is never pruned', async () => {
    const v = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    const a = await v.rotate(NOW);
    expect(await v.prune(NOW + 10 * OFFLINE_WINDOW_SECONDS)).toBe(0);
    expect((await v.current())!.id).toBe(a.id);
    expect(await v.open(a.id, A)).not.toBeNull();
  });

  it(`keeps at most ${MAX_RETAINED_PREKEYS} superseded seeds, deleting the oldest first`, async () => {
    const v = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    const ids: string[] = [];
    for (let i = 0; i < MAX_RETAINED_PREKEYS + 2; i++) ids.push((await v.rotate(NOW + i)).id);
    // current = last; superseded = the 17 before it, of which only the newest 16 are kept
    expect(await v.open(ids[0], A)).toBeNull();
    for (const id of ids.slice(1)) expect(await v.open(id, A)).not.toBeNull();
  });

  it('unknown or malformed IDs open to null; rotate validates its clock', async () => {
    const v = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    await v.rotate(NOW);
    expect(await v.open('f'.repeat(64), A)).toBeNull();
    expect(await v.open('NOT-HEX', A)).toBeNull();
    expect(await v.open('A'.repeat(64), A)).toBeNull();
    await expect(v.rotate(-1)).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(v.rotate(1.5)).rejects.toMatchObject({ code: 'invalid_argument' });
  });

  it('opened secrets decapsulate only 1120-byte ciphertexts', async () => {
    const v = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    const a = await v.rotate(NOW);
    const s = (await v.open(a.id, A))!;
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
    expect(await again.open(a.id, A)).not.toBeNull();
    await store.write('prekeys.json', enc.encode('{not json'));
    await expect(again.current()).rejects.toMatchObject({ code: 'storage_failed' });
    // a seed that does not derive its id
    const doc = { version: 2, current: { id: 'a'.repeat(64), seed: btoa('x'.repeat(32)), createdAt: NOW }, retained: [], peers: {} };
    await store.write('prekeys.json', enc.encode(JSON.stringify(doc)));
    await expect(again.open('a'.repeat(64), A)).rejects.toMatchObject({ code: 'storage_failed' });
  });
});

describe('PrekeyVault peer prekeys (04 § Peer prekeys)', () => {
  it('the offered key is stable until used; then it is in use (only for that peer) and the next offer is fresh', async () => {
    const { v } = vaultAt();
    const k1 = await v.offer(B, NOW);
    expect(await v.offer(B, NOW + 5)).toEqual(k1);
    expect(k1.id).toBe(prekeyId(Uint8Array.from(atob(k1.publicKey), (c) => c.charCodeAt(0))));
    expect(await v.open(k1.id, B)).not.toBeNull();
    await v.used(B, k1.id, NOW + 5);
    const k2 = await v.offer(B, NOW + 6);
    expect(k2.id).not.toBe(k1.id);
    expect((await v.open(k1.id, B))!.id).toBe(k1.id);
    expect(await v.open(k1.id, C)).toBeNull();
    expect(await v.open(k2.id, C)).toBeNull();
    expect(await v.offer(C, NOW)).not.toEqual(k2); // per peer
  });

  it('a newer key in use deletes the previous one', async () => {
    const { v } = vaultAt();
    const k1 = await v.offer(B, NOW);
    await v.used(B, k1.id, NOW);
    const k2 = await v.offer(B, NOW);
    await v.used(B, k2.id, NOW);
    expect(await v.open(k1.id, B)).toBeNull();
    expect(await v.open(k2.id, B)).not.toBeNull();
  });

  it('using the in-use key again, or an unknown ID, changes nothing', async () => {
    const { v } = vaultAt();
    const k1 = await v.offer(B, NOW);
    await v.used(B, k1.id, NOW);
    const k2 = await v.offer(B, NOW);
    await v.used(B, k1.id, NOW + 1);
    await v.used(B, 'f'.repeat(64), NOW + 1);
    await v.used(C, k2.id, NOW + 1);
    expect(await v.open(k1.id, B)).not.toBeNull();
    expect(await v.offer(B, NOW + 2)).toEqual(k2);
  });

  it('peer seeds open while now < offeredAt + W; an offer restarts the window, an expired offer is replaced', async () => {
    const { t, v } = vaultAt();
    const k1 = await v.offer(B, NOW);
    expect(await v.offer(B, NOW + W - 1)).toEqual(k1); // window restarts at NOW + W - 1
    t.now = NOW + W;
    expect(await v.open(k1.id, B)).not.toBeNull();
    t.now = NOW + 2 * W - 1;
    expect(await v.open(k1.id, B)).toBeNull();
    const k2 = await v.offer(B, NOW + 2 * W - 1);
    expect(k2.id).not.toBe(k1.id);
    await v.used(B, k2.id, NOW + 2 * W - 1);
    t.now = NOW + 3 * W - 1;
    expect(await v.open(k2.id, B)).toBeNull(); // in use: same window from its last offer
  });

  it('hold keeps the key from the newest packet', async () => {
    const { v } = vaultAt();
    const p1 = somePeerKey(), p2 = somePeerKey(), p3 = somePeerKey();
    await v.hold(A, p1, NOW - 10, PIN);
    await v.hold(A, p2, NOW - 20, PIN);
    expect(await v.held(A, PIN, NOW)).toEqual(p1);
    await v.hold(A, p2, NOW - 10, PIN); // not newer
    expect(await v.held(A, PIN, NOW)).toEqual(p1);
    await v.hold(A, p3, NOW - 9, PIN);
    expect(await v.held(A, PIN, NOW)).toEqual(p3);
    expect(await v.held(B, PIN, NOW)).toBeNull();
  });

  it('held is bound to the pin and the window; a mismatch deletes it', async () => {
    const { v } = vaultAt();
    const p = somePeerKey();
    await v.hold(A, p, NOW, PIN);
    expect(await v.held(A, OTHER_PIN, NOW)).toBeNull();
    expect(await v.held(A, PIN, NOW)).toBeNull(); // deleted
    await v.hold(A, p, NOW, PIN);
    expect(await v.held(A, PIN, NOW + W - 1)).toEqual(p);
    expect(await v.held(A, PIN, NOW + W)).toBeNull();
    await v.hold(A, p, NOW - 1, PIN); // nothing held any more: an older packet's key is held again
    expect(await v.held(A, PIN, NOW)).toEqual(p);
  });

  it('dropHeld deletes the held key only', async () => {
    const { v } = vaultAt();
    const k = await v.offer(A, NOW);
    await v.hold(A, somePeerKey(), NOW, PIN);
    await v.dropHeld(A);
    await v.dropHeld(B);
    expect(await v.held(A, PIN, NOW)).toBeNull();
    expect(await v.offer(A, NOW)).toEqual(k);
  });

  it('prune deletes expired peer seeds and held keys, then empty peers; published seeds as before', async () => {
    const { store, v } = vaultAt();
    await v.rotate(NOW);
    const k = await v.offer(A, NOW);
    await v.used(A, k.id, NOW);
    await v.offer(A, NOW + 10);
    await v.hold(B, somePeerKey(), NOW + 20, PIN);
    await v.prune(NOW + W);
    expect(Object.keys((await docOf(store)).peers)).toEqual([A, B]);
    expect((await docOf(store)).peers[A].inUse).toBeNull();
    await v.prune(NOW + W + 10);
    expect(Object.keys((await docOf(store)).peers)).toEqual([B]);
    expect(await v.prune(NOW + W + 20)).toBe(0);
    expect((await docOf(store)).peers).toEqual({});
    expect(await v.current()).not.toBeNull();
  });

  it('stores the version 2 document of 04 § Peer prekeys', async () => {
    const { store, v } = vaultAt();
    const k = await v.offer(A, NOW);
    await v.used(A, k.id, NOW);
    await v.offer(A, NOW + 1);
    const p = somePeerKey();
    await v.hold(A, p, NOW + 2, PIN);
    const d = await docOf(store);
    expect(Object.keys(d).sort()).toEqual(['current', 'peers', 'retained', 'version']);
    expect(d.version).toBe(2);
    expect(Object.keys(d.peers[A]).sort()).toEqual(['held', 'inUse', 'offered']);
    expect(Object.keys(d.peers[A].offered).sort()).toEqual(['offeredAt', 'seed']);
    expect(d.peers[A].offered.offeredAt).toBe(NOW + 1);
    expect(d.peers[A].inUse.offeredAt).toBe(NOW);
    expect(d.peers[A].held).toEqual({ publicKey: p.publicKey, timestamp: NOW + 2, pin: PIN });
    // reloads from the document
    const again = new StorePrekeyVault(store, { clock: () => NOW });
    expect((await again.open(k.id, A))!.id).toBe(k.id);
    expect(await again.held(A, PIN, NOW)).toEqual(p);
  });

  it('a version 1 or malformed document is storage_failed', async () => {
    const { store, v } = vaultAt();
    await store.write('prekeys.json', enc.encode(JSON.stringify({ version: 1, current: null, retained: [] })));
    await expect(v.current()).rejects.toMatchObject({ code: 'storage_failed' });
    await store.write('prekeys.json', enc.encode(JSON.stringify({ version: 2, current: null, retained: [] })));
    await expect(v.offer(A, NOW)).rejects.toMatchObject({ code: 'storage_failed' });
    await store.write('prekeys.json', enc.encode(JSON.stringify({ version: 2, current: null, retained: [], peers: { 'not-an-ace-id': { offered: null, inUse: null, held: null } } })));
    await expect(v.offer(A, NOW)).rejects.toMatchObject({ code: 'storage_failed' });
    await store.write('prekeys.json', enc.encode(JSON.stringify({ version: 2, current: null, retained: [], peers: { [A]: { offered: null, inUse: null, held: { publicKey: 'QQ==', timestamp: NOW, pin: PIN } } } })));
    await expect(v.held(A, PIN, NOW)).rejects.toMatchObject({ code: 'storage_failed' });
  });

  it('a held.publicKey of the wrong length is storage_failed', async () => {
    const { store, v } = vaultAt();
    const short = toBase64(new Uint8Array(1215).fill(1));
    await store.write('prekeys.json', enc.encode(JSON.stringify({ version: 2, current: null, retained: [], peers: { [A]: { offered: null, inUse: null, held: { publicKey: short, timestamp: NOW, pin: PIN } } } })));
    await expect(v.held(A, PIN, NOW)).rejects.toMatchObject({ code: 'storage_failed' });
    await expect(v.current()).rejects.toMatchObject({ code: 'storage_failed' });
  });

  it('protect seals the whole document, peer state included', async () => {
    const store = new MemoryStore();
    const seal = { seal: async (b: Uint8Array) => b.map((x) => x ^ 0x5a), open: async (b: Uint8Array) => b.map((x) => x ^ 0x5a) };
    const v = new StorePrekeyVault(store, { protect: seal, clock: () => NOW });
    const k = await v.offer(A, NOW);
    await v.hold(A, somePeerKey(), NOW, PIN);
    const raw = new TextDecoder().decode((await store.read('prekeys.json'))!);
    expect(raw).not.toContain('peers');
    expect(raw).not.toContain(A);
    expect(await new StorePrekeyVault(store, { protect: seal, clock: () => NOW }).offer(A, NOW)).toEqual(k);
  });

  it('arguments are checked (invalid_argument)', async () => {
    const { v } = vaultAt();
    const p = somePeerKey();
    await expect(v.offer('bob', NOW)).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(v.offer(A, -1)).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(v.used(A, 'f'.repeat(64), 1.5)).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(v.hold(A, p, NOW, 'PIN')).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(v.hold(A, { ...p, id: 'f'.repeat(64) }, NOW, PIN)).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(v.hold(A, p, -1, PIN)).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(v.held('bob', PIN, NOW)).rejects.toMatchObject({ code: 'invalid_argument' });
    await expect(v.dropHeld('bob')).rejects.toMatchObject({ code: 'invalid_argument' });
  });
});
