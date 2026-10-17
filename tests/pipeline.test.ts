// Receive pipeline ordering (ace-spec/06 § Receive pipeline, 05 § Receiver admission), mirroring sdk-py tests/test_inbox.py.
import { describe, expect, it, vi } from 'vitest';
import {
  CONTACT_SCHEMA_DIGEST, Inbox, MemoryStore, StorePrekeyVault, OFFLINE_WINDOW_SECONDS, RECEIPT_SCHEMA_DIGEST, sha256Hex,
  type ProfileRules,
} from './sdk.js';
import { NOW, identity } from './helpers.js';
import { inboxWorld, msg } from './helpers2.js';

const enc = new TextEncoder();

describe('receive pipeline order', () => {
  it('step 1: a packet for another identity is dropped (wrong_recipient), no receipt', async () => {
    const w = await inboxWorld();
    const other = await identity(w.clock);
    const p = await w.pack(w.sender, msg('x'));
    const out = await w.inbox.receive({ ...p, to: other.getACEId() });
    expect(out.kind).toBe('dropped');
    expect(w.receipts).toEqual([]);
  });

  it('step 1: raw bytes are decoded strictly (not JSON is dropped)', async () => {
    const w = await inboxWorld();
    expect((await w.inbox.receive(enc.encode('{nope'))).kind).toBe('dropped');
    const p = await w.pack(w.sender, msg('bytes'));
    expect((await w.inbox.receive(enc.encode(JSON.stringify(p)))).kind).toBe('delivered');
  });

  it('step 2: a blocked sender is dropped even though its KEL is pinned (no refresh, no receipt)', async () => {
    const w = await inboxWorld();
    await w.admission.update(w.sender.getACEId(), (old) => ({ ...old!, status: 'blocked' }));
    const out = await w.inbox.receive(await w.pack(w.sender, msg('x')));
    expect(out).toMatchObject({ kind: 'dropped', error: { code: 'not_permitted' } });
    expect(w.refreshPeer).not.toHaveBeenCalled();
    expect(w.receipts).toEqual([]);
    expect(w.delivered).toEqual([]);
  });

  it('step 2: a corrupt admission record is a storage failure, never treated as admitted', async () => {
    const w = await inboxWorld();
    const key = `admission/peers/${sha256Hex(w.sender.getACEId())}.json`;
    await w.store.write(key, enc.encode(JSON.stringify({ aceId: w.sender.getACEId(), status: 'bogus', updatedAt: NOW })));
    const out = await w.inbox.receive(await w.pack(w.sender, msg('x')));
    expect(out).toMatchObject({ kind: 'deferred', error: { code: 'storage_failed' } });
    expect(w.delivered).toEqual([]);
    await w.store.write(key, enc.encode('{not json'));
    expect(await w.inbox.receive(await w.pack(w.sender, msg('y')))).toMatchObject({ kind: 'deferred', error: { code: 'storage_failed' } });
    expect(w.delivered).toEqual([]);
  });

  it('step 4 before 6: a bad signature on a packet for an unknown prekey is dropped, not rejected:unknown_prekey', async () => {
    const w = await inboxWorld();
    const foreign = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    const fk = await foreign.rotate(NOW);
    const other = await identity(w.clock);
    const p = await w.pack(w.sender, msg('x'), w.clock.t, undefined, { id: fk.id, publicKey: fk.publicKey });
    const forgedSig = (await w.pack(other, msg('x'))).signature;
    const out = await w.inbox.receive({ ...p, signature: forgedSig });
    expect(out.kind).toBe('dropped');
    expect(w.receipts).toEqual([]);
  });

  it('step 5 before 6: a stale packet for an unknown prekey is dropped (stale_timestamp), not rejected', async () => {
    const w = await inboxWorld();
    w.clock.advance(OFFLINE_WINDOW_SECONDS + 10);
    const foreign = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    const fk = await foreign.rotate(NOW);
    const p = await w.pack(w.sender, msg('old'), NOW, undefined, { id: fk.id, publicKey: fk.publicKey });
    expect(await w.inbox.receive(p)).toMatchObject({ kind: 'dropped', error: { code: 'stale_timestamp' } });
    expect(w.receipts).toEqual([]);
  });

  it('step 5: more than 300 s in the future is dropped; exactly the window bounds are accepted', async () => {
    const w = await inboxWorld();
    expect((await w.inbox.receive(await w.pack(w.sender, msg('future'), w.clock.t + 301))).kind).toBe('dropped');
    expect((await w.inbox.receive(await w.pack(w.sender, msg('edge'), w.clock.t + 300))).kind).toBe('delivered');
    w.clock.advance(OFFLINE_WINDOW_SECONDS);
    expect((await w.inbox.receive(await w.pack(w.sender, msg('oldest'), w.clock.t - OFFLINE_WINDOW_SECONDS))).kind).toBe('delivered');
  });

  it('step 6: an unknown prekey is answered rejected:unknown_prekey', async () => {
    const w = await inboxWorld();
    const foreign = new StorePrekeyVault(new MemoryStore(), { clock: () => NOW });
    const fk = await foreign.rotate(NOW);
    const p = await w.pack(w.sender, msg('x'), w.clock.t, undefined, { id: fk.id, publicKey: fk.publicKey });
    expect(await w.inbox.receive(p)).toMatchObject({ kind: 'rejected', error: { code: 'unknown_prekey' } });
    expect(w.receipts).toEqual([[w.sender.getACEId(), { messageId: p.messageId, outcome: 'rejected', code: 'unknown_prekey', prekey: fk.id }]]);
    expect(w.delivered).toEqual([]);
  });

  it('step 6: a retained (superseded) prekey still decrypts', async () => {
    const w = await inboxWorld();
    await w.vault.rotate(NOW + 1);
    expect((await w.inbox.receive(await w.pack(w.sender, msg('old prekey'))))).toMatchObject({ kind: 'delivered' });
  });

  it('steps 7-8: receipts and contacts with an invalid body are dropped, never answered', async () => {
    const w = await inboxWorld();
    const badReceipt = { type: 'ace:receipt:1', schemaDigest: RECEIPT_SCHEMA_DIGEST, body: { messageId: crypto.randomUUID(), outcome: 'rejected' } };
    expect((await w.inbox.receive(await w.pack(w.sender, badReceipt))).kind).toBe('dropped');
    const badContact = { type: 'ace:contact:1', schemaDigest: CONTACT_SCHEMA_DIGEST, body: { kind: 'request', profile: 'ace:text:1', note: '', source: { kel: [], descriptor: {} }, permit: {} } };
    expect((await w.inbox.receive(await w.pack(w.sender, badContact))).kind).toBe('dropped');
    expect(w.receipts).toEqual([]);
  });

  it('contact packets have the ordinary time window: older than the offline window is stale_timestamp', async () => {
    const w = await inboxWorld();
    w.clock.advance(604_801);
    const contact = { type: 'ace:contact:1', schemaDigest: CONTACT_SCHEMA_DIGEST, body: { kind: 'request', profile: 'ace:text:1', note: '', source: { kel: [], descriptor: {} }, permit: {} } };
    expect(await w.inbox.receive(await w.pack(w.sender, contact, NOW))).toMatchObject({ kind: 'dropped', error: { code: 'stale_timestamp' } });
    expect(w.receipts).toEqual([]);
  });

  it('step 9 before 10: a duplicate is answered delivered without re-running profile rules', async () => {
    const check = vi.fn(), commit = vi.fn();
    const rules: ProfileRules[] = [{ types: ['ace:text:1'], check, commit }];
    const w = await inboxWorld({ rules });
    const p = await w.pack(w.sender, msg('once'));
    expect((await w.inbox.receive(p)).kind).toBe('delivered');
    // the rule would now refuse anything: a re-sent copy must still be answered delivered
    check.mockImplementation(() => { throw Object.assign(new Error('x'), { code: 'transition_not_allowed' }); });
    expect((await w.inbox.receive(p)).kind).toBe('duplicate');
    expect(check).toHaveBeenCalledTimes(1);
    expect(commit).toHaveBeenCalledTimes(1);
    expect(w.receipts.map(([, b]) => b.outcome)).toEqual(['delivered', 'delivered']);
    expect(w.delivered).toHaveLength(1);
  });

  it('step 10: a profile rule failure is answered rejected:<code> and nothing is committed', async () => {
    const { ACEError } = await import('./sdk.js');
    const commit = vi.fn();
    const rules: ProfileRules[] = [{ types: ['ace:text:1'], check: () => { throw new ACEError('wrong_role', 'no'); }, commit }];
    const w = await inboxWorld({ rules });
    const p = await w.pack(w.sender, msg('x'));
    expect(await w.inbox.receive(p)).toMatchObject({ kind: 'rejected', error: { code: 'wrong_role' } });
    expect(commit).not.toHaveBeenCalled();
    expect(w.delivered).toEqual([]);
    expect(w.receipts.at(-1)![1]).toMatchObject({ outcome: 'rejected', code: 'wrong_role' });
  });

  it('step 3: a newer delegation refreshes the pin at most once per sender per 30 s', async () => {
    const w = await inboxWorld();
    await w.sender.delegate({ now: w.clock.t }); // the pin still names the old delegation
    const first = await w.inbox.receive(await w.pack(w.sender, msg('1')));
    expect(w.refreshPeer).toHaveBeenCalledTimes(1);
    expect(first.kind).toBe('dropped'); // the refresh brought nothing newer: stale_peer_binding
    w.clock.advance(10);
    const second = await w.inbox.receive(await w.pack(w.sender, msg('2')));
    expect(w.refreshPeer).toHaveBeenCalledTimes(1);
    expect(second.kind).toBe('deferred'); // suppressed refresh: retry later (06 step 3)
    w.clock.advance(21);
    await w.peers.adopt(w.sender.getKel()); // the relay now serves the new log
    const third = await w.inbox.receive(await w.pack(w.sender, msg('3')));
    expect(third.kind).toBe('delivered');
  });

  it('step 3/4: a packet naming an older delegation than the pin is dropped without any refresh', async () => {
    const w = await inboxWorld();
    const old = await w.pack(w.sender, msg('old key'));
    await w.sender.delegate({ now: w.clock.t });
    await w.peers.adopt(w.sender.getKel());
    expect(await w.inbox.receive(old)).toMatchObject({ kind: 'dropped', error: { code: 'stale_peer_binding' } });
    expect(w.refreshPeer).not.toHaveBeenCalled();
    expect(w.delivered).toEqual([]);
  });

  it('restart: the seen store survives close/open, so a re-delivered message is a duplicate', async () => {
    const w = await inboxWorld();
    const p = await w.pack(w.sender, msg('persist'));
    expect((await w.inbox.receive(p)).kind).toBe('delivered');
    await w.inbox.close();
    const again = await Inbox.open(w.options);
    expect((await again.receive(p)).kind).toBe('duplicate');
    expect(w.delivered).toHaveLength(1);
    await again.close();
  });

  it('one Inbox per store: a second open is lock_busy', async () => {
    const w = await inboxWorld();
    await expect(Inbox.open(w.options)).rejects.toMatchObject({ code: 'lock_busy' });
  });
});
