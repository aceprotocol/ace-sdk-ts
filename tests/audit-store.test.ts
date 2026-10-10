import { describe, it, expect } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLog, AuditWitness, AuditTree, MemoryStore, ACEError, SoftwareIdentity, auditCommitment,
  createAuditCheckpoint, verifyAuditInclusion, verifyAuditConsistency, verifyAuditWitnessQuorum,
  createAuditWitnessReceipt, verifyAuditWitnessReceipt, auditCheckpointDigest } from '../src/index.js';
import { FileStore } from '../src/node.js';
import { agent, peerOf, expectCode } from './helpers.js';
const logId = '550e8400-e29b-41d4-a716-446655440000';
const signer = agent('alice'), operator = peerOf(signer), witnessSigner = agent('bob'), witness = peerOf(witnessSigner);
const cs = Array.from({ length: 36 }, (_, i) => auditCommitment(Uint8Array.of(i), new Uint8Array(32)));
const config = { logId, signer, operator, clock: () => 100 };
const wc = { logId, operator, signer: witnessSigner, witness, clock: () => 101 };

class BrokenStore extends MemoryStore {
  remaining = Infinity; after = false;
  override async write(k: string, b: Uint8Array) {
    if (--this.remaining === 0 && !this.after) throw new ACEError('storage_failed');
    await super.write(k, b);
    if (this.remaining === 0 && this.after) throw new ACEError('storage_failed');
  }
  override async delete(k: string) {
    if (--this.remaining === 0 && !this.after) throw new ACEError('storage_failed');
    await super.delete(k);
    if (this.remaining === 0 && this.after) throw new ACEError('storage_failed');
  }
}

describe('durable audit log', () => {
  it('builds incremental balanced and unbalanced trees with every historical proof', async () => {
    const log = new AuditLog(config, new MemoryStore());
    const first = await log.provision();
    expect(first.size).toBe(0);
    for (let n = 1; n <= cs.length; n++) {
      const appended = await log.append(cs[n - 1]);
      expect(appended.index).toBe(n - 1);
      const tree = new AuditTree(cs.slice(0, n));
      expect(appended.checkpoint.root).toBe(tree.root());
      expect(verifyAuditInclusion(cs[n - 1], n - 1, n, tree.root(), appended.proof)).toBe(true);
      for (let m = 0; m <= n; m++) {
        const got = await log.consistency(m, n);
        expect(got.proof).toEqual(tree.consistency(m));
        expect(verifyAuditConsistency(m, n, tree.root(m), tree.root(), got.proof)).toBe(true);
      }
    }
    for (let size = 1; size <= cs.length; size++) {
      const tree = new AuditTree(cs.slice(0, size));
      for (let i = 0; i < size; i++) {
        const r = await log.inclusion(i, size);
        expect(r.proof).toEqual(tree.inclusion(i));
        expect(r.checkpoint.root).toBe(tree.root());
      }
    }
  }, 20_000);
  it('serializes multiple instances and never duplicates the same commitment', async () => {
    const store = new MemoryStore(), a = new AuditLog(config, store), b = new AuditLog(config, store);
    await a.provision();
    const out = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? a : b).append(cs[i % 5])));
    expect((await a.checkpoint()).size).toBe(5);
    for (let i = 0; i < 5; i++) expect(new Set(out.filter((_, n) => n % 5 === i).map(x => x.index)).size).toBe(1);
  });
  it.each([false, true])('recovers crashes at every append write boundary (after=%s)', async after => {
    for (let failAt = 1; failAt <= 9; failAt++) {
      const store = new BrokenStore(), log = new AuditLog(config, store);
      await log.provision(); for (const c of cs.slice(0, 3)) await log.append(c);
      store.after = after; store.remaining = failAt;
      await log.append(cs[3]).catch(e => expect(e.code).toBe('storage_failed'));
      store.remaining = Infinity;
      const recovered = new AuditLog(config, store), result = await recovered.append(cs[3]);
      expect(result.index).toBe(3); expect(result.checkpoint.size).toBe(4);
      expect(result.checkpoint.root).toBe(new AuditTree(cs.slice(0, 4)).root());
      expect((await recovered.append(cs[3])).index).toBe(3);
    }
  });
  it('persists across FileStore instances and rejects missing/corrupt heads without resetting', async () => {
    const root = await mkdtemp(join(tmpdir(), 'ace-audit-'));
    try {
      const log = new AuditLog(config, new FileStore(root)); await log.provision(); await log.append(cs[0]);
      const reopened = new AuditLog(config, new FileStore(root));
      expect((await reopened.append(cs[0])).checkpoint.size).toBe(1);
      await expectCode(reopened.provision(), 'invalid_argument');
      const store = new FileStore(root);
      await store.delete(`audit-log/${logId}/head`);
      await expectCode(reopened.append(cs[1]), 'storage_failed');
      await expectCode(reopened.provision(), 'invalid_argument');
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  it('rejects altered nodes, foreign operator, malformed inputs and backwards clocks', async () => {
    const store = new MemoryStore(), log = new AuditLog(config, store);
    await log.provision(); await log.append(cs[0]);
    await expectCode(log.append('private plaintext'), 'invalid_argument');
    await expectCode(log.inclusion(-1), 'invalid_argument');
    await expectCode(log.consistency(2), 'invalid_argument');
    await expectCode(new AuditLog({ ...config, clock: () => 99 }, store).append(cs[1]), 'invalid_argument');
    await expectCode(new AuditLog({ ...config, signer: witnessSigner, operator: witness }, store).checkpoint(), 'storage_failed');
    await store.write(`audit-log/${logId}/nodes/0-0`, new TextEncoder().encode(JSON.stringify(cs[1])));
    await expectCode(log.append(cs[1]), 'storage_failed');
  });
});

describe('durable witnesses and quorum', () => {
  it('refreshes an idle log without adding events and witnesses the new claims durably', async () => {
    let now = 100;
    const log = new AuditLog({ ...config, clock: () => now }, new MemoryStore());
    const store = new MemoryStore(), w = new AuditWitness({ ...wc, clock: () => now }, store);
    const initial = await log.provision(); await w.provision(initial);
    now = 200; const fresh = await log.refresh();
    expect(fresh.size).toBe(0); expect(fresh.root).toBe(initial.root);
    const r = await w.observe(fresh, []);
    verifyAuditWitnessQuorum(fresh, [r], operator, { witnesses: [witness], threshold: 1, maxFaulty: 0, maxAgeSeconds: 10, maxFutureSkewSeconds: 0 }, now);
    expect(await new AuditWitness(wc, store).checkpoint()).toEqual(fresh);
    await expectCode(w.observe(initial, []), 'invalid_signature');
    now = 201; const next = await log.append(cs[0]);
    await w.observe(next.checkpoint, []);
    expect((await log.checkpoint(0)).timestamp).toBe(100);
  });
  it('retains the horizon across restart, refusing competing forks and shrinkage', async () => {
    const log = new AuditLog(config, new MemoryStore()), store = new MemoryStore();
    const anchor = await log.provision(), w = new AuditWitness(wc, store);
    await w.provision(anchor); const c = (await log.append(cs[0])).checkpoint;
    const r = await w.observe(c, []);
    verifyAuditWitnessReceipt(r, c, operator, witness);
    expect(await new AuditWitness(wc, store).observe(c, [])).toEqual(r);
    const fork = await createAuditCheckpoint(new AuditTree([cs[1]]), logId, signer, 100);
    await expectCode(w.observe(fork, []), 'invalid_signature');
    await expectCode(w.observe(anchor, []), 'invalid_signature');
    expect(await w.checkpoint()).toEqual(c);
    const next = await log.append(cs[1]), proof = (await log.consistency(1)).proof;
    await expectCode(w.observe(next.checkpoint, []), 'invalid_signature');
    await w.observe(next.checkpoint, proof);
  });
  it('never returns a witness signature if the accepted horizon cannot be persisted', async () => {
    const store = new BrokenStore(), w = new AuditWitness(wc, store);
    const zero = await createAuditCheckpoint(new AuditTree(), logId, signer, 100);
    await w.provision(zero);
    const one = await createAuditCheckpoint(new AuditTree([cs[0]]), logId, signer, 100);
    store.remaining = 1;
    await expectCode(w.observe(one, []), 'storage_failed');
    store.remaining = Infinity;
    expect((await w.checkpoint()).size).toBe(0);
    await w.observe(one, []);
  });
  it('does not trust a receipt naming itself, another log, unsigned fields, or changed content', async () => {
    const c = await createAuditCheckpoint(new AuditTree(cs), logId, signer, 100);
    const r = await createAuditWitnessReceipt(c, operator, witnessSigner, 101);
    for (const altered of [{ ...r, operator: witness.aceId }, { ...r, timestamp: 102 }, { ...r, extra: true },
      { ...r, logId: '00000000-0000-4000-8000-000000000001' }, { ...r, checkpointDigest: cs[0] }]) {
      expect(() => verifyAuditWitnessReceipt(altered, c, operator, witness)).toThrow();
    }
    await expectCode(createAuditWitnessReceipt(c, operator, signer, 101), 'invalid_argument');
  });
  it('requires an intersecting independent quorum and checks both clocks', async () => {
    const ids = await Promise.all([witnessSigner, SoftwareIdentity.generate('ed25519'), SoftwareIdentity.generate('ed25519'), SoftwareIdentity.generate('secp256k1')]);
    const peers = ids.map(i => peerOf(i));
    const c = await createAuditCheckpoint(new AuditTree(cs), logId, signer, 100);
    const rs = await Promise.all(ids.map(i => createAuditWitnessReceipt(c, operator, i, 101)));
    const p = { witnesses: peers, threshold: 3, maxFaulty: 1, maxAgeSeconds: 10, maxFutureSkewSeconds: 1 };
    verifyAuditWitnessQuorum(c, rs.slice(0, 3), operator, p, 102);
    for (const [receipts, policy, now] of [[rs.slice(0, 2), p, 102], [[rs[0], rs[0], rs[1]], p, 102],
      [rs, { ...p, threshold: 2 }, 102], [rs, p, 112], [rs, p, 99], [rs, { ...p, witnesses: [...peers, operator] }, 102]] as const) {
      expect(() => verifyAuditWitnessQuorum(c, receipts, operator, policy, now)).toThrow();
    }
    expect(auditCheckpointDigest(c)).toHaveLength(64);
  });
});
