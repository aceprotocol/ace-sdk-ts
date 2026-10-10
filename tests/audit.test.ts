import { describe, it, expect } from 'vitest';
import { AuditTree, auditCommitment, createAuditOpening, verifyAuditInclusion, verifyAuditConsistency,
  createAuditCheckpoint, verifyAuditCheckpoint, auditCheckpointDigest, verifyAuditWitnessReceipt,
  verifyAuditWitnessQuorum } from '../src/index.js';
import { agent, peerOf, V, unhex } from './helpers.js';
const logId = '550e8400-e29b-41d4-a716-446655440000';
const commitments = Array.from({ length: 35 }, (_, i) => auditCommitment(Uint8Array.of(i), new Uint8Array(32)));

describe('optional audit', () => {
  it('matches shared byte-level vectors and both signature schemes', () => {
    const v = V.audit, cs = v.openings.map((o: any) => o.commitment), tree = new AuditTree(cs);
    for (const o of v.openings) expect(auditCommitment(unhex(o.statementHex), unhex(o.saltHex))).toBe(o.commitment);
    v.roots.forEach((r: string, n: number) => expect(tree.root(n)).toBe(r));
    for (const p of v.inclusions) {
      expect(tree.inclusion(p.index, p.size)).toEqual(p.proof);
      expect(verifyAuditInclusion(cs[p.index], p.index, p.size, v.roots[p.size], p.proof)).toBe(true);
    }
    for (const p of v.consistencies) {
      expect(tree.consistency(p.first, p.second)).toEqual(p.proof);
      expect(verifyAuditConsistency(p.first, p.second, v.roots[p.first], v.roots[p.second], p.proof)).toBe(true);
    }
    v.checkpoints.forEach((c: any, i: number) => verifyAuditCheckpoint(c, peerOf(agent(i === 0 ? 'alice' : 'bob'))));
    for (const w of v.witnesses) {
      const op = peerOf(agent(w.operator)), witness = peerOf(agent(w.witness));
      expect(auditCheckpointDigest(w.checkpoint)).toBe(w.checkpointDigest);
      verifyAuditWitnessReceipt(w.receipt, w.checkpoint, op, witness);
      const policy = { witnesses: [witness], threshold: 1, maxFaulty: 0, maxAgeSeconds: 2, maxFutureSkewSeconds: 0 };
      verifyAuditWitnessQuorum(w.checkpoint, [w.receipt], op, policy, w.receipt.timestamp);
      expect(() => verifyAuditWitnessQuorum(w.checkpoint, [w.receipt], op, policy, w.receipt.timestamp + 3)).toThrow();
    }
  });
  it('uses fresh private salts and binds all bytes', () => {
    const text = new TextEncoder().encode('pay 1');
    const a = createAuditOpening(text), b = createAuditOpening(text);
    expect(a.salt.length).toBe(32); expect(a.commitment).not.toBe(b.commitment);
    expect(auditCommitment(text, a.salt)).toBe(a.commitment);
    expect(auditCommitment(text.slice(1), a.salt)).not.toBe(a.commitment);
    expect(() => auditCommitment(text, new Uint8Array(31))).toThrow();
  });
  it('validates every leaf and prefix of balanced and unbalanced trees', () => {
    const tree = new AuditTree(commitments);
    for (let n = 1; n <= tree.size; n++) {
      for (let i = 0; i < n; i++) {
        const proof = tree.inclusion(i, n);
        expect(verifyAuditInclusion(commitments[i], i, n, tree.root(n), proof)).toBe(true);
        expect(verifyAuditInclusion(commitments[i], i, n, tree.root(n), [...proof, commitments[0]])).toBe(false);
        expect(verifyAuditInclusion(commitments[(i + 1) % 35], i, n, tree.root(n), proof)).toBe(false);
      }
      for (let m = 0; m <= n; m++) {
        const proof = tree.consistency(m, n);
        expect(verifyAuditConsistency(m, n, tree.root(m), tree.root(n), proof)).toBe(true);
        expect(verifyAuditConsistency(m, n, tree.root(m), tree.root(n), [...proof, commitments[0]])).toBe(false);
        if (m > 0) expect(verifyAuditConsistency(m, n, commitments[0], tree.root(n), proof)).toBe(false);
      }
    }
    expect(verifyAuditConsistency(2, 1, tree.root(2), tree.root(1), [])).toBe(false);
    expect(verifyAuditInclusion(commitments[0], 0, 0, tree.root(0), [])).toBe(false);
    expect(verifyAuditConsistency(0, 0, commitments[0], commitments[0], [])).toBe(false);
  });
  it.each(['alice', 'bob'] as const)('binds log ID, operator, order and roots for %s', async name => {
    const signer = agent(name), peer = peerOf(signer);
    const first = await createAuditCheckpoint(new AuditTree(commitments.slice(0, 5)), logId, signer, 100);
    const tree = new AuditTree(commitments);
    const next = await createAuditCheckpoint(tree, logId, signer, 101);
    verifyAuditCheckpoint(first, peer);
    verifyAuditCheckpoint(next, peer, first, tree.consistency(5));
    for (const changed of [{ ...next, size: 4 }, { ...next, root: commitments[0] }, { ...next, timestamp: 99 },
      { ...next, logId: '00000000-0000-4000-8000-000000000001' }, { ...next, extra: 'unsigned' }]) {
      expect(() => verifyAuditCheckpoint(changed, peer, first, tree.consistency(5))).toThrow(/invalid_signature/);
    }
    const fork = await createAuditCheckpoint(new AuditTree(commitments.slice(1)), logId, signer, 102);
    expect(() => verifyAuditCheckpoint(fork, peer, next, [])).toThrow();
    expect(() => verifyAuditCheckpoint(next, peerOf(agent(name === 'alice' ? 'bob' : 'alice')))).toThrow();
  });
});
