/** Optional private commitments and RFC 9162 Merkle proofs. No publication or execution side effects. */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, randomBytes, concatBytes } from '@noble/hashes/utils.js';
import { decodeSignature, encodeSignature, hasExactKeys, utf8, isACEId, isConversationId, isMessageId, wireInt } from './encoding.js';
import { isVerifiedPeer, type VerifiedPeer } from './discovery.js';
import { buildSignData, encodePayload, verifySignature } from './signing.js';
import { ACEError } from './errors.js';
import type { ACEIdentity, SignatureEnvelope } from './types.js';

const fail = () => new ACEError('invalid_argument', 'invalid audit input');
const hash = (...parts: Uint8Array[]) => bytesToHex(sha256(concatBytes(...parts)));
const empty = hash(new Uint8Array());
const node = (a: string, b: string) => hash(Uint8Array.of(1), hexToBytes(a), hexToBytes(b));
const leaf = (commitment: string) => hash(Uint8Array.of(0), hexToBytes(commitment));
const digest = (v: unknown): v is string => isConversationId(v);
const size = (v: unknown): v is number => wireInt(v) !== null;
const proofOK = (p: unknown): p is string[] => Array.isArray(p) && p.length <= 54 && p.every(digest);
const split = (n: number) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
/** @internal RFC 9162 primitives shared with the durable log; not part of the public surface. */
export const merkle = { empty, leaf, node, split } as const;

/** The salt must stay private until intentional disclosure. Use a fresh opening per publication. */
export function auditCommitment(statement: Uint8Array, salt: Uint8Array): string {
  if (!(statement instanceof Uint8Array) || !(salt instanceof Uint8Array) || salt.length !== 32) throw fail();
  return hash(utf8('ace.audit.commitment.v1\0'), salt, statement);
}
export function createAuditOpening(statement: Uint8Array): { salt: Uint8Array; commitment: string } {
  const salt = randomBytes(32);
  return { salt, commitment: auditCommitment(statement, salt) };
}

/** Reference tree builder; inputs are commitments, never plaintext or salts. */
export class AuditTree {
  readonly #leaves: string[];
  /** Perfect (power-of-two) subtree hashes by `start:count`; proofs reuse them instead of rehashing leaves. */
  readonly #perfect = new Map<string, string>();
  constructor(commitments: readonly string[] = []) {
    if (!Array.isArray(commitments) || commitments.length > 65_536 || !commitments.every(digest)) throw fail();
    this.#leaves = commitments.map(leaf);
  }
  get size(): number { return this.#leaves.length; }
  #root(start: number, count: number): string {
    if (!count) return empty;
    if (count === 1) return this.#leaves[start];
    const perfect = (count & (count - 1)) === 0, key = `${start}:${count}`;
    const cached = perfect ? this.#perfect.get(key) : undefined;
    if (cached !== undefined) return cached;
    const k = split(count);
    const h = node(this.#root(start, k), this.#root(start + k, count - k));
    if (perfect) this.#perfect.set(key, h);
    return h;
  }
  root(count = this.size): string {
    if (!size(count) || count > this.size) throw fail();
    return this.#root(0, count);
  }
  inclusion(index: number, count = this.size): string[] {
    if (!size(index) || !size(count) || index >= count || count > this.size) throw fail();
    const walk = (i: number, start: number, n: number): string[] => {
      if (n === 1) return [];
      const k = split(n);
      return i < k ? [...walk(i, start, k), this.#root(start + k, n - k)]
        : [...walk(i - k, start + k, n - k), this.#root(start, k)];
    };
    return walk(index, 0, count);
  }
  consistency(first: number, second = this.size): string[] {
    if (!size(first) || !size(second) || first > second || second > this.size) throw fail();
    if (first === 0 || first === second) return [];
    const walk = (m: number, start: number, n: number, complete: boolean): string[] => {
      if (m === n) return complete ? [] : [this.#root(start, n)];
      const k = split(n);
      return m <= k ? [...walk(m, start, k, complete), this.#root(start + k, n - k)]
        : [...walk(m - k, start + k, n - k, false), this.#root(start, k)];
    };
    return walk(first, 0, second, true);
  }
}

export function verifyAuditInclusion(commitment: string, index: number, count: number, root: string, proof: readonly string[]): boolean {
  if (!digest(commitment) || !digest(root) || !size(index) || !size(count) || index >= count || !proofOK(proof)) return false;
  let at = 0;
  const walk = (i: number, n: number): string => {
    if (n === 1) return leaf(commitment);
    const k = split(n), child = i < k ? walk(i, k) : walk(i - k, n - k);
    const sibling = proof[at++];
    if (sibling === undefined) throw fail();
    return i < k ? node(child, sibling) : node(sibling, child);
  };
  try { return walk(index, count) === root && at === proof.length; } catch { return false; }
}

export function verifyAuditConsistency(first: number, second: number, firstRoot: string, secondRoot: string, proof: readonly string[]): boolean {
  if (!size(first) || !size(second) || first > second || !digest(firstRoot) || !digest(secondRoot) || !proofOK(proof)) return false;
  if (first === second) return proof.length === 0 && firstRoot === secondRoot && (first !== 0 || firstRoot === empty);
  if (first === 0) return firstRoot === empty && proof.length === 0;
  let at = 0;
  const take = () => { const x = proof[at++]; if (x === undefined) throw fail(); return x; };
  const walk = (m: number, n: number, complete: boolean): [string, string] => {
    if (m === n) { const h = complete ? firstRoot : take(); return [h, h]; }
    const k = split(n);
    if (m <= k) { const [old, next] = walk(m, k, complete); return [old, node(next, take())]; }
    const [old, next] = walk(m - k, n - k, false), left = take();
    return [node(left, old), node(left, next)];
  };
  try { const [old, next] = walk(first, second, true); return at === proof.length && old === firstRoot && next === secondRoot; }
  catch { return false; }
}

export interface AuditCheckpoint {
  logId: string; size: number; root: string; timestamp: number; signer: string; signature: SignatureEnvelope;
}
export function checkpointData(c: Omit<AuditCheckpoint, 'signature'>): Uint8Array {
  if (!isMessageId(c.logId) || !size(c.size) || !digest(c.root) || !size(c.timestamp) || (c.size === 0 && c.root !== empty)) throw fail();
  return buildSignData('audit', c.signer, c.timestamp, encodePayload(c.logId, String(c.size), hexToBytes(c.root)));
}
export async function createAuditCheckpoint(tree: AuditTree, logId: string, signer: ACEIdentity, timestamp: number): Promise<AuditCheckpoint> {
  return signAuditCheckpoint({ logId, size: tree.size, root: tree.root(), timestamp, signer: signer.getACEId() }, signer);
}
/** Internal signing seam for persistent trees; callers must compute and durably commit the tree. */
export async function signAuditCheckpoint(c: Omit<AuditCheckpoint, 'signature'>, signer: ACEIdentity): Promise<AuditCheckpoint> {
  if (c.signer !== signer.getACEId()) throw fail();
  const value = encodeSignature(await signer.sign(checkpointData(c)), signer.getSigningScheme());
  return { ...c, signature: { scheme: signer.getSigningScheme(), value } };
}
/** operator is a locally trusted log key. Prior checkpoints must be retained durably by the caller. */
export function verifyAuditCheckpoint(c: AuditCheckpoint, operator: VerifiedPeer, previous?: AuditCheckpoint, proof: readonly string[] = []): void {
  try {
    const valid = (v: AuditCheckpoint) => hasExactKeys(v, ['logId', 'root', 'signature', 'signer', 'size', 'timestamp'])
      && hasExactKeys(v.signature, ['scheme', 'value']) && v.signer === operator.aceId && v.signature.scheme === operator.scheme
      && verifySignature(checkpointData(v), decodeSignature(v.signature.value, operator.scheme, 'invalid_signature'), operator.scheme, operator.signingPublicKey);
    if (!isVerifiedPeer(operator) || !valid(c) || (previous && (!valid(previous) || c.logId !== previous.logId
      || c.timestamp < previous.timestamp || !verifyAuditConsistency(previous.size, c.size, previous.root, c.root, proof)))) throw fail();
    if (!previous && proof.length !== 0) throw fail();
  } catch { throw new ACEError('invalid_signature', 'invalid or inconsistent audit checkpoint'); }
}

/** Stable digest of checkpoint claims, independent of signature encoding/randomness. */
export function auditCheckpointDigest(c: AuditCheckpoint): string { return bytesToHex(checkpointData(c)); }

export interface AuditWitnessReceipt {
  logId: string; operator: string; checkpointDigest: string; timestamp: number; witness: string; signature: SignatureEnvelope;
}
function witnessData(r: Omit<AuditWitnessReceipt, 'signature'>): Uint8Array {
  if (!isMessageId(r.logId) || !isACEId(r.operator) || !isACEId(r.witness) || r.operator === r.witness
    || !digest(r.checkpointDigest) || !size(r.timestamp)) throw fail();
  return buildSignData('audit-witness', r.witness, r.timestamp,
    encodePayload(r.logId, r.operator, hexToBytes(r.checkpointDigest)));
}
/** A witness service MUST persist its accepted checkpoint before releasing this signature. */
export async function createAuditWitnessReceipt(c: AuditCheckpoint, operator: VerifiedPeer, witness: ACEIdentity, timestamp: number): Promise<AuditWitnessReceipt> {
  verifyAuditCheckpoint(c, operator);
  if (!size(timestamp) || timestamp < c.timestamp) throw fail();
  const r = { logId: c.logId, operator: c.signer, checkpointDigest: auditCheckpointDigest(c), timestamp, witness: witness.getACEId() };
  const value = encodeSignature(await witness.sign(witnessData(r)), witness.getSigningScheme());
  return { ...r, signature: { scheme: witness.getSigningScheme(), value } };
}
/** @internal `r` is `witness`'s receipt for `c`, whose checkpoint signature the caller already verified (`digest` is its digest). */
export function witnessReceiptValid(r: AuditWitnessReceipt, c: AuditCheckpoint, digest: string, witness: VerifiedPeer): boolean {
  try {
    return isVerifiedPeer(witness) && hasExactKeys(r, ['checkpointDigest', 'logId', 'operator', 'signature', 'timestamp', 'witness'])
      && hasExactKeys(r.signature, ['scheme', 'value']) && r.logId === c.logId && r.operator === c.signer
      && r.checkpointDigest === digest && r.timestamp >= c.timestamp && r.witness === witness.aceId
      && r.signature.scheme === witness.scheme && verifySignature(witnessData(r),
        decodeSignature(r.signature.value, witness.scheme, 'invalid_signature'), witness.scheme, witness.signingPublicKey);
  } catch { return false; }
}
export function verifyAuditWitnessReceipt(r: AuditWitnessReceipt, c: AuditCheckpoint, operator: VerifiedPeer, witness: VerifiedPeer): void {
  try {
    verifyAuditCheckpoint(c, operator);
    if (!witnessReceiptValid(r, c, auditCheckpointDigest(c), witness)) throw fail();
  } catch { throw new ACEError('invalid_signature', 'invalid audit witness receipt'); }
}
export interface AuditWitnessPolicy {
  witnesses: readonly VerifiedPeer[]; threshold: number; maxFaulty: number;
  maxAgeSeconds: number; maxFutureSkewSeconds: number;
}
/** Quorums must intersect in an honest witness: 2*threshold > N+maxFaulty. Time is local policy. */
export function verifyAuditWitnessQuorum(c: AuditCheckpoint, receipts: readonly AuditWitnessReceipt[], operator: VerifiedPeer,
  policy: AuditWitnessPolicy, now: number): void {
  try {
    verifyAuditCheckpoint(c, operator);
    const { witnesses: ws, threshold: q, maxFaulty: f, maxAgeSeconds: age, maxFutureSkewSeconds: skew } = policy;
    if (!Array.isArray(ws) || ws.length < 1 || ws.length > 32 || !ws.every(isVerifiedPeer)
      || new Set(ws.map(w => w.aceId)).size !== ws.length || ws.some(w => w.aceId === operator.aceId)
      || !size(q) || !size(f) || q > ws.length - f || 2*q <= ws.length + f
      || !size(age) || !size(skew) || !size(now) || !Array.isArray(receipts) || receipts.length > ws.length
      || c.timestamp - now > skew || now - c.timestamp > age) throw fail();
    const seen = new Set<string>(), digest = auditCheckpointDigest(c);
    for (const r of receipts) {
      const w = ws.find(w => w.aceId === r.witness);
      if (!w || seen.has(r.witness) || r.timestamp - now > skew || now - r.timestamp > age || !witnessReceiptValid(r, c, digest, w)) throw fail();
      seen.add(r.witness);
    }
    if (seen.size < q) throw fail();
  } catch { throw new ACEError('invalid_signature', 'audit witness quorum or freshness policy not satisfied'); }
}
