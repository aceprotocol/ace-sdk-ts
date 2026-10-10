/** Exact-intent capabilities. Message labels and account roles never confer execution rights. */
import { intentDigest } from './intent.js';
import { decodeB64, decodeSignature, encodeSignature, isACEId, isConversationId, hasExactKeys, isMessageId, isObj, toBase64, utf8, wireInt } from './encoding.js';
import { buildSignData, computeACEId, encodePayload, isValidSigningPublicKey, verifySignature } from './signing.js';
import { isVerifiedPeer, type VerifiedPeer } from './discovery.js';
import { ACEError } from './errors.js';
import { MAX_EXECUTION_JSON_BYTES } from './limits.js';
import { isMessageType, isSigningScheme, type ACEIdentity, type JSONObject, type SignatureEnvelope } from './types.js';

export interface ExecutionIntent {
  operationId: string; audience: string; resource: string; action: string; schemaDigest: string;
  details: JSONObject; expiresAt: number;
}
export interface GrantClaims {
  grantId: string; issuer: string; subject: string; audience: string; resource: string; intentDigest: string;
  issuedAt: number; expiresAt: number; epoch: number; parent: string | null; delegationDepth: number;
}
export interface ExecutionGrant { claims: GrantClaims; signingPublicKey: string; signature: SignatureEnvelope }
/** Must come from the executor's authoritative resource policy, never the request body. */
export interface ResourcePolicy {
  resource: string; authority: VerifiedPeer; epoch: number; revoked: readonly string[];
}
const bad = () => new ACEError('invalid_authorization', 'invalid execution intent or resource grant');
const name = (s: unknown): s is string => typeof s === 'string' && s.includes(':') && isMessageType(s);
/** Decimal integer units are profile-defined; no float rounding or scientific notation. */
export const isExecutionUnits = (s: unknown): s is string => typeof s === 'string' && /^(0|[1-9][0-9]{0,77})$/.exec(s)?.[0] === s;

export function executionIntentDigest(intent: ExecutionIntent): string {
  if (!hasExactKeys(intent, ['operationId', 'audience', 'resource', 'action', 'schemaDigest', 'details', 'expiresAt']) || !isMessageId(intent.operationId)
    || !isACEId(intent.audience) || !name(intent.resource) || !name(intent.action) || !isConversationId(intent.schemaDigest)
    || !isObj(intent.details) || wireInt(intent.expiresAt) === null) throw bad();
  // Enforce the same bounded JSON surface before hashing an application-owned object.
  function depth(v: unknown, n: number): void {
    if (n > 32) throw bad();
    if (v === null || typeof v === 'string' || typeof v === 'boolean' || typeof v === 'number' && Number.isFinite(v)) return;
    if (Array.isArray(v)) { for (const child of v) depth(child, n + 1); return; }
    if (!isObj(v) || Object.getPrototypeOf(v) !== Object.prototype && Object.getPrototypeOf(v) !== null) throw bad();
    for (const [key, child] of Object.entries(v)) {
      if (key.normalize('NFC') !== key) throw bad();
      depth(child, n + 1);
    }
  }
  depth(intent, 0);
  if (utf8(JSON.stringify(intent)).length > MAX_EXECUTION_JSON_BYTES) throw bad();
  return intentDigest(intent as unknown as JSONObject);
}
function claimsDigest(c: GrantClaims): string {
  if (!hasExactKeys(c, ['grantId', 'issuer', 'subject', 'audience', 'resource', 'intentDigest', 'issuedAt', 'expiresAt', 'epoch', 'parent', 'delegationDepth'])
    || !isMessageId(c.grantId) || !isACEId(c.issuer) || !isACEId(c.subject) || !isACEId(c.audience) || !name(c.resource)
    || !isConversationId(c.intentDigest) || wireInt(c.issuedAt) === null || wireInt(c.expiresAt) === null || c.issuedAt >= c.expiresAt
    || wireInt(c.epoch) === null || wireInt(c.delegationDepth) === null || c.delegationDepth > 7
    || c.parent !== null && !isConversationId(c.parent)) throw bad();
  return intentDigest(c as unknown as JSONObject);
}
const signData = (c: GrantClaims) => buildSignData('grant', c.issuer, c.issuedAt, encodePayload(claimsDigest(c)));
/** Stable parent reference: hash claims, not randomized signature bytes. */
export function executionGrantDigest(g: ExecutionGrant): string { return claimsDigest(g.claims); }
export async function createExecutionGrant(signer: ACEIdentity, claims: GrantClaims): Promise<ExecutionGrant> {
  const c = { ...claims }; // Own the exact claims before a hardware signer yields.
  if (c.issuer !== signer.getACEId()) throw bad();
  const digest = signData(c), scheme = signer.getSigningScheme(), signingPublicKey = toBase64(signer.getSigningPublicKey());
  const value = encodeSignature(await signer.sign(digest), scheme);
  return { claims: c, signingPublicKey, signature: { scheme, value } };
}
/** Pure proof verification. Call inside the authoritative reservation transaction, with current policy. */
export function verifyExecutionGrantChain(chain: readonly ExecutionGrant[], intent: ExecutionIntent, sender: string,
  executor: string, policy: ResourcePolicy, now: number): string {
  try {
    const digest = executionIntentDigest(intent);
    if (!Array.isArray(chain) || chain.length < 1 || chain.length > 8 || !isACEId(sender) || !isACEId(executor)
      || !isVerifiedPeer(policy.authority) || wireInt(now) === null || wireInt(policy.epoch) === null
      || !Array.isArray(policy.revoked) || !policy.revoked.every(isMessageId)
      || intent.audience !== executor || intent.resource !== policy.resource || now >= intent.expiresAt) throw bad();
    let previous: GrantClaims | undefined;
    const ids = new Set<string>();
    for (const g of chain) {
      if (!hasExactKeys(g, ['claims', 'signingPublicKey', 'signature']) || !hasExactKeys(g.signature, ['scheme', 'value']) || !isSigningScheme(g.signature.scheme)) throw bad();
      const c = g.claims, key = decodeB64(g.signingPublicKey, 'invalid_authorization', 'signingPublicKey', 64);
      if (!isValidSigningPublicKey(g.signature.scheme, key) || computeACEId(key) !== c.issuer || !verifySignature(signData(c),
        decodeSignature(g.signature.value, g.signature.scheme, 'invalid_authorization'), g.signature.scheme, key)
        || c.audience !== executor || c.resource !== policy.resource || c.intentDigest !== digest || c.epoch !== policy.epoch
        || now < c.issuedAt || now >= c.expiresAt || intent.expiresAt > c.expiresAt || policy.revoked.includes(c.grantId) || ids.has(c.grantId)) throw bad();
      if (previous) {
        if (c.parent !== claimsDigest(previous) || c.issuer !== previous.subject || c.delegationDepth >= previous.delegationDepth
          || c.issuedAt < previous.issuedAt || c.expiresAt > previous.expiresAt) throw bad();
      } else if (c.parent !== null || c.issuer !== policy.authority.aceId || g.signature.scheme !== policy.authority.scheme
        || toBase64(key) !== toBase64(policy.authority.signingPublicKey)) throw bad();
      ids.add(c.grantId); previous = c;
    }
    if (previous!.subject !== sender) throw bad();
    return digest;
  } catch { throw bad(); }
}
