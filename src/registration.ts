/** Relay registration (`POST /v1/register`, 07 § Registration): the client's request and the relay-side verifier. */
import { ACEError } from './errors.js';
import { assertFresh } from './auth.js';
import { closedKeys, isACEId, nowOf, sha256Hex, wireInt } from './encoding.js';
import { checkUsable, signOperational, type ACEIdentity } from './identity.js';
import { checkSignatureShape, isUsable, verifyKel, verifyOperationalSignature, type KelEvent, type KelState, type OperationalSignature } from './kel.js';
import { isCanonicalRelayUrl, normalizeRelayUrl } from './relay-url.js';
import { encodePayload, signingMessage } from './signing.js';

/**
 * `POST /v1/register` body. `audience` is the canonical URL of the relay the request is meant for: it is signed, so no
 * relay can replay the request to another.
 */
export interface RegistrationRequest { aceId: string; kel: KelEvent[]; timestamp: number; audience: string; signature: OperationalSignature }

/** Sign a registration request for the relay whose base URL is `o.audience` (normalized to its canonical form). */
export async function createRegistrationRequest(identity: ACEIdentity, o: { audience: string; timestamp?: number }): Promise<RegistrationRequest> {
  const timestamp = o.timestamp ?? nowOf();
  if (wireInt(timestamp) === null) throw new ACEError('invalid_argument', 'timestamp must be an integer in [0, 2^53-1]');
  const audience = normalizeRelayUrl(o.audience);
  const lastHash = checkUsable(identity, timestamp).lastHash;
  const signature = await signOperational(identity, timestamp, encodePayload(lastHash, audience), 'register-request');
  return { aceId: identity.getACEId(), kel: identity.getKel(), timestamp, audience, signature };
}

export interface VerifiedRegistration {
  request: RegistrationRequest;
  state: KelState;
  /** Hex SHA-256 of the signed message `M`: the idempotency digest. */
  requestDigest: string;
}

/**
 * Relay side: verify a registration request for the relay whose canonical URL is `opts.audience`, at one clock reading,
 * in 07 order: 1. shape (`invalid_registration`); 2. this relay's audience (`invalid_signature`); 3. freshness
 * (`stale_timestamp`); 4. the KEL verifies and is usable at `now` (`invalid_kel` / `invalid_signature`) and names
 * `aceId` (`invalid_registration`); 5. `signature.seq` names its delegation (`invalid_signature`), signed while live
 * (`stale_peer_binding`), the signature verifies (`invalid_authorization`). Step 6 (the stored record) is the relay's.
 */
export function verifyRegistrationRequest(body: unknown, opts: { audience: string; clock?: () => number }): VerifiedRegistration {
  const own = normalizeRelayUrl(opts.audience);
  const shape = (m: string) => new ACEError('invalid_registration', m);
  if (!closedKeys(body, ['aceId', 'kel', 'timestamp', 'audience', 'signature'])) throw shape('registration request must be {aceId, kel, timestamp, audience, signature}');
  const ts = wireInt(body.timestamp);
  if (!isACEId(body.aceId) || ts === null || !Array.isArray(body.kel)) throw shape('aceId, kel and timestamp are required and well-formed');
  if (!isCanonicalRelayUrl(body.audience, { allowLoopback: true })) throw shape('audience must be a canonical relay URL');
  const sig = checkSignatureShape(body.signature, 'invalid_registration');
  if (body.audience !== own) throw new ACEError('invalid_signature', 'registration request is for another relay');
  const now = nowOf(opts.clock);
  assertFresh(ts, now, 'registration timestamp');
  const state = verifyKel(body.kel, now);
  if (!isUsable(state, now)) throw new ACEError('invalid_kel', 'identity has no live signing delegation');
  if (state.aceId !== body.aceId) throw shape('aceId does not match the kel');
  if (sig.seq !== state.signing!.seq) throw new ACEError('invalid_signature', 'signature.seq is not the signing delegation');
  const payload = encodePayload(state.lastHash, own);
  verifyOperationalSignature(state, 'register-request', ts, payload, sig, now, 'invalid_authorization');
  const request = structuredClone(body) as unknown as RegistrationRequest;
  return { request, state, requestDigest: sha256Hex(signingMessage(state.aceId, ts, sig.seq, payload)) };
}
