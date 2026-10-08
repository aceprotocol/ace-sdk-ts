/** Relay registration requests: public key binding plus private write authorization (02). */

import { bytesToHex } from '@noble/hashes/utils.js';
import { ACEError } from './errors.js';
import { decodeB64, decodeSignature, encodeSignature, isACEId, toBase64, wireInt } from './encoding.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  bindingSignData, checkProfilePrincipal, decodeEncryptionKey, decodeSigningKey, mintPeer, validateProfile, verifyRegistrationFile,
  type VerifiedPeer,
} from './discovery.js';
import { KEM_PUBLIC_KEY_SIZE, TIMESTAMP_WINDOW_SECONDS } from './limits.js';
import { buildSignData, computeACEId, encodePayload, signingAddress, verifySignature } from './signing.js';
import type {
  ACEIdentity, AgentProfile, Capability, ChainInfo, HardwareBacking, IdentityTier, PrincipalRecord, RegistrationFile, RegistrationRequest,
} from './types.js';
import { isSigningScheme } from './types.js';

const KEEP = Symbol('keep');

/**
 * Build the registration file (02) of any identity, software or hardware-backed; throws
 * `invalid_registration` if the inputs are invalid.
 */
export function createRegistrationFile(identity: ACEIdentity, opts: {
  name: string;
  endpoint: string;
  description?: string;
  tier?: IdentityTier;
  hardwareBacking?: HardwareBacking;
  capabilities?: Capability[];
  settlement?: string[];
  chains?: ChainInfo[];
  principal?: PrincipalRecord;
}): RegistrationFile {
  if (typeof opts !== 'object' || opts === null) throw new ACEError('invalid_argument', 'options are required');
  const scheme = identity.getSigningScheme();
  const signingPublicKey = identity.getSigningPublicKey();
  const reg: RegistrationFile = {
    ace: '1.0',
    id: identity.getACEId(),
    name: opts.name,
    endpoint: opts.endpoint,
    tier: opts.tier ?? 0,
    signing: {
      scheme,
      address: signingAddress(scheme, signingPublicKey),
      encryptionPublicKey: toBase64(identity.getEncryptionPublicKey()),
    },
  };
  if (scheme === 'secp256k1') reg.signing.signingPublicKey = toBase64(signingPublicKey);
  if (opts.description !== undefined) reg.description = opts.description;
  if (opts.hardwareBacking !== undefined) reg.hardwareBacking = opts.hardwareBacking;
  if (opts.capabilities !== undefined) reg.capabilities = opts.capabilities;
  if (opts.settlement !== undefined) reg.settlement = opts.settlement;
  if (opts.chains !== undefined) reg.chains = opts.chains;
  if (opts.principal !== undefined) reg.principal = opts.principal;
  verifyRegistrationFile(reg, { pinnedAt: 0, clock: () => opts.principal?.issuedAt ?? Math.floor(Date.now() / 1000) });
  return reg;
}

/** The `register-request` payload (02). `profile`: KEEP, null, or a validated profile. */
function registrationPayload(encB64: string, sigB64: string, scheme: string, profile: AgentProfile | null | typeof KEEP): Uint8Array {
  if (profile === KEEP) return encodePayload(encB64, sigB64, scheme, 'keep');
  if (profile === null) return encodePayload(encB64, sigB64, scheme, 'remove');
  const pr = profile.pricing;
  const pp = profile.principal;
  return encodePayload(
    encB64, sigB64, scheme, 'replace', profile.name ?? '', profile.description ?? '', profile.image ?? '',
    encodePayload(...(profile.tags ?? [])), encodePayload(...(profile.capabilities ?? [])),
    encodePayload(...(profile.chains ?? [])), profile.endpoint ?? '',
    pr ? 'present' : 'absent', pr ? pr.currency : '', pr ? (pr.maxAmount ?? '') : '',
    pp ? 'present' : 'absent', pp ? pp.account : '', pp ? pp.roles.join(',') : '', pp ? pp.signer.scheme : '',
    pp ? pp.signer.publicKey : '', pp ? String(pp.issuedAt) : '', pp ? String(pp.expiresAt ?? 0) : '',
    pp ? (pp.scope ?? '') : '', pp ? pp.signature : '',
  );
}

function nowOf(clock?: () => number): number {
  return Math.floor(clock ? clock() : Date.now() / 1000);
}

/**
 * Build a `POST /v1/register` body. `profile` undefined keeps the stored profile,
 * `null` removes it, an object replaces it (validated; `invalid_profile`).
 */
export async function createRegistrationRequest(
  identity: ACEIdentity, profile?: AgentProfile | null, timestamp?: number,
): Promise<RegistrationRequest> {
  const ts = timestamp ?? nowOf();
  if (wireInt(ts) === null) throw new ACEError('invalid_argument', 'timestamp must be an integer in [0, 2^53-1]');
  const enc = identity.getEncryptionPublicKey();
  if (!(enc instanceof Uint8Array) || enc.length !== KEM_PUBLIC_KEY_SIZE) {
    throw new ACEError('invalid_key', 'identity encryption public key must be 1216 bytes');
  }
  const snapshot = profile === undefined ? KEEP : profile === null ? null : validateProfile(profile);
  if (snapshot !== KEEP && snapshot !== null) checkProfilePrincipal(snapshot, identity.getSigningPublicKey(), ts);
  const epk = toBase64(enc);
  const spk = toBase64(identity.getSigningPublicKey());
  const aceId = identity.getACEId();
  const scheme = identity.getSigningScheme();
  const signature = await identity.sign(bindingSignData(aceId, ts, epk, spk));
  const authorization = await identity.sign(buildSignData('register-request', aceId, ts, registrationPayload(epk, spk, scheme, snapshot)));
  const out: RegistrationRequest = {
    aceId, encryptionPublicKey: epk, signingPublicKey: spk, scheme, timestamp: ts,
    signature: encodeSignature(signature, scheme), authorization: encodeSignature(authorization, scheme),
  };
  if (snapshot !== KEEP) out.profile = snapshot;
  return out;
}

export interface VerifiedRegistration {
  request: RegistrationRequest;
  peer: VerifiedPeer;
  /** Hex SHA-256 of the `register-request` signData. */
  requestDigest: string;
}

/**
 * Verify a registration request. Check order (first failure wins): schema →
 * `invalid_registration`; freshness → `stale_timestamp`; ID hash → `invalid_registration`;
 * signing / encryption key → `invalid_key`; profile → `invalid_profile`; principal → `invalid_principal`; binding →
 * `invalid_signature`; authorization → `invalid_authorization`.
 */
export function verifyRegistrationRequest(
  body: unknown, opts: { clock?: () => number; windowSeconds?: number } = {},
): VerifiedRegistration {
  const windowSeconds = opts.windowSeconds ?? TIMESTAMP_WINDOW_SECONDS;
  if (!Number.isSafeInteger(windowSeconds) || windowSeconds < 0) {
    throw new ACEError('invalid_argument', 'windowSeconds must be a non-negative integer');
  }
  const bad = 'invalid_registration';
  if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new ACEError(bad, 'registration request must be an object');
  const b = body as Record<string, unknown>;
  const { aceId, scheme, encryptionPublicKey: epk, signingPublicKey: spk } = b;
  const ts = wireInt(b.timestamp);
  if (!isACEId(aceId) || !isSigningScheme(scheme) || ts === null) {
    throw new ACEError(bad, 'aceId, scheme and timestamp are required and well-formed');
  }
  if (typeof epk !== 'string' || typeof spk !== 'string') throw new ACEError(bad, 'encryptionPublicKey and signingPublicKey must be strings');
  const sig = decodeSignature(b.signature, scheme, bad);
  const auth = decodeSignature(b.authorization, scheme, bad);
  const hasProfile = 'profile' in b && b.profile !== undefined;
  const rawProfile = b.profile ?? null;
  if (rawProfile !== null && (typeof rawProfile !== 'object' || Array.isArray(rawProfile))) {
    throw new ACEError(bad, 'profile must be an object or null');
  }
  const spkBytes = decodeB64(spk, bad, 'signingPublicKey', 64);
  decodeB64(epk, bad, 'encryptionPublicKey', KEM_PUBLIC_KEY_SIZE + 3);
  if (Math.abs(nowOf(opts.clock) - ts) > windowSeconds) {
    throw new ACEError('stale_timestamp', 'registration timestamp is outside the freshness window');
  }
  if (computeACEId(spkBytes) !== aceId) throw new ACEError(bad, 'aceId does not match signingPublicKey');
  const signingKey = decodeSigningKey(scheme, spk, 'invalid_key');
  const encKey = decodeEncryptionKey(epk, 'invalid_key');
  const profile = rawProfile === null ? null : validateProfile(rawProfile as AgentProfile);
  checkProfilePrincipal(profile, signingKey, nowOf(opts.clock));
  if (!verifySignature(bindingSignData(aceId, ts, epk, spk), sig, scheme, signingKey)) {
    throw new ACEError('invalid_signature', 'registration binding signature does not verify');
  }
  const requestSignData = buildSignData('register-request', aceId, ts, registrationPayload(epk, spk, scheme, hasProfile ? profile : KEEP));
  if (!verifySignature(requestSignData, auth, scheme, signingKey)) {
    throw new ACEError('invalid_authorization', 'registration authorization does not verify');
  }
  const request: RegistrationRequest = {
    aceId, encryptionPublicKey: epk, signingPublicKey: spk, scheme, timestamp: ts,
    signature: b.signature as string, authorization: b.authorization as string,
  };
  if (hasProfile) request.profile = profile;
  const peer = mintPeer({
    aceId, scheme, signingPublicKey: signingKey, encryptionPublicKey: encKey, registeredAt: ts,
    registrationSignature: b.signature as string, source: 'relay', profile,
  });
  return { request, peer, requestDigest: bytesToHex(sha256(requestSignData)) };
}
