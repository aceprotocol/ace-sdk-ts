import type { ACEIdentity, AgentProfile, SigningScheme } from './types.js';
import { toBase64 } from './identity.js';
import { validateProfile } from './discovery.js';
import { validatePublicKey } from './encryption.js';
import { buildSignData, encodePayload, encodeSignature } from './signing.js';

export interface RegistrationRequest {
  aceId: string;
  encryptionPublicKey: string;
  signingPublicKey: string;
  scheme: SigningScheme;
  timestamp: number;
  /** Public encryption-key binding, safe to distribute to peers. */
  signature: string;
  /** Private write authorization; never returned by discovery endpoints. */
  authorization: string;
  /** Omitted = keep, null = remove, object = replace. */
  profile?: AgentProfile | null;
}

/** Canonical, length-prefixed registration mutation. Array order is significant. */
export function buildRegistrationPayload(
  encryptionPublicKey: string, signingPublicKey: string, scheme: SigningScheme,
  profile?: AgentProfile | null,
): Uint8Array {
  const fields: (string | Uint8Array)[] = [encryptionPublicKey, signingPublicKey, scheme];
  if (profile === undefined) return encodePayload(...fields, 'keep');
  if (profile === null) return encodePayload(...fields, 'remove');
  validateProfile(profile);
  return encodePayload(...fields, 'replace',
    profile.name ?? '', profile.description ?? '', profile.image ?? '',
    encodePayload(...(profile.tags ?? [])), encodePayload(...(profile.capabilities ?? [])),
    encodePayload(...(profile.chains ?? [])), profile.endpoint ?? '',
    profile.pricing ? 'present' : 'absent', profile.pricing?.currency ?? '', profile.pricing?.maxAmount ?? '');
}

/** Build a complete relay registration without exposing write authorization to peers. */
export async function createRegistrationRequest(
  identity: ACEIdentity, profile?: AgentProfile | null, timestamp = Math.floor(Date.now() / 1000),
): Promise<RegistrationRequest> {
  validatePublicKey(identity.getEncryptionPublicKey());
  const aceId = identity.getACEId();
  const scheme = identity.getSigningScheme();
  const encryptionPublicKey = toBase64(identity.getEncryptionPublicKey());
  const signingPublicKey = toBase64(identity.getSigningPublicKey());
  // Snapshot caller-owned profile before awaiting a hardware/software signer.
  const snapshot = profile == null ? profile : structuredClone(profile);
  const payload = buildRegistrationPayload(encryptionPublicKey, signingPublicKey, scheme, snapshot);
  const binding = buildSignData('register', aceId, timestamp, encodePayload(encryptionPublicKey, signingPublicKey));
  const signature = encodeSignature((await identity.sign(binding)).signature, scheme);
  const authorization = encodeSignature((await identity.sign(buildSignData('register-request', aceId, timestamp, payload))).signature, scheme);
  return { aceId, encryptionPublicKey, signingPublicKey, scheme, timestamp, signature, authorization,
    ...(snapshot !== undefined ? { profile: snapshot } : {}) };
}
