import bs58 from 'bs58';
import type { AgentProfile, RegistrationFile, SigningScheme } from './types.js';
import { computeACEId, fromBase64, secp256k1Address } from './identity.js';
import { buildSignData, encodePayload, verifySignature, decodeSignature } from './signing.js';
import { constantTimeEqual, CONTROL_CHAR_PATTERN } from './utils.js';
import { decodeKemPublicKey } from './encryption.js';

const DEFAULT_FETCH_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_REGISTRATION_BYTES = 1_048_576;

function decodeEd25519Address(address: string): Uint8Array {
  const pubKey = bs58.decode(address);
  if (pubKey.length !== 32) {
    throw new Error(`ed25519 signing.address must decode to 32 bytes, got ${pubKey.length}`);
  }
  return pubKey;
}

export interface FetchRegistrationFileOptions {
  timeoutMs?: number;
  maxBytes?: number;
  /** Set to true to skip SSRF protection (e.g. when behind a secure proxy). */
  allowPrivateIPs?: boolean;
}

/**
 * Validate ACE ID format: ace:sha256:<64 hex chars>
 */
export function validateACEId(id: string): boolean {
  return /^ace:sha256:[a-f0-9]{64}$/.test(id);
}

/**
 * Validate a registration file has all required fields and correct format.
 */
export function validateRegistrationFile(reg: RegistrationFile): void {
  if (reg.ace !== '1.0') {
    throw new Error(`Invalid ace version: expected '1.0', got '${reg.ace}'`);
  }
  if (!reg.id || !validateACEId(reg.id)) {
    throw new Error(`Invalid or missing ACE id: '${reg.id}'`);
  }
  if (!reg.name || typeof reg.name !== 'string') {
    throw new Error('Missing required field: name');
  }
  if (reg.name.length > 64) {
    throw new Error(`Registration name must be at most 64 characters, got ${reg.name.length}`);
  }
  if (CONTROL_CHAR_PATTERN.test(reg.name)) {
    throw new Error('Registration name must not contain control characters');
  }
  if (!reg.endpoint || typeof reg.endpoint !== 'string') {
    throw new Error('Missing required field: endpoint');
  }
  try {
    const endpointUrl = new URL(reg.endpoint);
    if (endpointUrl.protocol !== 'https:') {
      throw new Error(`Registration endpoint must use HTTPS: '${reg.endpoint.slice(0, 100)}'`);
    }
  } catch (e) {
    if (e instanceof Error && e.message.startsWith('Registration endpoint')) throw e;
    throw new Error(`Registration endpoint must be a valid URL: '${reg.endpoint.slice(0, 100)}'`);
  }
  if (reg.tier === undefined || ![0, 1].includes(reg.tier)) {
    throw new Error(`Invalid tier: ${reg.tier}`);
  }
  if (!reg.signing) {
    throw new Error('Missing required field: signing');
  }
  if (!reg.signing.scheme) {
    throw new Error('Missing required field: signing.scheme');
  }
  if (!reg.signing.address) {
    throw new Error('Missing required field: signing.address');
  }
  if (!reg.signing.encryptionPublicKey) {
    throw new Error('Missing required field: signing.encryptionPublicKey');
  }
  decodeKemPublicKey(reg.signing.encryptionPublicKey);

  if (reg.signing.scheme === 'ed25519') {
    const addressPubKey = decodeEd25519Address(reg.signing.address);
    if (reg.signing.signingPublicKey) {
      const signingPubKeyBytes = fromBase64(reg.signing.signingPublicKey);
      if (!constantTimeEqual(addressPubKey, signingPubKeyBytes)) {
        throw new Error('ed25519 signing.signingPublicKey does not match signing.address');
      }
    }
  } else if (reg.signing.scheme === 'secp256k1') {
    // secp256k1 requires signingPublicKey (address is a hash, can't recover pubkey from it)
    if (!reg.signing.signingPublicKey) {
      throw new Error('secp256k1 scheme requires signing.signingPublicKey');
    }
    const signingPubKeyBytes = fromBase64(reg.signing.signingPublicKey!);
    const derivedAddress = secp256k1Address(signingPubKeyBytes);
    if (reg.signing.address !== derivedAddress) {
      throw new Error('signing.address does not match signing.signingPublicKey');
    }
  }
}

/**
 * Verify that a registration file's ACE ID matches its signing key.
 */
export function verifyRegistrationId(reg: RegistrationFile): boolean {
  const signingPubKeyBytes = getRegistrationSigningPublicKey(reg);

  const expectedId = computeACEId(signingPubKeyBytes);
  if (reg.id !== expectedId) {
    return false;
  }
  if (reg.signing.scheme === 'secp256k1') {
    return reg.signing.address === secp256k1Address(signingPubKeyBytes);
  }
  return true;
}

/**
 * Extract the signing public key from a validated registration file.
 */
export function getRegistrationSigningPublicKey(reg: RegistrationFile): Uint8Array {
  if (reg.signing.scheme === 'ed25519') {
    const addressPubKey = decodeEd25519Address(reg.signing.address);
    if (reg.signing.signingPublicKey) {
      const signingPubKeyBytes = fromBase64(reg.signing.signingPublicKey);
      if (!constantTimeEqual(addressPubKey, signingPubKeyBytes)) {
        throw new Error('ed25519 signing.signingPublicKey does not match signing.address');
      }
    }
    return addressPubKey;
  }
  if (reg.signing.signingPublicKey) {
    return fromBase64(reg.signing.signingPublicKey);
  }
  throw new Error('Cannot derive signing public key from registration file');
}

/**
 * Extract the X-Wing encryption public key (1216 bytes) from a validated registration file.
 */
export function getRegistrationEncryptionPublicKey(reg: RegistrationFile): Uint8Array {
  return decodeKemPublicKey(reg.signing.encryptionPublicKey);
}

// === Encryption-key binding (relay-sourced peer keys) ===
//
// `aceId` self-certifies only the SIGNING key (aceId === sha256(signingKey)). The
// X-Wing ENCRYPTION key is separate — on its own it is an unauthenticated claim.
// A relay routes ciphertext and is untrusted by design, so it could hand a client
// its own X-Wing key and read messages the client believes are end-to-end
// encrypted. The binding below is the proof that closes that gap: the exact
// signature the relay already requires at registration, verifiable with nothing
// but the identity's own signing key.

/** Shape of a `GET /v1/peer` response or a `/v1/discover` agent entry. */
export interface RelayPeerResponse {
  aceId: string;
  scheme: SigningScheme;
  encryptionPublicKey: string;
  signingPublicKey: string;
  registrationSignature?: string;
  registeredAt?: number;
}

/** A peer's public keys AFTER the identity + encryption-key binding are verified. */
export interface VerifiedPeer {
  aceId: string;
  scheme: SigningScheme;
  signingPublicKey: Uint8Array;
  encryptionPublicKey: Uint8Array;
}

/**
 * Verify that `encryptionPublicKey` was authorized by `aceId`.
 *
 * The binding is identical to what `POST /v1/register` signs:
 *   buildSignData('register', aceId, timestamp,
 *                 encodePayload(encryptionPublicKey, signingPublicKey))
 * signed by the identity's signing key. This also re-checks
 * `aceId === sha256(signingPublicKey)`, so `true` means: this exact X-Wing key was
 * signed by the key that defines this identity.
 *
 * `encryptionPublicKey` / `signingPublicKey` MUST be the Base64 wire strings (the
 * signature commits to those strings). Returns `false` on any malformed input.
 */
export function verifyEncryptionKeyBinding(
  aceId: string,
  scheme: SigningScheme,
  encryptionPublicKey: string,
  signingPublicKey: string,
  timestamp: number,
  signature: string,
): boolean {
  if (scheme !== 'ed25519' && scheme !== 'secp256k1') return false;
  if (!Number.isInteger(timestamp)) return false;
  try {
    // The bound key must be a well-formed X-Wing public key.
    decodeKemPublicKey(encryptionPublicKey);
    const signingPubBytes = fromBase64(signingPublicKey);
    // The signing key must be the one that defines this identity.
    if (computeACEId(signingPubBytes) !== aceId) return false;
    const payload = encodePayload(encryptionPublicKey, signingPublicKey);
    const signData = buildSignData('register', aceId, timestamp, payload);
    const sigBytes = decodeSignature(signature, scheme);
    return verifySignature(signData, sigBytes, scheme, signingPubBytes);
  } catch {
    // Malformed key/signature bytes → treat as failed verification.
    return false;
  }
}

/**
 * Build a {@link VerifiedPeer} from a relay `GET /v1/peer` or `/v1/discover` entry.
 *
 * Throws if the binding signature is absent or fails — a relay that substitutes an
 * X-Wing key cannot produce a passing binding, so a VerifiedPeer can only be
 * obtained for a genuine key. Use its keys with {@link parseMessageFromPeer}.
 */
export function verifyPeerResponse(data: RelayPeerResponse): VerifiedPeer {
  const { aceId, scheme, encryptionPublicKey, signingPublicKey, registrationSignature, registeredAt } = data;

  if (typeof aceId !== 'string' || !validateACEId(aceId)) {
    throw new Error(`Invalid peer aceId: '${String(aceId).slice(0, 80)}'`);
  }
  if (scheme !== 'ed25519' && scheme !== 'secp256k1') {
    throw new Error(`Unsupported peer signing scheme: '${String(scheme).slice(0, 32)}'`);
  }
  if (registrationSignature === undefined || registeredAt === undefined) {
    throw new Error(
      'Peer response is missing the encryption-key binding (registrationSignature/registeredAt); ' +
      'its encryptionPublicKey cannot be trusted. Without the binding a relay could substitute ' +
      'its own X-Wing key and read messages meant to be end-to-end encrypted.',
    );
  }
  if (!verifyEncryptionKeyBinding(aceId, scheme, encryptionPublicKey, signingPublicKey, registeredAt, registrationSignature)) {
    throw new Error(
      'Peer encryption-key binding failed verification: the encryptionPublicKey is not signed by ' +
      "this identity's signing key (possible key substitution / relay MITM).",
    );
  }
  // The binding passed, so both strings are well-formed; decode them once here.
  return {
    aceId,
    scheme,
    signingPublicKey: fromBase64(signingPublicKey),
    encryptionPublicKey: decodeKemPublicKey(encryptionPublicKey),
  };
}

const TAG_PATTERN = /^[a-z0-9][a-z0-9-]*$/;

function validateTagLikeArray(items: string[], fieldName: string, maxCount: number): void {
  if (items.length > maxCount) {
    throw new Error(`profile.${fieldName} must have at most ${maxCount} items, got ${items.length}`);
  }
  for (const item of items) {
    if (item.length > 32) {
      throw new Error(`profile.${fieldName} item must be at most 32 characters: '${item}'`);
    }
    if (!TAG_PATTERN.test(item)) {
      throw new Error(`profile.${fieldName} item must match /^[a-z0-9][a-z0-9-]*$/: '${item}'`);
    }
  }
}

/**
 * Validate an AgentProfile object.
 * Throws an Error describing the first violation found.
 * An empty profile `{}` is valid.
 */
export function validateProfile(profile: AgentProfile): void {
  if (profile.name !== undefined) {
    if (profile.name.length < 1 || profile.name.length > 64) {
      throw new Error(`profile.name must be 1-64 characters, got ${profile.name.length}`);
    }
    if (CONTROL_CHAR_PATTERN.test(profile.name)) {
      throw new Error('profile.name must not contain control characters');
    }
  }

  if (profile.description !== undefined) {
    if (profile.description.length > 256) {
      throw new Error(`profile.description must be at most 256 characters, got ${profile.description.length}`);
    }
    // Reject control characters (U+0000–U+001F and U+007F)
    if (CONTROL_CHAR_PATTERN.test(profile.description)) {
      throw new Error('profile.description must not contain control characters');
    }
  }

  if (profile.image !== undefined) {
    if (profile.image.length > 512) {
      throw new Error(`profile.image must be at most 512 characters, got ${profile.image.length}`);
    }
    let url: URL;
    try {
      url = new URL(profile.image);
    } catch {
      throw new Error(`profile.image must be a valid URL: '${profile.image}'`);
    }
    if (url.protocol !== 'https:') {
      throw new Error(`profile.image must use HTTPS: '${profile.image}'`);
    }
  }

  if (profile.tags !== undefined) {
    validateTagLikeArray(profile.tags, 'tags', 10);
  }

  if (profile.capabilities !== undefined) {
    validateTagLikeArray(profile.capabilities, 'capabilities', 20);
  }

  if (profile.chains !== undefined) {
    if (profile.chains.length > 10) {
      throw new Error(`profile.chains must have at most 10 items, got ${profile.chains.length}`);
    }
    for (const chain of profile.chains) {
      if (!chain.includes(':')) {
        throw new Error(`profile.chains item must be in CAIP-2 format (must contain ':'): '${chain}'`);
      }
      const [namespace, reference] = chain.split(':', 2);
      if (!namespace || !reference) {
        throw new Error(`profile.chains item must have non-empty namespace and reference: '${chain}'`);
      }
    }
  }

  if (profile.endpoint !== undefined) {
    let url: URL;
    try {
      url = new URL(profile.endpoint);
    } catch {
      throw new Error(`profile.endpoint must be a valid URL: '${profile.endpoint}'`);
    }
    if (url.protocol !== 'https:') {
      throw new Error(`profile.endpoint must use HTTPS: '${profile.endpoint}'`);
    }
  }

  if (profile.pricing !== undefined) {
    if (!profile.pricing.currency || profile.pricing.currency.length === 0) {
      throw new Error('profile.pricing.currency must be a non-empty string');
    }
  }
}

// Strict domain validation: alphanumeric, hyphens, dots only. No ports, paths, or URL-special chars.
const VALID_DOMAIN_PATTERN = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

/**
 * SSRF protection: reject domains that are known private/internal hostnames.
 * This is a defense-in-depth check — it does NOT replace network-level controls.
 * DNS rebinding attacks can bypass this; production deployments should use
 * egress firewalls or HTTP proxies for full protection.
 */
const PRIVATE_DOMAIN_PATTERNS: RegExp[] = [
  /^localhost$/i,
  /\.localhost$/i,
  /\.local$/i,
  /\.internal$/i,
];

/**
 * Check if a resolved IP address is private/internal.
 * Covers: loopback, link-local, RFC 1918, carrier-grade NAT, multicast, broadcast,
 * and cloud metadata endpoints (169.254.169.254).
 */
function isPrivateIP(ip: string): boolean {
  // IPv4 patterns
  if (ip.startsWith('127.')) return true;          // Loopback
  if (ip.startsWith('10.')) return true;           // RFC 1918 Class A
  if (ip.startsWith('0.')) return true;            // "This" network
  if (ip === '255.255.255.255') return true;       // Broadcast
  if (ip.startsWith('169.254.')) return true;      // Link-local / cloud metadata
  if (ip.startsWith('192.168.')) return true;      // RFC 1918 Class C
  if (ip.startsWith('100.')) {                     // Carrier-grade NAT (100.64.0.0/10)
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 64 && second <= 127) return true;
  }
  if (ip.startsWith('172.')) {                     // RFC 1918 Class B (172.16.0.0/12)
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  // IPv6 patterns
  const lower = ip.toLowerCase();
  if (lower === '::1') return true;                // Loopback
  if (lower === '::') return true;                 // Unspecified
  if (lower.startsWith('fe80:')) return true;      // Link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // Unique local
  // IPv4-mapped IPv6 (::ffff:127.0.0.1)
  if (lower.startsWith('::ffff:')) {
    const v4Part = lower.slice(7);
    if (isPrivateIP(v4Part)) return true;
  }
  return false;
}

// Lazy-cached DNS module (Node.js only — null in browsers)
let _dnsModule: { resolve4: (domain: string) => Promise<string[]>; resolve6: (domain: string) => Promise<string[]> } | null | undefined;
async function _getDnsPromises() {
  if (_dnsModule === undefined) {
    try { _dnsModule = (await import('node:dns')).promises; } catch { _dnsModule = null; }
  }
  return _dnsModule;
}

/**
 * Resolve domain and validate that it does not point to private/internal IP addresses.
 * Uses Node.js dns module when available; skips in browser environments.
 */
async function validateNotPrivateHost(domain: string): Promise<void> {
  // Check domain name patterns first (no DNS needed)
  for (const pattern of PRIVATE_DOMAIN_PATTERNS) {
    if (pattern.test(domain)) {
      throw new Error(`SSRF protection: domain '${domain.slice(0, 100)}' resolves to a private/internal host`);
    }
  }

  // Attempt DNS resolution (Node.js only — gracefully skip in browsers)
  try {
    const dns = await _getDnsPromises();
    if (dns) {
      const [r4, r6] = await Promise.allSettled([dns.resolve4(domain), dns.resolve6(domain)]);
      const results = [
        ...(r4.status === 'fulfilled' ? r4.value : []),
        ...(r6.status === 'fulfilled' ? r6.value : []),
      ];

      for (const ip of results) {
        if (isPrivateIP(ip)) {
          throw new Error(
            `SSRF protection: domain '${domain.slice(0, 100)}' resolves to private IP '${ip}'`,
          );
        }
      }
    }
  } catch (e) {
    // Re-throw SSRF errors
    if (e instanceof Error && e.message.startsWith('SSRF protection:')) throw e;
    // DNS module not available (browser) — domain name checks above are the only guard
  }
}

/**
 * Fetch and validate a registration file from a well-known URL.
 */
export async function fetchRegistrationFile(
  domain: string,
  opts: FetchRegistrationFileOptions = {},
): Promise<RegistrationFile> {
  if (!VALID_DOMAIN_PATTERN.test(domain)) {
    throw new Error(`Invalid domain: '${domain.slice(0, 100)}'`);
  }
  const timeoutMs = opts.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_REGISTRATION_BYTES;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error(`Invalid timeoutMs: expected positive finite milliseconds, got '${timeoutMs}'`);
  }
  if (!Number.isInteger(maxBytes) || maxBytes <= 0) {
    throw new Error(`Invalid maxBytes: expected positive integer, got '${maxBytes}'`);
  }

  // SSRF protection: validate domain does not resolve to private/internal IPs
  if (!opts.allowPrivateIPs) {
    await validateNotPrivateHost(domain);
  }

  const url = `https://${domain}/.well-known/ace.json`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(url, {
      headers: { Accept: 'application/json' },
      signal: controller.signal,
      // Never follow redirects — a redirect target would bypass the SSRF host
      // check above (e.g. 302 to http://169.254.169.254). fetch throws on 3xx.
      redirect: 'error',
    });
  } catch (e) {
    if (e instanceof Error && e.name === 'AbortError') {
      throw new Error(`Timed out fetching registration file from ${url} after ${timeoutMs}ms`);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch registration file: ${response.status} ${response.statusText}`);
  }

  const contentType = response.headers.get('content-type');
  if (!contentType || !contentType.includes('application/json')) {
    throw new Error(`Invalid or missing content-type: expected application/json, got '${contentType}'`);
  }

  const contentLength = response.headers.get('content-length');
  if (contentLength) {
    const declaredLength = Number(contentLength);
    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
      throw new Error(`Registration file too large: ${declaredLength} bytes exceeds max ${maxBytes}`);
    }
  }

  // Stream-read with early abort to prevent memory exhaustion from chunked responses
  const reader = response.body?.getReader();
  let bodyBytes: Uint8Array;
  if (reader) {
    const chunks: Uint8Array[] = [];
    let totalRead = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        totalRead += value.length;
        if (totalRead > maxBytes) {
          reader.cancel();
          throw new Error(`Registration file too large: exceeds max ${maxBytes} bytes`);
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    bodyBytes = new Uint8Array(totalRead);
    let offset = 0;
    for (const chunk of chunks) {
      bodyBytes.set(chunk, offset);
      offset += chunk.length;
    }
  } else {
    // Fallback for environments without ReadableStream
    bodyBytes = new Uint8Array(await response.arrayBuffer());
    if (bodyBytes.length > maxBytes) {
      throw new Error(`Registration file too large: ${bodyBytes.length} bytes exceeds max ${maxBytes}`);
    }
  }

  let reg: RegistrationFile;
  try {
    reg = JSON.parse(new TextDecoder().decode(bodyBytes)) as RegistrationFile;
  } catch {
    throw new Error('Failed to parse registration file: invalid JSON response');
  }
  validateRegistrationFile(reg);
  if (!verifyRegistrationId(reg)) {
    throw new Error('Registration ACE ID does not match signing key');
  }

  return reg;
}
