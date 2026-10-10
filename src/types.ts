/** ACE Protocol type definitions. */

export type SigningScheme = 'ed25519' | 'secp256k1';
export type HardwareBacking = 'secure-enclave' | 'tpm' | 'hsm' | 'tee';
export type IdentityTier = 0 | 1;

export const SIGNING_SCHEMES: readonly SigningScheme[] = ['ed25519', 'secp256k1'];

export function isSigningScheme(v: unknown): v is SigningScheme {
  return v === 'ed25519' || v === 'secp256k1';
}

export type JSONValue = null | boolean | number | string | JSONValue[] | { [key: string]: JSONValue };
export type JSONObject = { [key: string]: JSONValue };

/** ASCII namespaced identifier (04 § Message Types grammar); also the key grammar of `ext`. */
export const NAMESPACED_ID_RE = /^[a-z][a-z0-9+.-]*:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$/;

// === Extensions (02 § Profile Fields) ===

/**
 * Namespaced extensions of a profile, registration file or intent: each key is a namespaced identifier (at most 256
 * bytes), each value a JSON object; at most 8 keys, canonical JSON at most 4096 bytes, nesting depth at most 8.
 * Validated by `validateExt`; the bundled `urn:ace:commerce:1` member is typed (`CommerceProfileExt`, `CommerceIntentExt`).
 */
export type ExtMap = { [namespace: string]: JSONObject };

/** `urn:ace:commerce:1` in a profile or registration file (04 § Commerce extension). */
export interface CommerceProfileExt {
  /** CAIP-2 identifiers, at most 10. */
  chains?: string[];
  pricing?: CommercePricing;
  /** Settlement methods (05), at most 10. */
  settlement?: string[];
  /** Payment addresses, at most 10. */
  accounts?: CommerceAccount[];
}

export interface CommercePricing {
  /** 1-16 characters without control characters. */
  currency: string;
  /** 1-32 characters matching `^[0-9]+(\.[0-9]+)?$`. */
  maxAmount?: string;
}

export interface CommerceAccount {
  /** CAIP-2. */
  network: string;
  address: string;
}

/** `urn:ace:commerce:1` in an intent: `maxPrice` (1-64) and `currency` (1-16), both present or both absent. */
export interface CommerceIntentExt {
  maxPrice?: string;
  currency?: string;
}

/**
 * What the SDK needs from an identity (software, Secure Enclave, HSM, ...).
 *
 * `decrypt`: an `ACEError` passes through unchanged; any other thrown error is
 * reported by the SDK as `identity_unavailable` (local, retryable), so a keychain or
 * hardware failure is retried instead of quarantined.
 */
export interface ACEIdentity {
  getACEId(): string;
  getSigningScheme(): SigningScheme;
  getSigningPublicKey(): Uint8Array;
  /** X-Wing public key, 1216 bytes. */
  getEncryptionPublicKey(): Uint8Array;
  /** Sign a 32-byte signData digest. secp256k1 returns r‖s‖v (low-S, v ∈ {0,1}). */
  sign(data: Uint8Array): Promise<Uint8Array>;
  decrypt(kemCiphertext: Uint8Array, payload: Uint8Array, conversationId: string): Promise<Uint8Array>;
}

// === Registration file ===

export interface Capability {
  id: string;
  description: string;
  input?: string;
  output?: string;
}

export interface SigningConfig {
  scheme: SigningScheme;
  address: string;
  /** Base64; required for secp256k1 (33-byte compressed point). */
  signingPublicKey?: string;
  /** Base64 of the 1216-byte X-Wing public key. */
  encryptionPublicKey: string;
}

export interface RegistrationFile {
  ace: '1.0';
  registeredAt: number;
  registrationSignature: string;
  id: string;
  name: string;
  description?: string;
  endpoint: string;
  tier: IdentityTier;
  hardwareBacking?: HardwareBacking;
  signing: SigningConfig;
  capabilities?: Capability[];
  /** Namespaced extensions, same rules as a profile's `ext` (commerce data lives under `urn:ace:commerce:1`). */
  ext?: ExtMap;
  principal?: PrincipalRecord;
}

// === Principal (09) ===

/** `controller` approves; `delegate` acts. */
export type PrincipalRole = 'controller' | 'delegate';

/** A `(scheme, publicKey)` pair as it appears in a principal record (`publicKey` is canonical Base64). */
export interface PrincipalKey {
  scheme: SigningScheme;
  publicKey: string;
}

/** 09-principal § Principal Record (wire shape). Semantic checks: `validatePrincipalRecord`. */
export interface PrincipalRecord {
  account: string;
  roles: PrincipalRole[];
  signer: PrincipalKey;
  issuedAt: number;
  /** Required; `issuedAt < expiresAt <= issuedAt + 31622400`. */
  expiresAt: number;
  scope?: string;
  signature: string;
}

// === Discovery ===

/** Relay discovery profile: self-asserted metadata. All fields optional. */
export interface AgentProfile {
  name?: string;
  description?: string;
  image?: string;
  tags?: string[];
  capabilities?: string[];
  endpoint?: string;
  /** Namespaced extensions (02 § Profile Fields); stored and served in canonical form, never indexed. */
  ext?: ExtMap;
  /** Principal record (09), verified against the peer's signing key when the peer is verified. */
  principal?: PrincipalRecord;
}

export interface DiscoverQuery {
  q?: string;
  /** Exact-match tags (all must match); sent comma-separated. */
  tags?: string[];
  scheme?: SigningScheme;
  /** CAIP-10 account (exact match on profile.principal.account). */
  account?: string;
  online?: boolean;
  limit?: number;
  cursor?: string;
}

/** Wire shape of `GET /v1/peer` and each `/v1/discover` entry. */
export interface PeerRecord {
  aceId: string;
  scheme: SigningScheme;
  encryptionPublicKey: string;
  signingPublicKey: string;
  registrationSignature: string;
  registeredAt: number;
  profile?: AgentProfile;
}

/** `POST /v1/register` body. Omitted profile = keep, null = remove, object = replace. */
export interface RegistrationRequest {
  aceId: string;
  encryptionPublicKey: string;
  signingPublicKey: string;
  scheme: SigningScheme;
  timestamp: number;
  signature: string;
  authorization: string;
  profile?: AgentProfile | null;
}

/** An intent from `GET /v1/intents`. */
export interface Intent {
  intentId: string;
  from: string;
  need: string;
  tags: string[];
  ttl: number;
  /** Present only when non-empty; `urn:ace:commerce:1` carries `maxPrice` / `currency`. */
  ext?: ExtMap;
  createdAt: number;
  expiresAt: number;
}

/** Canonical replay.json: entries `[messageId, sender, timestamp]` sorted by (timestamp, sender, messageId). */
export interface ReplayState {
  entries: Array<[string, string, number]>;
  horizon: number;
  senderHorizons: Record<string, number>;
  version: 1;
}

// === Messages ===

export type MessageType =
  | 'rfq' | 'offer' | 'accept' | 'reject' | 'invoice' | 'receipt' | 'deliver' | 'confirm'
  | 'info' | 'text'
  | 'request' | 'decision' | 'report'
  | `${string}:${string}`;

export const MESSAGE_TYPES: readonly MessageType[] = [
  'rfq', 'offer', 'accept', 'reject', 'invoice', 'receipt', 'deliver', 'confirm', 'info', 'text',
  'request', 'decision', 'report',
];
export const ECONOMIC_TYPES: readonly MessageType[] = MESSAGE_TYPES.slice(0, 8);
export const PRINCIPAL_TYPES: readonly MessageType[] = MESSAGE_TYPES.slice(10);

export function isMessageType(t: unknown): t is MessageType {
  return typeof t === 'string' && ((MESSAGE_TYPES as readonly string[]).includes(t)
    || (t.length <= 256 && NAMESPACED_ID_RE.exec(t)?.[0] === t));
}

export function isEconomicType(t: unknown): boolean {
  return typeof t === 'string' && (ECONOMIC_TYPES as readonly string[]).includes(t);
}

export function isPrincipalType(t: unknown): boolean {
  return typeof t === 'string' && (PRINCIPAL_TYPES as readonly string[]).includes(t);
}

export interface EncryptionEnvelope {
  /** Base64 of the 1120-byte X-Wing ciphertext. */
  kemCiphertext: string;
  /** Base64(nonce ‖ ciphertext ‖ tag). */
  payload: string;
}

export interface SignatureEnvelope {
  scheme: SigningScheme;
  /** ed25519: Base64; secp256k1: `0x` + 130 lowercase hex. */
  value: string;
}

/** A decoded envelope (wire shape). Obtain from `decodeEnvelope` or `createMessage`. */
export interface ACEMessage {
  ace: '2.0';
  messageId: string;
  from: string;
  to: string;
  conversationId: string;
  timestamp: number;
  encryption: EncryptionEnvelope;
  signature: SignatureEnvelope;
}

export interface ParsedMessage {
  messageId: string;
  from: string;
  to: string;
  conversationId: string;
  type: MessageType;
  /** SHA-256 of the locally installed schema definition; never fetched from the sender. */
  schemaDigest: string;
  threadId: string | null;
  timestamp: number;
  body: JSONObject;
}

// === Bodies ===

export interface RfqBody { need: string; maxPrice?: string; currency?: string; ttl?: number }
export interface OfferBody { price: string; currency: string; terms?: string; ttl?: number }
export interface AcceptBody { offerId: string }
export interface RejectBody { reason?: string }
export interface InvoiceBody {
  offerId: string; amount: string; currency: string; settlementMethod: string;
  settlementDetails?: JSONObject;
}
export interface ReceiptBody {
  referenceId: string; amount: string; currency: string; settlementMethod: string; proof: JSONObject;
}
export interface DeliverBody {
  type: 'inline' | 'reference'; content?: string; contentType?: string; uri?: string; metadata?: JSONObject;
}
export interface ConfirmBody { deliverId: string; message?: string }
export interface InfoBody { message: string }
export interface TextBody { message: string }

export interface MessageRef { conversationId: string; threadId?: string; messageId: string }
export interface RequestBody {
  action: string; summary: string; ref?: MessageRef; amount?: string; currency?: string; details?: JSONObject; ttl?: number;
}
export interface DecisionBody { requestId: string; outcome: 'approve' | 'deny'; reason?: string; result?: JSONObject }
export interface ReportBody {
  action: string; summary: string; outcome: 'ok' | 'failed' | 'skipped'; ref?: MessageRef; requestId?: string; proof?: JSONObject;
}
