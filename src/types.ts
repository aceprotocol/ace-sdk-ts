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

export interface PricingInfo {
  model: 'per-call' | 'per-token' | 'per-hour' | 'flat';
  amount: string;
  currency: string;
}

export interface Capability {
  id: string;
  description: string;
  input?: string;
  output?: string;
  pricing?: PricingInfo;
}

export interface ChainInfo {
  network: string; // CAIP-2
  address: string;
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
  id: string;
  name: string;
  description?: string;
  endpoint: string;
  tier: IdentityTier;
  hardwareBacking?: HardwareBacking;
  signing: SigningConfig;
  capabilities?: Capability[];
  settlement?: string[];
  chains?: ChainInfo[];
}

// === Discovery ===

export interface ProfilePricing {
  currency: string;
  maxAmount?: string;
}

/** Relay discovery profile: self-asserted metadata. All fields optional. */
export interface AgentProfile {
  name?: string;
  description?: string;
  image?: string;
  tags?: string[];
  capabilities?: string[];
  chains?: string[];
  endpoint?: string;
  pricing?: ProfilePricing;
}

export interface DiscoverQuery {
  q?: string;
  /** Exact-match tags (all must match); sent comma-separated. */
  tags?: string[];
  chain?: string;
  scheme?: SigningScheme;
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
  maxPrice?: string;
  currency?: string;
  ttl: number;
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
  | 'info' | 'text';

export const MESSAGE_TYPES: readonly MessageType[] = [
  'rfq', 'offer', 'accept', 'reject', 'invoice', 'receipt', 'deliver', 'confirm', 'info', 'text',
];
export const ECONOMIC_TYPES: readonly MessageType[] = MESSAGE_TYPES.slice(0, 8);

export function isMessageType(t: unknown): t is MessageType {
  return typeof t === 'string' && (MESSAGE_TYPES as readonly string[]).includes(t);
}

export function isEconomicType(t: unknown): boolean {
  return typeof t === 'string' && (ECONOMIC_TYPES as readonly string[]).includes(t);
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
  ace: '1.0';
  messageId: string;
  from: string;
  to: string;
  conversationId: string;
  type: MessageType;
  threadId?: string;
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
