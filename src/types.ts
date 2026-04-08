// === Identity Types ===

export type SigningScheme = 'ed25519' | 'secp256k1';
export type HardwareBacking = 'secure-enclave' | 'tpm' | 'hsm' | 'tee';
export type IdentityTier = 0 | 1;

export interface ACEIdentity {
  getEncryptionPublicKey(): Uint8Array;
  getSigningPublicKey(): Uint8Array;
  decrypt(ephemeralPub: Uint8Array, payload: Uint8Array, conversationId: string): Promise<Uint8Array>;
  sign(data: Uint8Array): Promise<{ signature: Uint8Array; scheme: SigningScheme }>;
  getAddress(): string;
  getSigningScheme(): SigningScheme;
  getTier(): IdentityTier;
  getACEId(): string;
}

// === Registration File Types ===

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
  network: string; // CAIP-2 format, e.g., "eip155:8453"
  address: string;
}

// --- Discovery Profile ---

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

export interface ProfilePricing {
  currency: string;
  maxAmount?: string;
}

export interface DiscoverQuery {
  q?: string;
  tags?: string;
  chain?: string;
  scheme?: string;
  online?: boolean;
  limit?: number;
  cursor?: string;
}

export interface DiscoverAgent {
  aceId: string;
  encryptionPublicKey: string;
  signingPublicKey: string;
  scheme: SigningScheme;
  profile: AgentProfile;
}

export interface DiscoverResult {
  agents: DiscoverAgent[];
  cursor: string | null;
}

export interface SigningConfig {
  scheme: SigningScheme;
  address: string;
  signingPublicKey?: string; // Base64, required for secp256k1
  encryptionPublicKey: string; // Base64, always required
}

export interface RegistrationFile {
  ace: '1.0';
  id: string; // ace:sha256:<fingerprint>
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

// === Message Types ===

export type MessageType =
  | 'rfq' | 'offer' | 'accept' | 'reject'
  | 'invoice' | 'receipt'
  | 'deliver' | 'confirm'
  | 'info' | 'text';

export const ECONOMIC_TYPES: ReadonlySet<MessageType> = new Set([
  'rfq', 'offer', 'accept', 'reject',
  'invoice', 'receipt',
  'deliver', 'confirm',
]);

export const SYSTEM_TYPES: ReadonlySet<MessageType> = new Set(['info']);
export const SOCIAL_TYPES: ReadonlySet<MessageType> = new Set(['text']);

export interface EncryptionEnvelope {
  ephemeralPubKey: string; // Base64
  payload: string; // Base64(nonce || ciphertext || tag)
}

export interface SignatureEnvelope {
  scheme: SigningScheme;
  value: string; // Base64 (ed25519) or 0x-hex (secp256k1)
}

export interface ACEMessage {
  ace: '1.0';
  messageId: string;
  from: string; // ACE ID
  to: string; // ACE ID
  conversationId: string;
  type: MessageType;
  threadId?: string;
  timestamp: number; // Unix seconds
  encryption: EncryptionEnvelope;
  signature: SignatureEnvelope;
}

// === Economic Message Body Types ===

export interface RfqBody {
  need: string;
  maxPrice?: string;
  currency?: string;
  ttl?: number;
}

export interface OfferBody {
  price: string;
  currency: string;
  terms?: string;
  ttl?: number;
}

export interface AcceptBody {
  offerId: string;
}

export interface RejectBody {
  reason?: string;
}

export interface InvoiceBody {
  offerId: string;
  amount: string;
  currency: string;
  settlementMethod: string;
  settlementDetails?: Record<string, unknown>;
}

export interface ReceiptBody {
  invoiceId: string;
  amount: string;
  currency: string;
  settlementMethod: string;
  proof: Record<string, unknown>;
}

export interface DeliverBody {
  type: 'inline' | 'reference';
  content?: string;
  contentType?: string;
  uri?: string;
  metadata?: Record<string, unknown>;
}

export interface ConfirmBody {
  deliverId: string;
  message?: string;
}

export interface InfoBody {
  message: string;
}

export interface TextBody {
  message: string;
}

// === Type Guards ===

export function isEconomicType(type: MessageType): boolean {
  return ECONOMIC_TYPES.has(type);
}

export function isSystemType(type: MessageType): boolean {
  return SYSTEM_TYPES.has(type);
}

export function isSocialType(type: MessageType): boolean {
  return SOCIAL_TYPES.has(type);
}
