export {
  // Types
  type ACEIdentity,
  type SigningScheme,
  type IdentityTier,
  type HardwareBacking,
  type RegistrationFile,
  type SigningConfig,
  type Capability,
  type PricingInfo,
  type ChainInfo,
  type AgentProfile,
  type ProfilePricing,
  type DiscoverQuery,
  type DiscoverAgent,
  type DiscoverResult,
  type ACEMessage,
  type MessageType,
  type EncryptionEnvelope,
  type SignatureEnvelope,
  type RfqBody,
  type OfferBody,
  type AcceptBody,
  type RejectBody,
  type InvoiceBody,
  type ReceiptBody,
  type DeliverBody,
  type ConfirmBody,
  type InfoBody,
  type TextBody,
  // Type guards
  isMessageType,
  isEconomicType,
  isSystemType,
  isSocialType,
  MESSAGE_TYPES,
  ECONOMIC_TYPES,
  SYSTEM_TYPES,
  SOCIAL_TYPES,
} from './types.js';

export { SoftwareIdentity, type SoftwareIdentityExport, type SoftwareIdentityBinaryExport, computeACEId, toBase64, fromBase64, secp256k1Address } from './identity.js';
export {
  computeConversationId, encrypt, decrypt, getACEKemSalt,
  kemEncapsulate, kemDecapsulate, kemPublicKeyFromSeed, generateKemSeed,
  validatePublicKey, validateKemCiphertext, validateSeed,
  decodeKemPublicKey, decodeKemCiphertext,
  KEM_SEED_SIZE, KEM_PUBLIC_KEY_SIZE, KEM_CIPHERTEXT_SIZE,
  MAX_PAYLOAD_SIZE, MAX_PLAINTEXT_SIZE,
} from './encryption.js';
export { buildSignData, encodePayload, verifySignature, encodeSignature, decodeSignature } from './signing.js';
export { createMessage, parseMessage, parseMessageFromRegistration, parseMessageFromPeer, validateBody, type CreateMessageOptions, type ParsedMessage, type ParseMessageOptions, type ParseMessageFromRegistrationOptions } from './messages.js';
export { validateRegistrationFile, validateACEId, verifyRegistrationId, fetchRegistrationFile, getRegistrationSigningPublicKey, getRegistrationEncryptionPublicKey, validateProfile, verifyEncryptionKeyBinding, verifyPeerResponse, type RegistrationKeys, type FetchRegistrationFileOptions, type RelayPeerResponse, type VerifiedPeer } from './discovery.js';
export { checkTimestampFreshness, validateMessageId, ReplayDetector, type ReplayDetectorExport } from './security.js';
export { ThreadStateMachine, InvalidTransitionError, validateThreadId, type ThreadState, type ThreadSnapshot, type ThreadStateMachineOptions } from './state-machine.js';
export { createRegistrationRequest, buildRegistrationPayload, type RegistrationRequest } from './registration.js';
