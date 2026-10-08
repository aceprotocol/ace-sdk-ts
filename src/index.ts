// ACE Protocol SDK — public API. Everything not exported here (or from ./node) is internal.

export type {
  ACEIdentity, SigningScheme, IdentityTier, HardwareBacking, RegistrationFile, SigningConfig, Capability,
  PricingInfo, ChainInfo, AgentProfile, ProfilePricing, DiscoverQuery, PeerRecord, ACEMessage, MessageType,
  EncryptionEnvelope, SignatureEnvelope, RfqBody, OfferBody, AcceptBody, RejectBody, InvoiceBody, ReceiptBody,
  DeliverBody, ConfirmBody, InfoBody, TextBody, MessageRef, RequestBody, DecisionBody, ReportBody, JSONValue, JSONObject, ParsedMessage, ReplayState,
  RegistrationRequest, Intent,
} from './types.js';
export type { ThreadState, ThreadSnapshot, ThreadHistoryEntry, ThreadEvent } from './state-machine.js';
export type { RelayAuthRequest, WebhookMethod } from './auth.js';
export type { Webhook, ListenEvent, InboxPage } from './relay.js';
export type { WebhookNotification, WebhookNotificationInput } from './webhook.js';
export type { ReceiveSource, ReceiveOutcome, DirectReply } from './inbox.js';
export type { PendingSend } from './outbox.js';
export type { ACEStore } from './store.js';
export type { ACEErrorCode, ACEErrorCategory } from './errors.js';
export type { SoftwareIdentityExport } from './identity.js';

export { ACEError } from './errors.js';
export { MESSAGE_TYPES, ECONOMIC_TYPES, PRINCIPAL_TYPES, isMessageType, isEconomicType, isPrincipalType, SIGNING_SCHEMES, isSigningScheme } from './types.js';
export {
  MAX_PLAINTEXT_BYTES, MAX_PAYLOAD_BYTES, MAX_ENVELOPE_BYTES, MAX_DIRECT_BODY_BYTES, MAX_JSON_DEPTH, MAX_THREAD_ID_LENGTH,
  MAX_OPEN_THREADS_PER_PEER, TIMESTAMP_WINDOW_SECONDS, OFFLINE_WINDOW_SECONDS, MAX_REGISTRATION_FILE_BYTES, MAX_INBOX_PAGE,
  KEM_SEED_SIZE, KEM_PUBLIC_KEY_SIZE, KEM_CIPHERTEXT_SIZE, DEFAULT_REPLAY_CAPACITY,
} from './limits.js';
export { SoftwareIdentity, computeACEId } from './identity.js';
export { toBase64, fromBase64, isACEId, isMessageId, isThreadId, isConversationId, isHttpsUrl } from './encoding.js';
export { computeConversationId, decryptWithSeed, kemPublicKeyFromSeed, generateKemSeed } from './encryption.js';
export { decodeEnvelope, verifyEnvelopeSignature, envelopeFingerprint } from './envelope.js';
export { createMessage, parseMessage, validateBody } from './messages.js';
export {
  VerifiedPeer, verifyPeerRecord, verifyRegistrationFile, fetchRegistrationFile, validateProfile, isBlockedAddress,
} from './discovery.js';
export { createRegistrationFile, createRegistrationRequest, verifyRegistrationRequest } from './registration.js';
export { createAuthHeaders, parseAuthHeaders, verifyAuthHeaders, isWebhookSecret } from './auth.js';
export { signWebhookNotification, verifyWebhookNotification } from './webhook.js';
export { ReplayDetector } from './replay.js';
export { ThreadStateMachine } from './state-machine.js';
export { ThreadStore } from './thread-store.js';
export { PeerStore } from './peer-store.js';
export { Inbox, PullResult } from './inbox.js';
export { Outbox } from './outbox.js';
export { RelayClient } from './relay.js';
export { MemoryStore } from './store.js';
