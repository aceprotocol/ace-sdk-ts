// ACE Protocol SDK — public API. Everything not exported here (or from ./node) is internal.

export type {
  ACEIdentity, SigningScheme, IdentityTier, HardwareBacking, RegistrationFile, SigningConfig, Capability,
  ExtMap, CommerceProfileExt, CommercePricing, CommerceAccount, CommerceIntentExt, AgentProfile, DiscoverQuery, PeerRecord, ACEMessage, MessageType,
  EncryptionEnvelope, SignatureEnvelope, RfqBody, OfferBody, AcceptBody, RejectBody, InvoiceBody, ReceiptBody,
  DeliverBody, ConfirmBody, InfoBody, TextBody, MessageRef, RequestBody, DecisionBody, ReportBody, JSONValue, JSONObject, ParsedMessage, ReplayState,
  RegistrationRequest, Intent, PrincipalKey, PrincipalRecord, PrincipalRole,
} from './types.js';
export type { PrincipalSigner, PrincipalContext, RequestRecord } from './principal.js';
export type { ExtCarrier } from './ext.js';
export type { ThreadState, ThreadSnapshot, ThreadHistoryEntry, ThreadEvent } from './state-machine.js';
export type { RelayAuthRequest, WebhookMethod } from './auth.js';
export type { Webhook, ListenEvent, InboxPage } from './relay.js';
export type { WebhookNotification, WebhookNotificationInput } from './webhook.js';
export type { ReceiveOutcome, InboxPrincipal } from './inbox.js';
export type { SchemaValidator } from './messages.js';
export type { PendingSend } from './outbox.js';
export type { ACEStore, StoreData, CoordinatedStore } from './store.js';
export type { ACEErrorCode, ACEErrorCategory } from './errors.js';
export type { SoftwareIdentityExport } from './identity.js';

export { ACEError } from './errors.js';
export { MESSAGE_TYPES, ECONOMIC_TYPES, PRINCIPAL_TYPES, isMessageType, isEconomicType, isPrincipalType, SIGNING_SCHEMES, isSigningScheme } from './types.js';
export {
  MAX_PLAINTEXT_BYTES, MAX_PAYLOAD_BYTES, MAX_ENVELOPE_BYTES, MAX_DIRECT_BODY_BYTES, MAX_JSON_DEPTH, MAX_THREAD_ID_LENGTH,
  MAX_OPEN_THREADS_PER_PEER, TIMESTAMP_WINDOW_SECONDS, OFFLINE_WINDOW_SECONDS, MAX_REGISTRATION_FILE_BYTES, MAX_INBOX_PAGE,
  KEM_SEED_SIZE, KEM_PUBLIC_KEY_SIZE, KEM_CIPHERTEXT_SIZE, DEFAULT_REPLAY_CAPACITY,
  MAX_EXT_KEYS, MAX_EXT_KEY_BYTES, MAX_EXT_BYTES, MAX_EXT_DEPTH,
} from './limits.js';
export { SoftwareIdentity, computeACEId } from './identity.js';
export { toBase64, fromBase64, isACEId, isMessageId, isThreadId, isConversationId, isHttpsUrl } from './encoding.js';
export { computeConversationId, decryptWithSeed, kemPublicKeyFromSeed, generateKemSeed } from './encryption.js';
export { decodeEnvelope, verifyEnvelopeSignature, envelopeFingerprint } from './envelope.js';
export { createMessage, parseMessage, validateBody, knownSchemaDigest } from './messages.js';
export {
  PRINCIPAL_ROLES, CAIP10_RE, isCaip10, principalSignerFromIdentity, principalPayload, principalSignData, createPrincipalRecord,
  validatePrincipalRecord, parsePrincipalRecord, checkPrincipalRules, loadRequestRecord,
} from './principal.js';
export {
  VerifiedPeer, verifyPeerRecord, verifyRegistrationFile, fetchRegistrationFile, validateProfile, isBlockedAddress,
} from './discovery.js';
export { COMMERCE_EXT, validateExt, validateCommerceExt, extCanonical, commerceExt, intentCommerceExt } from './ext.js';
export { createRegistrationFile, createRegistrationRequest, verifyRegistrationRequest } from './registration.js';
export { createAuthHeaders, parseAuthHeaders, verifyAuthHeaders, isWebhookSecret } from './auth.js';
export { signWebhookNotification, verifyWebhookNotification } from './webhook.js';
export { ReplayDetector } from './replay.js';
export { ThreadStateMachine } from './state-machine.js';
export { ThreadStore } from './thread-store.js';
export { PeerStore } from './peer-store.js';
export { Inbox, inboxPrincipalFromOwnRecord } from './inbox.js';
export { Outbox } from './outbox.js';
export { RelayClient } from './relay.js';
// The ACEStore contract checks, for third-party store implementations.
export { MemoryStore, checkKey, checkLockName, checkValue, checkTimeout, lockTimeoutError } from './store.js';

export { AuditTree, auditCommitment, createAuditOpening, createAuditCheckpoint, verifyAuditInclusion, verifyAuditConsistency, verifyAuditCheckpoint,
  auditCheckpointDigest, createAuditWitnessReceipt, verifyAuditWitnessReceipt, verifyAuditWitnessQuorum } from './audit.js';
export type { AuditCheckpoint, AuditWitnessReceipt, AuditWitnessPolicy } from './audit.js';

export { executionIntentDigest, executionGrantDigest, createExecutionGrant, verifyExecutionGrantChain, isExecutionUnits } from './grants.js';
export type { ExecutionIntent, GrantClaims, ExecutionGrant, ResourcePolicy } from './grants.js';
export { ExecutionAuthority } from './authority.js';
export type { AuthorityConfig, ExecutionReservation, ResourceUsage } from './authority.js';
export { EXECUTION_REQUEST_TYPE, EXECUTION_REQUEST_SCHEMA, EXECUTION_REQUEST_SCHEMA_DIGEST, parseExecutionRequest } from './execution-request.js';
export type { ExecutionRequest } from './execution-request.js';

export { AuditLog, AuditWitness } from './audit-store.js';
export type { AuditLogConfig, AuditWitnessConfig } from './audit-store.js';
