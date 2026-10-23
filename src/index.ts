// ACE Protocol SDK — the single public entry point.

export { ACEError, isOutcomeCode, type ACEErrorCode, type ACEErrorCategory, type ACEErrorOptions } from './errors.js';
export * from './limits.js';
export {
  canonicalStateBytes, conversationKey, sha256Hex, toBase64, fromBase64, ACE_ID_RE, CAIP10_RE, HANDLE_RE, isACEId, isMessageId, isThreadId, isHandle, handleAddress,
  isHex64, isHttpsUrl,
} from './encoding.js';
export { encodePayload, signingMessage, verifySignature } from './signing.js';
export type { SigningScheme, JSONValue, JSONObject, Admission, PrivateContent, ParsedMessage } from './types.js';
export { isMessageType } from './types.js';

export { SoftwareKey, generateSoftwareKey, keyDigest, type KeyProvider } from './keys.js';
export {
  verifyKel, extendKel, verifyOperationalSignature, eventHashes,
  type KelState, type KelEvent, type DelegatedKey, type ExtendOutcome, type OperationalSignature,
} from './kel.js';
export { SoftwareIdentity, type ACEIdentity, type SoftwareIdentityExport } from './identity.js';
export {
  StorePrekeyVault,
  type PrekeyVault, type Prekey, type PrekeyInfo, type PrekeySecret, type SecretProtector,
} from './prekey.js';
export {
  createPacket, decodePacket, parsePacket, verifyPacketSignature, checkPacketTime, decryptPacket,
  type Packet, type CreatePacketInput,
} from './packet.js';
export {
  createDescriptor, verifyPublishedAgent, validateCard, validateExt, createDelegationCredential, verifyDelegation,
  validateErc8004Binding, verifyErc8004Registration, createPermit, verifyPermit, documentDigest, delegationIssuers,
  type AgentDescriptor, type PublishedAgent, type VerifiedAgent, type DescriptorOptions, type VerifyOptions, type AgentCard,
  type DelegationCredential, type DescriptorDelegation, type Erc8004Binding, type DeliveryPermit,
} from './descriptor.js';
export {
  createCardRecord, verifyCardBundle, isCaip10Account, type CardRecord, type CardBundle, type VerifiedCard, type Contact,
} from './card-record.js';
export {
  ProfileSet, validateProfileManifest, profileDigest, messageDigest, BUNDLED_MANIFESTS,
  CORE_PROFILE_ID, RECEIPT_TYPE, CONTACT_TYPE, TEXT_TYPE, type ProfileManifest, type NetworkProfile,
} from './manifest.js';
export {
  receiptContent, contactContent, checkReceiptBody, RECEIPT_SCHEMA_DIGEST, CONTACT_SCHEMA_DIGEST, type ReceiptBody, type ContactBody,
} from './core-messages.js';
export type { ProfileRules, RuleEvent } from './rules.js';

export { MemoryStore, checkKey, checkLockName, checkValue, checkTimeout, lockTimeoutError, type ACEStore, type StoreData } from './store.js';
export { FileStore, publicHttpsFetch, publicRelay, type PublicHttpsOptions } from './node.js';
export { PeerStore } from './peer-store.js';
export { AdmissionBook, type PeerRecord, type PeerStatus, type ContactRequest } from './admission.js';
export type { ReplayState } from './replay.js';
export { Inbox, RECEIVE_LOCK, type InboxOptions, type ReceiveOutcome, type ContactEvent } from './inbox.js';
export { Outbox, type OutboxOptions, type OutboxEntry, type OutboxStatus, type OutboxTransport } from './outbox.js';
export { MessageLog, type StoredMessage, type MessageFilter, type MessageRef } from './message-log.js';

export { RelayClient, compareStreamIds, type RelayClientOptions, type InboxPage, type ListenEvent } from './relay.js';
export { isCanonicalRelayUrl, normalizeRelayUrl } from './relay-url.js';
// Relay side (07): the reference relay imports these verifiers and network helpers.
export { createAuthHeaders, parseAuthHeaders, verifyAuthHeaders, WAKE_TOKEN_RE, type AuthHeaders, type RelayAuth, type RelayAuthRequest } from './auth.js';
export { createRegistrationRequest, verifyRegistrationRequest, type RegistrationRequest, type VerifiedRegistration } from './registration.js';
export { isBlockedAddress, networkKey, parseIp, type ParsedIp } from './pinned-https.js';

export { createInvitation, type Invitation } from './invitation.js';
export { NetworkClient, type NetworkClientOptions } from './network-client.js';

// Optional commerce profile module.
export {
  commerceRules, ThreadStore, COMMERCE_PROFILE_ID, COMMERCE_TYPES,
  MAX_OPEN_THREADS_PER_PEER, type CommerceType, type ThreadState, type ThreadSnapshot, type ThreadHistoryEntry,
} from './commerce.js';
