import type {
  ACEIdentity, ACEMessage, MessageType, SigningScheme, RegistrationFile,
} from './types.js';
import { isEconomicType } from './types.js';
import { toBase64, fromBase64, computeACEId } from './identity.js';
import { computeConversationId, encrypt, decodeKemCiphertext, MAX_PAYLOAD_SIZE } from './encryption.js';
import { buildSignData, encodePayload, verifySignature, encodeSignature, decodeSignature } from './signing.js';
import { checkTimestampFreshness, validateMessageId, ReplayDetector } from './security.js';
import {
  validateRegistrationFile,
  verifyRegistrationId,
  getRegistrationSigningPublicKey,
  getRegistrationEncryptionPublicKey,
  type VerifiedPeer,
} from './discovery.js';
import { ThreadStateMachine } from './state-machine.js';

const _encoder = new TextEncoder();
const _decoder = new TextDecoder();

/** Maximum nesting depth for parsed JSON bodies — prevents stack overflow from malicious payloads. */
const MAX_JSON_DEPTH = 32;

/** Iterative depth check — no recursion, immune to stack overflow from the check itself. */
function assertMaxDepth(value: unknown, maxDepth: number): void {
  const stack: Array<{ val: unknown; depth: number }> = [{ val: value, depth: 0 }];
  while (stack.length > 0) {
    const { val, depth } = stack.pop()!;
    if (depth > maxDepth) {
      throw new Error(`Decrypted body exceeds maximum nesting depth of ${maxDepth}`);
    }
    if (typeof val === 'object' && val !== null) {
      for (const v of Object.values(val)) {
        if (typeof v === 'object' && v !== null) {
          stack.push({ val: v, depth: depth + 1 });
        }
      }
    }
  }
}

/** Shared pre-check: economic messages must carry a threadId. */
function requireThreadIdForEconomic(type: MessageType, threadId: string | undefined): void {
  if (isEconomicType(type) && !threadId) {
    throw new Error(`Economic message type '${type}' requires a threadId`);
  }
}

function estimateBase64DecodedLength(encoded: string): number {
  const length = encoded.length;
  const fullBlocks = Math.floor(length / 4);
  let decodedLength = fullBlocks * 3;
  if (encoded.endsWith('==')) {
    decodedLength -= 2;
  } else if (encoded.endsWith('=')) {
    decodedLength -= 1;
  }
  return decodedLength;
}

function normalizeThreadId(threadId: string | undefined): string {
  return threadId ?? '';
}

function buildSignedMessagePayload(
  type: MessageType,
  to: string,
  conversationId: string,
  messageId: string,
  threadId: string | undefined,
  kemCiphertext: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  // kemCiphertext is signed too: it is what the recipient decapsulates to derive
  // the decryption key, so it is part of the sender's commitment. Omitting it
  // would let a relay swap the KEM ciphertext (garbling the message) without
  // breaking the signature.
  return encodePayload(
    type, to, conversationId, messageId, normalizeThreadId(threadId),
    kemCiphertext, payload,
  );
}

// === Schema Validation ===

type BodyType = Record<string, unknown>;

const MAX_SHORT_STRING = 4096;
const MAX_LONG_STRING = 65536;

function requireString(body: BodyType, field: string, typeName: string, maxLen: number = MAX_SHORT_STRING): string {
  if (!Object.hasOwn(body, field)) {
    throw new Error(`${typeName} body requires '${field}' field`);
  }
  const value = body[field];
  if (value === undefined || value === null) {
    throw new Error(`${typeName} body requires '${field}' field`);
  }
  if (typeof value !== 'string') {
    throw new Error(`${typeName}.${field} must be a string`);
  }
  if (value.length > maxLen) {
    throw new Error(`${typeName}.${field} exceeds max length of ${maxLen} characters`);
  }
  return value;
}

function requireObject(body: BodyType, field: string, typeName: string): void {
  if (!Object.hasOwn(body, field)) {
    throw new Error(`${typeName} body requires '${field}' field`);
  }
  const value = body[field];
  if (value === undefined || value === null) {
    throw new Error(`${typeName} body requires '${field}' field`);
  }
  validateObject(value, field, typeName);
}

function validateOptionalString(body: BodyType, field: string, typeName: string, maxLen: number = MAX_SHORT_STRING): void {
  const value = body[field];
  if (value === undefined || value === null) return;
  if (typeof value !== 'string') {
    throw new Error(`${typeName}.${field} must be a string`);
  }
  if (value.length > maxLen) {
    throw new Error(`${typeName}.${field} exceeds max length of ${maxLen} characters`);
  }
}

function validateOptionalObject(body: BodyType, field: string, typeName: string): void {
  const value = body[field];
  if (value === undefined || value === null) return;
  validateObject(value, field, typeName);
}

function validateOptionalNumber(body: BodyType, field: string, typeName: string): void {
  const value = body[field];
  if (value === undefined || value === null) return;
  if (!isJSONNumber(value)) {
    throw new Error(`${typeName}.${field} must be a number`);
  }
}

function validateObject(value: unknown, field: string, typeName: string): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${typeName}.${field} must be an object`);
  }
}

function isJSONNumber(value: unknown): boolean {
  return typeof value === 'number' && Number.isFinite(value);
}

export function validateBody(type: MessageType, body: BodyType): void {
  switch (type) {
    case 'rfq':
      requireString(body, 'need', 'rfq');
      validateOptionalString(body, 'maxPrice', 'rfq');
      validateOptionalString(body, 'currency', 'rfq');
      validateOptionalNumber(body, 'ttl', 'rfq');
      break;
    case 'offer':
      requireString(body, 'price', 'offer');
      requireString(body, 'currency', 'offer');
      validateOptionalString(body, 'terms', 'offer');
      validateOptionalNumber(body, 'ttl', 'offer');
      break;
    case 'accept':
      requireString(body, 'offerId', 'accept');
      break;
    case 'reject':
      validateOptionalString(body, 'reason', 'reject');
      break;
    case 'invoice':
      requireString(body, 'offerId', 'invoice');
      requireString(body, 'amount', 'invoice');
      requireString(body, 'currency', 'invoice');
      requireString(body, 'settlementMethod', 'invoice');
      validateOptionalObject(body, 'settlementDetails', 'invoice');
      break;
    case 'receipt':
      requireString(body, 'invoiceId', 'receipt');
      requireString(body, 'amount', 'receipt');
      requireString(body, 'currency', 'receipt');
      requireString(body, 'settlementMethod', 'receipt');
      requireObject(body, 'proof', 'receipt');
      break;
    case 'deliver': {
      const deliverType = requireString(body, 'type', 'deliver');
      validateOptionalString(body, 'content', 'deliver', MAX_LONG_STRING);
      validateOptionalString(body, 'contentType', 'deliver');
      validateOptionalString(body, 'uri', 'deliver');
      validateOptionalObject(body, 'metadata', 'deliver');
      if (deliverType === 'inline') {
        requireString(body, 'content', 'deliver (inline)', MAX_LONG_STRING);
      } else if (deliverType === 'reference') {
        requireString(body, 'uri', 'deliver (reference)');
      } else {
        const sanitized = deliverType.slice(0, 50);
        throw new Error(`deliver.type must be 'inline' or 'reference', got '${sanitized}'`);
      }
      break;
    }
    case 'confirm':
      requireString(body, 'deliverId', 'confirm');
      validateOptionalString(body, 'message', 'confirm', MAX_LONG_STRING);
      break;
    case 'info':
      requireString(body, 'message', 'info', MAX_LONG_STRING);
      break;
    case 'text':
      requireString(body, 'message', 'text', MAX_LONG_STRING);
      break;
    default:
      // Unknown types: no validation (forward compatibility)
      break;
  }
}

function threadContainsMessage(
  stateMachine: ThreadStateMachine,
  conversationId: string,
  threadId: string,
  messageType: MessageType,
  messageId: string,
): boolean {
  return stateMachine.getSnapshot(conversationId, threadId).history
    .some((entry) => entry.type === messageType && entry.messageId === messageId);
}

function validateThreadReferences(
  type: MessageType,
  body: BodyType,
  stateMachine: ThreadStateMachine,
  conversationId: string,
  threadId: string,
): void {
  if (!isEconomicType(type) || threadId.length === 0) {
    return;
  }

  switch (type) {
    case 'accept':
      if (!threadContainsMessage(stateMachine, conversationId, threadId, 'offer', requireString(body, 'offerId', 'accept'))) {
        throw new Error('accept.offerId must reference an offer in the same thread');
      }
      break;
    case 'invoice':
      if (!threadContainsMessage(stateMachine, conversationId, threadId, 'offer', requireString(body, 'offerId', 'invoice'))) {
        throw new Error('invoice.offerId must reference an offer in the same thread');
      }
      break;
    case 'receipt':
      if (!threadContainsMessage(stateMachine, conversationId, threadId, 'invoice', requireString(body, 'invoiceId', 'receipt'))) {
        throw new Error('receipt.invoiceId must reference an invoice in the same thread');
      }
      break;
    case 'confirm':
      if (!threadContainsMessage(stateMachine, conversationId, threadId, 'deliver', requireString(body, 'deliverId', 'confirm'))) {
        throw new Error('confirm.deliverId must reference a deliver message in the same thread');
      }
      break;
    default:
      break;
  }
}

// === Message Construction ===

export interface CreateMessageOptions {
  sender: ACEIdentity;
  recipientPubKey: Uint8Array; // X-Wing encryption public key (1216 bytes)
  recipientACEId: string;
  type: MessageType;
  body: BodyType;
  stateMachine: ThreadStateMachine;
  threadId?: string; // Required for economic messages
  timestamp?: number; // defaults to Date.now() / 1000
}

export async function createMessage(
  opts: CreateMessageOptions,
): Promise<ACEMessage> {
  requireThreadIdForEconomic(opts.type, opts.threadId);

  // 1. Validate body schema
  validateBody(opts.type, opts.body);

  const messageId = crypto.randomUUID();
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);
  const fromId = opts.sender.getACEId();
  const toId = opts.recipientACEId;
  const conversationId = computeConversationId(
    opts.sender.getEncryptionPublicKey(),
    opts.recipientPubKey,
  );

  // 2. State machine pre-check (optimistic fail-fast before expensive crypto).
  // NOTE: This is NOT atomic with the final transition() at step 5 — concurrent
  // createMessage calls sharing the same stateMachine may both pass this check.
  // The authoritative guard is the transition() call after crypto completes.
  const threadKey = normalizeThreadId(opts.threadId);
  if (!opts.stateMachine.canTransition(conversationId, threadKey, opts.type)) {
    // Call transition() to produce the proper InvalidTransitionError
    opts.stateMachine.transition(conversationId, threadKey, opts.type, messageId, timestamp);
  }
  validateThreadReferences(opts.type, opts.body, opts.stateMachine, conversationId, threadKey);

  // 3. Encrypt body
  const bodyJson = JSON.stringify(opts.body);
  const bodyBytes = _encoder.encode(bodyJson);
  const { kemCiphertext, payload } = await encrypt(
    bodyBytes,
    opts.recipientPubKey,
    conversationId,
  );

  // 4. Build sign data and sign
  const messagePayload = buildSignedMessagePayload(
    opts.type,
    toId,
    conversationId,
    messageId,
    opts.threadId,
    kemCiphertext,
    payload,
  );
  const signData = buildSignData('message', fromId, timestamp, messagePayload);
  const { signature, scheme } = await opts.sender.sign(signData);

  // 5. Commit state transition (only after all crypto succeeded)
  opts.stateMachine.transition(conversationId, threadKey, opts.type, messageId, timestamp);

  // 6. Assemble envelope
  const msg: ACEMessage = {
    ace: '1.0',
    messageId,
    from: fromId,
    to: toId,
    conversationId,
    type: opts.type,
    timestamp,
    encryption: {
      kemCiphertext: toBase64(kemCiphertext),
      payload: toBase64(payload),
    },
    signature: {
      scheme,
      value: encodeSignature(signature, scheme),
    },
  };

  if (opts.threadId) {
    msg.threadId = opts.threadId;
  }

  return msg;
}

// === Message Parsing (Verify + Decrypt) ===

export interface ParsedMessage<T = Record<string, unknown>> {
  messageId: string;
  from: string;
  to: string;
  conversationId: string;
  type: MessageType;
  threadId?: string;
  timestamp: number;
  body: T;
}

export interface ParseMessageOptions {
  /** Offline acceptance floor; use the same value for every message of one backlog. */
  oldestTimestamp?: number;
  stateMachine: ThreadStateMachine;
  expectedScheme?: SigningScheme;
  replayDetector: ReplayDetector;
  senderEncryptionPubKey?: Uint8Array;
}

export interface ParseMessageFromRegistrationOptions {
  oldestTimestamp?: number;
  stateMachine: ThreadStateMachine;
  replayDetector: ReplayDetector;
}

export async function parseMessage(
  msg: ACEMessage,
  receiver: ACEIdentity,
  senderSigningPubKey: Uint8Array,
  opts: ParseMessageOptions,
): Promise<ParsedMessage> {
  // 1. Envelope validation (pipeline step 1)
  if (msg.ace !== '1.0') {
    throw new Error(`Unsupported ACE version: '${msg.ace}'`);
  }
  if (msg.to !== receiver.getACEId()) {
    throw new Error('Message not addressed to this recipient');
  }
  if (!msg.messageId || !msg.from || !msg.conversationId || !msg.type) {
    throw new Error('Missing required envelope fields');
  }
  if (msg.conversationId.length > 256) {
    throw new Error('conversationId exceeds max length of 256 characters');
  }
  validateMessageId(msg.messageId);

  // Validate encryption and signature envelopes exist
  if (!msg.encryption?.payload || !msg.encryption?.kemCiphertext) {
    throw new Error('Missing required encryption fields');
  }
  if (typeof msg.encryption.payload !== 'string') {
    throw new Error('encryption.payload must be a Base64 string');
  }
  if (!msg.signature?.scheme || !msg.signature?.value) {
    throw new Error('Missing required signature fields');
  }

  // Validate msg.from matches the sender's signing public key
  const expectedFromId = computeACEId(senderSigningPubKey);
  if (msg.from !== expectedFromId) {
    throw new Error('msg.from does not match sender signing public key');
  }
  if (opts.senderEncryptionPubKey) {
    const expectedConversationId = computeConversationId(
      opts.senderEncryptionPubKey,
      receiver.getEncryptionPublicKey(),
    );
    if (msg.conversationId !== expectedConversationId) {
      throw new Error('msg.conversationId does not match sender/recipient encryption keys');
    }
  }

  // Validate signature scheme if expected scheme is provided
  if (opts.expectedScheme && msg.signature.scheme !== opts.expectedScheme) {
    throw new Error(
      `Signature scheme mismatch: expected '${opts.expectedScheme}', got '${msg.signature.scheme}'`,
    );
  }

  requireThreadIdForEconomic(msg.type, msg.threadId);

  // 2–3. Timestamp freshness, replay horizon and seen check — BEFORE expensive ops
  checkTimestampFreshness(msg.timestamp, opts.oldestTimestamp);
  const replayError = () => new Error(`Replay detected: messageId '${msg.messageId}' already processed or below replay horizon`);
  if (!opts.replayDetector.accepts(msg.messageId, msg.timestamp)) {
    throw replayError();
  }

  // 4. Verify signature BEFORE decryption (pipeline step 4).
  const estimatedPayloadBytes = estimateBase64DecodedLength(msg.encryption.payload);
  if (estimatedPayloadBytes > MAX_PAYLOAD_SIZE) {
    throw new Error(
      `Payload too large: estimated decoded size ${estimatedPayloadBytes} bytes exceeds max ${MAX_PAYLOAD_SIZE}`,
    );
  }
  const payloadBytes = fromBase64(msg.encryption.payload);
  // Schema check: the X-Wing ciphertext has a fixed size. Rejected before any
  // signature verification or decapsulation runs.
  const kemCiphertext = decodeKemCiphertext(msg.encryption.kemCiphertext);
  const messagePayload = buildSignedMessagePayload(
    msg.type,
    msg.to,
    msg.conversationId,
    msg.messageId,
    msg.threadId,
    kemCiphertext,
    payloadBytes,
  );
  const signData = buildSignData('message', msg.from, msg.timestamp, messagePayload);
  const sigBytes = decodeSignature(msg.signature.value, msg.signature.scheme);
  let valid = false;
  try {
    valid = verifySignature(signData, sigBytes, msg.signature.scheme, senderSigningPubKey);
  } catch {
    // Malformed signature/key bytes → treat as failed verification.
  }
  if (!valid) {
    throw new Error('Signature verification failed');
  }
  // Commit now: an authentic message is one-shot, even if a later step fails.
  if (!opts.replayDetector.commit(msg.messageId, msg.timestamp, opts.oldestTimestamp)) {
    throw replayError();
  }

  // 5. Decrypt body via identity's decrypt method (pipeline step 5) —
  // kemCiphertext was length-checked and signature-verified above.
  const decrypted = await receiver.decrypt(
    kemCiphertext,
    payloadBytes,
    msg.conversationId,
  );

  const rawParsed: unknown = JSON.parse(_decoder.decode(decrypted));
  if (typeof rawParsed !== 'object' || rawParsed === null || Array.isArray(rawParsed)) {
    throw new Error('Decrypted body must be a JSON object');
  }
  // Guard against deeply nested JSON that could cause stack overflow or CPU exhaustion
  assertMaxDepth(rawParsed, MAX_JSON_DEPTH);
  // Isolate from Object.prototype to prevent prototype pollution via __proto__/constructor keys
  const body = Object.assign(Object.create(null), rawParsed) as BodyType;

  // 6. Validate body schema (pipeline step 6)
  validateBody(msg.type, body);
  validateThreadReferences(
    msg.type,
    body,
    opts.stateMachine,
    msg.conversationId,
    normalizeThreadId(msg.threadId),
  );

  // 7. State machine validation (pipeline step 7 — after all security checks)
  opts.stateMachine.transition(
    msg.conversationId,
    msg.threadId ?? '',
    msg.type,
    msg.messageId,
    msg.timestamp,
  );

  return {
    messageId: msg.messageId,
    from: msg.from,
    to: msg.to,
    conversationId: msg.conversationId,
    type: msg.type,
    threadId: msg.threadId,
    timestamp: msg.timestamp,
    body,
  };
}

export async function parseMessageFromRegistration(
  msg: ACEMessage,
  receiver: ACEIdentity,
  senderRegistration: RegistrationFile,
  opts: ParseMessageFromRegistrationOptions,
): Promise<ParsedMessage> {
  validateRegistrationFile(senderRegistration);
  if (!verifyRegistrationId(senderRegistration)) {
    throw new Error('Sender registration file failed cryptographic verification');
  }

  return parseMessage(
    msg,
    receiver,
    getRegistrationSigningPublicKey(senderRegistration),
    {
      oldestTimestamp: opts.oldestTimestamp,
      stateMachine: opts.stateMachine,
      expectedScheme: senderRegistration.signing.scheme,
      replayDetector: opts.replayDetector,
      senderEncryptionPubKey: getRegistrationEncryptionPublicKey(senderRegistration),
    },
  );
}

/**
 * Safe path for messages whose sender keys came from a relay.
 *
 * `sender` must be a {@link VerifiedPeer} — obtainable only after its encryption-key
 * binding was verified — so the recipient never trusts a relay-substituted X-Wing
 * key. `conversationId` is recomputed from the verified keys and must match.
 */
export async function parseMessageFromPeer(
  msg: ACEMessage,
  receiver: ACEIdentity,
  sender: VerifiedPeer,
  opts: ParseMessageFromRegistrationOptions,
): Promise<ParsedMessage> {
  return parseMessage(msg, receiver, sender.signingPublicKey, {
    oldestTimestamp: opts.oldestTimestamp,
    stateMachine: opts.stateMachine,
    expectedScheme: sender.scheme,
    replayDetector: opts.replayDetector,
    senderEncryptionPubKey: sender.encryptionPublicKey,
  });
}
