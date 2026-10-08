/** Message construction and the receive pipeline (06-security). */

import { ACEError } from './errors.js';
import {
  checkJsonValue, decodeSignature, dumpsBody, encodeSignature, isConversationId, isMessageId, isObj, isThreadId, loadsBody, toBase64, wireInt,
} from './encoding.js';
import { isVerifiedPeer, type VerifiedPeer } from './discovery.js';
import { computeConversationId, encrypt } from './encryption.js';
import { decodeEnvelope, decodeKemCiphertext, decodePayload, messageSignData } from './envelope.js';
import { MAX_PLAINTEXT_BYTES, TIMESTAMP_WINDOW_SECONDS } from './limits.js';
import { checkPrincipalRules, type PrincipalContext } from './principal.js';
import { ReplayDetector } from './replay.js';
import { verifySignature } from './signing.js';
import { ThreadStateMachine, type ThreadEvent } from './state-machine.js';
import type { ACEIdentity, ACEMessage, JSONObject, MessageType, ParsedMessage } from './types.js';
import { isEconomicType, isMessageType, isPrincipalType, isSigningScheme } from './types.js';

// --- body schema --------------------------------------------------------------------

type FieldKind = 'str' | 'optStr' | 'optObj' | 'obj' | 'optTtl';

const SCHEMAS: Record<MessageType, Array<[string, FieldKind]>> = {
  rfq: [['need', 'str'], ['maxPrice', 'optStr'], ['currency', 'optStr'], ['ttl', 'optTtl']],
  offer: [['price', 'str'], ['currency', 'str'], ['terms', 'optStr'], ['ttl', 'optTtl']],
  accept: [['offerId', 'str']],
  reject: [['reason', 'optStr']],
  invoice: [['offerId', 'str'], ['amount', 'str'], ['currency', 'str'], ['settlementMethod', 'str'], ['settlementDetails', 'optObj']],
  receipt: [['referenceId', 'str'], ['amount', 'str'], ['currency', 'str'], ['settlementMethod', 'str'], ['proof', 'obj']],
  deliver: [['type', 'str'], ['content', 'optStr'], ['contentType', 'optStr'], ['uri', 'optStr'], ['metadata', 'optObj']],
  confirm: [['deliverId', 'str'], ['message', 'optStr']],
  info: [['message', 'str']],
  text: [['message', 'str']],
  request: [['action', 'str'], ['summary', 'str'], ['ref', 'optObj'], ['amount', 'optStr'], ['currency', 'optStr'], ['details', 'optObj'], ['ttl', 'optTtl']],
  decision: [['requestId', 'str'], ['outcome', 'str'], ['reason', 'optStr'], ['result', 'optObj']],
  report: [['action', 'str'], ['summary', 'str'], ['outcome', 'str'], ['ref', 'optObj'], ['requestId', 'optStr'], ['proof', 'optObj']],
};

const OUTCOMES: Partial<Record<MessageType, readonly string[]>> = {
  decision: ['approve', 'deny'],
  report: ['ok', 'failed', 'skipped'],
};

function checkRef(type: MessageType, ref: Record<string, unknown>): void {
  if (!isConversationId(ref.conversationId)) throw new ACEError('invalid_body', `${type}.ref.conversationId must be 64 lowercase hex`);
  if (!isMessageId(ref.messageId)) throw new ACEError('invalid_body', `${type}.ref.messageId must be a lowercase UUID v4`);
  if (ref.threadId !== undefined && ref.threadId !== null && !isThreadId(ref.threadId)) {
    throw new ACEError('invalid_body', `${type}.ref.threadId must be a valid thread ID`);
  }
}

/**
 * Validate a body against its type's schema; failures are `invalid_body`
 * (an unknown type is `invalid_argument`). Optional fields set to null are absent;
 * unknown fields are ignored.
 */
export function validateBody(type: MessageType, body: JSONObject): void {
  if (!isMessageType(type)) throw new ACEError('invalid_argument', 'unknown message type');
  if (!isObj(body)) throw new ACEError('invalid_body', 'body must be a JSON object');
  for (const [name, kind] of SCHEMAS[type]) {
    const v = body[name];
    if (v === null || v === undefined) {
      if (kind === 'str' || kind === 'obj') throw new ACEError('invalid_body', `${type}.${name} is required`);
      continue;
    }
    const ok = kind === 'str' || kind === 'optStr' ? typeof v === 'string'
      : kind === 'obj' || kind === 'optObj' ? isObj(v)
        : wireInt(v) !== null;
    if (!ok) throw new ACEError('invalid_body', `${type}.${name} has the wrong type`);
  }
  if (type === 'deliver') {
    const kind = body.type;
    const required = kind === 'inline' ? 'content' : kind === 'reference' ? 'uri' : null;
    if (required === null) throw new ACEError('invalid_body', "deliver.type must be 'inline' or 'reference'");
    if (typeof body[required] !== 'string') throw new ACEError('invalid_body', `deliver (${kind}) requires ${required}`);
  }
  const outcomes = OUTCOMES[type];
  if (outcomes && !outcomes.includes(body.outcome as string)) {
    throw new ACEError('invalid_body', `${type}.outcome must be one of ${outcomes.join(', ')}`);
  }
  if ((type === 'request' || type === 'report') && body.ref !== undefined && body.ref !== null) {
    checkRef(type, body.ref as Record<string, unknown>);
  }
}

/** Internal: decrypted bytes -> validated body (`invalid_body`). */
export function decodeBody(type: MessageType, raw: Uint8Array): JSONObject {
  const body = loadsBody(raw);
  validateBody(type, body);
  return body;
}

function nowOf(clock?: () => number): number {
  return Math.floor(clock ? clock() : Date.now() / 1000);
}

export function eventOf(env: ACEMessage): ThreadEvent {
  return {
    conversationId: env.conversationId, threadId: env.threadId, type: env.type, messageId: env.messageId,
    timestamp: env.timestamp, from: env.from, to: env.to,
  };
}

// --- create -----------------------------------------------------------------------

export interface CreateMessageInput {
  sender: ACEIdentity;
  recipient: VerifiedPeer;
  type: MessageType;
  body: JSONObject;
  threads: ThreadStateMachine;
  threadId?: string;
  timestamp?: number;
}

/** Encrypt, sign and record an outbound message. */
export async function createMessage(opts: CreateMessageInput): Promise<ACEMessage> {
  return buildMessage(opts);
}

/** Internal: `createMessage`, optionally reusing a messageId (Outbox re-sign). */
export async function buildMessage(opts: CreateMessageInput, reuseMessageId?: string): Promise<ACEMessage> {
  if (typeof opts !== 'object' || opts === null) throw new ACEError('invalid_argument', 'options are required');
  const { sender, recipient, type, body, threads, threadId } = opts;
  if (!isVerifiedPeer(recipient)) throw new ACEError('invalid_argument', 'recipient must be a VerifiedPeer');
  if (!(threads instanceof ThreadStateMachine)) throw new ACEError('invalid_argument', 'threads must be a ThreadStateMachine');
  // 1. type, threadId, local identity
  if (!isMessageType(type)) throw new ACEError('invalid_argument', 'unknown message type');
  if (threadId !== undefined && !isThreadId(threadId)) {
    throw new ACEError('invalid_argument', 'threadId must be 1..256 code points without control characters');
  }
  if (threadId === undefined && isEconomicType(type)) throw new ACEError('invalid_argument', 'economic messages require threadId');
  const from = sender.getACEId();
  if (threads.localAceId !== from) throw new ACEError('invalid_argument', 'threads.localAceId must be the sender');
  const ts = opts.timestamp ?? nowOf();
  if (wireInt(ts) === null) throw new ACEError('invalid_argument', 'timestamp must be an integer in [0, 2^53-1]');
  // 2. JSON values, then schema
  if (!isObj(body)) throw new ACEError('invalid_body', 'body must be a JSON object');
  checkJsonValue(body);
  validateBody(type, body);
  // 3. conversation
  const conversationId = computeConversationId(sender.getEncryptionPublicKey(), recipient.encryptionPublicKey);
  const messageId = reuseMessageId ?? crypto.randomUUID();
  const event: ThreadEvent = { conversationId, threadId, type, messageId, timestamp: ts, from, to: recipient.aceId };
  // 4. state machine pre-check
  threads.check(event, body);
  // 5. serialize
  const plaintext = dumpsBody(body);
  if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new ACEError('limit_exceeded', `body exceeds ${MAX_PLAINTEXT_BYTES} bytes`);
  // 6. encrypt
  const { kemCiphertext, payload } = await encrypt(plaintext, recipient.encryptionPublicKey, conversationId);
  const scheme = sender.getSigningScheme();
  const env: ACEMessage = {
    ace: '1.0', messageId, from, to: recipient.aceId, conversationId, type, timestamp: ts,
    encryption: { kemCiphertext: toBase64(kemCiphertext), payload: toBase64(payload) },
    signature: { scheme, value: '' },
  };
  if (threadId !== undefined) env.threadId = threadId;
  // 7. sign
  env.signature.value = encodeSignature(await sender.sign(messageSignData(env)), scheme);
  // 8. commit
  threads.apply(event, body);
  return env;
}

// --- parse ------------------------------------------------------------------------

export interface ParseMessageOptions {
  threads: ThreadStateMachine;
  replay: ReplayDetector;
  /** Acceptance floor in [0, now]; default now - 300. */
  floor?: number;
  clock?: () => number;
  /** The receiver's principal context (09); without it principal types are `wrong_principal`. */
  principal?: PrincipalContext;
}

function isPrincipalKeyShape(v: unknown): boolean {
  return isObj(v) && isSigningScheme(v.scheme) && typeof v.publicKey === 'string' && v.publicKey.length > 0;
}

function isPrincipalContext(v: unknown): v is PrincipalContext {
  if (typeof v !== 'object' || v === null) return false;
  const c = v as Record<string, unknown>;
  return typeof c.account === 'string' && typeof c.openRequestTo === 'function'
    && (c.selfSigner === undefined || isPrincipalKeyShape(c.selfSigner))
    && (c.trustedSigners === undefined || (Array.isArray(c.trustedSigners) && c.trustedSigners.every(isPrincipalKeyShape)));
}

/**
 * Verify, decrypt and validate an inbound message. The first failure wins:
 * decode → wrong_recipient → from (invalid_envelope) → scheme_mismatch →
 * conversationId (invalid_envelope) → floor / timestamp (stale_timestamp) → replay →
 * invalid_signature → replay commit → decrypt → invalid_body → state machine / principal rules.
 * Principal types (`request`, `decision`, `report`) need `opts.principal`; without it they are `wrong_principal`.
 */
export async function parseMessage(
  envelope: ACEMessage, receiver: ACEIdentity, sender: VerifiedPeer, opts: ParseMessageOptions,
): Promise<ParsedMessage> {
  if (!isVerifiedPeer(sender)) throw new ACEError('invalid_argument', 'sender must be a VerifiedPeer');
  if (typeof opts !== 'object' || opts === null || !(opts.threads instanceof ThreadStateMachine) || !(opts.replay instanceof ReplayDetector)) {
    throw new ACEError('invalid_argument', 'threads and replay are required');
  }
  if (opts.principal !== undefined && !isPrincipalContext(opts.principal)) {
    throw new ACEError('invalid_argument', 'principal must be a PrincipalContext');
  }
  const { threads, replay } = opts;
  const receiverId = receiver.getACEId();
  if (threads.localAceId !== receiverId) throw new ACEError('invalid_argument', 'threads.localAceId must be the receiver');
  // 1
  const env = decodeEnvelope(envelope);
  // 2-5
  if (env.to !== receiverId) throw new ACEError('wrong_recipient', 'message is not addressed to this identity');
  if (env.from !== sender.aceId) throw new ACEError('invalid_envelope', 'from does not match the sender');
  if (env.signature.scheme !== sender.scheme) throw new ACEError('scheme_mismatch', 'signature scheme differs from the sender\'s scheme');
  if (env.conversationId !== computeConversationId(sender.encryptionPublicKey, receiver.getEncryptionPublicKey())) {
    throw new ACEError('invalid_envelope', 'conversationId does not match the verified keys');
  }
  // 6
  const now = nowOf(opts.clock);
  let floor: number;
  if (opts.floor === undefined) {
    floor = Math.max(0, now - TIMESTAMP_WINDOW_SECONDS);
  } else {
    if (wireInt(opts.floor) === null || opts.floor > now) throw new ACEError('invalid_argument', 'floor must be an integer in [0, now]');
    floor = opts.floor;
  }
  if (env.timestamp < floor || env.timestamp > now + TIMESTAMP_WINDOW_SECONDS) {
    throw new ACEError('stale_timestamp', 'timestamp is outside the acceptance window');
  }
  // 7
  if (!replay.accepts(env.messageId, env.from, env.timestamp)) throw new ACEError('replay', 'message already seen or below the replay horizon');
  // 8
  const sig = decodeSignature(env.signature.value, env.signature.scheme, 'invalid_envelope');
  if (!verifySignature(messageSignData(env), sig, sender.scheme, sender.signingPublicKey)) {
    throw new ACEError('invalid_signature', 'message signature does not verify');
  }
  // 9
  if (!replay.commit(env.messageId, env.from, env.timestamp, floor)) {
    throw new ACEError('replay', 'message already seen or below the replay horizon');
  }
  // 10
  let plaintext: Uint8Array;
  try {
    plaintext = await receiver.decrypt(decodeKemCiphertext(env.encryption.kemCiphertext), decodePayload(env.encryption.payload), env.conversationId);
  } catch (e) {
    if (e instanceof ACEError) throw e;
    throw new ACEError('identity_unavailable', `identity decrypt failed: ${e instanceof Error ? e.name : typeof e}`, { cause: e });
  }
  // 11-12
  const body = decodeBody(env.type, plaintext);
  // 13
  if (isEconomicType(env.type)) threads.apply(eventOf(env), body);
  else if (isPrincipalType(env.type)) await checkPrincipal(env, body, sender, opts.principal, now);
  return {
    messageId: env.messageId, from: env.from, to: env.to, conversationId: env.conversationId, type: env.type,
    threadId: env.threadId ?? null, timestamp: env.timestamp, body,
  };
}

/**
 * 06 step 7 for principal types (09 § Same-Account Rules). (The Inbox refreshes the
 * sender before parsing, outside any store lock, R-P20.)
 */
async function checkPrincipal(
  env: ACEMessage, body: JSONObject, sender: VerifiedPeer, ctx: PrincipalContext | undefined, now: number,
): Promise<void> {
  const peer = sender;
  await checkPrincipalRules(env.type, body, {
    conversationId: env.conversationId, senderPrincipal: peer.principal ?? null, senderSigningPublicKey: peer.signingPublicKey,
    selfAccount: ctx?.account ?? null, openRequestTo: ctx?.openRequestTo, now, selfSigner: ctx?.selfSigner,
    trustedSigners: ctx?.trustedSigners,
  });
}

