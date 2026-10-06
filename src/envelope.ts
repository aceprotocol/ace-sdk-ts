/** Envelope decoding (04 "Envelope Decoding"), signature check and fingerprint. */

import { ACEError } from './errors.js';
import {
  canonicalJson, decodeB64, decodeSignature, isACEId, isConversationId, isMessageId, isThreadId,
  sha256Hex, wireInt,
} from './encoding.js';
import { MIN_PAYLOAD_BYTES } from './encryption.js';
import { KEM_CIPHERTEXT_SIZE, MAX_PAYLOAD_BYTES } from './limits.js';
import { buildSignData, encodePayload, verifySignature } from './signing.js';
import type { ACEMessage, SigningScheme } from './types.js';
import { isEconomicType, isMessageType, isSigningScheme } from './types.js';

function bad(msg: string): ACEError {
  return new ACEError('invalid_envelope', msg);
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function decodeKemCiphertext(text: unknown): Uint8Array {
  const raw = decodeB64(text, 'invalid_envelope', 'encryption.kemCiphertext', KEM_CIPHERTEXT_SIZE);
  if (raw.length !== KEM_CIPHERTEXT_SIZE) throw bad(`encryption.kemCiphertext must be ${KEM_CIPHERTEXT_SIZE} bytes`);
  return raw;
}

export function decodePayload(text: unknown): Uint8Array {
  const raw = decodeB64(text, 'invalid_envelope', 'encryption.payload', MAX_PAYLOAD_BYTES);
  if (raw.length < MIN_PAYLOAD_BYTES || raw.length > MAX_PAYLOAD_BYTES) {
    throw bad(`encryption.payload must be ${MIN_PAYLOAD_BYTES}..${MAX_PAYLOAD_BYTES} bytes`);
  }
  return raw;
}

/**
 * Apply the 04 decoding rules exactly; `invalid_envelope` or `unsupported_version`.
 * Returns a fresh object with the known fields only (unknown fields are ignored).
 */
export function decodeEnvelope(json: unknown): ACEMessage {
  if (!isObject(json)) throw bad('envelope must be a JSON object');
  const ace = json.ace;
  if (typeof ace !== 'string') throw bad('ace must be a string');
  if (ace !== '1.0') throw new ACEError('unsupported_version', `unsupported ACE version ${JSON.stringify(ace.slice(0, 16))}`);
  const { messageId, from, to, conversationId, type } = json;
  if (!isMessageId(messageId)) throw bad('messageId must be a lowercase UUIDv4');
  if (!isACEId(from) || !isACEId(to)) throw bad('from/to must be ACE IDs');
  if (!isConversationId(conversationId)) throw bad('conversationId must be 64 lowercase hex characters');
  if (!isMessageType(type)) throw bad('unknown message type');
  let threadId: string | undefined;
  if (json.threadId !== undefined) {
    if (!isThreadId(json.threadId)) throw bad('threadId must be 1..256 code points without control characters');
    threadId = json.threadId;
  }
  if (threadId === undefined && isEconomicType(type)) throw bad('economic messages require threadId');
  const timestamp = wireInt(json.timestamp);
  if (timestamp === null) throw bad('timestamp must be an integer in [0, 2^53-1]');
  const enc = json.encryption;
  if (!isObject(enc)) throw bad('encryption must be an object');
  decodeKemCiphertext(enc.kemCiphertext);
  decodePayload(enc.payload);
  const sig = json.signature;
  if (!isObject(sig)) throw bad('signature must be an object');
  if (!isSigningScheme(sig.scheme)) throw bad('unsupported signature scheme');
  decodeSignature(sig.value, sig.scheme, 'invalid_envelope');
  const env: ACEMessage = {
    ace: '1.0',
    messageId,
    from,
    to,
    conversationId,
    type,
    timestamp,
    encryption: { kemCiphertext: enc.kemCiphertext as string, payload: enc.payload as string },
    signature: { scheme: sig.scheme, value: sig.value as string },
  };
  if (threadId !== undefined) env.threadId = threadId;
  return env;
}

/** The signed `message` signData of a decoded envelope. */
export function messageSignData(env: ACEMessage): Uint8Array {
  const payload = encodePayload(
    env.type, env.to, env.conversationId, env.messageId, env.threadId ?? '',
    decodeKemCiphertext(env.encryption.kemCiphertext), decodePayload(env.encryption.payload),
  );
  return buildSignData('message', env.from, env.timestamp, payload);
}

/**
 * Signature-only check against a known signer (e.g. a relay checking `/v1/send`).
 * The envelope is re-validated with the decoding rules. `scheme_mismatch` if the
 * envelope scheme differs from the signer's; `invalid_signature` if it does not verify.
 */
export function verifyEnvelopeSignature(env: ACEMessage, signer: { scheme: SigningScheme; signingPublicKey: Uint8Array }): void {
  const e = decodeEnvelope(env);
  if (typeof signer !== 'object' || signer === null || !isSigningScheme(signer.scheme) || !(signer.signingPublicKey instanceof Uint8Array)) {
    throw new ACEError('invalid_argument', 'signer must be {scheme, signingPublicKey}');
  }
  if (e.signature.scheme !== signer.scheme) throw new ACEError('scheme_mismatch', 'envelope signature scheme differs from the signer\'s');
  const sig = decodeSignature(e.signature.value, e.signature.scheme, 'invalid_envelope');
  if (!verifySignature(messageSignData(e), sig, signer.scheme, signer.signingPublicKey)) {
    throw new ACEError('invalid_signature', 'message signature does not verify');
  }
}

/** The 10 known fields in wire shape (threadId omitted when absent). */
export function envelopeKnownFields(env: ACEMessage): ACEMessage {
  const out: ACEMessage = {
    ace: env.ace,
    messageId: env.messageId,
    from: env.from,
    to: env.to,
    conversationId: env.conversationId,
    type: env.type,
    timestamp: env.timestamp,
    encryption: { kemCiphertext: env.encryption.kemCiphertext, payload: env.encryption.payload },
    signature: { scheme: env.signature.scheme, value: env.signature.value },
  };
  if (env.threadId !== undefined) out.threadId = env.threadId;
  return out;
}

/** Lowercase hex SHA-256 of the RFC 8785 JSON of the 10 known envelope fields. */
export function envelopeFingerprint(env: ACEMessage): string {
  if (typeof env !== 'object' || env === null || typeof env.encryption !== 'object' || typeof env.signature !== 'object') {
    throw new ACEError('invalid_argument', 'expected an ACEMessage');
  }
  try {
    return sha256Hex(canonicalJson(envelopeKnownFields(env)));
  } catch {
    throw new ACEError('invalid_argument', 'expected an ACEMessage');
  }
}
