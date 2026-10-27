/**
 * The packet: the only wire object (`ace: "1"`).
 *
 *   header  = encodePayload("ace.v1.packet", from, to, messageId, decimal(timestamp), prekeyId, kemCiphertext)
 *   (ss, kemCiphertext) = XWing.Encapsulate(prekey.publicKey)
 *   key     = HKDF-SHA256(ikm = ss, salt = "", info = header, L = 32)
 *   payload = nonce[12] ‖ AES-256-GCM(key, nonce, pad(plaintext), aad = header)
 *   signature (action "packet") over M(from, timestamp, seq, encodePayload(to, messageId, prekeyId, kemCiphertext, payload))
 *
 * The plaintext is the canonical JSON of the private content `{type, schemaDigest, threadId?, body, prekey, admission?}`;
 * `pad` hides its length up to a bucket: u32be(len) ‖ content ‖ zeros (03 § Encryption).
 */
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ACEError, type ACEErrorCode } from './errors.js';
import {
  canonicalStateBytes, checkJsonValue, closedKeys, decimal, decodeB64, isACEId, isHex64, isMessageId, isObj, isThreadId,
  nowOf, parseJSONBytes, toBase64, wireInt,
} from './encoding.js';
import { checkUsable, type ACEIdentity } from './identity.js';
import { checkSignatureShape, verifyOperationalSignature, type KelState, type OperationalSignature } from './kel.js';
import { KEM_CIPHERTEXT_SIZE, MAX_PACKET_BYTES, MAX_PLAINTEXT_BYTES, MIN_PLAINTEXT_BUCKET, OFFLINE_WINDOW_SECONDS, TIMESTAMP_WINDOW_SECONDS } from './limits.js';
import { CONTACT_TYPE, RECEIPT_TYPE } from './manifest.js';
import { decodePrekey, decodePrekeyPublicKey, type Prekey, type PrekeyVault } from './prekey.js';
import { encodePayload, SIGNATURE_SIZE, signingMessage } from './signing.js';
import { isMessageType, type Admission, type JSONObject, type PrivateContent } from './types.js';

const VERSION = '1';
const DOMAIN = 'ace.v1.packet';
const SALT = new Uint8Array(0);
const NONCE_LEN = 12;
/** nonce (12) + tag (16). */
const AEAD_OVERHEAD = 28;
const LENGTH_PREFIX = 4;
const LARGEST_BUCKET = MAX_PLAINTEXT_BYTES + LENGTH_PREFIX;
const MAX_PAYLOAD_BYTES = LARGEST_BUCKET + AEAD_OVERHEAD;

/**
 * The padded plaintext length for `contentLen` content bytes (03 § Encryption): the smallest power of two at least
 * MIN_PLAINTEXT_BUCKET holding `contentLen + 4`; above 2^20, MAX_PLAINTEXT_BYTES + 4.
 */
export function plaintextBucket(contentLen: number): number {
  const n = contentLen + LENGTH_PREFIX;
  if (n > 2 ** 20) return LARGEST_BUCKET;
  let b = MIN_PLAINTEXT_BUCKET;
  while (b < n) b *= 2;
  return b;
}

/** Every padded plaintext length: MIN_PLAINTEXT_BUCKET, 2·MIN_PLAINTEXT_BUCKET, …, 2^20, MAX_PLAINTEXT_BYTES + 4. */
export const PLAINTEXT_BUCKETS: ReadonlySet<number> = (() => {
  const out = new Set<number>([LARGEST_BUCKET]);
  for (let b = MIN_PLAINTEXT_BUCKET; b <= 2 ** 20; b *= 2) out.add(b);
  return out;
})();

/** `u32be(len(content)) ‖ content ‖ zeros` up to `plaintextBucket(len(content))`. */
export function padPlaintext(content: Uint8Array): Uint8Array {
  const out = new Uint8Array(plaintextBucket(content.length));
  new DataView(out.buffer).setUint32(0, content.length);
  out.set(content, LENGTH_PREFIX);
  return out;
}

/**
 * The content inside a padded plaintext, or `invalid_body` unless its length is a bucket, the length prefix is at most
 * MAX_PLAINTEXT_BYTES and fits, the bucket is the one the prefix implies and the padding is all zero.
 */
export function unpadPlaintext(plaintext: Uint8Array): Uint8Array {
  const size = plaintext.length;
  const n = size >= LENGTH_PREFIX ? new DataView(plaintext.buffer, plaintext.byteOffset, size).getUint32(0) : 0;
  if (
    !PLAINTEXT_BUCKETS.has(size) || n > MAX_PLAINTEXT_BYTES || LENGTH_PREFIX + n > size || plaintextBucket(n) !== size
    || !plaintext.subarray(LENGTH_PREFIX + n).every((x) => x === 0)
  ) throw new ACEError('invalid_body', 'plaintext padding is invalid');
  return plaintext.slice(LENGTH_PREFIX, LENGTH_PREFIX + n);
}

export interface Packet {
  ace: '1';
  messageId: string;
  from: string;
  to: string;
  timestamp: number;
  encryption: { prekey: string; kemCiphertext: string; payload: string };
  signature: OperationalSignature;
}

const bad = (m: string) => new ACEError('invalid_packet', m);
/** Base64 length of the packet's ml-dsa-65 signature value. */
const SIGNATURE_B64_LENGTH = 4 * Math.ceil(SIGNATURE_SIZE / 3);

/**
 * Decode a packet exactly: a closed object (unknown members rejected), `ace` other than "1" is
 * `unsupported_version`, anything else malformed is `invalid_packet`. Returns a fresh copy.
 */
export function decodePacket(value: unknown): Packet {
  if (!isObj(value)) throw bad('packet must be a JSON object');
  if (value.ace !== VERSION) {
    if (typeof value.ace === 'string') throw new ACEError('unsupported_version', `unsupported ACE version ${JSON.stringify(value.ace.slice(0, 16))}`);
    throw bad('ace must be "1"');
  }
  if (!closedKeys(value, ['ace', 'messageId', 'from', 'to', 'timestamp', 'encryption', 'signature'])) throw bad('packet has unknown or missing members');
  const { messageId, from, to, encryption: enc } = value;
  if (!isMessageId(messageId)) throw bad('messageId must be a lowercase UUIDv4');
  if (!isACEId(from) || !isACEId(to)) throw bad('from/to must be ACE IDs');
  if (from === to) throw bad('from and to must differ');
  const timestamp = wireInt(value.timestamp);
  if (timestamp === null) throw bad('timestamp must be an integer in [0, 2^53-1]');
  if (!closedKeys(enc, ['prekey', 'kemCiphertext', 'payload']) || !isHex64(enc.prekey)) throw bad('encryption must be {prekey, kemCiphertext, payload}');
  const kem = decodeKem(enc.kemCiphertext), payload = decodePayloadBytes(enc.payload);
  const signature = checkSignatureShape(value.signature, 'invalid_packet');
  const packet: Packet = {
    ace: VERSION, messageId, from, to, timestamp,
    encryption: { prekey: enc.prekey, kemCiphertext: enc.kemCiphertext as string, payload: enc.payload as string },
    signature,
  };
  if (canonicalStateBytes(packet).length > MAX_PACKET_BYTES) throw bad(`packet exceeds ${MAX_PACKET_BYTES} bytes`);
  remember(packet, kem, payload);
  return packet;
}

/**
 * The decoded `encryption` bytes of packets this module decoded or built, so signature checks and decryption do not
 * decode a payload of up to MAX_PAYLOAD_BYTES again. An entry is used only while the packet still holds the very
 * strings it was decoded from (a caller may mutate the object).
 */
const rawOf = new WeakMap<Packet, { kemText: string; payloadText: string; kem: Uint8Array; payload: Uint8Array }>();

function remember(p: Packet, kem: Uint8Array, payload: Uint8Array): void {
  rawOf.set(p, { kemText: p.encryption.kemCiphertext, payloadText: p.encryption.payload, kem, payload });
}

function encryptionBytes(p: Packet): { kem: Uint8Array; payload: Uint8Array } {
  const r = rawOf.get(p);
  if (r !== undefined && r.kemText === p.encryption.kemCiphertext && r.payloadText === p.encryption.payload) return r;
  return { kem: decodeKem(p.encryption.kemCiphertext), payload: decodePayloadBytes(p.encryption.payload) };
}

/** Decode packet bytes (UTF-8 JSON). */
export function parsePacket(raw: Uint8Array): Packet {
  if (raw.length > MAX_PACKET_BYTES * 2) throw bad('packet is too large');
  return decodePacket(parseJSONBytes(raw, 'invalid_packet', 'packet'));
}

function decodeKem(text: unknown): Uint8Array {
  const raw = decodeB64(text, 'invalid_packet', 'encryption.kemCiphertext', KEM_CIPHERTEXT_SIZE);
  if (raw.length !== KEM_CIPHERTEXT_SIZE) throw bad(`encryption.kemCiphertext must be ${KEM_CIPHERTEXT_SIZE} bytes`);
  return raw;
}

function decodePayloadBytes(text: unknown): Uint8Array {
  const raw = decodeB64(text, 'invalid_packet', 'encryption.payload', MAX_PAYLOAD_BYTES);
  if (!PLAINTEXT_BUCKETS.has(raw.length - AEAD_OVERHEAD)) throw bad('encryption.payload is not a padded bucket');
  return raw;
}

/** The AEAD header (also the HKDF info). */
export function packetHeader(from: string, to: string, messageId: string, timestamp: number, prekeyId: string, kemCiphertext: Uint8Array): Uint8Array {
  return encodePayload(DOMAIN, from, to, messageId, decimal(timestamp), prekeyId, kemCiphertext);
}

/** The signed payload of a packet (inside `M`). */
export function packetSignPayload(p: Packet): Uint8Array {
  const { kem, payload } = encryptionBytes(p);
  return signPayloadOf(p.to, p.messageId, p.encryption.prekey, kem, payload);
}

function signPayloadOf(to: string, messageId: string, prekeyId: string, kem: Uint8Array, payload: Uint8Array): Uint8Array {
  return encodePayload(to, messageId, prekeyId, kem, payload);
}

async function aesKey(ss: Uint8Array, header: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const raw = hkdf(sha256, ss, SALT, header, 32);
  try {
    return await crypto.subtle.importKey('raw', Uint8Array.from(raw), 'AES-GCM', false, [usage]);
  } finally {
    raw.fill(0);
  }
}

/** Internal (vectors): AEAD-seal `plaintext` under shared secret `ss` and `header`. */
export async function sealPayload(ss: Uint8Array, header: Uint8Array, plaintext: Uint8Array, nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(NONCE_LEN))): Promise<Uint8Array> {
  if (nonce.length !== NONCE_LEN) throw new ACEError('invalid_argument', 'nonce must be 12 bytes');
  const key = await aesKey(ss, header, 'encrypt');
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: Uint8Array.from(nonce), additionalData: Uint8Array.from(header) }, key, Uint8Array.from(plaintext)));
  const out = new Uint8Array(NONCE_LEN + ct.length);
  out.set(nonce, 0);
  out.set(ct, NONCE_LEN);
  return out;
}

/** Internal (vectors): open a payload sealed by `sealPayload`; any failure is `decryption_failed`. */
export async function openPayload(ss: Uint8Array, header: Uint8Array, payload: Uint8Array): Promise<Uint8Array> {
  const key = await aesKey(ss, header, 'decrypt');
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: Uint8Array.from(payload.subarray(0, NONCE_LEN)), additionalData: Uint8Array.from(header) },
      key, Uint8Array.from(payload.subarray(NONCE_LEN)),
    ));
  } catch {
    throw new ACEError('decryption_failed', 'AEAD authentication failed');
  }
}

/**
 * Validate private content (`invalid_body`; a missing or malformed `prekey` is `invalid_argument`; an oversize plaintext
 * is `limit_exceeded`) and return its canonical bytes (unpadded).
 */
export function encodePrivateContent(content: PrivateContent): Uint8Array {
  checkPrivateContent(content, 'invalid_argument');
  const out = canonicalStateBytes(content);
  if (out.length > MAX_PLAINTEXT_BYTES) throw new ACEError('limit_exceeded', `plaintext exceeds ${MAX_PLAINTEXT_BYTES} bytes`);
  return out;
}

/** `prekeyCode`: the error for a missing or malformed `prekey` (the sender's `invalid_argument`, else `invalid_body`). */
function checkPrivateContent(c: unknown, prekeyCode: ACEErrorCode = 'invalid_body'): asserts c is PrivateContent & { prekey: string } {
  if (!isObj(c)) throw new ACEError('invalid_body', 'private content must be a JSON object');
  // 04 § Peer prekeys: every packet (receipts and contact packets too) offers the receiver a peer prekey.
  if (!('prekey' in c)) throw new ACEError(prekeyCode, 'private content must carry prekey');
  decodePrekeyPublicKey(c.prekey, prekeyCode);
  if (!closedKeys(c, ['type', 'schemaDigest', 'body', 'prekey'], ['threadId', 'admission'])) throw new ACEError('invalid_body', 'private content must be {type, schemaDigest, threadId?, body, prekey, admission?}');
  if (!isMessageType(c.type)) throw new ACEError('invalid_body', 'type must be a namespaced identifier');
  if (!isHex64(c.schemaDigest)) throw new ACEError('invalid_body', 'schemaDigest must be 64 lowercase hex');
  if (c.threadId !== undefined && !isThreadId(c.threadId)) throw new ACEError('invalid_body', 'invalid threadId');
  if (!isObj(c.body)) throw new ACEError('invalid_body', 'body must be a JSON object');
  // 03 § Private content: the closed `{proof, permit, source}` of three JSON objects; their contents are checked by 05.
  const a = c.admission;
  if (a !== undefined && !(closedKeys(a, ['proof', 'permit', 'source']) && isObj(a.proof) && isObj(a.permit) && isObj(a.source))) {
    throw new ACEError('invalid_body', 'admission must be {proof, permit, source} of three JSON objects');
  }
  // Receipts and contact packets never carry it (03 § Private content).
  if (a !== undefined && (c.type === RECEIPT_TYPE || c.type === CONTACT_TYPE)) throw new ACEError('invalid_body', `${c.type} carries admission`);
  checkJsonValue(c); // 02 § JSON values: depth counted from the plaintext's top-level value
}

/** Decode unpadded plaintext into private content (`invalid_body`), `prekey` included (the receiver strips it). */
export function decodePrivateContent(raw: Uint8Array): PrivateContent {
  const c = parseJSONBytes(raw, 'invalid_body', 'plaintext');
  checkPrivateContent(c);
  return {
    type: c.type, schemaDigest: c.schemaDigest, ...(c.threadId !== undefined ? { threadId: c.threadId } : {}), body: c.body as JSONObject, prekey: c.prekey,
    ...(c.admission !== undefined ? { admission: c.admission as unknown as Admission } : {}),
  };
}

export interface CreatePacketInput {
  identity: ACEIdentity;
  to: string;
  /** The recipient's current descriptor prekey. */
  prekey: Prekey;
  content: PrivateContent;
  messageId?: string;
  timestamp?: number;
  /** Internal (vectors): a fixed encapsulation and nonce instead of fresh randomness. */
  _deterministic?: { kemCiphertext: Uint8Array; sharedSecret: Uint8Array; nonce: Uint8Array };
}

/** Encrypt `content` to the recipient's prekey and sign the packet with the identity's delegated signing key. */
export async function createPacket(input: CreatePacketInput): Promise<Packet> {
  const { identity, to } = input;
  const from = identity.getACEId();
  if (!isACEId(to) || to === from) throw new ACEError('invalid_argument', 'to must be another ACE ID');
  const messageId = input.messageId ?? crypto.randomUUID();
  if (!isMessageId(messageId)) throw new ACEError('invalid_argument', 'messageId must be a lowercase UUIDv4');
  const timestamp = input.timestamp ?? nowOf();
  if (wireInt(timestamp) === null) throw new ACEError('invalid_argument', 'timestamp must be a wire integer');
  const state = checkUsable(identity, timestamp);
  const pk = decodePrekey(input.prekey, 'invalid_argument');
  const plaintext = padPlaintext(encodePrivateContent(input.content));
  let kemCiphertext: Uint8Array, ss: Uint8Array, nonce: Uint8Array | undefined;
  if (input._deterministic) {
    ({ kemCiphertext, sharedSecret: ss, nonce } = input._deterministic);
  } else {
    const e = ml_kem768_x25519.encapsulate(pk);
    kemCiphertext = e.cipherText; ss = e.sharedSecret;
  }
  try {
    const header = packetHeader(from, to, messageId, timestamp, input.prekey.id, kemCiphertext);
    const payload = await sealPayload(ss, header, plaintext, nonce);
    const packet: Packet = {
      ace: VERSION, messageId, from, to, timestamp,
      encryption: { prekey: input.prekey.id, kemCiphertext: toBase64(kemCiphertext), payload: toBase64(payload) },
      signature: { scheme: 'ml-dsa-65', seq: state.signing!.seq, value: '' },
    };
    if (canonicalStateBytes(packet).length + SIGNATURE_B64_LENGTH > MAX_PACKET_BYTES) throw new ACEError('limit_exceeded', `packet exceeds ${MAX_PACKET_BYTES} bytes`);
    const m = signingMessage(from, timestamp, state.signing!.seq, signPayloadOf(to, messageId, input.prekey.id, kemCiphertext, payload));
    packet.signature.value = toBase64(await identity.sign(m, 'packet'));
    remember(packet, kemCiphertext, payload);
    return packet;
  } finally {
    if (!input._deterministic) ss.fill(0);
  }
}

/**
 * Verify the packet signature against the sender's verified KEL state at `now` (01 § Operational signatures:
 * `stale_peer_binding` / `invalid_signature`).
 */
export function verifyPacketSignature(packet: Packet, sender: KelState, now: number): void {
  if (sender.aceId !== packet.from) throw new ACEError('invalid_signature', 'sender state is not packet.from');
  verifyOperationalSignature(sender, 'packet', packet.timestamp, packetSignPayload(packet), packet.signature, now, 'invalid_signature');
}

/** `stale_timestamp` unless `now - OFFLINE_WINDOW_SECONDS <= timestamp <= now + TIMESTAMP_WINDOW_SECONDS`. */
export function checkPacketTime(packet: Packet, now: number): void {
  if (packet.timestamp < now - OFFLINE_WINDOW_SECONDS || packet.timestamp > now + TIMESTAMP_WINDOW_SECONDS) {
    throw new ACEError('stale_timestamp', 'packet timestamp is outside the acceptance window');
  }
}

/**
 * Decrypt with the referenced prekey, unpad and decode: `unknown_prekey` when the vault does not hold it,
 * `decryption_failed` on AEAD/KEM failure, `invalid_body` on bad padding or content.
 */
export async function decryptPacket(packet: Packet, vault: PrekeyVault): Promise<PrivateContent> {
  const secret = await vault.open(packet.encryption.prekey); // Task 8: pass packet.from (peer prekeys)
  if (secret === null) throw new ACEError('unknown_prekey', 'the referenced prekey is unknown or deleted');
  const { kem, payload } = encryptionBytes(packet);
  const ss = secret.decapsulate(kem);
  try {
    const header = packetHeader(packet.from, packet.to, packet.messageId, packet.timestamp, packet.encryption.prekey, kem);
    return decodePrivateContent(unpadPlaintext(await openPayload(ss, header, payload)));
  } finally {
    ss.fill(0);
  }
}
