/** The two core message types (`ace:core:1`, always installed): receipts and contact requests. */
import { ACEError, isOutcomeCode } from './errors.js';
import { isHex64, isMessageId, isObj, utf8 } from './encoding.js';
import { MAX_NOTE_BYTES } from './limits.js';
import { BUNDLED_MANIFESTS, CONTACT_TYPE, messageDigest, RECEIPT_TYPE } from './manifest.js';
import type { DeliveryPermit, PublishedAgent } from './descriptor.js';
import type { JSONObject, PrivateContent } from './types.js';

export interface ReceiptBody {
  messageId: string;
  outcome: 'delivered' | 'rejected';
  /** Only with `rejected`: `^[a-z0-9_]{1,64}$`. */
  code?: string;
  /** Exactly with `code: unknown_prekey`: the 64-hex prekey ID of the packet the receiver could not open. */
  prekey?: string;
  /** A renewal from the receiver when the newest permit it issued the sender has less than PERMIT_RENEWAL_SECONDS left. */
  permit?: DeliveryPermit;
}

export interface ContactBody {
  kind: 'request' | 'accepted' | 'rejected';
  profile: string;
  /** At most 512 UTF-8 bytes; travels encrypted. */
  note: string;
  /** The sender's PublishedAgent; verifies the outer signature. */
  source: PublishedAgent;
  /** Required with `request` / `accepted`: the sender's reply permit for the recipient. */
  permit?: DeliveryPermit;
}

function coreDigest(type: string): string {
  const m = BUNDLED_MANIFESTS.core.messages.find((x) => x.type === type)!;
  return messageDigest(m.type, m.schema);
}

export const RECEIPT_SCHEMA_DIGEST = coreDigest(RECEIPT_TYPE);
export const CONTACT_SCHEMA_DIGEST = coreDigest(CONTACT_TYPE);

/** Rules beyond the manifest schema (`invalid_body`). */
export function checkReceiptBody(body: JSONObject): ReceiptBody {
  if (!isMessageId(body.messageId)) throw new ACEError('invalid_body', 'receipt.messageId must be a UUIDv4');
  if (body.outcome === 'rejected' ? !isOutcomeCode(body.code) : body.code !== undefined) {
    throw new ACEError('invalid_body', 'receipt.code is required with (and only with) rejected, ^[a-z0-9_]{1,64}$');
  }
  if ((body.code === 'unknown_prekey') !== (body.prekey !== undefined) || (body.prekey !== undefined && !isHex64(body.prekey))) {
    throw new ACEError('invalid_body', 'receipt.prekey (64 lowercase hex) is required with (and only with) unknown_prekey');
  }
  if (body.permit !== undefined && !isObj(body.permit)) throw new ACEError('invalid_body', 'receipt.permit must be an object');
  return body as unknown as ReceiptBody;
}

/** Rules beyond the manifest schema (`invalid_body`); the source and permit signatures are checked by the receiver. */
export function checkContactBody(body: JSONObject): ContactBody {
  if (typeof body.note !== 'string' || utf8(body.note).length > MAX_NOTE_BYTES) throw new ACEError('invalid_body', `contact.note exceeds ${MAX_NOTE_BYTES} bytes`);
  if (body.kind !== 'rejected' && !isObj(body.permit)) throw new ACEError('invalid_body', 'contact request/accepted must carry a reply permit');
  return body as unknown as ContactBody;
}

export function receiptContent(body: ReceiptBody): PrivateContent {
  const b = { messageId: body.messageId, outcome: body.outcome, ...(body.code !== undefined ? { code: body.code } : {}), ...(body.prekey !== undefined ? { prekey: body.prekey } : {}), ...(body.permit ? { permit: body.permit } : {}) } as unknown as JSONObject;
  checkReceiptBody(b);
  return { type: RECEIPT_TYPE, schemaDigest: RECEIPT_SCHEMA_DIGEST, body: b };
}

export function contactContent(body: ContactBody): PrivateContent {
  const b = { kind: body.kind, profile: body.profile, note: body.note, source: body.source, ...(body.permit ? { permit: body.permit } : {}) } as unknown as JSONObject;
  checkContactBody(b);
  return { type: CONTACT_TYPE, schemaDigest: CONTACT_SCHEMA_DIGEST, body: b };
}
