/** Shared ACE type definitions. */

/** The only signing scheme (02 § Signatures); `scheme` members keep room for a later revision. */
export type SigningScheme = 'ml-dsa-65';

export type JSONValue = null | boolean | number | string | JSONValue[] | { [key: string]: JSONValue };
export type JSONObject = { [key: string]: JSONValue };

/** ASCII namespaced identifier: message types and profile ids. */
export const NAMESPACED_ID_RE = /^[a-z][a-z0-9+.-]*:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$/;

export function isMessageType(t: unknown): t is string {
  return typeof t === 'string' && t.length <= 256 && NAMESPACED_ID_RE.test(t);
}

/**
 * What an Outbox retry carries (05 § Admission recovery): `proof`, the permit the receiver issued the sender; `permit`,
 * a reply permit the sender issues the receiver; and `source`, the sender's current PublishedAgent. Decoding checks
 * only that all three are JSON objects; the receiver verifies them and never hands them to the application.
 */
export interface Admission {
  proof: JSONObject;
  permit: JSONObject;
  source: JSONObject;
}

/** The encrypted private content of a packet: its canonical JSON is the plaintext. */
export interface PrivateContent {
  type: string;
  /** The message digest of the installed manifest entry (never fetched from the sender). */
  schemaDigest: string;
  threadId?: string;
  body: JSONObject;
  /**
   * The peer prekey the sender offers the receiver for its replies (04 § Peer prekeys): canonical Base64 of a 1216-byte
   * X-Wing public key. Required on the wire (`encodePrivateContent` / `decodePrivateContent`); absent from content
   * stored before sending (the transport adds it per packet) and stripped by the receiver before hand-over.
   */
  prekey?: string;
  /** Only on an application message's Outbox retry (03 § Private content); never on receipts or contact packets. */
  admission?: Admission;
}

/** A verified, decrypted and schema-checked inbound message. */
export interface ParsedMessage {
  messageId: string;
  from: string;
  to: string;
  timestamp: number;
  /** Local conversation key (`conversationKey(from, to)`); not on the wire. */
  conversation: string;
  type: string;
  schemaDigest: string;
  threadId: string | null;
  body: JSONObject;
}
