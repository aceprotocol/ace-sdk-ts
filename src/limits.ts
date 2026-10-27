/** The normative constants of 02 § Constants (protocol-contract.json `limits`), then SDK-internal bounds. */

export const TIMESTAMP_WINDOW_SECONDS = 300;
export const OFFLINE_WINDOW_SECONDS = 604_800;
/** 1 MiB + 128 KiB: room for a full PublishedAgent in a contact request. */
export const MAX_PLAINTEXT_BYTES = 1_179_648;
export const MAX_PACKET_BYTES = 2_097_152;
/** `POST /v1/send` body: a packet plus room for a permit. */
export const MAX_SEND_BODY_BYTES = MAX_PACKET_BYTES + 65_536;
export const MAX_PUBLISHED_AGENT_BYTES = 1_048_576;
/** Canonical JSON of a card record (04 § Card record). */
export const MAX_CARD_RECORD_BYTES = 16_384;
export const MAX_JSON_DEPTH = 32;
export const MAX_TYPE_BYTES = 256;
export const MAX_THREAD_ID_LENGTH = 256;
export const MAX_KEL_EVENTS = 256;
export const MAX_DESCRIPTOR_LIFETIME = 604_800;
/** Upper bound of `notAfter - ts` for a `dlg` signing key. */
export const MAX_SIGNING_KEY_LIFETIME = 31_622_400;
export const MAX_PERMIT_LIFETIME = 2_592_000;
/** A receipt carries a fresh permit when the newest one issued to its recipient has less than this left. */
export const PERMIT_RENEWAL_SECONDS = 1_296_000;
export const MAX_RETAINED_PREKEYS = 16;
export const MAX_EXT_BYTES = 32_768;
/** Entries of a card record `pay`. */
export const MAX_PAY_ACCOUNTS = 8;
/** Entries of a card record `erc8004`. */
export const MAX_CARD_ERC8004 = 4;
export const MAX_NOTE_BYTES = 512;
/** Maximum and default `limit` of inbox and directory pages. */
export const MAX_INBOX_PAGE = 100;
export const MAX_PAGE_BYTES = 8_388_608;
export const MAX_MANIFEST_BYTES = 65_536;
export const MAX_PENDING_CONTACT_REQUESTS = 16;
/** Lifetime of a held incoming contact request and of a relay's stranger entries. */
export const CONTACT_REQUEST_TTL_SECONDS = 86_400;
export const MAX_STRANGER_KEL_EVENTS = 32;
export const STRANGER_ALLOWANCE = 16;
export const STRANGER_NETWORK_ALLOWANCE = 2;
export const MIN_BLOCK_CAP = 256;
export const PIN_REFRESH_INTERVAL_SECONDS = 30;
export const MAX_FETCH_ATTEMPTS = 3;

// --- SDK-internal bounds (no spec name) ---------------------------------------------------------------------

export const MAX_DESCRIPTOR_PROFILES = 32;
export const MAX_DESCRIPTOR_RELAYS = 4;
/** Reference descriptor lifetime (the default `ttl`; at most MAX_DESCRIPTOR_LIFETIME). */
export const DEFAULT_DESCRIPTOR_LIFETIME = 86_400;
/** Reference prekey rotation period. */
export const PREKEY_ROTATION_SECONDS = 86_400;
export const OUTBOX_FIRST_RETRY_SECONDS = 60;
export const OUTBOX_MAX_RETRY_SECONDS = 3600;
export const KEM_SEED_SIZE = 32;
export const KEM_PUBLIC_KEY_SIZE = 1216;
export const KEM_CIPHERTEXT_SIZE = 1120;
export const DEFAULT_REPLAY_CAPACITY = 100_000;
