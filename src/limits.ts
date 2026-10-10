/** Normative ACE size limits (04-messages "Size Limits") and SDK constants. */

export const MAX_PLAINTEXT_BYTES = 65508;
export const MAX_PAYLOAD_BYTES = 65536;
export const MAX_ENVELOPE_BYTES = 131072;
/** The largest direct-delivery request body (`{"message": Envelope}`), 08-relay § Direct Delivery. */
export const MAX_DIRECT_BODY_BYTES = MAX_ENVELOPE_BYTES + 1024;
export const MAX_JSON_DEPTH = 32;
export const MAX_THREAD_ID_LENGTH = 256;
export const MAX_OPEN_THREADS_PER_PEER = 1000;
export const TIMESTAMP_WINDOW_SECONDS = 300;
export const OFFLINE_WINDOW_SECONDS = 604800;
export const MAX_REGISTRATION_FILE_BYTES = 1048576;
export const MAX_INBOX_PAGE = 100;
/** The longest principal record lifetime, `expiresAt - issuedAt` (366 days), 09-principal. */
export const PRINCIPAL_MAX_LIFETIME_SECONDS = 31622400;
/** `ext` of a profile, registration file or intent (02-discovery § Profile Fields). */
export const MAX_EXT_KEYS = 8;
export const MAX_EXT_KEY_BYTES = 256;
export const MAX_EXT_BYTES = 4096;
export const MAX_EXT_DEPTH = 8;

export const KEM_SEED_SIZE = 32;
export const KEM_PUBLIC_KEY_SIZE = 1216;
export const KEM_CIPHERTEXT_SIZE = 1120;
export const DEFAULT_REPLAY_CAPACITY = 100000;

/** Pairwise MLS wire limits (13-secure-delivery): key packages, Welcome/ciphertext strings, raw engine responses. */
export const MLS_MAX_KEY_PACKAGE_CHARS = 10_924;
export const MLS_MAX_MESSAGE_CHARS = 64_000;
export const MLS_MAX_ENGINE_IO_BYTES = 140_000;
/** Lifetime of one secure-delivery attempt. */
export const SECURE_DELIVERY_TTL_SECONDS = 120;
/** Compact JSON of an execution intent / request body. */
export const MAX_EXECUTION_JSON_BYTES = 60_000;
