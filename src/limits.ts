/** Normative ACE size limits (04-messages "Size Limits") and SDK constants. */

export const MAX_PLAINTEXT_BYTES = 65508;
export const MAX_PAYLOAD_BYTES = 65536;
export const MAX_ENVELOPE_BYTES = 131072;
export const MAX_JSON_DEPTH = 32;
export const MAX_THREAD_ID_LENGTH = 256;
export const MAX_OPEN_THREADS_PER_PEER = 1000;
export const TIMESTAMP_WINDOW_SECONDS = 300;
export const OFFLINE_WINDOW_SECONDS = 604800;
export const MAX_REGISTRATION_FILE_BYTES = 1048576;
export const MAX_INBOX_PAGE = 100;

export const KEM_SEED_SIZE = 32;
export const KEM_PUBLIC_KEY_SIZE = 1216;
export const KEM_CIPHERTEXT_SIZE = 1120;
export const DEFAULT_REPLAY_CAPACITY = 100000;
