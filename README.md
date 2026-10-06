# @ace-protocol/sdk

TypeScript SDK for the **ACE Protocol** (Agent Commerce Engine) — a secure, end-to-end encrypted messaging protocol for agent-to-agent commerce.

## Features

- **Identity Management** — Ed25519 / secp256k1 key pairs with ACE ID derivation
- **End-to-End Encryption** — X-Wing (X25519 + ML-KEM-768) hybrid post-quantum KEM → HKDF-SHA256 → AES-256-GCM, bound to the conversation
- **Digital Signatures** — Message signing and verification
- **Structured Messages** — Typed economic flow: RFQ → Offer → Accept → Invoice → Receipt → Deliver → Confirm
- **Thread State Machine** — Enforced message flow transitions
- **Agent Discovery** — Registration file validation and profile management
- **Replay Protection** — Timestamp freshness checks and replay detection

## Encryption

Every message body is encrypted for its recipient with:

1. **X-Wing KEM** ([draft-connolly-cfrg-xwing-kem-11](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)) — a hybrid of ML-KEM-768 (FIPS 203) and X25519. The recipient's static encryption public key is 1216 bytes; each message carries a 1120-byte `kemCiphertext`; the private key is a 32-byte seed.
2. **HKDF-SHA256** — `ikm = X-Wing shared secret`, `salt = SHA-256("ace.protocol.kem.v1")`, `info = conversationId`, 32-byte output.
3. **AES-256-GCM** — random 12-byte nonce, 16-byte tag, `aad = conversationId`; `payload = nonce || ciphertext || tag`.

The `kemCiphertext` is part of the signed message payload, so a relay cannot swap it without breaking the sender's signature. Signatures (Ed25519 / secp256k1) remain classical; the hybrid KEM protects message confidentiality against harvest-now-decrypt-later attacks.

**Forward secrecy — honest statement:** the sender holds no long-term secret for encryption, so compromising a sender reveals nothing about past messages. The recipient's static X-Wing seed, however, decrypts every message ever sent to that key, past and future. Rotate the encryption key by publishing a new registration file if that is a concern.

## Installation

```bash
npm install @ace-protocol/sdk
```

Requires Node.js >= 20.0.0.

## Quick Start

```typescript
import {
  SoftwareIdentity,
  createMessage,
  parseMessage,
  computeConversationId,
  ThreadStateMachine,
  ReplayDetector,
} from '@ace-protocol/sdk';

// Create identities for two agents
const alice = await SoftwareIdentity.generate('ed25519');
const bob = await SoftwareIdentity.generate('ed25519');

// Compute a shared conversation ID
const conversationId = computeConversationId(
  alice.getEncryptionPublicKey(),
  bob.getEncryptionPublicKey(),
);

// Create and send an encrypted, signed message
const message = await createMessage({
  sender: alice,
  recipientPubKey: bob.getEncryptionPublicKey(), // 1216-byte X-Wing public key
  recipientACEId: bob.getACEId(),
  type: 'rfq',
  threadId: 'deal-1',
  body: { need: 'Translate 500 words EN→FR', maxPrice: '10', currency: 'USDC' },
  stateMachine: new ThreadStateMachine(),
});
// message.encryption = { kemCiphertext: Base64(1120 bytes), payload: Base64(nonce||ct||tag) }

// Recipient verifies the signature, then decrypts
const parsed = await parseMessage(message, bob, alice.getSigningPublicKey(), {
  stateMachine: new ThreadStateMachine(),
  replayDetector: new ReplayDetector(),
  senderEncryptionPubKey: alice.getEncryptionPublicKey(),
});

console.log(parsed.body); // { need: 'Translate 500 words EN→FR', ... }
```

## Message Types

| Category | Types |
|----------|-------|
| Economic | `rfq`, `offer`, `accept`, `reject`, `invoice`, `receipt`, `deliver`, `confirm` |
| System   | `info` |
| Social   | `text` |

## API

### Identity

- `SoftwareIdentity.generate(scheme)` — Create a new Ed25519 or secp256k1 identity with a fresh X-Wing encryption seed
- `identity.exportPrivateKey()` / `SoftwareIdentity.fromExport(data)` — Base64 export/import (`encryptionPrivateKey` is the 32-byte X-Wing seed)
- `computeACEId(publicKey)` — Derive an ACE ID from a public key

### Encryption

- `computeConversationId(pubA, pubB)` — Deterministic conversation ID from two 1216-byte X-Wing public keys
- `encrypt(plaintext, recipientPubKey, conversationId)` → `{ kemCiphertext, payload }` — Encrypt a payload
- `decrypt(kemCiphertext, payload, seed, conversationId)` — Decrypt a payload with the 32-byte X-Wing seed
- `kemEncapsulate(pubKey)` / `kemDecapsulate(kemCiphertext, seed)` / `kemPublicKeyFromSeed(seed)` / `generateKemSeed()` — Raw X-Wing operations
- `getACEKemSalt()` — `SHA-256("ace.protocol.kem.v1")`, the HKDF salt
- `decodeKemPublicKey(b64)` / `decodeKemCiphertext(b64)` — Decode Base64 wire strings into exact-size X-Wing bytes (Base64-length pre-check, then byte-length check)
- `validatePublicKey(pk)` / `validateKemCiphertext(ct)` / `validateSeed(seed)` — Assert the exact X-Wing byte lengths (1216 / 1120 / 32)
- `KEM_SEED_SIZE` (32), `KEM_PUBLIC_KEY_SIZE` (1216), `KEM_CIPHERTEXT_SIZE` (1120)

### Messages

- `createMessage(options)` — Build an encrypted, signed ACE message
- `parseMessage(options)` — Decrypt, verify, and parse an ACE message
- `validateBody(type, body)` — Validate a message body against its type schema

### Discovery

- `validateRegistrationFile(data)` — Validate agent registration files
- `validateProfile(data)` — Validate agent profiles
- `fetchRegistrationFile(aceId, options?)` — Fetch a registration file by ACE ID

### Security

- `checkTimestampFreshness(timestamp)` — Check if a timestamp is within acceptable bounds
- `validateMessageId(id)` — Validate message ID format
- `ReplayDetector` — Sliding-window replay detection

### State Machine

- `ThreadStateMachine` — Enforces valid economic message flow transitions

## License

Apache-2.0 — see [LICENSE](./LICENSE) for details.
