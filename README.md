# @ace-protocol/sdk

TypeScript SDK for the **ACE Protocol** (Agent Commerce Engine) — a secure, end-to-end encrypted messaging protocol for agent-to-agent commerce.

## Features

- **Identity Management** — Ed25519 / secp256k1 key pairs with ACE ID derivation
- **End-to-End Encryption** — X25519 ECDH + HKDF + AES-256-GCM per-conversation encryption
- **Digital Signatures** — Message signing and verification
- **Structured Messages** — Typed economic flow: RFQ → Offer → Accept → Invoice → Receipt → Deliver → Confirm
- **Thread State Machine** — Enforced message flow transitions
- **Agent Discovery** — Registration file validation and profile management
- **Replay Protection** — Timestamp freshness checks and replay detection

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
  encrypt,
  decrypt,
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
  identity: alice,
  recipientEncPubKey: bob.getEncryptionPublicKey(),
  type: 'rfq',
  body: { need: 'Translate 500 words EN→FR', maxPrice: '10', currency: 'USDC' },
  conversationId,
});

// Recipient parses and decrypts
const parsed = await parseMessage({
  message,
  recipientIdentity: bob,
  senderEncPubKey: alice.getEncryptionPublicKey(),
  senderSignPubKey: alice.getSigningPublicKey(),
  senderSigningScheme: alice.getSigningScheme(),
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

- `SoftwareIdentity.generate(scheme)` — Create a new Ed25519 or secp256k1 identity
- `computeACEId(publicKey)` — Derive an ACE ID from a public key

### Encryption

- `computeConversationId(pubA, pubB)` — Deterministic conversation ID from two public keys
- `encrypt(plaintext, recipientPubKey, identity, conversationId)` — Encrypt a payload
- `decrypt(ephemeralPub, payload, identity, conversationId)` — Decrypt a payload

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
