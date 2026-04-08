import { describe, it, expect } from 'vitest';
import {
  SoftwareIdentity,
  createMessage,
  parseMessage,
  computeConversationId,
  checkTimestampFreshness,
  ReplayDetector,
  ThreadStateMachine,
} from '../src/index.js';

function makeSM(): ThreadStateMachine {
  return new ThreadStateMachine();
}

describe('Integration: Full ACE Protocol Flow', () => {
  it('buyer-seller RFQ → offer → accept flow with state machine', async () => {
    const buyer = await SoftwareIdentity.generate('ed25519');
    const seller = await SoftwareIdentity.generate('secp256k1');

    const threadId = 'deal-gpu-rental-001';
    const buyerSM = makeSM();
    const sellerSM = makeSM();
    const buyerRD = new ReplayDetector();
    const sellerRD = new ReplayDetector();

    // === Step 1: Buyer sends RFQ ===
    const rfqMsg = await createMessage({
      sender: buyer,
      recipientPubKey: seller.getEncryptionPublicKey(),
      recipientACEId: seller.getACEId(),
      type: 'rfq',
      body: { need: '4x A100 GPU for 2 hours', maxPrice: '50.00', currency: 'USD' },
      threadId,
      stateMachine: buyerSM,
    });

    expect(rfqMsg.ace).toBe('1.0');
    expect(rfqMsg.type).toBe('rfq');
    expect(rfqMsg.threadId).toBe(threadId);

    // Seller receives and verifies RFQ
    const parsedRfq = await parseMessage(
      rfqMsg,
      seller,
      buyer.getSigningPublicKey(),
      { stateMachine: sellerSM, replayDetector: sellerRD },
    );
    expect(parsedRfq.body).toEqual({
      need: '4x A100 GPU for 2 hours',
      maxPrice: '50.00',
      currency: 'USD',
    });

    // === Step 2: Seller sends Offer ===
    const offerMsg = await createMessage({
      sender: seller,
      recipientPubKey: buyer.getEncryptionPublicKey(),
      recipientACEId: buyer.getACEId(),
      type: 'offer',
      body: { price: '40.00', currency: 'USD', terms: '4x A100, 2h, 99.9% SLA', ttl: 300 },
      threadId,
      stateMachine: sellerSM,
    });

    const parsedOffer = await parseMessage(
      offerMsg,
      buyer,
      seller.getSigningPublicKey(),
      { stateMachine: buyerSM, replayDetector: buyerRD },
    );
    expect(parsedOffer.body).toMatchObject({ price: '40.00', currency: 'USD' });

    // === Step 3: Buyer sends Accept ===
    const acceptMsg = await createMessage({
      sender: buyer,
      recipientPubKey: seller.getEncryptionPublicKey(),
      recipientACEId: seller.getACEId(),
      type: 'accept',
      body: { offerId: offerMsg.messageId },
      threadId,
      stateMachine: buyerSM,
    });

    const parsedAccept = await parseMessage(
      acceptMsg,
      seller,
      buyer.getSigningPublicKey(),
      { stateMachine: sellerSM, replayDetector: sellerRD },
    );
    expect(parsedAccept.body).toEqual({ offerId: offerMsg.messageId });
  });

  it('full deal flow: rfq → offer → accept → invoice → receipt → deliver → confirm', async () => {
    const buyer = await SoftwareIdentity.generate('ed25519');
    const seller = await SoftwareIdentity.generate('ed25519');
    const threadId = 'deal-full-001';
    const buyerSM = makeSM();
    const sellerSM = makeSM();
    const buyerRD = new ReplayDetector();
    const sellerRD = new ReplayDetector();

    // rfq
    const rfq = await createMessage({
      sender: buyer,
      recipientPubKey: seller.getEncryptionPublicKey(),
      recipientACEId: seller.getACEId(),
      type: 'rfq',
      body: { need: 'translation' },
      threadId,
      stateMachine: buyerSM,
    });
    await parseMessage(rfq, seller, buyer.getSigningPublicKey(), { stateMachine: sellerSM, replayDetector: sellerRD });

    // offer
    const offer = await createMessage({
      sender: seller,
      recipientPubKey: buyer.getEncryptionPublicKey(),
      recipientACEId: buyer.getACEId(),
      type: 'offer',
      body: { price: '5', currency: 'USD' },
      threadId,
      stateMachine: sellerSM,
    });
    await parseMessage(offer, buyer, seller.getSigningPublicKey(), { stateMachine: buyerSM, replayDetector: buyerRD });

    // accept
    const accept = await createMessage({
      sender: buyer,
      recipientPubKey: seller.getEncryptionPublicKey(),
      recipientACEId: seller.getACEId(),
      type: 'accept',
      body: { offerId: offer.messageId },
      threadId,
      stateMachine: buyerSM,
    });
    await parseMessage(accept, seller, buyer.getSigningPublicKey(), { stateMachine: sellerSM, replayDetector: sellerRD });

    // invoice
    const invoice = await createMessage({
      sender: seller,
      recipientPubKey: buyer.getEncryptionPublicKey(),
      recipientACEId: buyer.getACEId(),
      type: 'invoice',
      body: { offerId: offer.messageId, amount: '5', currency: 'USD', settlementMethod: 'crypto/instant' },
      threadId,
      stateMachine: sellerSM,
    });
    await parseMessage(invoice, buyer, seller.getSigningPublicKey(), { stateMachine: buyerSM, replayDetector: buyerRD });

    // receipt
    const receipt = await createMessage({
      sender: buyer,
      recipientPubKey: seller.getEncryptionPublicKey(),
      recipientACEId: seller.getACEId(),
      type: 'receipt',
      body: { invoiceId: invoice.messageId, amount: '5', currency: 'USD', settlementMethod: 'crypto/instant', proof: { txHash: '0xabc' } },
      threadId,
      stateMachine: buyerSM,
    });
    await parseMessage(receipt, seller, buyer.getSigningPublicKey(), { stateMachine: sellerSM, replayDetector: sellerRD });

    // deliver
    const deliver = await createMessage({
      sender: seller,
      recipientPubKey: buyer.getEncryptionPublicKey(),
      recipientACEId: buyer.getACEId(),
      type: 'deliver',
      body: { type: 'inline', content: 'translated text here' },
      threadId,
      stateMachine: sellerSM,
    });
    await parseMessage(deliver, buyer, seller.getSigningPublicKey(), { stateMachine: buyerSM, replayDetector: buyerRD });

    // confirm
    const confirm = await createMessage({
      sender: buyer,
      recipientPubKey: seller.getEncryptionPublicKey(),
      recipientACEId: seller.getACEId(),
      type: 'confirm',
      body: { deliverId: deliver.messageId },
      threadId,
      stateMachine: buyerSM,
    });
    await parseMessage(confirm, seller, buyer.getSigningPublicKey(), { stateMachine: sellerSM, replayDetector: sellerRD });

    // Both sides should be in confirmed state (terminal)
    const convId = computeConversationId(buyer.getEncryptionPublicKey(), seller.getEncryptionPublicKey());
    expect(buyerSM.getState(convId, threadId)).toBe('confirmed');
    expect(sellerSM.getState(convId, threadId)).toBe('confirmed');
  });

  it('rejects message with invalid signature', async () => {
    const sender = await SoftwareIdentity.generate('ed25519');
    const receiver = await SoftwareIdentity.generate('ed25519');
    const impersonator = await SoftwareIdentity.generate('ed25519');

    const msg = await createMessage({
      sender,
      recipientPubKey: receiver.getEncryptionPublicKey(),
      recipientACEId: receiver.getACEId(),
      type: 'text',
      body: { message: 'Trust me' },
      stateMachine: makeSM(),
    });

    await expect(
      parseMessage(msg, receiver, impersonator.getSigningPublicKey(), { stateMachine: makeSM() }),
    ).rejects.toThrow(/does not match sender signing public key/);
  });

  it('replay detection prevents duplicate processing', async () => {
    const detector = new ReplayDetector();
    const sender = await SoftwareIdentity.generate('ed25519');
    const receiver = await SoftwareIdentity.generate('ed25519');
    const sm = makeSM();

    const msg = await createMessage({
      sender,
      recipientPubKey: receiver.getEncryptionPublicKey(),
      recipientACEId: receiver.getACEId(),
      type: 'info',
      body: { message: 'hello' },
      stateMachine: makeSM(),
    });

    await parseMessage(msg, receiver, sender.getSigningPublicKey(), {
      stateMachine: sm,
      replayDetector: detector,
    });

    await expect(
      parseMessage(msg, receiver, sender.getSigningPublicKey(), {
        stateMachine: sm,
        replayDetector: detector,
      }),
    ).rejects.toThrow(/Replay detected/);
  });

  it('cross-scheme communication (ed25519 ↔ secp256k1)', async () => {
    const agentEd = await SoftwareIdentity.generate('ed25519');
    const agentSec = await SoftwareIdentity.generate('secp256k1');

    const msg1 = await createMessage({
      sender: agentEd,
      recipientPubKey: agentSec.getEncryptionPublicKey(),
      recipientACEId: agentSec.getACEId(),
      type: 'text',
      body: { message: 'Ed25519 → secp256k1' },
      stateMachine: makeSM(),
    });

    const parsed1 = await parseMessage(
      msg1,
      agentSec,
      agentEd.getSigningPublicKey(),
      { stateMachine: makeSM() },
    );
    expect(parsed1.body).toEqual({ message: 'Ed25519 → secp256k1' });

    const msg2 = await createMessage({
      sender: agentSec,
      recipientPubKey: agentEd.getEncryptionPublicKey(),
      recipientACEId: agentEd.getACEId(),
      type: 'text',
      body: { message: 'secp256k1 → Ed25519' },
      stateMachine: makeSM(),
    });

    const parsed2 = await parseMessage(
      msg2,
      agentEd,
      agentSec.getSigningPublicKey(),
      { stateMachine: makeSM() },
    );
    expect(parsed2.body).toEqual({ message: 'secp256k1 → Ed25519' });
  });
});
