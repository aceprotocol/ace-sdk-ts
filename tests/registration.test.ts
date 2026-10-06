import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createRegistrationRequest, buildRegistrationPayload, SoftwareIdentity, buildSignData, decodeSignature, verifySignature, type RegistrationRequest } from '../src/index.js';

const vectors = JSON.parse(readFileSync(new URL('./fixtures/test-vectors.json', import.meta.url), 'utf8'));
describe('registration authorization interop', () => {
  for (const vector of vectors.vectors.registrations) {
    it(`${vector.agent}: ${vector.mode}`, async () => {
      const a = vectors.agents[vector.agent];
      const identity = SoftwareIdentity.fromExport({ scheme: a.scheme, signingPrivateKey: a.signingPrivateKey, encryptionPrivateKey: a.encryptionPrivateKey });
      const request: RegistrationRequest = vector.request;
      const created = await createRegistrationRequest(identity, request.profile, request.timestamp);
      expect({ ...created, signature: request.signature, authorization: request.authorization }).toEqual(request);
      const data = buildSignData('register-request', request.aceId, request.timestamp,
        buildRegistrationPayload(request.encryptionPublicKey, request.signingPublicKey, request.scheme, request.profile));
      expect(Buffer.from(data).toString('hex')).toBe(vector.signDataHex);
      for (const signature of [created.authorization, request.authorization]) {
        expect(verifySignature(data, decodeSignature(signature, request.scheme), request.scheme, identity.getSigningPublicKey())).toBe(true);
      }
      // Published key proof must never authorize a write.
      expect(verifySignature(data, decodeSignature(request.signature, request.scheme), request.scheme, identity.getSigningPublicKey())).toBe(false);
    });
  }
});
