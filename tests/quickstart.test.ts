import { expect, it } from 'vitest';
it('the documented quickstart encrypts, authenticates and decrypts an RFQ', async () => {
  const { parsed } = await import('../examples/quickstart.js');
  expect(parsed.body).toEqual({ need: 'Translate 500 words EN→FR', maxPrice: '10', currency: 'USDC' });
});
