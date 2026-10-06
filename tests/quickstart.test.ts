import { expect, it } from 'vitest';
import { FakeRelay } from './fake-relay.js';

const BODY = { need: 'Translate 500 words EN→FR', maxPrice: '10', currency: 'USDC' };

it('the documented quickstart works locally and over a relay', async () => {
  const { parsed, overRelay } = await import('../examples/quickstart.js');
  expect(parsed.body).toEqual(BODY);
  const relay = await new FakeRelay().start();
  try {
    const received = await overRelay(relay.url);
    expect(received.map((m) => m.body)).toEqual([BODY]);
  } finally {
    await relay.close();
  }
});
