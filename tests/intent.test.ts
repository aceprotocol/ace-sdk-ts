import { expect, it } from 'vitest';
import { intentDigest } from '../src/intent.js';
import { codeOf } from './helpers.js';

it('operation identity matches the Python and Swift numeric/Unicode vectors', () => {
  const value = { z: [null, true, false, -0, 1.0, 1e-7, 1e21, '1'], '\ue000': 'private', '😀': '中文/\n' };
  expect(intentDigest(value)).toBe('5755ebae76cfdbfc522994dc18b9bba626d19aef7c98638c44a0ba8c852de634');
  expect(intentDigest({ a: 1 })).toBe('2317a230dd89e93a9aee06850327e78f32a0e7ccbca1771fcf4d3ae16478eb2c');
  expect(intentDigest({ '😀': '中文/\n', '\ue000': 'private', z: [null, true, false, 0, 1, 0.0000001, 1e21, '1'] })).toBe(intentDigest(value));
});

it('operation identity preserves types and rejects malformed Unicode', () => {
  expect(new Set([null, false, 0, '0', [], {}, ['number', '0000000000000000']].map(intentDigest)).size).toBe(7);
  expect(codeOf(() => intentDigest({ '\ud800': 'x' }))).toBe('invalid_body');
  expect(codeOf(() => intentDigest({ value: '\ud800' }))).toBe('invalid_body');
});
