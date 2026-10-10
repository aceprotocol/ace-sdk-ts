import { describe, expect, it } from 'vitest';
import { EtcdStore } from '../src/node.js';

describe('replicated store configuration', () => {
  const base = { endpoint: 'https://state.example', clusterId: '1', namespace: 'authority' };
  it('refuses implicit trust, unsafe endpoints and credential ambiguity', () => {
    for (const endpoint of ['http://state.example', 'https://user:secret@state.example', 'https://state.example/path', 'https://state.example/?token=secret', 'https://state.example/#fragment']) {
      expect(() => new EtcdStore({ ...base, endpoint })).toThrow(/invalid_argument/);
    }
    for (const clusterId of ['', '0', '01', 'auto', '-1', '18446744073709551616', '1\n']) {
      expect(() => new EtcdStore({ ...base, clusterId })).toThrow(/invalid_argument/);
    }
    for (const namespace of ['', '../other', 'state\n', 'STATE']) expect(() => new EtcdStore({ ...base, namespace })).toThrow(/invalid_argument/);
    for (const token of ['', 'bad\nheader', 'secret\n', 'x'.repeat(4097)]) expect(() => new EtcdStore({ ...base, token })).toThrow(/invalid_argument/);
    for (const leaseSeconds of [0, 301, 1.5, NaN]) expect(() => new EtcdStore({ ...base, leaseSeconds })).toThrow(/invalid_argument/);
  });
});
