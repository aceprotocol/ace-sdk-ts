/** Cross-SDK operation identity. Numeric identity uses binary64, not JSON spelling. */
import { bytesToHex } from '@noble/hashes/utils.js';
import { compareUtf8, sha256Hex } from './encoding.js';
import { ACEError } from './errors.js';
import type { JSONValue } from './types.js';

export function intentDigest(value: JSONValue): string {
  function text(s: string): string {
    if (/[\uD800-\uDFFF]/u.test(s)) throw new ACEError('invalid_body', 'unpaired Unicode surrogate');
    return s;
  }
  function tree(v: JSONValue): unknown[] {
    if (v === null) return ['null'];
    if (typeof v === 'boolean') return ['boolean', String(v)];
    if (typeof v === 'string') return ['string', text(v)];
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw new ACEError('invalid_body', 'non-finite number');
      const bytes = new Uint8Array(8);
      new DataView(bytes.buffer).setFloat64(0, v === 0 ? 0 : v, false);
      return ['number', bytesToHex(bytes)];
    }
    if (Array.isArray(v)) return ['array', ...v.map(tree)];
    return ['object', ...Object.keys(v).sort(compareUtf8).map(k => [text(k), tree(v[k])])];
  }
  return sha256Hex('ace.intent.v1\0' + JSON.stringify(tree(value)));
}
