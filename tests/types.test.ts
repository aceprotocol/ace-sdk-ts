import { describe, it, expect } from 'vitest';
import { isEconomicType, isSystemType, isSocialType } from '../src/types.js';

describe('Type Guards', () => {
  it('identifies economic message types', () => {
    expect(isEconomicType('rfq')).toBe(true);
    expect(isEconomicType('offer')).toBe(true);
    expect(isEconomicType('confirm')).toBe(true);
    expect(isEconomicType('info')).toBe(false);
    expect(isEconomicType('text')).toBe(false);
  });

  it('identifies system message types', () => {
    expect(isSystemType('info')).toBe(true);
    expect(isSystemType('rfq')).toBe(false);
  });

  it('identifies social message types', () => {
    expect(isSocialType('text')).toBe(true);
    expect(isSocialType('info')).toBe(false);
  });
});
