import { describe, it, expect } from 'vitest';
import { findContracts, compileContract } from './example-contracts-compile-helpers.js';

describe('Solidity examples: full 6-pass compilation', () => {
  const contracts = findContracts('sol', '.runar.sol');
  for (const { name, path } of contracts) {
    it(`compiles ${name}`, () => {
      const result = compileContract(path);
      expect(result.errors, 'compilation errors').toEqual([]);
      expect(result.success).toBe(true);
      expect(result.hasScript, 'should produce Bitcoin Script').toBe(true);
    });
  }
});
