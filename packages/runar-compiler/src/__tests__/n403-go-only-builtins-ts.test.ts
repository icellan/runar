import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/**
 * N-403 — follow-up to N-398. After N-398 the TS typechecker's GO_ONLY_BUILTINS
 * covered only the three BN254 pairing names, so verifySP1FRI,
 * merkleRootPoseidon2KB, assertGroth16WitnessAssisted,
 * assertGroth16WitnessAssistedWithMSM and groth16PublicInput still answered
 * "Unknown function" while Python (GO_ONLY_BUILTINS) and Rust
 * (go_only_builtin_family) name the Go-tier policy.
 *
 * What this proves: a call to each of the five is refused by the TS typechecker
 * with the Go-only diagnostic carrying the family label Python and Rust use
 * (verifySP1FRI "SP1 FRI", merkleRootPoseidon2KB "Poseidon2 Merkle", the three
 * Groth16 names "BN254 + Groth16"), and not with "Unknown function"; a typo'd
 * name still gets "Unknown function".
 *
 * What it does not prove: that TS can lower any of them (it cannot, by
 * policy), argument-arity handling, or that runar-lang exports these names
 * (it does not today; builtin-arity.ts lists them and the typechecker does
 * not consult imports).
 */

const FAMILIES: Record<string, string> = {
  verifySP1FRI: 'SP1 FRI',
  merkleRootPoseidon2KB: 'Poseidon2 Merkle',
  assertGroth16WitnessAssisted: 'BN254 + Groth16',
  assertGroth16WitnessAssistedWithMSM: 'BN254 + Groth16',
  groth16PublicInput: 'BN254 + Groth16',
};

function contractCalling(func: string): string {
  return `
import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  constructor() { super(); }
  public check(x: bigint) {
    assert(${func}(x, x) !== undefined);
  }
}
`;
}

function messages(source: string): string[] {
  const r = compile(source, { fileName: 'Probe.runar.ts' } as never);
  expect(r.success).toBe(false);
  return r.diagnostics.filter(d => d.severity === 'error').map(d => d.message);
}

describe('N-403: the other five Go-only builtins get the Go-only diagnostic in the TS tier', () => {
  for (const [func, family] of Object.entries(FAMILIES)) {
    it(`${func} is refused as Go-only (${family}), not as unknown`, () => {
      const joined = messages(contractCalling(func)).join('\n');
      expect(joined).not.toMatch(/Unknown function/i);
      expect(joined).toContain(`builtin '${func}' belongs to the ${family} family`);
      expect(joined).toContain('scoped to the Go tier by project policy');
      expect(joined).toContain('CLAUDE.md');
      expect(joined).toContain('"compilers" allowlist');
    });
  }

  it('a misspelled builtin still gets the plain unknown-function diagnostic', () => {
    const joined = messages(contractCalling('verifySP1FR')).join('\n');
    expect(joined).toMatch(/Unknown function 'verifySP1FR'/);
    expect(joined).not.toContain('Go tier');
  });
});
