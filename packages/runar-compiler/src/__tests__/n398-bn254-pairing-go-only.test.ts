import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile } from '../index.js';

/**
 * N-398 — `runar-lang` exports bn254Pairing / bn254MultiPairing3 /
 * bn254MultiPairing4 (N-396) and `builtin-arity.ts` lists them, but the TS
 * typechecker answered "Unknown function", telling the author a real builtin
 * does not exist. The Python and Rust tiers name the policy instead
 * (`GO_ONLY_BUILTINS` / `go_only_builtin_family`, R-258/R-259, N-238): the
 * BN254 pairing family is scoped to the Go tier (CLAUDE.md, "EVM/STARK
 * proof-system primitives"). This holds the TS tier to the same sentence.
 *
 * What this proves: for each of the three names, calls with the documented
 * arity AND with a wrong arity are refused by the TS typechecker with the
 * Go-only diagnostic (family "BN254 pairing", CLAUDE.md pointer, source.json
 * "compilers" allowlist advice) and NOT with "Unknown function"; the
 * conformance fixture bn254-pairing still fails to compile in TS (it stays
 * EXPECTED_NOT_TS_COMPILABLE), and a typo'd builtin name still gets
 * "Unknown function".
 *
 * What it does not prove: that TS can lower the pairing (it cannot, by
 * policy), nor that the other Go-only builtins (verifySP1FRI,
 * merkleRootPoseidon2KB, the Groth16 entries) are treated the same — they are
 * out of scope for N-398.
 */

const POINT_PARAMS = 'p: Point';
const ARITY: Record<string, number> = {
  bn254Pairing: 5,
  bn254MultiPairing3: 27,
  bn254MultiPairing4: 20,
};

function contractCalling(func: string, argCount: number): string {
  const args = Array.from({ length: argCount }, () => 'x').join(', ');
  return `
import { SmartContract, assert } from 'runar-lang';
import type { Point } from 'runar-lang';

class Probe extends SmartContract {
  constructor() { super(); }
  public check(${POINT_PARAMS}, x: bigint) {
    assert(${func}(${args}) !== undefined);
  }
}
`;
}

function messages(source: string): string[] {
  const r = compile(source, { fileName: 'Probe.runar.ts' } as never);
  expect(r.success).toBe(false);
  return r.diagnostics.filter(d => d.severity === 'error').map(d => d.message);
}

describe('N-398: BN254 pairing builtins get the Go-only diagnostic in the TS tier', () => {
  for (const [func, arity] of Object.entries(ARITY)) {
    for (const count of [arity, arity - 1]) {
      it(`${func}(${count} args) is refused as Go-only, not as unknown`, () => {
        const msgs = messages(contractCalling(func, count));
        const joined = msgs.join('\n');
        expect(joined).not.toMatch(/Unknown function/i);
        expect(joined).toContain(`builtin '${func}' belongs to the BN254 pairing family`);
        expect(joined).toContain('scoped to the Go tier by project policy');
        expect(joined).toContain('CLAUDE.md');
        expect(joined).toContain('"compilers" allowlist');
      });
    }
  }

  it('the bn254-pairing conformance fixture still does not compile in TS (stays Go-only)', () => {
    const src = readFileSync(
      join(__dirname, '../../../../conformance/tests/bn254-pairing/Bn254Pairing.runar.ts'),
      'utf8',
    );
    const joined = messages(src).join('\n');
    expect(joined).toContain("builtin 'bn254MultiPairing4' belongs to the BN254 pairing family");
  });

  it('a misspelled builtin still gets the plain unknown-function diagnostic', () => {
    const joined = messages(contractCalling('bn254Pairng', 5)).join('\n');
    expect(joined).toMatch(/Unknown function 'bn254Pairng'/);
    expect(joined).not.toContain('Go tier');
  });
});
