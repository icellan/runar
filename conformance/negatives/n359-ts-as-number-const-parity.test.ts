import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, judge } from './tier-harness.js';

/**
 * N-359: on `.runar.ts`, `x as number` is REFUSED and `5n as const` is ACCEPTED,
 * identically in every tier (user decision R126, "refuse in all 7").
 *
 * Before the fix the seven tiers split on both shapes. The TS reference and the
 * Rust tier parsed a type assertion as its operand and never looked at the
 * asserted type, so `x as number` compiled there while go, python, ruby, java
 * and zig refused it ("'number' type is not allowed in Rúnar contracts; use
 * 'bigint' instead"). Conversely Rust refused the const assertion `5n as const`
 * ("Unsupported expression: TsConstAssertion") while the other six accepted it.
 * `number` is not a Rúnar type anywhere else on the surface (a `x: number`
 * declaration is refused by all seven), so letting an assertion smuggle it past
 * the check was the divergence, not the refusal.
 *
 * What this proves: every available tier's one-shot CLI refuses each `as number`
 * shape (assertion on an identifier, bare inside assert(), and chained through
 * `as bigint`) with a diagnostic naming `number` (grading is discrimination, not prose: go words it "invalid TypeScript integer literal 'number'", the other six "'number' type is not allowed in Rúnar contracts"), and
 * compiles `5n as const` to exactly the bytes of the same contract written with
 * a plain `5n`, so the const assertion is erased and does not change the AST.
 * The accepted control `x as bigint` keeps compiling (N-346 covers the wider
 * accepted matrix).
 * What it does NOT prove: execution of the accepted bytes, the non-.runar.ts
 * surfaces (they have no TS `as` syntax), or any asserted type beyond
 * number / const / bigint (see the probe matrix in the N-359 log).
 */

const contract = (name: string, body: string) => `import { SmartContract, assert } from 'runar-lang';

class ${name} extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public unlock(x: bigint) {
    ${body}
  }
}
`;

const DIR = mkdtempSync(join(tmpdir(), 'n359-ts-as-number-'));
const tiers = buildSourceTiers().filter((t) => t.cmd !== null);
const ts = tiers.find((t) => t.id === 'ts');

const NUMBER_RE = /number/;

const REFUSED: Array<{ name: string; body: string }> = [
  { name: 'AsNumber', body: 'const y = x as number; assert(y > 0n);' },
  { name: 'AsNumberBare', body: 'assert(x as number > 0n);' },
  { name: 'AsNumberChained', body: 'const y = x as number as bigint; assert(y > 0n);' },
];

const ACCEPTED: Array<{ name: string; withAs: string; plain: string }> = [
  { name: 'AsConstLiteral', withAs: 'const y = 5n as const; assert(x > y);', plain: 'const y = 5n; assert(x > y);' },
  { name: 'AsConstInAssert', withAs: 'assert(x > (5n as const));', plain: 'assert(x > 5n);' },
];

describe('N-359: `as number` is refused and `as const` is accepted in every .runar.ts frontend', () => {
  it('the TS reference tier and at least one peer are available (else the comparison is vacuous)', () => {
    expect(ts).toBeDefined();
    expect(tiers.length).toBeGreaterThanOrEqual(2);
  });

  const control = join(DIR, 'ControlAsBigint.runar.ts');
  writeFileSync(control, contract('ControlAsBigint', 'const y = x as bigint; assert(y > 0n);'));
  for (const tier of tiers) {
    it(`${tier.id} still accepts the \`as bigint\` control (a refusal below is the asserted type, not the assertion)`, () => {
      expect(judge(tier, control).verdict).toBe('accepted');
    }, tier.timeoutMs);
  }

  for (const c of REFUSED) {
    const file = join(DIR, `${c.name}.runar.ts`);
    writeFileSync(file, contract(c.name, c.body));
    for (const tier of tiers) {
      it(`${tier.id} refuses ${c.name} with a diagnostic naming number`, () => {
        const r = judge(tier, file);
        expect(r.verdict).toBe('rejected');
        expect(r.diag).toMatch(NUMBER_RE);
      }, tier.timeoutMs);
    }
  }

  for (const c of ACCEPTED) {
    const asFile = join(DIR, `${c.name}As.runar.ts`);
    const plainFile = join(DIR, `${c.name}Plain.runar.ts`);
    writeFileSync(asFile, contract(`${c.name}As`, c.withAs));
    writeFileSync(plainFile, contract(`${c.name}Plain`, c.plain));
    for (const tier of tiers) {
      it(`${tier.id} compiles ${c.name} to the bytes of the assertion-free contract`, () => {
        const want = compileHex(ts!, plainFile);
        expect(compileHex(tier, asFile)).toBe(want);
      }, tier.timeoutMs);
    }
  }
});
