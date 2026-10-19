import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex } from './tier-harness.js';

/**
 * N-346: a TS `expr as T` type assertion inside a method body (or in the
 * constructor's `super(...)` arguments) compiles in every tier.
 *
 * The TS reference parses an AsExpression as its operand and drops the type
 * (01-parse.ts, `case SyntaxKind.AsExpression`). The Zig .runar.ts parser had
 * no `as` rule: it read `'aa' as ByteString` as the expression `'aa'` and then
 * choked on the identifier `as` ("Undefined variable 'as'"), while the other
 * six tiers accepted it.
 *
 * What this proves: for each assertion shape (literal, identifier, parenthesised
 * arithmetic, chained, call result, inside assert, inside a call argument,
 * inside super()) every available tier compiles the `as` contract to exactly
 * the bytes the TS tier compiles the same contract with the assertion removed,
 * so the assertion is erased and does not change the AST.
 * What it does NOT prove: execution of those bytes, `as number` (go/python/ruby/java/zig refuse it, TS accepts: open
 * divergence), `as const` (rust refuses it), or the non-.runar.ts surfaces.
 */

const contract = (name: string, body: string, superArg: string) => `import { SmartContract, assert, checkSig, sha256 } from 'runar-lang';
import type { ByteString, PubKey, Sig, Sha256 } from 'runar-lang';

class ${name} extends SmartContract {
  readonly h: ByteString;
  readonly p: PubKey;

  constructor(h: ByteString, p: PubKey) {
    super(${superArg}, p);
    this.h = h;
    this.p = p;
  }

  public unlock(x: bigint, sig: Sig) {
    ${body}
  }
}
`;

const CASES: Array<{ name: string; withAs: string; plain: string; superAs?: string }> = [
  { name: 'Literal', withAs: "assert(('aa' as ByteString) === this.h);", plain: "assert(('aa') === this.h);" },
  { name: 'LiteralLocal', withAs: "const k = 'aa' as ByteString; assert(k === this.h);", plain: "const k = 'aa'; assert(k === this.h);" },
  { name: 'Ident', withAs: 'const y = x as bigint; assert(y > 0n);', plain: 'const y = x; assert(y > 0n);' },
  { name: 'Paren', withAs: 'const y = (x + 1n) as bigint; assert(y > 0n);', plain: 'const y = (x + 1n); assert(y > 0n);' },
  { name: 'Chained', withAs: 'const y = x as bigint as bigint; assert(y > 0n);', plain: 'const y = x; assert(y > 0n);' },
  { name: 'CallResult', withAs: 'assert(sha256(this.h) as Sha256 === sha256(this.h));', plain: 'assert(sha256(this.h) === sha256(this.h));' },
  { name: 'InAssertBare', withAs: 'assert(x as bigint > 0n);', plain: 'assert(x > 0n);' },
  { name: 'CallArg', withAs: 'assert(checkSig(sig, this.p as PubKey));', plain: 'assert(checkSig(sig, this.p));' },
  { name: 'SuperArg', withAs: 'assert(x > 0n);', plain: 'assert(x > 0n);', superAs: 'h as ByteString' },
];

const DIR = mkdtempSync(join(tmpdir(), 'n346-ts-as-'));
const tiers = buildSourceTiers().filter((t) => t.cmd !== null);
const ts = tiers.find((t) => t.id === 'ts');

describe('N-346: `as` type assertions are erased in every .runar.ts frontend', () => {
  it('the TS reference tier and at least one peer are available (else the comparison is vacuous)', () => {
    expect(ts).toBeDefined();
    expect(tiers.length).toBeGreaterThanOrEqual(2);
  });

  for (const c of CASES) {
    const asFile = join(DIR, `${c.name}As.runar.ts`);
    const plainFile = join(DIR, `${c.name}Plain.runar.ts`);
    writeFileSync(asFile, contract(`${c.name}As`, c.withAs, c.superAs ?? 'h'));
    writeFileSync(plainFile, contract(`${c.name}Plain`, c.plain, 'h'));
    for (const tier of tiers) {
      it(`${tier.id} compiles the ${c.name} assertion to the bytes of the assertion-free contract`, () => {
        const want = compileHex(ts!, plainFile);
        expect(compileHex(tier, asFile)).toBe(want);
      }, tier.timeoutMs);
    }
  }
});
