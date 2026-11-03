import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex } from './tier-harness.js';

/**
 * N-049 — the controls behind negative N174 (output intrinsic in a ternary arm).
 *
 * N174 makes every tier refuse `c ? this.addRawOutput(...) : this.addRawOutput(...)`.
 * The rule must not reach the two ways of writing a conditional payout that
 * lower correctly: a ternary that only selects the VALUE handed to a single
 * output intrinsic, and the if/else statement form (whose lowering merges each
 * arm's output refs into the parent). Every available tier must compile both,
 * byte-identically to the TypeScript reference.
 *
 * What this proves: the N-049 refusal is scoped to output intrinsics inside an
 * arm in all seven tiers; both controls still compile and agree across tiers.
 * What it does not prove: on-chain behaviour of the controls (the if/else form
 * is spent on @bsv/sdk's Spend in packages/runar-testing's n049 test).
 */

const HEAD = `import { StatefulSmartContract, ByteString } from 'runar-lang';

class ConditionalPayout extends StatefulSmartContract {
  count: bigint;
  readonly payee: ByteString;
  readonly refund: ByteString;

  constructor(count: bigint, payee: ByteString, refund: ByteString) {
    super(count, payee, refund);
    this.count = count;
    this.payee = payee;
    this.refund = refund;
  }

  public release() {
    this.addOutput(1000n, this.count);
`;

const CONTROLS: Record<string, string> = {
  'value-selecting ternary': `${HEAD}    this.addRawOutput(50000n, this.count > 0n ? this.payee : this.refund);
  }
}
`,
  'if/else statement': `${HEAD}    if (this.count > 0n) {
      this.addRawOutput(50000n, this.payee);
    } else {
      this.addRawOutput(50000n, this.refund);
    }
  }
}
`,
};

const DIR = mkdtempSync(join(tmpdir(), 'n049-ternary-output-'));
const tiers = buildSourceTiers().filter((t) => t.cmd !== null);
const ts = tiers.find((t) => t.id === 'ts');

describe('N-049 controls: conditional payouts that lower correctly stay accepted', () => {
  it('the TS reference tier is available (else the comparison is vacuous)', () => {
    expect(ts).toBeDefined();
    expect(tiers.length).toBeGreaterThanOrEqual(2);
  });

  for (const [name, source] of Object.entries(CONTROLS)) {
    const file = join(DIR, `${name.replace(/[^a-z]+/g, '-')}.runar.ts`);
    writeFileSync(file, source);
    let want: string | undefined;
    const reference = (): string => (want ??= compileHex(ts!, file));
    for (const tier of tiers) {
      if (tier.id === 'ts') continue;
      it(`${tier.id} compiles the ${name} control byte-identically to ts`, () => {
        expect(reference().length).toBeGreaterThan(0);
        expect(compileHex(tier, file)).toBe(reference());
      }, tier.timeoutMs);
    }
  }
});
