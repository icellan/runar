import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex } from './tier-harness.js';

/**
 * F-222: seven-tier positive parity for an affine value consumed once in
 * each arm of an if/else.
 *
 * Every tier's affine checker walked the then and else arms against one
 * shared consumed set, so `checkSig(sig, ..)` once per arm was refused as a
 * double consumption, although no path consumes `sig` twice. Each arm is now
 * checked against the set as it stood before the if, and the two results are
 * unioned afterwards. The shapes where some path DOES consume twice are
 * refused by every tier through the N200-N209 fixtures that
 * rejection-parity.test.ts collects.
 *
 * What this proves: every available tier's CLI (fold-ON default) accepts the
 * three shapes below and compiles each to the pinned bytes, so a tier that
 * still refuses, or lowers the newly accepted shape differently, fails here.
 * packages/runar-testing/src/__tests__/f222-affine-if-else-arms-execution.test.ts
 * runs the same EitherKey and OneOfThree bytes through @bsv/sdk's Spend with
 * real signatures.
 * What it does NOT prove: fold-OFF output, the non-TS surfaces (the change is
 * in the typechecker, after every parser has produced the same AST), or the
 * ternary form `c ? checkSig(..) : checkSig(..)`, which is an expression
 * rather than an if statement and is still refused by all seven tiers.
 */

const SOURCES: Record<string, { source: string; hex: string }> = {
  'EitherKey (one consumption per arm)': {
    source: `import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class EitherKey extends SmartContract {
  readonly pkA: PubKey;
  readonly pkB: PubKey;

  constructor(pkA: PubKey, pkB: PubKey) {
    super(pkA, pkB);
    this.pkA = pkA;
    this.pkB = pkB;
  }

  public unlock(sig: Sig, useA: boolean) {
    if (useA) {
      assert(checkSig(sig, this.pkA));
    } else {
      assert(checkSig(sig, this.pkB));
    }
  }
}
`,
    hex: '767600877c51879b696300ac6700ac68',
  },
  'OneOfThree (nested if/else, one consumption per arm)': {
    source: `import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class OneOfThree extends SmartContract {
  readonly pkA: PubKey;
  readonly pkB: PubKey;
  readonly pkC: PubKey;

  constructor(pkA: PubKey, pkB: PubKey, pkC: PubKey) {
    super(pkA, pkB, pkC);
    this.pkA = pkA;
    this.pkB = pkB;
    this.pkC = pkC;
  }

  public unlock(sig: Sig, useA: boolean, useB: boolean) {
    if (useA) {
      assert(checkSig(sig, this.pkA));
    } else {
      if (useB) {
        assert(checkSig(sig, this.pkB));
      } else {
        assert(checkSig(sig, this.pkC));
      }
    }
  }
}
`,
    hex: '787600877c51879b69767600877c51879b697c637c00ac77676300ac6700ac6868',
  },
  'AliasArm (an alias consumed in one arm, the original in the other)': {
    source: `import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class AliasArm extends SmartContract {
  readonly pkA: PubKey;
  readonly pkB: PubKey;

  constructor(pkA: PubKey, pkB: PubKey) {
    super(pkA, pkB);
    this.pkA = pkA;
    this.pkB = pkB;
  }

  public unlock(sig: Sig, useA: boolean) {
    if (useA) {
      const s: Sig = sig;
      assert(checkSig(s, this.pkA));
    } else {
      assert(checkSig(sig, this.pkB));
    }
  }
}
`,
    hex: '767600877c51879b696300ac6700ac68',
  },
};

const DIR = mkdtempSync(join(tmpdir(), 'f222-affine-if-else-'));
const tiers = buildSourceTiers().filter((t) => t.cmd !== null);

describe('F-222: a Sig consumed once per if/else arm compiles identically in every tier', () => {
  it('the TS reference tier and at least one peer are available (else the comparison is vacuous)', () => {
    expect(tiers.find((t) => t.id === 'ts')).toBeDefined();
    expect(tiers.length).toBeGreaterThanOrEqual(2);
  });

  for (const [name, { source, hex }] of Object.entries(SOURCES)) {
    const file = join(DIR, `${name.split(' ')[0]}.runar.ts`);
    writeFileSync(file, source);
    for (const tier of tiers) {
      it(`${tier.id} accepts ${name} and emits the pinned script`, () => {
        expect(compileHex(tier, file)).toBe(hex);
      }, tier.timeoutMs);
    }
  }
});
