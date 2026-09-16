/**
 * W4 / PhantomLap — a for-loop ran one more time than its source says.
 *
 * `validateForStatement` carried the comment "The condition should compare the
 * iter var to a constant" and then read only `stmt.condition.right`. Nothing
 * anywhere required `condition.left` to BE the iterator, and
 * `extractLoopShape` computes `count = bound - start` from `right` alone. So
 *
 *     for (let i = 0n; i + 1n < 2n; i++)
 *
 * is one iteration in TypeScript (i=0: 0+1 < 2 true; i=1: 1+1 < 2 false) and
 * TWO in the emitted Script (count = 2 - 0). The extra lap is the `else` arm
 * the source can never reach, and in the vault below that arm sets
 * `authorized = true` with no signature at all: an EMPTY signature spends.
 *
 * Measured before the fix, on `@bsv/sdk` `Spend.validate()` — not the ANF
 * interpreter, which agrees with the compiler's own (wrong) unroll model:
 *
 *     phantom lap  `i + 1n < 2n`, empty signature  ->  validate() === true
 *     control      `i < 1n`,      empty signature  ->  validate() === false
 *
 * Two loops with identical source semantics, opposite on-chain outcomes.
 *
 * The fix refuses the syntax in `02-validate.ts` (and its six peers) rather
 * than teaching the unroll to evaluate a general condition, which would be a
 * language extension. The loop model is `start + k*step` tested against a
 * constant, so the condition must test the iterator itself.
 */
import { describe, it, expect } from 'vitest';
import { PrivateKey } from '@bsv/sdk';
import { compile, parse, lowerToANF } from 'runar-compiler';
import { ScriptExecutionContract } from '../script-execution.js';

/** A vault whose only signature check sits in the loop's first lap. */
function vault(loopHeader: string): string {
  return `
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

export class StrideVault extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public spend(sig: Sig): void {
    let authorized: boolean = false;
    ${loopHeader} {
      if (i === 0n) {
        authorized = checkSig(sig, this.owner);
      } else {
        authorized = true;
      }
    }
    assert(authorized);
  }
}
`;
}

function errorsOf(source: string): string[] {
  const r = compile(source, { fileName: 'StrideVault.runar.ts' });
  return r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
}

const owner = PrivateKey.fromRandom();
const ownerPub = ScriptExecutionContract.pubKeyHex(owner);

describe('W4 — for-loop condition must test the iterator', () => {
  it('control: `i < 1n` compiles, and an empty signature does NOT spend it', () => {
    const c = ScriptExecutionContract.fromSource(
      vault('for (let i: bigint = 0n; i < 1n; i++)'),
      { owner: ownerPub },
      'StrideVault.runar.ts',
    );
    // The acceptance oracle is @bsv/sdk Spend.validate(), reached through
    // ScriptExecutionContract.execute -> executeScripts.
    const r = c.execute('spend', ['']);
    expect(r.success).toBe(false);
  });

  it('control: `i < 1n` with a real signature still spends', () => {
    const c = ScriptExecutionContract.fromSource(
      vault('for (let i: bigint = 0n; i < 1n; i++)'),
      { owner: ownerPub },
      'StrideVault.runar.ts',
    );
    const r = c.executeSigned('spend', [''], 0, owner);
    expect(r.success).toBe(true);
  });

  it('PoC: `i + 1n < 2n` — a computed left-hand side — does not compile', () => {
    // Before the fix this compiled and `execute('spend', [''])` returned
    // success === true: the phantom second lap authorised the spend.
    const errs = errorsOf(vault('for (let i: bigint = 0n; i + 1n < 2n; i++)'));
    expect(errs.join('\n')).toMatch(/must compare the loop variable/i);
  });

  it('rejects a condition that multiplies the iterator (`i * 2n < 4n`)', () => {
    const errs = errorsOf(vault('for (let i: bigint = 0n; i * 2n < 4n; i++)'));
    expect(errs.join('\n')).toMatch(/must compare the loop variable/i);
  });

  it('rejects a condition testing an identifier that is not the iterator', () => {
    const src = `
import { SmartContract, assert } from 'runar-lang';

export class Stray extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public verify(j: bigint): void {
    let sum: bigint = 0n;
    for (let i: bigint = 0n; j < 3n; i++) {
      sum = sum + i;
    }
    assert(sum === 3n);
  }
}
`;
    const r = compile(src, { fileName: 'Stray.runar.ts' });
    const errs = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
    expect(errs.join('\n')).toMatch(/must compare the loop variable/i);
  });

  // The direction rule is NOT duplicated in validate: `extractLoopShape`
  // already refuses a mismatch, and these two record that it does so through
  // `compile()` rather than as an uncaught throw. Cross-tier agreement on the
  // same two programs is gated by
  // `conformance/negatives/N42-loop-direction-mismatch.runar.ts`.
  it('control: a counting-up update under a counting-down comparison is refused', () => {
    const errs = errorsOf(vault('for (let i: bigint = 0n; i > 1n; i++)'));
    expect(errs.join('\n')).toMatch(/counting up/i);
  });

  it('control: a counting-down update under a counting-up comparison is refused', () => {
    const errs = errorsOf(vault('for (let i: bigint = 3n; i < 1n; i--)'));
    expect(errs.join('\n')).toMatch(/counting down/i);
  });

  it('canonical loops still compile: countdown and non-zero start', () => {
    expect(errorsOf(vault('for (let i: bigint = 0n; i <= 0n; i++)'))).toEqual([]);
    expect(errorsOf(vault('for (let i: bigint = 0n; i > -1n; i--)'))).toEqual([]);
  });
});

/**
 * The `lowerToANF` backstop.
 *
 * The user-facing refusal lives in `02-validate.ts`, which is where a located
 * diagnostic belongs. But `lowerToANF` is a PUBLIC export of `runar-compiler`,
 * so `parse()` -> `lowerToANF()` reaches loop-shape extraction having run no
 * validator at all -- the R-012 shape, where a rule lives in exactly one pass
 * and another entry point walks past it. Rust's `extract_loop_shape` doc
 * comment already called itself "a hard guard for callers that skip
 * validation"; it simply had no left-hand-side half, which is the third
 * taxonomy shape: a comment asserting a property the code does not have.
 *
 * This test drives that exact path, so the backstop is not a guard nobody runs.
 */
describe('W4 — lowerToANF refuses the phantom lap without a validator', () => {
  const phantom = `
import { SmartContract, assert } from 'runar-lang';

export class Phantom extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public verify(x: bigint): void {
    let s: bigint = 0n;
    for (let i: bigint = 0n; i + 1n < 2n; i++) { s = s + i; }
    assert(x === s);
  }
}
`;

  it('parse() -> lowerToANF() throws rather than unrolling the extra lap', () => {
    const parsed = parse(phantom, 'Phantom.runar.ts');
    expect(parsed.contract).not.toBeNull();
    expect(() => lowerToANF(parsed.contract!)).toThrow(/must compare the loop variable/i);
  });

  it('control: the same path lowers a canonical loop without throwing', () => {
    const ok = phantom.replace('i + 1n < 2n', 'i < 1n');
    const parsed = parse(ok, 'Phantom.runar.ts');
    expect(() => lowerToANF(parsed.contract!)).not.toThrow();
  });
});
