import { describe, it, expect } from 'vitest';
import { compile, parse, lowerToANF } from '../index.js';

/**
 * N-049 (EXT-2 "TernaryToll") — an output intrinsic inside a ternary arm is
 * lowered but never reaches the method's output list.
 *
 * `lowerTernaryExpr` lowers each arm into `ctx.subContext()`, which starts with
 * a fresh empty `_addOutputRefs`, and nothing propagates that list back to the
 * method context — unlike `lowerIfStatement`, which concatenates each arm's
 * outputs into one ref so the parent sees them. Measured before this fix on
 *
 *     this.addOutput(1000n, this.count);
 *     this.count > 0n ? this.addRawOutput(50000n, this.payee)
 *                     : this.addRawOutput(50000n, this.refund);
 *
 * every tier compiled a continuation hash over the state output and the change
 * only: a spend that DROPS the payee output was accepted, and the honest
 * three-output spend was rejected. Without the top-level `addOutput` the method
 * failed with the internal "_newAmount is not on the stack" invariant error.
 *
 * Fail-closed (same shape as R-127's loop refusal): the validator refuses an
 * output intrinsic — direct, or reached through a private helper that is
 * inlined into the arm — in either arm of a ternary, and pass 4 refuses it
 * again for the public `lowerToANF` path that skips validation. The diagnostic
 * text is shared verbatim with the other six tiers. The if/else statement form
 * and a ternary that only selects VALUES stay accepted.
 *
 * What this proves: the TS reference refuses every ternary-arm output shape
 * below with the shared diagnostic, at both pass 2 and pass 4, and still
 * compiles the value-selecting and if/else controls.
 * What it does not prove: anything about emitted bytes or the other tiers (the
 * on-chain consequence is in runar-testing's n049 test; cross-tier refusal is
 * the conformance negative N174).
 */

const HEAD = `import { StatefulSmartContract, ByteString } from 'runar-lang';

export class ConditionalPayout extends StatefulSmartContract {
  count: bigint;
  readonly payee: ByteString;
  readonly refund: ByteString;

  constructor(count: bigint, payee: ByteString, refund: ByteString) {
    super(count, payee, refund);
    this.count = count;
    this.payee = payee;
    this.refund = refund;
  }
`;

const contract = (body: string) => `${HEAD}${body}\n}\n`;

const REFUSAL = 'cannot be called inside a conditional (ternary) expression arm';

function compileResult(source: string) {
  return compile(source, { fileName: 'ConditionalPayout.runar.ts', disableConstantFolding: true });
}

function errors(source: string): string {
  const r = compileResult(source);
  return r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message).join('\n');
}

describe('N-049 output intrinsics inside a ternary arm', () => {
  it('refuses the TernaryToll shape with a located shared diagnostic', () => {
    const r = compileResult(contract(`
  public release() {
    this.addOutput(1000n, this.count);
    this.count > 0n ? this.addRawOutput(50000n, this.payee)
                    : this.addRawOutput(50000n, this.refund);
  }`));
    expect(r.success).toBe(false);
    const d = r.diagnostics.find((x) => x.message.includes(REFUSAL));
    expect(d, r.diagnostics.map((x) => x.message).join('\n')).toBeDefined();
    expect(d!.message).toContain("Output intrinsic 'addRawOutput' cannot be called inside a conditional (ternary) expression arm.");
    expect(d!.loc?.line).toBeGreaterThan(0);
  });

  it('refuses a ternary-only method instead of the _newAmount invariant error', () => {
    const msgs = errors(contract(`
  public release() {
    this.count > 0n ? this.addRawOutput(50000n, this.payee)
                    : this.addRawOutput(50000n, this.refund);
  }`));
    expect(msgs).toContain(REFUSAL);
    expect(msgs).not.toMatch(/_newAmount|not on the stack/);
  });

  it('refuses a ternary bound to a local (the void-typed variable shape)', () => {
    expect(errors(contract(`
  public release() {
    this.addOutput(1000n, this.count);
    const x = this.count > 0n ? this.addRawOutput(50000n, this.payee) : this.addRawOutput(1n, this.payee);
  }`))).toContain("Output intrinsic 'addRawOutput' cannot be called inside a conditional (ternary) expression arm.");
  });

  it('refuses addOutput and addDataOutput in an arm', () => {
    expect(errors(contract(`
  public release() {
    this.count > 0n ? this.addOutput(1000n, this.count + 1n) : this.addOutput(1000n, this.count);
  }`))).toContain("Output intrinsic 'addOutput' cannot be called inside a conditional (ternary) expression arm.");
    expect(errors(contract(`
  public release() {
    this.addOutput(1000n, this.count);
    this.count > 0n ? this.addDataOutput(0n, this.payee) : this.addDataOutput(0n, this.refund);
  }`))).toContain("Output intrinsic 'addDataOutput' cannot be called inside a conditional (ternary) expression arm.");
  });

  it('refuses an output reached through a private helper called in an arm', () => {
    expect(errors(contract(`
  public release() {
    this.addOutput(1000n, this.count);
    this.count > 0n ? this.payTo(this.payee) : this.payTo(this.refund);
  }

  private payTo(script: ByteString): void {
    this.addRawOutput(50000n, script);
  }`))).toContain(
      "Output intrinsic 'addRawOutput' (reached through private method 'payTo') cannot be called inside a conditional (ternary) expression arm.",
    );
  });

  it('control: a ternary that only selects VALUES for one addRawOutput still compiles', () => {
    const r = compileResult(contract(`
  public release() {
    this.addOutput(1000n, this.count);
    this.addRawOutput(50000n, this.count > 0n ? this.payee : this.refund);
  }`));
    expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
    expect(r.success).toBe(true);
  });

  it('control: the if/else statement form still compiles', () => {
    const r = compileResult(contract(`
  public release() {
    this.addOutput(1000n, this.count);
    if (this.count > 0n) {
      this.addRawOutput(50000n, this.payee);
    } else {
      this.addRawOutput(50000n, this.refund);
    }
  }`));
    expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
    expect(r.success).toBe(true);
  });
});

/**
 * Pass-4 backstop: `parse` -> `lowerToANF` runs no validator, so
 * `lowerTernaryExpr` must refuse an arm that registered an output ref itself.
 */
describe('N-049 lowering backstop: lowerToANF without validation', () => {
  const lowerUnvalidated = (source: string): string | undefined => {
    const p = parse(source, 'ConditionalPayout.runar.ts');
    expect(p.errors).toEqual([]);
    try {
      lowerToANF(p.contract!);
      return undefined;
    } catch (e) {
      return e instanceof Error ? e.message : String(e);
    }
  };

  it('refuses addRawOutput in a ternary arm', () => {
    const refusal = lowerUnvalidated(contract(`
  public release() {
    this.addOutput(1000n, this.count);
    this.count > 0n ? this.addRawOutput(50000n, this.payee)
                    : this.addRawOutput(50000n, this.refund);
  }`));
    expect(refusal, 'lowerToANF accepted an output intrinsic inside a ternary arm').toBeDefined();
    expect(refusal).toContain("Output intrinsic 'addRawOutput' cannot be called inside a conditional (ternary) expression arm.");
  });

  it('control: a value-selecting ternary still lowers', () => {
    expect(lowerUnvalidated(contract(`
  public release() {
    this.addOutput(1000n, this.count);
    this.addRawOutput(50000n, this.count > 0n ? this.payee : this.refund);
  }`))).toBeUndefined();
  });
});
