import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/**
 * R-127 / CL-BUG-171 — an output intrinsic inside a loop body is silently
 * dropped from the continuation hash. (R-126 / CL-BUG-164 is the OTHER
 * add_output truncation — under-arity args dropped at stack lowering — and is
 * a separate item.)
 *
 * `lowerForStatement` lowers the body into `ctx.subContext()`, which starts
 * with a fresh empty `_addOutputRefs`, and nothing propagates that list back to
 * the method context — unlike `lowerIfStatement`, which concatenates each
 * arm's outputs into one ref precisely so the parent sees them. The method
 * therefore builds its continuation from whatever `addOutput` calls sit at the
 * TOP level, while the loop's outputs are still emitted into the transaction.
 *
 * Measured on the reference tier before this fix, with a two-iteration loop:
 *
 *   loop-only       ts/go/rust/python REFUSE with an internal invariant error
 *                   ("method parameter '_newAmount' is not on the stack at a
 *                   post-consumption reference"), zig/ruby COMPILE a covenant
 *                   over the WRONG output set, java compiles with none.
 *
 *   loop + one top-level addOutput
 *                   compiles clean in every tier. The ANF continuation hashes
 *                   exactly ONE leaf -- the top-level `add_output` -- while
 *                   three outputs are built:
 *                     Three (hand-unrolled):  hashLeaves = t12, t17, t22, if
 *                     LoopTop (1 + loop x2):  hashLeaves = t12, if
 *                   An earlier probe counted `OP_8 OP_NUM2BIN` groups instead
 *                   and read 7 for both, concluding the shape was fine. Group
 *                   count measures output bytes BUILT, not bytes HASHED; the
 *                   cat-chain feeding hash256 is the thing that matters.
 *
 * CL-BUG-164 settles what a truncated continuation costs: the spend is
 * "spendable only by a hand-crafted transaction, unspendable through every
 * shipped SDK ... and the successor it produces is permanently unspendable."
 *
 * The fix is refusal, not lowering. Propagating the refs cannot work by name:
 * the loop is unrolled at stack-lowering, so one body binding name denotes N
 * physical slots and `findDepth` would resolve it to the last iteration only.
 * A correct lowering means unrolling at ANF time, which is a language feature
 * with no golden behind it -- while a refusal removes nothing that works
 * today. Same shape as R-065's for-update rejection, diagnostic text shared
 * verbatim with the other six tiers.
 */

const HEAD = `import { StatefulSmartContract, assert } from 'runar-lang';

export class Fan extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }
`;

const contract = (body: string) => `${HEAD}${body}\n}\n`;

function diagnostics(source: string): string[] {
  const r = compile(source, { fileName: 'Fan.runar.ts', disableConstantFolding: true });
  return r.success ? [] : r.diagnostics.map((d) => d.message);
}

function compileResult(source: string) {
  return compile(source, { fileName: 'Fan.runar.ts', disableConstantFolding: true });
}

describe('R-127 output intrinsics inside a loop body', () => {
  it('refuses addOutput in a loop body with a located diagnostic', () => {
    const src = contract(`
  public fan(n: bigint) {
    for (let i = 0n; i < 2n; i++) {
      this.addOutput(1000n, this.count + i);
    }
    assert(n > 0n);
  }`);
    const r = compileResult(src);
    expect(r.success).toBe(false);
    const msgs = r.diagnostics.map((d) => d.message);
    expect(msgs.join('\n')).toMatch(/addOutput/);
    expect(msgs.join('\n')).toMatch(/loop/i);
    // Not the internal stack-lowering invariant blow-up it used to be.
    expect(msgs.join('\n')).not.toMatch(/_newAmount|not on the stack/);
    // Located: a real source position, not the zero default.
    const d = r.diagnostics.find((x) => /addOutput/.test(x.message));
    expect(d?.loc?.line).toBeGreaterThan(0);
  });

  it('refuses the loop + top-level shape — the one that compiled a truncated covenant', () => {
    const src = contract(`
  public fan(n: bigint) {
    this.addOutput(1000n, this.count);
    for (let i = 0n; i < 2n; i++) {
      this.addOutput(1000n, this.count + i);
    }
    assert(n > 0n);
  }`);
    expect(diagnostics(src).join('\n')).toMatch(/addOutput/);
  });

  it('refuses addRawOutput and addDataOutput in a loop body too', () => {
    const raw = contract(`
  public fan(n: bigint) {
    for (let i = 0n; i < 2n; i++) {
      this.addRawOutput(1000n, this.scriptOf(i));
    }
    assert(n > 0n);
  }

  private scriptOf(i: bigint): ByteString {
    return num2bin(i, 4n);
  }`).replace("import { StatefulSmartContract, assert }", "import { StatefulSmartContract, assert, num2bin, ByteString }");
    expect(diagnostics(raw).join('\n')).toMatch(/addRawOutput/);

    const data = contract(`
  public fan(n: bigint) {
    for (let i = 0n; i < 2n; i++) {
      this.addDataOutput(num2bin(i, 4n));
    }
    this.count = this.count + 1n;
    assert(n > 0n);
  }`).replace("import { StatefulSmartContract, assert }", "import { StatefulSmartContract, assert, num2bin }");
    expect(diagnostics(data).join('\n')).toMatch(/addDataOutput/);
  });

  it('refuses an output nested inside an if inside a loop', () => {
    const src = contract(`
  public fan(n: bigint) {
    for (let i = 0n; i < 2n; i++) {
      if (i < n) {
        this.addOutput(1000n, this.count + i);
      }
    }
    assert(n > 0n);
  }`);
    expect(diagnostics(src).join('\n')).toMatch(/addOutput/);
  });

  it('refuses an output reached through a private helper called in a loop', () => {
    const src = contract(`
  public fan(n: bigint) {
    for (let i = 0n; i < 2n; i++) {
      this.emitOne(i);
    }
    assert(n > 0n);
  }

  private emitOne(i: bigint) {
    this.addOutput(1000n, this.count + i);
  }`);
    expect(diagnostics(src).join('\n')).toMatch(/addOutput|emitOne/);
  });

  it('still accepts addOutput AFTER a loop — the loop-if-merged-locals shape', () => {
    const src = contract(`
  public fan(x: bigint, limit: bigint) {
    let na: bigint = 0n;
    for (let i = 0n; i < 2n; i++) {
      if (i < limit) {
        na = na + x;
      }
    }
    this.addOutput(1000n, na);
  }`);
    const r = compileResult(src);
    expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
    expect(r.success).toBe(true);
  });

  it('still accepts a loop with no output intrinsic at all', () => {
    const src = contract(`
  public fan(n: bigint) {
    let acc: bigint = 0n;
    for (let i = 0n; i < 3n; i++) {
      acc = acc + i;
    }
    this.count = acc + n;
  }`);
    expect(compileResult(src).success).toBe(true);
  });
});
