/**
 * DCE must not delete a `bin_op` that can abort the script.
 *
 * Found by the nightly source-vs-script execution fuzzer (seed 1351961626,
 * FuzzContract94.method2): `let m = 41n & p; m = …;` compiled fold-ON to a
 * script that accepted every `p`, while the interpreter (and the fold-OFF
 * script) reject any `p` that does not encode to one byte — OP_AND requires
 * equal-length operands.
 *
 * `hasSideEffect` listed `bin_op` as pure. Purity is not totality
 * (spec/semantics.md §3.7): `& | ^` abort on unequal operand lengths,
 * `<< >>` on a negative count, `/ %` on a zero divisor. A binding the source
 * evaluates is therefore not removable just because nothing reads it.
 *
 * What these tests prove: the predicate keeps exactly those seven operators
 * (and still frees the total ones), the fold-ON N-138 prune and the EC-armed
 * DCE sweep both keep an orphaned/unread partial op through the real
 * `compile()` pipeline.
 *
 * What they do NOT prove: that the emitted script aborts on the bad input —
 * `conformance/dce/fold-orphan-partial.test.ts` executes it on ScriptVM in all
 * seven tiers.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { hasSideEffect } from '../optimizer/dce.js';
import type { ANFValue, ANFBinding } from '../ir/index.js';

const PARTIAL = ['/', '%', '&', '|', '^', '<<', '>>'] as const;
const TOTAL = ['+', '-', '*', '===', '!==', '<', '<=', '>', '>='] as const;

function binOp(op: string): ANFValue {
  return { kind: 'bin_op', op, left: 'a', right: 'b' } as ANFValue;
}

function flatten(bs: ANFBinding[]): ANFBinding[] {
  return bs.flatMap((b) =>
    b.value.kind === 'if'
      ? [b, ...flatten(b.value.then), ...flatten(b.value.else)]
      : b.value.kind === 'loop'
        ? [b, ...flatten(b.value.body)]
        : [b],
  );
}

function binOps(source: string, method: string, disableConstantFolding: boolean): string[] {
  const r = compile(source, { fileName: 'T.runar.ts', disableConstantFolding });
  expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
  const m = r.anf!.methods.find((x) => x.name === method)!;
  return flatten(m.body)
    .map((b) => b.value)
    .filter((v): v is Extract<ANFValue, { kind: 'bin_op' }> => v.kind === 'bin_op')
    .map((v) => v.op);
}

describe('DCE keeps partial bin_ops', () => {
  for (const op of PARTIAL) {
    it(`treats bin_op '${op}' as effectful (it can abort)`, () => {
      expect(hasSideEffect(binOp(op))).toBe(true);
    });
  }
  for (const op of TOTAL) {
    it(`still treats bin_op '${op}' as removable`, () => {
      expect(hasSideEffect(binOp(op))).toBe(false);
    });
  }

  it('fold-ON prune keeps an orphaned `41n & p` (the fuzzer finding)', () => {
    const src = `import { SmartContract, assert } from 'runar-lang';
class T extends SmartContract {
  constructor() { super(); }
  public unlock(p: bigint): void {
    let m: bigint = 41n & p;
    m = 5n;
    assert(m === 5n);
  }
}`;
    expect(binOps(src, 'unlock', true)).toContain('&');
    expect(binOps(src, 'unlock', false)).toContain('&');
  });

  it('EC-armed DCE sweep keeps a never-read `100n / p` in both fold modes', () => {
    const src = `import { SmartContract, assert, ByteString, ecMulGen } from 'runar-lang';
class T extends SmartContract {
  readonly tag: ByteString;
  constructor(tag: ByteString) { super(tag); this.tag = tag; }
  public unlock(p: bigint): void {
    const q: bigint = 100n / p;
    const g: ByteString = ecMulGen(1n);
    assert(g !== this.tag);
  }
}`;
    expect(binOps(src, 'unlock', true)).toContain('/');
    expect(binOps(src, 'unlock', false)).toContain('/');
  });
});
