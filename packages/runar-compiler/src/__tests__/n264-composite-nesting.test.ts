import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { compile } from '../index.js';

/**
 * N-264 — call depth x nesting must not overflow the host stack.
 *
 * F-213 bounds a method's own nesting (MAX_SOURCE_NESTING = 128) and N-180
 * bounds the call graph (MAX_CALL_DEPTH = 128), but private methods are
 * inlined at every call site, so the two compose MULTIPLICATIVELY: a chain of
 * D helpers that each place their call under K nested ifs is D*K nested ifs
 * after inlining. Every pass that recursed once per nested `if` across an
 * inlined call (the side-effect summary in validate, stack lowering, the
 * peephole optimizer and emit over the nested Stack IR) overflowed — TS threw
 * "Maximum call stack size exceeded" at D=16 x 120. User decision R106: lower
 * iteratively, with an explicit work stack, so the admissible input compiles.
 *
 * The source is remediation-logs/N-180/compgen.py's shape. The pinned digests
 * are sha256(scriptHex) of the UNMODIFIED Go compiler's output (`runar-go
 * --source compD k120.runar.ts --hex` at 5b75534ec, before any N-264 change):
 * goroutine stacks grow, so Go compiled every depth before the fix, and its
 * D=8 output was byte-identical to all six other tiers'. That makes it an
 * independent oracle for the deep case no conformance fixture reaches.
 *
 * Proves: the TS tier compiles D=32 x 120 (3,840 nested ifs after inlining)
 * and the deepest admissible chain D=127 x 120, byte-identical to Go's output.
 * Does not prove: the other six tiers (conformance/negatives/
 * n264-composite-nesting-parity.test.ts drives all seven CLIs); that Go's
 * deep output is semantically right beyond agreeing with every tier at D=8.
 */

/** remediation-logs/N-180/compgen.py, verbatim. */
function comp(d: number, k: number): string {
  const body = (i: number) =>
    '  let r: bigint = x;\n'
    + Array.from({ length: k }, (_, j) => `  if (x > ${j}n) {\n`).join('')
    + `  r = this.m${i + 1}(x);\n` + '  }\n'.repeat(k)
    + '  return r;\n';
  const ms = Array.from({ length: d }, (_, i) => ` private m${i}(x: bigint): bigint {\n${body(i)} }\n`).join('');
  return "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n"
    + ms + ` private m${d}(x: bigint): bigint { return x; }\n public verify(a: bigint) { assert(this.m0(a) == this.t); }\n}\n`;
}

const GO_DIGEST: Record<number, string> = {
  // N-216 (2026-10-21): re-pinned to the post-fix Go output (D=32: 30586 -> 30525 B, D=127: 121406 -> 121155 B); the opcode diff vs the 5b75534ec pin is only the branch-reconcile `<k> OP_ROLL` -> OP_SWAP / OP_ROT folds.
  32: '84c53e49c0d144c35d8db922859dd52fd71590d0c2e6ebea5b82501593301ec8',
  127: 'ccec07fd320da3dfe9c4013365bc1d9afbd83efbf6256ee009df920d129fab13',
};

describe('N-264: composite call depth x nesting compiles without host-stack overflow', () => {
  for (const d of [32, 127]) {
    it(`compiles D=${d} x 120 byte-identically to Go`, () => {
      const r = compile(comp(d, 120), { fileName: `comp${d}k120.runar.ts` });
      const errs = r.diagnostics.filter((x) => x.severity === 'error').map((x) => x.message);
      expect(errs).toEqual([]);
      expect(r.success).toBe(true);
      const digest = createHash('sha256').update(r.scriptHex!).digest('hex');
      expect(digest).toBe(GO_DIGEST[d]);
    }, 120_000);
  }
});
