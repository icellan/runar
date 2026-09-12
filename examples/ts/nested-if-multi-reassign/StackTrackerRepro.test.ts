import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, runDifferentialExecution } from 'runar-testing';
import { compile } from 'runar-compiler';

/**
 * R-106 — `nested-if-multi-reassign` had zero tests, zero conformance fixture,
 * and zero references anywhere in the repo. It is a REGRESSION REPRO for issue
 * #34, checked in without the test that would have made it one.
 *
 * The defect: the ANF parameter-type lookup searched EVERY method's parameters,
 * so the local `x: bigint` in `walk` picked up the `x: ByteString` parameter of
 * `other` — a different method entirely. `1n + x` then lowered to OP_CAT (0x7e,
 * byte concatenation) instead of OP_ADD (0x93), and the compiled script quietly
 * stopped agreeing with the interpreter.
 *
 * A repro with no assertions is a file, not a test. This pins the fix three
 * ways, cheapest first:
 *
 *   1. the ANF binds `1n + x` as a bigint `+`, not a concat — the exact node
 *      that regressed;
 *   2. the interpreter accepts a concrete spend;
 *   3. the interpreter and the @bsv/sdk ScriptVM agree on that spend — which is
 *      the property the miscompile broke, and the one a byte-parity gate cannot
 *      see, because all seven tiers would have miscompiled it identically.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'StackTrackerRepro.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

/** `buf` whose first byte is 0, so `x = 0` and the slice is 1 byte long. */
const BUF = new Uint8Array([0x00, 0xaa, 0xbb]);
const TARGET = new Uint8Array([0x00]);

describe('StackTrackerRepro (issue #34 — cross-method parameter shadowing)', () => {
  it('lowers `1n + x` as bigint addition, not byte concatenation', () => {
    const result = compile(source, { fileName: FILE });
    expect(result.success, result.diagnostics.map((d) => d.message).join('\n')).toBe(true);

    // No JSON round-trip: the ANF carries bigint literals, which JSON.stringify
    // refuses. Read the structure directly.
    const anf = result.anf!;
    const walk = anf.methods.find((m) => m.name === 'walk');
    expect(walk, 'the walk method must survive lowering').toBeDefined();

    // RECURSE. The `1n + x` that regressed sits INSIDE the `if`, and an `if`
    // keeps its bindings nested rather than flattened into the method body — a
    // top-level-only sweep sees exactly one `bin_op` here (the `0n < count`
    // condition) and would never look at the node this test exists for.
    type Binding = { name: string; value: Record<string, unknown> };
    const collect = (body: Binding[], out: Record<string, unknown>[] = []) => {
      for (const b of body) {
        const v = b.value;
        out.push(v);
        for (const key of ['body', 'then', 'else']) {
          const nested = (v as Record<string, unknown>)[key];
          if (Array.isArray(nested)) collect(nested as Binding[], out);
        }
      }
      return out;
    };
    const values = collect(walk!.body as unknown as Binding[]);
    const binOps = values.filter((v) => v.kind === 'bin_op') as {
      op: string; left: string; right: string; result_type?: string;
    }[];

    // Non-vacuity: the method really does contain the `+` this test classifies.
    expect(
      binOps.map((v) => v.op).sort(),
      'the arithmetic this test is about must be reachable from the walk',
    ).toContain('+');

    // `result_type` is the operand-type hint: "bytes" for the ByteString
    // family, omitted for numeric. The regression set it on the `1n + x`
    // addition, which is how OP_ADD became OP_CAT.
    const byteAdds = binOps
      .filter((v) => v.op === '+' && v.result_type === 'bytes')
      .map((v) => `${v.left} + ${v.right}`);
    expect(
      byteAdds,
      'a `+` typed as bytes in walk() is issue #34 exactly: a local shadowed by ' +
        "another method's parameter type",
    ).toEqual([]);
  });

  it('the interpreter accepts a concrete walk', () => {
    const c = TestContract.fromSource(source, {}, FILE);
    const r = c.call('walk', { buf: BUF, count: 1n, target: TARGET });
    expect(r.success, r.error).toBe(true);
  });

  it('the interpreter and the ScriptVM agree on that walk', () => {
    const r = runDifferentialExecution({
      source,
      fileName: FILE,
      method: 'walk',
      args: [BUF, 1n, TARGET],
    });
    expect(
      r.agrees,
      `source semantics and script semantics disagree — interpreter=${r.interpreterAccepted} ` +
        `vm=${r.vmAccepted} ${r.interpreterError ?? ''} ${r.vmError ?? ''}`,
    ).toBe(true);
  });
});
