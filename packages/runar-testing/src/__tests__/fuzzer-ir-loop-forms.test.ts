/**
 * F-300 / CL-GAP-096: the IR-mode generator that feeds the `--ir` cross-tier
 * parity fuzzer hardcoded `op: '<'` and `step: 1` at both loop sites, so the
 * seven-tier gate had never compiled a countdown loop or a closed (`<=` / `>=`)
 * bound in any tier. (`arbLoopBounds` draws them, but it feeds the TS-only
 * tri-modal generator.)
 *
 * `arbGeneratedContractWideLoops` / `arbGeneratedStatefulContractWideLoops` are
 * the loop-form-widened variants the `--ir` fuzzer uses under its `ts` render
 * strategy. The default `arbGeneratedContract` stays in the cross-tier
 * renderable subset (see fuzzer-branch-shapes.test.ts), because the native
 * Go/Rust/Python/Zig/Ruby renderers have no surface form for the wide shapes.
 *
 * PROVES: across a fixed-seed sample, the generated `ForStmt` nodes include a
 * countdown and every one of the four comparison operators; every loop
 * terminates and runs 1..3 iterations (the pre-existing bound); the contracts
 * compile in both folding modes in the TS tier; the Java renderer can render
 * them.
 * DOES NOT PROVE: that the other six tiers agree on them. That is the job of
 * `conformance/fuzzer` `--ir`, which this generator now feeds. It also does not
 * cover |step| >= 2 (the IR type is `step: 1 | -1`).
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { compile } from 'runar-compiler';
import {
  IR_LOOP_SHAPES,
  arbGeneratedContractWideLoops,
  arbGeneratedStatefulContractWideLoops,
  arbGeneratedContractWithShape,
  renderTypeScript,
  renderJava,
  type GeneratedContract,
} from '../fuzzer/index.js';
import type { Stmt } from '../fuzzer/contract-ir.js';

const SEED = 424242;
type For = Extract<Stmt, { kind: 'for' }>;

function loopsOf(body: Stmt[], out: For[] = []): For[] {
  for (const s of body) {
    if (s.kind === 'for') {
      out.push(s);
      loopsOf(s.body, out);
    } else if (s.kind === 'if') {
      loopsOf(s.then, out);
      loopsOf(s.else_ ?? [], out);
    }
  }
  return out;
}

function allLoops(cs: GeneratedContract[]): For[] {
  return cs.flatMap((c) => c.methods.flatMap((m) => loopsOf(m.body)));
}

/** Iteration count of a loop as the surface semantics define it. */
function iterations(l: For): bigint {
  const n =
    l.step === 1
      ? l.op === '<'
        ? l.bound - l.start
        : l.op === '<='
          ? l.bound - l.start + 1n
          : -1n
      : l.op === '>'
        ? l.start - l.bound
        : l.op === '>='
          ? l.start - l.bound + 1n
          : -1n;
  return n;
}

const STATELESS = fc.sample(arbGeneratedContractWideLoops, { numRuns: 200, seed: SEED });
const STATEFUL = fc.sample(arbGeneratedStatefulContractWideLoops, { numRuns: 200, seed: SEED });

describe('IR generator: wide loop forms (F-300)', () => {
  for (const [label, sample] of [['stateless', STATELESS], ['stateful', STATEFUL]] as const) {
    it(`${label}: draws countdown loops and non-'<' bounds`, () => {
      const loops = allLoops(sample);
      expect(loops.length).toBeGreaterThan(0);
      expect(loops.some((l) => l.step === -1)).toBe(true);
      expect(loops.some((l) => l.op !== '<')).toBe(true);
      for (const op of ['<', '<=', '>', '>='] as const) {
        expect(loops.some((l) => l.op === op), `op ${op}`).toBe(true);
      }
    });

    it(`${label}: every loop is well-formed, terminates, and runs 1..3 iterations`, () => {
      for (const l of allLoops(sample)) {
        // Direction and comparison agree, so the loop cannot run forever.
        expect(l.step === 1 ? l.op === '<' || l.op === '<=' : l.op === '>' || l.op === '>=').toBe(true);
        const n = iterations(l);
        expect(n >= 1n && n <= 3n, `${l.op} step ${l.step} ${l.start}..${l.bound} runs ${n}`).toBe(true);
      }
    });
  }

  it('every pinned loop shape also draws wide forms', () => {
    const seen = new Set<string>();
    for (const shape of IR_LOOP_SHAPES) {
      const cs = fc.sample(arbGeneratedContractWithShape(undefined, shape, true), { numRuns: 40, seed: SEED });
      for (const l of allLoops(cs)) seen.add(`${l.op}/${l.step}`);
    }
    expect(seen.has('>/-1') || seen.has('>=/-1')).toBe(true);
    expect(seen.has('<=/1')).toBe(true);
  });

  it('compiles in the TS tier in both folding modes', () => {
    for (const c of [...STATELESS.slice(0, 40), ...STATEFUL.slice(0, 40)]) {
      const source = renderTypeScript(c);
      for (const disableConstantFolding of [false, true]) {
        const r = compile(source, { fileName: `${c.name}.runar.ts`, disableConstantFolding });
        expect(
          r.success,
          `fold ${disableConstantFolding ? 'OFF' : 'ON'}: ${r.diagnostics.map((d) => d.message).join('; ')}\n${source}`,
        ).toBe(true);
      }
    }
  });

  it('the Java renderer (always used by --ir, whatever the strategy) renders them', () => {
    for (const c of STATELESS.slice(0, 60)) {
      const src = renderJava(c);
      for (const l of allLoops([c])) {
        const cmp = { '<': 'lt', '<=': 'le', '>': 'gt', '>=': 'ge' }[l.op];
        expect(src).toContain(`${l.iterVar}.${cmp}(`);
        expect(src).toContain(l.step === 1 ? `${l.iterVar}.plus(Bigint.ONE)` : `${l.iterVar}.minus(Bigint.ONE)`);
      }
    }
  });
});
