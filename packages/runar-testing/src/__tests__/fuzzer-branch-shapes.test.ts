/**
 * REACHABILITY gate for the IR generator's BRANCH and LOOP shapes.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * `arbGeneratedContract` / `arbGeneratedStatefulContract` drive BOTH the 7-tier
 * `--ir` parity fuzzer and the `--execute` absolute oracle. Until 2026-08-06
 * their reachable space had two structural holes:
 *
 *   1. `arbIfStmtIR` built `then: [assert]` / `else_: [assert]` and nothing
 *      else, and `arbVarDeclStmtIR` hard-coded `mutable: false`. A branch arm
 *      that REASSIGNS anything — indeed a local reassignment ANYWHERE, branch
 *      or straight-line — was OUTSIDE the reachable space. The confirmed
 *      branch-merged-local miscompile (PALMER-1,
 *      `conformance/tests/branch-merged-locals/`) is exactly that shape, so no
 *      seed and no budget could have produced it.
 *   2. Neither method generator ever emitted a `ForStmt`, and the six non-TS
 *      renderers refused one outright, so the cross-tier parity fuzzer had
 *      never compiled a loop in ANY tier.
 *
 * A probability argument is not evidence here. Every assertion below is made on
 * the generated IR — the actual `Stmt` trees — with a FIXED seed, in the style
 * of `fuzzer-loop-shapes.test.ts`:
 *
 *   1. `arbGeneratedContractWithShape(shape)` pins the topology, so each shape
 *      is proved reachable directly rather than waited for.
 *   2. The composite generators are sampled at one fixed seed and every shape
 *      is shown to appear, with the sample index it first appears at.
 *   3. Shapes are re-derived from the IR, never from a label — there is no
 *      label on `GeneratedContract` to trust in the first place.
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { compile } from 'runar-compiler';
import {
  BRANCH_SHAPES,
  STATEFUL_BRANCH_SHAPES,
  IR_LOOP_SHAPES,
  branchShapeCarriers,
  irLoopShapeCarriers,
  arbGeneratedContract,
  arbGeneratedStatefulContract,
  arbGeneratedContractWithShape,
  arbGeneratedStatefulContractWithShape,
  renderTypeScript,
  RENDERERS,
  type BranchShape,
  type IrLoopShape,
  type GeneratedContract,
} from '../fuzzer/index.js';
import type { Stmt, Expr } from '../fuzzer/contract-ir.js';
import { runDifferentialExecution } from '../oracle/index.js';

const SEED = 424242;
const STATELESS = fc.sample(arbGeneratedContract, { numRuns: 120, seed: SEED });
const STATEFUL = fc.sample(arbGeneratedStatefulContract, { numRuns: 120, seed: SEED });

// ---------------------------------------------------------------------------
// IR helpers — these read the generated STATEMENTS, never a label
// ---------------------------------------------------------------------------

type Assign = Extract<Stmt, { kind: 'assign' }>;
type If = Extract<Stmt, { kind: 'if' }>;
type For = Extract<Stmt, { kind: 'for' }>;
type VarDecl = Extract<Stmt, { kind: 'var_decl' }>;

const isAssign = (s: Stmt): s is Assign => s.kind === 'assign';

function findIf(body: Stmt[]): If | null {
  for (const s of body) if (s.kind === 'if') return s;
  return null;
}

function findFor(body: Stmt[]): For | null {
  for (const s of body) if (s.kind === 'for') return s;
  return null;
}

/** Names assigned by an arm, in order, split by local vs property. */
function targets(arm: Stmt[] | undefined, isProperty: boolean): string[] {
  return (arm ?? []).filter(isAssign).filter((s) => s.isProperty === isProperty).map((s) => s.target);
}

/** Mutable locals declared at the top level of a method body, in order. */
function mutableDecls(body: Stmt[]): string[] {
  return body
    .filter((s): s is VarDecl => s.kind === 'var_decl' && s.mutable)
    .map((s) => s.name);
}

/** Every `var_ref` name inside an expression. */
function refs(expr: Expr, out: string[] = []): string[] {
  switch (expr.kind) {
    case 'var_ref':
      out.push(expr.name);
      break;
    case 'binary':
      refs(expr.left, out);
      refs(expr.right, out);
      break;
    case 'unary':
      refs(expr.operand, out);
      break;
    case 'ternary':
      refs(expr.condition, out);
      refs(expr.consequent, out);
      refs(expr.alternate, out);
      break;
    case 'call':
      expr.args.forEach((a) => refs(a, out));
      break;
  }
  return out;
}

/** Does any statement AFTER `idx` read `name`? */
function readAfter(body: Stmt[], idx: number, name: string): boolean {
  for (let i = idx + 1; i < body.length; i++) {
    const s = body[i]!;
    if (s.kind === 'assert' && refs(s.condition).includes(name)) return true;
    if (s.kind === 'assign' && refs(s.value).includes(name)) return true;
    if (s.kind === 'var_decl' && refs(s.value).includes(name)) return true;
  }
  return false;
}

/** Re-derive the branch topology from the IR. Null when the method has none. */
function classifyBranch(body: Stmt[]): BranchShape | null {
  const carriers = mutableDecls(body).filter((n) => n.startsWith('merge'));
  const branch = findIf(body);
  if (branch === null) {
    // No branch: only the straight-line rebind declares a `merge` carrier.
    if (carriers.length === 0) return null;
    return body.some((s) => isAssign(s) && !s.isProperty && s.target === carriers[0])
      ? 'straight-line-rebind'
      : null;
  }
  // The #149 shape, re-derived from the statements rather than from a label:
  // an outer `if` with NO else whose ONLY statement is an inner `if` that
  // rebinds the SAME single local in both arms — leaving the second declared
  // carrier live and untouched in the region inherited from the outer arm.
  const innerIf = branch.then.length === 1 && branch.then[0]!.kind === 'if' ? (branch.then[0] as If) : null;
  if (innerIf !== null && branch.else_ === undefined) {
    const it_ = [...new Set(targets(innerIf.then, false))];
    const ie = [...new Set(targets(innerIf.else_, false))];
    if (
      it_.length === 1 &&
      ie.length === 1 &&
      it_[0] === ie[0] &&
      carriers.length === 2 &&
      it_[0] === carriers[0] &&
      !targets(innerIf.then, false).includes(carriers[1]!) &&
      !targets(innerIf.else_, false).includes(carriers[1]!)
    ) {
      return 'nested-sibling-no-else';
    }
  }
  const thenLocals = targets(branch.then, false);
  const elseLocals = targets(branch.else_, false);
  const thenProps = targets(branch.then, true);
  if (thenLocals.length === 0 && elseLocals.length === 0 && thenProps.length === 0) {
    return 'assert-only';
  }
  if (thenProps.length > 0) return 'prop-write-in-arm';
  if (branch.else_ === undefined) return 'rebind-read-after';
  const uniq = (xs: string[]): string[] => [...new Set(xs)].sort();
  const t = uniq(thenLocals);
  const e = uniq(elseLocals);
  if (t.length === 1 && e.length === 1 && t[0] === e[0]) return 'both-arms-rebind-one';
  if (t.length === 1 && e.length === 1 && t[0] !== e[0]) return 'asymmetric-rebind';
  if (t.length === 2 && e.length === 0) return 'multi-rebind-one-arm';
  if (t.length === 2 && e.length === 2) return 'both-arms-rebind-both';
  return null;
}

/** Re-derive the loop topology from the IR. Null when the method has none. */
function classifyLoop(body: Stmt[]): IrLoopShape | null {
  const loop = findFor(body);
  if (loop === null) return null;
  const inner = findFor(loop.body);
  if (inner !== null) return 'nested-cross-read';
  const t = [...new Set(targets(loop.body, false))];
  if (t.length === 1) return 'single-carrier';
  if (t.length === 2) return 'k2-cross-read';
  return null;
}

function shapesIn(
  contracts: GeneratedContract[],
  classify: (body: Stmt[]) => BranchShape | IrLoopShape | null,
): Map<string, number> {
  const firstIndex = new Map<string, number>();
  contracts.forEach((c, i) => {
    for (const m of c.methods) {
      const s = classify(m.body);
      if (s !== null && !firstIndex.has(s)) firstIndex.set(s, i);
    }
  });
  return firstIndex;
}

// ---------------------------------------------------------------------------
// Reachability
// ---------------------------------------------------------------------------

describe('IR generator branch shapes: reachability', () => {
  it('the stateless generator reaches EVERY branch shape at a fixed seed', () => {
    const firstIndex = shapesIn(STATELESS, classifyBranch);
    const missing = BRANCH_SHAPES.filter((s) => !firstIndex.has(s));
    expect(
      missing,
      `seed ${SEED} / 120 samples reached: ${JSON.stringify(Object.fromEntries(firstIndex))}`,
    ).toEqual([]);
    // Fixed seed => fixed first-hit indices. Recorded so a change to the draw
    // order shows up in the diff rather than silently shifting the corpus.
    // Re-measured 2026-09-16 when the R-169 `pow` arm was added to
    // `arbBigintExprIR`: a new arm in the oneof shifts the draw, so every
    // first-hit index moves even though the reachable SET is unchanged (the
    // `missing` assertion above is what pins reachability, and it stayed
    // empty). This map is the change detector working as designed.
    expect(Object.fromEntries(firstIndex)).toEqual({
      'rebind-read-after': 1,
      'both-arms-rebind-both': 3,
      'assert-only': 4,
      'straight-line-rebind': 6,
      'multi-rebind-one-arm': 10,
      'nested-sibling-no-else': 12,
      'both-arms-rebind-one': 13,
      'asymmetric-rebind': 14,
    });
    // The stateless contract has only readonly properties, so no arm can
    // contain a property write there — that shape is stateful-only.
    expect(firstIndex.has('prop-write-in-arm')).toBe(false);
  });

  it('the stateful generator reaches EVERY branch shape, including the property write', () => {
    const firstIndex = shapesIn(STATEFUL, classifyBranch);
    const missing = STATEFUL_BRANCH_SHAPES.filter((s) => !firstIndex.has(s));
    expect(
      missing,
      `seed ${SEED} / 120 samples reached: ${JSON.stringify(Object.fromEntries(firstIndex))}`,
    ).toEqual([]);
    // Re-measured 2026-09-16 with the R-169 `pow` arm — see the stateless
    // case above. The #149 `nested-sibling-no-else` shape used to land at
    // index 80, deep in the 120-sample corpus, and the note below warned that
    // a draw change could push it past the budget. It moved the other way, to
    // index 1; the warning stands for the next draw change.
    expect(Object.fromEntries(firstIndex)).toEqual({
      // The #149 shape, and the reason this map is pinned rather than merely
      // checked for completeness: it is drawn from the same uniform pool as
      // the rest but needs a stateful method that draws the branch block at
      // all. A draw change that pushed it past the sample budget would
      // silently drop the ONLY nested-`if` topology `--execute` can reach.
      'nested-sibling-no-else': 1,
      'rebind-read-after': 1,
      'asymmetric-rebind': 2,
      'straight-line-rebind': 2,
      'both-arms-rebind-both': 10,
      'both-arms-rebind-one': 15,
      'multi-rebind-one-arm': 23,
      'prop-write-in-arm': 23,
      'assert-only': 29,
    });
  });

  it('both generators reach EVERY loop shape at a fixed seed', () => {
    const stateless = shapesIn(STATELESS, classifyLoop);
    const stateful = shapesIn(STATEFUL, classifyLoop);
    expect(IR_LOOP_SHAPES.filter((s) => !stateless.has(s))).toEqual([]);
    expect(IR_LOOP_SHAPES.filter((s) => !stateful.has(s))).toEqual([]);
    expect(Object.fromEntries(stateless)).toEqual({
      // Re-measured 2026-09-16 with the R-169 `pow` arm — see above.
      'k2-cross-read': 0,
      'nested-cross-read': 1,
      'single-carrier': 2,
    });
    expect(Object.fromEntries(stateful)).toEqual({
      // Re-measured 2026-09-16 with the R-169 `pow` arm — see above.
      'nested-cross-read': 2,
      'single-carrier': 4,
      'k2-cross-read': 29,
    });
  });

  it('a loop reaches the cross-tier `--ir` corpus at all (it never did before)', () => {
    // The regression this pins: `arbMethodIR` never called a loop generator, so
    // `--ir` — the 7-tier byte-parity fuzzer — had compiled zero loops.
    const withLoop = STATELESS.filter((c) => c.methods.some((m) => findFor(m.body) !== null));
    expect(withLoop.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Structure, per shape, asserted against the IR
// ---------------------------------------------------------------------------

describe('IR generator branch shapes: structure', () => {
  const sampleOf = (shape: BranchShape): GeneratedContract[] =>
    fc.sample(
      shape === 'prop-write-in-arm'
        ? arbGeneratedStatefulContractWithShape(shape)
        : arbGeneratedContractWithShape(shape),
      { numRuns: 10, seed: SEED },
    );

  it.each([...STATEFUL_BRANCH_SHAPES])('%s is produced on demand with the right IR', (shape) => {
    for (const c of sampleOf(shape)) {
      for (const m of c.methods) {
        expect(classifyBranch(m.body), `${c.name}.${m.name} has the wrong topology`).toBe(shape);
        // Every carrier the shape declares is a MUTABLE local declared before
        // the branch — `mutable: false` was hard-coded until 2026-08-06.
        const declared = mutableDecls(m.body).filter((n) => n.startsWith('merge'));
        expect(declared).toEqual(branchShapeCarriers(shape));
      }
    }
  });

  it('every rebinding shape READS its carriers after the branch', () => {
    // A rebound local nothing reads afterwards is dead: a post-branch reference
    // resolved to the wrong stack slot would not change any engine's verdict,
    // and no downstream oracle could see it.
    for (const shape of STATEFUL_BRANCH_SHAPES) {
      if (shape === 'assert-only') continue;
      for (const c of sampleOf(shape)) {
        for (const m of c.methods) {
          const branchIdx = m.body.findIndex((s) => s.kind === 'if' || (isAssign(s) && !s.isProperty));
          for (const carrier of branchShapeCarriers(shape)) {
            expect(
              readAfter(m.body, branchIdx, carrier),
              `${shape}: ${carrier} is never read after the branch`,
            ).toBe(true);
          }
        }
      }
    }
  });

  it('asymmetric-rebind is the PALMER-1 shape: the arms rebind DIFFERENT locals', () => {
    for (const c of sampleOf('asymmetric-rebind')) {
      for (const m of c.methods) {
        const branch = findIf(m.body)!;
        expect(targets(branch.then, false)).toEqual(['merge0']);
        expect(targets(branch.else_, false)).toEqual(['merge1']);
      }
    }
  });

  it('nested-sibling-no-else has BOTH #149 degrees of freedom', () => {
    for (const c of sampleOf('nested-sibling-no-else')) {
      for (const m of c.methods) {
        const outer = findIf(m.body)!;
        // (2) the OUTER `if` has no else, so only one outer path rearranges the
        // inherited region and the two paths exit at equal DEPTH, different
        // LAYOUT. With an else, both paths get rearranged and every
        // post-OP_ENDIF read resolves the same way on either.
        expect(outer.else_, 'the outer if must have NO else').toBeUndefined();
        expect(outer.then.length).toBe(1);
        const inner = outer.then[0]!;
        expect(inner.kind).toBe('if');
        if (inner.kind !== 'if') continue;
        // (1) the inner `if` merges merge0 in BOTH arms — so it DECLARES a
        // result and ROLL+DROPs the stale copy — and never touches merge1,
        // which therefore stays live in the region inherited from the outer arm.
        expect(targets(inner.then, false)).toEqual(['merge0']);
        expect(targets(inner.else_, false)).toEqual(['merge0']);
        expect(mutableDecls(m.body).filter((n) => n.startsWith('merge'))).toEqual([
          'merge0',
          'merge1',
        ]);
      }
    }
  });

  it('nested-sibling-no-else reads the merged local and the sibling ORDER-SENSITIVELY', () => {
    // `===` / `!==` are symmetric in their operands: a script that read the two
    // slots CROSSED reports the same verdict as one that read them correctly,
    // so every downstream oracle agrees on bytes that resolved the wrong stack
    // positions. Measured on the tri-modal generator, whose commutative read
    // clause did exactly that. Only a RELATIONAL read flips under the rotation.
    const RELATIONAL = new Set(['<', '>', '<=', '>=']);
    for (const c of sampleOf('nested-sibling-no-else')) {
      for (const m of c.methods) {
        const last = m.body[m.body.findIndex((s) => s.kind === 'if') + 1]!;
        expect(last.kind).toBe('assert');
        if (last.kind !== 'assert') continue;
        const cond = last.condition;
        expect(cond.kind).toBe('binary');
        if (cond.kind !== 'binary') continue;
        expect(RELATIONAL.has(cond.op), `read clause op ${cond.op} is symmetric`).toBe(true);
        expect(cond.left).toEqual({ kind: 'var_ref', name: 'merge0' });
        expect(cond.right).toEqual({ kind: 'var_ref', name: 'merge1' });
      }
    }
  });

  it('the UNFORCED stateless corpus now nests an `if` (it never did)', () => {
    // The regression this pins, measured on the pre-2026-08-17 generator: over
    // 3000 unforced samples of `arbGeneratedContract` the maximum `if`-nesting
    // depth was 1. `--execute` draws its ENTIRE corpus from this arbitrary, so
    // no seed and no budget could have reached a nested-`if` layout defect —
    // while `--tri-modal` and `--spend-oracle` had both been extended to.
    const depth = (stmts: Stmt[]): number =>
      stmts.reduce((best, s) => {
        if (s.kind === 'if') {
          return Math.max(best, 1 + Math.max(depth(s.then), depth(s.else_ ?? [])));
        }
        if (s.kind === 'for') return Math.max(best, depth(s.body));
        return best;
      }, 0);
    const corpus = fc.sample(arbGeneratedContract, { numRuns: 120, seed: SEED });
    const maxDepth = Math.max(
      ...corpus.flatMap((c) => c.methods.map((m) => depth(m.body))),
    );
    expect(maxDepth).toBeGreaterThanOrEqual(2);
  });

  it('prop-write-in-arm writes a PROPERTY inside an arm', () => {
    for (const c of sampleOf('prop-write-in-arm')) {
      for (const m of c.methods) {
        const branch = findIf(m.body)!;
        const props = targets(branch.then, true);
        expect(props.length).toBe(1);
        expect(c.properties.some((p) => p.name === props[0] && !p.readonly)).toBe(true);
      }
    }
  });

  it('straight-line-rebind rebinds a local with NO branch at all', () => {
    for (const c of sampleOf('straight-line-rebind')) {
      for (const m of c.methods) {
        expect(findIf(m.body)).toBeNull();
        expect(m.body.filter(isAssign).filter((s) => !s.isProperty).map((s) => s.target)).toContain(
          'merge0',
        );
      }
    }
  });

  it('assert-only is unchanged: neither arm assigns anything', () => {
    for (const c of sampleOf('assert-only')) {
      for (const m of c.methods) {
        const branch = findIf(m.body)!;
        expect(branch.then.every((s) => s.kind === 'assert')).toBe(true);
        expect((branch.else_ ?? []).every((s) => s.kind === 'assert')).toBe(true);
        expect(mutableDecls(m.body).filter((n) => n.startsWith('merge'))).toEqual([]);
      }
    }
  });
});

describe('IR generator loop shapes: structure', () => {
  const sampleOf = (shape: IrLoopShape): GeneratedContract[] =>
    fc.sample(arbGeneratedContractWithShape(undefined, shape), { numRuns: 10, seed: SEED });

  it.each([...IR_LOOP_SHAPES])('%s is produced on demand with the right IR', (shape) => {
    for (const c of sampleOf(shape)) {
      for (const m of c.methods) {
        expect(classifyLoop(m.body)).toBe(shape);
        expect(mutableDecls(m.body).filter((n) => n.startsWith('sum'))).toEqual(
          irLoopShapeCarriers(shape),
        );
      }
    }
  });

  it('every loop is in the CROSS-TIER renderable subset (ascending, unit step)', () => {
    // The Rust DSL only has `for i in a..b`; a countdown or an inclusive bound
    // has no Rust surface form, so the native renderers reject them. A loop the
    // `--ir` corpus can produce must therefore be in this subset.
    const checkLoop = (l: For): void => {
      expect(l.step).toBe(1);
      expect(l.op).toBe('<');
      expect(l.bound).toBeGreaterThan(l.start);
      for (const s of l.body) if (s.kind === 'for') checkLoop(s);
    };
    for (const shape of IR_LOOP_SHAPES) {
      for (const c of sampleOf(shape)) {
        for (const m of c.methods) {
          const l = findFor(m.body);
          if (l) checkLoop(l);
        }
      }
    }
  });

  it('every loop body references a runtime value, so folding cannot erase it', () => {
    // A bounded loop is UNROLLED. A body built only from literals is folded
    // away before stack lowering, so the shape would be in the corpus and still
    // never reach the code under test.
    for (const shape of IR_LOOP_SHAPES) {
      for (const c of sampleOf(shape)) {
        for (const m of c.methods) {
          const loop = findFor(m.body);
          if (!loop) continue;
          const live = new Set([
            ...m.params.filter((p) => p.type === 'bigint').map((p) => p.name),
            'k0',
            'k1',
          ]);
          const bodyRefs = (l: For): string[] =>
            l.body.flatMap((s) =>
              s.kind === 'for' ? bodyRefs(s) : isAssign(s) ? refs(s.value) : [],
            );
          const props = c.properties.filter((p) => p.type === 'bigint').map((p) => p.name);
          const propRefs = (l: For): string[] =>
            l.body.flatMap((s) =>
              s.kind === 'for'
                ? propRefs(s)
                : isAssign(s) && s.value.kind === 'binary' && s.value.right.kind === 'property_ref'
                  ? [s.value.right.name]
                  : [],
            );
          const seen = [...bodyRefs(loop), ...propRefs(loop)];
          expect(
            seen.some((n) => live.has(n) || props.includes(n)),
            `${shape}: loop body has no runtime reference`,
          ).toBe(true);
        }
      }
    }
  });

  it('every native renderer emits the loop (all six used to throw)', () => {
    for (const shape of IR_LOOP_SHAPES) {
      for (const c of sampleOf(shape)) {
        for (const [format, render] of Object.entries(RENDERERS)) {
          const src = render(c);
          expect(src.length, `${format} rendered nothing for ${shape}`).toBeGreaterThan(0);
        }
        // Spot-check that each surface really produced its own loop syntax.
        expect(RENDERERS.ts(c)).toMatch(/for \(let k0/);
        expect(RENDERERS.go(c)).toMatch(/for k0 := runar\.Int\(/);
        expect(RENDERERS.rs(c)).toMatch(/for k0 in \d+\.\.\d+/);
        expect(RENDERERS.py(c)).toMatch(/for k0 in range\(/);
        expect(RENDERERS.zig(c)).toMatch(/while \(k0 < \d+\) : \(k0 \+= 1\)/);
        expect(RENDERERS.rb(c)).toMatch(/for k0 in \d+\.\.\.\d+/);
        expect(RENDERERS.java(c)).toMatch(/for \(Bigint k0 = /);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// The widened space compiles — every shape, both folding modes
// ---------------------------------------------------------------------------
//
// `both-arms-rebind-one` was excluded here until 2026-08-06: forcing it found a
// live k=1 branch-merge defect the moment the widened space was turned on. It
// is fixed (see the witness block below), so no shape is exempt.
//
// Each shape runs against the generator that can actually express it.
// `prop-write-in-arm` writes a PROPERTY inside an arm, which only a
// `StatefulSmartContract` has — every property of a stateless contract is
// readonly — so it is stateful-only, and forcing it on the stateless generator
// draws a null property-write statement. That is a generator misuse, not a
// compiler limit: `STATEFUL_BRANCH_SHAPES` is the stateless set plus that one
// shape.
//
// `prop-write-in-arm` was the ONE shape that did not compile. An arm that
// writes a property AND rebinds a merged local carries two results against
// what used to be a single-result `if` node; every tier emitted an UNSPENDABLE
// script for it until 2026-08-06, when the Layer C result-depth invariant
// turned that into a compile refusal — containment, not a fix.
//
// It compiles now, in every tier: the `if` node DECLARES its result list, an
// arm-written property is a first-class result beside the merged locals, and
// both arms materialise the whole set in the declared order. The shape is back
// in the compiles-clean list, and the spend-level proof (deploy -> call ->
// `Spend`, against the hand-derived post-state) is in
// packages/runar-testing/src/__tests__/branch-prop-write-with-merged-local-vm.test.ts.
const COMPILING_STATEFUL_BRANCH_SHAPES: readonly BranchShape[] = STATEFUL_BRANCH_SHAPES;

describe('IR generator branch shapes: the widened space compiles', () => {
  it.each([...BRANCH_SHAPES])(
    '%s compiles in both folding modes (stateless)',
    (shape) => {
      const contracts = fc.sample(
        arbGeneratedContractWithShape(shape),
        { numRuns: 10, seed: SEED },
      );
      for (const c of contracts) {
        const source = renderTypeScript(c);
        for (const disableConstantFolding of [false, true]) {
          const r = compile(source, { fileName: `${c.name}.runar.ts`, disableConstantFolding });
          expect(
            r.success,
            `${shape} (fold ${disableConstantFolding ? 'OFF' : 'ON'}): ` +
              `${r.diagnostics.map((d) => d.message).join('; ')}\n${source}`,
          ).toBe(true);
        }
      }
    },
  );

  it.each([...COMPILING_STATEFUL_BRANCH_SHAPES])(
    '%s compiles in both folding modes (stateful)',
    (shape) => {
      const contracts = fc.sample(
        arbGeneratedStatefulContractWithShape(shape),
        { numRuns: 10, seed: SEED },
      );
      for (const c of contracts) {
        const source = renderTypeScript(c);
        for (const disableConstantFolding of [false, true]) {
          const r = compile(source, { fileName: `${c.name}.runar.ts`, disableConstantFolding });
          expect(
            r.success,
            `${shape} (fold ${disableConstantFolding ? 'OFF' : 'ON'}): ` +
              `${r.diagnostics.map((d) => d.message).join('; ')}\n${source}`,
          ).toBe(true);
        }
      }
    },
  );

  it.each([...IR_LOOP_SHAPES])('loop shape %s compiles in both folding modes', (shape) => {
    const contracts = fc.sample(arbGeneratedContractWithShape('assert-only', shape), {
      numRuns: 10,
      seed: SEED,
    });
    for (const c of contracts) {
      const source = renderTypeScript(c);
      for (const disableConstantFolding of [false, true]) {
        const r = compile(source, { fileName: `${c.name}.runar.ts`, disableConstantFolding });
        expect(
          r.success,
          `${shape} (fold ${disableConstantFolding ? 'OFF' : 'ON'}): ` +
            `${r.diagnostics.map((d) => d.message).join('; ')}\n${source}`,
        ).toBe(true);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// FIXED 2026-08-06 — k=1 branch merge (regression witnesses)
// ---------------------------------------------------------------------------
//
// Both were the SAME FAMILY as PALMER-1 — "one stack carrier asked to hold N
// live values" — at k=1, the arity the 2026-08-05 branch-merged-locals fix did
// NOT cover. Both reproduced in ALL SEVEN TIERS and in a pristine `git archive`
// of both HEAD and its pre-fix ancestor `bc95cfb1`. Both were compile-time
// REJECTIONS of valid Rúnar, not silent miscompiles.
//
//   A — both arms rebind the SAME single local FROM ITSELF. 04-anf-lower does
//       not append a `__merge$<i>` block at k=1; it aliases the local to the
//       `if` binding instead. Reading the local inside the arms makes each arm
//       ROLL the parent slot and leave its result in place, so the arms' net
//       stack effect is zero, no depth-growth case in `lowerIf` fires, and the
//       `if` binding was never registered. The `if` now DECLARES its results
//       and 05-stack-lower adopts them by the declared order (`If.results`);
//       the `branchInPlaceRebindDepth` inference that first contained this is
//       deleted in all seven tiers.
//   B — the same k=1 merge under a COMPILE-TIME-CONSTANT condition, fold-ON
//       only. The folder blanked the statically-dead arm while leaving the
//       `if` in place, destroying the arm-shape contract. It no longer does.
//
// These are now regression witnesses: they assert the CORRECT behaviour.

const SELF_READ_BOTH_ARMS = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) { super(a); this.a = a; }

  public m(p: bigint): void {
    assert(this.a > -1000000n);
    let m0: bigint = 1n;
    if (p > 0n) {
      m0 = (m0 + 1n);
    } else {
      m0 = (m0 - 1n);
    }
    assert(m0 > -1000000n);
  }
}`;

const CONST_CONDITION_K1 = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) { super(a); this.a = a; }

  public m(p: bigint): void {
    assert(this.a > -1000000n);
    let m0: bigint = 1n;
    if (true) {
      m0 = 2n;
    } else {
      m0 = 3n;
    }
    assert(m0 > -1000000n);
  }
}`;

describe('FIXED (2026-08-06) — k=1 branch merge, found by the widened space', () => {
  it('A: one local rebound FROM ITSELF in BOTH arms compiles in both fold modes', () => {
    for (const disableConstantFolding of [false, true]) {
      const r = compile(SELF_READ_BOTH_ARMS, {
        fileName: 'C.runar.ts',
        disableConstantFolding,
      });
      expect(
        r.success,
        `fold ${disableConstantFolding ? 'OFF' : 'ON'}: ` +
          r.diagnostics.map((d) => d.message).join('; '),
      ).toBe(true);
    }
  });

  it('A control: the SAME shape at k=2 compiles (the 2026-08-05 fix covered k>=2)', () => {
    const k2 = SELF_READ_BOTH_ARMS.replace(
      '    let m0: bigint = 1n;',
      '    let m0: bigint = 1n;\n    let m1: bigint = 2n;',
    )
      .replace('      m0 = (m0 + 1n);', '      m0 = (m0 + 1n);\n      m1 = (m1 + 1n);')
      .replace('      m0 = (m0 - 1n);', '      m0 = (m0 - 1n);\n      m1 = (m1 - 1n);')
      .replace('    assert(m0 > -1000000n);\n  }', '    assert((m0 > -1000000n) && (m1 > -1000000n));\n  }');
    const r = compile(k2, { fileName: 'C.runar.ts' });
    expect(r.success, r.diagnostics.map((d) => d.message).join('; ')).toBe(true);
  });

  it('A control: a single arm (no `else`) compiles', () => {
    const noElse = SELF_READ_BOTH_ARMS.replace(
      '    } else {\n      m0 = (m0 - 1n);\n    }',
      '    }',
    );
    const r = compile(noElse, { fileName: 'C.runar.ts' });
    expect(r.success, r.diagnostics.map((d) => d.message).join('; ')).toBe(true);
  });

  it('B: a COMPILE-TIME-CONSTANT condition compiles the same k=1 merge in both modes', () => {
    const on = compile(CONST_CONDITION_K1, { fileName: 'C.runar.ts' });
    expect(on.success, on.diagnostics.map((d) => d.message).join('; ')).toBe(true);
    // Folding OFF is exactly why the `--anf` / `--ir` parity fuzzers (which
    // pass --disable-constant-folding) were blind to this one.
    const off = compile(CONST_CONDITION_K1, {
      fileName: 'C.runar.ts',
      disableConstantFolding: true,
    });
    expect(off.success, off.diagnostics.map((d) => d.message).join('; ')).toBe(true);
  });

  it('B control: a RUNTIME condition with the same arms compiles in both modes', () => {
    const runtimeCond = CONST_CONDITION_K1.replace('if (true) {', 'if (p > 0n) {');
    for (const disableConstantFolding of [false, true]) {
      const r = compile(runtimeCond, { fileName: 'C.runar.ts', disableConstantFolding });
      expect(r.success, r.diagnostics.map((d) => d.message).join('; ')).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// FIXED 2026-08-06 — FUND-SAFETY MISCOMPILE the widened space found
// ---------------------------------------------------------------------------
//
// The `--execute` absolute oracle went red on its first run against the widened
// corpus (`FuzzContract98.method2`, seed 424242). Minimised below.
//
// An `if` whose condition folded to a compile-time constant, whose STATICALLY
// DEAD arm rebinds exactly TWO locals that are both read after the branch,
// compiled to a script that resolved the post-branch operands to the WRONG
// stack slots. The deployed script's verdict was wrong IN BOTH DIRECTIONS
// depending on the baked value:
//
//   s = -60267 → source REJECTS, deployed script ACCEPTED (guard bypassed —
//                a covenant condition that must stop the spend did not)
//   s =   1000 → source ACCEPTS, deployed script REJECTED (unspendable UTXO)
//
// Properties that made it invisible until then:
//   * FOLD-ON ONLY. `--anf` and `--ir` both pass --disable-constant-folding,
//     and fold-OFF was correct, so neither parity fuzzer could reach it.
//   * ALL SEVEN TIERS EMITTED THE IDENTICAL WRONG SCRIPT
//     (00014e01ce0063000067527978687c537aa1777777), so cross-tier agreement
//     held perfectly while every tier was wrong together.
//   * k-SENSITIVE: k=1 and k=3 dead-arm rebinds were correct; only k=2 broke.
//     Every hand-written branch fixture in `conformance/tests/` uses a runtime
//     condition, which was also correct.
//
// Root cause: the constant folder blanked the statically-dead arm (`then: []`)
// while leaving the `if` node in place. That erased the `__merge$<i>` result
// block 04-anf-lower appends to BOTH arms, so the arms stopped holding the
// results the node declares, `lowerIf`'s reconcile could not adopt them, and
// ONE stackMap slot was registered for TWO physical results. The folder no
// longer blanks arms, and the arm-shape contract is now checked rather than
// inferred (the `countMergedLocalResults` count is deleted in all 7 tiers).

const DEAD_ARM_K2 = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly s: bigint;

  constructor(s: bigint) { super(s); this.s = s; }

  public m(p: bigint): void {
    let a: bigint = this.s;
    let b: bigint = -78n;
    if (false) {
      a = 1n;
      b = p;
    }
    assert(b <= a);
  }
}`;

describe('FIXED (2026-08-06) — statically-dead branch arm rebinding k=2 locals', () => {
  const run = (s: bigint, disableConstantFolding: boolean) =>
    runDifferentialExecution({
      source: DEAD_ARM_K2,
      fileName: 'C.runar.ts',
      method: 'm',
      constructorArgs: { s },
      args: [-5020n],
      disableConstantFolding,
    });

  it('fold-ON: the deployed script REJECTS the spend the source REJECTS', () => {
    // -78 <= -60267 is false, so `assert(b <= a)` must fail.
    const r = run(-60267n, false);
    expect(r.interpreterAccepted).toBe(false);
    expect(r.vmAccepted).toBe(false);
  });

  it('fold-ON: the deployed script ACCEPTS the spend the source ACCEPTS', () => {
    // -78 <= 1000 is true, so `assert(b <= a)` must pass.
    const r = run(1000n, false);
    expect(r.interpreterAccepted).toBe(true);
    expect(r.vmAccepted).toBe(true);
  });

  it('fold-OFF is correct too, which is why the parity fuzzers could not see it', () => {
    for (const s of [-60267n, 1000n]) {
      const r = run(s, true);
      expect(r.vmAccepted, `fold-OFF diverged at s=${s}`).toBe(r.interpreterAccepted);
    }
  });

  it('control: the same shape with a RUNTIME condition is correct', () => {
    const runtimeCond = DEAD_ARM_K2.replace('if (false) {', 'if (p > 0n) {');
    for (const s of [-60267n, 1000n]) {
      const r = runDifferentialExecution({
        source: runtimeCond,
        fileName: 'C.runar.ts',
        method: 'm',
        constructorArgs: { s },
        args: [-5020n],
        disableConstantFolding: false,
      });
      expect(r.vmAccepted, `runtime-condition control diverged at s=${s}`).toBe(
        r.interpreterAccepted,
      );
    }
  });

  it('control: k=1 and k=3 dead-arm rebinds are correct too (the defect was k=2)', () => {
    const k1 = DEAD_ARM_K2.replace('    let b: bigint = -78n;\n', '')
      .replace('      b = p;\n', '')
      .replace('assert(b <= a);', 'assert(a > 0n);');
    const k3 = DEAD_ARM_K2.replace(
      '    let b: bigint = -78n;',
      '    let b: bigint = -78n;\n    let c: bigint = -5n;',
    )
      .replace('      b = p;', '      b = p;\n      c = 2n;')
      .replace('assert(b <= a);', 'assert((b <= a) && (c > 0n));');
    for (const [label, source] of [['k=1', k1], ['k=3', k3]] as const) {
      for (const s of [-60267n, 1000n]) {
        const r = runDifferentialExecution({
          source,
          fileName: 'C.runar.ts',
          method: 'm',
          constructorArgs: { s },
          args: [-5020n],
          disableConstantFolding: false,
        });
        expect(r.vmAccepted, `${label} diverged at s=${s}`).toBe(r.interpreterAccepted);
      }
    }
  });
});
