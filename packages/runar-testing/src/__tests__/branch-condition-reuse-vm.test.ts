import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { runStatelessSigned } from '../oracle/real-crypto-execution.js';

/**
 * Two independent live defects in how a conditional handles parent-scope
 * locals. NEW-015 is fail-CLOSED (legal source will not compile); NEW-016 is
 * fail-OPEN off-chain (it compiles, the interpreter accepts, and the chain
 * rejects the spend) — an ordinary contract deployed to a permanently
 * unspendable UTXO.
 *
 * NEW-015 — a conditional whose CONDITION is a named local that is read again
 * INSIDE one of its arms failed to compile.
 *
 *     let f: boolean = c > 0n;
 *     assert(f ? c > 10n : !f);
 *     //  Value 'f' not found on stack (stack has 1 items: [c])
 *
 * Legal source. `02-validate` and `03-typecheck` both accept it; the rejection
 * comes out of 05-stack-lower, so there is no diagnostic a developer can act
 * on — the contract simply cannot be built.
 *
 * ROOT CAUSE
 * ----------
 * `lowerIf` decides whether OP_IF may CONSUME the condition slot:
 *
 *     const isLast = this.isLastUse(cond, bindingIndex, lastUses);
 *     this.bringToTop(cond, isLast);   // isLast => ROLL, else PICK
 *
 * `lastUses` is keyed by the index of the ENCLOSING binding, and
 * `collectRefs` folds an `if`'s arm reads into that same index (it recurses
 * into `value.then` / `value.else` on purpose, so an arm-only ref is not
 * dropped early). So for a ref read as the condition AND inside an arm,
 * `lastUses.get(ref) === bindingIndex` — indistinguishable from a ref used
 * only as the condition. `lowerIf` therefore ROLLed the slot away and the arm
 * then looked for a value that was no longer there.
 *
 * The same index collision also kept the ref out of `protectedRefs`, which is
 * built from `lastIdx > bindingIndex`, so nothing downstream restored it.
 * A ref that happens to be live AFTER the `if` was protected by that rule and
 * compiled fine — which is why the shape only ever failed when the condition
 * local was dead at the `if`.
 *
 * WHY IT MATTERS BEYOND THE TERNARY
 * ---------------------------------
 * `&&` / `||` desugar to this node (NEW-014), so every `f || !f` and
 * `f ? … : f` shape routes through the same path. `examples/ts/
 * nested-if-multi-reassign/StackTrackerRepro.runar.ts` ends in
 * `assert(found || !found)` — it compiled only because the eager lowering
 * never built an `if` at all.
 *
 * NEW-016 — an arm that is a BARE local read produced an EMPTY result
 * -------------------------------------------------------------------
 *     let f: boolean = c > 0n;
 *     let g: boolean = c > 3n;
 *     assert(g ? f : c === 0n);   // c = 7: source says ACCEPT
 *
 * `lowerExprToRef` returns an existing ref without emitting a binding, so the
 * arm came out as `then: []` — an `if` arm with no bindings at all, a +0 stack
 * effect where the parent models +1. The depth reconcile padded the shortfall
 * with an EMPTY push, so the arm's `true` was replaced by an empty (false)
 * value: `Spend` rejects with "OP_VERIFY requires the top stack value to be
 * truthy" over a stack of `[01, ]` while `TestContract` accepts. Fixed in
 * 04-anf-lower by aliasing the arm result through `load_const @ref:` — the
 * idiom `let x = y` already uses — so the arm ends on its own result.
 *
 * The two are independent: NEW-016's condition (`g`) is never re-read.
 *
 * WHAT THIS TEST PINS
 * -------------------
 * Both halves, because "it compiles" is satisfied by a compiler that drops an
 * arm: every case is executed through `runStatelessSigned`, so the real
 * `@bsv/sdk` `Spend` over the deployed bytes and `TestContract` over the
 * source AST must BOTH return the verdict the source says, on inputs that
 * exercise each arm and both outcomes.
 */

const FILE = 'T.runar.ts';

function contract(body: string): string {
  return `import { SmartContract, assert } from 'runar-lang';

export class T extends SmartContract {
  readonly k: bigint;
  constructor(k: bigint) { super(k); this.k = k; }
  public m(c: bigint): void {
${body}
    assert(this.k > 0n);
  }
}
`;
}

/** Condition local read again in the ELSE arm. */
const ELSE_REUSE = contract(
  '    let f: boolean = c > 0n;\n    assert(f ? c > 10n : !f);',
);

/** Condition local read again in the THEN arm and in both nested else arms. */
const BOTH_REUSE = contract(
  '    let f: boolean = c > 0n;\n    assert(f ? f : (c === 0n ? !f : f));',
);

/** The StackTrackerRepro shape: the condition local is also branch-merged. */
const MERGED_REUSE = contract(
  '    let f: boolean = false;\n    if (0n < c) { f = true; }\n    assert(f ? c > 10n : !f);',
);

/** A nested ternary inside the arm re-reads the outer condition. */
const NESTED_REUSE = contract(
  '    let f: boolean = c > 0n;\n    assert(f ? (f ? c > 10n : false) : !f);',
);

/** CONTROL — the condition is not reused, so the slot may be consumed. */
const NO_REUSE = contract(
  '    let f: boolean = c > 0n;\n    assert(f ? c > 10n : c === 0n);',
);

/**
 * NEW-016 — an arm whose whole body is a BARE LOCAL READ. `lowerExprToRef`
 * returned `f` without emitting anything, so the arm was `then: []` — a +0
 * stack effect where the parent models +1 — and the depth reconcile padded the
 * shortfall with an EMPTY push. Compiles clean, `TestContract` accepts,
 * `Spend` rejects on `[01, ]`. Independent of NEW-015: `g` is the condition
 * and is never re-read.
 */
const BARE_LOCAL_ARM = contract(
  '    let f: boolean = c > 0n;\n    let g: boolean = c > 3n;\n    assert(g ? f : c === 0n);',
);

/** NEW-016 with the bare local read in the ELSE arm instead. */
const BARE_LOCAL_ELSE_ARM = contract(
  '    let f: boolean = c > 0n;\n    let g: boolean = c > 3n;\n    assert(g ? c > 10n : f);',
);

/** NEW-016 with the bare local read inside a NESTED ternary's arm. */
const BARE_LOCAL_NESTED_ARM = contract(
  '    let f: boolean = c > 0n;\n    let g: boolean = c > 3n;\n    assert(g ? (c > 10n ? f : false) : c === 0n);',
);

/** CONTROL — the condition local is live AFTER the `if`; this always worked. */
const LIVE_AFTER = contract(
  '    let f: boolean = c > 0n;\n    assert(f ? c > 10n : !f);\n    assert(f ? true : true);',
);

interface Case {
  readonly label: string;
  readonly source: string;
  /** `c` => what the SOURCE says, and therefore what both engines must say. */
  readonly expect: ReadonlyArray<readonly [bigint, boolean]>;
}

const CASES: Case[] = [
  {
    label: 'condition local re-read in the else arm',
    source: ELSE_REUSE,
    // f=true  -> c > 10n ;  f=false -> !f = true
    expect: [[20n, true], [5n, false], [0n, true], [-3n, true]],
  },
  {
    label: 'condition local re-read in both arms',
    source: BOTH_REUSE,
    // f=true -> f ; f=false -> (c===0 ? !f : f)
    expect: [[7n, true], [0n, true], [-1n, false]],
  },
  {
    label: 'condition local is branch-merged and re-read (StackTrackerRepro shape)',
    source: MERGED_REUSE,
    expect: [[20n, true], [5n, false], [0n, true], [-3n, true]],
  },
  {
    label: 'nested ternary re-reads the outer condition',
    source: NESTED_REUSE,
    expect: [[20n, true], [5n, false], [0n, true]],
  },
  {
    label: 'CONTROL condition local not reused',
    source: NO_REUSE,
    expect: [[20n, true], [5n, false], [0n, true], [-3n, false]],
  },
  {
    label: 'CONTROL condition local live after the conditional',
    source: LIVE_AFTER,
    expect: [[20n, true], [5n, false], [0n, true]],
  },
  {
    label: 'NEW-016 then arm is a bare local read',
    source: BARE_LOCAL_ARM,
    // g -> f ; !g -> c === 0n
    expect: [[7n, true], [1n, false], [0n, true], [-1n, false]],
  },
  {
    label: 'NEW-016 else arm is a bare local read',
    source: BARE_LOCAL_ELSE_ARM,
    // g -> c > 10n ; !g -> f
    expect: [[20n, true], [5n, false], [1n, true], [0n, false]],
  },
  {
    label: 'NEW-016 nested ternary arm is a bare local read',
    source: BARE_LOCAL_NESTED_ARM,
    // g -> (c > 10n ? f : false) ; !g -> c === 0n
    expect: [[20n, true], [5n, false], [0n, true], [-1n, false]],
  },
];

describe('NEW-015 / NEW-016 — conditionals over parent-scope locals', () => {
  for (const c of CASES) {
    it(`${c.label}: compiles`, () => {
      const r = compile(c.source, { fileName: FILE });
      const errors = (r.diagnostics ?? [])
        .filter(d => d.severity === 'error')
        .map(d => d.message);
      expect(errors, 'stack lowering rejected legal source').toEqual([]);
      expect(r.success).toBe(true);
    });

    for (const [arg, accepts] of c.expect) {
      it(`${c.label}: c=${arg} => ${accepts ? 'ACCEPT' : 'REJECT'} on both engines`, () => {
        const r = runStatelessSigned({
          source: c.source,
          fileName: FILE,
          method: 'm',
          args: [arg],
          constructorArgs: { k: 1n },
        });
        expect(r.reachedEngine, `never reached Spend: ${r.vmError ?? ''}`).toBe(true);
        expect(
          r.vmAccepted,
          `the real engine disagreed with the source: ${r.vmError ?? '(accepted)'}`,
        ).toBe(accepts);
        expect(
          r.interpreterAccepted,
          `TestContract disagreed with the real engine: ${r.interpreterError ?? '(accepted)'}`,
        ).toBe(accepts);
      });
    }
  }
});
