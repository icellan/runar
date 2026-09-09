/**
 * R-001 — a private helper that emits an output, called from inside an `if`
 * arm, must not escape the continuation hash.
 *
 * Background: `LoweringContext.subContext()` (04-anf-lower.ts) builds the
 * context an `if` arm / loop body / inlined block is lowered into. It used to
 * call `new LoweringContext(this.contract)` — ONE argument — so the
 * `sideEffects` summary defaulted to `null` in every nested context.
 * `shouldInlinePrivate()` opens with `if (!this.sideEffects) return false;`,
 * so a `this.helper(...)` call sitting inside a branch was NEVER inlined at
 * ANF time. Three consequences compound:
 *
 *   1. the arm's `getAddOutputRefs()` stays empty, so `branchHasOutputs` is
 *      false and `branchOutputRejectionReason` — the guard written precisely
 *      to refuse unrepresentable branch-output shapes — is bypassed by
 *      construction rather than defeated;
 *   2. the public method's `addOutputRefs` stays empty of the helper's output,
 *      so the continuation builder commits to an output set that OMITS it;
 *   3. stack lowering STILL emits the output bytes, because
 *      `inlineMethodCall` (05-stack-lower.ts) splices the helper body verbatim
 *      regardless of what ANF decided.
 *
 * Net effect before the fix: the locking script constructs an output that the
 * `hashOutputs` assertion does not commit to, so a spending transaction is
 * free to drop that payment. Measured at b3f08f2c: the branch-hosted-helper
 * variant emitted 79 bytes MORE than the same contract with the helper call
 * replaced by a plain `assert`, while its continuation `cat` chain still had
 * exactly two leaves (the one top-level output, and change).
 *
 * Either outcome is a pass here: a loud `branchOutputRejectionReason` refusal,
 * or an artifact whose continuation commits to the branch's output too. What
 * is NOT acceptable is today's silent third option — emit the bytes, commit to
 * neither. (With the fix in place this shape takes the SECOND route: it is
 * representable, so it compiles and the branch joins the hashed set.)
 *
 * SCOPE — what this test does NOT cover:
 *   - It asserts the ANF/continuation shape, not on-chain spendability. There
 *     is no Script-VM or node execution here; the proof that the committed set
 *     matches the SDK's built tx lives in the VM/integration suites.
 *   - It covers the `if`-arm sub-context only. `subContext()` is also used for
 *     loop bodies, ternary arms, and the compiler-generated change-output arms;
 *     those inherit the same fix but are not pinned here.
 *   - `subContext()` still does NOT copy `sighashFlag` or `paramAliasStack`.
 *     The `paramAliasStack` omission is a SEPARATE, pre-existing defect with a
 *     different trigger (it does not depend on `sideEffects`): a private
 *     helper's parameter referenced inside an `if` arm of the HELPER's own body
 *     lowers to a `load_param` for a parameter the calling method does not
 *     have. Tracked separately; deliberately not fixed here.
 *   - This is the TypeScript tier only. The Go / Rust / Python / Zig / Ruby /
 *     Java lowerers need their own port + pin.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import type { ANFBinding } from '../ir/anf-ir.js';

/**
 * A stateful contract whose PUBLIC method declares one output directly and
 * delegates a second one to a PRIVATE helper from inside an `if` arm.
 */
const BRANCH_HOSTED_HELPER_OUTPUT = `import { StatefulSmartContract, assert } from 'runar-lang';

class BranchHostedHelperOutput extends StatefulSmartContract {
  count: bigint = 0n;

  constructor(seed: bigint) {
    super(seed);
    this.count = seed;
  }

  private payOut(amount: bigint): void {
    this.addOutput(amount, this.count);
  }

  public tick(flag: bigint): void {
    assert(flag >= 0n);
    this.addOutput(1000n, this.count);
    if (flag > 0n) {
      this.payOut(500n);
    }
  }
}
`;

/** Every binding in a method body, including the ones nested in `if` arms and `loop` bodies. */
function allBindings(bindings: ANFBinding[]): ANFBinding[] {
  const out: ANFBinding[] = [];
  for (const b of bindings) {
    out.push(b);
    const v = b.value;
    if (v.kind === 'if') {
      out.push(...allBindings(v.then));
      out.push(...allBindings(v.else));
    } else if (v.kind === 'loop') {
      out.push(...allBindings(v.body));
    }
  }
  return out;
}

/** Flatten the continuation's `cat` chain to the refs it actually concatenates. */
function catLeaves(top: ANFBinding[], ref: string): string[] {
  const b = top.find((x) => x.name === ref);
  const v = b?.value;
  if (v !== undefined && v.kind === 'call' && v.func === 'cat') {
    return v.args.flatMap((a) => catLeaves(top, a));
  }
  return [ref];
}

/** The refs the auto-injected `hashOutputs` assertion commits to. */
function continuationLeaves(body: ANFBinding[]): string[] {
  // hash256(<outputs>) === extractOutputHash(txPreimage), asserted at method exit.
  let cmpRef: string | undefined;
  for (const b of body) {
    if (b.value.kind === 'assert' && b.value.isAutoInjectedStateCheck === true) {
      cmpRef = b.value.value;
    }
  }
  if (cmpRef === undefined) return [];

  const cmp = body.find((b) => b.name === cmpRef);
  if (cmp === undefined || cmp.value.kind !== 'bin_op') return [];
  const hashRef: string = cmp.value.left;

  const hash = body.find((b) => b.name === hashRef);
  if (hash === undefined || hash.value.kind !== 'call') return [];
  const hashArg = hash.value.args[0];
  if (hashArg === undefined) return [];

  return catLeaves(body, hashArg);
}

describe('R-001: branch-hosted private-helper output', () => {
  it('either refuses the shape, or commits the helper output to the continuation hash', () => {
    let result: ReturnType<typeof compile> | null = null;
    let error: Error | null = null;
    try {
      result = compile(BRANCH_HOSTED_HELPER_OUTPUT, {
        fileName: 'BranchHostedHelperOutput.runar.ts',
      });
    } catch (e) {
      error = e as Error;
    }

    // Outcome 1 (the reviewers' expected result): a loud refusal. The guard
    // that exists for exactly this shape finally sees it.
    if (error !== null) {
      expect(error.message).toMatch(
        /Cannot compile conditional that both declares outputs and/,
      );
      return;
    }

    // Outcome 2: it compiles — then the continuation MUST cover the helper's
    // output. Concretely: no `method_call` to an output-emitting private
    // helper may survive ANF (a surviving one is the escape hatch, since
    // stack lowering inlines it behind the continuation builder's back), and
    // the branch that hosts it must be one of the hashed leaves.
    const anf = result?.anf;
    expect(anf, 'compilation reported no error, so the ANF program must exist').not.toBeNull();
    const method = anf!.methods.find((m) => m.name === 'tick');
    expect(method, 'expected the public method `tick` in the lowered program').toBeDefined();
    const body: ANFBinding[] = method!.body;

    const escapedHelperCalls = allBindings(body).filter(
      (b) => b.value.kind === 'method_call' && b.value.method === 'payOut',
    );
    expect(
      escapedHelperCalls.map((b) => b.name),
      'an output-emitting private helper survived as a method_call, so stack lowering ' +
        'will splice its output bytes in behind the continuation builder',
    ).toEqual([]);

    const branchIf = body.find((b) => {
      const v = b.value;
      if (v.kind !== 'if') return false;
      return allBindings([...v.then, ...v.else]).some(
        (inner) => inner.value.kind === 'add_output' || inner.value.kind === 'method_call',
      );
    });
    expect(branchIf, 'expected the output-bearing branch to survive as an `if` binding').toBeDefined();

    expect(
      continuationLeaves(body),
      'the continuation hash must concatenate the branch that carries the helper output',
    ).toContain(branchIf!.name);
  });
});
