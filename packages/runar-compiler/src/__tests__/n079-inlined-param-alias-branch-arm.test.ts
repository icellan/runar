/**
 * N-079 — the inlined argument alias must survive into a branch arm.
 *
 * `spec/semantics.md` §6.3 defines a private method as source-level
 * substitution at every call site. So this:
 *
 *     private pay(v: bigint): void { ...uses v... }
 *     public  go(v: bigint) { this.pay(v * 2n); }
 *
 * and the hand-substituted program (`const a = v * 2n;` then the body with
 * `a` in place of `v`) are the SAME program and must compile to the same
 * script. That gives an oracle that consults no reference tier.
 *
 * The defect: `inlinePrivateMethodCall` pushes the caller's argument refs onto
 * the CURRENT lowering context (`pushParamAlias`) and then lowers the private
 * method's body into it. When that body contains an `if` / `for` / ternary, the
 * arm is built by `subContext()` — a FRESH context that did not copy
 * `paramAliasStack`. A read of the private's parameter inside the arm therefore
 * found no alias and fell through to `load_param`, which resolved to the
 * CALLER's same-named parameter instead of the argument that was passed in.
 *
 * Concretely, for the `if-arm` probe below, the caller passes `v * 2n` but the
 * arm read the caller's `v`:
 *
 *     ts   OP_5 OP_PICK OP_1ADD       (reaches past the alias to `v`)
 *     go   OP_1 OP_ROT OP_SWAP OP_ADD (reads the alias slot: `v * 2n`)
 *
 * Two different programs, not two encodings of one. The covenant's output
 * amount became `v + 100` where the source says `(v * 2) + 100` — a
 * continuation-hash mismatch (UTXO unspendable) or a wrong payment. Nobody
 * refuses; five of the seven tiers silently emitted a different program.
 *
 * Measured on the pre-fix HEAD, `--disable-constant-folding`:
 *
 *                    go   rust  python  zig  ruby  java  ts
 *     hand-inlined   705   705    705   705   705   705  705
 *     via helper     705   705    703   703   703   703  703
 *
 * Go and Rust were right: Go's `subContext` already deep-copied the alias
 * stack, with a comment naming this exact hazard. TS, Python, Zig, Ruby and
 * Java were fixed to match it.
 *
 * This is the FIFTH field of the same sub-context to be missed one at a time —
 * `scriptLevelCodeSeparator` (R-010), `renamedParams` (#130), `privateMethods`
 * (N-051), the three `MethodScope` fields (R-072), now `paramAliasStack`. Same
 * family as the NEW-014 / NEW-018 branch-lowering arm contract.
 *
 * The (byteLength, sha256-of-hex) pairs below are the SEVEN-TIER agreed
 * output. Every tier pins the same table in its own
 * `n079_inlined_param_alias_branch_arm` test, which is what makes this a parity
 * gate: a tier that lowers the fix differently fails its own test. The scripts
 * are ~700 B (a stateful covenant — the ANF-level inliner only fires for a
 * helper that emits outputs), so they are pinned by digest rather than inline.
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { compile } from '../index.js';

const PRELUDE = `import { StatefulSmartContract, assert } from "runar-lang";

class C extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

`;

function contract(body: string): string {
  return PRELUDE + body;
}

/** The item's probe: a helper containing an `if`, called with `v * 2n`. */
const IF_ARM = contract(`  private pay(v: bigint): void {
    let extra: bigint = 0n;
    if (v > 5n) {
      extra = v + 100n;
    } else {
      extra = v + 1n;
    }
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
`);

/** §6.3 control: the same program with the helper substituted by hand. */
const IF_ARM_MANUAL = contract(`  public go(v: bigint) {
    this.count = this.count + 1n;
    const a: bigint = v * 2n;
    let extra: bigint = 0n;
    if (a > 5n) {
      extra = a + 100n;
    } else {
      extra = a + 1n;
    }
    this.addOutput(extra, this.count);
    assert(v >= 0n);
  }
}
`);

/** N-051 oracle: differs from IF_ARM ONLY inside the then-arm (+200 not +100). */
const IF_ARM_200 = contract(`  private pay(v: bigint): void {
    let extra: bigint = 0n;
    if (v > 5n) {
      extra = v + 200n;
    } else {
      extra = v + 1n;
    }
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
`);

/** Same hazard through a ternary arm. */
const TERNARY_ARM = contract(`  private pay(v: bigint): void {
    const extra: bigint = v > 5n ? v + 100n : v + 1n;
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
`);

const TERNARY_ARM_MANUAL = contract(`  public go(v: bigint) {
    this.count = this.count + 1n;
    const a: bigint = v * 2n;
    const extra: bigint = a > 5n ? a + 100n : a + 1n;
    this.addOutput(extra, this.count);
    assert(v >= 0n);
  }
}
`);

/** Same hazard through a `for` body — `subContext()` builds that too. */
const LOOP_BODY = contract(`  private pay(v: bigint): void {
    let acc: bigint = 0n;
    for (let i = 0; i < 3; i++) {
      acc = acc + v;
    }
    this.addOutput(acc, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
`);

const LOOP_BODY_MANUAL = contract(`  public go(v: bigint) {
    this.count = this.count + 1n;
    const a: bigint = v * 2n;
    let acc: bigint = 0n;
    for (let i = 0; i < 3; i++) {
      acc = acc + a;
    }
    this.addOutput(acc, this.count);
    assert(v >= 0n);
  }
}
`);

/** Control: a helper with NO nested block at all. Must be byte-unchanged. */
const NO_IF = contract(`  private pay(v: bigint): void {
    const extra: bigint = v + 100n;
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
`);

/**
 * Control: the parameter is read at STATEMENT level inside the helper, and the
 * `if` in the helper does not read it. Must be byte-unchanged.
 */
const STMT_LEVEL = contract(`  private pay(v: bigint): void {
    const extra: bigint = v + 100n;
    let bump: bigint = 0n;
    if (this.count > 5n) {
      bump = 1n;
    } else {
      bump = 2n;
    }
    this.addOutput(extra + bump, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
`);

/**
 * Control: the argument IS the caller's own parameter (`this.pay(v)`), so
 * caller-param and argument coincide and the WRONG lowering computed the right
 * VALUE. It was still a different script — 701 B where Go/Rust emitted 703 —
 * because the arm re-issued `load_param` instead of reading the alias slot.
 * The five fixed tiers converge onto Go/Rust's 703 here, which is why this
 * probe is pinned rather than asserted unchanged.
 */
const PASSTHROUGH = contract(`  private pay(v: bigint): void {
    let extra: bigint = 0n;
    if (v > 5n) {
      extra = v + 100n;
    } else {
      extra = v + 1n;
    }
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v);
    assert(v >= 0n);
  }
}
`);

/** label -> [script byte length, sha256 of the lowercase script hex]. */
const SEVEN_TIER: Record<string, [number, string]> = {
  // W1: +3 bytes each — the zero-pad (`01 00 7e`) before the auto-injected
  // sighash-type pin's OP_BIN2NUM. One pad site per script; the alias-survival
  // equalities between the `-manual` pairs are unchanged.
  'if-arm': [702, '92db59e2c0e61df6dbeef8256d0c37ac1f74880f71d22bdd1e992fab9e257507'],
  'if-arm-manual': [702, '92db59e2c0e61df6dbeef8256d0c37ac1f74880f71d22bdd1e992fab9e257507'],
  'if-arm-200': [703, '7584c506d6b04e415c9036f8e345c749dc1661ef6dd13c7a05aa83597ddbd840'],
  'ternary-arm': [688, 'ed951f38c72d41f09b0e20d9aeb1408693cbc7936f3e9ea7b6d34905ed6df613'],
  'ternary-arm-manual': [688, 'ed951f38c72d41f09b0e20d9aeb1408693cbc7936f3e9ea7b6d34905ed6df613'],
  'loop-body': [695, 'af13b9a1c80743a69ed0181c4bf227d99f632b18a2f8d71f51cf694b720e9590'],
  'loop-body-manual': [695, 'af13b9a1c80743a69ed0181c4bf227d99f632b18a2f8d71f51cf694b720e9590'],
  'no-if': [680, 'bfea7ecbf3196c7e4943227546da0918055d0c11548ba41ac4b45676f741f170'],
  'stmt-level': [698, '0b1e61517510b65cbdb2f18458df8c3d67b0decd116aabf592f3aef5e936a470'],
  'passthrough': [700, '1e7409174b2026df384f2d22e3baf6b8926ee9bfd4e17772f004bd7711a5f7e5'],
};

const CASES: [string, string][] = [
  ['if-arm', IF_ARM],
  ['if-arm-manual', IF_ARM_MANUAL],
  ['if-arm-200', IF_ARM_200],
  ['ternary-arm', TERNARY_ARM],
  ['ternary-arm-manual', TERNARY_ARM_MANUAL],
  ['loop-body', LOOP_BODY],
  ['loop-body-manual', LOOP_BODY_MANUAL],
  ['no-if', NO_IF],
  ['stmt-level', STMT_LEVEL],
  ['passthrough', PASSTHROUGH],
];

function compileScriptHex(source: string, disableConstantFolding: boolean): string {
  const r = compile(source, { fileName: 'C.runar.ts', disableConstantFolding });
  expect(r.success, r.diagnostics.map((d) => d.message).join('; ')).toBe(true);
  return r.artifact!.script.toLowerCase();
}

function digest(hex: string): string {
  return createHash('sha256').update(hex).digest('hex');
}

describe('N-079: the inlined argument alias survives into a branch arm', () => {
  for (const [label, source] of CASES) {
    for (const disable of [true, false]) {
      it(`${label} (fold-${disable ? 'off' : 'on'}) matches the seven-tier script`, () => {
        const hex = compileScriptHex(source, disable);
        const [wantLen, wantSha] = SEVEN_TIER[label]!;
        expect(hex.length / 2).toBe(wantLen);
        expect(digest(hex)).toBe(wantSha);
      });
    }
  }

  // spec/semantics.md §6.3: inlining IS substitution. Needs no reference tier.
  const SUBSTITUTION: [string, string, string][] = [
    ['if', IF_ARM, IF_ARM_MANUAL],
    ['ternary', TERNARY_ARM, TERNARY_ARM_MANUAL],
    ['for', LOOP_BODY, LOOP_BODY_MANUAL],
  ];
  for (const [kind, helper, manual] of SUBSTITUTION) {
    it(`a helper whose body contains an ${kind} compiles exactly like the hand-inlined source`, () => {
      for (const disable of [true, false]) {
        expect(compileScriptHex(helper, disable)).toBe(compileScriptHex(manual, disable));
      }
    });
  }

  // The N-051 oracle, again consulting no reference tier: two helper bodies
  // that differ only INSIDE the arm must not compile to the same script.
  it('the arm reads the argument — a different arm body changes the script', () => {
    for (const disable of [true, false]) {
      expect(compileScriptHex(IF_ARM, disable)).not.toBe(compileScriptHex(IF_ARM_200, disable));
    }
  });
});
