/**
 * Byte pins for four stack-lowering paths the 71-fixture golden corpus does
 * not reach (v1 audit, mutation-survivor triage — 2026-08-17).
 *
 * WHERE THESE CAME FROM
 * ---------------------
 * 1169 mechanical mutants (ROR / LCR / AOR / ICR / UOI) were generated over
 * `05-stack-lower.ts`, `06-emit.ts` and `src/optimizer/*` and scored by
 * compiling every `conformance/tests/*` fixture's `.runar.ts` fold-OFF and
 * comparing `scriptHex` against the checked-in `expected-script.hex`. 347 of
 * the 964 non-degenerate mutants survived that corpus.
 *
 * 66 of the survivors are in the branch-merge / frame-offset class — the
 * `StackMap` slot arithmetic and every ROLL/PICK depth expression inside
 * `lowerIf`. Each was re-run against a MUCH wider program corpus (2101
 * compiles: 500 generated stateless/stateful contracts across two seeds, every
 * `BRANCH_SHAPES` and `IR_LOOP_SHAPES` member forced, both folding modes, plus
 * the fixtures again fold-ON). 60 changed nothing anywhere — evidence of
 * equivalence, not proof. SIX changed emitted bytes for an ordinary generated
 * contract, i.e. they are real holes in the golden corpus rather than
 * semantically-null edits:
 *
 *   05-stack-lower.ts:244  `slots.length - 1` -> `- 2` / `- 0`  (StackMap.dup)
 *   05-stack-lower.ts:1125 `depth === 1`      -> `!==`          (residue drain)
 *   05-stack-lower.ts:2406 `&&` -> `||`, twice                  (if-no-else reconcile)
 *
 * N-450: those two line numbers are historical (the file has since moved; the
 * sites are now :1502 and :3036), and the ORIGINAL witnesses stopped reaching
 * them — drainBranchPrivateResidue found no candidates and the empty-else
 * condition's operands were all true, so neither mutant changed a byte in
 * either folding mode. W2 now has a new source witness; the empty-else
 * condition is pinned by the hand-built-IR test at the end of this file (W5).
 *   05-stack-lower.ts:2538 `d - nDeclared`    -> `d + nDeclared` (#149 sinkBelow)
 *
 * Each witness below was delta-reduced from the generated program that first
 * distinguished the mutant, and each kills EXACTLY the mutants named on it and
 * none of the others (measured, 1:1). They are registered in
 * `conformance/mutation/mutants.json` against the `stack-frame-mutation-pins`
 * gate.
 *
 * WHY BYTE PINS
 * -------------
 * The defect class is "the emitted frame offset moved" — it does not always
 * change a spend verdict, so a behavioural assertion alone cannot be relied on
 * to catch it (that is exactly how these survived a corpus of behavioural
 * gates). The hex pins are the mutation-killing half; the source-vs-script
 * agreement checks underneath them are the meaning-preserving half, and say
 * WHAT the bytes are supposed to do. If a legitimate codegen change moves these
 * bytes, re-stamp the pins — but only after the agreement checks still pass.
 *
 * These pins were GENERATED from the compiler at
 * `fix/v1-audit-triage` (post-#149). No pre-existing golden was modified.
 */

import { createHash } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { compile, compileFromANF, loadANFFromJSON } from 'runar-compiler';
import { runDifferentialExecution } from '../oracle/index.js';

interface Pin {
  /** Reduced witness source. */
  source: string;
  fileName: string;
  /** `05-stack-lower.ts` lines whose mutants this witness kills. */
  kills: string;
  /** scriptHex — or, for the stateful witness, `sha256(scriptHex)`. */
  foldOff: string;
  /** Same, with folding ON (the user-facing default). */
  foldOn: string;
}

const sha256 = (s: string): string => createHash('sha256').update(s).digest('hex');

// ---------------------------------------------------------------------------
// W1 — StackMap.dup() must record the DUPLICATED name, not its neighbour
// ---------------------------------------------------------------------------
//
// `bringToTop(name, consume=false)` emits OP_DUP and calls `stackMap.dup()`
// when the value is already at depth 0. `dup()` pushes
// `slots[slots.length - 1]`; at `- 2` it records the SECOND slot's name and at
// `- 0` it records `undefined`, so the next `findDepth` of that name resolves
// to the stale copy one slot deeper and every later reference is generated
// against the wrong offset.
//
// Reaching it needs a value that is at TOS and read again WITHOUT being
// consumed — `x >= (x + x)` over a single local does exactly that, and no
// conformance fixture does.
const W1: Pin = {
  fileName: 'TosSelfRead.runar.ts',
  kills: '244 (StackMap.dup)',
  source: `import { SmartContract, assert } from 'runar-lang';

export class TosSelfRead extends SmartContract {
  readonly p: bigint;

  constructor(p: bigint) {
    super(p);
    this.p = p;
  }

  public m(a: bigint): void {
    const x: bigint = (a + this.p);
    assert((x >= (x + x)));
  }
}
`,
  foldOff: '0093767693a2',
  foldOn: '0093767693a2',
};

// ---------------------------------------------------------------------------
// W2 — branch-private residue drain: depth 1 is OP_NIP, deeper is ROLL+DROP
// ---------------------------------------------------------------------------
//
// `drainBranchPrivateResidue` (05-stack-lower.ts:1489) removes slots a branch
// body introduced that the parent's model does not know about, deepest-first.
// The `depth === 1` arm (:1502) emits OP_NIP; every other depth emits
// `push d; ROLL d; DROP`. Inverting the test emits the three-op sequence for
// depth 1 and a bare OP_NIP for depth 2+, which silently removes the WRONG slot.
//
// N-450: the arm-local `t` is used twice (`t * t`), so it is still on the stack
// one slot below the arm's result when the drain runs — a depth-1 candidate.
// MEASURED (LOGDIR mutants2.txt): the `!==` mutant turns `...7776...` (OP_NIP)
// into `...7c75...` (SWAP DROP) in BOTH fold-OFF and fold-ON; this source is
// untouched by the constant folder, so the two modes are the same bytes and
// either one kills the mutant. The old witness (N-446 era) never produced a
// drain candidate and killed nothing.
const W2: Pin = {
  fileName: 'BranchResidue.runar.ts',
  kills: '1502 (drainBranchPrivateResidue depth===1)',
  source: `import { SmartContract, assert } from 'runar-lang';

export class BranchResidue extends SmartContract {
  readonly p: bigint;

  constructor(p: bigint) {
    super(p);
    this.p = p;
  }

  public m(a: bigint): void {
    let x: bigint = 1n;
    if (a > 3n) {
      const t = a * 7n;
      x = t * t;
    }
    assert(x + this.p > 2n);
  }
}
`,
  foldOff: '517853a0637c5795767695776777766877009352a0',
  foldOn: '517853a0637c5795767695776777766877009352a0',
};

// ---------------------------------------------------------------------------
// W3 — if-without-else (PLAIN BYTE PIN since N-450)
// ---------------------------------------------------------------------------
//
// This source was written to kill `&&` -> `||` in the empty-else reconcile
// (05-stack-lower.ts:3036). It no longer does: that condition is not reached
// for it at all, and for BranchResidue-style sources every operand is true, so
// no mutant of the condition changes a byte in either mode. It stays only as a
// byte pin of an `if` with an always-failing arm (the
// `conformance/tests/assert-false-guard` family, one `if` deeper) plus the
// source-vs-script agreement cases below. The real kill of the condition is W5.
const W3: Pin = {
  fileName: 'EmptyElseGuard.runar.ts',
  kills: 'none (plain byte pin; see W5 for the :3036 condition)',
  source: `import { SmartContract, assert } from 'runar-lang';

export class EmptyElseGuard extends SmartContract {
  readonly q: boolean;

  constructor(q: boolean) {
    super(q);
    this.q = q;
  }

  public m(b: boolean): void {
    if ((this.q || b)) {
      assert(!(true));
    }
    assert(!((false || b)));
  }
}
`,
  // W3 / BoolBamboozle re-stamp: `m(b: boolean)` is a public method with a
  // `boolean` parameter, so both spellings now open with the 9-byte ABI-domain
  // gate `76 76 00 87 7c 51 87 9b 69`. The mutation this pin kills lives in the
  // empty-else reconcile further down the stream and is unaffected — the tail
  // of both strings is byte-for-byte what it was.
  foldOff: '767600877c51879b690063516776686351916968006351776891',
  // N-446 re-stamp: the post-fold nested prune shortened fold-ON; fold-OFF is unchanged.
  foldOn: '767600877c51879b6900635167766863006968006351776891',
};

// ---------------------------------------------------------------------------
// W4 — the #149 `sinkBelow` DISTANCE, not just its sign
// ---------------------------------------------------------------------------
//
// `sinkBelow` records how far below the adopted result block the deepest stale
// slot sat, so the block can be sunk back under the slots it crossed. The guard
// `if (sinkBelow > 0)` is covered; the DISTANCE `d - nDeclared` is not — turning
// it into `d + nDeclared` keeps the repair firing and rotates the layout by the
// wrong amount, which is the same funds-losing class #149 itself was.
//
// Needs an arm that writes a PROPERTY beside a merged local, so the declared
// result list has something for the adopted block to cross.
const W4: Pin = {
  fileName: 'SinkDistance.runar.ts',
  kills: '2538 (#149 sinkBelow distance)',
  source: `import { StatefulSmartContract, abs } from 'runar-lang';

export class SinkDistance extends StatefulSmartContract {
  prop1: bigint;

  constructor(prop1: bigint) {
    super(prop1);
    this.prop1 = prop1;
  }

  public m(p: bigint): void {
    let merge0: bigint = ((17573n << 6n) & -46931n);
    if ((p > 3n)) {
      this.prop1 = (merge0 << 8n);
    } else {
      merge0 = abs(p);
    }
  }
}
`,
  // Stateful: ~1 KB of preimage machinery (R-010 added the `_codePart`
  // authentication, +79 hex chars fold-OFF), so the pin is `sha256(scriptHex)`
  // rather than a kilobyte of literal hex. Same detection power; when it fires,
  // diff the two scripts rather than reading the digest.
  // F-024 (R14) re-stamp: the injected `_newAmount >= extractAmount(txPreimage)`
  // check added 32 bytes (+64 hex) to both modes. Re-measured with the
  // 2538 `d + nDeclared` mutant applied: fold-OFF 1496 / fold-ON 1512 hex
  // chars, different digests — the pin still kills it.
  // N-216 (2026-10-21) re-stamp: two branch-reconcile `OP_2 OP_ROLL` pairs now
  // fold to OP_ROT (-4 hex chars, both modes; opcode diff is the folds only).
  // Re-measured against the same mutant: fold-OFF 1494 / fold-ON 1510 hex
  // chars, different digests — still killed.
  foldOff: 'e09d8fba20bc9d24cd2cbe88250816061be18623a135e56bc7e5ac559801310a',
  foldOn: '968674def6e9d75ba10e9fbabf2d9622d1b65ae2fb0720aafbe289964705563f',
};

const PINS: Pin[] = [W1, W2, W3, W4];

function hexOf(p: Pin, disableConstantFolding: boolean): string {
  const r = compile(p.source, { fileName: p.fileName, disableConstantFolding });
  expect(r.success, `${p.fileName} failed to compile: ${JSON.stringify(r.diagnostics)}`).toBe(true);
  expect(r.scriptHex).toBeDefined();
  return r.scriptHex!;
}

describe('stack-frame byte pins (mutation survivors the golden corpus misses)', () => {
  it.each(PINS.map((p) => [`${p.fileName} / 05-stack-lower.ts:${p.kills}`, p] as const))(
    '%s',
    (_label, p) => {
      const off = hexOf(p, true);
      const on = hexOf(p, false);
      if (p === W4) {
        // W1's zero-pad before the auto-injected sighash-type pin's OP_BIN2NUM
        // added 6 hex chars to both modes.
        // F-024 (R14): +64 hex chars in both modes for the value check.
        // N-216: -4 hex chars in both modes (two reconcile rolls fold to OP_ROT).
        expect(off.length, `${p.fileName} fold-OFF script length moved`).toBe(1474);
        // N-138 (2026-10-30): fold-ON no longer carries the dead operand pushes
        // the folder orphaned (-22 hex chars); fold-OFF is unchanged.
        expect(on.length, `${p.fileName} fold-ON script length moved`).toBe(1472);
        expect(sha256(off), `${p.fileName} fold-OFF bytes moved`).toBe(p.foldOff);
        expect(sha256(on), `${p.fileName} fold-ON bytes moved`).toBe(p.foldOn);
      } else {
        expect(off, `${p.fileName} fold-OFF bytes moved`).toBe(p.foldOff);
        expect(on, `${p.fileName} fold-ON bytes moved`).toBe(p.foldOn);
      }
    },
  );
});

// ---------------------------------------------------------------------------
// What the bytes are supposed to MEAN
// ---------------------------------------------------------------------------
//
// The pins above catch any movement; these say which behaviour the movement
// would break. Stateless witnesses only — W4 is a stateful continuation, whose
// spend-level coverage lives in branch-inherited-layout-directions-vm.test.ts.

describe('stack-frame byte pins: source and script still agree', () => {
  const CASES: Array<[Pin, Record<string, bigint | boolean>, Array<bigint | boolean>]> = [
    // x = a + p; accepts exactly when x <= 0.
    [W1, { p: 5n }, [-7n]],
    [W1, { p: 5n }, [-5n]],
    [W1, { p: 5n }, [1n]],
    [W1, { p: -3n }, [40n]],
    // x = a > 3 ? 49a^2 : 1; accepts exactly when x + p > 2.
    [W2, { p: 10n }, [9n]],
    [W2, { p: -5n }, [0n]],
    [W2, { p: -5n }, [9n]],
    [W2, { p: -5000n }, [9n]],
    // accepts only when q === false and b === false.
    [W3, { q: false }, [false]],
    [W3, { q: false }, [true]],
    [W3, { q: true }, [false]],
    [W3, { q: true }, [true]],
  ];

  it.each(CASES.map((c, i) => [i, c] as const))(
    'case %i: the interpreter and the deployed script reach the same verdict',
    (_i, [pin, constructorArgs, args]) => {
      const r = runDifferentialExecution({
        source: pin.source,
        fileName: pin.fileName,
        method: 'm',
        args,
        constructorArgs,
      });
      expect(
        r.vmAccepted,
        `${pin.fileName}(${JSON.stringify(args, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v))}): ` +
          `interpreter=${r.interpreterAccepted} script=${r.vmAccepted}`,
      ).toBe(r.interpreterAccepted);
    },
  );
});

// ---------------------------------------------------------------------------
// W5 — the empty-else reconcile condition (05-stack-lower.ts:3036)
// ---------------------------------------------------------------------------
//
// `if (elseBindings.length === 0 && thenName && elseCtx.stackMap.has(thenName))`
// selects "push a COPY of the then arm's rebound local into the empty else
// arm". No source program was found whose operands differ (an if-without-else
// always rebinds a local that exists in the parent), so this is hand-built
// `--ir` input, the same route as n262-nonempty-arm-padding.test.ts: the then
// arm computes a FRESH name `a` that the parent does not hold, the else arm is
// empty. The correct lowering pads the else arm with OP_0.
//
// MEASURED (LOGDIR mutants2.txt), both fold modes alike (IR input, nothing to
// fold): each of `&&` -> `||` (first, second, both) makes the compiler throw
// "Value 'a' not found on stack" instead of padding — so a throw here is the
// kill. Proves: the guard's three operands are load-bearing for this shape.
// Does not prove: the copy branch (all operands true) emits the right bytes —
// that is what the BranchResidue-style byte pins and the agreement cases do.
describe('stack-frame byte pins: empty-else reconcile condition (hand-built IR)', () => {
  const ir = JSON.stringify({
    contractName: 'P',
    properties: [],
    methods: [
      {
        name: 'm',
        isPublic: true,
        params: [{ name: 'x', type: 'bigint' }],
        body: [
          { name: 't0', value: { kind: 'load_param', name: 'x' } },
          { name: 't1', value: { kind: 'load_const', value: 0 } },
          { name: 't2', value: { kind: 'bin_op', op: '>', left: 't0', right: 't1' } },
          {
            name: 't3',
            value: {
              kind: 'if',
              cond: 't2',
              then: [{ name: 'a', value: { kind: 'load_const', value: 1 } }],
              else: [],
            },
          },
          { name: 't4', value: { kind: 'assert', value: 't3' } },
        ],
      },
    ],
  });

  it.each([true, false])('pads the empty else arm with OP_0 (disableConstantFolding=%s)', (off) => {
    expect(compileFromANF(loadANFFromJSON(ir), { disableConstantFolding: off }).scriptHex).toBe(
      '00a06351670068',
    );
  });
});
