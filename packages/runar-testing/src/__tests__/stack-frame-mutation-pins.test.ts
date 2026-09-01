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
import { compile } from 'runar-compiler';
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
// `drainBranchPrivateResidue` removes slots a branch body introduced that the
// parent's model does not know about, deepest-first. The `depth === 1` arm
// emits OP_NIP; every other depth emits `push d; ROLL d; DROP`. Inverting the
// test emits the three-op sequence for depth 1 and a bare OP_NIP for depth 2+,
// which silently removes the WRONG slot.
//
// The residue here is the pre-branch binding of `merge0`, left below TOS
// because the arm rebinds it and the post-branch assert reads something else.
const W2: Pin = {
  fileName: 'BranchResidue.runar.ts',
  kills: '1125 (drainBranchPrivateResidue depth===1)',
  source: `import { SmartContract, assert } from 'runar-lang';

export class BranchResidue extends SmartContract {
  readonly p: bigint;

  constructor(p: bigint) {
    super(p);
    this.p = p;
  }

  public m(a: bigint): void {
    let merge0: bigint = ((66n << 1n) | 8982n);
    if ((a > 3n)) {
      merge0 = (97n - 8n);
    }
    assert((((-45n) + this.p) <= 28n));
  }
}
`,
  foldOff: '01425198021623857c53a063015967766877012d8f0093011ca177',
  foldOn: '01425198021623857c53a06301615801597b757767766877012d01ad0093011ca17777',
};

// ---------------------------------------------------------------------------
// W3 — if-without-else, arm result already present in the parent model
// ---------------------------------------------------------------------------
//
// `if (elseBindings.length === 0 && thenName && elseCtx.stackMap.has(thenName))`
// selects the empty-else reconcile. Turning either `&&` into `||` fires that
// reconcile for arms it was not written for; under folding ON the mutated
// compiler stops producing a script for this contract at all.
//
// The always-failing arm is load-bearing, not decoration: with a satisfiable
// arm the reconcile is reached by a path the mutation cannot distinguish. This
// is the `conformance/tests/assert-false-guard` family, one `if` deeper.
const W3: Pin = {
  fileName: 'EmptyElseGuard.runar.ts',
  kills: '2406 (empty-else reconcile, both &&)',
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
  foldOff: '00789b6351916968007c9b91',
  foldOn: '00789b63510069670068007b9b9177',
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
  // Stateful: ~1 KB of preimage machinery, so the pin is `sha256(scriptHex)`
  // rather than a kilobyte of literal hex. Same detection power; when it fires,
  // diff the two scripts rather than reading the digest.
  foldOff: '5702a5b2755c59ea57fee5b59b9304d0447868cc2793f3d75e0d122dc1baebf6',
  foldOn: 'd8c752ee2160480f1b3e87aedad6144a21aec4f160162813a4bf3cbea4c709b0',
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
        expect(off.length, `${p.fileName} fold-OFF script length moved`).toBe(1282);
        expect(on.length, `${p.fileName} fold-ON script length moved`).toBe(1300);
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
    // accepts exactly when p <= 73; `a` picks the branch.
    [W2, { p: 10n }, [9n]],
    [W2, { p: 10n }, [0n]],
    [W2, { p: 500n }, [9n]],
    [W2, { p: 500n }, [0n]],
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
