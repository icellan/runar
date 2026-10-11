import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  BrokenTier,
  IR_TIER_IDS,
  REPO,
  Tier,
  buildIrTiers,
  missingTierIds,
  verdict,
} from './tier-harness.js';

/**
 * Cross-tier REJECTION parity on the `--ir` path.
 *
 * ---------------------------------------------------------------------------
 * N-112 — why this file exists
 * ---------------------------------------------------------------------------
 *
 * `rejection-parity.test.ts` drives each tier's `--source` CLI. That gate is
 * real, but it covers exactly one of the compiler's two front doors. The other
 * one is `--ir`, which takes ANF IR JSON from OUTSIDE the compiler and skips
 * parse / validate / typecheck entirely — every rule the frontend enforces is,
 * on that path, enforced only by whatever the IR loader happens to re-check.
 *
 * Nothing gated it. The consequence was not hypothetical: R-079, R-081, R-086,
 * R-087, N-111 and N-115 are all `--ir`-path defects, and they could coexist in
 * six tiers at once because no test in the repo compared the tiers' answers to
 * malformed IR. The positive `--ir-parity` runner (runner.ts
 * `runAllIrParityChecks`) compares emitted BYTES for IR the compiler itself
 * produced — by construction it never sees an input a tier should refuse.
 *
 * So: same gate, other door. Every fixture here is IR that no tier should
 * accept, and every available tier must refuse all of them.
 *
 * ---------------------------------------------------------------------------
 * Six tiers, not seven
 * ---------------------------------------------------------------------------
 *
 * TypeScript is absent BY DESIGN and this is the one place it is legitimate.
 * The reference tier ships no IR-consuming CLI mode at all; `runar-cli compile`
 * takes source. runner.ts's `IR_PARITY_COMPILERS` excludes `ts` for the same
 * reason on the positive side. `IR_TIER_IDS` in the harness records that, and
 * the vacuity guard below asserts the matrix matches it — so a tier dropping
 * out of this lane still fails loudly, which is the property R-100 was about.
 *
 * ---------------------------------------------------------------------------
 * The corpus lives in ./ir/, not alongside the source fixtures
 * ---------------------------------------------------------------------------
 *
 * `rejection-parity.test.ts` globs `N<nn>-*.runar.<ext>` out of this directory.
 * IR fixtures are neither Rúnar source nor written in any of the nine frontend
 * surfaces, and driving one through `--source` would produce a parse error that
 * looks like a pass while proving nothing about the IR loader. A separate
 * directory with a separate extension (`I<nn>-*.ir.json`) makes it impossible
 * for a fixture to be picked up by the wrong lane, which overloading the
 * existing glob would not.
 *
 * ---------------------------------------------------------------------------
 * The gate grades DISCRIMINATION, not prose
 * ---------------------------------------------------------------------------
 *
 * Inherited from R-100 and reinforced by what the six tiers actually emit here.
 * Their IR diagnostics are not a common vocabulary and cannot be made into one:
 * Go/Rust/Ruby/Python share an `IR validation: ...` sentence, Java prefixes
 * `runar-java: ir parse error: ...`, and Zig's IR loader is an error-enum
 * channel with no message payload at all — it prints `error: InvalidConstValue`
 * for both a non-hex body and an odd-length one. An assertion on wording would
 * gate Zig's error names, not its behaviour.
 *
 * What makes a "rejects" row mean something is therefore the same thing that
 * makes it mean something in the source lane: the POSITIVE CONTROL. Every tier
 * must be observed ACCEPTING valid IR before its refusals count. A tier whose
 * `--ir` mode is broken, missing, or mis-driven fails that test first, so a
 * lane that rejects everything cannot post a perfect score.
 *
 * The controls are not hand-written approximations of valid IR — they are
 * checked-in goldens (`asm-raw-script`, and `bounded-loop` for the fixtures
 * that need a `loop` binding), used in place, and every negative fixture here
 * is one of those files with ONE field changed. A probe whose control also
 * fails proves nothing; deriving the probe and its control from the same
 * golden is what keeps them honest.
 */

const DIR = join(__dirname, 'ir');

/**
 * Valid IR every tier must accept: the compiler's own output for the
 * `asm-raw-script` conformance fixture, read from the golden tree rather than
 * copied here. It has no `compilers` allowlist, so all six tiers are in scope
 * for it, and it exercises `raw_script` — the value kind half this corpus is
 * about — with a well-formed body.
 */
const POSITIVE_CONTROL = join(REPO, 'conformance/tests/asm-raw-script/expected-ir.json');

/**
 * The second control, for the fixtures that cannot be derived from the first.
 *
 * N-115 is about a `loop` binding's `count`, and `asm-raw-script` contains no
 * loop — so `I07` is "the checked-in golden with ONE field changed" against
 * `bounded-loop` instead. The rule that makes these fixtures mean anything is
 * that their control is a real golden every tier accepts, not which golden it
 * is, so a fixture derived from a second golden needs that second golden
 * observed being accepted. `bounded-loop` qualifies on the same terms as
 * `asm-raw-script`: it is checked in, it carries no `compilers` allowlist, and
 * all six IR tiers emit identical bytes for it
 * (000052797b7c937c935152...547b7b7c937c93009c).
 *
 * Without this row, N-115's negative would have been graded against a control
 * that never exercised the code path it probes.
 */
const LOOP_POSITIVE_CONTROL = join(REPO, 'conformance/tests/bounded-loop/expected-ir.json');

/**
 * The third control. `I08` (N-111) is about a `method_call`'s argument list,
 * and neither golden above contains one. `multi-method` does — a two-argument
 * call to the private helper `computeThreshold` — carries no `compilers`
 * allowlist, and all six IR tiers emit
 * `76009c637552958b5aa06900ac67519d00ac68` for it.
 */
const METHOD_CALL_POSITIVE_CONTROL = join(REPO, 'conformance/tests/multi-method/expected-ir.json');

/**
 * The fourth control. `I24`-`I27` (N-132) are about a PROPERTY's
 * `initialValue`, and none of the three goldens above carries one that the
 * locking script pushes. `fixed-array-index` carries four, each of which does
 * move bytes when edited; it has no `compilers` allowlist, and all six IR
 * tiers emit `7891635a7b756778519c6301147b75677c529c63011e6701286868687c9c`
 * for it.
 *
 * (`property-initializers` also has an `initialValue`, but its only bigint
 * one is a mutable state field the locking script never pushes: changing it
 * moves no bytes on any tier, so a probe derived from it would be graded
 * against a control that never exercised the code path.)
 */
const PROPERTY_INIT_POSITIVE_CONTROL = join(
  REPO,
  'conformance/tests/fixed-array-index/expected-ir.json',
);

/**
 * The fifth control. `I43`-`I46` (N-059) are about a `check_preimage`
 * binding's `sighashFlag`, and none of the goldens above contains a
 * `check_preimage`. `stateful-counter` does (`increment`'s `t1`); it has no
 * `compilers` allowlist and all six IR tiers emit its golden bytes.
 */
const CHECK_PREIMAGE_POSITIVE_CONTROL = join(
  REPO,
  'conformance/tests/stateful-counter/expected-ir.json',
);

/*
 * `I47`-`I52` (N-087, the parentClass and property-write rules) reuse three
 * controls above: `multi-method` (I47 one property made mutable; I52 the same
 * with parentClass also removed, so the fail-closed inference is exercised),
 * `stateful-counter` (I48 relabelled SmartContract; I49 `count` made readonly,
 * so `increment` writes a readonly property; I51 relabelled AND every property
 * made readonly, so the stateful-only nodes are the only violation) and
 * `asm-raw-script` (I50 relabelled SmartContract). I51 and I52 change two
 * fields because their rule cannot be reached with one.
 */

/*
 * `I53`-`I56` (N-101, the re-derived StatefulSmartContract scaffolding) reuse
 * the `stateful-counter` control, each with ONE field of `increment` changed:
 * I53 the continuation compares the output hash with itself; I54 the
 * sighash-type assert pins 67 instead of 65; I55 the checkPreimage assert
 * asserts the preimage instead of the check's result; I56 the auto-injected
 * `_newAmount` parameter is retyped ByteString.
 */

/*
 * `I57` (N-096, the syntheticArrayChain rule) reuses the `fixed-array-index`
 * control with ONE field changed: `table__0`'s chain repeated to 1024 levels,
 * one past the deepest chain the artifact regrouper can consume. Go panicked
 * on such a chain (exit 2); Python, Java, Zig and TS compiled it.
 */

/*
 * `I58` (F-283 / CL-GAP-164, the nested-loop PRODUCT bound) reuses the
 * `bounded-loop` control with the `verify` method's one `loop` binding
 * changed: its `count` set to 10,000 and its `body` wrapped in a second
 * `loop` of count 10,000 (the original body becomes that inner loop's
 * body). Each of the two counts individually satisfies MAX_LOOP_COUNT
 * (10,000) — the per-binding bound I07 already covers — but their product
 * is 100,000,000. Every tier bounded the single count; before this fix none
 * bounded the product.
 *
 * `I59` (F-357) reuses the `bounded-loop` control with ONE field changed:
 * the `loop` binding's `step` is the string `"abc"` instead of an integer.
 * Go, Rust, Python, Ruby and Java all already refuse this (their JSON
 * decoders type-check the field on the way in); Zig's hand-rolled loader
 * read it through `if (obj.get("step")) |v| switch (v) { .integer => ...,
 * .float => ..., else => 1 }` — a wrong-typed value fell into the same
 * `else` arm as a genuinely absent one and silently became the commonest
 * step value (1) instead of an error. (I58 is F-283's.)
 */

/** Every golden a fixture in this lane is derived from. */
const POSITIVE_CONTROLS: ReadonlyArray<readonly [string, string]> = [
  ['asm-raw-script', POSITIVE_CONTROL],
  ['bounded-loop', LOOP_POSITIVE_CONTROL],
  ['multi-method', METHOD_CALL_POSITIVE_CONTROL],
  ['fixed-array-index', PROPERTY_INIT_POSITIVE_CONTROL],
  ['stateful-counter', CHECK_PREIMAGE_POSITIVE_CONTROL],
];

const fixtures = readdirSync(DIR)
  .filter((f) => /^I\d{2}-.*\.ir\.json$/.test(f))
  .sort();

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

describe('cross-tier rejection parity (--ir path)', () => {
  // -- vacuity guards -------------------------------------------------------

  it('the matrix names all six IR-capable tiers (a dropped tier fails here)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('the corpus is non-empty and every control is a checked-in golden', () => {
    expect(fixtures.length).toBeGreaterThanOrEqual(4);
    for (const [name, path] of POSITIVE_CONTROLS) {
      expect(existsSync(path), `${name} golden is missing`).toBe(true);
    }
  });

  it('the missing-tier predicate actually detects a missing tier', () => {
    const withHole: Tier[] = [
      ...TIERS,
      { id: 'ghost', cmd: null, prefix: [], argsFor: () => [], cwd: REPO, timeoutMs: 1 },
    ];
    expect(missingTierIds(withHole)).toContain('ghost');
    expect(missingTierIds(TIERS)).not.toContain('ghost');
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = missingTierIds(TIERS);
    if (process.env.CI === 'true') {
      expect(
        missing,
        `CI=true but these tiers have no toolchain: ${missing.join(', ')}. ` +
          `The matrix would silently shrink and still report PASS.`,
      ).toEqual([]);
    }
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  // -- positive control -----------------------------------------------------
  //
  // The strongest guard in the file. A tier that cannot be observed accepting
  // valid IR is not a witness to anything when it "rejects" invalid IR — and
  // on this lane that is the likeliest failure of all, because `--ir` is a
  // different argv shape per tier (Zig's is a positional subcommand) and a
  // mis-driven CLI refuses everything it is handed.

  for (const tier of available) {
    for (const [name, path] of POSITIVE_CONTROLS) {
      it(`${tier.id} ACCEPTS the ${name} control IR (else its rejections are vacuous)`, () => {
        expect(
          verdict(tier, path),
          `${tier.id} did not accept valid IR its own peers emit. Every ` +
            `"rejects" row for this tier below is therefore meaningless — the ` +
            `tier's --ir mode is either mis-invoked or broken.`,
        ).toBe('accepted');
      });
    }
  }

  // -- the gate itself ------------------------------------------------------

  for (const fixture of fixtures) {
    const input = join(DIR, fixture);
    for (const tier of available) {
      it(`${tier.id} rejects ${fixture}`, () => {
        expect(
          verdict(tier, input),
          `${tier.id} ACCEPTED ${fixture} on the --ir path. The --ir loader is ` +
            `a trust boundary: it takes IR from outside the compiler and skips ` +
            `parse/validate/typecheck, so a rule its peers enforce here is the ` +
            `only thing standing between malformed IR and an emitted locking ` +
            `script.`,
        ).toBe('rejected');
      });
    }
  }

  // -- the verdict function's own contract, on THIS lane --------------------
  //
  // R-100's regression tests, re-run against the IR argv shapes. The failure
  // they encode is lane-independent (a tier that cannot start scores a perfect
  // rejection rate) but the argv is not, and it is the argv this lane gets
  // wrong: three of the six tiers take `--ir`, one takes a positional
  // subcommand, and two are launched through a runtime.

  describe('verdict() distinguishes a rejection from a broken run', () => {
    const witness = available[0];

    it('a tier that is ABSENT is BROKEN, not "rejected"', () => {
      const absent: Tier = {
        id: 'absent',
        cmd: null,
        prefix: [],
        argsFor: (p) => ['--ir', p, '--hex'],
        cwd: REPO,
        timeoutMs: 10_000,
      };
      // This is the precise claim "a lane that rejects everything cannot post
      // a perfect score" rests on: an unbuilt tier yields no verdict at all,
      // so it can neither accept nor reject its way to a green row.
      expect(() => verdict(absent, POSITIVE_CONTROL)).toThrow(BrokenTier);
    });

    it('a nonexistent executable is BROKEN, not "rejected"', () => {
      const dead: Tier = {
        id: 'dead',
        cmd: join(REPO, 'no/such/compiler-binary'),
        prefix: [],
        argsFor: (p) => ['--ir', p, '--hex'],
        cwd: REPO,
        timeoutMs: 10_000,
      };
      expect(() => verdict(dead, POSITIVE_CONTROL)).toThrow(/could not run/i);
    });

    it('a nonexistent jar is BROKEN, not "rejected"', () => {
      const deadJar: Tier = {
        id: 'dead-java',
        cmd: 'java',
        prefix: ['-jar', join(REPO, 'no/such/runar.jar')],
        argsFor: (p) => ['--ir', p, '--hex'],
        cwd: REPO,
        timeoutMs: 60_000,
      };
      expect(() => verdict(deadJar, POSITIVE_CONTROL)).toThrow(BrokenTier);
    });

    it('an interpreter command passed unsplit is BROKEN, not "rejected"', () => {
      const unsplit: Tier = {
        id: 'unsplit-ruby',
        cmd: `ruby ${join(REPO, 'compilers/ruby/bin/runar-compiler-ruby')}`,
        prefix: [],
        argsFor: (p) => ['--ir', p, '--hex'],
        cwd: join(REPO, 'compilers/ruby'),
        timeoutMs: 10_000,
      };
      expect(() => verdict(unsplit, POSITIVE_CONTROL)).toThrow(/could not run/i);
    });

    it('a bad argv is BROKEN, not "rejected"', () => {
      const badArgv: Tier = {
        ...witness!,
        id: `${witness!.id}-bad-argv`,
        argsFor: (p) => ['--definitely-not-a-real-flag', p],
      };
      expect(() => verdict(badArgv, POSITIVE_CONTROL)).toThrow(BrokenTier);
    });

    // The lane-specific mis-drive, and the one most likely to happen by
    // accident: Zig's IR consumer is `compile-ir <file>`, NOT `--ir <file>`.
    // Handing it the other five tiers' argv makes it refuse every input,
    // including the positive control — a perfect 100% rejection rate from a
    // tier that never read a byte of IR.
    it('driving a positional-subcommand tier with the --ir flag is BROKEN', () => {
      const zig = available.find((t) => t.id === 'zig');
      if (!zig) return; // Zig not built locally; CI's build guard above covers it.
      const misdriven: Tier = {
        ...zig,
        id: 'zig-misdriven',
        argsFor: (p) => ['--ir', p, '--hex'],
      };
      expect(() => verdict(misdriven, POSITIVE_CONTROL)).toThrow(BrokenTier);
    });
  });
});
