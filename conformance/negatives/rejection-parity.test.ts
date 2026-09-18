import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  ALL_TIER_IDS,
  BrokenTier,
  REPO,
  Tier,
  buildSourceTiers,
  missingTierIds,
  verdict,
} from './tier-harness.js';

/**
 * Cross-tier REJECTION parity.
 *
 * CLAUDE.md's first invariant is frontend parity with no exceptions, but every
 * gate we had measured it on programs that COMPILE: the conformance corpus,
 * the parser-only matrix, the fuzzers. Nothing checked that the seven tiers
 * agree on what to REFUSE.
 *
 * That gap let a real defect reach RC. The Go tier's tree-sitter walk silently
 * dropped any statement it could not parse, so `this.value = ;` compiled to a
 * locking script with the state write missing, and `assert(claim ==)` to one
 * with the spending guard missing — while the other six tiers rejected both.
 * A corpus of programs that must NOT compile is the only thing that catches
 * that class, so it lives here as a gate rather than in an audit directory.
 *
 * Each fixture is malformed or violates the language subset. Every available
 * tier must refuse all of them. A tier that accepts one is either missing a
 * rule its peers enforce or, worse, silently discarding the offending code.
 *
 * ---------------------------------------------------------------------------
 * R-100 — two ways this gate was lying about its own coverage
 * ---------------------------------------------------------------------------
 *
 * 1. The matrix listed five tiers. TypeScript — the REFERENCE implementation
 *    every other tier is defined against — and Python were simply absent, so
 *    "all tiers reject this" was never a claim about the reference tier.
 *
 * 2. The verdict was a bare `try { run() } catch { return REJECTED }`. Any
 *    failure whatsoever scored as a clean rejection: a missing jar, a bad
 *    argv, a segfault on startup, a timeout. A compiler that could not launch
 *    at all therefore posted a perfect score.
 *
 *    That was not hypothetical. `findRubyBinary()` returns the string
 *    `"ruby /path/to/runar-compiler-ruby"` — a command AND its argument — and
 *    it was handed to `execFileSync` as a single executable name, which is
 *    ENOENT every time. The Java row destructured `['-jar', jar, ...]` into
 *    `cmd = '-jar'`, spawning a program named `-jar`. Neither tier ever ran a
 *    single fixture; both showed 13/13 green. The whole suite finished in
 *    450ms, which is less than one JVM cold start.
 *
 *    This repo has been bitten by this exact shape before (the Zig merge
 *    negatives passed against an unrelated SDK bug), and the rule written down
 *    from it is: a bare catch is not a rejection assertion.
 *
 * The fix has three parts, in increasing order of strength:
 *
 *   a. A rejection now requires a VERDICT: the child must exit under its own
 *      control (no spawn error, no signal), with a non-zero status, and with a
 *      diagnostic on stderr/stdout. Anything else throws `BrokenTier` and
 *      fails the test loudly instead of being counted as a pass.
 *   b. A usage/unknown-flag diagnostic is classified BROKEN, not rejected —
 *      that is the harness mis-driving the CLI, not the language refusing a
 *      program. This is deliberately the only wording the gate looks at:
 *      matching each tier's error prose would couple the gate to seven
 *      independently-worded diagnostics for no extra safety.
 *   c. A POSITIVE CONTROL. Every tier must ACCEPT `positive-control.runar.ts`.
 *      This is the guard that actually kills the class, because it is
 *      wording-independent: a tier only counts as a witness if it has been
 *      observed to say yes to good code and no to bad code. Grade the
 *      discrimination, not the prose.
 *
 * ---------------------------------------------------------------------------
 * Known limit of this gate, found by widening it (R-100)
 * ---------------------------------------------------------------------------
 *
 * The gate measures the CLI's exit status, which is the whole compiler. It
 * cannot see WHICH PASS refused. That distinction turned out to matter:
 *
 *   N07-undeclared-var is rejected by six tiers in the TYPECHECKER. The Java
 *   tier's frontend USED TO ACCEPT it — `ParserDispatch.parse -> Validate.run
 *   -> ExpandFixedArrays.run -> Typecheck.run` all passed, and the only thing
 *   that stopped it was a defensive guard in stack lowering ("Refusing to emit
 *   a silent OP_0 placeholder"), exiting 70 (EX_SOFTWARE) where every other
 *   negative exits 65 (EX_DATAERR). That made `runar.lang.sdk.CompileCheck` —
 *   the frontend-only API a Java contract author calls to ask "is this valid
 *   Rúnar?" — green-light N07.
 *
 *   R-092 fixed it at the root: `neverDeclared` infers as `<unknown>`, and the
 *   Java typechecker carried an `&& !"<unknown>".equals(t)` escape at eight
 *   operand checks that its six peers do not have. Deleting those escapes moved
 *   the rejection into the typechecker ("left operand of '>' must be bigint,
 *   got '<unknown>'") and the exit code to 65. N15 below is the fixture for the
 *   operand shape itself.
 *
 *   The structural limit still stands: this gate measures the CLI, so it cannot
 *   SEE which pass refused. Proving the frontend is the one that refuses needs
 *   a per-tier frontend driver the CLIs do not expose (`--parse-only` stops
 *   before typecheck); for the Java tier that assertion lives in
 *   `compilers/java/.../R092UnknownOperandRejectionTest`.
 */

const DIR = __dirname;

/**
 * The tier matrix and the `verdict()` contract live in `./tier-harness.ts`.
 *
 * They were extracted there (N-112) when the `--ir` lane was added, because
 * R-100's finding was precisely that a second, weaker verdict mechanism is how
 * a gate ends up scoring dead tiers as perfect. One `verdict()`, two lanes.
 */
const TIERS: Tier[] = buildSourceTiers();

const POSITIVE_CONTROL = join(DIR, 'positive-control.runar.ts');

/**
 * Negative fixtures are `N<nn>-*.runar.<ext>`; the positive control is not.
 *
 * Every one of the nine frontend surfaces is eligible, not just `.runar.ts`.
 * N-108 is the reason: `Sha256Digest` is a name the reference tier resolves on
 * seven surfaces and refuses on `.runar.sol` / `.runar.move`, so the rule it
 * breaks is only expressible in a fixture written in those languages. A corpus
 * that could only hold TypeScript could not gate a per-surface rule at all —
 * which is how a one-tier acceptance survived on `.sol` unnoticed.
 */
const fixtures = readdirSync(DIR)
  .filter((f) => /^N\d{2}-.*\.runar\.(ts|sol|move|go|rs|py|zig|rb|java)$/.test(f))
  .sort();

const available = TIERS.filter((t) => t.cmd !== null);

describe('cross-tier rejection parity', () => {
  // -- vacuity guards -------------------------------------------------------

  it('the matrix names all seven tiers (a silently dropped tier fails here)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
  });

  it('the corpus is non-empty (a silently empty gate proves nothing)', () => {
    expect(fixtures.length).toBeGreaterThanOrEqual(28);
    expect(existsSync(POSITIVE_CONTROL)).toBe(true);
  });

  /**
   * Local devs rarely have all seven toolchains. CI has no such excuse, and a
   * conformance job that reports PASS while a tier never ran is the exact
   * failure `assertAllCompilersAvailableInCi` (runner.ts) was added to stop —
   * same idea, same CI gate, enforced as an assertion rather than an exit.
   */
  it('the missing-tier predicate actually detects a missing tier', () => {
    // Exercises the CI guard's logic without needing to uninstall a toolchain.
    const withHole: Tier[] = [
      ...TIERS,
      { id: 'ghost', cmd: null, prefix: [], argsFor: () => [], cwd: REPO, timeoutMs: 1 },
    ];
    expect(missingTierIds(withHole)).toContain('ghost');
    expect(missingTierIds(TIERS)).not.toContain('ghost');
  });

  it('every tier is built (strict in CI, ">=2" locally)', () => {
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
  // The strongest guard in the file: a tier that cannot be observed accepting
  // valid Rúnar is not a witness to anything when it "rejects" invalid Rúnar.

  for (const tier of available) {
    it(`${tier.id} ACCEPTS the positive control (else its rejections are vacuous)`, () => {
      expect(
        verdict(tier, POSITIVE_CONTROL),
        `${tier.id} did not accept a valid contract. Every "rejects" row for ` +
          `this tier below is therefore meaningless — the tier is either ` +
          `mis-invoked or broken.`,
      ).toBe('accepted');
    });
  }

  // -- the gate itself ------------------------------------------------------

  for (const fixture of fixtures) {
    const src = join(DIR, fixture);
    for (const tier of available) {
      it(`${tier.id} rejects ${fixture}`, () => {
        expect(
          verdict(tier, src),
          `${tier.id} ACCEPTED ${fixture}. Either the tier is missing a rule its ` +
            `peers enforce, or it is silently dropping the offending construct — ` +
            `the latter emits a locking script for a program no other tier accepts.`,
        ).toBe('rejected');
      });
    }
  }

  // -- the verdict function's own contract ----------------------------------
  //
  // These are the regression tests for the bare catch. Without them nothing
  // stops a future edit from collapsing `verdict` back to try/catch->false.

  describe('verdict() distinguishes a rejection from a broken run', () => {
    const witness = available[0];

    it('a nonexistent executable is BROKEN, not "rejected"', () => {
      const dead: Tier = {
        id: 'dead',
        cmd: join(REPO, 'no/such/compiler-binary'),
        prefix: [],
        argsFor: (s) => ['--source', s, '--hex'],
        cwd: REPO,
        timeoutMs: 10_000,
      };
      expect(() => verdict(dead, POSITIVE_CONTROL)).toThrow(/could not run/i);
    });

    // The historical Java row. `java -jar /missing.jar` SPAWNS FINE and exits
    // 1 with a message on stderr — indistinguishable from a compile error by
    // exit code alone, and counted as 13/13 green by the old bare catch.
    it('a nonexistent jar is BROKEN, not "rejected"', () => {
      const deadJar: Tier = {
        id: 'dead-java',
        cmd: 'java',
        prefix: ['-jar', join(REPO, 'no/such/runar.jar')],
        argsFor: (s) => ['--source', s, '--hex'],
        cwd: REPO,
        timeoutMs: 60_000,
      };
      expect(() => verdict(deadJar, POSITIVE_CONTROL)).toThrow(BrokenTier);
    });

    // The historical Ruby row: the finder returns "ruby <script>" and the old
    // code handed that whole string to execFileSync as one executable name.
    it('an interpreter command passed unsplit is BROKEN, not "rejected"', () => {
      const unsplit: Tier = {
        id: 'unsplit-ruby',
        cmd: `ruby ${join(REPO, 'compilers/ruby/bin/runar-compiler-ruby')}`,
        prefix: [],
        argsFor: (s) => ['--source', s, '--hex'],
        cwd: join(REPO, 'compilers/ruby'),
        timeoutMs: 10_000,
      };
      expect(() => verdict(unsplit, POSITIVE_CONTROL)).toThrow(/could not run/i);
    });

    it('a bad argv is BROKEN, not "rejected"', () => {
      const badArgv: Tier = {
        ...witness!,
        id: `${witness!.id}-bad-argv`,
        argsFor: (s) => ['--definitely-not-a-real-flag', s],
      };
      expect(() => verdict(badArgv, POSITIVE_CONTROL)).toThrow(BrokenTier);
    });
  });
});
