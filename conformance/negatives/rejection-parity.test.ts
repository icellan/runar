import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  findGoBinary,
  findJavaJarPath,
  findPythonBinary,
  findRubyBinary,
  findRustBinary,
  findZigBinary,
} from '../runner/runner.js';

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

const REPO = resolve(__dirname, '../..');
const DIR = __dirname;

/** The seven tiers, by id. A tier silently vanishing from the matrix is the
 *  failure mode this list exists to make impossible — it is asserted below. */
const ALL_TIER_IDS = ['go', 'java', 'python', 'ruby', 'rust', 'ts', 'zig'] as const;

/**
 * Tier binaries are resolved through the RUNNER's own finders, never by
 * hardcoded paths. CI does not lay the tree out the way a local build does: the
 * conformance job downloads compiler artifacts to the REPO ROOT (`runar-go`,
 * `runar-compiler-rust`, `runar-zig`) and the Java compiler as a jar under
 * `compilers/java/build/libs/`, while a local build leaves them under
 * `compilers/<tier>/`. Hardcoding the local layout found exactly one tier in
 * CI, which the vacuity self-check below caught.
 *
 * `cmd` is the executable ONLY; everything else goes in `prefix`. Several of
 * the runner's finders return `"<interpreter> <script>"` as one space-joined
 * string, which is why they are split here rather than passed through.
 */
interface Tier {
  id: string;
  /** null when the toolchain is not built on this machine. */
  cmd: string | null;
  /** Argv that precedes the source-file arguments. */
  prefix: string[];
  /** Argv that follows `prefix`, given the source path. */
  argsFor: (src: string) => string[];
  cwd: string;
  timeoutMs: number;
}

/** Split a runner finder's `"ruby /path/to/script"` into cmd + args. */
function splitCmd(s: string | null): { cmd: string | null; args: string[] } {
  if (s === null) return { cmd: null, args: [] };
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0] ?? null, args: parts.slice(1) };
}

/**
 * Locate the tsx loader so the TS reference compiler can be driven as
 * `node --import <loader> packages/runar-cli/src/bin.ts`. Mirrors
 * `resolveTsxLoader` in runner.ts, which is module-private.
 */
function resolveTsxLoader(): string | null {
  for (const p of [
    join(REPO, 'conformance/node_modules/tsx/dist/loader.mjs'),
    join(REPO, 'node_modules/tsx/dist/loader.mjs'),
    join(REPO, 'integration/ts/node_modules/tsx/dist/loader.mjs'),
  ]) {
    if (existsSync(p)) return pathToFileURL(p).href;
  }
  return null;
}

const NATIVE_TIMEOUT = 120_000;
/** tsx pays a cold start on every spawn; the runner budgets 180s for the same
 *  invocation shape. */
const TS_TIMEOUT = 180_000;

function buildTiers(): Tier[] {
  const go = splitCmd(findGoBinary());
  const rust = splitCmd(findRustBinary());
  const zig = splitCmd(findZigBinary());
  const ruby = splitCmd(findRubyBinary());
  const python = splitCmd(findPythonBinary());
  const jar = findJavaJarPath();
  const tsxLoader = resolveTsxLoader();
  const tsCli = join(REPO, 'packages/runar-cli/src/bin.ts');

  return [
    {
      id: 'ts',
      // The reference tier has no standalone binary: it is the runar-cli
      // entrypoint under tsx, which is exactly how conformance/runner drives
      // it (`runTsCompiler`). `compile <file> --hex` is the same one-shot
      // source->hex contract the other six CLIs expose.
      cmd: tsxLoader && existsSync(tsCli) ? process.execPath : null,
      prefix: tsxLoader ? ['--import', tsxLoader, tsCli, 'compile'] : [],
      argsFor: (s) => [s, '--hex'],
      cwd: REPO,
      timeoutMs: TS_TIMEOUT,
    },
    {
      id: 'go',
      cmd: go.cmd,
      prefix: go.args,
      argsFor: (s) => ['--source', s, '--hex'],
      cwd: join(REPO, 'compilers/go'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'rust',
      cmd: rust.cmd,
      prefix: rust.args,
      argsFor: (s) => ['--source', s, '--hex'],
      cwd: join(REPO, 'compilers/rust'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'python',
      // findPythonBinary() returns "python3 -m runar_compiler"; it only
      // resolves from the package directory, hence the cwd.
      cmd: python.cmd,
      prefix: python.args,
      argsFor: (s) => ['--source', s, '--hex'],
      cwd: join(REPO, 'compilers/python'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'zig',
      cmd: zig.cmd,
      prefix: zig.args,
      argsFor: (s) => ['compile', s, '--hex'],
      cwd: join(REPO, 'compilers/zig'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'ruby',
      // findRubyBinary() returns "ruby <script>" — split, never passed whole.
      cmd: ruby.cmd,
      prefix: ruby.args,
      argsFor: (s) => ['--source', s, '--hex'],
      cwd: join(REPO, 'compilers/ruby'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'java',
      // Java ships as a jar, so the executable is `java` and the jar is the
      // first argument — it belongs in `prefix`, not at argv[0].
      cmd: jar ? 'java' : null,
      prefix: jar ? ['-jar', jar] : [],
      argsFor: (s) => ['--source', s, '--hex'],
      cwd: REPO,
      timeoutMs: NATIVE_TIMEOUT,
    },
  ];
}

const TIERS: Tier[] = buildTiers();

/** Ids of tiers with no toolchain on this machine. Extracted so the CI guard's
 *  predicate is itself testable — a guard nobody has watched fire is a guard. */
function missingTierIds(tiers: Tier[]): string[] {
  return tiers.filter((t) => t.cmd === null).map((t) => t.id);
}

/**
 * Signatures every CLI framework we drive emits for an unrecognized flag or a
 * usage error (Go `flag`, clap, argparse, Ruby OptionParser, commander, the
 * Java hand-rolled parser). Borrowed from runner.ts's `UNKNOWN_FLAG_RE`.
 *
 * A tier that answers with one of these did not judge the PROGRAM — it
 * rejected our command line. Counting that as "the language refused this
 * source" is the bare catch wearing a different hat.
 */
const USAGE_ERROR_RE =
  /flag provided but not defined|unexpected argument|unrecognized argument|unrecognized option|invalid option|unknown flag|unknown option|no such option|usage: |error: unexpected|too many arguments/i;

/**
 * Signatures emitted by the RUNTIME LAUNCHERS we go through (the JVM, node,
 * python3, ruby, /usr/bin/env) when the program never got as far as running.
 * These all arrive as a plain non-zero exit with a plausible-looking message
 * on stderr, which is precisely why the bare catch swallowed them.
 *
 * The concrete case: `java -jar /missing.jar` exits 1 with "Unable to access
 * jarfile". That is a launcher failure, not the Java tier's typechecker
 * declining a program — but nothing about the exit code distinguishes them.
 */
const LAUNCH_ERROR_RE =
  /unable to access jarfile|no main manifest attribute|could not find or load main class|cannot find module|modulenotfounderror|no such file or directory|command not found|permission denied|is a directory/i;

class BrokenTier extends Error {}

type Verdict = 'accepted' | 'rejected';

/**
 * Run one tier against one source and return its VERDICT, or throw
 * `BrokenTier` if the process never produced one.
 *
 * `rejected` requires all of:
 *   - the child spawned (no ENOENT/EACCES),
 *   - it exited under its own control (no signal, no timeout kill),
 *   - a non-zero exit status,
 *   - a non-empty diagnostic on stderr or stdout,
 *   - that diagnostic is not a usage/unknown-flag complaint.
 */
function verdict(tier: Tier, src: string): Verdict {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(src)];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });

  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;

  if (res.error) {
    throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  }
  if (res.signal !== null) {
    throw new BrokenTier(
      `${where} could not run to completion: killed by ${res.signal} ` +
        `(timeout is ${tier.timeoutMs}ms). A signalled child has no verdict.`,
    );
  }
  if (res.status === null) {
    throw new BrokenTier(`${where} could not run: no exit status`);
  }
  if (res.status === 0) return 'accepted';

  const diag = `${res.stderr ?? ''}\n${res.stdout ?? ''}`.trim();
  if (diag === '') {
    throw new BrokenTier(
      `${where} exited ${res.status} with an EMPTY diagnostic. A silent ` +
        `non-zero exit is a crash or a lost pipe, not a rejection.`,
    );
  }
  if (USAGE_ERROR_RE.test(diag)) {
    throw new BrokenTier(
      `${where} exited ${res.status} with a USAGE error, not a compile ` +
        `diagnostic — the harness is mis-driving this CLI:\n${diag.slice(0, 600)}`,
    );
  }
  if (LAUNCH_ERROR_RE.test(diag)) {
    throw new BrokenTier(
      `${where} exited ${res.status} with a LAUNCHER error — the compiler ` +
        `never started, so it has no opinion about this source:\n${diag.slice(0, 600)}`,
    );
  }
  return 'rejected';
}

const POSITIVE_CONTROL = join(DIR, 'positive-control.runar.ts');

/** Negative fixtures are `N<nn>-*.runar.ts`; the positive control is not. */
const fixtures = readdirSync(DIR)
  .filter((f) => /^N\d{2}-.*\.runar\.ts$/.test(f))
  .sort();

const available = TIERS.filter((t) => t.cmd !== null);

describe('cross-tier rejection parity', () => {
  // -- vacuity guards -------------------------------------------------------

  it('the matrix names all seven tiers (a silently dropped tier fails here)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
  });

  it('the corpus is non-empty (a silently empty gate proves nothing)', () => {
    expect(fixtures.length).toBeGreaterThanOrEqual(23);
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
