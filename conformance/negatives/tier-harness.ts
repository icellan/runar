import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
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
 * Shared tier-driving machinery for the cross-tier REJECTION gates.
 *
 * Extracted verbatim from `rejection-parity.test.ts` (R-100) when the `--ir`
 * lane was added (N-112). The extraction is deliberate rather than incidental:
 * R-100's whole finding was that a second, weaker verdict mechanism is how a
 * gate ends up scoring dead tiers as perfect. There is exactly ONE `verdict()`
 * in this directory and both lanes go through it.
 *
 * See rejection-parity.test.ts's header for the full R-100 rationale. The
 * short version, because it governs every edit to this file:
 *
 *   - a bare `catch` is not a rejection assertion;
 *   - a rejection requires a VERDICT — spawned, exited under its own control,
 *     non-zero, with a diagnostic that is neither a usage nor a launcher error;
 *   - anything else throws `BrokenTier` and fails loudly;
 *   - and the gate grades DISCRIMINATION (yes to good input, no to bad input),
 *     never prose.
 */

export const REPO = resolve(__dirname, '../..');

/** The seven tiers, by id. A tier silently vanishing from a matrix is the
 *  failure mode this list exists to make impossible. */
export const ALL_TIER_IDS = ['go', 'java', 'python', 'ruby', 'rust', 'ts', 'zig'] as const;

/**
 * The six tiers with an `--ir` CLI mode.
 *
 * TypeScript is absent BY DESIGN, not by oversight: the reference tier has no
 * IR-consuming CLI mode at all, which is why `IR_PARITY_COMPILERS`
 * (runner.ts) excludes it from the positive `--ir` parity run too. The `--ir`
 * lane is therefore a six-tier gate, and this constant is asserted against
 * that one so the two never drift apart.
 */
export const IR_TIER_IDS = ['go', 'java', 'python', 'ruby', 'rust', 'zig'] as const;

/**
 * Tier binaries are resolved through the RUNNER's own finders, never by
 * hardcoded paths. CI does not lay the tree out the way a local build does: the
 * conformance job downloads compiler artifacts to the REPO ROOT (`runar-go`,
 * `runar-compiler-rust`, `runar-zig`) and the Java compiler as a jar under
 * `compilers/java/build/libs/`, while a local build leaves them under
 * `compilers/<tier>/`. Hardcoding the local layout found exactly one tier in
 * CI, which the vacuity self-check catches.
 *
 * `cmd` is the executable ONLY; everything else goes in `prefix`. Several of
 * the runner's finders return `"<interpreter> <script>"` as one space-joined
 * string, which is why they are split here rather than passed through.
 */
export interface Tier {
  id: string;
  /** null when the toolchain is not built on this machine. */
  cmd: string | null;
  /** Argv that precedes the input-file arguments. */
  prefix: string[];
  /** Argv that follows `prefix`, given the input path. */
  argsFor: (input: string) => string[];
  cwd: string;
  timeoutMs: number;
}

/** Split a runner finder's `"ruby /path/to/script"` into cmd + args. */
export function splitCmd(s: string | null): { cmd: string | null; args: string[] } {
  if (s === null) return { cmd: null, args: [] };
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0] ?? null, args: parts.slice(1) };
}

/**
 * Locate the tsx loader so the TS reference compiler can be driven as
 * `node --import <loader> packages/runar-cli/src/bin.ts`. Mirrors
 * `resolveTsxLoader` in runner.ts, which is module-private.
 */
export function resolveTsxLoader(): string | null {
  for (const p of [
    join(REPO, 'conformance/node_modules/tsx/dist/loader.mjs'),
    join(REPO, 'node_modules/tsx/dist/loader.mjs'),
    join(REPO, 'integration/ts/node_modules/tsx/dist/loader.mjs'),
  ]) {
    if (existsSync(p)) return pathToFileURL(p).href;
  }
  return null;
}

export const NATIVE_TIMEOUT = 120_000;
/** tsx pays a cold start on every spawn; the runner budgets 180s for the same
 *  invocation shape. */
export const TS_TIMEOUT = 180_000;

/** The seven tiers driven through their one-shot `source -> hex` CLI. */
export function buildSourceTiers(): Tier[] {
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

/**
 * The six tiers driven through their `IR JSON -> hex` CLI mode.
 *
 * The argv shapes are NOT invented here — they are the ones
 * `runIrToHex()` in runner.ts uses for the positive `--ir-parity` run, copied
 * deliberately so this gate exercises the same entrypoint the parity run
 * measures. In particular Zig's IR consumer is a positional subcommand
 * (`compile-ir <file>`) and takes no fold flag, which is exactly the kind of
 * per-tier detail that, got wrong, produces a usage error the old bare catch
 * would have scored as a clean rejection.
 */
export function buildIrTiers(): Tier[] {
  const go = splitCmd(findGoBinary());
  const rust = splitCmd(findRustBinary());
  const zig = splitCmd(findZigBinary());
  const ruby = splitCmd(findRubyBinary());
  const python = splitCmd(findPythonBinary());
  const jar = findJavaJarPath();

  const irArgs = (p: string) => ['--ir', p, '--hex', '--disable-constant-folding'];

  return [
    {
      id: 'go',
      cmd: go.cmd,
      prefix: go.args,
      argsFor: irArgs,
      cwd: join(REPO, 'compilers/go'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'rust',
      cmd: rust.cmd,
      prefix: rust.args,
      argsFor: irArgs,
      cwd: join(REPO, 'compilers/rust'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'python',
      cmd: python.cmd,
      prefix: python.args,
      argsFor: irArgs,
      cwd: join(REPO, 'compilers/python'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'zig',
      cmd: zig.cmd,
      prefix: zig.args,
      // Positional subcommand, no fold flag — see runner.ts `runIrToHex`.
      argsFor: (p) => ['compile-ir', p, '--hex'],
      cwd: join(REPO, 'compilers/zig'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'ruby',
      cmd: ruby.cmd,
      prefix: ruby.args,
      argsFor: irArgs,
      cwd: join(REPO, 'compilers/ruby'),
      timeoutMs: NATIVE_TIMEOUT,
    },
    {
      id: 'java',
      cmd: jar ? 'java' : null,
      prefix: jar ? ['-jar', jar] : [],
      argsFor: irArgs,
      cwd: REPO,
      timeoutMs: NATIVE_TIMEOUT,
    },
  ];
}

/** Ids of tiers with no toolchain on this machine. Extracted so the CI guard's
 *  predicate is itself testable — a guard nobody has watched fire is a guess. */
export function missingTierIds(tiers: Tier[]): string[] {
  return tiers.filter((t) => t.cmd === null).map((t) => t.id);
}

/**
 * Signatures every CLI framework we drive emits for an unrecognized flag or a
 * usage error (Go `flag`, clap, argparse, Ruby OptionParser, commander, the
 * Java hand-rolled parser). Borrowed from runner.ts's `UNKNOWN_FLAG_RE`.
 *
 * A tier that answers with one of these did not judge the PROGRAM — it
 * rejected our command line. Counting that as "the language refused this
 * input" is the bare catch wearing a different hat.
 *
 * N-112 narrowed one alternative. R-100's list carried `error: unexpected`,
 * intended for clap's `error: unexpected argument '--foo' found`. It is
 * REDUNDANT for that case — `unexpected argument` already matches it — and
 * over-broad for every other, which the `--ir` lane caught the moment it ran:
 *
 *   zig   `error: UnexpectedEndOfInput`              (truncated IR JSON)
 *   java  `ir parse error: unexpected end of input`  (truncated IR JSON)
 *
 * Both are the loader judging the input, and both were being reclassified as
 * "the harness is mis-driving this CLI". The filter must err toward BROKEN
 * when it is genuinely ambiguous, but not toward BROKEN on a substring that
 * adds nothing — a gate that cannot see a real rejection is as useless as one
 * that cannot see a fake one.
 */
export const USAGE_ERROR_RE =
  /flag provided but not defined|unexpected argument|unrecognized argument|unrecognized option|invalid option|unknown flag|unknown option|no such option|usage: |too many arguments/i;

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
export const LAUNCH_ERROR_RE =
  /unable to access jarfile|no main manifest attribute|could not find or load main class|cannot find module|modulenotfounderror|no such file or directory|command not found|permission denied|is a directory/i;

export class BrokenTier extends Error {}

export type Verdict = 'accepted' | 'rejected';

/**
 * Run one tier against one input and return its VERDICT, or throw
 * `BrokenTier` if the process never produced one.
 *
 * `rejected` requires all of:
 *   - the child spawned (no ENOENT/EACCES),
 *   - it exited under its own control (no signal, no timeout kill),
 *   - a non-zero exit status,
 *   - a non-empty diagnostic on stderr or stdout,
 *   - that diagnostic is not a usage/unknown-flag complaint,
 *   - and it is not a launcher failure.
 */
export function verdict(tier: Tier, input: string): Verdict {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(input)];
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
        `never started, so it has no opinion about this input:\n${diag.slice(0, 600)}`,
    );
  }
  return 'rejected';
}

/**
 * Run one tier's one-shot `source -> hex` CLI and return the locking script
 * hex, or throw `BrokenTier` if the process never produced one.
 *
 * Same spawn discipline as `verdict()` above, and deliberately in this file
 * rather than in a caller: R-100's finding was that a SECOND, weaker way to
 * drive a tier is how a gate ends up scoring dead tiers as perfect. This one
 * needs the tier's OUTPUT rather than its verdict, so it cannot be expressed
 * as a `verdict()` call — but it must not relax any of the checks:
 *
 *   - the child spawned, exited under its own control, and exited 0;
 *   - stdout carries a non-empty, even-length hex string and nothing else.
 *
 * A tier that answers with a usage error, a launcher error, or prose instead
 * of hex fails loudly here instead of contributing an empty string to a
 * "all tiers agree" comparison that would then be vacuously true.
 */
export function compileHex(tier: Tier, input: string): string {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(input)];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });

  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;

  if (res.error) throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  if (res.signal !== null) {
    throw new BrokenTier(
      `${where} was killed by ${res.signal} (timeout ${tier.timeoutMs}ms); no output.`,
    );
  }
  if (res.status !== 0) {
    const diag = `${res.stderr ?? ''}\n${res.stdout ?? ''}`.trim();
    throw new BrokenTier(`${where} exited ${res.status}: ${diag.slice(0, 600)}`);
  }

  const hex = (res.stdout ?? '').trim();
  if (hex === '') throw new BrokenTier(`${where} exited 0 with EMPTY stdout.`);
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new BrokenTier(
      `${where} exited 0 but stdout is not a hex script:\n${hex.slice(0, 600)}`,
    );
  }
  return hex.toLowerCase();
}
