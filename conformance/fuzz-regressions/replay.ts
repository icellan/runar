#!/usr/bin/env node

/**
 * Fuzzer regression-replay runner.
 *
 * WHY THIS EXISTS
 * ---------------
 * The nightly differential fuzzers (`conformance/fuzzer/index.ts`) hard-fail on
 * a divergence, so a finding is loud when it happens. What they do NOT do is
 * PERSIST it: `.github/workflows/fuzzer-nightly.yml` uploads the
 * `conformance/fuzz-findings-<oracle>` trees as CI artifacts with
 * `retention-days: 30`.
 * After 30 days the reproducer is gone and nothing replays it, so a bug found
 * once is only ever covered again by chance — the fuzzer has to rediscover it.
 *
 * This runner closes that loop. Every entry under `entries/` is a MINIMISED
 * reproducer of a divergence the fuzzer actually found, checked into git, and
 * replayed through the SAME differential path the `--execute` fuzzer uses
 * (`runDifferentialExecution` from `packages/runar-testing/src/oracle`). It
 * runs on EVERY CI run, not just nightly, and entries are never deleted.
 *
 * DETERMINISM
 * -----------
 * There is no RNG here and no network. An entry is a fixed contract source, a
 * fixed method, fixed constructor/method arguments, and the two PINNED verdicts
 * the oracle must reproduce. Same inputs, same bytes, same verdicts, every run.
 *
 * WHY VERDICTS ARE PINNED (and not just `agrees`)
 * -----------------------------------------------
 * Asserting only `interpreterAccepted === vmAccepted` is too weak: a change
 * that breaks BOTH engines the same way keeps `agrees` true. Each entry
 * therefore pins the exact expected verdict of each engine, so a regression is
 * caught whether it desynchronises the engines or corrupts both.
 *
 * WHY `requiredOpcodes` EXISTS
 * ----------------------------
 * A regression entry that no longer reaches the code path it was written for is
 * worthless — it would keep passing green while covering nothing. Each entry
 * names the Script opcodes its compiled locking script MUST still contain. If a
 * future optimiser folds the interesting operation away, the entry fails loudly
 * with "no longer exercises OP_x" rather than silently degrading to a no-op.
 *
 * Usage:
 *   npx tsx conformance/fuzz-regressions/replay.ts [--filter <substr>] [--verbose]
 *   npx tsx conformance/fuzz-regressions/replay.ts --list
 *   npx tsx conformance/fuzz-regressions/replay.ts --promote <findings-dir> --id <slug>
 *
 * Also reachable as `npx tsx conformance/fuzzer/index.ts --replay` and as
 * `npm run fuzz:replay` from `conformance/`.
 */

import { execFileSync } from 'node:child_process';
import {
  readdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  statSync,
  mkdirSync,
} from 'node:fs';
import { join, resolve, relative, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  runDifferentialExecution,
  runTriModalExecution,
} from '../../packages/runar-testing/src/oracle/index.js';
import type { WitnessArg } from '../../packages/runar-testing/src/oracle/index.js';
import { disassemble, hexToBytes } from '../../packages/runar-testing/src/vm/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/** Corpus root. Entries are directories directly beneath this. */
export const ENTRIES_DIR = join(__dirname, 'entries');

// ---------------------------------------------------------------------------
// Entry schema
// ---------------------------------------------------------------------------

export interface RegressionEntry {
  /** Directory name; also the id reported on failure. */
  id: string;
  /** One-line description of the divergence this entry guards against. */
  title: string;
  /** ISO date the underlying divergence was found. */
  discovered: string;
  /**
   * Which fuzzer oracle produced the finding.
   *
   * - `execute`   — the bare `ScriptVM` accept/reject oracle. `ScriptVM.success`
   *                 is "no evaluation error and truthy top of stack"; it does
   *                 NOT apply the consensus wrappers, so it does not enforce
   *                 minimal encoding, clean stack, or push-only unlocking.
   * - `tri-modal` — the CONSENSUS verdict (`Spend.validate()`). Required for any
   *                 divergence that only a real node sees. A shift result such
   *                 as `1 >> 1` = [0x00] is non-minimal: a node aborts when a
   *                 numeric op consumes it, while the bare VM accepts. Pinning
   *                 such an entry against `execute` would record the weaker
   *                 engine's verdict as if it were the chain's.
   *
   * `expect.vmAccepted` is read as the chosen oracle's script-side verdict.
   */
  oracle: 'execute' | 'tri-modal';
  /** Contract source file, relative to the entry directory. */
  sourceFile: string;
  /** File name handed to the compiler — selects the frontend parser. */
  fileName: string;
  /** Public method spent through. */
  method: string;
  /** Constructor args, encoded (see `decodeArg`). */
  constructorArgs: Record<string, string | boolean>;
  /** Method args in declaration order, encoded (see `decodeArg`). */
  args: Array<string | boolean>;
  /** The pinned verdicts both engines must reproduce. */
  expect: {
    interpreterAccepted: boolean;
    vmAccepted: boolean;
  };
  /**
   * Opcodes the compiled locking script must still contain. Guards against the
   * entry silently ceasing to exercise the buggy path. Never empty.
   */
  requiredOpcodes: string[];
  /** Where this entry came from and what fixed the bug. */
  provenance: {
    /** Original findings-directory name, when one was archived. */
    finding?: string;
    /** Commits that fixed the divergence. */
    fixedBy?: string[];
    /** GitHub issue / PR reference. */
    issue?: string;
    /** Free-form note on how the entry was reconstructed. */
    note?: string;
  };
  /** Why these exact verdicts are correct. Explains the entry to a reader. */
  rationale: string;
}

// ---------------------------------------------------------------------------
// Argument codec
// ---------------------------------------------------------------------------

/**
 * Inverse of `jsonifyArg` in `conformance/fuzzer/execute-differential.ts`, which
 * is the encoding every saved finding already uses:
 *   bigint     -> "123n"
 *   boolean    -> true / false (JSON boolean)
 *   ByteString -> "0xdeadbeef"
 * Sharing the encoding is what makes `--promote` a near-copy rather than a
 * translation.
 */
export function decodeArg(v: string | boolean): WitnessArg {
  if (typeof v === 'boolean') return v;
  if (/^-?\d+n$/.test(v)) return BigInt(v.slice(0, -1));
  if (/^0x[0-9a-fA-F]*$/.test(v)) return hexToBytes(v.slice(2));
  throw new Error(
    `unrecognised encoded argument ${JSON.stringify(v)} (expected "<int>n", true/false, or "0x<hex>")`,
  );
}

/** Constructor args reach the compiler as bigint | boolean | hex string. */
function decodeCtorArg(v: string | boolean): bigint | boolean | string {
  if (typeof v === 'boolean') return v;
  if (/^-?\d+n$/.test(v)) return BigInt(v.slice(0, -1));
  if (/^0x[0-9a-fA-F]*$/.test(v)) return v.slice(2);
  throw new Error(`unrecognised encoded constructor argument ${JSON.stringify(v)}`);
}

// ---------------------------------------------------------------------------
// Opcode guard
// ---------------------------------------------------------------------------

/**
 * Opcodes whose semantics have historically diverged between the ANF
 * interpreter and the deployed script, or that carry non-obvious Script
 * semantics. `--promote` intersects this set with the compiled script to
 * populate `requiredOpcodes` automatically, so a promoted entry gets a
 * meaningful anti-triviality guard without hand-editing.
 */
const SEMANTIC_OPCODES: readonly string[] = [
  // byte-array bitwise / shift — the shift/bitwise divergence family
  'OP_AND', 'OP_OR', 'OP_XOR', 'OP_INVERT', 'OP_LSHIFT', 'OP_RSHIFT',
  // arithmetic beyond add/sub
  'OP_MUL', 'OP_DIV', 'OP_MOD', 'OP_ABS', 'OP_MIN', 'OP_MAX', 'OP_WITHIN',
  // splice / byte-string
  'OP_CAT', 'OP_SPLIT', 'OP_NUM2BIN', 'OP_BIN2NUM', 'OP_SIZE',
  // crypto
  'OP_SHA256', 'OP_HASH160', 'OP_HASH256', 'OP_RIPEMD160', 'OP_SHA1',
  'OP_CHECKSIG', 'OP_CHECKSIGVERIFY', 'OP_CHECKMULTISIG', 'OP_CHECKMULTISIGVERIFY',
];

/**
 * Opcode mnemonics present in a compiled script. `disassemble` renders push
 * payloads as bare hex and only opcodes as `OP_*`, so a data byte that happens
 * to equal an opcode value cannot produce a false positive.
 */
export function scriptOpcodes(lockingHex: string): Set<string> {
  const asm = disassemble(hexToBytes(lockingHex));
  return new Set(asm.split(/\s+/).filter((t) => t.startsWith('OP_')));
}

// ---------------------------------------------------------------------------
// Corpus loading
// ---------------------------------------------------------------------------

export interface LoadedEntry {
  entry: RegressionEntry;
  dir: string;
  source: string;
}

function requireField<T>(v: T | undefined, entryId: string, field: string): T {
  if (v === undefined || v === null) {
    throw new Error(`corpus entry ${entryId}: missing required field "${field}"`);
  }
  return v;
}

/** Load and validate every entry under `entries/`, sorted by id for stability. */
export function loadCorpus(entriesDir: string = ENTRIES_DIR): LoadedEntry[] {
  if (!existsSync(entriesDir)) return [];
  const ids = readdirSync(entriesDir)
    .filter((n) => !n.startsWith('.') && statSync(join(entriesDir, n)).isDirectory())
    .sort();

  return ids.map((id) => {
    const dir = join(entriesDir, id);
    const entryPath = join(dir, 'entry.json');
    if (!existsSync(entryPath)) {
      throw new Error(`corpus entry ${id}: no entry.json in ${dir}`);
    }
    const entry = JSON.parse(readFileSync(entryPath, 'utf-8')) as RegressionEntry;

    // Fail fast on a malformed entry rather than silently replaying nothing.
    requireField(entry.sourceFile, id, 'sourceFile');
    requireField(entry.fileName, id, 'fileName');
    requireField(entry.method, id, 'method');
    requireField(entry.expect, id, 'expect');
    requireField(entry.expect?.interpreterAccepted, id, 'expect.interpreterAccepted');
    requireField(entry.expect?.vmAccepted, id, 'expect.vmAccepted');
    // `entry.oracle` is only a compile-time union (`'execute' | 'tri-modal'`);
    // the cast above does not check it at runtime. Reject anything else here —
    // a missing, misspelt, or future value must never silently fall through
    // `replayEntry`'s dispatch into the weaker `execute`/bare-ScriptVM path.
    if (entry.oracle !== 'execute' && entry.oracle !== 'tri-modal') {
      throw new Error(
        `corpus entry ${id}: "oracle" must be "execute" or "tri-modal", got ` +
          `${JSON.stringify(entry.oracle)} — an unrecognised value would silently fall ` +
          `through to the weaker execute/ScriptVM-only oracle`,
      );
    }
    if (!Array.isArray(entry.requiredOpcodes) || entry.requiredOpcodes.length === 0) {
      throw new Error(
        `corpus entry ${id}: requiredOpcodes must be a non-empty array — an entry that ` +
          `names no opcode cannot prove it still exercises the buggy path`,
      );
    }
    if (entry.id !== id) {
      throw new Error(`corpus entry ${id}: entry.json "id" is "${entry.id}", must match directory name`);
    }

    const sourcePath = join(dir, entry.sourceFile);
    if (!existsSync(sourcePath)) {
      throw new Error(`corpus entry ${id}: sourceFile ${entry.sourceFile} not found`);
    }
    return { entry, dir, source: readFileSync(sourcePath, 'utf-8') };
  });
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

export interface ReplayOutcome {
  id: string;
  passed: boolean;
  /** Human-readable failure reasons; empty when passed. */
  failures: string[];
  interpreterAccepted?: boolean;
  vmAccepted?: boolean;
  lockingHex?: string;
  durationMs: number;
}

/** Replay one entry through the `--execute` fuzzer's differential oracle. */
export function replayEntry(loaded: LoadedEntry): ReplayOutcome {
  const { entry, source } = loaded;
  const started = Date.now();
  const failures: string[] = [];

  let ctor: Record<string, bigint | boolean | string>;
  let args: WitnessArg[];
  try {
    ctor = Object.fromEntries(
      Object.entries(entry.constructorArgs ?? {}).map(([k, v]) => [k, decodeCtorArg(v)]),
    );
    args = (entry.args ?? []).map(decodeArg);
  } catch (e) {
    return {
      id: entry.id,
      passed: false,
      failures: [`argument decode failed: ${e instanceof Error ? e.message : String(e)}`],
      durationMs: Date.now() - started,
    };
  }

  let result;
  try {
    // SAME path as `conformance/fuzzer/execute-differential.ts`: fold-ON
    // deployed bytes on the @bsv/sdk ScriptVM vs the ANF interpreter. For a
    // `tri-modal` entry the script side is the CONSENSUS verdict instead, so
    // `vmAccepted` below carries `Spend.validate()`.
    if (entry.oracle === 'tri-modal') {
      const tri = runTriModalExecution({
        source,
        fileName: entry.fileName,
        method: entry.method,
        args,
        constructorArgs: ctor,
      });
      // Re-key BOTH the verdict and `agrees` onto consensus. `agrees` on a
      // tri-modal result means "all three engines agree", which is false here
      // by construction: the bare VM accepts the non-minimal encoding that the
      // chain rejects. Leaving it would report DIVERGENCE REOPENED on an entry
      // whose pinned verdicts both match.
      result = {
        ...tri,
        vmAccepted: tri.spendAccepted,
        vmError: tri.spendError,
        agrees: tri.interpreterAccepted === tri.spendAccepted,
      };
    } else {
      result = runDifferentialExecution({
        source,
        fileName: entry.fileName,
        method: entry.method,
        args,
        constructorArgs: ctor,
      });
    }
  } catch (e) {
    return {
      id: entry.id,
      passed: false,
      failures: [`oracle threw: ${e instanceof Error ? e.message : String(e)}`],
      durationMs: Date.now() - started,
    };
  }

  // 1. The entry must still exercise the code path it was written for.
  const present = scriptOpcodes(result.lockingHex);
  const missing = entry.requiredOpcodes.filter((op) => !present.has(op));
  if (missing.length > 0) {
    failures.push(
      `compiled script no longer exercises ${missing.join(', ')} — this entry has ` +
        `degraded into a no-op and covers nothing. Fix the entry or the compiler.`,
    );
  }

  // 2. Both engines must reproduce their pinned verdicts.
  if (result.interpreterAccepted !== entry.expect.interpreterAccepted) {
    failures.push(
      `interpreter verdict changed: expected accepted=${entry.expect.interpreterAccepted}, ` +
        `got ${result.interpreterAccepted}` +
        (result.interpreterError ? ` (${result.interpreterError})` : ''),
    );
  }
  if (result.vmAccepted !== entry.expect.vmAccepted) {
    failures.push(
      `script-VM verdict changed: expected accepted=${entry.expect.vmAccepted}, ` +
        `got ${result.vmAccepted}` +
        (result.vmError ? ` (${result.vmError})` : ''),
    );
  }

  // 3. And they must still agree — the original divergence must stay closed.
  if (!result.agrees) {
    failures.push(
      `DIVERGENCE REOPENED: interpreter=${result.interpreterAccepted} vm=${result.vmAccepted} ` +
        `(interpreterError=${result.interpreterError ?? 'none'}; vmError=${result.vmError ?? 'none'})`,
    );
  }

  return {
    id: entry.id,
    passed: failures.length === 0,
    failures,
    interpreterAccepted: result.interpreterAccepted,
    vmAccepted: result.vmAccepted,
    lockingHex: result.lockingHex,
    durationMs: Date.now() - started,
  };
}

export interface ReplayReport {
  total: number;
  passed: number;
  failed: number;
  outcomes: ReplayOutcome[];
  durationMs: number;
}

export interface ReplayOptions {
  entriesDir?: string;
  /** Only replay entries whose id contains this substring. */
  filter?: string;
  verbose?: boolean;
}

export function runReplay(opts: ReplayOptions = {}): ReplayReport {
  const started = Date.now();
  const fullCorpus = loadCorpus(opts.entriesDir);
  // An empty corpus (entriesDir missing, or present but with zero entries) is
  // not a passing run — it is "entries are never deleted" (README.md rule 3)
  // having been violated. Checked against the UNFILTERED corpus so a
  // `--filter` that happens to match nothing stays its own, separate case.
  if (fullCorpus.length === 0) {
    throw new Error(
      `fuzzer regression corpus at ${opts.entriesDir ?? ENTRIES_DIR} is empty — entries are ` +
        'never deleted (see conformance/fuzz-regressions/README.md rule 3); a corpus with no ' +
        'entries must fail loudly, not replay as a green 0/0/0 run',
    );
  }
  let corpus = fullCorpus;
  if (opts.filter) corpus = corpus.filter((c) => c.entry.id.includes(opts.filter!));

  const outcomes = corpus.map((loaded) => {
    const outcome = replayEntry(loaded);
    if (opts.verbose || !outcome.passed) {
      const mark = outcome.passed ? 'ok  ' : 'FAIL';
      console.log(`  ${mark} ${outcome.id} (${outcome.durationMs}ms) — ${loaded.entry.title}`);
      for (const f of outcome.failures) console.error(`       ${f}`);
    }
    return outcome;
  });

  return {
    total: outcomes.length,
    passed: outcomes.filter((o) => o.passed).length,
    failed: outcomes.filter((o) => !o.passed).length,
    outcomes,
    durationMs: Date.now() - started,
  };
}

// ---------------------------------------------------------------------------
// Promotion: findings directory -> corpus entry
// ---------------------------------------------------------------------------

/** The subset of `execute-differential.ts`'s ExecFinding that promotion needs. */
interface SavedFinding {
  contractName?: string;
  method?: string;
  source?: string;
  constructorArgs?: Record<string, string>;
  args?: string[];
  reason?: string;
  seed?: number;
}

export interface PromoteOptions {
  findingsDir: string;
  id: string;
  title?: string;
  note?: string;
  issue?: string;
  fixedBy?: string[];
  entriesDir?: string;
}

/**
 * Convert a fuzzer findings directory into a corpus entry.
 *
 * The finding was recorded while the bug was LIVE, so its verdicts are the
 * DIVERGENT ones. A corpus entry is a regression guard, not an xfail — the
 * expected verdicts are therefore captured by re-running the oracle at current
 * HEAD, and promotion REFUSES if the entry still diverges. Fix the bug first,
 * then promote.
 */
export function promoteFinding(opts: PromoteOptions): string {
  const findingPath = join(opts.findingsDir, 'finding.json');
  if (!existsSync(findingPath)) {
    throw new Error(`no finding.json in ${opts.findingsDir}`);
  }
  const finding = JSON.parse(readFileSync(findingPath, 'utf-8')) as SavedFinding;

  const sourcePath = join(opts.findingsDir, 'contract.runar.ts');
  if (!existsSync(sourcePath)) {
    throw new Error(`no contract.runar.ts in ${opts.findingsDir}`);
  }
  const source = readFileSync(sourcePath, 'utf-8');

  const contractName = finding.contractName ?? 'Contract';
  const method = finding.method;
  if (!method) throw new Error(`finding.json has no "method"`);

  const fileName = `${contractName}.runar.ts`;
  const constructorArgs = finding.constructorArgs ?? {};
  const encodedArgs = finding.args ?? [];

  // Re-run at current HEAD to capture the post-fix verdicts.
  const result = runDifferentialExecution({
    source,
    fileName,
    method,
    args: encodedArgs.map((a) => decodeArg(a)),
    constructorArgs: Object.fromEntries(
      Object.entries(constructorArgs).map(([k, v]) => [k, decodeCtorArg(v)]),
    ),
  });

  if (!result.agrees) {
    throw new Error(
      `refusing to promote ${opts.id}: the oracle STILL diverges at HEAD ` +
        `(interpreter=${result.interpreterAccepted} vm=${result.vmAccepted}). ` +
        `A corpus entry is a regression guard, not an xfail — fix the bug first, ` +
        `then promote so the entry passes and locks the fix in.`,
    );
  }

  const present = scriptOpcodes(result.lockingHex);
  const requiredOpcodes = SEMANTIC_OPCODES.filter((op) => present.has(op));
  if (requiredOpcodes.length === 0) {
    throw new Error(
      `refusing to promote ${opts.id}: the compiled script contains none of the ` +
        `semantically interesting opcodes, so the entry would have no anti-triviality ` +
        `guard. Add the relevant opcode to SEMANTIC_OPCODES in replay.ts, or write the ` +
        `entry by hand with an explicit requiredOpcodes list.`,
    );
  }

  const entriesDir = opts.entriesDir ?? ENTRIES_DIR;
  const outDir = join(entriesDir, opts.id);
  if (existsSync(outDir)) {
    throw new Error(`corpus entry ${opts.id} already exists at ${outDir} — entries are never overwritten`);
  }
  mkdirSync(outDir, { recursive: true });

  const entry: RegressionEntry = {
    id: opts.id,
    title: opts.title ?? finding.reason ?? `regression from ${basename(opts.findingsDir)}`,
    discovered: new Date().toISOString().slice(0, 10),
    oracle: 'execute',
    sourceFile: 'contract.runar.ts',
    fileName,
    method,
    constructorArgs,
    args: encodedArgs,
    expect: {
      interpreterAccepted: result.interpreterAccepted,
      vmAccepted: result.vmAccepted,
    },
    requiredOpcodes,
    provenance: {
      finding: basename(opts.findingsDir),
      ...(opts.fixedBy ? { fixedBy: opts.fixedBy } : {}),
      ...(opts.issue ? { issue: opts.issue } : {}),
      ...(opts.note ? { note: opts.note } : {}),
    },
    rationale:
      `Promoted from fuzzer finding "${finding.reason ?? 'unknown'}". Verdicts captured at ` +
      `promotion time with both engines agreeing (interpreter=${result.interpreterAccepted}, ` +
      `vm=${result.vmAccepted}).`,
  };

  writeFileSync(join(outDir, 'contract.runar.ts'), source, 'utf-8');
  writeFileSync(join(outDir, 'entry.json'), JSON.stringify(entry, null, 2) + '\n', 'utf-8');
  return outDir;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printHelp(): void {
  console.log(
    `
Rúnar fuzzer regression replay

Replays every checked-in minimised fuzzer reproducer through the same
differential oracle the --execute fuzzer uses. Deterministic, no network,
runs on every CI run.

Usage:
  npx tsx conformance/fuzz-regressions/replay.ts [options]

Options:
  --filter <substr>       Only replay entries whose id contains <substr>
  --list                  List corpus entries and exit
  --verbose               Print every entry, not just failures
  --promote <dir>         Convert a fuzzer findings directory into a corpus entry
  --id <slug>             Entry id for --promote (required with --promote)
  --title <text>          Entry title for --promote
  --note <text>           Provenance note for --promote
  --issue <ref>           Issue/PR reference for --promote
  --fixed-by <shas>       Comma-separated fixing commits for --promote
  --check-no-deletions    Fail if any entries/ id present at the merge-base
                          with --base (default origin/main) is gone now
                          (README.md rule 3: entries are never deleted)
  --base <ref>            Base ref for --check-no-deletions (default origin/main)
  --root <path>           Repo root for --check-no-deletions (default: git rev-parse --show-toplevel)
  --help, -h              Show this message

Examples:
  npx tsx conformance/fuzz-regressions/replay.ts
  npx tsx conformance/fuzz-regressions/replay.ts --filter shift --verbose
  npx tsx conformance/fuzz-regressions/replay.ts \\
      --promote conformance/fuzz-findings-execute/2026-07-12T08-02-20-043Z-Foo-bar \\
      --id 2026-07-12-foo-bar --title "OP_AND length mismatch" --fixed-by abc1234
  npx tsx conformance/fuzz-regressions/replay.ts --check-no-deletions --base origin/main
`.trim(),
  );
}

async function main(): Promise<void> {
  const argv = process.argv;
  let filter: string | undefined;
  let verbose = false;
  let list = false;
  let promote: string | undefined;
  let id: string | undefined;
  let title: string | undefined;
  let note: string | undefined;
  let issue: string | undefined;
  let fixedBy: string[] | undefined;
  let checkNoDeletions = false;
  let base: string | undefined;
  let root: string | undefined;

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i]!;
    switch (arg) {
      case '--filter': filter = argv[++i]; break;
      case '--verbose': verbose = true; break;
      case '--list': list = true; break;
      case '--promote': promote = resolve(argv[++i] ?? ''); break;
      case '--id': id = argv[++i]; break;
      case '--title': title = argv[++i]; break;
      case '--note': note = argv[++i]; break;
      case '--issue': issue = argv[++i]; break;
      case '--fixed-by': fixedBy = (argv[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean); break;
      case '--check-no-deletions': checkNoDeletions = true; break;
      case '--base': base = argv[++i]; break;
      case '--root': root = argv[++i]; break;
      case '--help':
      case '-h': printHelp(); process.exit(0);
      // eslint-disable-next-line no-fallthrough
      default:
        console.error(`Unknown option: ${arg}`);
        process.exit(1);
    }
  }

  if (checkNoDeletions) {
    process.exit(runCheckNoDeletions({ baseRef: base ?? 'origin/main', root }));
  }

  if (promote) {
    if (!id) {
      console.error('--promote requires --id <slug>');
      process.exit(1);
    }
    try {
      const out = promoteFinding({ findingsDir: promote, id, title, note, issue, fixedBy });
      console.log(`Promoted ${promote}\n     -> ${out}`);
      console.log('Review the generated entry.json (title/rationale/provenance) and commit it.');
    } catch (e) {
      console.error(`Promotion failed: ${e instanceof Error ? e.message : String(e)}`);
      process.exit(1);
    }
    return;
  }

  if (list) {
    for (const { entry } of loadCorpus()) {
      console.log(`${entry.id}\n  ${entry.title}\n  opcodes: ${entry.requiredOpcodes.join(', ')}`);
    }
    return;
  }

  const report = runReplayAndReport({ filter, verbose });
  if (report.failed > 0) process.exit(1);
}

/** Shared by the standalone CLI and `conformance/fuzzer/index.ts --replay`. */
export function runReplayAndReport(opts: ReplayOptions = {}): ReplayReport {
  console.log('Rúnar fuzzer regression replay');
  const report = runReplay(opts);

  if (report.total === 0) {
    // runReplay() throws before returning when the corpus itself is empty
    // (see its own guard), so the only way to reach this with total === 0 is
    // a `--filter` that matched nothing.
    console.log('  (no entries matched the filter)');
  }
  console.log('');
  console.log(`  Entries: ${report.total}`);
  console.log(`  Passed:  ${report.passed}`);
  console.log(`  Failed:  ${report.failed}`);
  console.log(`  Duration: ${report.durationMs}ms`);
  if (report.failed > 0) {
    console.error('');
    console.error(
      `REGRESSION: ${report.failed} corpus entr${report.failed === 1 ? 'y' : 'ies'} failed — ` +
        `${report.outcomes.filter((o) => !o.passed).map((o) => o.id).join(', ')}`,
    );
    console.error('A previously fixed fuzzer finding has come back. See conformance/fuzz-regressions/README.md.');
  }
  return report;
}

// ---------------------------------------------------------------------------
// README.md rule 3 — "Entries are never deleted" (N-230)
// ---------------------------------------------------------------------------
//
// `runReplay`'s empty-corpus guard above only catches the corpus being wiped
// to ZERO entries (F-250). Deleting ONE entry out of a corpus that still has
// several left is a passing, non-empty run — nothing else in this file
// notices that an id which existed on the base branch is simply gone. That
// needs a base-ref diff of `entries/`, which is what this section adds.

/** Entry ids present in `baseIds` but missing from `currentIds` — a deletion. */
export function findDeletedEntryIds(baseIds: string[], currentIds: string[]): string[] {
  const current = new Set(currentIds);
  return baseIds.filter((id) => !current.has(id)).sort();
}

/** The merge-base commit of `baseRef` and HEAD, in `repoRoot`. */
export function resolveMergeBase(baseRef: string, repoRoot: string): string {
  return execFileSync('git', ['-C', repoRoot, 'merge-base', baseRef, 'HEAD'], {
    encoding: 'utf-8',
  }).trim();
}

/**
 * Directory names directly under `relEntriesDir` as they existed at git ref
 * `ref`, in `repoRoot`. Returns `[]` — not an error — when `relEntriesDir` did
 * not exist at `ref` at all (e.g. the corpus postdates that commit): there is
 * nothing to have deleted relative to a point before it existed.
 */
export function listEntryIdsAtRef(ref: string, repoRoot: string, relEntriesDir: string): string[] {
  let out: string;
  try {
    out = execFileSync(
      'git',
      ['-C', repoRoot, 'ls-tree', '-d', '--name-only', `${ref}:${relEntriesDir}`],
      { encoding: 'utf-8' },
    );
  } catch {
    return [];
  }
  return out.split('\n').map((s) => s.trim()).filter(Boolean).sort();
}

export interface CheckNoDeletionsOptions {
  /** The repository root `git` is run in. */
  repoRoot: string;
  /** The ref to diff against — e.g. `origin/main`. Compared at its MERGE-BASE
   * with HEAD, not its live tip, so a base branch that gains new entries
   * after this branch forked is never mistaken for a deletion on this branch
   * (same three-dot-from-merge-base convention as
   * `conformance/scripts/check-golden-provenance.mjs`). */
  baseRef: string;
  /** Local filesystem path to the current `entries/` directory. */
  entriesDir?: string;
}

/**
 * Entry ids that existed under `entries/` at the merge-base of `baseRef` and
 * HEAD, but are gone from disk now. A non-empty result is rule 3 violated.
 *
 * Deliberately independent of `loadCorpus`'s validation: this check's job is
 * only "did a directory disappear", not "is every remaining entry well
 * formed" — an unrelated malformed entry must not mask a real deletion
 * behind a schema error.
 */
export function checkEntriesNotDeleted(opts: CheckNoDeletionsOptions): string[] {
  // Default relative to `repoRoot`, NOT the real repo's `ENTRIES_DIR` — this
  // check is exercised against throwaway git repos in tests, whose entries/
  // lives at the same repo-relative path but under a different root.
  const entriesDir =
    opts.entriesDir ?? join(opts.repoRoot, 'conformance', 'fuzz-regressions', 'entries');
  const mergeBase = resolveMergeBase(opts.baseRef, opts.repoRoot);
  const relEntriesDir = relative(opts.repoRoot, entriesDir);
  const baseIds = listEntryIdsAtRef(mergeBase, opts.repoRoot, relEntriesDir);
  const currentIds = existsSync(entriesDir)
    ? readdirSync(entriesDir)
        .filter((n) => !n.startsWith('.') && statSync(join(entriesDir, n)).isDirectory())
        .sort()
    : [];
  return findDeletedEntryIds(baseIds, currentIds);
}

/** Resolve the repo root for the `--check-no-deletions` CLI path. */
function resolveCliRepoRoot(explicit?: string): string {
  if (explicit) return resolve(explicit);
  try {
    const top = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (top) return top;
  } catch {
    /* not a git work tree — fall through */
  }
  return resolve(__dirname, '..', '..');
}

/** Runs the rule-3 check and reports it; returns the process exit code. */
export function runCheckNoDeletions(opts: { baseRef?: string; root?: string } = {}): number {
  const repoRoot = resolveCliRepoRoot(opts.root);
  const baseRef = opts.baseRef || 'origin/main';
  let deleted: string[];
  try {
    deleted = checkEntriesNotDeleted({ repoRoot, baseRef });
  } catch (e) {
    console.error(
      `fuzz-regressions --check-no-deletions failed: ${e instanceof Error ? e.message : String(e)}`,
    );
    return 1;
  }
  if (deleted.length > 0) {
    console.error(
      `RULE 3 VIOLATED: ${deleted.length} corpus entr${deleted.length === 1 ? 'y' : 'ies'} deleted ` +
        `since the merge-base with ${baseRef}: ${deleted.join(', ')}`,
    );
    console.error(
      'Entries are never deleted (conformance/fuzz-regressions/README.md rule 3). Removing one ' +
        'requires an explicit rationale in the PR description — this check has no allowlist or ' +
        'override; that rationale is the only way past it.',
    );
    return 1;
  }
  console.log(`Fuzz regression corpus: no entries deleted since the merge-base with ${baseRef}.`);
  return 0;
}

// Only run the CLI when invoked directly, not when imported by the fuzzer CLI.
if (process.argv[1] && resolve(process.argv[1]) === resolve(__filename)) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
