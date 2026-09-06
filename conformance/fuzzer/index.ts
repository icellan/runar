#!/usr/bin/env node

/**
 * Rúnar Differential Fuzzer -- CLI entry point.
 *
 * Usage:
 *   npx tsx conformance/fuzzer/index.ts [options]
 *
 * Options:
 *   --num <count>          Number of random programs to generate (default: 100)
 *   --seed <n>             RNG seed for reproducibility
 *   --compilers <list>     Comma-separated list: ts,go,rust,python,zig,ruby (default: all available)
 *   --verbose              Print each generated program and result
 *   --property             Use fast-check property-based mode (with shrinking)
 *   --hex                  Compare final hex script instead of IR
 *   --findings-dir <path>  Directory to save failing cases (default: conformance/fuzz-findings)
 *   --output <path>        Write results JSON to file
 *   --help                 Show this help message
 */

import { resolve } from 'path';
import { writeFileSync } from 'fs';
import {
  runDifferentialFuzzing,
  runPropertyBasedDifferential,
  type DifferentialResult,
  type FuzzerOptions,
  type CompilerName,
} from './differential.js';
import {
  runIRDifferentialFuzzing,
  type RenderStrategy,
} from './ir-differential.js';
import {
  runAnfDifferential,
  ALL_TIERS,
  type CompilerName as AnfCompilerName,
} from './anf-differential.js';
import {
  runCanonicalDifferential,
  ALL_TIERS as CANON_ALL_TIERS,
  type CompilerName as CanonCompilerName,
} from './canonical-json-differential.js';
import { runExecuteDifferential } from './execute-differential.js';
import { runTriModalDifferential } from './tri-modal-differential.js';
import { runSpendOracle } from './spend-oracle.js';
import { runReplayAndReport } from '../fuzz-regressions/replay.js';
import { shouldFailRun } from './run-policy.js';

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

interface FuzzerCLIOptions {
  num: number;
  seed?: number;
  compilers: CompilerName[];
  verbose: boolean;
  property: boolean;
  hex: boolean;
  findingsDir?: string;
  output?: string;
  help: boolean;
  /** Use the rich IR-based generator (arbGeneratedContract). */
  ir: boolean;
  /** Render per-compiler native source instead of a shared TS source. */
  renderStrategy: RenderStrategy;
  /** Include stateful contracts in the generated distribution (IR mode only). */
  stateful: boolean;
  /**
   * Use the ANF-IR differential fuzzer (Item 7): generates random ANF
   * programs directly, skips the source-rendering frontends, and
   * stresses every tier's loader + stack-lowerer + emitter.
   */
  anf: boolean;
  /**
   * GAP-002 — cross-tier canonicalJson (RFC 8785 / JCS) differential fuzzer.
   * Generates random JSON-shaped values spanning the tricky surface (key
   * ordering, float boundaries, surrogate handling, nesting) and asserts all
   * 7 tiers' canonicalJson produce byte-identical output OR an identical
   * typed rejection.
   */
  canonical: boolean;
  /**
   * `--canonical` only. Tiers whose shim MUST be runnable; a missing one is a
   * FAILURE, not a smaller run.
   *
   * Undefined (the default) means "every tier in `--compilers`", which for a
   * bare invocation is all 7. `--require-tiers none` opts out for an
   * exploratory local run. Without this the harness degraded silently: a tier
   * whose shim binary was absent was marked `skip`, dropped from the compare,
   * and the run still printed "Mismatches: 0" and exited 0 — a seven-tier
   * wire-parity gate reporting success on six tiers.
   */
  requireTiers?: CompilerName[];
  /**
   * TS-GAP-001 (randomized) / TS-GAP-005 — source-vs-script EXECUTION oracle.
   * Generates stateless, non-crypto contracts, renders each to TS, and runs
   * every generated spend through the ANF interpreter AND the compiled fold-ON
   * script on ScriptVM, asserting accept/reject agreement. A divergence is a
   * real shared-design bug (all 7 tiers can agree on the same wrong bytes and
   * still pass the parity fuzzers).
   */
  execute: boolean;
  /**
   * Issue #124 — TRI-MODAL source-vs-script execution oracle in fast-check
   * PROPERTY mode. Generates stateless contracts with loops + byte-ops +
   * post-loop param reads, and runs every spend through the ANF interpreter,
   * ScriptVM (the @bsv/sdk Spend engine stepped opcode by opcode), AND a strict
   * full-consensus Spend.validate(), asserting all three agree. Unlike
   * `--execute` (bi-modal, `fc.sample`, no shrinking),
   * a divergence is SHRUNK to a minimal (contract, inputs) repro. `--num` =
   * property runs; `--seed` reproduces the run.
   */
  triModal: boolean;
  /**
   * Phase E3 (testing-gap remediation) — the SPEND-ORACLE fuzzer. Every other
   * mode in this file is either HORIZONTAL (tier vs tier: `--anf`, `--ir`,
   * `--canonical`) or scoped to stateless fragments against a synthetic tx
   * context (`--execute`, `--tri-modal`). This one generates construct-biased
   * STATEFUL contracts (multi-local branch merges, 1-byte OP_N-range /
   * negative state values, multi-slot constructor args), compiles them fold-ON,
   * drives a real deploy + call through the SDK, replays both broadcasts
   * through the real `@bsv/sdk` Spend engine, and compares the post-state
   * decoded from the BROADCAST TRANSACTION'S BYTES against the generator's own
   * independent model. See `spend-oracle.ts`.
   */
  spendOracle: boolean;
  /**
   * Spend-oracle mode only (Phase E4). Also run each generated case's
   * SEMANTICS-PRESERVING metamorphic variants (renamed locals; swapped pure
   * `if/else` arms) and require an identical engine verdict AND an identical
   * `expectedState` outcome.
   */
  metamorphic: boolean;
  /**
   * Regression-replay mode. Instead of generating anything, replay every
   * checked-in reproducer under `conformance/fuzz-regressions/entries/` through
   * the same differential oracle `--execute` uses. Deterministic and fast, so
   * unlike every other mode here this one runs on EVERY CI run — it is what
   * keeps a divergence the fuzzer already found from having to be rediscovered
   * by chance once its 30-day findings artifact expires.
   * See `conformance/fuzz-regressions/README.md`.
   */
  replay: boolean;
  /** Replay mode only. Substring filter over entry ids. */
  replayFilter?: string;
  /** Execution-oracle input vectors per (contract, method). Default 6. */
  inputs?: number;
  /** Wall-clock budget in ms (anf / execute modes). */
  timeBudgetMs?: number;
  /**
   * ANF mode only. Run every tier with constant-folding ON (omit
   * `--disable-constant-folding`). Default off → fold-OFF, matching the
   * checked-in goldens.
   */
  foldOn: boolean;
}

function parseArgs(argv: string[]): FuzzerCLIOptions {
  // Default compiler list: includes every compiler that can be driven from a
  // single generator run. The Java compiler parses all 9 .runar.* formats just
  // like the other 6 compilers, but the legacy string-based harness in
  // `differential.ts` only produces .runar.ts text and has no structured AST
  // to re-render as Java, so it silently skips Java. The IR-based harness
  // (`ir-differential.ts`) does have a structured generator and renders
  // per-compiler native sources for Java (and every other compiler).
  const opts: FuzzerCLIOptions = {
    num: 100,
    compilers: ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'],
    verbose: false,
    property: false,
    hex: false,
    help: false,
    ir: false,
    renderStrategy: 'ts',
    stateful: false,
    anf: false,
    canonical: false,
    execute: false,
    triModal: false,
    spendOracle: false,
    metamorphic: false,
    replay: false,
    foldOn: false,
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i]!;
    switch (arg) {
      case '--num':
        opts.num = parseInt(argv[++i] ?? '100', 10);
        break;
      case '--seed':
        opts.seed = parseInt(argv[++i] ?? '0', 10);
        break;
      case '--compilers': {
        const raw = argv[++i] ?? 'ts,go,rust,python,zig,ruby,java';
        opts.compilers = raw.split(',').map((s) => s.trim()) as CompilerName[];
        break;
      }
      case '--verbose':
        opts.verbose = true;
        break;
      case '--property':
        opts.property = true;
        break;
      case '--hex':
        opts.hex = true;
        break;
      case '--findings-dir':
        opts.findingsDir = resolve(argv[++i] ?? '');
        break;
      case '--output':
        opts.output = resolve(argv[++i] ?? '');
        break;
      case '--ir':
        opts.ir = true;
        break;
      case '--render': {
        const v = argv[++i];
        if (v !== 'ts' && v !== 'native') {
          console.error(`--render must be 'ts' or 'native', got ${v}`);
          process.exit(1);
        }
        opts.renderStrategy = v;
        break;
      }
      case '--stateful':
        opts.stateful = true;
        break;
      case '--anf':
        opts.anf = true;
        break;
      case '--canonical':
        opts.canonical = true;
        break;
      case '--require-tiers': {
        const raw = (argv[++i] ?? '').trim();
        // `none` is the explicit opt-out. An EMPTY value is not: silently
        // requiring nothing is the exact failure this flag exists to stop.
        if (raw === 'none') {
          opts.requireTiers = [];
        } else if (raw === '' || raw === 'all') {
          opts.requireTiers = ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'];
        } else {
          opts.requireTiers = raw.split(',').map((s) => s.trim()).filter(Boolean) as CompilerName[];
        }
        break;
      }
      case '--execute':
        opts.execute = true;
        break;
      case '--tri-modal':
        opts.triModal = true;
        break;
      case '--spend-oracle':
        opts.spendOracle = true;
        break;
      case '--metamorphic':
        opts.metamorphic = true;
        break;
      case '--replay':
        opts.replay = true;
        break;
      case '--replay-filter':
        opts.replayFilter = argv[++i];
        break;
      case '--inputs':
        opts.inputs = parseInt(argv[++i] ?? '6', 10);
        break;
      case '--fold-on':
        opts.foldOn = true;
        break;
      case '--time-budget-ms':
        opts.timeBudgetMs = parseInt(argv[++i] ?? '0', 10);
        break;
      case '--help':
      case '-h':
        opts.help = true;
        break;
      default:
        console.error(`Unknown option: ${arg}`);
        process.exit(1);
    }
  }

  return opts;
}

function printHelp(): void {
  console.log(`
Rúnar Differential Fuzzer

Generates random valid Rúnar contract programs, compiles them through all
available compiler implementations, and verifies that the output matches
byte-for-byte.

Usage:
  npx tsx conformance/fuzzer/index.ts [options]

Options:
  --num <count>          Number of random programs to generate (default: 100)
  --seed <n>             RNG seed for reproducible runs
  --compilers <list>     Comma-separated list: ts,go,rust,python,zig,ruby,java
                         (default: all available)
  --verbose              Print each generated program and its result
  --property             Use fast-check property-based mode with shrinking
                         (finds minimal failing programs)
  --hex                  Compare final hex script instead of IR
  --findings-dir <path>  Directory to save failing cases
                         (default: conformance/fuzz-findings)
  --output <path>        Write results JSON to file
  --ir                   Use the rich IR-based generator (multi-type props,
                         built-in calls, multiple methods, stateful contracts).
  --render <ts|native>   IR mode only. 'ts' (default) renders a single TS source
                         that all compilers parse. 'native' renders each compiler's
                         native source (.runar.go / .runar.rs / .runar.py / …) to
                         also stress each compiler's frontend.
  --stateful             IR mode only. Mix stateful contracts into the sample.
  --anf                  Item 7 — direct ANF IR differential fuzzer.
                         Generates random valid ANF programs and asserts every
                         tier's --ir --hex pipeline produces byte-identical
                         Bitcoin Script. Skips frontends entirely.
  --canonical            GAP-002 — cross-tier canonicalJson (RFC 8785 / JCS)
                         differential fuzzer. Generates random JSON-shaped
                         values spanning the tricky surface (UTF-16 key order,
                         ECMA-262 float boundaries, lone surrogates, nesting)
                         and asserts all 7 SDK tiers' canonicalJson produce
                         byte-identical output OR an identical typed rejection.
                         Each non-TS tier is driven via its --canonicalise CLI
                         shim. Use --num for case count and --seed to reproduce.
  --require-tiers <list> --canonical only. Tiers whose shim MUST be runnable; a
                         missing one FAILS the run instead of quietly shrinking
                         it. Default: every tier in --compilers (all 7 for a
                         bare run). 'all' = all 7; 'none' = opt out (local
                         exploration only — never in CI).
  --execute              TS-GAP-001 (randomized) / TS-GAP-005 — source-vs-script
                         EXECUTION oracle. Generates stateless, non-crypto
                         contracts, renders each to TS, and runs every generated
                         spend through the ANF interpreter AND the compiled
                         fold-ON script on ScriptVM, asserting accept/reject
                         agreement. Unlike the parity fuzzers (--anf/--ir), this
                         catches bugs where all 7 tiers agree on the SAME wrong
                         bytes. --num = contract count; --inputs = input vectors
                         per method; --seed reproduces the corpus AND the inputs.
  --tri-modal            Issue #124 — TRI-MODAL execution oracle in fast-check
                         PROPERTY mode. Generates stateless contracts with loops
                         (non-zero start + countdown), substr/cat/len byte-ops
                         over ByteString params, and post-loop param reads, then
                         runs every spend through the ANF interpreter, ScriptVM
                         (the @bsv/sdk Spend engine stepped opcode by opcode),
                         AND a strict full-consensus Spend.validate(),
                         asserting all three agree. Unlike --execute
                         (bi-modal, fc.sample, no shrinking), a divergence is
                         SHRUNK to a minimal (contract, inputs) repro. --num =
                         property runs (~200 for the PR gate); --seed reproduces.
  --spend-oracle         Phase E3 — SPEND-ORACLE fuzz. The only mode whose
                         oracle is both ABSOLUTE and covers a full transaction
                         context AND the state VALUE. Generates construct-biased
                         STATEFUL contracts (multi-local branch merges incl. the
                         asymmetric PALMER-1 shape; 1-byte OP_N-range / 0x00 /
                         empty / negative state values; multi-slot constructor
                         args with shifting offsets), compiles fold-ON, drives a
                         real deploy + call through the SDK, replays both
                         broadcasts through the real @bsv/sdk Spend engine, and
                         compares the post-state decoded from the BROADCAST
                         TRANSACTION'S BYTES against the generator's OWN model
                         (never against the SDK's next-state computation, which
                         runs through the same ANF the covenant does and is
                         therefore poisoned by the very bug class this hunts).
                         Fails on: reject-when-accept-intended,
                         accept-when-reject-intended, interpreter-vs-Spend
                         disagreement, and expectedState mismatch.
                         --num = generated contracts; --seed reproduces exactly.
  --metamorphic          Spend-oracle mode only (Phase E4). Also run each case's
                         semantics-preserving rewrites (renamed locals; swapped
                         pure if/else arms) and require an identical verdict AND
                         an identical expectedState outcome. ~3x runtime.
  --replay               Regression replay. Generates NOTHING — replays every
                         checked-in minimised reproducer under
                         conformance/fuzz-regressions/entries/ through the same
                         differential oracle --execute uses, and fails with the
                         entry name on any divergence. Deterministic and fast
                         (no seed, no network), so unlike every other mode here
                         it runs on EVERY CI run: it is what stops a divergence
                         the fuzzer already found from having to be rediscovered
                         by chance once its 30-day findings artifact expires.
                         See conformance/fuzz-regressions/README.md.
  --replay-filter <s>    Replay mode only. Only replay entries whose id contains
                         the substring <s>.
  --inputs <n>           Execute mode only. Input vectors per (contract, method)
                         (default 6).
  --time-budget-ms <n>   ANF / execute modes. Early-stop once wall-clock exceeded.
  --fold-on              ANF mode only. Run every tier with constant-folding
                         ENABLED (omit --disable-constant-folding). Default is
                         fold-OFF, matching the checked-in goldens. Either mode
                         must produce byte-identical hex across all tiers.
  --help, -h             Show this help message

Examples:
  # Quick smoke test with TypeScript compiler only
  npx tsx conformance/fuzzer/index.ts --num 10 --compilers ts

  # Reproducible run with seed
  npx tsx conformance/fuzzer/index.ts --seed 42 --verbose

  # Compare hex output across all 6 compilers
  npx tsx conformance/fuzzer/index.ts --hex --num 50

  # Property-based mode (will shrink failing inputs)
  npx tsx conformance/fuzzer/index.ts --property --seed 12345

  # Full differential run saving results
  npx tsx conformance/fuzzer/index.ts --num 500 --output fuzz-results.json
`.trim());
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function writeOutput(path: string, report: unknown): void {
  writeFileSync(path, JSON.stringify(report, null, 2) + '\n', 'utf-8');
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);

  if (opts.help) {
    printHelp();
    process.exit(0);
  }

  // Replay generates nothing, so it short-circuits before the generator banner
  // and before any seed/compiler setup. See conformance/fuzz-regressions/.
  if (opts.replay) {
    const report = runReplayAndReport({ filter: opts.replayFilter, verbose: opts.verbose });
    if (opts.output) {
      writeOutput(opts.output, {
        timestamp: new Date().toISOString(),
        generator: 'replay',
        ...report,
      });
      console.log(`\nResults written to: ${opts.output}`);
    }
    if (report.failed > 0) process.exit(1);
    return;
  }

  console.log('Rúnar Differential Fuzzer');
  console.log(`  Programs: ${opts.num}`);
  console.log(`  Compilers: ${opts.compilers.join(', ')}`);
  console.log(`  Compare: ${opts.hex ? 'hex script' : 'ANF IR'}`);
  if (opts.seed !== undefined) {
    console.log(`  Seed: ${opts.seed}`);
  }
  if (opts.ir) {
    console.log(`  Generator: IR (render=${opts.renderStrategy}${opts.stateful ? ', stateful' : ''})`);
  }
  if (opts.anf) {
    console.log('  Generator: ANF (Item 7 — direct ANF IR, all 7 tiers via --ir --hex)');
    console.log(`  Folding: ${opts.foldOn ? 'ON (fold-on)' : 'OFF (--disable-constant-folding)'}`);
    if (opts.timeBudgetMs !== undefined) {
      console.log(`  Budget: ${opts.timeBudgetMs}ms`);
    }
  }
  if (opts.canonical) {
    console.log('  Generator: canonical (GAP-002 — cross-tier canonicalJson RFC 8785 / JCS)');
  }
  if (opts.execute) {
    console.log('  Generator: execute (TS-GAP-001/005 — source-vs-script execution oracle, fold-ON)');
    console.log(`  Inputs/method: ${opts.inputs ?? 6}`);
    if (opts.timeBudgetMs !== undefined) {
      console.log(`  Budget: ${opts.timeBudgetMs}ms`);
    }
  }
  if (opts.triModal) {
    console.log('  Generator: tri-modal (issue #124 — interpreter / ScriptVM / @bsv/sdk Spend, property mode)');
    console.log(`  Property runs: ${opts.num}`);
  }
  if (opts.spendOracle) {
    console.log('  Generator: spend-oracle (Phase E3 — construct-biased stateful deploy→call→Spend, fold-ON)');
    console.log(`  Metamorphic: ${opts.metamorphic ? 'ON (Phase E4 variants)' : 'off'}`);
    if (opts.timeBudgetMs !== undefined) {
      console.log(`  Budget: ${opts.timeBudgetMs}ms`);
    }
  }
  console.log(`  Mode: ${opts.property ? 'property-based (with shrinking)' : 'sample-based'}`);
  console.log('');

  if (opts.spendOracle) {
    const report = await runSpendOracle({
      numCases: opts.num,
      seed: opts.seed,
      timeBudgetMs: opts.timeBudgetMs,
      findingsDir: opts.findingsDir,
      metamorphic: opts.metamorphic,
      verbose: opts.verbose,
    });
    console.log('');
    console.log('Spend-oracle fuzzing complete:');
    console.log(`  Cases run:     ${report.casesRun}/${report.totalCases}`);
    console.log(`  Verdicts:      accept=${report.acceptCount} reject=${report.rejectCount}`);
    console.log(`  Failures:      ${report.failureCount}`);
    if (report.failureCount > 0) {
      console.log(`  By kind:       ${Object.entries(report.byKind)
        .map(([k, n]) => `${k}=${n}`)
        .join(' ')}`);
    }
    console.log(`  Spend inputs:  ${report.validatedInputs} replayed through Spend.validate()`);
    console.log(`  Constructs:    ${report.tagsCovered.length} tags (${report.tagsCovered.join(', ')})`);
    console.log(`  Duration:      ${report.durationMs}ms`);
    console.log(`  Seed:          ${report.effectiveSeed} (replay with --spend-oracle --seed ${report.effectiveSeed} --num ${opts.num})`);
    if (report.earlyStop) console.log('  Early-stopped: time budget reached');
    if (report.findings.length > 0) console.log(`  Findings dir:  ${report.findings[0]}`);
    if (opts.output) {
      writeOutput(opts.output, {
        timestamp: new Date().toISOString(),
        generator: 'spend-oracle',
        ...report,
      });
      console.log(`\nResults written to: ${opts.output}`);
    }
    // Same C5 rule as the other budgeted modes: an early-stopped run that did
    // not finish the generated corpus must never report an unqualified PASS.
    const incompleteSpendRun = shouldFailRun({
      earlyStop: report.earlyStop,
      completed: report.casesRun,
      total: report.totalCases,
    });
    if (incompleteSpendRun) {
      console.error(
        `INCOMPLETE RUN: time budget reached after ${report.casesRun}/${report.totalCases} cases — treating as a failure.`,
      );
    }
    // A run in which NOTHING reached the real engine is a vacuous pass.
    const vacuousRun = report.casesRun > 0 && report.validatedInputs === 0;
    if (vacuousRun) {
      console.error(
        'VACUOUS RUN: no input was replayed through Spend.validate() — the oracle never ran.',
      );
    }
    if (report.failureCount > 0 || incompleteSpendRun || vacuousRun) process.exit(1);
    return;
  }

  if (opts.triModal) {
    const report = await runTriModalDifferential({
      numCases: opts.num,
      seed: opts.seed,
      findingsDir: opts.findingsDir,
      verbose: opts.verbose,
    });
    console.log('');
    console.log('Tri-modal source-vs-script execution fuzzing complete:');
    console.log(`  Property runs: ${report.numRuns}`);
    console.log(`  Result:        ${report.failed ? 'FAILED (divergence)' : 'all three engines agree'}`);
    console.log(`  Duration:      ${report.durationMs}ms`);
    console.log(`  Seed:          ${report.seed} (replay with --seed ${report.seed})`);
    if (report.repro) console.log(`  Shrunk repro:  ${report.repro}`);
    if (report.findings.length > 0) console.log(`  Findings dir:  ${report.findings[0]}`);
    if (opts.output) {
      writeOutput(opts.output, {
        timestamp: new Date().toISOString(),
        generator: 'tri-modal',
        ...report,
      });
      console.log(`\nResults written to: ${opts.output}`);
    }
    if (report.failed) process.exit(1);
    return;
  }

  if (opts.execute) {
    const report = await runExecuteDifferential({
      numContracts: opts.num,
      seed: opts.seed,
      inputsPerMethod: opts.inputs,
      timeBudgetMs: opts.timeBudgetMs,
      findingsDir: opts.findingsDir,
      verbose: opts.verbose,
    });
    console.log('');
    console.log('Source-vs-script execution fuzzing complete:');
    console.log(`  Contracts run: ${report.contractsRun}/${report.totalContracts}`);
    console.log(`  Spends run:    ${report.casesRun} (accept=${report.acceptCount} reject=${report.rejectCount})`);
    console.log(`  Divergences:   ${report.divergenceCount}`);
    console.log(`  Errors:        ${report.errorCount}`);
    console.log(`  Duration:      ${report.durationMs}ms`);
    console.log(`  Seed:          ${report.effectiveSeed} (replay with --seed ${report.effectiveSeed})`);
    if (report.earlyStop) console.log('  Early-stopped: time budget reached');
    if (report.findings.length > 0) {
      console.log(`  Findings dir:  ${report.findings[0]}`);
    }
    if (opts.output) {
      writeOutput(opts.output, {
        timestamp: new Date().toISOString(),
        generator: 'execute',
        seed: opts.seed,
        ...report,
      });
      console.log(`\nResults written to: ${opts.output}`);
    }
    // A divergence is a real shared-design bug; a throw is a distinct anomaly.
    // Either fails the run so the gate catches it. An early-stopped run that
    // didn't finish the whole generated corpus is ALSO a failure (C5): an
    // incomplete execution-oracle run must never report an unqualified PASS.
    const incompleteExecuteRun = shouldFailRun({
      earlyStop: report.earlyStop,
      completed: report.contractsRun,
      total: report.totalContracts,
    });
    if (incompleteExecuteRun) {
      console.error(
        `INCOMPLETE RUN: time budget reached after ${report.contractsRun}/${report.totalContracts} contracts — treating as a failure.`,
      );
    }
    if (report.divergenceCount > 0 || report.errorCount > 0 || incompleteExecuteRun) process.exit(1);
    return;
  }

  if (opts.canonical) {
    const tiers = (opts.compilers as readonly string[]).filter((c): c is CanonCompilerName =>
      (CANON_ALL_TIERS as readonly string[]).includes(c),
    );
    // A tier that is not required is still not proven. Default the requirement
    // to everything the caller asked to compare.
    const requireTiers = (opts.requireTiers ?? tiers).filter((c): c is CanonCompilerName =>
      (CANON_ALL_TIERS as readonly string[]).includes(c),
    );
    const report = await runCanonicalDifferential({
      numCases: opts.num,
      seed: opts.seed,
      tiers,
      requireTiers,
      verbose: opts.verbose,
      findingsDir: opts.findingsDir,
    });
    console.log('');
    console.log('canonicalJson differential fuzzing complete:');
    console.log(`  Cases run:   ${report.casesRun}/${report.totalCases}`);
    console.log(`  Mismatches:  ${report.mismatchCount}`);
    console.log(`  Duration:    ${report.durationMs}ms`);
    // Three distinct states, previously collapsed into two: a tier that ran, a
    // tier that was asked for and could NOT run (the silent-degradation case),
    // and a tier this invocation never asked for.
    console.log(`  Tiers:       ${CANON_ALL_TIERS
      .map((t) => {
        if (!(tiers as readonly string[]).includes(t)) return `${t}=not-requested`;
        return `${t}=${report.perTierAvailable[t] ? 'ok' : 'SKIP'}`;
      })
      .join(' ')}`);
    console.log(`  Required:    ${report.requiredTiers.length > 0 ? report.requiredTiers.join(',') : '(none)'}`);
    // Loud either way. A skipped tier was never compared, so "Mismatches: 0"
    // says nothing about it — that must be visible even when it is tolerated.
    if (report.skippedTiers.length > 0) {
      console.warn(
        `  WARNING:     ${report.skippedTiers.length} tier(s) SKIPPED and NOT compared: ` +
          `${report.skippedTiers.join(', ')}. "Mismatches: 0" says nothing about them.`,
      );
    }
    if (report.findings.length > 0) {
      console.log(`  Findings:    ${report.findings.length} (e.g. ${report.findings[0]})`);
    }
    if (opts.output) {
      writeOutput(opts.output, {
        timestamp: new Date().toISOString(),
        seed: opts.seed,
        generator: 'canonical',
        ...report,
      });
      console.log(`\nResults written to: ${opts.output}`);
    }
    if (report.missingRequiredTiers.length > 0) {
      console.error('');
      console.error(
        `INCOMPLETE RUN: required tier(s) ${report.missingRequiredTiers.join(', ')} were NOT ` +
          `compared (shim missing, or not in --compilers), so this gate established parity ` +
          `across ${report.requiredTiers.length - report.missingRequiredTiers.length} of ` +
          `${report.requiredTiers.length} required tiers, not all of them.`,
      );
      console.error(
        'canonicalJson is a WIRE primitive: one divergent byte breaks every cross-tier ' +
          'signature, so an unchecked tier must never read as an agreeing tier.',
      );
      console.error(
        'Build the missing shim (Zig needs `cd packages/runar-zig && zig build canonicalise`) ' +
          'or narrow the requirement deliberately with --require-tiers.',
      );
      process.exit(1);
    }
    if (report.mismatchCount > 0) process.exit(1);
    return;
  }

  if (opts.anf) {
    // Filter the requested compilers down to the ANF tier list (the
    // CompilerName union in differential.ts matches the ANF one — same
    // 7-tier set).
    const tiers = (opts.compilers as readonly string[]).filter((c): c is AnfCompilerName =>
      (ALL_TIERS as readonly string[]).includes(c),
    );
    const report = await runAnfDifferential({
      numPrograms: opts.num,
      seed: opts.seed,
      tiers,
      verbose: opts.verbose,
      findingsDir: opts.findingsDir,
      timeBudgetMs: opts.timeBudgetMs,
      disableConstantFolding: !opts.foldOn,
    });
    console.log('');
    console.log(`ANF differential fuzzing complete:`);
    console.log(`  Programs run:  ${report.programsRun}/${report.totalPrograms}`);
    console.log(`  Mismatches:    ${report.mismatchCount}`);
    console.log(`  Duration:      ${report.durationMs}ms`);
    if (report.earlyStop) console.log(`  Early-stopped: time budget reached`);
    console.log(`  Tiers:         ${Object.entries(report.perTierAvailable)
      .map(([t, ok]) => `${t}=${ok ? 'ok' : 'skip'}`)
      .join(' ')}`);
    if (report.findings.length > 0) {
      console.log(`  Findings dir:  ${report.findings[0]}`);
    }
    if (opts.output) {
      writeOutput(opts.output, {
        timestamp: new Date().toISOString(),
        seed: opts.seed,
        ...report,
      });
      console.log(`\nResults written to: ${opts.output}`);
    }
    // An early-stopped run that didn't finish the whole generated corpus is a
    // failure (C5): an incomplete run must never report an unqualified PASS.
    const incompleteAnfRun = shouldFailRun({
      earlyStop: report.earlyStop,
      completed: report.programsRun,
      total: report.totalPrograms,
    });
    if (incompleteAnfRun) {
      console.error(
        `INCOMPLETE RUN: time budget reached after ${report.programsRun}/${report.totalPrograms} programs — treating as a failure.`,
      );
    }
    if (report.mismatchCount > 0 || incompleteAnfRun) process.exit(1);
    return;
  }

  if (opts.ir) {
    const results = await runIRDifferentialFuzzing(opts.num, {
      seed: opts.seed,
      compilers: opts.compilers,
      verbose: opts.verbose,
      compareHex: opts.hex,
      renderStrategy: opts.renderStrategy,
      includeStateful: opts.stateful,
      findingsDir: opts.findingsDir,
    });

    const mismatches = results.filter((r) => !r.match);
    if (mismatches.length > 0) {
      console.log(`\nMismatches found: ${mismatches.length}`);
      for (const m of mismatches) {
        console.log(`\n--- Mismatching contract: ${m.contractName} ---`);
        console.log(`Details: ${m.mismatchDetails}`);
      }
    }

    if (opts.output) {
      writeOutput(opts.output, {
        timestamp: new Date().toISOString(),
        totalPrograms: results.length,
        mismatches: mismatches.length,
        seed: opts.seed,
        compilers: opts.compilers,
        compareHex: opts.hex,
        generator: 'ir',
        renderStrategy: opts.renderStrategy,
        stateful: opts.stateful,
        results: results.map((r) => ({
          match: r.match,
          mismatchDetails: r.mismatchDetails,
          contractName: r.contractName,
        })),
      });
      console.log(`\nResults written to: ${opts.output}`);
    }

    if (mismatches.length > 0) process.exit(1);
    return;
  }

  const fuzzerOpts: FuzzerOptions = {
    seed: opts.seed,
    compilers: opts.compilers,
    verbose: opts.verbose,
    compareHex: opts.hex,
    findingsDir: opts.findingsDir,
  };

  if (opts.property) {
    try {
      await runPropertyBasedDifferential(fuzzerOpts);
      console.log('All property checks passed.');
    } catch (err) {
      console.error('Property check failed:');
      console.error(err instanceof Error ? err.message : err);
      process.exit(1);
    }
  } else {
    const results = await runDifferentialFuzzing(opts.num, fuzzerOpts);

    const mismatches = results.filter((r) => !r.match);
    if (mismatches.length > 0) {
      console.log(`\nMismatches found: ${mismatches.length}`);
      for (const m of mismatches) {
        console.log(`\n--- Mismatching program ---`);
        console.log(m.programSource);
        console.log(`Details: ${m.mismatchDetails}`);
      }
    }

    if (opts.output) {
      const report = {
        timestamp: new Date().toISOString(),
        totalPrograms: results.length,
        mismatches: mismatches.length,
        seed: opts.seed,
        compilers: opts.compilers,
        compareHex: opts.hex,
        results: results.map((r) => ({
          match: r.match,
          mismatchDetails: r.mismatchDetails,
          source: r.programSource,
        })),
      };
      writeOutput(opts.output, report);
      console.log(`\nResults written to: ${opts.output}`);
    }

    if (mismatches.length > 0) {
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(2);
});
