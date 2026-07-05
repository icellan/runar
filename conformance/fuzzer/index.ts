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
   * TS-GAP-001 (randomized) / TS-GAP-005 — source-vs-script EXECUTION oracle.
   * Generates stateless, non-crypto contracts, renders each to TS, and runs
   * every generated spend through the ANF interpreter AND the compiled fold-ON
   * script on ScriptVM, asserting accept/reject agreement. A divergence is a
   * real shared-design bug (all 7 tiers can agree on the same wrong bytes and
   * still pass the parity fuzzers).
   */
  execute: boolean;
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
      case '--execute':
        opts.execute = true;
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
  --execute              TS-GAP-001 (randomized) / TS-GAP-005 — source-vs-script
                         EXECUTION oracle. Generates stateless, non-crypto
                         contracts, renders each to TS, and runs every generated
                         spend through the ANF interpreter AND the compiled
                         fold-ON script on ScriptVM, asserting accept/reject
                         agreement. Unlike the parity fuzzers (--anf/--ir), this
                         catches bugs where all 7 tiers agree on the SAME wrong
                         bytes. --num = contract count; --inputs = input vectors
                         per method; --seed reproduces the corpus AND the inputs.
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
  console.log(`  Mode: ${opts.property ? 'property-based (with shrinking)' : 'sample-based'}`);
  console.log('');

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
    // Either fails the run so the gate catches it.
    if (report.divergenceCount > 0 || report.errorCount > 0) process.exit(1);
    return;
  }

  if (opts.canonical) {
    const tiers = (opts.compilers as readonly string[]).filter((c): c is CanonCompilerName =>
      (CANON_ALL_TIERS as readonly string[]).includes(c),
    );
    const report = await runCanonicalDifferential({
      numCases: opts.num,
      seed: opts.seed,
      tiers,
      verbose: opts.verbose,
      findingsDir: opts.findingsDir,
    });
    console.log('');
    console.log('canonicalJson differential fuzzing complete:');
    console.log(`  Cases run:   ${report.casesRun}/${report.totalCases}`);
    console.log(`  Mismatches:  ${report.mismatchCount}`);
    console.log(`  Duration:    ${report.durationMs}ms`);
    console.log(`  Tiers:       ${Object.entries(report.perTierAvailable)
      .map(([t, ok]) => `${t}=${ok ? 'ok' : 'skip'}`)
      .join(' ')}`);
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
    if (report.mismatchCount > 0) process.exit(1);
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
