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
}

function parseArgs(argv: string[]): FuzzerCLIOptions {
  // Default compiler list: includes every compiler that can be driven from a
  // single generator run. The IR-based harness (`ir-differential.ts`) renders
  // per-compiler native sources for 'java' automatically. The legacy string
  // harness in `differential.ts` can only emit .runar.ts and silently skips
  // Java; that is intentional and documented in compileJavaSource().
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
  console.log(`  Mode: ${opts.property ? 'property-based (with shrinking)' : 'sample-based'}`);
  console.log('');

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
