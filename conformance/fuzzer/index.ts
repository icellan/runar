#!/usr/bin/env node

/**
 * TSOP Differential Fuzzer -- CLI entry point.
 *
 * Usage:
 *   npx tsx conformance/fuzzer/index.ts [options]
 *
 * Options:
 *   --num <count>          Number of random programs to generate (default: 100)
 *   --seed <n>             RNG seed for reproducibility
 *   --compilers <list>     Comma-separated list of compilers: ts,go,rust (default: ts,go,rust)
 *   --verbose              Print each generated program and result
 *   --property             Use fast-check property-based mode (with shrinking)
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
} from './differential.js';

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

interface FuzzerCLIOptions {
  num: number;
  seed?: number;
  compilers: ('ts' | 'go' | 'rust')[];
  verbose: boolean;
  property: boolean;
  output?: string;
  help: boolean;
}

function parseArgs(argv: string[]): FuzzerCLIOptions {
  const opts: FuzzerCLIOptions = {
    num: 100,
    compilers: ['ts', 'go', 'rust'],
    verbose: false,
    property: false,
    help: false,
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
        const raw = argv[++i] ?? 'ts,go,rust';
        opts.compilers = raw.split(',').map((s) => s.trim()) as FuzzerCLIOptions['compilers'];
        break;
      }
      case '--verbose':
        opts.verbose = true;
        break;
      case '--property':
        opts.property = true;
        break;
      case '--output':
        opts.output = resolve(argv[++i] ?? '');
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
TSOP Differential Fuzzer

Generates random valid TSOP contract programs, compiles them through all
available compiler implementations, and verifies that the IR output matches
byte-for-byte.

Usage:
  npx tsx conformance/fuzzer/index.ts [options]

Options:
  --num <count>          Number of random programs to generate (default: 100)
  --seed <n>             RNG seed for reproducible runs
  --compilers <list>     Comma-separated list: ts,go,rust (default: ts,go,rust)
  --verbose              Print each generated program and its result
  --property             Use fast-check property-based mode with shrinking
                         (finds minimal failing programs)
  --output <path>        Write results JSON to file
  --help, -h             Show this help message

Examples:
  # Quick smoke test with TypeScript compiler only
  npx tsx conformance/fuzzer/index.ts --num 10 --compilers ts

  # Reproducible run with seed
  npx tsx conformance/fuzzer/index.ts --seed 42 --verbose

  # Property-based mode (will shrink failing inputs)
  npx tsx conformance/fuzzer/index.ts --property --seed 12345

  # Full differential run saving results
  npx tsx conformance/fuzzer/index.ts --num 500 --output fuzz-results.json
`.trim());
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);

  if (opts.help) {
    printHelp();
    process.exit(0);
  }

  console.log('TSOP Differential Fuzzer');
  console.log(`  Programs: ${opts.num}`);
  console.log(`  Compilers: ${opts.compilers.join(', ')}`);
  if (opts.seed !== undefined) {
    console.log(`  Seed: ${opts.seed}`);
  }
  console.log(`  Mode: ${opts.property ? 'property-based (with shrinking)' : 'sample-based'}`);
  console.log('');

  const fuzzerOpts: FuzzerOptions = {
    seed: opts.seed,
    compilers: opts.compilers,
    verbose: opts.verbose,
  };

  if (opts.property) {
    // Property-based mode: fast-check handles iteration and shrinking
    try {
      await runPropertyBasedDifferential(fuzzerOpts);
      console.log('All property checks passed.');
    } catch (err) {
      console.error('Property check failed:');
      console.error(err instanceof Error ? err.message : err);
      process.exit(1);
    }
  } else {
    // Sample-based mode: generate N programs and compare
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
        results: results.map((r) => ({
          match: r.match,
          mismatchDetails: r.mismatchDetails,
          source: r.programSource,
        })),
      };
      writeFileSync(opts.output, JSON.stringify(report, null, 2) + '\n', 'utf-8');
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
