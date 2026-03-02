#!/usr/bin/env node

/**
 * Rúnar Conformance Test Runner -- CLI entry point.
 *
 * Usage:
 *   npx tsx conformance/runner/index.ts [options]
 *
 * Options:
 *   --tests-dir <path>    Directory containing test cases (default: conformance/tests)
 *   --filter <name>       Only run tests whose name includes this substring
 *   --format <fmt>        Output format: console (default), json, markdown
 *   --output <path>       Write report to file instead of stdout
 *   --update-golden       Update golden files from TS compiler output
 *   --help                Show this help message
 */

import { resolve, join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { writeFileSync, readdirSync } from 'fs';
import { runAllConformanceTests, runConformanceTest, updateGoldenFiles } from './runner.js';
import {
  generateReport,
  formatReportAsJSON,
  formatReportAsMarkdown,
  printReportToConsole,
} from './report.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

interface CLIOptions {
  testsDir: string;
  filter?: string;
  format: 'console' | 'json' | 'markdown';
  output?: string;
  updateGolden: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): CLIOptions {
  const opts: CLIOptions = {
    testsDir: resolve(__dirname, '../tests'),
    format: 'console',
    updateGolden: false,
    help: false,
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i]!;
    switch (arg) {
      case '--tests-dir':
        opts.testsDir = resolve(argv[++i] ?? opts.testsDir);
        break;
      case '--filter':
        opts.filter = argv[++i];
        break;
      case '--format':
        opts.format = (argv[++i] as CLIOptions['format']) ?? 'console';
        break;
      case '--output':
        opts.output = resolve(argv[++i] ?? '');
        break;
      case '--update-golden':
        opts.updateGolden = true;
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
Rúnar Conformance Test Runner

Runs Rúnar contract source files through all available compiler implementations
(TypeScript, Go, Rust) and compares the outputs byte-for-byte.

Usage:
  npx tsx conformance/runner/index.ts [options]

Options:
  --tests-dir <path>    Directory containing test cases
                        (default: conformance/tests)
  --filter <name>       Only run tests whose name includes this substring
  --format <fmt>        Output format: console (default), json, markdown
  --output <path>       Write report to file instead of stdout
  --update-golden       Update golden files from TS compiler output
                        (overwrites expected-ir.json and expected-script.hex)
  --help, -h            Show this help message

Test Directory Structure:
  Each subdirectory under the tests directory is a test case:
    <test-name>/
      <test-name>.runar.ts      Contract source (required)
      expected-ir.json          Expected ANF IR golden file (optional)
      expected-script.hex       Expected script hex golden file (optional)

Exit Code:
  0 if all tests pass, 1 if any test fails.
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

  // Handle --update-golden mode
  if (opts.updateGolden) {
    console.log('Updating golden files from TypeScript compiler output...');
    const entries = readdirSync(opts.testsDir, { withFileTypes: true });
    const testDirs = entries
      .filter((e) => e.isDirectory())
      .map((e) => join(opts.testsDir, e.name));

    for (const testDir of testDirs) {
      try {
        await updateGoldenFiles(testDir);
        console.log(`  Updated: ${testDir}`);
      } catch (err) {
        console.error(`  Failed: ${testDir}: ${err instanceof Error ? err.message : err}`);
      }
    }
    return;
  }

  // Run conformance tests
  console.log(`Running conformance tests from: ${opts.testsDir}`);
  if (opts.filter) {
    console.log(`Filter: ${opts.filter}`);
  }
  console.log('');

  const results = await runAllConformanceTests(opts.testsDir, {
    filter: opts.filter,
  });

  const report = generateReport(results);

  // Output the report
  switch (opts.format) {
    case 'json': {
      const json = formatReportAsJSON(report);
      if (opts.output) {
        writeFileSync(opts.output, json + '\n', 'utf-8');
        console.log(`Report written to: ${opts.output}`);
      } else {
        console.log(json);
      }
      break;
    }
    case 'markdown': {
      const md = formatReportAsMarkdown(report);
      if (opts.output) {
        writeFileSync(opts.output, md + '\n', 'utf-8');
        console.log(`Report written to: ${opts.output}`);
      } else {
        console.log(md);
      }
      break;
    }
    case 'console':
    default: {
      printReportToConsole(report);
      if (opts.output) {
        const json = formatReportAsJSON(report);
        writeFileSync(opts.output, json + '\n', 'utf-8');
        console.log(`Full report written to: ${opts.output}`);
      }
      break;
    }
  }

  // Exit with failure code if any tests failed
  if (report.failed > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(2);
});
