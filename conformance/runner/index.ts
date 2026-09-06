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
import { writeFileSync, readdirSync, existsSync } from 'fs';
import { spawn } from 'child_process';
import { runAllConformanceTests, runAllMultiFormatConformanceTests, runAllParserOnlyChecks, printParserCoverageReport, runAllIrParityChecks, printIrParityReport, updateGoldenFiles, shutdownJavaDaemon, getSpawnStats, getHarnessFaults } from './runner.js';
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
  multiFormat: boolean;
  /** When true, run the universal `--parse-only` matrix and exit. */
  parserOnly: boolean;
  /** When true, run the IR -> hex cross-tier parity gate and exit. */
  irParity: boolean;
  prebuild: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): CLIOptions {
  const opts: CLIOptions = {
    testsDir: resolve(__dirname, '../tests'),
    format: 'console',
    updateGolden: false,
    multiFormat: false,
    parserOnly: false,
    irParity: false,
    // Pre-build is OFF by default to keep the runner safe to drop into CI
    // jobs that ship prebuilt binaries via actions/download-artifact. Local
    // dev loops should pass --prebuild (or set RUNAR_PREBUILD=1) to ensure
    // the binaries are up-to-date.
    prebuild: process.env.RUNAR_PREBUILD === '1',
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
      case '--multi-format':
        opts.multiFormat = true;
        break;
      case '--parser-only':
        opts.parserOnly = true;
        break;
      case '--ir-parity':
        opts.irParity = true;
        break;
      case '--prebuild':
        opts.prebuild = true;
        break;
      case '--no-prebuild':
        opts.prebuild = false;
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
(TypeScript, Go, Rust, Python, Zig, Ruby) and compares the outputs byte-for-byte.

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
  --multi-format        Test all format variants (.ts, .sol, .move, .go, .rs)
                        instead of only .runar.ts
  --parser-only         Run the universal parser-only coverage matrix:
                        every available compiler runs --parse-only on every
                        fixture × every declared format. The per-fixture
                        \`compilers\` allowlist in source.json is IGNORED for
                        this mode (it scopes Stack-IR / hex parity, not the
                        frontend layer). Exits non-zero on any (compiler,
                        fixture, format) parser failure.
  --ir-parity           Run the cross-tier IR -> hex parity gate: compile
                        every fixture's checked-in expected-ir.json with all
                        six non-TS compilers and require byte-identical hex,
                        plus equality with expected-script.hex. Unlike
                        --parser-only, the per-fixture \`compilers\` allowlist
                        DOES scope this gate. Always fold-OFF (the goldens
                        were stamped fold-OFF). This mode is the single
                        source of truth for the rule that ci.yml used to
                        re-implement inline in bash/jq.
  --prebuild            Pre-build all native compiler binaries (Go, Rust, Zig,
                        Java) before running the suite. Default: off (so CI
                        jobs that download prebuilt artifacts aren't slowed
                        down). Local devs should pass this or set
                        RUNAR_PREBUILD=1.
  --no-prebuild         Force skip pre-build even if RUNAR_PREBUILD=1.

Environment:
  RUNAR_CONFORMANCE_CONCURRENCY  Cap on parallel test execution (default: cpus/4, capped at 8)
  RUNAR_JAVA_DAEMON=0            Disable the Java compile daemon (default: on)
  RUNAR_CONFORMANCE_SPAWN_STATS=1  Print the child-process tally at the end of the run
  RUNAR_CONFORMANCE_COMPILE_TIMEOUT_MS  Per-invocation hang detector for native
                        compilers (default: 180000). This is not a performance
                        budget: killing a slow-but-healthy child destroys its
                        output mid-pipe, which is why the budget is generous.
  RUNAR_PREBUILD=1               Same as --prebuild

  --help, -h            Show this help message

Test Directory Structure:
  Each subdirectory under the tests directory is a test case:
    <test-name>/
      <test-name>.runar.ts      Contract source (required)
      expected-ir.json          Expected ANF IR golden file (optional)
      expected-script.hex       Expected script hex golden file (optional)

Exit Code:
  0  all tests passed and every compiler subprocess produced usable output
  1  CONFORMANCE failure — the compilers disagreed, or a golden did not match
  2  HARNESS failure — a compiler subprocess timed out, was killed by a signal,
     blew the output-capture cap, or failed to spawn. The run produced NO
     trustworthy parity verdict (in either direction) and must be re-run; it
     is deliberately not reported as a cross-tier divergence.
`.trim());
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/**
 * Print the child-process tally when RUNAR_CONFORMANCE_SPAWN_STATS=1. Every
 * compiler invocation goes through `runCmd`, so this is an exact count — the
 * cheapest way to confirm the runner is still on the single-spawn
 * (`--hex --emit-ir-to`) path rather than the `--emit-ir` + `--hex` double.
 */
function maybePrintSpawnStats(): void {
  if (process.env.RUNAR_CONFORMANCE_SPAWN_STATS !== '1') return;
  const stats = getSpawnStats();
  console.log('');
  console.log(`Compiler subprocess spawns: ${stats.total}`);
  for (const [cmd, n] of Object.entries(stats.byCommand).sort((a, b) => b[1] - a[1])) {
    console.log(`  ${cmd.padEnd(24)} ${n}`);
  }
  console.log('');
}

/**
 * Exit status for a HARNESS failure — the runner or the host failed to obtain
 * a compiler's output (timeout, signal kill, over-cap capture, failed spawn).
 *
 * Deliberately distinct from the conformance-failure status (1). A harness
 * fault says NOTHING about whether the tiers agree, and must never be read as
 * a cross-tier divergence — nor may a run that suffered one be read as
 * agreement, which is why it fails even when every fixture passed.
 */
const EXIT_HARNESS_FAILURE = 2;

/**
 * Print any recorded harness faults and report whether the run is tainted.
 * Called on every exit path so no mode can drop them silently.
 */
function reportHarnessFaults(): boolean {
  const faults = getHarnessFaults();
  if (faults.length === 0) return false;
  const RED = '\x1b[31m';
  const BOLD = '\x1b[1m';
  const RESET = '\x1b[0m';
  console.error('');
  console.error(`${BOLD}${RED}HARNESS FAILURE${RESET} — ${faults.length} compiler subprocess(es) did not`);
  console.error('produce usable output. These are NOT conformance results: the runner could');
  console.error('not obtain a verdict from the tier(s) below, so this run proves nothing about');
  console.error('cross-tier parity either way. Re-run on a less loaded host, or raise');
  console.error('RUNAR_CONFORMANCE_COMPILE_TIMEOUT_MS / lower RUNAR_CONFORMANCE_CONCURRENCY.');
  console.error('');
  for (const f of faults) {
    console.error(`  ${RED}[${f.kind}]${RESET} ${f.detail}`);
    console.error(`::error::conformance harness: ${f.detail}`);
  }
  console.error('');
  return true;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);

  if (opts.help) {
    printHelp();
    process.exit(0);
  }

  if (opts.prebuild) {
    await prebuildAllCompilers();
  }

  // Handle --parser-only mode (universal frontend coverage matrix).
  // Every available compiler runs `--parse-only` on every fixture × every
  // declared format. The per-fixture `compilers` allowlist in source.json
  // is intentionally ignored — it scopes Stack-IR / hex parity, not the
  // frontend. Exits non-zero on any failure.
  if (opts.parserOnly) {
    console.log(`Running universal parser-only coverage check from: ${opts.testsDir}`);
    if (opts.filter) console.log(`Filter: ${opts.filter}`);
    console.log('');
    const startedAt = Date.now();
    const report = await runAllParserOnlyChecks(opts.testsDir, { filter: opts.filter });
    const elapsedMs = Date.now() - startedAt;
    console.log(`\nCompleted ${report.entries.length} (fixture × format) parse checks in ${(elapsedMs / 1000).toFixed(1)}s.`);
    printParserCoverageReport(report);
    maybePrintSpawnStats();
    await shutdownJavaDaemon();
    const tainted = reportHarnessFaults();
    if (tainted) {
      process.exit(EXIT_HARNESS_FAILURE);
    }
    if (!report.allOk) {
      process.exit(1);
    }
    return;
  }

  // Handle --ir-parity mode (cross-tier IR -> hex parity gate). Compiles
  // every fixture's checked-in expected-ir.json with all six non-TS tiers
  // and requires byte-identical hex + equality with expected-script.hex.
  // The per-fixture `compilers` allowlist DOES scope this gate (it scopes
  // Stack-IR / hex parity — which is exactly what this is). Always fold-OFF.
  // See runner.ts for why this is the single source of truth.
  if (opts.irParity) {
    console.log(`Running cross-tier IR -> hex parity check from: ${opts.testsDir}`);
    if (opts.filter) console.log(`Filter: ${opts.filter}`);
    console.log('');
    const startedAt = Date.now();
    const report = await runAllIrParityChecks(opts.testsDir, { filter: opts.filter });
    const elapsedMs = Date.now() - startedAt;
    console.log(`\nCompleted ${report.results.length} fixture parity checks in ${(elapsedMs / 1000).toFixed(1)}s.`);
    printIrParityReport(report);
    maybePrintSpawnStats();
    await shutdownJavaDaemon();
    const tainted = reportHarnessFaults();
    if (tainted) {
      process.exit(EXIT_HARNESS_FAILURE);
    }
    if (!report.allOk) {
      for (const f of report.failures) {
        console.error(`::error::conformance: ${f.fixture} — ${f.error.split('\n')[0]}`);
      }
      process.exit(1);
    }
    return;
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
    await shutdownJavaDaemon();
    return;
  }

  // Run conformance tests
  console.log(`Running conformance tests from: ${opts.testsDir}`);
  if (opts.filter) {
    console.log(`Filter: ${opts.filter}`);
  }
  console.log('');

  const startedAt = Date.now();
  const results = opts.multiFormat
    ? await runAllMultiFormatConformanceTests(opts.testsDir, { filter: opts.filter })
    : await runAllConformanceTests(opts.testsDir, { filter: opts.filter });
  const elapsedMs = Date.now() - startedAt;
  console.log(`\nCompleted ${results.length} test runs in ${(elapsedMs / 1000).toFixed(1)}s.`);

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

  maybePrintSpawnStats();

  // Tear down the Java daemon (if any). We do this before process.exit so
  // the JVM gets a clean shutdown rather than a SIGKILL on parent exit.
  await shutdownJavaDaemon();

  // A harness fault is reported SEPARATELY from a conformance failure, and
  // closes the misreporting hole in both directions:
  //   * it cannot be filed as a divergence — the banner and exit 2 say the
  //     runner never got an answer, so nobody goes hunting a codegen bug;
  //   * it cannot be laundered into a green run — a fault fails the run even
  //     with a clean 71/71 board.
  // The full report (including any genuine divergence) is printed above
  // regardless; only the exit status is claimed by the harness verdict, on
  // the grounds that a run whose subprocesses died did not measure parity.
  const tainted = reportHarnessFaults();
  if (tainted) {
    process.exit(EXIT_HARNESS_FAILURE);
  }
  // Exit with failure code if any tests failed
  if (report.failed > 0) {
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Pre-build (Win 5)
// ---------------------------------------------------------------------------
//
// Runs the build step for each native compiler before the main test loop.
// Each step is best-effort: a missing toolchain is logged and skipped, but
// does not abort the run (the runner already gracefully degrades when a
// compiler binary isn't on disk). Sequential — these are themselves heavy
// builds that compete for the same disk / CPU.

async function prebuildAllCompilers(): Promise<void> {
  console.log('Pre-building native compiler binaries...');
  const repoRoot = resolve(__dirname, '../..');

  const steps: Array<{ name: string; cwd: string; cmd: string; args: string[]; skipIf?: () => boolean }> = [
    {
      name: 'Go compiler (runar-go)',
      cwd: join(repoRoot, 'compilers/go'),
      cmd: 'go',
      args: ['build', '-o', 'runar-go', '.'],
      skipIf: () => !existsSync(join(repoRoot, 'compilers/go/main.go')),
    },
    {
      name: 'Rust compiler (runar-compiler-rust)',
      cwd: join(repoRoot, 'compilers/rust'),
      cmd: 'cargo',
      args: ['build', '--release'],
      skipIf: () => !existsSync(join(repoRoot, 'compilers/rust/Cargo.toml')),
    },
    {
      name: 'Zig compiler (runar-zig)',
      cwd: join(repoRoot, 'compilers/zig'),
      cmd: 'zig',
      args: ['build', '-Doptimize=ReleaseFast'],
      skipIf: () => !existsSync(join(repoRoot, 'compilers/zig/build.zig')),
    },
    {
      // The Java compiler ships as a single executable jar via Gradle's
      // built-in `jar` task — no shadow / fat-jar plugin is configured. If
      // a `shadowJar` task ever lands here, switch over (it's a faster
      // bundle).
      name: 'Java compiler (runar-java jar)',
      cwd: join(repoRoot, 'compilers/java'),
      cmd: 'gradle',
      args: ['jar', '--no-daemon', '-q'],
      skipIf: () => !existsSync(join(repoRoot, 'compilers/java/build.gradle.kts')) &&
                    !existsSync(join(repoRoot, 'compilers/java/build.gradle')),
    },
  ];

  for (const step of steps) {
    if (step.skipIf?.()) {
      console.log(`  Skipping ${step.name}: missing build files`);
      continue;
    }
    const t0 = Date.now();
    const code = await new Promise<number>((res) => {
      const p = spawn(step.cmd, step.args, {
        cwd: step.cwd,
        stdio: 'inherit',
        env: process.env,
      });
      p.on('close', (c) => res(c ?? 1));
      p.on('error', () => res(127));
    });
    const dt = ((Date.now() - t0) / 1000).toFixed(1);
    if (code === 0) {
      console.log(`  Built ${step.name} in ${dt}s`);
    } else {
      console.warn(`  Skipping ${step.name}: build returned exit ${code} in ${dt}s (will fall back to whatever's on disk)`);
    }
  }
  console.log('Pre-build complete.\n');
}

main().catch(async (err) => {
  console.error('Fatal error:', err);
  await shutdownJavaDaemon();
  process.exit(2);
});
