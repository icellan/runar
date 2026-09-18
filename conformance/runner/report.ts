import type { ConformanceResult, CompilerOutput } from './runner.js';

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

export interface ConformanceReport {
  timestamp: string;
  totalTests: number;
  passed: number;
  failed: number;
  skipped: number;
  results: TestResult[];
  compilers: CompilerInfo[];
}

export interface TestResult {
  testName: string;
  status: 'pass' | 'fail' | 'skip';
  irMatch: boolean;
  scriptMatch: boolean;
  errors: string[];
  timings: {
    ts?: number;
    go?: number;
    rust?: number;
    python?: number;
    zig?: number;
    ruby?: number;
    java?: number;
  };
}

export interface CompilerInfo {
  name: string;
  available: boolean;
  testsRun: number;
  testsSucceeded: number;
  averageDurationMs: number;
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

/** Build a structured ConformanceReport from raw runner results. */
export function generateReport(results: ConformanceResult[]): ConformanceReport {
  const timestamp = new Date().toISOString();

  const testResults: TestResult[] = results.map((r) => {
    const hasErrors = r.errors.length > 0;

    // A tier that produced NO result (undefined) was not run for this fixture
    // (allowlisted out, or its binary was unavailable) — distinct from a tier
    // that ran and FAILED (a defined result with success=false). A fixture is
    // genuinely "skipped" only when nothing was evaluated at all. TS always has
    // a result, so treat its source-not-found stub as "not run" too. Java is
    // included here — the old check omitted it entirely.
    const notRun = (c?: { success: boolean }) => c === undefined;
    const tsNotRun = !r.tsCompiler.success && /not found/i.test(r.tsCompiler.error ?? '');
    const allCompilersSkipped =
      tsNotRun &&
      notRun(r.goCompiler) && notRun(r.rustCompiler) && notRun(r.pythonCompiler) &&
      notRun(r.zigCompiler) && notRun(r.rubyCompiler) && notRun(r.javaCompiler);

    let status: TestResult['status'];
    if (hasErrors || !r.irMatch || !r.scriptMatch) {
      // A real mismatch or error is ALWAYS a failure — it must never be masked
      // as a skip (which drops it from report.failed and passes CI). The old
      // code checked all-skipped FIRST, so a fixture where every tier failed
      // (all success=false) was reported 'skip' and hidden (audit #17).
      status = 'fail';
    } else if (allCompilersSkipped) {
      status = 'skip';
    } else {
      status = 'pass';
    }

    return {
      testName: r.testName,
      status,
      irMatch: r.irMatch,
      scriptMatch: r.scriptMatch,
      errors: r.errors,
      timings: {
        ts: r.tsCompiler.durationMs,
        go: r.goCompiler?.durationMs,
        rust: r.rustCompiler?.durationMs,
        python: r.pythonCompiler?.durationMs,
        zig: r.zigCompiler?.durationMs,
        ruby: r.rubyCompiler?.durationMs,
        java: r.javaCompiler?.durationMs,
      },
    };
  });

  // Compiler statistics
  const compilers: CompilerInfo[] = [];

  // TypeScript compiler
  const tsDurations = results.filter((r) => r.tsCompiler.success).map((r) => r.tsCompiler.durationMs);
  compilers.push({
    name: 'TypeScript',
    available: true,
    testsRun: results.length,
    testsSucceeded: results.filter((r) => r.tsCompiler.success).length,
    averageDurationMs: tsDurations.length > 0
      ? tsDurations.reduce((a, b) => a + b, 0) / tsDurations.length
      : 0,
  });

  // Go compiler
  const goResults = results.filter((r) => r.goCompiler !== undefined);
  const goSuccess = goResults.filter((r) => r.goCompiler?.success);
  const goDurations = goSuccess.map((r) => r.goCompiler!.durationMs);
  compilers.push({
    name: 'Go',
    available: goResults.length > 0,
    testsRun: goResults.length,
    testsSucceeded: goSuccess.length,
    averageDurationMs: goDurations.length > 0
      ? goDurations.reduce((a, b) => a + b, 0) / goDurations.length
      : 0,
  });

  // Rust compiler
  const rustResults = results.filter((r) => r.rustCompiler !== undefined);
  const rustSuccess = rustResults.filter((r) => r.rustCompiler?.success);
  const rustDurations = rustSuccess.map((r) => r.rustCompiler!.durationMs);
  compilers.push({
    name: 'Rust',
    available: rustResults.length > 0,
    testsRun: rustResults.length,
    testsSucceeded: rustSuccess.length,
    averageDurationMs: rustDurations.length > 0
      ? rustDurations.reduce((a, b) => a + b, 0) / rustDurations.length
      : 0,
  });

  // Python compiler
  const pythonResults = results.filter((r) => r.pythonCompiler !== undefined);
  const pythonSuccess = pythonResults.filter((r) => r.pythonCompiler?.success);
  const pythonDurations = pythonSuccess.map((r) => r.pythonCompiler!.durationMs);
  compilers.push({
    name: 'Python',
    available: pythonResults.length > 0,
    testsRun: pythonResults.length,
    testsSucceeded: pythonSuccess.length,
    averageDurationMs: pythonDurations.length > 0
      ? pythonDurations.reduce((a, b) => a + b, 0) / pythonDurations.length
      : 0,
  });

  // Zig compiler
  const zigResults = results.filter((r) => r.zigCompiler !== undefined);
  const zigSuccess = zigResults.filter((r) => r.zigCompiler?.success);
  const zigDurations = zigSuccess.map((r) => r.zigCompiler!.durationMs);
  compilers.push({
    name: 'Zig',
    available: zigResults.length > 0,
    testsRun: zigResults.length,
    testsSucceeded: zigSuccess.length,
    averageDurationMs: zigDurations.length > 0
      ? zigDurations.reduce((a, b) => a + b, 0) / zigDurations.length
      : 0,
  });

  // Ruby compiler
  const rubyResults = results.filter((r) => r.rubyCompiler !== undefined);
  const rubySuccess = rubyResults.filter((r) => r.rubyCompiler?.success);
  const rubyDurations = rubySuccess.map((r) => r.rubyCompiler!.durationMs);
  compilers.push({
    name: 'Ruby',
    available: rubyResults.length > 0,
    testsRun: rubyResults.length,
    testsSucceeded: rubySuccess.length,
    averageDurationMs: rubyDurations.length > 0
      ? rubyDurations.reduce((a, b) => a + b, 0) / rubyDurations.length
      : 0,
  });

  // Java compiler.
  //
  // This block was missing while `javaCompiler` was already being populated
  // (runner.ts) and already participating in the cross-tier comparison and the
  // per-fixture duration map below. So the Java tier really was compiling and
  // being compared, but the human-readable banner listed only six tiers --
  // which reads exactly like "Java did not run" and invites a reviewer to
  // believe a 7-tier parity claim rests on 6. Under-reporting coverage is the
  // same failure mode as over-reporting it: the number stops meaning what it
  // says. Keep this in step with `runner.ts`'s tier list.
  const javaResults = results.filter((r) => r.javaCompiler !== undefined);
  const javaSuccess = javaResults.filter((r) => r.javaCompiler?.success);
  const javaDurations = javaSuccess.map((r) => r.javaCompiler!.durationMs);
  compilers.push({
    name: 'Java',
    available: javaResults.length > 0,
    testsRun: javaResults.length,
    testsSucceeded: javaSuccess.length,
    averageDurationMs: javaDurations.length > 0
      ? javaDurations.reduce((a, b) => a + b, 0) / javaDurations.length
      : 0,
  });

  return {
    timestamp,
    totalTests: results.length,
    passed: testResults.filter((r) => r.status === 'pass').length,
    failed: testResults.filter((r) => r.status === 'fail').length,
    skipped: testResults.filter((r) => r.status === 'skip').length,
    results: testResults,
    compilers,
  };
}

// ---------------------------------------------------------------------------
// Markdown formatter
// ---------------------------------------------------------------------------

/** Render a ConformanceReport as Markdown suitable for CI comments or logs. */
export function formatReportAsMarkdown(report: ConformanceReport): string {
  const lines: string[] = [];

  lines.push('# Rúnar Conformance Test Report');
  lines.push('');
  lines.push(`**Date:** ${report.timestamp}`);
  lines.push(`**Total:** ${report.totalTests} | **Passed:** ${report.passed} | **Failed:** ${report.failed} | **Skipped:** ${report.skipped}`);
  lines.push('');

  // Compiler availability table
  lines.push('## Compilers');
  lines.push('');
  lines.push('| Compiler | Available | Tests Run | Succeeded | Avg Duration |');
  lines.push('|----------|-----------|-----------|-----------|-------------|');
  for (const c of report.compilers) {
    const available = c.available ? 'Yes' : 'No';
    const avgMs = c.averageDurationMs > 0 ? `${c.averageDurationMs.toFixed(1)}ms` : '-';
    lines.push(`| ${c.name} | ${available} | ${c.testsRun} | ${c.testsSucceeded} | ${avgMs} |`);
  }
  lines.push('');

  // Results table
  lines.push('## Test Results');
  lines.push('');
  lines.push('| Test | Status | IR Match | Script Match | Errors |');
  lines.push('|------|--------|----------|-------------|--------|');
  for (const r of report.results) {
    const statusIcon = r.status === 'pass' ? 'PASS' : r.status === 'fail' ? 'FAIL' : 'SKIP';
    const irMatch = r.irMatch ? 'Yes' : 'No';
    const scriptMatch = r.scriptMatch ? 'Yes' : 'No';
    const errors = r.errors.length > 0 ? r.errors.join('; ') : '-';
    lines.push(`| ${r.testName} | ${statusIcon} | ${irMatch} | ${scriptMatch} | ${errors} |`);
  }
  lines.push('');

  // Timing details
  lines.push('## Timing Details');
  lines.push('');
  lines.push('| Test | TS (ms) | Go (ms) | Rust (ms) | Python (ms) | Zig (ms) | Ruby (ms) |');
  lines.push('|------|---------|---------|-----------|-------------|----------|-----------|');
  for (const r of report.results) {
    const ts = r.timings.ts !== undefined ? r.timings.ts.toFixed(1) : '-';
    const go = r.timings.go !== undefined ? r.timings.go.toFixed(1) : '-';
    const rust = r.timings.rust !== undefined ? r.timings.rust.toFixed(1) : '-';
    const python = r.timings.python !== undefined ? r.timings.python.toFixed(1) : '-';
    const zig = r.timings.zig !== undefined ? r.timings.zig.toFixed(1) : '-';
    const ruby = r.timings.ruby !== undefined ? r.timings.ruby.toFixed(1) : '-';
    lines.push(`| ${r.testName} | ${ts} | ${go} | ${rust} | ${python} | ${zig} | ${ruby} |`);
  }
  lines.push('');

  // Failure details
  const failures = report.results.filter((r) => r.status === 'fail');
  if (failures.length > 0) {
    lines.push('## Failure Details');
    lines.push('');
    for (const f of failures) {
      lines.push(`### ${f.testName}`);
      lines.push('');
      for (const err of f.errors) {
        lines.push(`- ${err}`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// JSON formatter
// ---------------------------------------------------------------------------

/** Render a ConformanceReport as formatted JSON for machine consumption. */
export function formatReportAsJSON(report: ConformanceReport): string {
  return JSON.stringify(report, null, 2);
}

// ---------------------------------------------------------------------------
// Console formatter (for terminal output)
// ---------------------------------------------------------------------------

/** Print a colorized summary to the console. */
export function printReportToConsole(report: ConformanceReport): void {
  const RESET = '\x1b[0m';
  const GREEN = '\x1b[32m';
  const RED = '\x1b[31m';
  const YELLOW = '\x1b[33m';
  const BOLD = '\x1b[1m';
  const DIM = '\x1b[2m';

  console.log('');
  console.log(`${BOLD}Rúnar Conformance Test Report${RESET}`);
  console.log(`${DIM}${report.timestamp}${RESET}`);
  console.log('');

  // Compiler info
  for (const c of report.compilers) {
    const status = c.available ? `${GREEN}available${RESET}` : `${DIM}not found${RESET}`;
    console.log(`  ${c.name}: ${status}`);
  }
  console.log('');

  // Per-test results
  for (const r of report.results) {
    let icon: string;
    let color: string;
    switch (r.status) {
      case 'pass':
        icon = 'PASS';
        color = GREEN;
        break;
      case 'fail':
        icon = 'FAIL';
        color = RED;
        break;
      case 'skip':
        icon = 'SKIP';
        color = YELLOW;
        break;
    }
    const timing = r.timings.ts !== undefined ? `${DIM}(${r.timings.ts.toFixed(0)}ms)${RESET}` : '';
    console.log(`  ${color}${icon}${RESET} ${r.testName} ${timing}`);

    if (r.errors.length > 0) {
      for (const err of r.errors) {
        console.log(`       ${RED}${err}${RESET}`);
      }
    }
  }

  // Summary
  console.log('');
  const passColor = report.passed > 0 ? GREEN : DIM;
  const failColor = report.failed > 0 ? RED : DIM;
  const skipColor = report.skipped > 0 ? YELLOW : DIM;
  console.log(
    `${BOLD}Summary:${RESET} ` +
    `${passColor}${report.passed} passed${RESET}, ` +
    `${failColor}${report.failed} failed${RESET}, ` +
    `${skipColor}${report.skipped} skipped${RESET} ` +
    `(${report.totalTests} total)`,
  );

  // R-103: a run that never exercised a tier must not be mistakable for full
  // coverage. The runner only hard-fails on a missing toolchain in CI (or when
  // RUNAR_CONFORMANCE_STRICT is set); everywhere else the summary has to say
  // out loud which tiers contributed nothing.
  const absent = report.compilers.filter((c) => !c.available).map((c) => c.name);
  if (absent.length > 0) {
    console.log('');
    console.log(
      `${BOLD}${YELLOW}INCOMPLETE COVERAGE:${RESET} ` +
      `${absent.length} of ${report.compilers.length} tiers produced no results: ` +
      `${BOLD}${absent.join(', ')}${RESET}.`,
    );
    console.log(
      `  This PASS covers ${report.compilers.length - absent.length} tiers, not ${report.compilers.length}. ` +
      `Set RUNAR_CONFORMANCE_STRICT=1 to exit non-zero instead.`,
    );
  }
  console.log('');
}
