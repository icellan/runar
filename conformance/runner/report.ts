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
    const tsOk = r.tsCompiler.success;
    const allCompilersSkipped = !tsOk && !r.goCompiler?.success && !r.rustCompiler?.success && !r.pythonCompiler?.success;

    let status: TestResult['status'];
    if (allCompilersSkipped) {
      status = 'skip';
    } else if (hasErrors || !r.irMatch || !r.scriptMatch) {
      status = 'fail';
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
  lines.push('| Test | TS (ms) | Go (ms) | Rust (ms) | Python (ms) |');
  lines.push('|------|---------|---------|-----------|-------------|');
  for (const r of report.results) {
    const ts = r.timings.ts !== undefined ? r.timings.ts.toFixed(1) : '-';
    const go = r.timings.go !== undefined ? r.timings.go.toFixed(1) : '-';
    const rust = r.timings.rust !== undefined ? r.timings.rust.toFixed(1) : '-';
    const python = r.timings.python !== undefined ? r.timings.python.toFixed(1) : '-';
    lines.push(`| ${r.testName} | ${ts} | ${go} | ${rust} | ${python} |`);
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
  console.log('');
}
