/**
 * CLI command: runar analyze — analyze compiled Bitcoin Script for issues.
 *
 * Accepts input as:
 *   - Hex string: runar analyze 76a90088ac
 *   - .hex file:  runar analyze expected-script.hex
 *   - Artifact:   runar analyze artifacts/Counter.json (reads "script" field)
 */

import { readFileSync, existsSync } from 'node:fs';
import { extname } from 'node:path';
import { analyzeScript } from 'runar-testing';
import type { AnalysisResult, FindingSeverity } from 'runar-testing';

export interface AnalyzeOptions {
  json?: boolean;
  verbose?: boolean;
  severity?: string;
}

/**
 * Resolve the input to a hex script string.
 */
function resolveInput(input: string): string {
  // "-" reads hex from stdin
  if (input === '-') {
    return readFileSync(0, 'utf-8').trim();
  }

  // Check if input is a file path
  if (existsSync(input)) {
    const ext = extname(input).toLowerCase();

    if (ext === '.json') {
      // Read artifact JSON and extract the "script" field
      const content = readFileSync(input, 'utf-8');
      const artifact = JSON.parse(content);
      if (typeof artifact.script !== 'string') {
        throw new Error(`Artifact JSON at ${input} does not contain a "script" field`);
      }
      return artifact.script;
    }

    // .hex file or any other file — read as raw hex
    return readFileSync(input, 'utf-8').trim();
  }

  // Assume it's a hex string
  return input;
}

const SEVERITY_COLORS: Record<FindingSeverity, string> = {
  error: '\x1b[31m',   // red
  warning: '\x1b[33m', // yellow
  info: '\x1b[36m',    // cyan
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

const SEVERITY_LEVELS: FindingSeverity[] = ['error', 'warning', 'info'];

/**
 * Print analysis results in human-readable format.
 */
function printResults(result: AnalysisResult, options: AnalyzeOptions): void {
  const minSeverity = (options.severity as FindingSeverity) || 'info';
  const minLevel = SEVERITY_LEVELS.indexOf(minSeverity);

  const filtered = result.findings.filter(
    (f) => SEVERITY_LEVELS.indexOf(f.severity) <= minLevel,
  );

  // Header
  console.log(`${BOLD}Script Analysis${RESET} (${result.scriptSize} bytes)`);
  console.log('');

  if (filtered.length === 0) {
    console.log('  No issues found.');
  } else {
    for (const finding of filtered) {
      const color = SEVERITY_COLORS[finding.severity];
      const severity = finding.severity.toUpperCase().padEnd(7);
      const offset = finding.offset !== undefined ? ` [offset ${finding.offset}]` : '';
      const opcode = finding.opcode ? ` (${finding.opcode})` : '';
      console.log(`  ${color}${severity}${RESET} ${finding.code}${offset}${opcode}`);
      console.log(`          ${finding.message}`);
      if (finding.path) {
        console.log(`          path: ${finding.path}`);
      }
    }
  }

  console.log('');

  // Summary
  const s = result.summary;
  console.log(`${BOLD}Summary${RESET}`);
  console.log(`  Paths: ${s.totalPaths} total, ${s.reachablePaths} reachable`);
  console.log(`  Sig checks: ${s.pathsWithCheckSig} with, ${s.pathsWithoutCheckSig} without`);
  console.log(`  Script size: ${s.scriptSizeBytes} bytes`);

  if (options.verbose && result.paths.length > 0) {
    console.log('');
    console.log(`${BOLD}Execution Paths${RESET}`);
    for (const path of result.paths) {
      const sig = path.hasCheckSig ? 'sig' : 'NO-SIG';
      console.log(`  [${path.id}] ${path.description} (stack: ${path.stackDepthAtEnd}, ${sig})`);
    }
  }

  // Error counts
  const errors = filtered.filter((f) => f.severity === 'error').length;
  const warnings = filtered.filter((f) => f.severity === 'warning').length;
  const infos = filtered.filter((f) => f.severity === 'info').length;

  console.log('');
  console.log(
    `  ${errors} error(s), ${warnings} warning(s), ${infos} info(s)`,
  );
}

/**
 * CLI action handler for the analyze command.
 */
export async function analyzeCommand(
  input: string,
  options: AnalyzeOptions,
): Promise<void> {
  try {
    const hexScript = resolveInput(input);
    const result = analyzeScript(hexScript);

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      printResults(result, options);
    }

    // Exit with non-zero if there are errors
    const hasErrors = result.findings.some((f) => f.severity === 'error');
    if (hasErrors) {
      process.exit(1);
    }
  } catch (err) {
    console.error(
      `Error: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
}
