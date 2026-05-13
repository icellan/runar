/**
 * Bitcoin Script static analyzer — main entry point.
 *
 * Orchestrates script parsing, stack safety analysis, path enumeration,
 * signature hygiene checks, and opcode concern detection.
 */

import { parseScript, collapseRawScriptSpans } from './script-parser.js';
import { analyzeStackLinear, checkTerminalStack } from './stack-analyzer.js';
import { analyzePaths } from './path-analyzer.js';
import { analyzeSigHygiene } from './sig-analyzer.js';
import { analyzeOpcodeConcerns } from './opcode-concerns.js';
import type {
  AnalysisFinding,
  AnalysisResult,
  AnalysisSummary,
  AnalyzeOptions,
  FindingSeverity,
} from './types.js';

// Re-export types and utilities
export {
  parseScript,
  collapseRawScriptSpans,
  isRawSpan,
  RAW_SPAN_OPCODE,
} from './script-parser.js';
export type { ParsedOpcode } from './script-parser.js';
export { getStackEffect, analyzeStackLinear } from './stack-analyzer.js';
export { analyzePaths } from './path-analyzer.js';
export { analyzeSigHygiene } from './sig-analyzer.js';
export { analyzeOpcodeConcerns } from './opcode-concerns.js';
export type {
  AnalysisFinding,
  AnalysisResult,
  AnalysisSummary,
  AnalyzeOptions,
  ExecutionPath,
  FindingSeverity,
  FindingCode,
  RawScriptSpan,
} from './types.js';

// ---------------------------------------------------------------------------
// Severity ordering for sorting
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  error: 0,
  warning: 1,
  info: 2,
};

function sortFindings(findings: AnalysisFinding[]): AnalysisFinding[] {
  return [...findings].sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sevDiff !== 0) return sevDiff;
    return (a.offset ?? Infinity) - (b.offset ?? Infinity);
  });
}

// ---------------------------------------------------------------------------
// Main analyzer
// ---------------------------------------------------------------------------

/**
 * Analyze a hex-encoded Bitcoin Script for potential issues.
 *
 * @param hexScript - The hex-encoded Bitcoin Script to analyze.
 * @param options  - Optional `rawScriptSpans` from the artifact, surfaced by
 *                   the compiler for `asm({...})` regions. When supplied, the
 *                   analyzer skips opcode-level inspection inside each span
 *                   and carries stack depth across them using the declared
 *                   `inArity` / `outArity`.
 * @returns Analysis result with findings, execution paths, and summary.
 */
export function analyzeScript(
  hexScript: string,
  options: AnalyzeOptions = {},
): AnalysisResult {
  const normalizedHex = hexScript.replace(/\s/g, '').toLowerCase();
  const scriptSizeBytes = normalizedHex.length / 2;
  const allFindings: AnalysisFinding[] = [];

  // Handle empty script
  if (normalizedHex.length === 0) {
    const emptyFinding = checkTerminalStack(0, 0);
    if (emptyFinding) allFindings.push(emptyFinding);

    return {
      script: normalizedHex,
      scriptSize: 0,
      findings: allFindings,
      paths: [],
      summary: {
        totalPaths: 0,
        reachablePaths: 0,
        pathsWithCheckSig: 0,
        pathsWithoutCheckSig: 0,
        maxStackDepth: 0,
        scriptSizeBytes: 0,
      },
    };
  }

  // Step 1: Parse the script and collapse raw_script spans into opaque steps.
  let opcodes = parseScript(normalizedHex);
  if (options.rawScriptSpans && options.rawScriptSpans.length > 0) {
    opcodes = collapseRawScriptSpans(opcodes, options.rawScriptSpans);
  }

  // Step 2: Path analysis (includes stack analysis per path and branch structure validation)
  const { paths, findings: pathFindings } = analyzePaths(opcodes);
  allFindings.push(...pathFindings);

  // Step 3: If no paths were enumerated (due to structural errors), do linear analysis
  if (paths.length === 0 && !pathFindings.some((f) => f.code === 'UNBALANCED_IF_ENDIF')) {
    const linearResult = analyzeStackLinear(opcodes);
    allFindings.push(...linearResult.findings);
  }

  // Step 4: Signature hygiene
  const sigFindings = analyzeSigHygiene(opcodes, paths);
  allFindings.push(...sigFindings);

  // Step 5: Opcode concerns
  const opcodeConcerns = analyzeOpcodeConcerns(opcodes, scriptSizeBytes);
  allFindings.push(...opcodeConcerns);

  // Build summary
  const reachablePaths = paths.filter((p) => p.reachable);
  const pathsWithCheckSig = reachablePaths.filter((p) => p.hasCheckSig);
  const pathsWithoutCheckSig = reachablePaths.filter((p) => !p.hasCheckSig);
  const maxStackDepth = paths.length > 0
    ? Math.max(...paths.map((p) => p.stackDepthAtEnd), 0)
    : 0;

  const summary: AnalysisSummary = {
    totalPaths: paths.length,
    reachablePaths: reachablePaths.length,
    pathsWithCheckSig: pathsWithCheckSig.length,
    pathsWithoutCheckSig: pathsWithoutCheckSig.length,
    maxStackDepth,
    scriptSizeBytes,
  };

  return {
    script: normalizedHex,
    scriptSize: scriptSizeBytes,
    findings: sortFindings(allFindings),
    paths,
    summary,
  };
}
