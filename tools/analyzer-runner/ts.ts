#!/usr/bin/env -S node --import=tsx
/**
 * TS-tier analyzer wrapper for the conformance driver.
 *
 * Reads a hex file from argv[1] and writes the analyzer report (JSON)
 * to stdout in the canonical format specified by
 * spec/script-analyzer-format.md §3.
 */

import { readFileSync } from 'node:fs';
import { analyzeScript } from '../../packages/runar-testing/src/analyzer/index.js';

const FINDING_KEY_ORDER = ['severity', 'code', 'message', 'offset', 'opcode', 'path'] as const;
const PATH_KEY_ORDER = ['id', 'description', 'branchChoices', 'reachable', 'hasCheckSig', 'stackDepthAtEnd'] as const;
const SUMMARY_KEY_ORDER = ['totalPaths', 'reachablePaths', 'pathsWithCheckSig', 'pathsWithoutCheckSig', 'maxStackDepth', 'scriptSizeBytes'] as const;
const TOP_KEY_ORDER = ['script', 'scriptSize', 'findings', 'paths', 'summary'] as const;

function reorder<T extends Record<string, unknown>>(obj: T, order: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of order) {
    if (k in obj && obj[k] !== undefined) out[k] = obj[k];
  }
  return out;
}

function buildReport(result: ReturnType<typeof analyzeScript>): Record<string, unknown> {
  const orderedFindings = result.findings.map((f) => reorder(f as Record<string, unknown>, FINDING_KEY_ORDER));
  const orderedPaths = result.paths.map((p) => reorder(p as Record<string, unknown>, PATH_KEY_ORDER));
  const orderedSummary = reorder(result.summary as Record<string, unknown>, SUMMARY_KEY_ORDER);
  return reorder(
    {
      script: result.script,
      scriptSize: result.scriptSize,
      findings: orderedFindings,
      paths: orderedPaths,
      summary: orderedSummary,
    },
    TOP_KEY_ORDER,
  );
}

const hexPath = process.argv[2];
if (!hexPath) {
  console.error('usage: ts.ts <hex-file>');
  process.exit(2);
}

const hex = readFileSync(hexPath, 'utf8').trim();
const result = analyzeScript(hex);
process.stdout.write(JSON.stringify(buildReport(result), null, 2) + '\n');
