/**
 * Rule loader — loads peephole rules from the central JSON definition.
 *
 * The JSON rules in optimizer/peephole-rules.json serve as the canonical
 * rule definition shared across all four compilers. Each compiler implements
 * the rules procedurally for performance, but this loader validates that
 * the implementation matches the central definition.
 *
 * This module is used by tests to verify rule coverage, not at runtime. Until
 * R-139 it had no callers at all (CL-GAP-005), which is how the JSON came to
 * declare an unguarded `OP_NOT OP_NOT` elimination that neither implementation
 * carries; `r139-peephole-rules-json-parity.test.ts` is the caller that now
 * holds the file to the implemented table.
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);

export interface JsonRule {
  name: string;
  match: JsonMatchOp[];
  replace: JsonReplaceOp[];
  type?: string;
  /** Why a rule is spelled the way it is — see the `not-not-elim` entry (R-139). */
  note?: string;
}

export interface JsonMatchOp {
  op: string;
  any?: boolean;
  int?: number | string;
  code?: string;
  depth?: number;
}

export interface JsonReplaceOp {
  op: string;
  code?: string;
  int?: number | string;
}

export interface TestVector {
  name: string;
  before: Record<string, unknown>[];
  after: Record<string, unknown>[];
  bytes_saved: number;
}

let _cachedRules: JsonRule[] | null = null;
let _cachedTestVectors: TestVector[] | null = null;

export function loadPeepholeRules(): JsonRule[] {
  if (_cachedRules) return _cachedRules;
  _cachedRules = require('../../../../optimizer/peephole-rules.json') as JsonRule[];
  return _cachedRules;
}

export function loadTestVectors(): TestVector[] {
  if (_cachedTestVectors) return _cachedTestVectors;
  _cachedTestVectors = require('../../../../optimizer/test-vectors.json') as TestVector[];
  return _cachedTestVectors;
}

export function ruleNames(): string[] {
  return loadPeepholeRules().map(r => r.name);
}
