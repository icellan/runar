/**
 * Rule loader — loads peephole rules from the central JSON definition.
 *
 * The JSON rules in optimizer/peephole-rules.json serve as the canonical
 * rule definition shared across all four compilers. Each compiler implements
 * the rules procedurally for performance, but this loader validates that
 * the implementation matches the central definition.
 *
 * This module is used by tests to verify rule coverage, not at runtime.
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);

export interface JsonRule {
  name: string;
  match: JsonMatchOp[];
  replace: JsonReplaceOp[];
  type?: string;
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
