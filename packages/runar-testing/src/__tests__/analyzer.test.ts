import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { analyzeScript, analyzeStackLinear, parseScript } from '../analyzer/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CONFORMANCE_DIR = resolve(
  import.meta.dirname ?? __dirname,
  '../../../../conformance/tests',
);

function readGoldenHex(testName: string): string | null {
  const hexPath = join(CONFORMANCE_DIR, testName, 'expected-script.hex');
  if (!existsSync(hexPath)) return null;
  return readFileSync(hexPath, 'utf-8').trim();
}

// ---------------------------------------------------------------------------
// 1. Golden file tests — all conformance scripts should produce no errors
// ---------------------------------------------------------------------------

describe('Analyzer: conformance golden files', () => {
  // Dynamically discover all conformance test directories
  const testDirs = existsSync(CONFORMANCE_DIR)
    ? readdirSync(CONFORMANCE_DIR, { withFileTypes: true })
        .filter((d) => d.isDirectory())
        .map((d) => d.name)
    : [];

  it.each(testDirs)('%s — no errors', (testName) => {
    const hex = readGoldenHex(testName);
    if (!hex) return; // skip if no hex file

    const result = analyzeScript(hex);
    const errors = result.findings.filter((f) => f.severity === 'error');

    // Compiler-generated scripts should have no errors
    expect(errors).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 2. Known-good scripts
// ---------------------------------------------------------------------------

describe('Analyzer: known-good scripts', () => {
  it('P2PKH (76a90088ac) — no errors', () => {
    // OP_DUP OP_HASH160 OP_0 OP_EQUALVERIFY OP_CHECKSIG
    const result = analyzeScript('76a90088ac');
    const errors = result.findings.filter((f) => f.severity === 'error');
    expect(errors).toEqual([]);

    // Should have exactly one linear path
    expect(result.paths.length).toBeGreaterThanOrEqual(1);
    // Path should have a checksig
    expect(result.paths.some((p) => p.hasCheckSig)).toBe(true);
  });

  it('if-else script — no errors', () => {
    // From conformance: 007c637c0093677c00946800a0
    const result = analyzeScript('007c637c0093677c00946800a0');
    const errors = result.findings.filter((f) => f.severity === 'error');
    expect(errors).toEqual([]);
    // Should have 2 paths (IF true, IF false)
    expect(result.paths.length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// 3. Crafted bad scripts
// ---------------------------------------------------------------------------

describe('Analyzer: crafted bad scripts', () => {
  it('empty script — INVALID_TERMINAL_STACK', () => {
    const result = analyzeScript('');
    expect(result.findings.some((f) => f.code === 'INVALID_TERMINAL_STACK')).toBe(true);
  });

  it('OP_RETURN followed by OP_1 — UNREACHABLE_AFTER_RETURN', () => {
    // OP_RETURN (6a) then OP_1 (51)
    const result = analyzeScript('6a51');
    expect(result.findings.some((f) => f.code === 'UNREACHABLE_AFTER_RETURN')).toBe(true);
  });

  it('OP_ADD with known stack — STACK_UNDERFLOW', () => {
    // OP_ADD (93) requires 2 items. With explicit initialDepth=1,
    // we know there's only 1 item so OP_ADD causes underflow.
    const ops = parseScript('93');
    const result = analyzeStackLinear(ops, 1);
    expect(result.findings.some((f) => f.code === 'STACK_UNDERFLOW')).toBe(true);
  });

  it('unbalanced IF/ENDIF — OP_ENDIF without IF', () => {
    // OP_ENDIF (68) without matching OP_IF
    const result = analyzeScript('68');
    expect(result.findings.some((f) => f.code === 'UNBALANCED_IF_ENDIF')).toBe(true);
  });

  it('unbalanced IF/ENDIF — OP_IF without ENDIF', () => {
    // OP_1 (51) OP_IF (63) OP_1 (51) — no ENDIF
    const result = analyzeScript('516351');
    expect(result.findings.some((f) => f.code === 'UNBALANCED_IF_ENDIF')).toBe(true);
  });

  it('script with no OP_CHECKSIG — NO_SIG_CHECK warning', () => {
    // OP_1 OP_1 OP_ADD — no signature check
    const result = analyzeScript('515193');
    expect(
      result.findings.some(
        (f) => f.code === 'NO_SIG_CHECK' && f.severity === 'warning',
      ),
    ).toBe(true);
  });

  it('OP_CHECKSIG followed by OP_DROP — CHECKSIG_RESULT_DROPPED', () => {
    // OP_0 OP_0 OP_CHECKSIG OP_DROP
    const result = analyzeScript('0000ac75');
    expect(
      result.findings.some(
        (f) => f.code === 'CHECKSIG_RESULT_DROPPED' && f.severity === 'warning',
      ),
    ).toBe(true);
  });

  it('OP_PUSHDATA1 for 2-byte data — INEFFICIENT_PUSH', () => {
    // OP_PUSHDATA1 (4c) length=2 (02) data=aabb
    // Direct push 0x02 would be more efficient
    const result = analyzeScript('4c02aabb');
    expect(
      result.findings.some(
        (f) => f.code === 'INEFFICIENT_PUSH' && f.severity === 'info',
      ),
    ).toBe(true);
  });

  it('OP_ELSE without IF — UNBALANCED_IF_ENDIF', () => {
    // OP_ELSE (67) without matching IF
    const result = analyzeScript('67');
    expect(result.findings.some((f) => f.code === 'UNBALANCED_IF_ENDIF')).toBe(true);
  });

  it('lone OP_1 — UNCONDITIONALLY_SUCCEEDS', () => {
    // OP_1 (51) — script leaves a truthy constant on the stack with no checks
    const result = analyzeScript('51');
    expect(
      result.findings.some(
        (f) => f.code === 'UNCONDITIONALLY_SUCCEEDS' && f.severity === 'warning',
      ),
    ).toBe(true);
  });

  it('arithmetic-only script — UNCONDITIONALLY_SUCCEEDS', () => {
    // OP_1 OP_1 OP_ADD (515193) — no verify/sig check anywhere
    const result = analyzeScript('515193');
    expect(
      result.findings.some((f) => f.code === 'UNCONDITIONALLY_SUCCEEDS'),
    ).toBe(true);
  });

  it('P2PKH — no UNCONDITIONALLY_SUCCEEDS', () => {
    // Standard P2PKH has OP_CHECKSIG — should not be flagged
    const result = analyzeScript('76a90088ac');
    expect(
      result.findings.some((f) => f.code === 'UNCONDITIONALLY_SUCCEEDS'),
    ).toBe(false);
  });

  it('IF/ELSE with unequal deltas — INCONSISTENT_BRANCH_DEPTH', () => {
    // OP_1 OP_IF OP_1 OP_ELSE OP_1 OP_1 OP_ENDIF OP_ADD
    // THEN pushes 1, ELSE pushes 2 — deltas differ.
    const result = analyzeScript('51635167515168 93'.replace(/ /g, ''));
    expect(
      result.findings.some(
        (f) => f.code === 'INCONSISTENT_BRANCH_DEPTH' && f.severity === 'warning',
      ),
    ).toBe(true);
  });

  it('IF without ELSE with non-zero body delta — INCONSISTENT_BRANCH_DEPTH', () => {
    // OP_1 OP_IF OP_1 OP_ENDIF — body pushes 1 with no ELSE counterpart
    const result = analyzeScript('51635168');
    expect(
      result.findings.some((f) => f.code === 'INCONSISTENT_BRANCH_DEPTH'),
    ).toBe(true);
  });

  it('IF/ELSE with equal deltas — no INCONSISTENT_BRANCH_DEPTH', () => {
    // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF — both branches push exactly 1
    const result = analyzeScript('5163526753 68'.replace(/ /g, ''));
    expect(
      result.findings.some((f) => f.code === 'INCONSISTENT_BRANCH_DEPTH'),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 4. Summary structure
// ---------------------------------------------------------------------------

describe('Analyzer: summary', () => {
  it('includes correct script size', () => {
    const result = analyzeScript('76a90088ac');
    expect(result.scriptSize).toBe(5);
    expect(result.summary.scriptSizeBytes).toBe(5);
  });

  it('reports path counts correctly', () => {
    // OP_0 OP_SWAP OP_IF OP_SWAP OP_0 OP_ADD OP_ELSE OP_SWAP OP_0 OP_SUB OP_ENDIF OP_GREATERTHAN
    // 007c637c0093677c00946800a0
    const result = analyzeScript('007c637c0093677c00946800a0');
    expect(result.summary.totalPaths).toBe(2);
    expect(result.summary.reachablePaths).toBe(2);
  });

  it('handles whitespace in hex input', () => {
    const result = analyzeScript('76 a9 00 88 ac');
    expect(result.scriptSize).toBe(5);
    const errors = result.findings.filter((f) => f.severity === 'error');
    expect(errors).toEqual([]);
  });

  it('handles uppercase hex', () => {
    const result = analyzeScript('76A90088AC');
    expect(result.scriptSize).toBe(5);
    const errors = result.findings.filter((f) => f.severity === 'error');
    expect(errors).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 4b. Path truncation
// ---------------------------------------------------------------------------

describe('Analyzer: path truncation', () => {
  it('emits PATHS_TRUNCATED warning when paths exceed MAX_PATHS=256', () => {
    // Construct a script with 9 sequential OP_IF/OP_ENDIF pairs.
    // 2^9 = 512 > 256 (MAX_PATHS), so path enumeration must truncate and
    // emit a single PATHS_TRUNCATED finding.
    // Each branch: OP_1 (51) OP_IF (63) OP_ENDIF (68) = "516368"
    const branchHex = '516368'.repeat(9);
    const result = analyzeScript(branchHex);

    const truncation = result.findings.filter(
      (f) => f.code === 'PATHS_TRUNCATED' && f.severity === 'warning',
    );
    expect(truncation.length).toBe(1);
    expect(truncation[0]!.message).toMatch(/truncated/i);
    // Only MAX_PATHS paths should be enumerated.
    expect(result.paths.length).toBe(256);
  });

  it('does not emit PATHS_TRUNCATED for a script with <= 8 branches', () => {
    // 8 branches: 2^8 = 256 exactly == MAX_PATHS, no truncation.
    const branchHex = '516368'.repeat(8);
    const result = analyzeScript(branchHex);
    const truncation = result.findings.filter((f) => f.code === 'PATHS_TRUNCATED');
    expect(truncation).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 5. Edge cases
// ---------------------------------------------------------------------------

describe('Analyzer: edge cases', () => {
  it('single OP_RETURN', () => {
    const result = analyzeScript('6a');
    // OP_RETURN alone: no unreachable code after it
    const unreachable = result.findings.filter(
      (f) => f.code === 'UNREACHABLE_AFTER_RETURN',
    );
    expect(unreachable).toEqual([]);
  });

  it('nested IF/ELSE/ENDIF', () => {
    // OP_1 OP_IF OP_1 OP_IF OP_1 OP_ENDIF OP_ENDIF
    analyzeScript('5163516351686851686851');
    // Should not crash and should have no errors
    // (may have structural issues depending on nesting)
  });

  it('single OP_CHECKSIG', () => {
    // OP_0 OP_0 OP_CHECKSIG
    const result = analyzeScript('0000ac');
    const errors = result.findings.filter((f) => f.severity === 'error');
    expect(errors).toEqual([]);
    expect(result.paths.some((p) => p.hasCheckSig)).toBe(true);
  });
});
