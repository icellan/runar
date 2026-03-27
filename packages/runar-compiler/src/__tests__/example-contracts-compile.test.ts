/**
 * Full 6-pass compilation test for ALL example contracts.
 *
 * Runs every example contract through the COMPLETE compiler pipeline:
 *   parse → validate → typecheck → ANF lower → stack lower → emit
 *
 * This uses the same compile() function that the CLI uses. It catches
 * bugs at every level — parser issues, validator rejections, type errors,
 * ANF lowering failures, stack lowering crashes, and emit errors.
 *
 * Previously this test only ran passes 1-3, which missed stack lowering
 * crashes (e.g., "Value 't40' not found on stack") and ANF lowering
 * issues (e.g., addOutput not recognized as an intrinsic).
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { readFileSync, existsSync, readdirSync } from 'fs';
import { join } from 'path';

const EXAMPLES_DIR = join(__dirname, '..', '..', '..', '..', 'examples');

function findContracts(langDir: string, ext: string): { name: string; path: string }[] {
  const dir = join(EXAMPLES_DIR, langDir);
  if (!existsSync(dir)) return [];
  const contracts: { name: string; path: string }[] = [];
  for (const sub of readdirSync(dir)) {
    const subDir = join(dir, sub);
    try {
      for (const f of readdirSync(subDir)) {
        if (f.endsWith(ext)) {
          contracts.push({ name: `${sub}/${f}`, path: join(subDir, f) });
        }
      }
    } catch { /* not a directory */ }
  }
  return contracts;
}

function compileContract(filePath: string) {
  const source = readFileSync(filePath, 'utf-8');
  const result = compile(source, { fileName: filePath });
  const errors = result.diagnostics.filter(d => d.severity === 'error');
  return {
    success: result.success,
    errors: errors.map(e => e.message),
    hasScript: !!result.scriptHex && result.scriptHex.length > 0,
  };
}

// -------------------------------------------------------------------------
// TypeScript examples
// -------------------------------------------------------------------------

describe('TypeScript examples: full 6-pass compilation', () => {
  const contracts = findContracts('ts', '.runar.ts');
  for (const { name, path } of contracts) {
    it(`compiles ${name}`, () => {
      const result = compileContract(path);
      expect(result.errors, 'compilation errors').toEqual([]);
      expect(result.success).toBe(true);
      expect(result.hasScript, 'should produce Bitcoin Script').toBe(true);
    });
  }
});

// -------------------------------------------------------------------------
// Solidity examples
// -------------------------------------------------------------------------

describe('Solidity examples: full 6-pass compilation', () => {
  const contracts = findContracts('sol', '.runar.sol');
  for (const { name, path } of contracts) {
    it(`compiles ${name}`, () => {
      const result = compileContract(path);
      expect(result.errors, 'compilation errors').toEqual([]);
      expect(result.success).toBe(true);
      expect(result.hasScript, 'should produce Bitcoin Script').toBe(true);
    });
  }
});

// -------------------------------------------------------------------------
// Move examples
// -------------------------------------------------------------------------

describe('Move examples: full 6-pass compilation', () => {
  const contracts = findContracts('move', '.runar.move');
  for (const { name, path } of contracts) {
    it(`compiles ${name}`, () => {
      const result = compileContract(path);
      expect(result.errors, 'compilation errors').toEqual([]);
      expect(result.success).toBe(true);
      expect(result.hasScript, 'should produce Bitcoin Script').toBe(true);
    });
  }
});

// -------------------------------------------------------------------------
// Go examples
// -------------------------------------------------------------------------

describe('Go examples: full 6-pass compilation', () => {
  const contracts = findContracts('go', '.runar.go');
  for (const { name, path } of contracts) {
    it(`compiles ${name}`, () => {
      const result = compileContract(path);
      expect(result.errors, 'compilation errors').toEqual([]);
      expect(result.success).toBe(true);
      expect(result.hasScript, 'should produce Bitcoin Script').toBe(true);
    });
  }
});

// -------------------------------------------------------------------------
// Rust examples
// -------------------------------------------------------------------------

describe('Rust examples: full 6-pass compilation', () => {
  const contracts = findContracts('rust', '.runar.rs');
  for (const { name, path } of contracts) {
    it(`compiles ${name}`, () => {
      const result = compileContract(path);
      expect(result.errors, 'compilation errors').toEqual([]);
      expect(result.success).toBe(true);
      expect(result.hasScript, 'should produce Bitcoin Script').toBe(true);
    });
  }
});

// -------------------------------------------------------------------------
// Python examples
// -------------------------------------------------------------------------

describe('Python examples: full 6-pass compilation', () => {
  const contracts = findContracts('python', '.runar.py');
  for (const { name, path } of contracts) {
    it(`compiles ${name}`, () => {
      const result = compileContract(path);
      expect(result.errors, 'compilation errors').toEqual([]);
      expect(result.success).toBe(true);
      expect(result.hasScript, 'should produce Bitcoin Script').toBe(true);
    });
  }
});

// -------------------------------------------------------------------------
// Ruby examples
// -------------------------------------------------------------------------

describe('Ruby examples: full 6-pass compilation', () => {
  const contracts = findContracts('ruby', '.runar.rb');
  for (const { name, path } of contracts) {
    it(`compiles ${name}`, () => {
      const result = compileContract(path);
      expect(result.errors, 'compilation errors').toEqual([]);
      expect(result.success).toBe(true);
      expect(result.hasScript, 'should produce Bitcoin Script').toBe(true);
    });
  }
});
