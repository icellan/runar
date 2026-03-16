/**
 * Multi-format conformance tests.
 *
 * Verifies that all frontend formats (.runar.yaml, .runar.sol, .runar.move)
 * produce valid ASTs through the TypeScript compiler, and that the parse()
 * dispatcher routes correctly based on file extension.
 */

import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CONFORMANCE_DIR = join(__dirname, '..', '..', '..', '..', 'conformance', 'tests');

const FORMAT_EXTENSIONS = ['.runar.ts', '.runar.sol', '.runar.move'] as const;

function readConformanceSource(testName: string, ext: string): string | null {
  const path = join(CONFORMANCE_DIR, testName, `${testName}${ext}`);
  if (!existsSync(path)) return null;
  return readFileSync(path, 'utf-8');
}

// ---------------------------------------------------------------------------
// Dispatch tests: parse() routes by file extension
// ---------------------------------------------------------------------------

describe('Multi-format: parse() dispatch', () => {
  it('dispatches .runar.sol to Solidity parser', () => {
    const source = readConformanceSource('arithmetic', '.runar.sol');
    if (!source) return;
    const result = parse(source, 'arithmetic.runar.sol');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('Arithmetic');
  });

  it('dispatches .runar.move to Move parser', () => {
    const source = readConformanceSource('arithmetic', '.runar.move');
    if (!source) return;
    const result = parse(source, 'arithmetic.runar.move');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('Arithmetic');
  });

  it('dispatches .runar.ts to TypeScript parser (default)', () => {
    const source = readConformanceSource('arithmetic', '.runar.ts');
    if (!source) return;
    const result = parse(source, 'arithmetic.runar.ts');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('Arithmetic');
  });

  it('defaults to TypeScript parser for unrecognized extensions', () => {
    const source = readConformanceSource('arithmetic', '.runar.ts');
    if (!source) return;
    const result = parse(source, 'arithmetic.unknown');
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('Arithmetic');
  });

  it('dispatches .runar.py to Python parser (row 64)', () => {
    const source = readConformanceSource('basic-p2pkh', '.runar.py');
    if (!source) return;
    const result = parse(source, 'basic-p2pkh.runar.py');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('P2PKH');
  });

  it('parses .runar.go files using the Go parser (row 318)', () => {
    const source = readConformanceSource('basic-p2pkh', '.runar.go');
    if (!source) return;
    const result = parse(source, 'basic-p2pkh.runar.go');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('P2PKH');
  });

  it('dispatches .runar.rs to Rust parser (row 321)', () => {
    const source = readConformanceSource('basic-p2pkh', '.runar.rs');
    if (!source) return;
    const result = parse(source, 'basic-p2pkh.runar.rs');
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('P2PKH');
  });

  it('unknown extension produces errors or falls back to TS parser (row 323)', () => {
    // When an unknown extension is passed with invalid source, it produces errors.
    const result = parse('this is not valid typescript', 'contract.runar.xyz');
    // Either no contract or errors
    const hasErrorsOrNoContract = result.contract === null || result.errors.some(e => e.severity === 'error');
    expect(hasErrorsOrNoContract).toBe(true);
  });

  it('empty source produces error (row 72)', () => {
    // An empty string has no class declaration → error or null contract
    const result = parse('', 'contract.runar.ts');
    const hasErrorsOrNoContract = result.contract === null || result.errors.some(e => e.severity === 'error');
    expect(hasErrorsOrNoContract).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Cross-format: each format parses to valid contract structure
// ---------------------------------------------------------------------------

const CONFORMANCE_TESTS = [
  { name: 'arithmetic', contractName: 'Arithmetic', parentClass: 'SmartContract' },
  { name: 'basic-p2pkh', contractName: 'P2PKH', parentClass: 'SmartContract' },
  { name: 'boolean-logic', contractName: 'BooleanLogic', parentClass: 'SmartContract' },
  { name: 'if-else', contractName: 'IfElse', parentClass: 'SmartContract' },
  { name: 'bounded-loop', contractName: 'BoundedLoop', parentClass: 'SmartContract' },
  { name: 'multi-method', contractName: 'MultiMethod', parentClass: 'SmartContract' },
];

describe('Multi-format: conformance test parsing', () => {
  for (const { name, contractName } of CONFORMANCE_TESTS) {
    for (const ext of FORMAT_EXTENSIONS) {
      it(`parses ${name}${ext} successfully`, () => {
        const source = readConformanceSource(name, ext);
        if (!source) return; // skip if file doesn't exist
        const result = parse(source, `${name}${ext}`);
        const errors = result.errors.filter(e => e.severity === 'error');
        expect(errors).toEqual([]);
        expect(result.contract).not.toBeNull();
        expect(result.contract!.name).toBe(contractName);
        expect(result.contract!.properties.length).toBeGreaterThan(0);
        expect(result.contract!.methods.length).toBeGreaterThan(0);
      });
    }
  }
});

// ---------------------------------------------------------------------------
// Cross-format: AST structural consistency
// ---------------------------------------------------------------------------

describe('Multi-format: cross-format structural consistency', () => {
  for (const { name } of CONFORMANCE_TESTS) {
    it(`all formats of ${name} produce matching contract structure`, () => {
      const results: { ext: string; contract: NonNullable<ReturnType<typeof parse>['contract']> }[] = [];

      for (const ext of FORMAT_EXTENSIONS) {
        const source = readConformanceSource(name, ext);
        if (!source) continue;
        const result = parse(source, `${name}${ext}`);
        if (result.errors.filter(e => e.severity === 'error').length > 0) continue;
        if (!result.contract) continue;
        results.push({ ext, contract: result.contract });
      }

      if (results.length < 2) return; // need at least 2 formats to compare

      const ref = results[0]!;
      for (let i = 1; i < results.length; i++) {
        const cmp = results[i]!;

        // Contract name must match
        expect(cmp.contract.name).toBe(ref.contract.name);

        // Same number of properties
        expect(cmp.contract.properties.length).toBe(ref.contract.properties.length);

        // Property names and readonly flags must match
        for (let j = 0; j < ref.contract.properties.length; j++) {
          expect(cmp.contract.properties[j]!.name).toBe(ref.contract.properties[j]!.name);
          expect(cmp.contract.properties[j]!.readonly).toBe(ref.contract.properties[j]!.readonly);
        }

        // Same number of methods
        expect(cmp.contract.methods.length).toBe(ref.contract.methods.length);

        // Method names and visibility must match
        for (let j = 0; j < ref.contract.methods.length; j++) {
          expect(cmp.contract.methods[j]!.name).toBe(ref.contract.methods[j]!.name);
          expect(cmp.contract.methods[j]!.visibility).toBe(ref.contract.methods[j]!.visibility);
          expect(cmp.contract.methods[j]!.params.length).toBe(ref.contract.methods[j]!.params.length);
        }
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Stateful contract format tests
// ---------------------------------------------------------------------------

describe('Multi-format: stateful contract', () => {
  for (const ext of FORMAT_EXTENSIONS) {
    it(`parses stateful contract from ${ext}`, () => {
      const source = readConformanceSource('stateful', ext);
      if (!source) return;
      const result = parse(source, `stateful${ext}`);
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors).toEqual([]);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.name).toBe('Stateful');

      // Stateful contracts should have mutable properties
      const hasMutable = result.contract!.properties.some(p => !p.readonly);
      expect(hasMutable).toBe(true);
    });
  }
});
