/**
 * Multi-format conformance tests.
 *
 * Verifies that all frontend formats (.runar.yaml, .runar.sol, .runar.move)
 * produce valid ASTs through the TypeScript compiler, and that the parse()
 * dispatcher routes correctly based on file extension.
 */

import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { compile } from '../index.js';
import { readFileSync, existsSync, readdirSync } from 'fs';
import { join, resolve, basename } from 'path';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CONFORMANCE_DIR = join(__dirname, '..', '..', '..', '..', 'conformance', 'tests');

const FORMAT_EXTENSIONS = [
  '.runar.ts',
  '.runar.sol',
  '.runar.move',
  '.runar.go',
  '.runar.rs',
  '.runar.py',
  '.runar.zig',
  '.runar.rb',
  '.runar.java',
] as const;

interface SourceConfig {
  sources?: Record<string, string>;
  compilers?: string[];
}

function loadSourceConfig(testName: string): SourceConfig {
  const configFile = join(CONFORMANCE_DIR, testName, 'source.json');
  if (!existsSync(configFile)) {
    throw new Error(`source.json not found for conformance fixture '${testName}': ${configFile}`);
  }
  return JSON.parse(readFileSync(configFile, 'utf-8')) as SourceConfig;
}

/**
 * Resolve a source file referenced by `source.json`'s `sources` map.
 *
 * Returns the absolute path if the extension is declared, or `null` if the
 * fixture intentionally does not ship that format (e.g. babybear is
 * Go-only, so `.runar.ts` is absent).
 *
 * Throws if `source.json` declares the path but the file is missing on disk
 * — that's a real bug, not a legitimate skip.
 */
function resolveSourcePath(testName: string, ext: string): string | null {
  const config = loadSourceConfig(testName);
  const rel = config.sources?.[ext];
  if (rel === undefined) return null;
  const absPath = resolve(CONFORMANCE_DIR, testName, rel);
  if (!existsSync(absPath)) {
    throw new Error(
      `source.json for '${testName}' declares ${ext} -> ${rel}, but resolved path does not exist: ${absPath}`,
    );
  }
  return absPath;
}

/** Read the source for (testName, ext). Throws if not declared OR missing on disk. */
function readRequiredSource(testName: string, ext: string): { content: string; fileName: string } {
  const path = resolveSourcePath(testName, ext);
  if (path === null) {
    throw new Error(
      `source.json for '${testName}' does not declare a ${ext} source — every fixture in CONFORMANCE_TESTS must ship every FORMAT_EXTENSIONS variant.`,
    );
  }
  return { content: readFileSync(path, 'utf-8'), fileName: basename(path) };
}

function findZigConformanceCases(): { testName: string; fileName: string }[] {
  const cases: { testName: string; fileName: string }[] = [];
  for (const entry of readdirSync(CONFORMANCE_DIR, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const sourcePath = resolveSourcePath(entry.name, '.runar.zig');
    if (sourcePath === null) continue;
    cases.push({ testName: entry.name, fileName: basename(sourcePath) });
  }
  return cases.sort((a, b) => a.testName.localeCompare(b.testName) || a.fileName.localeCompare(b.fileName));
}

// ---------------------------------------------------------------------------
// Dispatch tests: parse() routes by file extension
// ---------------------------------------------------------------------------

describe('Multi-format: parse() dispatch', () => {
  it('dispatches .runar.sol to Solidity parser', () => {
    const { content, fileName } = readRequiredSource('arithmetic', '.runar.sol');
    const result = parse(content, fileName);
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('Arithmetic');
  });

  it('dispatches .runar.move to Move parser', () => {
    const { content, fileName } = readRequiredSource('arithmetic', '.runar.move');
    const result = parse(content, fileName);
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('Arithmetic');
  });

  it('dispatches .runar.ts to TypeScript parser (default)', () => {
    const { content, fileName } = readRequiredSource('arithmetic', '.runar.ts');
    const result = parse(content, fileName);
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('Arithmetic');
  });

  it('defaults to TypeScript parser for unrecognized extensions', () => {
    const { content } = readRequiredSource('arithmetic', '.runar.ts');
    const result = parse(content, 'arithmetic.unknown');
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('Arithmetic');
  });

  it('dispatches .runar.py to Python parser (row 64)', () => {
    const { content, fileName } = readRequiredSource('basic-p2pkh', '.runar.py');
    const result = parse(content, fileName);
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('P2PKH');
  });

  it('parses .runar.go files using the Go parser (row 318)', () => {
    const { content, fileName } = readRequiredSource('basic-p2pkh', '.runar.go');
    const result = parse(content, fileName);
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('P2PKH');
  });

  it('dispatches .runar.rs to Rust parser (row 321)', () => {
    const { content, fileName } = readRequiredSource('basic-p2pkh', '.runar.rs');
    const result = parse(content, fileName);
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('P2PKH');
  });

  it('dispatches .runar.zig to Zig parser', () => {
    const { content, fileName } = readRequiredSource('basic-p2pkh', '.runar.zig');
    const result = parse(content, fileName);
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
        const { content, fileName } = readRequiredSource(name, ext);
        const result = parse(content, fileName);
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
        const { content, fileName } = readRequiredSource(name, ext);
        const result = parse(content, fileName);
        const errors = result.errors.filter(e => e.severity === 'error');
        expect(errors, `parse errors for ${name}${ext}`).toEqual([]);
        expect(result.contract, `null contract for ${name}${ext}`).not.toBeNull();
        results.push({ ext, contract: result.contract! });
      }

      // Every fixture in CONFORMANCE_TESTS ships every FORMAT_EXTENSIONS variant.
      expect(results.length).toBe(FORMAT_EXTENSIONS.length);

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

// ---------------------------------------------------------------------------
// Universal parser-coverage: every fixture × every format must parse cleanly
// ---------------------------------------------------------------------------
//
// This is the parser-layer guarantee from spec/README.md: "Each compiler must
// parse every fixture in every one of the nine source formats. There are no
// per-tier carve-outs at the parser layer." A fixture's optional `compilers`
// allowlist scopes Stack-IR/hex parity (see runner/runner.ts) but never the
// parser. Conversely, a fixture may opt OUT of a single format at the parser
// layer by listing it in `parserSkip` with a non-empty `parserSkipReason` —
// that escape hatch exists for genuinely blocked ports (e.g. a Move-syntax
// limitation), and the runner's discoverFormats() asserts that every other
// format ships AND that every parserSkip entry carries a justification.
//
// This test enforces the same discipline at the TS-frontend layer: every
// format declared by a fixture's source.json must round-trip through parse()
// without errors and yield a non-null Contract whose name matches across all
// formats.
function findAllConformanceFixtures(): string[] {
  return readdirSync(CONFORMANCE_DIR, { withFileTypes: true })
    .filter(e => e.isDirectory())
    .map(e => e.name)
    .sort();
}

describe('Multi-format: universal parser coverage (every fixture × every declared format)', () => {
  const fixtures = findAllConformanceFixtures();

  it('discovers conformance fixtures', () => {
    expect(fixtures.length).toBeGreaterThan(0);
  });

  for (const fixture of fixtures) {
    const config = (() => {
      try {
        return loadSourceConfig(fixture);
      } catch {
        return { sources: undefined } as SourceConfig;
      }
    })();
    const declaredExts = Object.keys(config.sources ?? {});
    if (declaredExts.length === 0) continue;

    for (const ext of declaredExts) {
      it(`parses ${fixture}${ext} cleanly`, () => {
        const { content, fileName } = readRequiredSource(fixture, ext as (typeof FORMAT_EXTENSIONS)[number]);
        const result = parse(content, fileName);
        const errors = result.errors.filter(e => e.severity === 'error');
        expect(errors, `parse errors for ${fixture}${ext}`).toEqual([]);
        expect(result.contract, `null contract for ${fixture}${ext}`).not.toBeNull();
      });
    }

    // When a fixture ships all 9 declared formats, the contract name MUST
    // be identical across every variant. Mirrors the cross-format
    // structural-consistency rule that's already pinned for the smaller
    // CONFORMANCE_TESTS subset above, but applied universally.
    if (declaredExts.length === FORMAT_EXTENSIONS.length) {
      it(`all 9 formats of ${fixture} agree on contract name`, () => {
        const names = new Set<string>();
        for (const ext of declaredExts) {
          const { content, fileName } = readRequiredSource(fixture, ext as (typeof FORMAT_EXTENSIONS)[number]);
          const result = parse(content, fileName);
          if (result.contract) names.add(result.contract.name);
        }
        expect(
          names.size,
          `${fixture}: contract name disagrees across formats: ${[...names].join(', ')}`,
        ).toBeLessThanOrEqual(1);
      });
    }
  }
});

describe('Multi-format: stateful contract', () => {
  for (const ext of FORMAT_EXTENSIONS) {
    it(`parses stateful contract from ${ext}`, () => {
      const { content, fileName } = readRequiredSource('stateful', ext);
      const result = parse(content, fileName);
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

// ---------------------------------------------------------------------------
// Zig conformance: parse and hex parity
// ---------------------------------------------------------------------------

describe('Multi-format: Zig conformance', () => {
  const zigConformanceCases = findZigConformanceCases();

  it('discovers Zig conformance cases via source.json', () => {
    // Sanity: source.json indirection actually surfaces fixtures. If this
    // returns 0, the resolver is broken and every per-case test below would
    // be a no-op.
    expect(zigConformanceCases.length).toBeGreaterThan(0);
  });

  it('parses basic-p2pkh from .runar.zig', () => {
    const { content, fileName } = readRequiredSource('basic-p2pkh', '.runar.zig');
    const result = parse(content, fileName);
    const errors = result.errors.filter(e => e.severity === 'error');

    expect(errors).toEqual([]);
    expect(result.contract).not.toBeNull();
    expect(result.contract!.name).toBe('P2PKH');
    expect(result.contract!.properties).toHaveLength(1);
    expect(result.contract!.methods.map(method => method.name)).toContain('unlock');
  });

  it('compiles basic-p2pkh .runar.zig to the golden script hex', () => {
    const { content, fileName } = readRequiredSource('basic-p2pkh', '.runar.zig');

    const expectedHex = readFileSync(
      join(CONFORMANCE_DIR, 'basic-p2pkh', 'expected-script.hex'),
      'utf-8',
    ).trim().toLowerCase();

    const result = compile(content, {
      fileName,
      disableConstantFolding: true,
    });

    expect(result.success).toBe(true);
    expect(result.diagnostics.filter(diagnostic => diagnostic.severity === 'error')).toEqual([]);
    expect(typeof result.scriptHex).toBe('string');
    expect(result.scriptHex!.toLowerCase()).toBe(expectedHex);
  });

  for (const { testName, fileName } of zigConformanceCases) {
    it(`compiles ${testName}/${fileName} to the golden script hex`, () => {
      const { content } = readRequiredSource(testName, '.runar.zig');

      const expectedHex = readFileSync(
        join(CONFORMANCE_DIR, testName, 'expected-script.hex'),
        'utf-8',
      ).trim().toLowerCase();

      const result = compile(content, {
        fileName,
        disableConstantFolding: true,
      });

      expect(result.success).toBe(true);
      expect(result.diagnostics.filter(diagnostic => diagnostic.severity === 'error')).toEqual([]);
      expect(typeof result.scriptHex).toBe('string');
      expect(result.scriptHex!.toLowerCase()).toBe(expectedHex);
    });
  }
});
