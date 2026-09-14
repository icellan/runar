/**
 * Zig parser: verify the Zig example tree mirrors the native example set and parses cleanly.
 */

import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'fs';
import { join, relative } from 'path';
import { parse } from '../passes/01-parse.js';
import { parseZigSource } from '../passes/01-parse-zig.js';
import { compile } from '../index.js';

const REPO_ROOT = join(__dirname, '..', '..', '..', '..');
const EXAMPLES_ZIG_DIR = join(REPO_ROOT, 'examples', 'zig');
const EXAMPLES_TS_DIR = join(REPO_ROOT, 'examples', 'ts');

function findExampleFiles(baseDir: string, extension: string): string[] {
  if (!existsSync(baseDir)) return [];

  const results: string[] = [];

  for (const entry of readdirSync(baseDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const dirPath = join(baseDir, entry.name);

    for (const file of readdirSync(dirPath)) {
      if (file.endsWith(extension)) {
        results.push(relative(baseDir, join(dirPath, file)));
      }
    }
  }

  return results.sort();
}

const ZIG_EXAMPLES = findExampleFiles(EXAMPLES_ZIG_DIR, '.runar.zig');
const TS_EXAMPLES = findExampleFiles(EXAMPLES_TS_DIR, '.runar.ts')
  .map((file) => file.replace(/\.runar\.ts$/, '.runar.zig'))
  .sort();

// TS examples that don't yet have a Zig port. Listed explicitly so future
// TS-only landings can be tracked here rather than silently dropped from
// parity.
const ZIG_PORT_PENDING: readonly string[] = [
  // Intentionally TS-only: a compiler regression fixture for issue #34
  // (cross-method param-name shadowing). The fix it guards lives in all 7
  // tiers and is verified via the .runar.ts conformance fixture compiled by
  // every tier; it needs no per-format example port.
  'nested-if-multi-reassign/StackTrackerRepro.runar.zig',
  // TS-only until the non-TS tiers receive the outer-scope-refs-across-
  // unrolled-loops stack-lowering fix (the TS fix landed in
  // 05-stack-lower.ts): CompanionVerifier's bounded multi-input walk
  // references `inCount`/`off` inside an unrolled loop, which the Go/Rust
  // stack lowerers still reject with "value 'inCount' not found on stack".
  // Port these alongside that fix.
  'companion-verifier/AttributedToken.runar.zig',
  'companion-verifier/CompanionVerifier.runar.zig',
  // NOT pending — permanently TS-only, unlike every other entry here. R-209
  // added this example for the `@embedAlways` and `@sighash` comment
  // directives, and both are read on the `.runar.ts` surface ALONE: the other
  // eight parsers REJECT a source carrying either, deliberately, because
  // silently dropping a directive would change DCE or signing semantics without
  // saying so. A `.runar.zig` translation is a parse error by design, so there
  // is nothing to port and nothing to track. See examples/README.md.
  'compiler-directives/Directives.runar.zig',
];

describe('Zig parser: example inventory', () => {
  it('ships a Zig example for every native example contract (minus known pending ports)', () => {
    // Every TS example must have a Zig counterpart, except those explicitly
    // listed as pending. Zig may carry format-specific extras (e.g. Zig-only
    // demos like ec-unit or bitwise-ops) that have no TS analogue; those
    // don't break parity.
    const expected = TS_EXAMPLES.filter((rel) => !ZIG_PORT_PENDING.includes(rel));
    const missing = expected.filter((rel) => !ZIG_EXAMPLES.includes(rel));
    expect(missing).toEqual([]);
  });
});

describe('Zig parser: example contracts', () => {
  for (const relativePath of ZIG_EXAMPLES) {
    it(`parses ${relativePath} without errors`, () => {
      const fullPath = join(EXAMPLES_ZIG_DIR, relativePath);
      const source = readFileSync(fullPath, 'utf-8');
      const fileName = relativePath.split('/').pop()!;

      const directResult = parseZigSource(source, fileName);
      const dispatchResult = parse(source, fileName);

      const directErrors = directResult.errors.filter(error => error.severity === 'error');
      const dispatchErrors = dispatchResult.errors.filter(error => error.severity === 'error');

      expect(directErrors).toEqual([]);
      expect(dispatchErrors).toEqual([]);
      expect(directResult.contract).not.toBeNull();
      expect(dispatchResult.contract).not.toBeNull();
      expect(dispatchResult.contract!.name).toBe(directResult.contract!.name);
    });

    it(`compiles ${relativePath} through the TypeScript compiler frontend`, () => {
      const fullPath = join(EXAMPLES_ZIG_DIR, relativePath);
      const source = readFileSync(fullPath, 'utf-8');
      const fileName = relativePath.split('/').pop()!;

      const result = compile(source, {
        fileName,
        disableConstantFolding: true,
      });

      const errors = result.diagnostics.filter(diagnostic => diagnostic.severity === 'error');

      expect(errors).toEqual([]);
      expect(result.success).toBe(true);
      expect(typeof result.scriptHex).toBe('string');
      expect(result.scriptHex!.length).toBeGreaterThan(0);
    });
  }
});

describe('Zig parser: stateful example parity', () => {
  const parityPairs = [
    ['auction/Auction.runar.zig', 'auction/Auction.runar.ts'],
    ['token-ft/FungibleTokenExample.runar.zig', 'token-ft/FungibleTokenExample.runar.ts'],
    ['token-nft/NFTExample.runar.zig', 'token-nft/NFTExample.runar.ts'],
  ] as const;

  for (const [zigRelativePath, tsRelativePath] of parityPairs) {
    it(`matches TypeScript script hex for ${zigRelativePath}`, () => {
      const zigSource = readFileSync(join(EXAMPLES_ZIG_DIR, zigRelativePath), 'utf-8');
      const tsSource = readFileSync(join(EXAMPLES_TS_DIR, tsRelativePath), 'utf-8');

      const zigResult = compile(zigSource, {
        fileName: zigRelativePath.split('/').pop()!,
        disableConstantFolding: true,
      });
      const tsResult = compile(tsSource, {
        fileName: tsRelativePath.split('/').pop()!,
        disableConstantFolding: true,
      });

      expect(zigResult.diagnostics.filter(diagnostic => diagnostic.severity === 'error')).toEqual([]);
      expect(tsResult.diagnostics.filter(diagnostic => diagnostic.severity === 'error')).toEqual([]);
      expect(zigResult.success).toBe(true);
      expect(tsResult.success).toBe(true);
      expect(zigResult.scriptHex).toBe(tsResult.scriptHex);
    });
  }
});
