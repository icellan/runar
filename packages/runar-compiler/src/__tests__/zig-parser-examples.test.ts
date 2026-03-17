/**
 * Zig parser: verify the Zig example tree mirrors the native example set and parses cleanly.
 */

import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'fs';
import { join, relative } from 'path';
import { parse } from '../passes/01-parse.js';
import { parseZigSource } from '../passes/01-parse-zig.js';

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

describe('Zig parser: example inventory', () => {
  it('ships a Zig example for every native example contract', () => {
    expect(ZIG_EXAMPLES).toEqual(TS_EXAMPLES);
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
  }
});
