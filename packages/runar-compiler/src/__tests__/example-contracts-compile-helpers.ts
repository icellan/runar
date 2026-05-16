/**
 * Shared helpers for the per-language `example-contracts-compile-<lang>.test.ts`
 * files. Split into a non-`.test.ts` module so vitest discovers each language
 * as its own test file and parallelises them across workers.
 */
import { compile } from '../index.js';
import { readFileSync, existsSync, readdirSync } from 'fs';
import { join } from 'path';

export const EXAMPLES_DIR = join(__dirname, '..', '..', '..', '..', 'examples');

export function findContracts(langDir: string, ext: string): { name: string; path: string }[] {
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

export function compileContract(filePath: string) {
  const source = readFileSync(filePath, 'utf-8');
  const result = compile(source, { fileName: filePath });
  const errors = result.diagnostics.filter(d => d.severity === 'error');
  return {
    success: result.success,
    errors: errors.map(e => e.message),
    hasScript: !!result.scriptHex && result.scriptHex.length > 0,
  };
}
