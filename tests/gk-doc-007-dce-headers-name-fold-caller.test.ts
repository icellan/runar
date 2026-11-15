/**
 * GK-DOC-007: every tier's DCE module header named the EC optimizer as its
 * only caller. In all seven tiers the constant folder's prune step
 * (foldConstantsAndPrune and its spellings, N-138) also calls the
 * candidate-restricted variant, so "only caller" was false. dce.zig was worse:
 * it called itself a standalone pass after constant folding (pass 4.25),
 * which is the claim R-194 / F-303 / F-219 / R-240 / F-326 / F-275 removed
 * elsewhere; no whole-program DCE runs in the Zig pipeline.
 *
 * Proves: each header names its tier's fold caller next to the EC caller, and
 * dce.zig no longer claims to be a standalone pass.
 * Does not prove: where DCE runs (the per-tier positional pins r194, f303,
 * f219, r240, f326 and F275 check the call sites themselves).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p: string) => readFileSync(join(ROOT, p), 'utf8');

/** The leading comment block of each DCE module. */
function header(path: string): string {
  const src = read(path);
  if (path.endsWith('.ts')) return src.slice(0, src.indexOf('*/'));
  if (path.endsWith('.go')) return src.slice(0, src.indexOf('import ('));
  if (path.endsWith('.py')) return src.slice(0, src.indexOf('"""', 3));
  if (path.endsWith('.rb')) return src.slice(0, src.indexOf('require "set"'));
  if (path.endsWith('.java')) return src.slice(src.indexOf('/**\n * Dead Code'), src.indexOf('public final class Dce'));
  // .rs / .zig: the //! module-doc lines
  return src.split('\n').filter((l) => l.startsWith('//!')).join('\n');
}

const TIERS: Array<{ tier: string; path: string; ecCaller: RegExp; foldCaller: RegExp }> = [
  { tier: 'ts', path: 'packages/runar-compiler/src/optimizer/dce.ts', ecCaller: /optimizeEC/, foldCaller: /foldConstantsAndPrune/ },
  { tier: 'go', path: 'compilers/go/frontend/dce.go', ecCaller: /optimizeMethodEC/, foldCaller: /FoldConstantsAndPrune/ },
  { tier: 'rust', path: 'compilers/rust/src/frontend/dce.rs', ecCaller: /optimize_ec/, foldCaller: /fold_constants_and_prune/ },
  { tier: 'python', path: 'compilers/python/runar_compiler/frontend/dce.py', ecCaller: /optimize_ec/, foldCaller: /fold_constants_and_prune/ },
  { tier: 'zig', path: 'compilers/zig/src/passes/dce.zig', ecCaller: /ec_optimizer\.zig/, foldCaller: /foldConstantsAndPrune/ },
  { tier: 'ruby', path: 'compilers/ruby/lib/runar_compiler/frontend/dce.rb', ecCaller: /optimize_ec/, foldCaller: /fold_constants_and_prune/ },
  { tier: 'java', path: 'compilers/java/src/main/java/runar/compiler/passes/Dce.java', ecCaller: /AnfOptimize/, foldCaller: /ConstantFold\.runAndPrune/ },
];

describe('GK-DOC-007: every DCE header names both production callers', () => {
  for (const t of TIERS) {
    it(`${t.tier}: names the EC caller and the fold-prune caller`, () => {
      const h = header(t.path);
      expect(h.length, `${t.path}: header not found`).toBeGreaterThan(200);
      expect(h, `${t.path}: EC caller not named`).toMatch(t.ecCaller);
      expect(h, `${t.path}: the fold-prune caller is not named`).toMatch(t.foldCaller);
    });
  }

  it('zig: dce.zig does not call itself a standalone pass', () => {
    const h = header('compilers/zig/src/passes/dce.zig');
    expect(h).not.toMatch(/standalone pass/);
    expect(h).not.toMatch(/pass 4\.25/);
  });
});
