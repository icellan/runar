import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { checkAgainstReference, type SourceMap } from './independent-oracle.js';
import { findZigBinary } from '../runner/runner.js';

// N-368 (R156): the Zig tier's source map must leave compiler-synthesized
// opcodes (stateful preamble: checkPreimage / OP_PUSH_TX, state continuation,
// codeseparator glue) UNMAPPED where the TS reference leaves them unmapped.
// Before the fix Zig anchored every ANF binding injected by the stateful
// scaffold to the method's own line, so stateful-counter carried 432 mappings
// (422 of them opcodes the reference leaves unmapped, 111 on one anchor).
//
// What this proves: for each stateful fixture below, compiling the REAL zig
// binary and the REAL TS CLI live (not the committed goldens, so it cannot be
// satisfied by regenerating a golden) gives a Zig map with zero extra
// mappings and zero merged anchors against the TS map of the same opcodes.
// What it does not prove: that the anchors themselves point at the right
// token (independent-oracle.ts#checkSourceAnchors does that), nor anything
// about the other five tiers or stateless fixtures.

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
// Same lookup as the runner: CI downloads the built binary to the repo root.
const ZIG_BIN = findZigBinary() ?? join(REPO_ROOT, 'compilers/zig/zig-out/bin/runar-zig');
const TS_CLI = join(REPO_ROOT, 'packages/runar-cli/src/bin.ts');

const FIXTURES: Array<{ name: string; ts: string; zig: string }> = [
  { name: 'stateful-counter', ts: 'examples/ts/stateful-counter/Counter.runar.ts', zig: 'examples/zig/stateful-counter/Counter.runar.zig' },
  { name: 'token-ft', ts: 'examples/ts/token-ft/FungibleTokenExample.runar.ts', zig: 'examples/zig/token-ft/FungibleTokenExample.runar.zig' },
];

function tsxLoader(): string {
  for (const p of [
    join(REPO_ROOT, 'node_modules/tsx/dist/loader.mjs'),
    join(REPO_ROOT, 'conformance/node_modules/tsx/dist/loader.mjs'),
  ]) if (existsSync(p)) return new URL(`file://${p}`).href;
  const r = spawnSync('find', [join(REPO_ROOT, 'node_modules', '.pnpm'), '-name', 'loader.mjs', '-path', '*tsx*'], { encoding: 'utf-8' });
  const first = r.stdout.split('\n').find((l) => l.trim());
  if (!first) throw new Error('no tsx loader found');
  return new URL(`file://${first}`).href;
}

function emit(cmd: string, args: string[], out: string, cwd: string): SourceMap {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf-8', timeout: 120_000, maxBuffer: 64 * 1024 * 1024 });
  expect(r.status, `${cmd} failed: ${r.stderr}`).toBe(0);
  return JSON.parse(readFileSync(out, 'utf-8')) as SourceMap;
}

describe('N-368: zig leaves compiler-synthesized opcodes unmapped, like the TS reference', () => {
  expect(ZIG_BIN === 'runar-zig' || existsSync(ZIG_BIN), `build compilers/zig first (${ZIG_BIN})`).toBe(true);
  const dir = mkdtempSync(join(tmpdir(), 'n368-'));
  mkdirSync(dir, { recursive: true });

  for (const fx of FIXTURES) {
    it(`${fx.name}: zig map has no extra mappings and no merged anchors vs TS`, () => {
      const tsMap = emit('node', ['--import', tsxLoader(), TS_CLI, 'compile', join(REPO_ROOT, fx.ts), '--disable-constant-folding', '-o', dir, '--emit-source-map', join(dir, `${fx.name}-ts.json`)], join(dir, `${fx.name}-ts.json`), join(REPO_ROOT, 'compilers/python'));
      const zigMap = emit(ZIG_BIN, ['--source', join(REPO_ROOT, fx.zig), '--disable-constant-folding', '--emit-source-map', join(dir, `${fx.name}-zig.json`)], join(dir, `${fx.name}-zig.json`), REPO_ROOT);
      const shape = checkAgainstReference(zigMap, tsMap);
      expect(shape).toEqual({ mergedAnchors: 0, extraMappings: 0 });
    });
  }
});
