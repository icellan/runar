import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { buildSourceTiers, type Tier } from '../negatives/tier-harness.js';

// N-350 (follow-up to F-188, which fixed Java only): `liftBranchUpdateProps`
// rewrites a conditional property update (`if/else if/else` that each end in
// `this.x = ...`) into flat load_prop / if / update_prop bindings. TS, Go,
// Rust, Python, Zig and Ruby built those bindings with no source location, so
// the opcodes that implement the conditional state update were absent from
// their source maps. Java's scheme: the condition temporaries take the
// original `if`'s location, and each branch's load_prop / if / update_prop /
// keep-old bindings take that branch's own update statement location.
//
// What this proves: compiling ONE `.runar.ts` source with each of the seven
// real CLIs (live, not committed goldens) yields, for every tier, exactly the
// same (opcodeIndex -> line) mapping that Java emits on the update-statement
// lines, and that mapping is non-empty for every branch's update line. Hex
// parity makes opcode N the same opcode in every tier, so equality with Java
// is the "same file:line as Java" claim.
// What it does not prove: columns (compared nowhere here, tiers differ in
// granularity), the shape of the maps outside the update/if lines, or the
// other surface syntaxes (only `.runar.ts` is fed to every tier).

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');

const SRC = `import { StatefulSmartContract } from 'runar-lang';

class Sw extends StatefulSmartContract {
  x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public set(p: bigint, a: bigint, b: bigint, c: bigint) {
    if (p === 0n) {
      this.x = a;
    } else if (p === 1n) {
      this.x = b;
    } else {
      this.x = c;
    }
  }
}
`;

function lineOf(needle: string): number {
  const i = SRC.split('\n').findIndex((l) => l.includes(needle));
  if (i < 0) throw new Error(`no line containing ${needle}`);
  return i + 1;
}

const UPDATE_LINES = [lineOf('this.x = a;'), lineOf('this.x = b;'), lineOf('this.x = c;')];
const IF_LINES = [lineOf('if (p === 0n)'), lineOf('} else if (p === 1n)')];
const CHECKED = new Set([...UPDATE_LINES, ...IF_LINES]);

interface Mapping { opcodeIndex: number; line: number }

function emit(t: Tier, srcPath: string, dir: string): Mapping[] {
  const smOut = join(dir, `${t.id}.sourcemap.json`);
  const args = [...t.prefix, ...t.argsFor(srcPath), '--disable-constant-folding', '--emit-source-map', smOut];
  if (t.id === 'ts') args.push('-o', dir);
  const r = spawnSync(t.cmd!, args, { cwd: t.cwd, encoding: 'utf-8', timeout: t.timeoutMs, maxBuffer: 64 * 1024 * 1024 });
  expect(r.status, `${t.id} failed: ${r.stderr}`).toBe(0);
  const map = JSON.parse(readFileSync(smOut, 'utf-8')) as { mappings: Array<{ opcodeIndex: number; line: number }> };
  return map.mappings.map((m) => ({ opcodeIndex: m.opcodeIndex, line: m.line }));
}

// Per-line opcode indices, restricted to the lines the lift is responsible for.
function lineIndex(maps: Mapping[]): Record<number, number[]> {
  const out: Record<number, number[]> = {};
  for (const m of maps) {
    if (!CHECKED.has(m.line)) continue;
    (out[m.line] ??= []).push(m.opcodeIndex);
  }
  for (const k of Object.keys(out)) out[Number(k)]!.sort((a, b) => a - b);
  return out;
}

describe('N-350: lifted branch property updates keep source locations in every tier', () => {
  const dir = mkdtempSync(join(tmpdir(), 'n350-'));
  mkdirSync(dir, { recursive: true });
  const srcPath = join(dir, 'Sw.runar.ts');
  writeFileSync(srcPath, SRC);
  const tiers = buildSourceTiers();
  const java = tiers.find((t) => t.id === 'java')!;

  for (const t of tiers) {
    it(`${t.id}: update-statement and if lines map the same opcodes as Java`, () => {
      expect(t.cmd, `${t.id} toolchain is not built`).not.toBeNull();
      expect(java.cmd, 'java toolchain is not built').not.toBeNull();
      const want = lineIndex(emit(java, srcPath, dir));
      for (const l of UPDATE_LINES) {
        expect(want[l]?.length ?? 0, `Java reference lost line ${l}`).toBeGreaterThan(0);
      }
      const got = lineIndex(emit(t, srcPath, dir));
      for (const l of UPDATE_LINES) {
        expect(got[l]?.length ?? 0, `${t.id}: no source-map entry for update line ${l}`).toBeGreaterThan(0);
      }
      expect(got).toEqual(want);
    });
  }
});
