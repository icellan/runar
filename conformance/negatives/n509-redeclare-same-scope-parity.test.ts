import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compile } from '../../packages/runar-compiler/src/index.js';
import { BrokenTier, Tier, buildSourceTiers, compileHex, verdict } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-509 — a local re-declared in the same scope, all seven tiers.
 *
 * spec/grammar.md (Statement Restrictions) says a variable cannot be
 * re-declared in the same scope. Every tier accepted it anyway, on every
 * surface that has a declaration keyword: `const a = 1n; const a = 2n;`,
 * `let x; var x`, a parameter re-declared at the top of its method body, and
 * `const a = ...; let a = ...; a = 3n;` — the second declaration hid the
 * const from the const-reassignment check.
 *
 * "Same scope" is one statement list: a method or constructor body (together
 * with that method's parameters), an `if` branch, an `else` branch, or a loop
 * body. A declaration in a NESTED list that reuses an outer name (shadowing)
 * is not a re-declaration and stays accepted; the spec says nothing about it,
 * and every tier already lowers it exactly as the renamed program.
 *
 * Corpus: `redeclare-cases.json` — each refused case with a renamed twin, and
 * the accepted shadowing shapes.
 *
 * What this proves: all seven tiers refuse each case with the one shared
 * diagnostic and compile each twin to the same bytes as the reference tier;
 * every accepted shape compiles in every tier.
 * What it does NOT prove: the accepted shadowing shapes compute what the
 * source means (that was checked by hand: each compiles to the same hex as
 * its renamed program).
 */

interface Case { name: string; file: string; src: string; twin: string; error: string }
const CORPUS = JSON.parse(readFileSync(join(__dirname, 'redeclare-cases.json'), 'utf8')) as {
  cases: Case[];
  accept: Array<{ name: string; file: string; src: string }>;
};

const DIR = mkdtempSync(join(tmpdir(), 'n509-redeclare-'));
let seq = 0;
const writeFile = (fileName: string, content: string): string => {
  const d = join(DIR, String(seq++));
  mkdirSync(d);
  const p = join(d, fileName);
  writeFileSync(p, content);
  return p;
};

const TIERS: Tier[] = buildSourceTiers().filter((t) => t.id !== 'ts' && t.cmd !== null);

function run(tier: Tier, input: string): { status: number; out: string; diag: string } {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(input)];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  if (res.signal !== null) throw new BrokenTier(`${where} killed by ${res.signal}`);
  if (res.status === null) throw new BrokenTier(`${where}: no exit status`);
  return { status: res.status, out: (res.stdout ?? '').trim(), diag: `${res.stderr ?? ''}\n${res.stdout ?? ''}` };
}

const tsHex = (src: string, file: string): string => {
  const r = compile(src, { fileName: file });
  if (!r.success || !r.scriptHex) throw new Error(JSON.stringify(r.diagnostics));
  return r.scriptHex.toLowerCase();
};

describe('N-509: same-scope re-declaration (all 7 tiers)', () => {
  it('the corpus covers every declaring surface and both directions', () => {
    const exts = new Set(CORPUS.cases.map((c) => c.file.replace(/^.*?\.runar\./, '')));
    expect([...exts].sort()).toEqual(['go', 'java', 'move', 'rs', 'sol', 'ts', 'zig']);
    expect(CORPUS.cases.length).toBeGreaterThanOrEqual(16);
    expect(CORPUS.accept.length).toBeGreaterThanOrEqual(7);
    for (const c of CORPUS.cases) {
      expect(c.error, c.name).toMatch(/^'[^']+' is already declared in this scope and cannot be re-declared$/);
      expect(c.twin, c.name).not.toBe(c.src);
    }
  });

  it('every native tier is built (strict in CI, ">=2" locally)', () => {
    if (isCiEnv(process.env)) {
      expect(TIERS.map((t) => t.id).sort()).toEqual(['go', 'java', 'python', 'ruby', 'rust', 'zig']);
    }
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
  });

  for (const c of CORPUS.cases) {
    it(`ts refuses ${c.name} with the shared diagnostic`, () => {
      const r = compile(c.src, { fileName: c.file });
      expect(r.success).toBe(false);
      expect(r.diagnostics.map((d) => d.message)).toContain(c.error);
    });

    for (const tier of TIERS) {
      it(`${tier.id} refuses ${c.name} with the shared diagnostic`, () => {
        const { status, out, diag } = run(tier, writeFile(c.file, c.src));
        expect(status, `${tier.id} accepted ${c.name} (emitted "${out}")`).not.toBe(0);
        expect(diag).toContain(c.error);
      });
    }

    it(`every tier compiles the renamed twin of ${c.name} to the same bytes`, () => {
      const want = tsHex(c.twin, c.file);
      const input = writeFile(c.file, c.twin);
      for (const tier of TIERS) {
        expect(compileHex(tier, input), `${tier.id} vs ts on the twin of ${c.name}`).toBe(want);
      }
    });
  }

  for (const a of CORPUS.accept) {
    it(`every tier accepts ${a.name}`, () => {
      tsHex(a.src, a.file);
      const input = writeFile(a.file, a.src);
      for (const tier of TIERS) expect(verdict(tier, input), tier.id).toBe('accepted');
    });
  }
});
