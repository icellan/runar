import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO, buildSourceTiers } from './negatives/tier-harness.js';

/**
 * N-498 — Python and Ruby artifacts carry `sourceLoc` on ANF bindings like TS.
 *
 * The two tiers populate `binding.source_loc` internally (it feeds the source
 * map) but their ANF serializers used to drop it, so the artifact's
 * `anf.methods[].body[]` had no `sourceLoc` at all while TS, Go, Rust, Zig and
 * Java emit one. The conformance runner strips `sourceLoc` before comparing
 * ANF, so this is invisible to the golden gate and has to be pinned here.
 *
 * Reference: `compilers/zig/src/tests/n475_ts_anf_sourceloc_reference.json`
 * (the TS tier on the `.runar.ts` examples) and `n487_...` (the TS tier on the
 * sol/move/go/rs/zig surfaces of the same contracts), each a depth-first walk
 * of `anf.methods[].body[]` (descending `then` / `else` / `body`) listing
 * `[line, column]` per binding, `null` where TS emits no `sourceLoc`. The
 * columns are TS's 0-based columns. Compiled with constant folding OFF, as the
 * references were.
 *
 * What this proves: for every listed file, the Python and Ruby artifacts have
 * a `sourceLoc` on exactly the bindings TS has one on, with the same line and
 * the same 0-based column, plus a `file` string.
 * What it does NOT prove: fold-on locations, surfaces/contracts outside the
 * reference files, the `file` string's spelling (each CLI spells it its own
 * way; only that it is present), or that Python/Ruby stack-level source maps
 * are unchanged (the golden source-map tests cover those).
 */

const REF_DIR = join(REPO, 'compilers/zig/src/tests');
const REFS: Record<string, Array<[number, number] | null>> = {
  ...JSON.parse(readFileSync(join(REF_DIR, 'n475_ts_anf_sourceloc_reference.json'), 'utf8')),
  ...JSON.parse(readFileSync(join(REF_DIR, 'n487_ts_anf_sourceloc_reference.json'), 'utf8')),
};

type Loc = { file?: unknown; line: number; column: number };
type Binding = { sourceLoc?: Loc; value: { then?: Binding[]; else?: Binding[]; body?: Binding[] } };

function walk(bs: Binding[], acc: Array<[number, number] | null>, files: unknown[]): void {
  for (const b of bs) {
    acc.push(b.sourceLoc ? [b.sourceLoc.line, b.sourceLoc.column] : null);
    if (b.sourceLoc) files.push(b.sourceLoc.file);
    for (const k of ['then', 'else', 'body'] as const) {
      const v = b.value[k];
      if (Array.isArray(v)) walk(v, acc, files);
    }
  }
}

const TIERS = buildSourceTiers().filter((t) => t.id === 'python' || t.id === 'ruby');

describe('N-498: Python and Ruby ANF bindings carry the TS sourceLoc', () => {
  it('has both tiers', () => {
    expect(TIERS.map((t) => t.id).sort()).toEqual(['python', 'ruby']);
    for (const t of TIERS) expect(t.cmd, `${t.id} toolchain`).not.toBeNull();
  });

  for (const tier of TIERS) {
    for (const [rel, expected] of Object.entries(REFS)) {
      it(`${tier.id}: ${rel}`, () => {
        const argv = [...tier.prefix, '--source', join(REPO, rel), '--disable-constant-folding'];
        const res = spawnSync(tier.cmd!, argv, { cwd: tier.cwd, encoding: 'utf-8', timeout: tier.timeoutMs, maxBuffer: 64 * 1024 * 1024 });
        expect(res.status, `${tier.id} exited ${res.status}: ${String(res.stderr).slice(0, 400)}`).toBe(0);
        const artifact = JSON.parse(res.stdout) as { anf: { methods: Array<{ body: Binding[] }> } };
        const got: Array<[number, number] | null> = [];
        const files: unknown[] = [];
        for (const m of artifact.anf.methods) walk(m.body, got, files);
        expect(got).toEqual(expected);
        for (const f of files) expect(typeof f === 'string' && f.length > 0).toBe(true);
      }, 120_000);
    }
  }
});
