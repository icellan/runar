/**
 * Build-time template generator.
 *
 * Walks every .runar.ts contract under examples/ts/, compiles it, and
 * records (scriptHex → canonical source verbatim) into templates-data.json.
 *
 * The decompiler loads this manifest at module init and uses it as the
 * first matching layer. Every corpus contract whose compiled bytes hit a
 * manifest entry instantly round-trips.
 *
 * Run: pnpm --filter runar-decompiler run templates:build
 *
 * N-088: every example under examples/ts/ is expected to compile — a
 * contract that fails is a compiler regression, not a legitimate skip. The
 * generator used to log skipped contracts and still write the manifest with
 * exit 0, so a regression that broke one example silently dropped it from
 * the manifest (and the decompiler's round-trip coverage for it) without
 * failing any gate. `--examples-dir` / `--out` are test-only overrides (the
 * real corpus and manifest paths are the defaults).
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { resolve, dirname, basename, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..', '..', '..');

function argValue(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const EXAMPLES_DIR = resolve(argValue('--examples-dir') ?? resolve(REPO_ROOT, 'examples', 'ts'));
const OUT = resolve(argValue('--out') ?? resolve(__dirname, '..', 'templates-data.json'));

interface Entry {
  /** Compiled scriptHex (no leading 0x). */
  hex: string;
  /** Canonical TS source, verbatim. */
  source: string;
  /** Relative path within examples/ts (for traceability + tests). */
  origin: string;
  /** Byte length of the compiled script. */
  bytes: number;
}

interface Manifest {
  generatedAt: string;
  compilerVersion: string;
  entries: Entry[];
}

function walk(dir: string, out: string[]) {
  for (const entry of readdirSync(dir)) {
    const full = resolve(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (entry.endsWith('.runar.ts')) out.push(full);
  }
}

function main() {
  const files: string[] = [];
  walk(EXAMPLES_DIR, files);
  files.sort();

  const entries: Entry[] = [];
  const skipped: { path: string; reason: string }[] = [];

  for (const f of files) {
    const source = readFileSync(f, 'utf8');
    const r = compile(source, { fileName: basename(f) });
    if (!r.success || !r.scriptHex) {
      const errs = r.diagnostics.filter(d => d.severity === 'error').map(d => d.message).join('; ');
      skipped.push({ path: relative(REPO_ROOT, f), reason: errs || 'no scriptHex' });
      continue;
    }
    if (r.scriptHex.length === 0) {
      skipped.push({ path: relative(REPO_ROOT, f), reason: 'empty script' });
      continue;
    }
    entries.push({
      hex: r.scriptHex,
      source,
      origin: relative(REPO_ROOT, f),
      bytes: r.scriptHex.length / 2,
    });
  }

  // N-088: every contract under examples/ts/ is expected to compile — a
  // skip here is a compiler regression, not a legitimate outcome. The
  // manifest used to be written anyway and the process exited 0, so a
  // regression silently shrank the manifest (and the decompiler's
  // round-trip coverage) without failing any gate. Fail closed: print the
  // list and exit non-zero WITHOUT writing OUT, so a stale-but-complete
  // manifest on disk from a prior good run is never clobbered with an
  // incomplete one.
  if (skipped.length > 0) {
    console.error(`[templates] ${skipped.length} contract(s) failed to compile and were skipped:`);
    for (const s of skipped) console.error(`  - ${s.path}: ${s.reason}`);
    console.error('[templates] refusing to write the manifest; fix the contract or the compiler.');
    process.exit(1);
  }

  // Detect hex collisions — two different sources producing the same bytes.
  // The first one wins; we report the rest so a human can decide which
  // canonical form to keep.
  const byHex = new Map<string, Entry>();
  const collisions: { hex: string; first: string; collides: string }[] = [];
  for (const e of entries) {
    const prev = byHex.get(e.hex);
    if (prev) {
      collisions.push({ hex: e.hex, first: prev.origin, collides: e.origin });
    } else {
      byHex.set(e.hex, e);
    }
  }

  // Preserve generatedAt when entries are semantically unchanged so the
  // manifest doesn't churn on timestamp alone.
  let preservedTimestamp: string | null = null;
  try {
    const prev = JSON.parse(readFileSync(OUT, 'utf8')) as Manifest;
    const prevKey = JSON.stringify(prev.entries);
    const nextKey = JSON.stringify(entries);
    if (prevKey === nextKey) preservedTimestamp = prev.generatedAt;
  } catch {
    // ignore — file absent or unparseable
  }

  const manifest: Manifest = {
    generatedAt: preservedTimestamp ?? new Date().toISOString(),
    compilerVersion: '0.5.0',
    entries,
  };

  writeFileSync(OUT, JSON.stringify(manifest, null, 2) + '\n', 'utf8');

  console.log(`[templates] wrote ${entries.length} entries → ${OUT}${preservedTimestamp ? ' (timestamp preserved)' : ''}`);
  if (collisions.length > 0) {
    console.log(`[templates] ${collisions.length} hex collisions (first wins):`);
    for (const c of collisions) console.log(`  - ${c.first} <==> ${c.collides}`);
  }
}

main();
