/**
 * `entry.oracle` is declared as the TS union `'execute' | 'tri-modal'`, but
 * `loadCorpus` reads it with `JSON.parse(...) as RegressionEntry` — a
 * compile-time-only assertion. Nothing at runtime checked the actual string a
 * corpus entry carries. A missing, misspelt, or future `oracle` value fell
 * through `replayEntry`'s `if (entry.oracle === 'tri-modal') {...} else {...}`
 * dispatch into the weaker bare-`ScriptVM` `execute` path and silently
 * recorded that engine's verdict as if it were the consensus one (F-171).
 *
 * These tests prove `loadCorpus` now rejects any `oracle` value other than
 * the two it understands, naming the entry and the bad value, instead of
 * loading the entry and letting `replayEntry` silently downgrade the oracle.
 *
 * What they do NOT prove: that `replayEntry`'s dispatch itself is correct for
 * either oracle, or that any real corpus entry under `entries/` is affected —
 * only that a malformed `oracle` field can no longer reach that dispatch.
 */

import { afterEach, describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadCorpus, runReplay, runReplayAndReport } from './replay.js';

/** Build one corpus entry directory with a valid skeleton plus overrides. */
function writeEntry(entriesRoot: string, id: string, overrides: Record<string, unknown>): string {
  const dir = join(entriesRoot, id);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'contract.runar.ts'), 'export class Dummy {}\n', 'utf-8');
  const entry: Record<string, unknown> = {
    id,
    title: 'fixture entry for replay.test.ts',
    discovered: '2026-01-01',
    oracle: 'execute',
    sourceFile: 'contract.runar.ts',
    fileName: 'Dummy.runar.ts',
    method: 'noop',
    constructorArgs: {},
    args: [],
    expect: { interpreterAccepted: true, vmAccepted: true },
    requiredOpcodes: ['OP_CHECKSIG'],
    provenance: {},
    rationale: 'fixture only, never replayed',
    ...overrides,
  };
  writeFileSync(join(dir, 'entry.json'), JSON.stringify(entry, null, 2), 'utf-8');
  return dir;
}

describe('loadCorpus validates entry.oracle', () => {
  let root: string | undefined;

  afterEach(() => {
    if (root) rmSync(root, { recursive: true, force: true });
    root = undefined;
  });

  it('rejects a misspelt oracle value, naming the entry and the bad value', () => {
    root = mkdtempSync(join(tmpdir(), 'runar-fuzz-regressions-'));
    writeEntry(root, 'bad-oracle', { oracle: 'excute' });

    expect(() => loadCorpus(root!)).toThrow(/oracle/i);
    expect(() => loadCorpus(root!)).toThrow(/excute/);
    expect(() => loadCorpus(root!)).toThrow(/bad-oracle/);
  });

  it('rejects an entry whose oracle field is entirely missing', () => {
    root = mkdtempSync(join(tmpdir(), 'runar-fuzz-regressions-'));
    const dir = writeEntry(root, 'missing-oracle', {});
    const entryPath = join(dir, 'entry.json');
    const raw = JSON.parse(readFileSync(entryPath, 'utf-8')) as Record<string, unknown>;
    delete raw.oracle;
    writeFileSync(entryPath, JSON.stringify(raw, null, 2), 'utf-8');

    expect(() => loadCorpus(root!)).toThrow(/oracle/i);
    expect(() => loadCorpus(root!)).toThrow(/missing-oracle/);
  });

  it('still accepts both recognised oracle values', () => {
    root = mkdtempSync(join(tmpdir(), 'runar-fuzz-regressions-'));
    writeEntry(root, 'ok-execute', { oracle: 'execute' });
    writeEntry(root, 'ok-tri-modal', { oracle: 'tri-modal' });

    expect(() => loadCorpus(root!)).not.toThrow();
    const loaded = loadCorpus(root!);
    expect(loaded.map((l) => l.entry.id).sort()).toEqual(['ok-execute', 'ok-tri-modal']);
  });
});

/**
 * `runReplayAndReport` treated `report.total === 0` as an ordinary passing
 * run: it logged "(corpus is empty)" and returned `{ total: 0, passed: 0,
 * failed: 0 }`. `main()`'s only failure condition is `report.failed > 0`,
 * which a report of all zeroes never trips — so an `entries/` directory
 * wiped down to nothing (violating the corpus's own README.md rule 3,
 * "entries are never deleted") replayed green on every CI run (F-250).
 *
 * These tests prove `runReplay`/`runReplayAndReport` now refuse to produce a
 * report at all when the (unfiltered) corpus has zero entries — whether
 * `entriesDir` exists and is empty, or does not exist — instead of silently
 * reporting success, and that a non-empty corpus (in particular the real one
 * under `entries/`) is unaffected.
 *
 * What they do NOT prove: that deleting ONE entry out of an otherwise
 * non-empty corpus is detected. That needs a base-ref git diff (did a
 * directory that existed on the base branch disappear?) and is a separate,
 * larger piece of work than this item's testable assertion covers. Nor do
 * they exercise `process.exit` directly — they rely on the thrown error
 * propagating through the existing `main().catch(...)` wrappers in this file
 * and in `conformance/fuzzer/index.ts`, which is not re-verified here.
 */
describe('runReplay / runReplayAndReport refuse an empty corpus (F-250)', () => {
  let root: string | undefined;

  afterEach(() => {
    if (root) rmSync(root, { recursive: true, force: true });
    root = undefined;
  });

  it('throws instead of silently reporting a green 0/0/0 run when entriesDir exists but is empty', () => {
    root = mkdtempSync(join(tmpdir(), 'runar-fuzz-regressions-empty-'));
    expect(() => runReplay({ entriesDir: root! })).toThrow(/empty/i);
  });

  it('throws the same way through runReplayAndReport, the shared CLI + fuzzer/index.ts entry point', () => {
    root = mkdtempSync(join(tmpdir(), 'runar-fuzz-regressions-empty-'));
    expect(() => runReplayAndReport({ entriesDir: root! })).toThrow(/empty/i);
  });

  it('throws when entriesDir does not exist at all, not only when it exists and is empty', () => {
    root = mkdtempSync(join(tmpdir(), 'runar-fuzz-regressions-missing-'));
    const missing = join(root, 'does-not-exist');
    expect(() => runReplay({ entriesDir: missing })).toThrow(/empty/i);
  });

  it('does not throw once the corpus has at least one entry, even if that entry fails to replay', () => {
    // The fixture written by `writeEntry` is "fixture only, never replayed" in
    // loadCorpus's own tests (F-171) — here it IS replayed, and its `Dummy`
    // class fails to compile. That is the point: the empty-corpus guard keys
    // on entry COUNT, not on pass/fail, so a corpus with one failing entry
    // must still produce a (failing) report rather than throw.
    root = mkdtempSync(join(tmpdir(), 'runar-fuzz-regressions-nonempty-'));
    writeEntry(root, 'ok-entry', {});
    expect(() => runReplay({ entriesDir: root! })).not.toThrow();
  });

  it('does not throw for the real, checked-in corpus under entries/', () => {
    expect(loadCorpus().length).toBeGreaterThan(0);
    expect(() => runReplay()).not.toThrow();
  });
});
