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

import { afterAll, afterEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  checkEntriesNotDeleted,
  findDeletedEntryIds,
  loadCorpus,
  runCheckNoDeletions,
  runReplay,
  runReplayAndReport,
} from './replay.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

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
 * non-empty corpus is detected. That needed a base-ref git diff (did a
 * directory that existed on the base branch disappear?) and was a separate,
 * larger piece of work than this item's testable assertion covered — it is
 * now covered by `checkEntriesNotDeleted` below (N-230). Nor do
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

/**
 * README.md rule 3: "Entries are never deleted." The empty-corpus guard above
 * (F-250) only catches the corpus being wiped to ZERO entries. Deleting one
 * entry out of five is a passing, non-empty corpus — nothing in `loadCorpus`
 * or `runReplay` sees that an id that existed on the base branch is gone
 * (N-230).
 *
 * `checkEntriesNotDeleted` closes that gap: it lists the entry directory
 * names present at the merge-base of a given ref and HEAD (via `git ls-tree`),
 * lists the directory names present on disk now, and returns any id in the
 * first set missing from the second. Merge-base, not the base ref's live tip,
 * so a base branch that gains NEW entries after this branch forked is never
 * mistaken for a deletion on this branch (mirrors the repo's documented
 * three-dot-from-merge-base convention, e.g. `check-golden-provenance.mjs`).
 *
 * These tests prove: the pure diff (`findDeletedEntryIds`) is correct; the
 * git-backed check detects a real single-entry deletion across two commits in
 * an actual repo and names the deleted id; it does NOT false-positive when
 * entries are only added, when nothing changed, or when the base branch moved
 * forward with entries this branch never had; and it tolerates the base ref
 * not having an `entries/` directory at all. It does NOT prove anything about
 * CI wiring (the `.github/workflows/ci.yml` step), about rename detection (a
 * rename is indistinguishable from delete+add by directory name, which is
 * correct — the directory name is the entry's id and provenance key — and is
 * not separately exercised here), or about what happens on a direct push to
 * main with no PR review (merge-base == HEAD there, so the check cannot catch
 * it; that is a documented gap, not a defect in this check).
 */
describe('checkEntriesNotDeleted (N-230, README.md rule 3)', () => {
  describe('findDeletedEntryIds — pure diff', () => {
    it('returns ids present at base but missing now', () => {
      expect(findDeletedEntryIds(['a', 'b', 'c'], ['a', 'c'])).toEqual(['b']);
    });

    it('returns empty when nothing was deleted, including when entries were only added', () => {
      expect(findDeletedEntryIds(['a', 'b'], ['a', 'b', 'c'])).toEqual([]);
      expect(findDeletedEntryIds(['a', 'b'], ['a', 'b'])).toEqual([]);
      expect(findDeletedEntryIds([], [])).toEqual([]);
    });
  });

  describe('checkEntriesNotDeleted — over a real git repo', () => {
    interface Repo {
      root: string;
      entriesDir: string;
      git: (...args: string[]) => string;
      writeEntry: (id: string) => void;
      write: (rel: string, body: string) => void;
      commit: (msg: string) => string;
    }

    const roots: string[] = [];

    function repo(): Repo {
      const root = mkdtempSync(join(tmpdir(), 'fuzz-regressions-delete-check-'));
      roots.push(root);
      const entriesDir = join(root, 'conformance', 'fuzz-regressions', 'entries');
      const git = (...args: string[]) =>
        execFileSync('git', ['-C', root, ...args], { encoding: 'utf-8' }).trim();
      git('init', '-q', '-b', 'main');
      git('config', 'user.email', 'n230@example.invalid');
      git('config', 'user.name', 'n230');
      git('config', 'commit.gpgsign', 'false');
      return {
        root,
        entriesDir,
        git,
        writeEntry(id) {
          // Only the directory name matters to this check — it never reads
          // entry.json — so an empty marker file is enough to make the
          // directory real to git (git does not track empty directories).
          const dir = join(entriesDir, id);
          mkdirSync(dir, { recursive: true });
          writeFileSync(join(dir, 'contract.runar.ts'), '// fixture\n', 'utf-8');
        },
        write(rel, body) {
          writeFileSync(join(root, rel), body, 'utf-8');
        },
        commit(msg) {
          git('add', '-A');
          git('commit', '-q', '--no-verify', '-m', msg);
          return git('rev-parse', 'HEAD');
        },
      };
    }

    afterAll(() => {
      for (const r of roots) rmSync(r, { recursive: true, force: true });
    });

    it('detects a single entry deleted since the base ref and names it', () => {
      const r = repo();
      r.writeEntry('2026-01-01-a');
      r.writeEntry('2026-01-02-b');
      r.commit('base: two entries');

      rmSync(join(r.entriesDir, '2026-01-02-b'), { recursive: true, force: true });
      r.commit('branch: delete entry b');

      const deleted = checkEntriesNotDeleted({ repoRoot: r.root, baseRef: 'HEAD~1' });
      expect(deleted).toEqual(['2026-01-02-b']);
    });

    /** Run `runCheckNoDeletions` in-process, capturing console output and the returned exit code. */
    function runCheckNoDeletionsCapturing(opts: { baseRef: string; root: string }): {
      code: number;
      out: string;
    } {
      const chunks: string[] = [];
      const log = console.log;
      const err = console.error;
      console.log = (...a: unknown[]) => void chunks.push(a.join(' '));
      console.error = (...a: unknown[]) => void chunks.push(a.join(' '));
      try {
        return { code: runCheckNoDeletions(opts), out: chunks.join('\n') };
      } finally {
        console.log = log;
        console.error = err;
      }
    }

    it('runCheckNoDeletions (the CLI path) returns exit code 1 and reports the deleted id, not just checkEntriesNotDeleted', () => {
      const r = repo();
      r.writeEntry('2026-01-01-a');
      r.writeEntry('2026-01-02-b');
      r.commit('base: two entries');

      rmSync(join(r.entriesDir, '2026-01-02-b'), { recursive: true, force: true });
      r.commit('branch: delete entry b');

      const { code, out } = runCheckNoDeletionsCapturing({ baseRef: 'HEAD~1', root: r.root });
      expect(code).toBe(1);
      expect(out).toContain('RULE 3 VIOLATED');
      expect(out).toContain('2026-01-02-b');
    });

    it('runCheckNoDeletions returns exit code 0 when nothing was deleted', () => {
      const r = repo();
      r.writeEntry('2026-01-01-a');
      r.commit('base: one entry');
      r.write('UNRELATED.md', 'touches nothing under entries/\n');
      r.commit('branch: unrelated change, entries/ untouched');

      const { code, out } = runCheckNoDeletionsCapturing({ baseRef: 'HEAD~1', root: r.root });
      expect(code).toBe(0);
      expect(out).not.toContain('RULE 3 VIOLATED');
    });

    it('does not flag anything when an entry is only added', () => {
      const r = repo();
      r.writeEntry('2026-01-01-a');
      r.commit('base: one entry');

      r.writeEntry('2026-01-02-b');
      r.commit('branch: add entry b');

      expect(checkEntriesNotDeleted({ repoRoot: r.root, baseRef: 'HEAD~1' })).toEqual([]);
    });

    it('does not flag anything when the corpus is unchanged', () => {
      const r = repo();
      r.writeEntry('2026-01-01-a');
      r.commit('base: one entry');
      r.write('UNRELATED.md', 'touches nothing under entries/\n');
      r.commit('branch: unrelated change, entries/ untouched');

      expect(checkEntriesNotDeleted({ repoRoot: r.root, baseRef: 'HEAD~1' })).toEqual([]);
    });

    it('uses the merge-base, not the base ref live tip: an entry only main gained AFTER the fork is not "deleted" on this branch', () => {
      const r = repo();
      r.writeEntry('2026-01-01-a');
      r.commit('base: one entry');

      r.git('checkout', '-q', '-b', 'feature');
      r.write('UNRELATED.md', 'diverge from main\n');
      r.commit('feature: unrelated change, diverges from main');

      r.git('checkout', '-q', 'main');
      r.writeEntry('2026-02-01-c');
      r.commit('main: a LATER PR adds entry c (feature forked before this and never had it)');

      r.git('checkout', '-q', 'feature');
      // feature's own entries/ still only has 'a'. main's live tip now has
      // {a, c}. Diffing against that live tip directly would see 'c' missing
      // from feature and misreport it as DELETED — it was simply never there.
      // The merge-base of main and feature is the original one-entry commit,
      // so the correct answer is "nothing deleted".
      expect(checkEntriesNotDeleted({ repoRoot: r.root, baseRef: 'main' })).toEqual([]);
    });

    it('tolerates the base ref not having an entries/ directory at all', () => {
      const r = repo();
      r.git('commit', '--allow-empty', '-q', '--no-verify', '-m', 'base: no conformance/ directory yet');

      r.writeEntry('2026-01-01-a');
      r.commit('branch: introduce the corpus for the first time');

      expect(checkEntriesNotDeleted({ repoRoot: r.root, baseRef: 'HEAD~1' })).toEqual([]);
    });
  });

  describe('checkEntriesNotDeleted — the real, checked-in corpus', () => {
    it('reports no deletions against origin/main from this worktree', () => {
      // Smoke test over the actual repo, not a fixture: proves the function
      // runs cleanly against the real entries/ directory and the real git
      // history available in CI (fetch-depth: 0) and in this worktree.
      const repoRoot = resolve(__dirname, '..', '..');
      expect(() =>
        execFileSync('git', ['-C', repoRoot, 'rev-parse', '--verify', 'origin/main'], {
          stdio: 'ignore',
        }),
      ).not.toThrow();
      expect(checkEntriesNotDeleted({ repoRoot, baseRef: 'origin/main' })).toEqual([]);
    });
  });
});
