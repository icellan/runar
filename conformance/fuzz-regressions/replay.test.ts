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
import { loadCorpus } from './replay.js';

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
