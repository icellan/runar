/**
 * N-320: the state-reading paths must refuse a hostile script with a typed
 * error, never crash, hang or fabricate state.
 *
 * Replays conformance/sdk-matches-artifact/hostile-state.json (the N-317
 * hostile scripts of hostile.json, with expected outcomes for
 * extractStateFromScript, fromUtxo and fromTxId; replayed by all 7 SDKs) in
 * a child process (n320-hostile-state-replay.mts) so a reader that never
 * terminates is killed at a wall-clock cap.
 *
 * Proves: for each of the 30 scripts, extractStateFromScript on the stateful
 * artifact returns exactly the expected state / null / MalformedScriptError,
 * and fromUtxo and fromTxId either reconnect or throw MalformedScriptError
 * (never another exception) — so an odd-length, non-hex or non-ASCII script
 * is refused before any reader runs, and a stateful artifact over a script
 * with no state section is refused (C10) with the typed error; the replay
 * stays inside a process-CPU budget.
 * Does NOT prove: on-chain spendability of a reconnected contract; artifact
 * shapes other than the two in the fixture; the MalformedScriptError
 * deserializeState raises on a hex-valid truncated or overlong state section
 * (no case here reaches it; pushdata4-unsigned-length.test.ts covers it).
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const fx = JSON.parse(readFileSync(resolve(repoRoot, 'conformance/sdk-matches-artifact/hostile-state.json'), 'utf8')) as {
  cases: { name: string; state: unknown; fromUtxo: string }[];
};

const CPU_BUDGET_MS = 20_000;
const WALL_CAP_MS = 120_000;

describe('N-320: hostile scripts on the state-reading paths (shared vector)', () => {
  const child = spawnSync(
    process.execPath,
    [resolve(repoRoot, 'node_modules/tsx/dist/cli.mjs'), resolve(here, 'n320-hostile-state-replay.mts')],
    { encoding: 'utf8', timeout: WALL_CAP_MS, maxBuffer: 1 << 24 },
  );
  const out = child.status === 0 ? JSON.parse(child.stdout) as {
    state: Record<string, unknown>; fromUtxo: Record<string, string>; fromTxId: Record<string, string>; cpuMs: number;
  } : undefined;

  it('the replay terminates and stays inside the CPU budget', () => {
    expect(child.error, `replay killed after ${WALL_CAP_MS} ms (hang)`).toBeUndefined();
    expect(child.status, child.stderr).toBe(0);
    expect(out!.cpuMs).toBeLessThan(CPU_BUDGET_MS);
  });

  for (const c of fx.cases) {
    it(`extractStateFromScript: ${c.name} -> ${JSON.stringify(c.state)}`, () => {
      expect(out?.state[c.name]).toEqual(c.state);
    });
    it(`fromUtxo / fromTxId: ${c.name} -> ${c.fromUtxo}`, () => {
      expect(out?.fromUtxo[c.name]).toBe(c.fromUtxo);
      expect(out?.fromTxId[c.name]).toBe(c.fromUtxo);
    });
  }
});
