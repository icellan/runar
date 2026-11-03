/**
 * N-317: one hostile UTXO script must not take TokenWallet.getUtxos down.
 *
 * Replays the shared cross-tier vector conformance/sdk-matches-artifact/
 * hostile.json (also replayed by the Go, Rust, Python, Zig, Ruby and Java
 * SDKs): odd-length and non-hex scripts, truncated OP_PUSHDATA1/2/4,
 * OP_PUSHDATA4 lengths with the high bit set, a push running past the slot,
 * empty and short scripts, and ~1 MiB scripts, beside SDK-built genuine
 * instances. The replay runs in a child process (n317-hostile-replay.mts)
 * because before the fix findLastOpReturn never terminated on an
 * OP_PUSHDATA4 length >= 0x80000000 (signed `<< 24`), and a synchronous loop
 * cannot be timed out in-process.
 *
 * Proves: matchesArtifact gives exactly the fixture's outcome for every
 * vector (match / no match / MalformedScriptError, never another exception);
 * getUtxos keeps exactly the genuine instances for a stateful and a
 * stateless artifact and never throws; the whole replay stays inside a
 * process-CPU budget (the child is also killed at a wall-clock cap so a hang
 * fails instead of stalling the suite).
 * Does NOT prove: on-chain spendability of the kept UTXOs, behaviour on
 * artifact shapes other than the two in the fixture, or anything about a
 * forged codeSepIndex element (N-318).
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const fx = JSON.parse(readFileSync(resolve(repoRoot, 'conformance/sdk-matches-artifact/hostile.json'), 'utf8')) as {
  artifacts: Record<string, unknown>;
  cases: { name: string; artifact: string; matches: string; wallet: boolean | null }[];
};

// Measured: the replay takes well under a second of CPU after the fix;
// before it, the first high-bit OP_PUSHDATA4 vector never returned.
const CPU_BUDGET_MS = 20_000;
const WALL_CAP_MS = 120_000;

describe('N-317: hostile UTXO scripts (shared vector)', () => {
  const child = spawnSync(
    process.execPath,
    [resolve(repoRoot, 'node_modules/tsx/dist/cli.mjs'), resolve(here, 'n317-hostile-replay.mts')],
    { encoding: 'utf8', timeout: WALL_CAP_MS, maxBuffer: 1 << 24 },
  );
  const out = child.status === 0 ? JSON.parse(child.stdout) as {
    matches: Record<string, string>; wallet: Record<string, string[] | string>; cpuMs: number;
  } : undefined;

  it('the replay terminates and stays inside the CPU budget', () => {
    expect(child.error, `replay killed after ${WALL_CAP_MS} ms (hang)`).toBeUndefined();
    expect(child.status, child.stderr).toBe(0);
    expect(out!.cpuMs).toBeLessThan(CPU_BUDGET_MS);
  });

  for (const c of fx.cases) {
    it(`matchesArtifact: ${c.name} -> ${c.matches}`, () => {
      expect(out?.matches[c.name]).toBe(c.matches);
    });
  }

  for (const name of Object.keys(fx.artifacts)) {
    it(`getUtxos (${name}) keeps exactly the genuine instances`, () => {
      const want = fx.cases.flatMap((c, i) =>
        c.artifact === name && c.wallet === true ? [i.toString(16).padStart(2, '0').repeat(32)] : []);
      expect(out?.wallet[name]).toEqual(want);
    });
  }
});
