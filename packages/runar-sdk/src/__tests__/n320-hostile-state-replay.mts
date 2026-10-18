/**
 * N-320 replay helper (not a test file). Run in a child process by
 * n320-hostile-state-paths.test.ts so a reader that never terminates is
 * killed instead of hanging vitest. Prints one JSON line with every case's
 * extractStateFromScript / fromUtxo / fromTxId outcome and the process CPU
 * time used.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractStateFromScript } from '../state.js';
import { RunarContract } from '../contract.js';
import { MalformedScriptError } from '../errors.js';
import { MockProvider } from '../providers/mock.js';
import type { RunarArtifact } from '../types.js';

interface HostileCase { name: string; artifact: string; prefix: string; repeat?: string; count?: number; suffix?: string }
const dir = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../conformance/sdk-matches-artifact');
const fx = JSON.parse(readFileSync(resolve(dir, 'hostile.json'), 'utf8')) as {
  artifacts: Record<string, RunarArtifact>; cases: HostileCase[];
};
const scriptOf = (c: HostileCase) => c.prefix + (c.repeat ?? '').repeat(c.count ?? 0) + (c.suffix ?? '');
const txidOf = (i: number) => i.toString(16).padStart(2, '0').repeat(32);

const classify = (e: unknown) =>
  e instanceof MalformedScriptError ? 'malformed' : `error:${(e as Error).constructor.name}: ${(e as Error).message}`;

const start = process.cpuUsage();
const state: Record<string, unknown> = {};
const fromUtxo: Record<string, string> = {};
const fromTxId: Record<string, string> = {};
const provider = new MockProvider();
for (const [i, c] of fx.cases.entries()) {
  const script = scriptOf(c);
  try {
    const s = extractStateFromScript(fx.artifacts.stateful!, script);
    state[c.name] = s === null ? null : Object.fromEntries(Object.entries(s).map(([k, v]) => [k, String(v)]));
  } catch (e) {
    state[c.name] = classify(e);
  }
  try {
    RunarContract.fromUtxo(fx.artifacts[c.artifact]!, { txid: txidOf(i), outputIndex: 0, satoshis: 1000, script });
    fromUtxo[c.name] = 'ok';
  } catch (e) {
    fromUtxo[c.name] = classify(e);
  }
  provider.addTransaction({ txid: txidOf(i), version: 1, inputs: [], outputs: [{ satoshis: 1000, script }], locktime: 0 });
  try {
    await RunarContract.fromTxId(fx.artifacts[c.artifact]!, txidOf(i), 0, provider);
    fromTxId[c.name] = 'ok';
  } catch (e) {
    fromTxId[c.name] = classify(e);
  }
}
const used = process.cpuUsage(start);
process.stdout.write(JSON.stringify({ state, fromUtxo, fromTxId, cpuMs: (used.user + used.system) / 1000 }) + '\n');
