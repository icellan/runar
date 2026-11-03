/**
 * N-317 replay helper (not a test file). Run in a child process by
 * n317-hostile-utxo-scripts.test.ts so a matcher that never terminates is
 * killed instead of hanging vitest: a synchronous loop cannot be interrupted
 * in-process. Prints one JSON line with every case's outcome, the txids
 * TokenWallet.getUtxos kept per artifact, and the process CPU time used.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { matchesArtifact } from '../script-utils.js';
import { MalformedScriptError } from '../errors.js';
import { TokenWallet } from '../tokens.js';
import { MockProvider } from '../providers/mock.js';
import type { RunarArtifact } from '../types.js';
import type { Signer } from '../signers/signer.js';

interface HostileCase {
  name: string; artifact: string; prefix: string; repeat?: string; count?: number; suffix?: string;
  matches: 'match' | 'no_match' | 'malformed'; wallet: boolean | null;
}
const fx = JSON.parse(readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), '../../../../conformance/sdk-matches-artifact/hostile.json'),
  'utf8',
)) as { artifacts: Record<string, RunarArtifact>; cases: HostileCase[] };

const scriptOf = (c: HostileCase) => c.prefix + (c.repeat ?? '').repeat(c.count ?? 0) + (c.suffix ?? '');
const txidOf = (i: number) => i.toString(16).padStart(2, '0').repeat(32);

const signer = {
  async getPublicKey() { return '02' + '11'.repeat(32); },
  async getAddress() { return 'hostile-address'; },
  async sign() { return '00'.repeat(71); },
} as unknown as Signer;

const start = process.cpuUsage();
const matches: Record<string, string> = {};
fx.cases.forEach((c) => {
  try {
    matches[c.name] = matchesArtifact(fx.artifacts[c.artifact]!, scriptOf(c)) ? 'match' : 'no_match';
  } catch (e) {
    matches[c.name] = e instanceof MalformedScriptError ? 'malformed' : `error:${(e as Error).constructor.name}`;
  }
});
const wallet: Record<string, string[] | string> = {};
for (const name of Object.keys(fx.artifacts)) {
  const provider = new MockProvider();
  fx.cases.forEach((c, i) => {
    if (c.artifact !== name || c.wallet === null) return;
    provider.addUtxo('hostile-address', { txid: txidOf(i), outputIndex: 0, satoshis: 1000, script: scriptOf(c) });
  });
  try {
    wallet[name] = (await new TokenWallet(fx.artifacts[name]!, provider, signer).getUtxos()).map((u) => u.txid);
  } catch (e) {
    wallet[name] = `threw ${(e as Error).constructor.name}: ${(e as Error).message}`;
  }
}
const used = process.cpuUsage(start);
process.stdout.write(JSON.stringify({ matches, wallet, cpuMs: (used.user + used.system) / 1000 }) + '\n');
