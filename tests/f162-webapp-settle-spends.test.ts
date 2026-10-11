/**
 * F-162 (CL-BUG-255) — the PriceBet webapp's settle path spends.
 *
 * The webapp compiled every PriceBet with `oraclePubKey = 12345` and always
 * spent through `cancel`, so the oracle settlement it advertises never ran.
 * Under that key no genuine oracle signature verifies, while — because
 * verifyRabinSig reduces the digest mod the key — `sig = 0, padding =
 * SHA256(msg) mod 12345` passes for any price, signed by nobody.
 *
 * `examples/end2end-example/webapp/settle_spend_test.go` builds the vectors
 * with the webapp's own code (the locking script deployContract broadcasts and
 * the settle spend handleReveal broadcasts); this file replays each one on
 * @bsv/sdk Spend under the strict v1 rule set. Spend, not the Go compiler or
 * the ANF interpreter, gives the verdict.
 *
 * Proves: for a contract the webapp deploys, the settle spend the webapp builds
 * is accepted, pays the round's winner, needs only the winner's signature, and
 * maps "over"/"under" onto the contract's alice/bob slots correctly whichever
 * player bet over; a loser-signed spend, a price the oracle did not sign, and
 * the 12345-era forged signature are all rejected.
 *
 * Does not prove: that a regtest node relays or mines it (fee, mempool policy,
 * the RPC plumbing in handleReveal), nor the other eight source languages —
 * the vectors compile the TypeScript source; F-148's price-bet fixture holds
 * all nine to one script.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Transaction } from '@bsv/sdk';
import { validateContractInput } from '../packages/runar-testing/src/oracle/index.js';

const REPO = resolve(__dirname, '..');
const WEBAPP = join(REPO, 'examples', 'end2end-example', 'webapp');

interface SettleVector {
  name: string;
  fundingTx: string;
  settleTx: string;
  expect: 'accept' | 'reject';
  winnerP2PKH?: string;
}

let vectors: SettleVector[] = [];

beforeAll(() => {
  const out = join(mkdtempSync(join(tmpdir(), 'f162-')), 'settle-vectors.json');
  execFileSync('go', ['test', '-count=1', '-run', '^TestF162SettleVectors$', '.'], {
    cwd: WEBAPP,
    env: { ...process.env, F162_SETTLE_VECTORS: out },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  vectors = JSON.parse(readFileSync(out, 'utf8')) as SettleVector[];
}, 180_000);

function spends(v: SettleVector): boolean {
  try {
    return validateContractInput(Transaction.fromHex(v.settleTx), 0, Transaction.fromHex(v.fundingTx), 0);
  } catch {
    return false;
  }
}

describe('F-162: the PriceBet webapp settles through the oracle path', () => {
  it('emits the expected vectors', () => {
    expect(vectors.filter((v) => v.expect === 'accept')).toHaveLength(4);
    expect(vectors.filter((v) => v.expect === 'reject')).toHaveLength(4);
  });

  it('every settle spend the webapp builds is accepted and pays the winner', () => {
    for (const v of vectors.filter((x) => x.expect === 'accept')) {
      expect(spends(v), v.name).toBe(true);
      const tx = Transaction.fromHex(v.settleTx);
      expect(tx.outputs.map((o) => o.lockingScript.toHex()), v.name).toEqual([v.winnerP2PKH]);
    }
  });

  it('a loser-signed, re-priced or forged settle is rejected', () => {
    for (const v of vectors.filter((x) => x.expect === 'reject')) {
      expect(spends(v), v.name).toBe(false);
    }
  });
});
