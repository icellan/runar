/**
 * #197 independent oracle for the add-output-env family: only `update_prop`
 * changes a property; `addOutput(sats, ...values)` serialises its values into
 * its OWN output and does not write the property later reads load.
 *
 * The pinned goldens (expected/ and expected-strict/) are stamped from an
 * interpreter, so by themselves they only prove the interpreters agree. This
 * test checks them against the compiled locking script: it deploys the
 * contract and calls each method through the validating MockProvider, which
 * replays the broadcast through @bsv/sdk's real Spend (OP_PUSH_TX + the
 * covenant's own hashOutputs reconstruction). A transaction whose outputs
 * differ from what the script computes by even one byte is refused. The
 * continuation states are then decoded straight off the broadcast outputs
 * (byte layout, not by re-running the transition) and compared with the
 * golden `state`, which is the LAST write.
 *
 * Proves: the outputs the script commits to are count+1 / count+100 (fanOut)
 * and count+1 / count+105 (bumpBetween), and the goldens' last-write state
 * equals the last on-chain continuation. Does not prove: the per-tier driver
 * agreement (cross-interpreter*.test.ts) or CallOptions behaviour.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Transaction } from '@bsv/sdk';
import { compile } from '../../packages/runar-compiler/src/index.js';
import {
  RunarContract, MockProvider, LocalSigner, buildP2PKHScript, extractStateFromScript,
} from '../../packages/runar-sdk/src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(here, 'programs/AddOutputEnv.runar.ts'), 'utf8');
const artifact = (() => {
  const r = compile(source, { fileName: 'AddOutputEnv.runar.ts' });
  if (!r.artifact) throw new Error(JSON.stringify(r.diagnostics));
  return r.artifact;
})();

const cases = [
  { name: 'fan-out', method: 'fanOut', onChain: [1n, 100n] },
  { name: 'bump-between', method: 'bumpBetween', onChain: [1n, 105n] },
] as const;

describe('add-output-env: goldens agree with the deployed script on a real Spend', () => {
  for (const c of cases) {
    it(`${c.method}: continuations ${c.onChain.join(', ')}; golden state = the last`, async () => {
      const key = '0000000000000000000000000000000000000000000000000000000000000005';
      const signer = new LocalSigner(key);
      const provider = new MockProvider('testnet');
      provider.addUtxo(await signer.getAddress(), {
        txid: 'ee'.repeat(32), outputIndex: 0, satoshis: 500_000,
        script: buildP2PKHScript(await signer.getPublicKey()),
      });
      const contract = new RunarContract(artifact, [0n]);
      await contract.deploy(provider, signer, { satoshis: 5000 });
      await contract.call(c.method, [], provider, signer); // MockProvider Spend-validates

      const tx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
      const counts = tx.outputs.slice(0, 2).map(
        (o) => extractStateFromScript(artifact, o.lockingScript.toHex())!.count as bigint,
      );
      expect(counts).toEqual([...c.onChain]);

      for (const dir of ['expected', 'expected-strict']) {
        const golden = JSON.parse(
          readFileSync(join(here, dir, `add-output-env-${c.name}.json`), 'utf8'),
        ) as { state: { count: string } };
        expect(golden.state.count, `${dir}/${c.name}`).toBe(`${c.onChain[1]}n`);
      }
    });
  }
});
