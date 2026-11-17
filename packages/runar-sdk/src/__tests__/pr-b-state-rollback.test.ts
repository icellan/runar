/**
 * Pre-existing bug found while writing the PR B regtest negatives:
 * `prepareCall` advances the contract's local state BEFORE `finalizeCall`
 * broadcasts, and nothing put it back when the node (here MockProvider's
 * Spend replay) refused the transaction. The next call was then built from a
 * state the chain never reached.
 *
 * Proves: after a rejected broadcast, `contract.state` and the tracked UTXO
 * are exactly what they were before the call, and an honest follow-up call
 * commits the state the chain expects. Does not prove: other SDK tiers.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';

const SRC = `import { StatefulSmartContract, assert } from 'runar-lang';

class Gate extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(k: bigint) {
    assert(k === 7n);
    this.n = this.n + 1n;
  }
}
`;

describe('a refused broadcast leaves the local state untouched', () => {
  it('state and UTXO roll back; the next honest call commits n = 1', async () => {
    const r = compile(SRC, { fileName: 'Gate.runar.ts' });
    if (!r.artifact) throw new Error(JSON.stringify(r.diagnostics));
    const signer = new LocalSigner('11'.repeat(32));
    const provider = new MockProvider();
    provider.addUtxo(await signer.getAddress(), {
      txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5_000_000,
      script: buildP2PKHScript(await signer.getPublicKey()),
    });
    const contract = new RunarContract(r.artifact, [0n]);
    await contract.deploy(provider, signer, { satoshis: 50_000 });
    const utxoBefore = contract.getUtxo();

    // k = 8 fails the covenant's assert: MockProvider refuses the broadcast.
    await expect(contract.call('bump', [8n], provider, signer)).rejects.toThrow(/refusing to broadcast/);
    expect(contract.state).toEqual({ n: 0n });
    expect(contract.getUtxo()).toEqual(utxoBefore);

    await contract.call('bump', [7n], provider, signer);
    expect(contract.state).toEqual({ n: 1n });
  });
});
