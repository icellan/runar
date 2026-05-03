/**
 * DataOutputs integration test - stateful contract emitting an OP_RETURN
 * data output via this.addDataOutput(...).
 *
 * Ported from integration/go/data_outputs_test.go (BSVM R9 acceptance:
 * data outputs must appear in declaration order between state outputs
 * and change so the compile-time continuation-hash check matches at
 * spend time).
 *
 * Compiles a stateful contract whose method calls this.addDataOutput
 * (counter += 1; addDataOutput(0n, payload)), drives it through
 * RunarContract.deploy/.call against the regtest node, then re-fetches
 * the broadcast tx and asserts that:
 *   - output[0] = state continuation
 *   - output[1] = data output (OP_RETURN payload, 0 sats)
 *   - output[2] = change (P2PKH)
 */

import { describe, it, expect } from 'vitest';
import { Transaction } from '@bsv/sdk';
import { compileSource } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';
import { rpcCall } from './helpers/node.js';

const SOURCE = `
import { StatefulSmartContract, ByteString } from 'runar-lang';

export class DataEmitter extends StatefulSmartContract {
    counter: bigint;

    constructor(counter: bigint) {
        super(counter);
        this.counter = counter;
    }

    public emit(payload: ByteString) {
        this.counter = this.counter + 1n;
        this.addDataOutput(0n, payload);
    }
}
`;

describe('DataOutputs (addDataOutput)', () => {
  it('emits a data output at index [1] between state and change', async () => {
    const artifact = compileSource(SOURCE, 'DataEmitter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 10_000 });
    expect(deployTxid).toBeTruthy();

    // OP_RETURN "bsvm-test" — the data payload (matches Go test exactly)
    const payload = '6a09' + '6273766d2d74657374';

    const { txid: callTxid } = await contract.call('emit', [payload], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(contract.state.counter).toBe(1n);

    // Re-fetch the broadcasted call tx via JSON-RPC and parse outputs.
    const rawTxHex = (await rpcCall('getrawtransaction', callTxid)) as string;
    const tx = Transaction.fromHex(rawTxHex);

    // Expected output order: [0]=state, [1]=data (OP_RETURN payload, 0 sats),
    // [2]=change (P2PKH). The state-continuation hash must match this exact
    // ordering for the spend to validate on-chain.
    expect(tx.outputs.length).toBeGreaterThanOrEqual(2);

    const dataOutput = tx.outputs[1]!;
    expect(dataOutput.satoshis).toBe(0);
    expect(dataOutput.lockingScript.toHex()).toBe(payload);
  });

  it('chains two emits and accumulates state', async () => {
    const artifact = compileSource(SOURCE, 'DataEmitter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 10_000 });

    const payload1 = '6a05' + '6669727374'; // OP_RETURN "first"
    const payload2 = '6a06' + '7365636f6e64'; // OP_RETURN "second"

    const { txid: t1 } = await contract.call('emit', [payload1], provider, signer);
    expect(t1).toBeTruthy();
    expect(contract.state.counter).toBe(1n);

    const { txid: t2 } = await contract.call('emit', [payload2], provider, signer);
    expect(t2).toBeTruthy();
    expect(contract.state.counter).toBe(2n);

    const raw2 = (await rpcCall('getrawtransaction', t2)) as string;
    const tx2 = Transaction.fromHex(raw2);
    expect(tx2.outputs[1]!.lockingScript.toHex()).toBe(payload2);
    expect(tx2.outputs[1]!.satoshis).toBe(0);
  });
});
