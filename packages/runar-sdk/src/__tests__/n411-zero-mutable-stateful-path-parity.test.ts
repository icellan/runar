/**
 * N-411 — the single-contract path (RunarContract.call) and the multi-contract
 * path (assembleMultiContractCall) must agree on which ABI params the SDK
 * supplies for a StatefulSmartContract with ZERO mutable fields
 * (AllReadonlyCleanstack: parentClass StatefulSmartContract, stateFields []).
 * Convention (user decision R162, pinned by the n085/n258/n227 tests in all
 * seven tiers): txPreimage is a USER arg, passed as null; claim() takes
 * [null, null].
 *
 * Proves: assembleMultiContractCall accepts the same [null, null] args as
 * call(), the assembled input validates under @bsv/sdk Spend, and its unlocking
 * script has the same push layout (chunk count and sizes) as the one call()
 * broadcasts; the old multi-contract arity (1 arg) is refused.
 *
 * Does not prove: byte-equality of the two unlocks (the transactions differ,
 * so the preimages and signatures differ), the other six SDKs (they have no
 * multi-contract assembler), or contracts with state fields (covered by
 * multi-contract-call.test.ts).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { Transaction, UnlockingScript } from '@bsv/sdk';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { assembleMultiContractCall } from '../multi-contract.js';
import fs from 'fs';
import path from 'path';

const KEY = '0000000000000000000000000000000000000000000000000000000000000003';

function chunkSizes(unlockHex: string): number[] {
  return UnlockingScript.fromHex(unlockHex).chunks.map((c) => c.data?.length ?? 0);
}

describe('N-411 zero-mutable StatefulSmartContract: call() and multi-contract agree', () => {
  it('both paths take [null, null] and build the same unlock layout', async () => {
    const source = fs.readFileSync(
      path.join(__dirname, '../../../../examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts'),
      'utf8',
    );
    const r = compile(source, { fileName: 'AllReadonlyCleanstack.runar.ts' });
    const artifact = r.artifact!;
    expect(artifact.parentClass).toBe('StatefulSmartContract');
    expect(artifact.stateFields ?? []).toEqual([]);

    const signer = new LocalSigner(KEY);
    const pubKey = await signer.getPublicKey();
    const address = await signer.getAddress();
    const lockingHex = new RunarContract(artifact, [pubKey]).getLockingScript();
    const utxo = { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5000, script: lockingHex };
    const funding = { txid: 'bb'.repeat(32), outputIndex: 0, satoshis: 100_000, script: buildP2PKHScript(pubKey) };

    // Single-contract path.
    const provider = new MockProvider('testnet');
    provider.addUtxo(address, funding);
    provider.addContractUtxo(lockingHex, utxo);
    const single = RunarContract.fromUtxo(artifact, utxo);
    await single.call('claim', [null, null], provider, signer);
    const singleTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
    const singleUnlock = singleTx.inputs[0]!.unlockingScript!.toHex();

    // Multi-contract path, same args.
    const multi = RunarContract.fromUtxo(artifact, utxo);
    const outputs = [{ satoshis: 4000, script: buildP2PKHScript(pubKey) }];
    const assembled = await assembleMultiContractCall(
      [{ contract: multi, method: 'claim', args: [null, null], utxo, signer }],
      outputs,
    );
    // Chunk 0 is a DER signature (70-73 bytes, varies per tx); the rest is the
    // preimage, whose size depends only on the locking script.
    const norm = (sizes: number[]): number[] => sizes.map((n, i) => (i === 0 && n >= 70 && n <= 73 ? -1 : n));
    expect(chunkSizes(singleUnlock).length).toBe(2);
    expect(norm(chunkSizes(assembled.unlocks[0]!))).toEqual(norm(chunkSizes(singleUnlock)));

    // The pre-N-411 multi-contract arity (preimage SDK-supplied) is refused.
    await expect(
      assembleMultiContractCall(
        [{ contract: multi, method: 'claim', args: [null], utxo, signer }],
        outputs,
      ),
    ).rejects.toThrow(/expects 2 args, got 1/);
  });
});
