/**
 * N-258 (user decision R99): a zero-mutable-field `StatefulSmartContract`
 * call that also spends `additionalContractInputs` builds a REAL per-input
 * unlock for every extra contract input, instead of refusing (N-227's
 * fail-closed guard) or shipping the sizing placeholder.
 *
 * `AllReadonlyCleanstack` has ZERO mutable fields, so `prepareCall` takes its
 * "stateless" branch (`isStateful` false) even though the contract IS
 * `parentStateful` and auto-injects `checkPreimage`. Each extra input now gets
 * its own OP_PUSH_TX preimage (its own outpoint / scriptCode / amount) and its
 * own Sig, signed at its own input index over the post-OP_CODESEPARATOR
 * subscript, and fee/change are re-derived from those real unlocks.
 *
 * The scenario is deterministic (fixed key, outpoints, amounts, MockProvider's
 * default 100 sat/KB) and every tier's N-258 test builds the same call; the
 * resulting tx hex is pinned in `N258_MERGE_TX_HEX` below and in each tier.
 *
 * What this test proves: the merge tx is accepted by MockProvider's default
 * broadcast validation, which runs @bsv/sdk's `Spend` on EVERY input (both
 * contract inputs and the funding input are known outpoints) and enforces the
 * fee floor against the real broadcast bytes; and the bytes equal the pinned
 * cross-tier vector. (The narrowed N-227 guard — a plain `SmartContract` with
 * extra contract inputs is still refused — is pinned in
 * n227-zero-mutable-field-merge-refused.test.ts.)
 *
 * What this test does not prove: merges on a zero-mutable-field contract with
 * more than one public method (the stateless branch's OP_PUSH_TX uses method
 * index 0, a separate pre-existing question), `allPrevouts` auto-resolution on
 * this branch, or the `terminalOutputs` path, which ignores extra inputs.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { Transaction } from '@bsv/sdk';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import type { RunarArtifact } from 'runar-ir-schema';
import fs from 'fs';
import path from 'path';

const SIGNER_KEY = '0000000000000000000000000000000000000000000000000000000000000003';

function compileSource(source: string, fileName: string): RunarArtifact {
  const result = compile(source, { fileName });
  if (!result.artifact) {
    const errors = (result.diagnostics || [])
      .filter((d: { severity: string }) => d.severity === 'error')
      .map((d: { message: string }) => d.message);
    throw new Error(`Compile failed: ${errors.join('; ')}`);
  }
  return result.artifact;
}

describe('N-258 — zero-mutable-field StatefulSmartContract merge builds real per-input unlocks', () => {
  it('claim() with additionalContractInputs broadcasts a Spend-valid tx on every input', async () => {
    const source = fs.readFileSync(
      path.join(__dirname, '../../../../examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts'),
      'utf8',
    );
    const artifact = compileSource(source, 'AllReadonlyCleanstack.runar.ts');
    expect(artifact.parentClass).toBe('StatefulSmartContract');
    expect(artifact.stateFields ?? []).toEqual([]);

    const signer = new LocalSigner(SIGNER_KEY);
    const address = await signer.getAddress();
    const pubKey = await signer.getPublicKey();
    const lockingHex = new RunarContract(artifact, [pubKey]).getLockingScript();

    const primary = { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5000, script: lockingHex };
    const extra = { txid: 'cc'.repeat(32), outputIndex: 1, satoshis: 7000, script: lockingHex };
    const funding = { txid: 'bb'.repeat(32), outputIndex: 0, satoshis: 100_000, script: buildP2PKHScript(pubKey) };

    // Default MockProvider: Spend-validates every input, refuses unknown
    // inputs, enforces the fee floor. All three outpoints are registered.
    const provider = new MockProvider('testnet');
    provider.addUtxo(address, funding);
    provider.addContractUtxo(lockingHex, primary);
    provider.addContractUtxo(lockingHex + ':extra', extra);

    const contract = RunarContract.fromUtxo(artifact, primary);
    await contract.call('claim', [null, null], provider, signer, {
      additionalContractInputs: [extra],
    });

    const txHex = provider.getBroadcastedTxs()[0]!;
    const tx = Transaction.fromHex(txHex);
    expect(tx.inputs.length).toBe(3);
    expect(provider.getValidationStats().validated).toBe(3);
    expect(txHex).toBe(N258_MERGE_TX_HEX);
  });
});

const N258_MERGE_TX_HEX =
  '0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdea02473044022033b20ee497b244a5f44ea460cbeb66c867d72ee622cf6e8163651998b66da33d02200b7580e4c31b3bf66410bbd033e935bcf41449fcabfdf90275cc2a7df78f8911414d9f0201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fd000276aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac778813000000000000ffffffffe0fb8d8fe33024ae55861c19ec7c3056e7ba656aa6623274dc5d6140edcd3d370000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdea0247304402203b86795685f996d25ad0c7db76fb2b1d3ba6e1127332ba7806f9786e6ef03d0602201eca36661b0bb5e080c43fe881cae23d59194a557a76fdbca879995aaabc2314414d9f0201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fd000276aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac77581b000000000000ffffffffe0fb8d8fe33024ae55861c19ec7c3056e7ba656aa6623274dc5d6140edcd3d370000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006b483045022100fe183c7919d2e06724b2134fa072fa1d6a698eb1b6cc07dd42341eeff238c11f02200abfed215d06dcaae1226e0497cff4ef3834ea7043cdbb76af44104c630b7c25412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01ceb40100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000';
