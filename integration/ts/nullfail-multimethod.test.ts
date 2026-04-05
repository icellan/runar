/**
 * NULLFAIL reproduction test — multi-method stateful contract where some
 * methods use checkSig and others don't.
 *
 * Bug: After several UTXO chain spends of the non-checkSig method,
 * the transaction is rejected with:
 *   "Signature must be zero for failed CHECK(MULTI)SIG operation"
 *
 * This is the BSV NULLFAIL rule (BIP 146): when OP_CHECKSIG evaluates
 * to false (non-taken branch), the signature argument on the stack must
 * be an empty byte string, not a non-empty placeholder.
 */

import { describe, it, expect } from 'vitest';
import { compileSource } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

// A minimal multi-method stateful contract:
// - Method 0 (advanceState): no checkSig, just updates state
// - Method 1 (freeze): uses checkSig
const MULTI_METHOD_SOURCE = `
import {
  StatefulSmartContract, assert, checkSig,
} from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class MultiMethodContract extends StatefulSmartContract {
  stateRoot: ByteString;
  blockNumber: bigint;
  frozen: bigint;
  readonly governanceKey: PubKey;

  constructor(stateRoot: ByteString, blockNumber: bigint, frozen: bigint, governanceKey: PubKey) {
    super(stateRoot, blockNumber, frozen, governanceKey);
    this.stateRoot = stateRoot;
    this.blockNumber = blockNumber;
    this.frozen = frozen;
    this.governanceKey = governanceKey;
  }

  // Method 0: no checkSig — authorized by proof data
  public advanceState(newStateRoot: ByteString, newBlockNumber: bigint) {
    assert(this.frozen === 0n);
    assert(newBlockNumber > this.blockNumber);
    this.stateRoot = newStateRoot;
    this.blockNumber = newBlockNumber;
  }

  // Method 1: uses checkSig — governance action
  public freeze(sig: Sig) {
    assert(checkSig(sig, this.governanceKey));
    this.frozen = 1n;
  }
}
`;

// 4-method contract matching the bug report's pattern more closely:
// - Method 0 (advanceState): no checkSig, large data params
// - Method 1 (freeze): checkSig
// - Method 2 (unfreeze): checkSig
// - Method 3 (upgrade): checkSig
const FOUR_METHOD_SOURCE = `
import {
  StatefulSmartContract, assert, checkSig, hash256, cat,
} from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class RollupContract extends StatefulSmartContract {
  stateRoot: ByteString;
  blockNumber: bigint;
  frozen: bigint;
  readonly governanceKey: PubKey;
  readonly verifyingKeyHash: ByteString;

  constructor(stateRoot: ByteString, blockNumber: bigint, frozen: bigint,
              governanceKey: PubKey, verifyingKeyHash: ByteString) {
    super(stateRoot, blockNumber, frozen, governanceKey, verifyingKeyHash);
    this.stateRoot = stateRoot;
    this.blockNumber = blockNumber;
    this.frozen = frozen;
    this.governanceKey = governanceKey;
    this.verifyingKeyHash = verifyingKeyHash;
  }

  public advanceState(newStateRoot: ByteString, newBlockNumber: bigint,
                      batchData: ByteString, proofBlob: ByteString) {
    assert(this.frozen === 0n);
    assert(newBlockNumber > this.blockNumber);
    const expectedHash = hash256(cat(this.stateRoot, newStateRoot));
    assert(hash256(batchData) === expectedHash);
    this.stateRoot = newStateRoot;
    this.blockNumber = newBlockNumber;
  }

  public freeze(sig: Sig) {
    assert(checkSig(sig, this.governanceKey));
    this.frozen = 1n;
  }

  public unfreeze(sig: Sig) {
    assert(checkSig(sig, this.governanceKey));
    assert(this.frozen === 1n);
    this.frozen = 0n;
  }

  public upgrade(sig: Sig, newVerifyingKeyHash: ByteString) {
    assert(checkSig(sig, this.governanceKey));
  }
}
`;

describe('NULLFAIL multi-method reproduction', () => {
  it('should compile the multi-method contract', () => {
    const artifact = compileSource(MULTI_METHOD_SOURCE, 'MultiMethodContract.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('MultiMethodContract');
  });

  it('should chain 10 advanceState calls without NULLFAIL', async () => {
    const artifact = compileSource(MULTI_METHOD_SOURCE, 'MultiMethodContract.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    const initialRoot = 'aa'.repeat(32);
    const contract = new RunarContract(artifact, [initialRoot, 0n, 0n, pubKeyHex]);

    // Deploy with enough satoshis for many chained calls
    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 1000000 });
    expect(deployTxid).toBeTruthy();

    // Chain 10 advanceState calls (method 0, no checkSig)
    // The bug report says failure occurs around call 7
    for (let i = 1; i <= 10; i++) {
      const newRoot = (i.toString(16).padStart(2, '0')).repeat(32);
      const { txid } = await contract.call(
        'advanceState',
        [newRoot, BigInt(i)],
        provider,
        signer,
      );
      expect(txid).toBeTruthy();
      expect(txid.length).toBe(64);
      expect(contract.state.blockNumber).toBe(BigInt(i));
    }
  });

  it('should call freeze (checkSig method) after advanceState', async () => {
    const artifact = compileSource(MULTI_METHOD_SOURCE, 'MultiMethodContract.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    const initialRoot = 'aa'.repeat(32);
    const contract = new RunarContract(artifact, [initialRoot, 0n, 0n, pubKeyHex]);

    await contract.deploy(provider, signer, { satoshis: 100000 });

    // First advance state (method 0)
    const newRoot = 'bb'.repeat(32);
    await contract.call('advanceState', [newRoot, 1n], provider, signer);
    expect(contract.state.blockNumber).toBe(1n);

    // Then freeze (method 1, with checkSig)
    const { txid } = await contract.call('freeze', [null], provider, signer);
    expect(txid).toBeTruthy();
    expect(contract.state.frozen).toBe(1n);
  });

  // === 4-method contract tests (closer to bug report) ===

  it('4-method: should chain 10 advanceState calls with large data', async () => {
    const artifact = compileSource(FOUR_METHOD_SOURCE, 'RollupContract.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    const vkHash = 'cc'.repeat(32);
    const initialRoot = 'aa'.repeat(32);
    const contract = new RunarContract(artifact, [initialRoot, 0n, 0n, pubKeyHex, vkHash]);

    await contract.deploy(provider, signer, { satoshis: 5000000 });

    for (let i = 1; i <= 10; i++) {
      const prevRoot = contract.state.stateRoot as string;
      const newRoot = (i.toString(16).padStart(2, '0')).repeat(32);
      // batchData such that hash256(batchData) === hash256(cat(prevRoot, newRoot))
      const batchData = prevRoot + newRoot; // cat of old+new roots
      // proofBlob: large data to simulate real proof (~10KB)
      const proofBlob = 'ff'.repeat(5000);

      const { txid } = await contract.call(
        'advanceState',
        [newRoot, BigInt(i), batchData, proofBlob],
        provider,
        signer,
      );
      expect(txid).toBeTruthy();
      expect(contract.state.blockNumber).toBe(BigInt(i));
    }
  });

  // Known bug: second checkSig method call fails with OP_NUMEQUALVERIFY
  // See RUNAR-SDK-BUG.md — freeze works but unfreeze after freeze fails
  it.skip('4-method: freeze then unfreeze (checkSig methods)', async () => {
    const artifact = compileSource(FOUR_METHOD_SOURCE, 'RollupContract.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    const vkHash = 'cc'.repeat(32);
    const initialRoot = 'aa'.repeat(32);
    const contract = new RunarContract(artifact, [initialRoot, 0n, 0n, pubKeyHex, vkHash]);

    await contract.deploy(provider, signer, { satoshis: 100000 });

    // Freeze
    await contract.call('freeze', [null], provider, signer);
    expect(contract.state.frozen).toBe(1n);

    // Unfreeze
    await contract.call('unfreeze', [null], provider, signer);
    expect(contract.state.frozen).toBe(0n);
  });

  // Known bug: same as above — unfreeze after freeze fails
  it.skip('4-method: advanceState then freeze then unfreeze then advanceState', async () => {
    const artifact = compileSource(FOUR_METHOD_SOURCE, 'RollupContract.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    const vkHash = 'cc'.repeat(32);
    const initialRoot = 'aa'.repeat(32);
    const contract = new RunarContract(artifact, [initialRoot, 0n, 0n, pubKeyHex, vkHash]);

    await contract.deploy(provider, signer, { satoshis: 500000 });

    // Advance 1
    const newRoot1 = 'bb'.repeat(32);
    const batchData1 = initialRoot + newRoot1;
    await contract.call('advanceState', [newRoot1, 1n, batchData1, 'ff'.repeat(100)], provider, signer);
    expect(contract.state.blockNumber).toBe(1n);

    // Freeze
    await contract.call('freeze', [null], provider, signer);
    expect(contract.state.frozen).toBe(1n);

    // Unfreeze
    await contract.call('unfreeze', [null], provider, signer);
    expect(contract.state.frozen).toBe(0n);

    // Advance 2 (after freeze/unfreeze cycle)
    const newRoot2 = 'dd'.repeat(32);
    const batchData2 = newRoot1 + newRoot2;
    await contract.call('advanceState', [newRoot2, 2n, batchData2, 'ff'.repeat(100)], provider, signer);
    expect(contract.state.blockNumber).toBe(2n);
  });

  it('should reject advanceState when frozen', async () => {
    const artifact = compileSource(MULTI_METHOD_SOURCE, 'MultiMethodContract.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    const initialRoot = 'aa'.repeat(32);
    // Deploy with frozen=1
    const contract = new RunarContract(artifact, [initialRoot, 0n, 1n, pubKeyHex]);

    await contract.deploy(provider, signer, { satoshis: 100000 });

    // advanceState should fail because frozen=1
    const newRoot = 'bb'.repeat(32);
    await expect(
      contract.call('advanceState', [newRoot, 1n], provider, signer),
    ).rejects.toThrow();
  });
});
