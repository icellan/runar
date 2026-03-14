/**
 * Tests for InductiveProofManager and the end-to-end inductive contract flow.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { InductiveProofManager, PROOF_SIZE, ZERO_PROOF } from '../inductive-proof.js';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { compile } from 'runar-compiler';
import type { RunarArtifact } from 'runar-ir-schema';
import { Hash, Transaction } from '@bsv/sdk';

const PROJECT_ROOT = resolve(import.meta.dirname, '..', '..', '..', '..');

function compileContract(sourcePath: string): RunarArtifact {
  const absPath = resolve(PROJECT_ROOT, sourcePath);
  const source = readFileSync(absPath, 'utf-8');
  const fileName = absPath.split('/').pop()!;
  const result = compile(source, { fileName });
  if (!result.artifact) {
    throw new Error(`Compile failed: ${JSON.stringify(result.errors)}`);
  }
  return result.artifact;
}

const PRIV_KEY = '0000000000000000000000000000000000000000000000000000000000000001';
const ZERO_SENTINEL = '00'.repeat(36);
const TOKEN_ID = Buffer.from('TEST-TOKEN').toString('hex');

async function setupFundedProvider(satoshis: number) {
  const signer = new LocalSigner(PRIV_KEY);
  const address = await signer.getAddress();
  const pubKeyHex = await signer.getPublicKey();
  const provider = new MockProvider();
  provider.addUtxo(address, {
    txid: 'aa'.repeat(32),
    outputIndex: 0,
    satoshis,
    script: '76a914' + '00'.repeat(20) + '88ac',
  });
  return { provider, signer, address, pubKeyHex };
}

function setupRealTxidBroadcast(provider: MockProvider, signer: LocalSigner) {
  provider.broadcast = async (rawTxOrObj: any): Promise<string> => {
    const rawTx = typeof rawTxOrObj === 'string' ? rawTxOrObj : rawTxOrObj.toHex();
    const rawBytes = rawTx.match(/.{2}/g)!.map((b: string) => parseInt(b, 16));
    const hash1 = Hash.sha256(rawBytes);
    const hash2 = Hash.sha256(hash1);
    const txid = Array.from(hash2)
      .reverse()
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    const tx = Transaction.fromHex(rawTx);
    provider.addTransaction({
      txid,
      version: tx.version,
      inputs: tx.inputs.map((inp) => ({
        txid: inp.sourceTXID!,
        outputIndex: inp.sourceOutputIndex,
        script: inp.unlockingScript?.toHex() ?? '',
        sequence: inp.sequence,
      })),
      outputs: tx.outputs.map((out) => ({
        satoshis: out.satoshis ?? 0,
        script: out.lockingScript.toHex(),
      })),
      locktime: tx.lockTime,
      raw: rawTx,
    });

    const addr = await signer.getAddress();
    for (let i = 0; i < tx.outputs.length; i++) {
      provider.addUtxo(addr, {
        txid,
        outputIndex: i,
        satoshis: tx.outputs[i]!.satoshis ?? 0,
        script: tx.outputs[i]!.lockingScript.toHex(),
      });
    }
    return txid;
  };
}

describe('InductiveProofManager', () => {
  it('initializes with zero proof by default', () => {
    const pm = new InductiveProofManager();
    expect(pm.proof).toBe(ZERO_PROOF);
    expect(pm.proof.length).toBe(PROOF_SIZE * 2);
  });

  it('initializes with a custom proof', () => {
    const customProof = 'ab'.repeat(PROOF_SIZE);
    const pm = new InductiveProofManager(customProof);
    expect(pm.proof).toBe(customProof);
  });

  it('rejects proofs of wrong size', () => {
    const pm = new InductiveProofManager();
    expect(() => { pm.proof = 'ab'.repeat(10); }).toThrow('256 bytes');
  });

  it('generates zero proof without a generator', async () => {
    const pm = new InductiveProofManager();
    const proof = await pm.generateProof('aa'.repeat(36), 'bb'.repeat(32), {});
    expect(proof).toBe(ZERO_PROOF);
    expect(pm.hasGenerator).toBe(false);
  });

  it('uses custom generator when provided', async () => {
    const customProof = 'cc'.repeat(PROOF_SIZE);
    const generator = async () => customProof;
    const pm = new InductiveProofManager(undefined, generator);

    expect(pm.hasGenerator).toBe(true);
    const proof = await pm.generateProof('aa'.repeat(36), 'bb'.repeat(32), {});
    expect(proof).toBe(customProof);
    expect(pm.proof).toBe(customProof);
  });

  it('generator receives correct arguments', async () => {
    const genesis = 'dd'.repeat(36);
    const txid = 'ee'.repeat(32);
    const state = { count: 42n };

    let receivedArgs: unknown[] = [];
    const generator = async (g: string, prev: string, t: string, s: Record<string, unknown>) => {
      receivedArgs = [g, prev, t, s];
      return 'ff'.repeat(PROOF_SIZE);
    };

    const pm = new InductiveProofManager(undefined, generator);
    await pm.generateProof(genesis, txid, state);

    expect(receivedArgs[0]).toBe(genesis);
    expect(receivedArgs[1]).toBe(ZERO_PROOF); // previous proof was zero
    expect(receivedArgs[2]).toBe(txid);
    expect(receivedArgs[3]).toEqual(state);
  });

  it('verifyProof returns true without verifier (stub mode)', () => {
    const pm = new InductiveProofManager();
    expect(pm.verifyProof(ZERO_PROOF, 'aa'.repeat(36))).toBe(true);
    expect(pm.hasVerifier).toBe(false);
  });

  it('verifyProof delegates to custom verifier', () => {
    const verifier = (proof: string, genesis: string) => proof !== ZERO_PROOF;
    const pm = new InductiveProofManager(undefined, undefined, verifier);
    expect(pm.hasVerifier).toBe(true);
    expect(pm.verifyProof(ZERO_PROOF, 'aa'.repeat(36))).toBe(false);
    expect(pm.verifyProof('ff'.repeat(PROOF_SIZE), 'aa'.repeat(36))).toBe(true);
  });
});

describe('InductiveSmartContract + ProofManager integration', () => {
  it('contract.setProofManager writes proof to _proof state on call', async () => {
    const artifact = compileContract(
      'examples/ts/inductive-token/InductiveToken.runar.ts',
    );
    const { provider, signer, pubKeyHex } = await setupFundedProvider(2_000_000);
    setupRealTxidBroadcast(provider, signer);

    const contract = new RunarContract(artifact, [pubKeyHex, 1000n, TOKEN_ID, ZERO_SENTINEL, ZERO_PROOF]);
    contract.connect(provider, signer);

    // Attach proof manager with a custom proof
    const customProof = 'ab'.repeat(PROOF_SIZE);
    const pm = new InductiveProofManager(customProof);
    contract.setProofManager(pm);

    // Deploy
    const { txid: deployTxid } = await contract.deploy({ satoshis: 100_000 });
    expect(deployTxid).toBeTruthy();

    // The initial _proof should be the zero proof (from state field initializer)
    expect(contract.state._proof).toBe(ZERO_PROOF);

    // Call transfer — this should update _proof from the proof manager
    // transfer(sig, to, amount, outputSatoshis) — sig=null is auto-signed
    await contract.call('transfer', [null, pubKeyHex, 500n, 100_000n], {
      outputs: [
        { satoshis: 100_000, state: { owner: pubKeyHex, balance: 500n } },
        { satoshis: 100_000, state: { owner: pubKeyHex, balance: 500n } },
      ],
    });

    // After the call, _proof should have been updated to the manager's proof
    expect(contract.state._proof).toBe(customProof);
  });

  it('deploy → 3 generations with proof tracking', async () => {
    const artifact = compileContract(
      'examples/ts/inductive-token/InductiveToken.runar.ts',
    );
    const { provider, signer, pubKeyHex } = await setupFundedProvider(5_000_000);
    setupRealTxidBroadcast(provider, signer);

    const proofHistory: string[] = [];
    const generator = async (
      genesis: string,
      prevProof: string,
      parentTxId: string,
    ) => {
      // Each generation produces a deterministic proof based on genesis + generation number
      const gen = proofHistory.length;
      const proof = (gen.toString(16).padStart(2, '0')).repeat(PROOF_SIZE);
      proofHistory.push(proof);
      return proof;
    };

    const pm = new InductiveProofManager(undefined, generator);
    const contract = new RunarContract(artifact, [pubKeyHex, 1000n, TOKEN_ID, ZERO_SENTINEL, ZERO_PROOF]);
    contract.connect(provider, signer);
    contract.setProofManager(pm);

    // Deploy (generation 0)
    const { txid: deployTxid } = await contract.deploy({ satoshis: 1_000_000 });
    expect(deployTxid).toBeTruthy();

    expect(contract.state._genesisOutpoint).toBe(ZERO_SENTINEL);

    // Generation 1: first spend sets genesis
    // transfer(sig, to, amount, outputSatoshis) — sig=null is auto-signed
    const genesis1 = contract.state._genesisOutpoint;
    await pm.generateProof(genesis1 as string, deployTxid, { supply: 1000n });
    await contract.call('transfer', [null, pubKeyHex, 100n, 1_000_000n], {
      outputs: [
        { satoshis: 1_000_000, state: { owner: pubKeyHex, balance: 100n } },
        { satoshis: 1_000_000, state: { owner: pubKeyHex, balance: 900n } },
      ],
    });

    // Genesis should now be set (non-zero)
    expect(contract.state._genesisOutpoint).not.toBe(ZERO_SENTINEL);
    // Proof should be from the generator
    expect(contract.state._proof).toBe(proofHistory[0]);

    // Generation 2 (balance is now 900n from continuation output)
    const genesis2 = contract.state._genesisOutpoint;
    await pm.generateProof(genesis2 as string, 'bb'.repeat(32), { supply: 900n });
    await contract.call('transfer', [null, pubKeyHex, 200n, 1_000_000n], {
      outputs: [
        { satoshis: 1_000_000, state: { owner: pubKeyHex, balance: 200n } },
        { satoshis: 1_000_000, state: { owner: pubKeyHex, balance: 700n } },
      ],
    });

    // Genesis should be unchanged (frozen after first spend)
    expect(contract.state._genesisOutpoint).toBe(genesis2);
    expect(contract.state._proof).toBe(proofHistory[1]);

    // Generation 3 (balance is now 700n)
    const genesis3 = contract.state._genesisOutpoint;
    await pm.generateProof(genesis3 as string, 'cc'.repeat(32), { supply: 700n });
    await contract.call('transfer', [null, pubKeyHex, 50n, 1_000_000n], {
      outputs: [
        { satoshis: 1_000_000, state: { owner: pubKeyHex, balance: 50n } },
        { satoshis: 1_000_000, state: { owner: pubKeyHex, balance: 650n } },
      ],
    });

    expect(contract.state._genesisOutpoint).toBe(genesis2); // still the same genesis
    expect(contract.state._proof).toBe(proofHistory[2]);
    expect(proofHistory).toHaveLength(3);
  });

  it('off-chain verifier rejects forged proofs', async () => {
    // A verifier that only accepts proofs starting with 'ab'
    const verifier = (proof: string, genesis: string) => proof.startsWith('ab');
    const validProof = 'ab'.repeat(PROOF_SIZE);
    const forgedProof = 'ff'.repeat(PROOF_SIZE);

    const pm = new InductiveProofManager(undefined, undefined, verifier);

    // Valid proof passes off-chain verification
    expect(pm.verifyProof(validProof, 'aa'.repeat(36))).toBe(true);

    // Forged proof is caught before it ever reaches the chain
    expect(pm.verifyProof(forgedProof, 'aa'.repeat(36))).toBe(false);

    // Zero proof (no generator) also fails custom verifier
    expect(pm.verifyProof(ZERO_PROOF, 'aa'.repeat(36))).toBe(false);
  });

  it('generator + verifier pipeline catches invalid generation', async () => {
    // Simulate a buggy generator that produces an invalid proof
    const buggyGenerator = async () => 'ff'.repeat(PROOF_SIZE);
    const verifier = (proof: string) => proof.startsWith('ab');

    const pm = new InductiveProofManager(undefined, buggyGenerator, verifier);

    // Generator produces a proof
    const proof = await pm.generateProof('aa'.repeat(36), 'bb'.repeat(32), {});
    expect(proof).toBe('ff'.repeat(PROOF_SIZE));

    // But off-chain verification catches it before broadcast
    expect(pm.verifyProof(proof, 'aa'.repeat(36))).toBe(false);
  });
});
