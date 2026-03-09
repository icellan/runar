import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import type { RunarArtifact } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeArtifact(
  overrides: Partial<RunarArtifact> & Pick<RunarArtifact, 'script' | 'abi'>,
): RunarArtifact {
  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'Test',
    asm: '',
    buildTimestamp: '2026-03-02T00:00:00.000Z',
    ...overrides,
  };
}

const PRIV_KEY =
  '0000000000000000000000000000000000000000000000000000000000000001';

async function setupFundedProvider(
  satoshis: number,
): Promise<{ provider: MockProvider; signer: LocalSigner; address: string }> {
  const signer = new LocalSigner(PRIV_KEY);
  const address = await signer.getAddress();
  const provider = new MockProvider();
  provider.addUtxo(address, {
    txid: 'aa'.repeat(32),
    outputIndex: 0,
    satoshis,
    script: '76a914' + '00'.repeat(20) + '88ac',
  });
  return { provider, signer, address };
}

// ---------------------------------------------------------------------------
// Terminal method call tests
// ---------------------------------------------------------------------------

describe('RunarContract terminal call', () => {
  it('terminal call broadcasts a transaction with exact outputs and no change', async () => {
    const { provider, signer } = await setupFundedProvider(100_000);
    const artifact = makeArtifact({
      script: '51', // OP_TRUE
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'cancel', params: [], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    await contract.deploy(provider, signer, { satoshis: 50_000 });

    // Now call cancel as a terminal method
    const payoutScript = '76a914' + 'bb'.repeat(20) + '88ac';
    const result = await contract.call('cancel', [], provider, signer, {
      terminalOutputs: [
        { scriptHex: payoutScript, satoshis: 49_000 },
      ],
    });

    expect(result.txid).toBeDefined();
    expect(result.txid.length).toBe(64);

    // Contract should be fully spent
    expect((contract as unknown as { currentUtxo: unknown }).currentUtxo).toBeNull();
  });

  it('terminal call sets currentUtxo to null', async () => {
    const { provider, signer } = await setupFundedProvider(100_000);
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'spend', params: [], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    await contract.deploy(provider, signer, { satoshis: 10_000 });

    await contract.call('spend', [], provider, signer, {
      terminalOutputs: [
        { scriptHex: '76a914' + 'cc'.repeat(20) + '88ac', satoshis: 9_000 },
      ],
    });

    // Subsequent call should throw "not deployed"
    await expect(
      contract.call('spend', [], provider, signer),
    ).rejects.toThrow('not deployed');
  });

  it('terminal call with multiple outputs', async () => {
    const { provider, signer } = await setupFundedProvider(100_000);
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'settle', params: [], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    await contract.deploy(provider, signer, { satoshis: 20_000 });

    const result = await contract.call('settle', [], provider, signer, {
      terminalOutputs: [
        { scriptHex: '76a914' + 'aa'.repeat(20) + '88ac', satoshis: 10_000 },
        { scriptHex: '76a914' + 'bb'.repeat(20) + '88ac', satoshis: 9_000 },
      ],
    });

    expect(result.txid).toBeDefined();
    expect((contract as unknown as { currentUtxo: unknown }).currentUtxo).toBeNull();
  });

  it('terminal call broadcasted tx has correct structure', async () => {
    const { provider, signer } = await setupFundedProvider(100_000);
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'cancel', params: [], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    await contract.deploy(provider, signer, { satoshis: 50_000 });

    const payoutScript = '76a914' + 'dd'.repeat(20) + '88ac';
    await contract.call('cancel', [], provider, signer, {
      terminalOutputs: [
        { scriptHex: payoutScript, satoshis: 49_000 },
      ],
    });

    const broadcastedTxs = provider.getBroadcastedTxs();
    // First broadcast was deploy, second is the terminal call
    expect(broadcastedTxs.length).toBe(2);

    const termTxHex = broadcastedTxs[1]!;
    // Parse the raw tx to verify structure:
    // version (8 hex) + input count varint
    expect(termTxHex.slice(0, 8)).toBe('01000000'); // version 1 LE

    // Input count should be 1 (no funding inputs)
    const inputCountByte = termTxHex.slice(8, 10);
    expect(inputCountByte).toBe('01');
  });
});
