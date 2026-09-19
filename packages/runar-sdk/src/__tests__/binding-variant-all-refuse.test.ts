/**
 * `@bindingVariant all` is opt-in and unspendable at nVersion = 1. The SDK
 * builds version-1 transactions and must refuse `prepareCall` for that method
 * rather than bumping `tx.version` to make the compact blob work.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import type { RunarArtifact } from 'runar-ir-schema';

const SIGNER_KEY = '0000000000000000000000000000000000000000000000000000000000000008';

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

const SRC = `
  class AllBump extends StatefulSmartContract {
    n: bigint;
    constructor(n: bigint) { super(n); this.n = n; }
    /** @bindingVariant all */
    public bump(): void { this.addOutput(1000n, this.n); }
  }
`;

describe('SDK refuses @bindingVariant all without bumping tx.version', () => {
  it('prepareCall throws and the artifact still carries bindingVariant all', async () => {
    const artifact = compileSource(SRC, 'AllBump.runar.ts');
    expect(artifact.abi.methods.find((m) => m.name === 'bump')!.bindingVariant).toBe('all');

    const provider = new MockProvider('testnet');
    const signer = new LocalSigner(SIGNER_KEY);
    const address = await signer.getAddress();
    provider.addUtxo(address, {
      txid: SIGNER_KEY.slice(0, 64),
      outputIndex: 0,
      satoshis: 500_000,
      script: buildP2PKHScript(await signer.getPublicKey()),
    });
    const contract = new RunarContract(artifact, [0n]);
    contract.connect(provider, signer);
    await contract.deploy(provider, signer, {});

    await expect(contract.prepareCall('bump', [])).rejects.toThrow(/bindingVariant all/);
  });
});
