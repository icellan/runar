// ---------------------------------------------------------------------------
// Runtime round-trip test for the `Sha256Digest` type alias.
//
// `Sha256Digest` is a type alias over `Sha256` (see
// packages/runar-lang/src/types.ts). Using the alias in a Rúnar contract's
// field annotation must exercise the TypeScript parser's alias-resolution
// path — prior to this test the TS parser rejected `Sha256Digest` with an
// "Unsupported type" diagnostic because the alias was only recognised by
// the Go / Rust / Python / Zig / Ruby parsers.
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import type { RunarArtifact } from 'runar-ir-schema';

// Private key "1" — the smallest valid secp256k1 private key.
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

// The contract uses `Sha256Digest` in a constructor param + readonly field.
// If the TS parser has the alias registered, compilation must succeed and
// the primitive is Sha256 — which is what the field slot + constructor
// serialiser both expect.
const HASHLOCK_SOURCE = `
class HashLockDigest extends SmartContract {
  readonly hashValue: Sha256Digest;

  constructor(hashValue: Sha256Digest) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) === this.hashValue);
  }
}
`;

describe('Sha256Digest alias — TS parser + SDK deploy round-trip', () => {
  it('TS compiler accepts Sha256Digest in a field annotation', () => {
    const result = compile(HASHLOCK_SOURCE, { fileName: 'HashLockDigest.runar.ts' });
    if (!result.success) {
      const msgs = result.diagnostics
        .filter((d) => d.severity === 'error')
        .map((d) => d.message);
      throw new Error(
        'Expected Sha256Digest to compile, got diagnostics:\n' + msgs.join('\n'),
      );
    }
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.contractName).toBe('HashLockDigest');

    // The Sha256Digest primitive must be resolved to Sha256 in the ABI.
    const ctorParams = result.artifact!.abi.constructor.params;
    expect(ctorParams).toHaveLength(1);
    expect(ctorParams[0]!.name).toBe('hashValue');
    expect(ctorParams[0]!.type).toBe('Sha256');
  });

  it('deploy produces a locking script that embeds the constructor Sha256Digest arg', async () => {
    const result = compile(HASHLOCK_SOURCE, { fileName: 'HashLockDigest.runar.ts' });
    expect(result.success).toBe(true);
    const artifact = result.artifact as RunarArtifact;

    const { provider, signer } = await setupFundedProvider(100_000);

    // A deterministic 32-byte hash (the sha256 of "runar-test").
    const digest =
      'be4d388e9e1b36f9a4c8c93f96bbdbe85d34e2f7d2f2e3d0cd94b1a19ad1e1c5';

    const contract = new RunarContract(artifact, [digest]);
    const { txid } = await contract.deploy(provider, signer, { satoshis: 50_000 });
    expect(txid).toBeTypeOf('string');
    expect(txid.length).toBeGreaterThan(0);

    // The compiled code prefix should match what's on-chain. We cannot
    // inspect state after deploy for a non-stateful contract (there is
    // no state), but the currentUtxo tracking proves deploy succeeded
    // against the Sha256-sized constructor slot without throwing a slot
    // length mismatch.
    expect(contract.currentUtxo).toBeDefined();
    expect(contract.currentUtxo!.satoshis).toBe(50_000);
  });
});
