/**
 * ConvergenceProof integration test — stateless contract using EC point operations.
 *
 * The contract verifies that R_A - R_B = deltaO * G on secp256k1, proving two
 * OPRF submissions share the same underlying token without revealing it.
 *
 * We verify compilation, deployment, and spending (valid + invalid deltaO).
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { ecMulGen, encodePoint, EC_N } from './helpers/crypto.js';
import { createProvider } from './helpers/node.js';

/**
 * Generate test data for ConvergenceProof:
 * - Pick random scalars a, b
 * - R_A = a*G, R_B = b*G
 * - deltaO = (a - b) mod N
 */
function generateTestData() {
  // Use deterministic small values for reproducibility
  const a = 12345n;
  const b = 6789n;
  const deltaO = ((a - b) % EC_N + EC_N) % EC_N;

  const [rAx, rAy] = ecMulGen(a);
  const [rBx, rBy] = ecMulGen(b);

  return {
    rA: encodePoint(rAx, rAy),
    rB: encodePoint(rBx, rBy),
    deltaO,
    // Wrong delta for rejection test
    wrongDelta: ((a - b + 1n) % EC_N + EC_N) % EC_N,
  };
}

describe('ConvergenceProof', () => {
  it('should compile successfully', () => {
    const artifact = compileContract('examples/ts/convergence-proof/ConvergenceProof.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('ConvergenceProof');
  });

  it('should deploy with valid EC points', async () => {
    const artifact = compileContract('examples/ts/convergence-proof/ConvergenceProof.runar.ts');
    const { rA, rB } = generateTestData();

    const contract = new RunarContract(artifact, [rA, rB]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
    expect(deployTxid.length).toBe(64);
  });

  it('should spend with valid deltaO via proveConvergence', async () => {
    const artifact = compileContract('examples/ts/convergence-proof/ConvergenceProof.runar.ts');
    const { rA, rB, deltaO } = generateTestData();

    const contract = new RunarContract(artifact, [rA, rB]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    const { txid: spendTxid } = await contract.call(
      'proveConvergence',
      [deltaO],
      provider,
      signer,
    );
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  it('should reject invalid deltaO', async () => {
    const artifact = compileContract('examples/ts/convergence-proof/ConvergenceProof.runar.ts');
    const { rA, rB, wrongDelta } = generateTestData();

    const contract = new RunarContract(artifact, [rA, rB]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    await expect(
      contract.call('proveConvergence', [wrongDelta], provider, signer),
    ).rejects.toThrow();
  });
});
