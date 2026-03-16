/**
 * MathDemo integration test — stateful contract exercising built-in math functions.
 * All state transitions are auto-computed from ANF IR (no manual newState).
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('MathDemo', () => {
  it('should deploy with initial value 1000', async () => {
    const artifact = compileContract('examples/ts/math-demo/MathDemo.runar.ts');
    const contract = new RunarContract(artifact, [1000n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 5000 });
    expect(deployTxid).toBeTruthy();
  });

  it('should divideBy: 1000 / 10 = 100', async () => {
    const artifact = compileContract('examples/ts/math-demo/MathDemo.runar.ts');
    const contract = new RunarContract(artifact, [1000n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    const { txid: callTxid } = await contract.call('divideBy', [10n], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(contract.state.value).toBe(100n);
  });

  it('should chain divideBy then clampValue: 1000 -> 100 -> clamp(0,50) = 50', async () => {
    const artifact = compileContract('examples/ts/math-demo/MathDemo.runar.ts');
    const contract = new RunarContract(artifact, [1000n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    await contract.call('divideBy', [10n], provider, signer);
    expect(contract.state.value).toBe(100n);

    await contract.call('clampValue', [0n, 50n], provider, signer);
    expect(contract.state.value).toBe(50n);
  });

  it('should squareRoot: sqrt(49) = 7', async () => {
    const artifact = compileContract('examples/ts/math-demo/MathDemo.runar.ts');
    const contract = new RunarContract(artifact, [49n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    const { txid: callTxid } = await contract.call('squareRoot', [], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(contract.state.value).toBe(7n);
  });

  it('should exponentiate: 2^10 = 1024', async () => {
    const artifact = compileContract('examples/ts/math-demo/MathDemo.runar.ts');
    const contract = new RunarContract(artifact, [2n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    const { txid: callTxid } = await contract.call('exponentiate', [10n], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(contract.state.value).toBe(1024n);
  });

  it('should reduceGcd: gcd(100, 75) = 25', async () => {
    const artifact = compileContract('examples/ts/math-demo/MathDemo.runar.ts');
    const contract = new RunarContract(artifact, [100n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    const { txid: callTxid } = await contract.call('reduceGcd', [75n], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(contract.state.value).toBe(25n);
  });

  it('should computeLog2: log2(1024) = 10', async () => {
    const artifact = compileContract('examples/ts/math-demo/MathDemo.runar.ts');
    const contract = new RunarContract(artifact, [1024n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    const { txid: callTxid } = await contract.call('computeLog2', [], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(contract.state.value).toBe(10n);
  });

  it('should scaleByRatio: 100 * 3 / 4 = 75', async () => {
    const artifact = compileContract('examples/ts/math-demo/MathDemo.runar.ts');
    const contract = new RunarContract(artifact, [100n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    const { txid: callTxid } = await contract.call('scaleByRatio', [3n, 4n], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(contract.state.value).toBe(75n);
  });

  it('should normalize: sign(-42) = -1', async () => {
    const artifact = compileContract('examples/ts/math-demo/MathDemo.runar.ts');
    const contract = new RunarContract(artifact, [-42n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    const { txid: callTxid } = await contract.call('normalize', [], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(contract.state.value).toBe(-1n);
  });

  it('should chain operations: 1000 -> 100 -> 10 -> scaleByRatio(5,1) = 50', async () => {
    const artifact = compileContract('examples/ts/math-demo/MathDemo.runar.ts');
    const contract = new RunarContract(artifact, [1000n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    await contract.call('divideBy', [10n], provider, signer);
    expect(contract.state.value).toBe(100n);

    await contract.call('squareRoot', [], provider, signer);
    expect(contract.state.value).toBe(10n);

    await contract.call('scaleByRatio', [5n, 1n], provider, signer);
    expect(contract.state.value).toBe(50n);
  });

  it('should reject divideBy zero', async () => {
    const artifact = compileContract('examples/ts/math-demo/MathDemo.runar.ts');
    const contract = new RunarContract(artifact, [1000n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    // divideBy(0) → safediv returns 0 on-chain, but assert(value > 0) may fail
    await expect(
      contract.call('divideBy', [0n], provider, signer),
    ).rejects.toThrow();
  });

  it('should reject wrong state after divideBy (manual override)', async () => {
    const artifact = compileContract('examples/ts/math-demo/MathDemo.runar.ts');
    const contract = new RunarContract(artifact, [1000n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    // Claim value=999 instead of 100 — hashOutputs mismatch
    await expect(
      contract.call('divideBy', [10n], provider, signer, {
        newState: { value: 999n },
      }),
    ).rejects.toThrow();
  });
});
