/**
 * Baby Bear field arithmetic integration tests — inline contracts testing
 * bbFieldAdd/Sub/Mul/Inv on a real regtest node.
 *
 * Each test compiles a minimal stateless contract, deploys on regtest, and
 * spends via contract.call(). The compiled script contains inlined modular
 * arithmetic opcodes validated by a real BSV node.
 *
 * Tests include:
 *   - Happy path: add, sub, mul, inv with known values
 *   - Wrap-around: field boundary behavior
 *   - Algebraic identity: a * inv(a) = 1
 *   - Unhappy path: wrong expected values rejected on-chain
 */

import { describe, it, expect } from 'vitest';
import { compileSource } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

const BB_P = 2013265921n;

describe('Baby Bear Field Arithmetic', () => {
  // ---- bbFieldAdd ----

  it('bbFieldAdd: (3 + 7) mod p = 10', async () => {
    const source = `
import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

class BBAddTest extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldAdd(a, b) === this.expected);
  }
}
`;
    const artifact = compileSource(source, 'BBAddTest.runar.ts');
    const contract = new RunarContract(artifact, [10n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [3n, 7n], provider, signer);
    expect(txid).toBeTruthy();
    expect(txid.length).toBe(64);
  });

  it('bbFieldAdd: wrap-around (p-1) + 1 = 0', async () => {
    const source = `
import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

class BBAddWrap extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldAdd(a, b) === this.expected);
  }
}
`;
    const artifact = compileSource(source, 'BBAddWrap.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [BB_P - 1n, 1n], provider, signer);
    expect(txid).toBeTruthy();
  });

  // ---- bbFieldSub ----

  it('bbFieldSub: (10 - 3) mod p = 7', async () => {
    const source = `
import { SmartContract, assert, bbFieldSub } from 'runar-lang';

class BBSubTest extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldSub(a, b) === this.expected);
  }
}
`;
    const artifact = compileSource(source, 'BBSubTest.runar.ts');
    const contract = new RunarContract(artifact, [7n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [10n, 3n], provider, signer);
    expect(txid).toBeTruthy();
  });

  it('bbFieldSub: negative wrap (0 - 1) mod p = p-1', async () => {
    const source = `
import { SmartContract, assert, bbFieldSub } from 'runar-lang';

class BBSubNeg extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldSub(a, b) === this.expected);
  }
}
`;
    const artifact = compileSource(source, 'BBSubNeg.runar.ts');
    const contract = new RunarContract(artifact, [BB_P - 1n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [0n, 1n], provider, signer);
    expect(txid).toBeTruthy();
  });

  // ---- bbFieldMul ----

  it('bbFieldMul: (6 * 7) mod p = 42', async () => {
    const source = `
import { SmartContract, assert, bbFieldMul } from 'runar-lang';

class BBMulTest extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldMul(a, b) === this.expected);
  }
}
`;
    const artifact = compileSource(source, 'BBMulTest.runar.ts');
    const contract = new RunarContract(artifact, [42n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [6n, 7n], provider, signer);
    expect(txid).toBeTruthy();
  });

  it('bbFieldMul: (-1) * (-1) = 1 (field wrap)', async () => {
    const source = `
import { SmartContract, assert, bbFieldMul } from 'runar-lang';

class BBMulNeg extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldMul(a, b) === this.expected);
  }
}
`;
    const artifact = compileSource(source, 'BBMulNeg.runar.ts');
    const contract = new RunarContract(artifact, [1n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [BB_P - 1n, BB_P - 1n], provider, signer);
    expect(txid).toBeTruthy();
  });

  // ---- bbFieldInv ----

  it('bbFieldInv: a * inv(a) = 1 (algebraic identity)', async () => {
    const source = `
import { SmartContract, assert, bbFieldInv, bbFieldMul } from 'runar-lang';

class BBInvIdentity extends SmartContract {
  constructor() { super(); }
  public verify(a: bigint) {
    const inv = bbFieldInv(a);
    assert(bbFieldMul(a, inv) === 1n);
  }
}
`;
    const artifact = compileSource(source, 'BBInvIdentity.runar.ts');
    const contract = new RunarContract(artifact, []);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [42n], provider, signer);
    expect(txid).toBeTruthy();
  });

  it('bbFieldInv: inv(1) = 1', async () => {
    const source = `
import { SmartContract, assert, bbFieldInv } from 'runar-lang';

class BBInvOne extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint) {
    assert(bbFieldInv(a) === this.expected);
  }
}
`;
    const artifact = compileSource(source, 'BBInvOne.runar.ts');
    const contract = new RunarContract(artifact, [1n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [1n], provider, signer);
    expect(txid).toBeTruthy();
  });

  // ---- Unhappy path: on-chain rejection ----

  it('rejects wrong add result on-chain', async () => {
    const source = `
import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

class BBAddReject extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldAdd(a, b) === this.expected);
  }
}
`;
    const artifact = compileSource(source, 'BBAddReject.runar.ts');
    // Wrong expected: 3+7=10, not 11
    const contract = new RunarContract(artifact, [11n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    await expect(
      contract.call('verify', [3n, 7n], provider, signer),
    ).rejects.toThrow();
  });

  it('rejects wrong inv result on-chain', async () => {
    const source = `
import { SmartContract, assert, bbFieldInv } from 'runar-lang';

class BBInvReject extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint) {
    assert(bbFieldInv(a) === this.expected);
  }
}
`;
    const artifact = compileSource(source, 'BBInvReject.runar.ts');
    // Wrong expected: inv(2) is not 2
    const contract = new RunarContract(artifact, [2n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    await expect(
      contract.call('verify', [2n], provider, signer),
    ).rejects.toThrow();
  });
});
