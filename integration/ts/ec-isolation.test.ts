/**
 * EC isolation integration tests — inline contracts testing individual EC functions.
 *
 * Each test compiles a minimal stateless contract that exercises a single EC
 * built-in, deploys it on regtest, and spends via contract.call().
 */

import { describe, it, expect } from 'vitest';
import { compileSource } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { ecMulGen, encodePoint, EC_N, EC_P, EC_GX, EC_GY } from './helpers/crypto.js';
import { createProvider } from './helpers/node.js';

describe('EC Isolation', () => {
  it('ecOnCurve: should compile and deploy a contract checking point validity', async () => {
    const source = `
import { SmartContract, assert, ecOnCurve } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcOnCurveTest extends SmartContract {
  readonly p: Point;

  constructor(p: Point) {
    super(p);
    this.p = p;
  }

  public verify() {
    assert(ecOnCurve(this.p));
  }
}
`;
    const artifact = compileSource(source, 'EcOnCurveTest.runar.ts');
    expect(artifact.contractName).toBe('EcOnCurveTest');

    // Use a valid point on the curve (generator * some scalar)
    const [gx, gy] = ecMulGen(42n);
    const pointHex = encodePoint(gx, gy);

    const contract = new RunarContract(artifact, [pointHex]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 5000 });
    expect(deployTxid).toBeTruthy();

    const { txid: spendTxid } = await contract.call('verify', [], provider, signer);
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  it('ecMulGen: should compile and deploy a scalar-multiply-generator contract', async () => {
    const source = `
import { SmartContract, assert, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcMulGenTest extends SmartContract {
  readonly expected: Point;

  constructor(expected: Point) {
    super(expected);
    this.expected = expected;
  }

  public verify(k: bigint) {
    const result = ecMulGen(k);
    assert(ecPointX(result) === ecPointX(this.expected));
    assert(ecPointY(result) === ecPointY(this.expected));
  }
}
`;
    const artifact = compileSource(source, 'EcMulGenTest.runar.ts');
    expect(artifact.contractName).toBe('EcMulGenTest');

    const k = 7n;
    const [ex, ey] = ecMulGen(k);
    const expectedHex = encodePoint(ex, ey);

    const contract = new RunarContract(artifact, [expectedHex]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 5000 });
    expect(deployTxid).toBeTruthy();

    const { txid: spendTxid } = await contract.call('verify', [k], provider, signer);
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  it('ecAdd: should compile and deploy a point addition contract', async () => {
    const source = `
import { SmartContract, assert, ecAdd, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcAddTest extends SmartContract {
  readonly a: Point;
  readonly b: Point;
  readonly expected: Point;

  constructor(a: Point, b: Point, expected: Point) {
    super(a, b, expected);
    this.a = a;
    this.b = b;
    this.expected = expected;
  }

  public verify() {
    const result = ecAdd(this.a, this.b);
    assert(ecPointX(result) === ecPointX(this.expected));
    assert(ecPointY(result) === ecPointY(this.expected));
  }
}
`;
    const artifact = compileSource(source, 'EcAddTest.runar.ts');
    expect(artifact.contractName).toBe('EcAddTest');

    const [ax, ay] = ecMulGen(3n);
    const [bx, by] = ecMulGen(5n);
    // 3G + 5G = 8G
    const [ex, ey] = ecMulGen(8n);

    const contract = new RunarContract(artifact, [
      encodePoint(ax, ay),
      encodePoint(bx, by),
      encodePoint(ex, ey),
    ]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 5000 });
    expect(deployTxid).toBeTruthy();

    const { txid: spendTxid } = await contract.call('verify', [], provider, signer);
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  it('ecNegate: should compile, deploy, and spend a point negation contract', async () => {
    const source = `
import { SmartContract, assert, ecNegate, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcNegateTest extends SmartContract {
  readonly pt: Point;

  constructor(pt: Point) {
    super(pt);
    this.pt = pt;
  }

  public check(expectedNegY: bigint) {
    assert(ecPointY(ecNegate(this.pt)) === expectedNegY);
  }
}
`;
    const artifact = compileSource(source, 'EcNegateTest.runar.ts');
    expect(artifact.contractName).toBe('EcNegateTest');

    const [px, py] = ecMulGen(10n);
    const contract = new RunarContract(artifact, [encodePoint(px, py)]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 5000 });
    expect(deployTxid).toBeTruthy();

    // ecNegate(P).y === EC_P - P.y on secp256k1
    const negY = EC_P - py;
    const { txid: spendTxid } = await contract.call('check', [negY], provider, signer);
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  it('ecPointX: should extract the X coordinate of a point', async () => {
    const source = `
import { SmartContract, assert, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcPointXTest extends SmartContract {
  readonly pt: Point;

  constructor(pt: Point) {
    super(pt);
    this.pt = pt;
  }

  public check(expectedX: bigint) {
    assert(ecPointX(this.pt) === expectedX);
  }
}
`;
    const artifact = compileSource(source, 'EcPointXTest.runar.ts');
    const pointHex = encodePoint(EC_GX, EC_GY);
    const contract = new RunarContract(artifact, [pointHex]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    const { txid } = await contract.call('check', [EC_GX], provider, signer);
    expect(txid).toBeTruthy();
  });

  it('ecOnCurveThenPointX: should verify point is on curve and extract X', async () => {
    const source = `
import { SmartContract, assert, ecOnCurve, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcOnCurveTwice extends SmartContract {
  readonly pt: Point;

  constructor(pt: Point) {
    super(pt);
    this.pt = pt;
  }

  public check(expectedX: bigint) {
    assert(ecOnCurve(this.pt));
    assert(ecPointX(this.pt) === expectedX);
  }
}
`;
    const artifact = compileSource(source, 'EcOnCurveTwice.runar.ts');
    const pointHex = encodePoint(EC_GX, EC_GY);
    const contract = new RunarContract(artifact, [pointHex]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    const { txid } = await contract.call('check', [EC_GX], provider, signer);
    expect(txid).toBeTruthy();
  });

  it('convergencePattern: should verify EC convergence proof', async () => {
    const source = `
import { SmartContract, assert, ecOnCurve, ecAdd, ecNegate, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

class ConvergencePattern extends SmartContract {
  readonly rA: Point;
  readonly rB: Point;

  constructor(rA: Point, rB: Point) {
    super(rA, rB);
    this.rA = rA;
    this.rB = rB;
  }

  public proveConvergence(deltaO: bigint) {
    assert(ecOnCurve(this.rA));
    assert(ecOnCurve(this.rB));
    const diff = ecAdd(this.rA, ecNegate(this.rB));
    const expected = ecMulGen(deltaO);
    assert(ecPointX(diff) === ecPointX(expected));
    assert(ecPointY(diff) === ecPointY(expected));
  }
}
`;
    const artifact = compileSource(source, 'ConvergencePattern.runar.ts');
    const a = 142n;
    const b = 37n;
    const deltaO = a - b;
    const [rAx, rAy] = ecMulGen(a);
    const [rBx, rBy] = ecMulGen(b);

    const contract = new RunarContract(artifact, [
      encodePoint(rAx, rAy),
      encodePoint(rBx, rBy),
    ]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 500000 });

    const { txid } = await contract.call('proveConvergence', [deltaO], provider, signer);
    expect(txid).toBeTruthy();
  });

  it('ecMulGen with large scalar: should handle scalars near curve order', async () => {
    const source = `
import { SmartContract, assert, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcMulGenTest extends SmartContract {
  readonly expected: Point;

  constructor(expected: Point) {
    super(expected);
    this.expected = expected;
  }

  public verify(k: bigint) {
    const result = ecMulGen(k);
    assert(ecPointX(result) === ecPointX(this.expected));
    assert(ecPointY(result) === ecPointY(this.expected));
  }
}
`;
    const artifact = compileSource(source, 'EcMulGenTest.runar.ts');
    const k = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364100n;
    const [ex, ey] = ecMulGen(k);
    const contract = new RunarContract(artifact, [encodePoint(ex, ey)]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    const { txid } = await contract.call('verify', [k], provider, signer);
    expect(txid).toBeTruthy();
  });
});
