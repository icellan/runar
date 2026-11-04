/**
 * N-433 (PERF, LOW): the stateless / zero-mutable-field `prepareCall` branch
 * and the stateless terminal branch computed a k=1 OP_PUSH_TX ECDSA signature
 * via `computeOpPushTxWithCodeSep` and never put it in any output:
 * `buildStatefulPrefix` ignores its first parameter (F-369), and the only
 * reader of the value was a `finalOpPushTxSig` truthiness flag that is true
 * exactly when `needsOpPushTx` is. They now use the preimage-only variant
 * (N-253) with a boolean flag.
 *
 * What this proves: on each stateless path (single-input call, zero-mutable
 * merge with extra contract inputs, terminal call) zero ECDSA signs are made
 * with the OP_PUSH_TX key (k=1), counted by spying `PrivateKey.prototype.sign`
 * and filtering on the key; and the broadcast bytes equal the hex pinned from
 * the pre-change code (the N-258 / N-270 cross-tier vectors, plus a terminal
 * vector captured at base), so no output byte moved.
 * What it does not prove: anything on-chain beyond what MockProvider's
 * `Spend` validation covers; other SDK tiers (their own N-433 tests).
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { compile } from 'runar-compiler';
import { PrivateKey } from '@bsv/sdk';
import { RunarContract } from '../contract.js';
import { assembleMultiContractCall } from '../multi-contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import type { RunarArtifact } from 'runar-ir-schema';
import fs from 'fs';
import path from 'path';

const SIGNER_KEY = '0000000000000000000000000000000000000000000000000000000000000003';
const K1_HEX = '00'.repeat(31) + '01';

const TWO_METHOD_SRC = `import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';
class TwoMethodReadonly extends StatefulSmartContract {
  readonly owner: PubKey;
  constructor(owner: PubKey) { super(owner); this.owner = owner; }
  public methodA(sig: Sig): void { assert(checkSig(sig, this.owner)); }
  public methodB(sig: Sig): void { assert(checkSig(sig, this.owner)); }
}
`;

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

function spyOnK1Signs(): { count: () => number } {
  const orig = PrivateKey.prototype.sign;
  let n = 0;
  vi.spyOn(PrivateKey.prototype, 'sign').mockImplementation(function (this: PrivateKey, ...args: unknown[]) {
    if (this.toHex() === K1_HEX) n++;
    return (orig as (...a: unknown[]) => unknown).apply(this, args) as ReturnType<typeof orig>;
  } as typeof orig);
  return { count: () => n };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('N-433 -- stateless OP_PUSH_TX paths do not compute a discarded signature', () => {
  it('zero-mutable merge (extra contract input) makes zero k=1 signs and keeps the N-258 bytes', async () => {
    const source = fs.readFileSync(
      path.join(__dirname, '../../../../examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts'),
      'utf8',
    );
    const artifact = compileSource(source, 'AllReadonlyCleanstack.runar.ts');
    const signer = new LocalSigner(SIGNER_KEY);
    const address = await signer.getAddress();
    const pubKey = await signer.getPublicKey();
    const lockingHex = new RunarContract(artifact, [pubKey]).getLockingScript();
    const primary = { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5000, script: lockingHex };
    const extra = { txid: 'cc'.repeat(32), outputIndex: 1, satoshis: 7000, script: lockingHex };
    const funding = { txid: 'bb'.repeat(32), outputIndex: 0, satoshis: 100_000, script: buildP2PKHScript(pubKey) };
    const provider = new MockProvider('testnet');
    provider.addUtxo(address, funding);
    provider.addContractUtxo(lockingHex, primary);
    provider.addContractUtxo(lockingHex + ':extra', extra);

    const spy = spyOnK1Signs();
    const contract = RunarContract.fromUtxo(artifact, primary);
    await contract.call('claim', [null, null], provider, signer, { additionalContractInputs: [extra] });
    expect(spy.count()).toBe(0);
    expect(provider.getBroadcastedTxs()[0]).toBe(N258_MERGE_TX_HEX);
  });

  it('single-input stateless call (methodB) makes zero k=1 signs and keeps the N-270 bytes', async () => {
    const artifact = compileSource(TWO_METHOD_SRC, 'TwoMethodReadonly.runar.ts');
    const signer = new LocalSigner(SIGNER_KEY);
    const address = await signer.getAddress();
    const pubKey = await signer.getPublicKey();
    const lockingHex = new RunarContract(artifact, [pubKey]).getLockingScript();
    const primary = { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5000, script: lockingHex };
    const funding = { txid: 'bb'.repeat(32), outputIndex: 0, satoshis: 100_000, script: buildP2PKHScript(pubKey) };
    const provider = new MockProvider('testnet');
    provider.addUtxo(address, funding);
    provider.addContractUtxo(lockingHex, primary);

    const spy = spyOnK1Signs();
    const contract = RunarContract.fromUtxo(artifact, primary);
    await contract.call('methodB', [null, null], provider, signer);
    expect(spy.count()).toBe(0);
    expect(provider.getBroadcastedTxs()[0]).toBe(N270_METHOD_B_TX_HEX);
  });

  it('stateless terminal call makes zero k=1 signs and keeps the pre-change bytes', async () => {
    const artifact = compileSource(TWO_METHOD_SRC, 'TwoMethodReadonly.runar.ts');
    const signer = new LocalSigner(SIGNER_KEY);
    const address = await signer.getAddress();
    const pubKey = await signer.getPublicKey();
    const lockingHex = new RunarContract(artifact, [pubKey]).getLockingScript();
    const primary = { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5000, script: lockingHex };
    const funding = { txid: 'bb'.repeat(32), outputIndex: 0, satoshis: 100_000, script: buildP2PKHScript(pubKey) };
    const provider = new MockProvider('testnet');
    provider.addUtxo(address, funding);
    provider.addContractUtxo(lockingHex, primary);

    const spy = spyOnK1Signs();
    const contract = RunarContract.fromUtxo(artifact, primary);
    await contract.call('methodB', [null, null], provider, signer, {
      terminalOutputs: [{ scriptHex: buildP2PKHScript(pubKey), satoshis: 4000 }],
    });
    expect(spy.count()).toBe(0);
    expect(provider.getBroadcastedTxs()[0]).toBe(N433_TERMINAL_TX_HEX);
  });
  it('assembleMultiContractCall makes zero k=1 signs and keeps the pre-change bytes', async () => {
    const binderSrc = `import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';
class Gate extends StatefulSmartContract {
  owner: PubKey;
  constructor(owner: PubKey) { super(owner); this.owner = owner; }
  public open(sig: Sig) { assert(checkSig(sig, this.owner)); }
}
`;
    const artifact = compileSource(binderSrc, 'Gate.runar.ts');
    const signer = new LocalSigner(SIGNER_KEY);
    const pubKey = await signer.getPublicKey();
    const contract = new RunarContract(artifact, [pubKey]);
    const utxo = { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5000, script: contract.getLockingScript() };

    const spy = spyOnK1Signs();
    const assembled = await assembleMultiContractCall(
      [{ contract, method: 'open', args: [null], utxo, signer }],
      [{ satoshis: 4000, script: buildP2PKHScript(pubKey) }],
      { dryRun: false },
    );
    expect(spy.count()).toBe(0);
    expect(assembled.txHex).toBe(N433_MULTI_TX_HEX);
  });
});

const N258_MERGE_TX_HEX =
  '0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fde502483045022100ade686ada1bdadb2468b07f0699412c9d7016ca589633ac0730ea806c47437db022073f4f2a4e1bc2def562624d3ac86e4233410ca8aa84e102615ea3176fd84bb85414d990201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdfa0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac778813000000000000ffffffffbeeb1fa51feba41db76fb4b7c36a128ec3bec67bada65fbf951be782f1d1c09e0000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fde5024830450221009a9a66120d3a5e7f7d936b6b3c5a50116922b0eb6ae6255cc2c4280bab7b2f8b02200cb7382c58409af60b09bde18c241316f68dd95f2d1326109142f7794953704a414d990201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdfa0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac77581b000000000000ffffffffbeeb1fa51feba41db76fb4b7c36a128ec3bec67bada65fbf951be782f1d1c09e0000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000000069463043021f10b0ce2db56a17ad04c53de15da45671cd370f10aef72f52f1b07d41c9c4c102206ccf57f5b8e81448179f0882f269ffca5baddf87066c7c2cbf48fa4a6c0b7e7c412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01d0b40100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000';

const N270_METHOD_B_TX_HEX =
  '0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc202473044022025bdb788c88800da0e122ee07bd7e7cf108c4c6d53ebf09ed2ed7f37e4ab1ec3022012880daf6cb232de74f645e6c69e69b74e7096257735aea1ff394d87d6309fcf414d760201000000ef9b6802354444eada24842d68525e3b2860d0af5b1b6abc6c2438eb193da948752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdd70176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffffb80a35939e20ceea1e5b24188c0630fdc61fad29e98ab26a0a7546b96748de06000000004100000051ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a47304402200274b1644d07fe4be16d71199ab51edb6c62666285ae09526a0badb16bbc815c022019c1ea6f05f733859e15312ef965dd2cb0fb9d6f8c4632828763fc7a1fad2238412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01c9990100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000';

const N433_TERMINAL_TX_HEX = 
  '0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc302483045022100923a5fee18fb37ef44a838f67ddf578473ec3ac72becc46c99e78caa1a11423f022038c8f6f613e9b1b6c61a200f443ee6987755170a43ff9c2056e0dccc8ca84953414d7602010000006324e33631b1cb491f73dac8baa476a642eaeccfc7e00c2708764468c82a4e6c3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdd70176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffff5a1ddad12332f96e1d310e510254be705e6fea5b749df0e0192092b1d56a4c14000000004100000051ffffffff01a00f0000000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000';

const N433_MULTI_TX_HEX =
  '0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdd90247304402204b5fbf0e7755423ceb4c802ed3c95b9a49de3dfe4a8f5105e3d6a2ac538d02f302202827f8b9e0be37780edb28a0ce45931505b6f063974cdd2c7ae742c61a7638ce414d8e02010000006324e33631b1cb491f73dac8baa476a642eaeccfc7e00c2708764468c82a4e6c3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdef0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad69768254947f7701007e8101419d01687f7782012c947f758258947f75820121947f777c78ac776a02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f98813000000000000ffffffff5a1ddad12332f96e1d310e510254be705e6fea5b749df0e0192092b1d56a4c140000000041000000ffffffff01a00f0000000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000';
