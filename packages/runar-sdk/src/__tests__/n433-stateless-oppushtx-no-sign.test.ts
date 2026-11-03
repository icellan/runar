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
  '0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdea02473044022033b20ee497b244a5f44ea460cbeb66c867d72ee622cf6e8163651998b66da33d02200b7580e4c31b3bf66410bbd033e935bcf41449fcabfdf90275cc2a7df78f8911414d9f0201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fd000276aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac778813000000000000ffffffffe0fb8d8fe33024ae55861c19ec7c3056e7ba656aa6623274dc5d6140edcd3d370000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdea0247304402203b86795685f996d25ad0c7db76fb2b1d3ba6e1127332ba7806f9786e6ef03d0602201eca36661b0bb5e080c43fe881cae23d59194a557a76fdbca879995aaabc2314414d9f0201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fd000276aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac77581b000000000000ffffffffe0fb8d8fe33024ae55861c19ec7c3056e7ba656aa6623274dc5d6140edcd3d370000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006b483045022100fe183c7919d2e06724b2134fa072fa1d6a698eb1b6cc07dd42341eeff238c11f02200abfed215d06dcaae1226e0497cff4ef3834ea7043cdbb76af44104c630b7c25412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01ceb40100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000';

const N270_METHOD_B_TX_HEX =
  '0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc802473044022061c3519e6e4cfa60f9dde9c5f0d4e460e5ef60197ba44c0e71cca562c47c4a71022010e5eab8367b1acf7fd6ec54818e4dda8e47660e53190564d41e0b4904b37f49414d7c0201000000ef9b6802354444eada24842d68525e3b2860d0af5b1b6abc6c2438eb193da948752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fddd0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffffb80a35939e20ceea1e5b24188c0630fdc61fad29e98ab26a0a7546b96748de06000000004100000051ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a47304402200274b1644d07fe4be16d71199ab51edb6c62666285ae09526a0badb16bbc815c022019c1ea6f05f733859e15312ef965dd2cb0fb9d6f8c4632828763fc7a1fad2238412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01c9990100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000';

const N433_TERMINAL_TX_HEX = 
  '0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc8024730440220620e5c2cd05d97ca2d91951469bfc3a61a9bb4b1dc1959e16e510f69fba043e902203900d7ee047c058c57776952d71d634d41fe175107bbf35b5518275d8e38bb53414d7c02010000006324e33631b1cb491f73dac8baa476a642eaeccfc7e00c2708764468c82a4e6c3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fddd0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffff5a1ddad12332f96e1d310e510254be705e6fea5b749df0e0192092b1d56a4c14000000004100000051ffffffff01a00f0000000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000';

const N433_MULTI_TX_HEX =
  '0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fddf02473044022022bb8eddab6a14ebc9c21d8a3b7196a357108aa0bd432d532ef24498d517ed5d02200fcf2b8a14081a61dd51e445e1e2b35ec245095f6686dff14392958f4cb22210414d9402010000006324e33631b1cb491f73dac8baa476a642eaeccfc7e00c2708764468c82a4e6c3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdf50176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad69768254947f7701007e8101419d01687f7782012c947f758258947f75820121947f777c78ac776a02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f98813000000000000ffffffff5a1ddad12332f96e1d310e510254be705e6fea5b749df0e0192092b1d56a4c140000000041000000ffffffff01a00f0000000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000';
