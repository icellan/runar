/**
 * N-270: the "stateless branch" of `prepareCall` (taken whenever
 * `isStateful` — derived from non-empty `stateFields` — is false, which
 * includes a zero-mutable-field `StatefulSmartContract`) only computed a
 * REAL `methodIndex` when `isStateful` was true. For any OTHER method than
 * the first, `methodIndex` stayed 0, so `computeOpPushTxWithCodeSep` looked
 * up `codeSeparatorIndices[0]` and `publicMethods[0].sigHashType` instead of
 * the entries for the method actually being called.
 *
 * `TwoMethodReadonly` has ZERO mutable fields (so `isStateful` is false) but
 * two public methods, each with its own auto-injected `checkPreimage` and
 * therefore its own `OP_CODESEPARATOR` at a DIFFERENT byte offset (verified
 * below: `codeSeparatorIndices` is `[6, 454]`, not a single shared offset —
 * `lowerCheckPreimage` only collapses to one script-level separator when a
 * `_codePart` witness is used anywhere in the contract, which this fixture
 * never does). Calling `methodB` (real index 1) with the pre-fix code builds
 * the OP_PUSH_TX preimage's `scriptCode` from `codeSeparatorIndices[0]`
 * (methodA's offset), which the real on-chain script — dispatched to
 * methodB's branch, past methodB's OWN separator — does not match. The
 * node's internally-computed BIP-143 sighash then differs from the one the
 * fixed-nonce signature was derived against, so OP_CHECKSIG fails.
 *
 * What this test proves: `methodB` (index 1) of a 2-method zero-mutable-field
 * StatefulSmartContract is accepted by `@bsv/sdk`'s `Spend` (via
 * `MockProvider`'s default strict broadcast validation, which runs `Spend`
 * on every known input) after the fix, where it was rejected before it
 * (OP_CHECKSIG / NULLFAIL failure from the wrong `scriptCode`).
 *
 * What this test does NOT prove: the terminal-call branch (same bug, same
 * fix, different call sites — `computeOpPushTxWithCodeSep` at the terminal
 * paths), a `methodIndex`-driven merge (`additionalContractInputs`) on this
 * fixture, or any tier besides TS/Go (Python/Rust/Ruby already compute the
 * real method index unconditionally and are pinned as a cross-tier parity
 * check in their own test suites).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { Transaction } from '@bsv/sdk';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import type { RunarArtifact } from 'runar-ir-schema';

const SIGNER_KEY = '0000000000000000000000000000000000000000000000000000000000000003';

const SOURCE = `import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';
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

describe('N-270 — stateless-branch OP_PUSH_TX uses the REAL method index', () => {
  it('fixture has per-method code separators at distinct offsets (discriminating precondition)', () => {
    const artifact = compileSource(SOURCE, 'TwoMethodReadonly.runar.ts');
    expect(artifact.parentClass).toBe('StatefulSmartContract');
    expect(artifact.stateFields ?? []).toEqual([]);
    expect(artifact.codeSeparatorIndices).toBeDefined();
    expect(artifact.codeSeparatorIndices!.length).toBe(2);
    expect(artifact.codeSeparatorIndices![0]).not.toBe(artifact.codeSeparatorIndices![1]);
  });

  it('calling methodB (real index 1) is Spend-valid', async () => {
    const artifact = compileSource(SOURCE, 'TwoMethodReadonly.runar.ts');

    const signer = new LocalSigner(SIGNER_KEY);
    const address = await signer.getAddress();
    const pubKey = await signer.getPublicKey();
    const lockingHex = new RunarContract(artifact, [pubKey]).getLockingScript();

    const primary = { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5000, script: lockingHex };
    const funding = { txid: 'bb'.repeat(32), outputIndex: 0, satoshis: 100_000, script: buildP2PKHScript(pubKey) };

    // Default MockProvider: Spend-validates every known input via @bsv/sdk's
    // production Script interpreter before acking the broadcast.
    const provider = new MockProvider('testnet');
    provider.addUtxo(address, funding);
    provider.addContractUtxo(lockingHex, primary);

    const contract = RunarContract.fromUtxo(artifact, primary);
    await contract.call('methodB', [null, null], provider, signer);

    const txHex = provider.getBroadcastedTxs()[0]!;
    const tx = Transaction.fromHex(txHex);
    expect(tx.inputs.length).toBe(2);
    expect(provider.getValidationStats().validated).toBe(2);
    expect(txHex).toBe(N270_METHOD_B_TX_HEX);
  });
});

// Pinned after the fix lands (deterministic: fixed key, fixed outpoints,
// MockProvider's default 100 sat/KB fee rate). See contract.py's
// independent, never-buggy codeSepIdx computation for the cross-check this
// value was verified against before being pinned here.
const N270_METHOD_B_TX_HEX =
  '0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc802473044022061c3519e6e4cfa60f9dde9c5f0d4e460e5ef60197ba44c0e71cca562c47c4a71022010e5eab8367b1acf7fd6ec54818e4dda8e47660e53190564d41e0b4904b37f49414d7c0201000000ef9b6802354444eada24842d68525e3b2860d0af5b1b6abc6c2438eb193da948752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fddd0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffffb80a35939e20ceea1e5b24188c0630fdc61fad29e98ab26a0a7546b96748de06000000004100000051ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a47304402200274b1644d07fe4be16d71199ab51edb6c62666285ae09526a0badb16bbc815c022019c1ea6f05f733859e15312ef965dd2cb0fb9d6f8c4632828763fc7a1fad2238412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01c9990100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000';
