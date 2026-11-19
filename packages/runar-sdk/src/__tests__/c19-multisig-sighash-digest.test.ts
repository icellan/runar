/**
 * Deep-review finding C19 (P1): `PreparedCall.sighash` is documented as "BIP-143
 * sighash (hex) — what external signers ECDSA-sign", but the SDK computed it
 * as SINGLE-SHA256(preimage), not the double-SHA256 BIP-143 digest
 * hash256(preimage) = sha256(sha256(preimage)).
 *
 * The DEFAULT `call()` path never notices: `LocalSigner.sign()` independently
 * recomputes the preimage and calls `Hash.sha256(preimage)` before handing the
 * result to `PrivateKey.sign()`, which ITSELF re-hashes its input once more —
 * so the total ends up correct (hash256) for that one path BY CONSTRUCTION.
 * It never reads `prepared.sighash`.
 *
 * But an external wallet / hardware signer wired to the multi-signer
 * `prepareCall()` / `finalizeCall()` API is handed `prepared.sighash` and is
 * expected to ECDSA-sign it DIRECTLY — a `signHash(digest)`-style API (e.g.
 * BRC-100 wallets) does not apply any additional hashing. Handed the
 * single-hashed value, it signs the WRONG digest and the node's real
 * `OP_CHECKSIG` (BIP-143) rejects the spend.
 *
 * `prepared.sighash` must therefore be `hash256(preimage)`, matching the
 * Java SDK. `finalizeCall` never reads `prepared.sighash` itself (it only
 * consumes the externally-supplied signature via the `signatures` map), so
 * this is a pure exposed-value fix with no other internal consumer to
 * migrate — verified by tracing every `.sighash` read site in contract.ts
 * before this fix landed.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Spend, LockingScript, Transaction, TransactionSignature, PrivateKey, BigNumber, ECDSA, Hash } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const SIGNER_KEY = '0000000000000000000000000000000000000000000000000000000000000005';
const SIGHASH_ALL_FORKID = 0x41;

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

// Copied VERBATIM from c20-c27-branch-semantics.test.ts.
function validateSpend(tx: Transaction, inputIdx: number, sourceTx: Transaction, sourceOutputIdx: number): boolean {
  const input = tx.inputs[inputIdx]!;
  const sourceOutput = sourceTx.outputs[sourceOutputIdx]!;
  const spend = new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: sourceOutput.satoshis!,
    lockingScript: sourceOutput.lockingScript,
    transactionVersion: tx.version,
    otherInputs: tx.inputs
      .filter((_: unknown, i: number) => i !== inputIdx)
      .map((inp: { sourceOutputIndex: number; sourceTXID?: string; sequence?: number }, idx: number) => ({
        inputIndex: idx >= inputIdx ? idx + 1 : idx,
        sourceOutputIndex: inp.sourceOutputIndex,
        sourceTXID: inp.sourceTXID!,
        sequence: inp.sequence,
        unlockingScript: undefined as never,
        sourceSatoshis: 0,
        lockingScript: LockingScript.fromHex(''),
      })),
    outputs: tx.outputs.map((o: { lockingScript: unknown; satoshis?: number }) => ({
      lockingScript: o.lockingScript,
      satoshis: o.satoshis,
    })),
    unlockingScript: input.unlockingScript,
    inputIndex: inputIdx,
    inputSequence: input.sequence,
    lockTime: tx.lockTime,
  });
  return spend.validate();
}

function spendRejects(tx: Transaction, inputIdx: number, sourceTx: Transaction, sourceOutputIdx: number): boolean {
  try {
    return validateSpend(tx, inputIdx, sourceTx, sourceOutputIdx) === false;
  } catch {
    return true;
  }
}

/**
 * Signs a 32-byte digest DIRECTLY with raw ECDSA — no additional hashing.
 * This is @bsv/sdk's low-level sign-the-hash entry point and mirrors what an
 * external wallet's `signHash(digest)` / BRC-100 `createSignature` API does:
 * the caller must hand over the EXACT bytes to be ECDSA-signed, and the
 * wallet does not re-hash them.
 *
 * Contrast with `LocalSigner.sign()` (packages/runar-sdk/src/signers/local.ts),
 * which deliberately passes `Hash.sha256(preimage)` into `PrivateKey.sign()`
 * BECAUSE that higher-level method re-hashes its input once more internally —
 * so passing a single SHA-256 there nets the correct hash256 total. There is
 * no such second hash here: whatever digest is handed to `signDigestDirect`
 * is exactly what gets ECDSA-signed.
 */
function signDigestDirect(privKeyHex: string, digestHex: string, sigHashType = SIGHASH_ALL_FORKID): string {
  const priv = PrivateKey.fromHex(privKeyHex);
  const msg = new BigNumber(digestHex, 16);
  const sig = ECDSA.sign(msg, priv, true);
  const derHex = sig.toDER('hex') as string;
  return derHex + sigHashType.toString(16).padStart(2, '0');
}

const SRC = `
  import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
  import type { PubKey, Sig } from 'runar-lang';

  class OwnerBump extends StatefulSmartContract {
    readonly owner: PubKey;
    counter: bigint;
    constructor(owner: PubKey, counter: bigint) {
      super(owner, counter);
      this.owner = owner;
      this.counter = counter;
    }
    public bump(sig: Sig): void {
      assert(checkSig(sig, this.owner));
      this.counter = this.counter + 1n;
    }
  }
`;

/**
 * @param alwaysAck - Only for the "control" test below, which deliberately
 *   broadcasts a script-invalid call tx (wrong-digest signature) to prove
 *   the digests differ at the script layer, independent of the SDK's own
 *   `dryRun` guard. A validating provider would refuse that broadcast before
 *   the test can inspect it, so that one test opts out explicitly.
 */
async function deployOwnerBump(alwaysAck = false) {
  const artifact = compileSource(SRC, 'OwnerBump.runar.ts');
  const provider = new MockProvider('testnet', alwaysAck ? { validateBroadcasts: false } : undefined);
  const signer = new LocalSigner(SIGNER_KEY);
  const address = await signer.getAddress();
  const pubKeyHex = await signer.getPublicKey();
  provider.addUtxo(address, {
    txid: SIGNER_KEY.slice(0, 64),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(pubKeyHex),
  });
  const contract = new RunarContract(artifact, [pubKeyHex, 0n]);
  contract.connect(provider, signer);
  await contract.deploy(provider, signer, {});
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  return { contract, provider, signer, deployTx };
}

describe('C19 — PreparedCall.sighash must be the double-SHA256 BIP-143 digest', () => {
  it('an external wallet signing prepared.sighash DIRECTLY (no re-hash) produces a Spend-valid tx', async () => {
    const { contract, provider, signer, deployTx } = await deployOwnerBump();

    const prepared = await contract.prepareCall('bump', [null]);
    expect(prepared.sigIndices).toEqual([0]);
    expect(prepared.sighash).not.toBe('');

    // What a `signHash`/BRC-100 external wallet does: sign the handed-over
    // digest directly, no extra hashing.
    const externalSig = signDigestDirect(signer.getPrivateKeyHex(), prepared.sighash);

    await contract.finalizeCall(prepared, { 0: externalSig });
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    // Sanity: still bumped the counter locally (business logic untouched).
    expect(contract.state.counter).toBe(1n);
    // The real on-chain OP_CHECKSIG must accept this externally-supplied
    // signature. This is the crux of C19.
    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
  });

  it('sanity: prepared.sighash equals hash256 of the user signature\'s ALL|FORKID preimage, not sha256', async () => {
    const { contract } = await deployOwnerBump();
    const utxo = contract.getUtxo()!;
    const prepared = await contract.prepareCall('bump', [null]);
    // D25: OwnerBump is mutate-only, so its covenant preimage is SIGHASH_SINGLE
    // (0x43); a user Sig is ALL|FORKID, so its digest comes from the ALL
    // preimage of the same tx and subscript, built here by @bsv/sdk itself.
    const sub = contract.getSubscriptForSigning(utxo.script, 0);
    const allPreimage = TransactionSignature.format({
      sourceTXID: utxo.txid, sourceOutputIndex: utxo.outputIndex, sourceSatoshis: utxo.satoshis,
      transactionVersion: prepared.tx.version,
      otherInputs: prepared.tx.inputs.slice(1).map((i) => ({ ...i, sourceTXID: i.sourceTXID! })),
      outputs: prepared.tx.outputs, inputIndex: 0, subscript: LockingScript.fromHex(sub),
      inputSequence: prepared.tx.inputs[0]!.sequence!, lockTime: prepared.tx.lockTime,
      scope: SIGHASH_ALL_FORKID,
    });
    const wantHash256 = Buffer.from(Hash.hash256(allPreimage)).toString('hex');
    const singleSha256 = Buffer.from(Hash.sha256(allPreimage)).toString('hex');
    expect(prepared.sighash).toBe(wantHash256);
    expect(prepared.sighash).not.toBe(singleSha256);
  });

  it('regression guard: the DEFAULT call() path (full signer.sign) still validates on Spend', async () => {
    const { contract, provider, signer, deployTx } = await deployOwnerBump();
    await contract.call('bump', [null], provider, signer);
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
    expect(contract.state.counter).toBe(1n);
    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
  });

  it('control: signing the OLD single-SHA256 value directly is REJECTED by Spend (proves the digests differ)', async () => {
    // `skipDryRun` opts out of the C8 pre-broadcast dry-run purely so this
    // control can reach the on-chain assertion. Without it the dry-run — which
    // is exactly the C8 fix — intercepts the bad signature inside
    // finalizeCall() and throws, so the tx never reaches the provider and
    // `spendRejects` could never observe the script-level rejection this test
    // exists to prove. The sibling test below asserts that interception
    // directly; this one isolates the DIGEST difference at the script layer.
    // `deployOwnerBump(true)`: the provider must ACK the script-invalid call
    // tx so this test can inspect it — MockProvider's own broadcast
    // validation would otherwise refuse it before `spendRejects` gets a
    // chance to prove the rejection independently.
    const { contract, provider, signer, deployTx } = await deployOwnerBump(true);
    const prepared = await contract.prepareCall('bump', [null]);
    const preimageBytes = Buffer.from(prepared.preimage, 'hex');
    const wrongDigest = Buffer.from(Hash.sha256(Array.from(preimageBytes))).toString('hex');
    const wrongSig = signDigestDirect(signer.getPrivateKeyHex(), wrongDigest);
    await contract.finalizeCall(prepared, { 0: wrongSig });
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
    expect(spendRejects(callTx, 0, deployTx, 0)).toBe(true);
  });

  it('C8: the pre-broadcast dry-run REJECTS a wrong-digest signature instead of broadcasting it', async () => {
    // The same wrong-digest signature as the control above, but with the C8
    // dry-run opted IN: finalizeCall must fail closed locally rather than hand
    // a script-invalid tx to the provider. (The dry-run is opt-in rather than
    // default-on — see the CallOptions.dryRun docstring for the
    // false-rejection evidence behind that polarity.)
    const { contract, signer } = await deployOwnerBump();
    const prepared = await contract.prepareCall('bump', [null], { dryRun: true });
    const preimageBytes = Buffer.from(prepared.preimage, 'hex');
    const wrongDigest = Buffer.from(Hash.sha256(Array.from(preimageBytes))).toString('hex');
    const wrongSig = signDigestDirect(signer.getPrivateKeyHex(), wrongDigest);
    await expect(contract.finalizeCall(prepared, { 0: wrongSig })).rejects.toThrow(/dry-run/i);
  });
});
