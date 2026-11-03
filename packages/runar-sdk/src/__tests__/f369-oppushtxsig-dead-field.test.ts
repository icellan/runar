/**
 * F-369 (CL-GAP-112, MEDIUM): `PreparedCall.opPushTxSig` was documented
 * public surface ("for external signer coordination") that nothing in
 * `finalizeCall` actually consumes, and acting on it (prepending it to the
 * unlock the way its placement and docs invite) produces an INVALID unlock.
 *
 * Root cause: post-BUG-100, the OP_PUSH_TX signature is derived ON-CHAIN
 * from the preimage (see `codegen emitCheckPreimageBinding`), so the
 * unlocking script has no stack slot for a spender-supplied signature.
 * `buildStatefulPrefix(_opSig, needsCodePart)` already ignores its first
 * argument (the leading underscore marks it as intentionally unused — kept
 * only for call-site compatibility) — but `PreparedCall` still computed and
 * exposed `opPushTxSig` as if it were meaningful handoff data for an
 * external signer, which is exactly backwards: the one thing an external
 * signer must NOT do is push it.
 *
 * This is confirmed NOT a TS-only defect in behaviour — Go, Rust, Python,
 * Ruby and Zig all compute and expose the equivalent field, and all of
 * their `buildStatefulPrefix`/`build_stateful_prefix` equivalents ignore it
 * identically (verified by reading `packages/runar-go/sdk_contract.go:2491`
 * ff.). Only the Java tier never put the field on its public `PreparedCall`
 * surface in the first place. This item is scoped to `sdk:ts` (the brief's
 * tier), so only the TS field is removed here; the cross-tier doc drift on
 * the other five SDKs is a separate, not-yet-filed follow-up (see the
 * SUBAGENT REPORT `notes for dispatcher`).
 *
 * Fix: delete the dead `opPushTxSig` field from `PreparedCall` entirely
 * (wiring it IN instead would be the wrong fix — the finding is explicit
 * that acting on it breaks the unlock) and stop reading it at the two
 * `finalizeCall` call sites that fed it into `buildStatefulPrefix`.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { PrivateKey, BigNumber, ECDSA } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const SIGNER_KEY = '0000000000000000000000000000000000000000000000000000000000000007';
const SIGHASH_ALL_FORKID = 0x41;

/**
 * Signs a 32-byte digest DIRECTLY with raw ECDSA — no additional hashing.
 * Mirrors what an external BRC-100-style wallet's `signHash(digest)` does.
 * Copied from c19-multisig-sighash-digest.test.ts's `signDigestDirect`.
 */
function signDigestDirect(privKeyHex: string, digestHex: string, sigHashType = SIGHASH_ALL_FORKID): string {
  const priv = PrivateKey.fromHex(privKeyHex);
  const msg = new BigNumber(digestHex, 16);
  const sig = ECDSA.sign(msg, priv, true);
  const derHex = sig.toDER('hex') as string;
  return derHex + sigHashType.toString(16).padStart(2, '0');
}

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

async function deployOwnerBump() {
  const artifact = compileSource(SRC, 'OwnerBump.runar.ts');
  const provider = new MockProvider('testnet');
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
  return { contract, provider, signer };
}

describe('F-369 — PreparedCall.opPushTxSig is dead surface and must not exist', () => {
  it('prepareCall() on a stateful (non-terminal) method does not return an opPushTxSig key', async () => {
    const { contract } = await deployOwnerBump();
    const prepared = await contract.prepareCall('bump', [null]);
    // RED before the fix: the field was present (and non-empty — a real
    // ECDSA-signed value, per oppushtx.ts's computeOpPushTx). GREEN after:
    // the field no longer exists on the returned object at all.
    expect('opPushTxSig' in prepared).toBe(false);
  });

  it('finalizeCall() still completes a normal external-signer flow after the field is removed', async () => {
    // Regression guard: proves removing the dead field did not disturb the
    // real external-signer path — `prepared.sighash` + `sigIndices` are
    // untouched by this fix, and finalizeCall() still broadcasts a
    // script-valid tx built purely from them (same pattern as
    // c19-multisig-sighash-digest.test.ts).
    const { contract, provider, signer } = await deployOwnerBump();
    const prepared = await contract.prepareCall('bump', [null]);
    expect(prepared.sigIndices).toEqual([0]);
    expect(prepared.sighash).not.toBe('');

    const externalSig = signDigestDirect(signer.getPrivateKeyHex(), prepared.sighash);
    const { txid } = await contract.finalizeCall(prepared, { 0: externalSig });

    expect(txid).toBeTruthy();
    expect(contract.state.counter).toBe(1n);
    expect(provider.getBroadcastedTxs().length).toBe(2); // deploy + call
  });
});
