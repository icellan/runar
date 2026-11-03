/**
 * F-039 — execution proof for a malformed `@sighash` directive.
 *
 * `/** @sighash SINGLE|FORKID! *\/` is a one-character typo of a well-formed
 * SINGLE|FORKID directive. Before F-039 every tier except Zig read it as "no
 * directive" and emitted the DEFAULT ALL|FORKID covenant — silently. The
 * pre-fix Rust artifact for the source below was measured (remediation log
 * F-039/prefix-matrix.txt) to be byte-identical to the explicit ALL|FORKID
 * artifact: the script-hex sha1 of both starts `ca7fb3bd4d`, pinned below.
 *
 * What that costs on chain, via @bsv/sdk `Spend.validate()` (not the ANF
 * interpreter, not TestContract):
 *   - a SIGHASH_SINGLE|FORKID spend — what the author declared, and what a
 *     wallet reading the author's intent would sign — is REJECTED by the
 *     pre-fix artifact;
 *   - an ALL|FORKID spend is ACCEPTED by it;
 *   - the SAME SINGLE|FORKID flow is accepted by the covenant the author
 *     actually intended (the well-formed directive), so the rejection is the
 *     mode mismatch and not a harness defect.
 * Post-fix, the malformed source does not compile at all.
 *
 * Does not prove: anything about the other six tiers' refusal (that is the
 * rejection-parity gate, conformance/negatives/N95-N98), or a live-node spend.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Spend, LockingScript, UnlockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const DEPLOYER_KEY = '0000000000000000000000000000000000000000000000000000000000000003';
const CALLER_KEY = '0000000000000000000000000000000000000000000000000000000000000004';

// Byte-for-byte the remediation-log probe `p1-trailing-bang.runar.ts`, with the
// directive line parameterised.
const probe = (directive: string) => `import { StatefulSmartContract, assert } from 'runar-lang';

export class Probe extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

${directive}
  public bump() {
    this.addOutput(1000n, this.count);
  }
}
`;

function compileArtifact(source: string): RunarArtifact {
  const result = compile(source, { fileName: 'Probe.runar.ts' });
  if (!result.artifact) {
    const errors = (result.diagnostics || [])
      .filter((d: { severity: string }) => d.severity === 'error')
      .map((d: { message: string }) => d.message);
    throw new Error(`Compile failed: ${errors.join('; ')}`);
  }
  return result.artifact;
}

function validateSpend(tx: Transaction, sourceTx: Transaction): { valid: boolean; error?: string } {
  const input = tx.inputs[0]!;
  const sourceOutput = sourceTx.outputs[0]!;
  const spend = new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: sourceOutput.satoshis!,
    lockingScript: sourceOutput.lockingScript,
    transactionVersion: tx.version,
    otherInputs: tx.inputs.slice(1).map((inp, idx) => ({
      inputIndex: idx + 1,
      sourceOutputIndex: inp.sourceOutputIndex,
      sourceTXID: inp.sourceTXID!,
      sequence: inp.sequence,
      unlockingScript: undefined as never,
      sourceSatoshis: 0,
      lockingScript: LockingScript.fromHex(''),
    })),
    outputs: tx.outputs.map((o) => ({ lockingScript: o.lockingScript, satoshis: o.satoshis })),
    unlockingScript: input.unlockingScript,
    inputIndex: 0,
    inputSequence: input.sequence,
    lockTime: tx.lockTime,
  });
  // @bsv/sdk's Spend.validate() throws a ScriptEvaluationError on a script
  // failure rather than returning false. Anything else is a harness defect and
  // propagates; a rejection is asserted on its message by the caller.
  try {
    return { valid: spend.validate() };
  } catch (e) {
    if (e instanceof Error && /^Script evaluation error:/.test(e.message)) {
      return { valid: false, error: e.message };
    }
    throw e;
  }
}

/** The BIP-143 preimage's sighash flag byte (first of its last 4 bytes). */
function preimageSighashByte(tx: Transaction): number {
  let biggest: number[] = [];
  for (const c of UnlockingScript.fromHex(tx.inputs[0]!.unlockingScript!.toHex()).chunks) {
    if (c.data && c.data.length > biggest.length) biggest = c.data;
  }
  return biggest[biggest.length - 4]!;
}

/** Deploy `artifact`, build (do not broadcast) a `bump` call, replay it through Spend. */
async function deployAndCall(artifact: RunarArtifact): Promise<{ flag: number; valid: boolean; error?: string }> {
  // #116 exact-cover trick (unfunded caller -> change clamps to 0) keeps the
  // continuation the SOLE output, at the covenant input's index, which is what
  // SINGLE commits to. The call is built with prepareCall and never broadcast,
  // so the verdict is this file's explicit Spend replay, not the provider's.
  const provider = new MockProvider('testnet', { enforceFeeFloor: false });
  const deployer = new LocalSigner(DEPLOYER_KEY);
  provider.addUtxo(await deployer.getAddress(), {
    txid: DEPLOYER_KEY,
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(await deployer.getPublicKey()),
  });
  const contract = new RunarContract(artifact, [0n]);
  // Deployed at exactly the continuation's 1000 sats: change clamps to 0, so
  // no change output follows the continuation.
  await contract.deploy(provider, deployer, { satoshis: 1000 });
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  contract.connect(provider, new LocalSigner(CALLER_KEY));
  const prepared = await contract.prepareCall('bump', []);
  expect(prepared.sigIndices).toEqual([]);
  const callTx = Transaction.fromHex(prepared.tx.toHex());
  return { flag: preimageSighashByte(callTx), ...validateSpend(callTx, deployTx) };
}

describe('F-039 — malformed @sighash: the pre-fix artifact is an ALL|FORKID covenant', () => {
  // What the pre-fix parser saw for `@sighash SINGLE|FORKID!`: no directive.
  const preFix = compileArtifact(probe('  /** @sighash ALL|FORKID */'));
  const intended = compileArtifact(probe('  /** @sighash SINGLE|FORKID */'));

  it('post-fix, the malformed source is refused (no artifact at all)', () => {
    expect(() => compileArtifact(probe('  /** @sighash SINGLE|FORKID! */'))).toThrow(
      /@sighash: malformed directive/,
    );
  });

  it('the stand-in is the measured pre-fix Rust artifact (script sha1 ca7fb3bd4d…)', () => {
    const sha1 = createHash('sha1').update(preFix.script).digest('hex');
    expect(sha1.startsWith('ca7fb3bd4d')).toBe(true);
    expect(preFix.abi.methods.find((m) => m.name === 'bump')!.sigHashType).toBeUndefined();
  });

  it('an ALL|FORKID spend of the pre-fix covenant is ACCEPTED', async () => {
    const r = await deployAndCall(preFix);
    expect(r.flag).toBe(0x41);
    expect(r.valid).toBe(true);
  });

  it('a SIGHASH_SINGLE|FORKID spend (the author\'s intent) of the pre-fix covenant is REJECTED', async () => {
    // Same locking script; the ABI mode is what a wallet honouring the
    // author's declared SINGLE|FORKID would sign under.
    const singleSigned: RunarArtifact = {
      ...preFix,
      abi: {
        ...preFix.abi,
        methods: preFix.abi.methods.map((m) => (m.name === 'bump' ? { ...m, sigHashType: 0x43 } : m)),
      },
    };
    const r = await deployAndCall(singleSigned);
    expect(r.flag).toBe(0x43);
    expect(r.valid).toBe(false);
    // The covenant's OP_PUSH_TX derives its signature under its own 0x41 flag
    // over a preimage signed for 0x43 — the signature check is what refuses.
    expect(r.error).toMatch(/OP_CHECKSIGVERIFY requires that a valid signature is provided/);
  });

  it('control: the same SINGLE|FORKID flow is ACCEPTED by the intended covenant', async () => {
    expect(intended.abi.methods.find((m) => m.name === 'bump')!.sigHashType).toBe(0x43);
    const r = await deployAndCall(intended);
    expect(r.flag).toBe(0x43);
    expect(r.valid).toBe(true);
  });
});
