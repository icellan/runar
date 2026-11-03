/**
 * Issue #106 — `EMPTY_SIG` producer-side convention for OR-CHECKSIG branched
 * authorization.
 *
 * An OR-CHECKSIG method — `checkSig(sigA, pkA) || checkSig(sigB, pkB)`. `||`
 * short-circuits: it lowers to OP_IF / OP_ELSE / OP_ENDIF (NEW-014), not to
 * `OP_BOOLOR`, so the second `OP_CHECKSIG` runs only when the first FAILS —
 * and the first then ran with whatever its slot holds. A branch that is
 * evaluated and must fail MUST push an empty signature (OP_0) or BIP146
 * NULLFAIL aborts the whole spend. Since N-198 the SDK ANF interpreters and
 * TestContract model that rule; @bsv/sdk `Spend` does not (see below).
 *
 * These tests drive the full SDK deploy → call path and replay the built call
 * tx offline through @bsv/sdk's `Spend` interpreter:
 *   * GREEN (interpreter-level): `call('execute', [null, EMPTY_SIG])` signs only
 *     the auto slot; the EMPTY_SIG slot stays OP_0 → the spend VALIDATES, and
 *     the non-matching branch's Sig push is OP_0 (NULLFAIL-clean whichever
 *     branch runs).
 *   * RED baseline (wire-level): `call('execute', [null, null])` fills BOTH sig
 *     slots with Alice's signature, so the non-matching branch carries a
 *     NON-EMPTY, invalid signature. Here Alice is pkA, so branch A succeeds and
 *     the short-circuit never runs branch B — this particular tx is valid on a
 *     node. The pattern is a NULLFAIL abort (ARC HTTP 461) exactly when the
 *     evaluated failing branch holds it, e.g. the signer is pkB and branch A
 *     carries the non-empty invalid signature. The test pins the wire bytes.
 *
 * Note on the interpreter: the installed @bsv/sdk (2.0.7) `Spend` does NOT
 * implement SCRIPT_VERIFY_NULLFAIL — a non-empty invalid signature makes
 * CHECKSIG push `false` rather than abort — so it cannot itself REJECT the
 * `[null, null]` tx. The reporter cited a NULLFAIL-enforcing fork
 * (`packages/sdk/src/script/Spend.ts:1326`); a real node/ARC enforces it too.
 * The RED baseline is therefore captured at the wire level: the failing
 * branch's push is non-empty under `[null, null]` and empty (OP_0) under
 * `[null, EMPTY_SIG]`.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract, EMPTY_SIG, encodeArg } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const ALICE_KEY = '0000000000000000000000000000000000000000000000000000000000000003';
const BOB_KEY = '0000000000000000000000000000000000000000000000000000000000000007';

const SRC = `
  class OrChecksig extends SmartContract {
    readonly pkA: PubKey;
    readonly pkB: PubKey;
    constructor(pkA: PubKey, pkB: PubKey) { super(pkA, pkB); this.pkA = pkA; this.pkB = pkB; }
    public execute(sigA: Sig, sigB: Sig): void {
      assert(checkSig(sigA, this.pkA) || checkSig(sigB, this.pkB));
    }
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

async function setupWallet(provider: MockProvider, privKey: string, satoshis: number) {
  const signer = new LocalSigner(privKey);
  const address = await signer.getAddress();
  provider.addUtxo(address, {
    txid: privKey.slice(0, 64),
    outputIndex: 0,
    satoshis,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  return signer;
}

/** Replay `inputIdx` of `tx` through @bsv/sdk's Spend with real tx context. */
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

/** Parse the data elements pushed by a scriptSig hex. OP_0 yields an empty element. */
function parsePushes(scriptHex: string): string[] {
  const pushes: string[] = [];
  let p = 0;
  const byteAt = (i: number) => parseInt(scriptHex.slice(i * 2, i * 2 + 2), 16);
  const nBytes = scriptHex.length / 2;
  while (p < nBytes) {
    const op = byteAt(p);
    p += 1;
    if (op === 0x00) {
      pushes.push(''); // OP_0 → empty push
    } else if (op >= 0x01 && op <= 0x4b) {
      pushes.push(scriptHex.slice(p * 2, (p + op) * 2));
      p += op;
    } else if (op === 0x4c) {
      const n = byteAt(p);
      p += 1;
      pushes.push(scriptHex.slice(p * 2, (p + n) * 2));
      p += n;
    } else {
      pushes.push(''); // bare opcode (not expected here)
    }
  }
  return pushes;
}

async function deployOrChecksig() {
  const artifact = compileSource(SRC, 'OrChecksig.runar.ts');
  const provider = new MockProvider('testnet');
  const alice = await setupWallet(provider, ALICE_KEY, 500_000);
  const bob = new LocalSigner(BOB_KEY);
  const pkA = await alice.getPublicKey();
  const pkB = await bob.getPublicKey();

  const contract = new RunarContract(artifact, [pkA, pkB]);
  await contract.deploy(provider, alice, {});
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  return { contract, provider, alice, deployTx };
}

describe('#106 — EMPTY_SIG for OR-CHECKSIG branched authorization', () => {
  it('encodes EMPTY_SIG as OP_0 (empty signature push)', () => {
    expect(encodeArg(EMPTY_SIG)).toBe('00');
  });

  it('GREEN: [null, EMPTY_SIG] validates through Spend; failing branch is OP_0', async () => {
    const { contract, provider, alice, deployTx } = await deployOrChecksig();

    // Alice signs branch A (null → auto); branch B is deliberately empty.
    await contract.call('execute', [null, EMPTY_SIG], provider, alice);
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    // The built spend validates through the real interpreter.
    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);

    // Wire-level: branch A carries a real signature, branch B is OP_0 (empty).
    const pushes = parsePushes(callTx.inputs[0]!.unlockingScript!.toHex());
    expect(pushes).toHaveLength(2);
    expect(pushes[0]!.length).toBeGreaterThan(0); // branch A: real signature
    expect(pushes[1]).toBe(''); // branch B: OP_0 — satisfies NULLFAIL
  });

  it('RED baseline: [null, null] produces the non-empty failing-branch sig NULLFAIL rejects', async () => {
    const { contract, provider, alice } = await deployOrChecksig();

    // Both slots auto → the SDK fills BOTH with Alice's signature. Branch B's
    // non-empty-but-invalid signature (valid for pkA, checked against pkB) is
    // the byte pattern a NULLFAIL-enforcing node rejects (ARC HTTP 461) when
    // that branch is evaluated — not here, where branch A succeeds first.
    await contract.call('execute', [null, null], provider, alice);
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    const pushes = parsePushes(callTx.inputs[0]!.unlockingScript!.toHex());
    expect(pushes).toHaveLength(2);
    expect(pushes[0]!.length).toBeGreaterThan(0); // branch A: real signature
    expect(pushes[1]!.length).toBeGreaterThan(0); // branch B: non-empty → trips NULLFAIL
    expect(pushes[1]).toBe(pushes[0]); // same single-signer signature in both slots
  });
});
