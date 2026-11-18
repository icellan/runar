/**
 * #198 — `buildContractUnlock(tx, inputIndex, input)`: the per-input unlock
 * step of `assembleMultiContractCall`, exported for a transaction that was
 * built ELSEWHERE (e.g. by a BRC-100 wallet that adds its own funding input).
 *
 * Every positive test validates through @bsv/sdk's production Spend
 * interpreter (real ECDSA, real BIP-143, real hashOutputs binding), never just
 * a shape assertion: an output-order or change mismatch would strand funds.
 *
 * Proves: a contract input at index 1 beside a foreign P2PKH input at index 0,
 * in a tx @bsv/sdk built outside Rúnar, gets an unlock that verifies, both
 * through dryRunMultiContractInput and through Spend for EVERY input of the
 * whole tx; the API refuses (throws) when the declared change cannot match the
 * tx, when the outpoint/index/widths are wrong, and when an opt-in dry run
 * fails. Does not prove: that a given wallet will keep these outputs when it
 * finalises its own tx (docs caveat), or the pre-sign preimage hook (not
 * shipped).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import {
  Hash, Utils, PrivateKey, P2PKH, Transaction, Spend, LockingScript, UnlockingScript,
} from '@bsv/sdk';
import { RunarContract } from '../contract.js';
import {
  buildContractUnlock,
  buildContractUnlockSkeleton,
  dryRunMultiContractInput,
} from '../multi-contract.js';
import { LocalSigner } from '../signers/local.js';
import type { RunarArtifact } from 'runar-ir-schema';

const TOKEN_SOURCE = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, Sha256 } from 'runar-lang';

class BumpToken extends StatefulSmartContract {
  owner: PubKey;
  value: bigint;

  constructor(owner: PubKey, value: bigint) {
    super(owner, value);
    this.owner = owner;
    this.value = value;
  }

  public bump(sig: Sig, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, this.owner, this.value + 1n);
  }

  public tag(sig: Sig, digest: Sha256, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, this.owner, this.value);
  }

  public freeze(sig: Sig, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, this.owner, this.value);
  }
}
`;

const artifact: RunarArtifact = (() => {
  const r = compile(TOKEN_SOURCE, { fileName: 'BumpToken.runar.ts' });
  if (!r.artifact) throw new Error(`compile failed: ${JSON.stringify(r.diagnostics)}`);
  return r.artifact;
})();

const ownerSigner = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
const ownerPub = await ownerSigner.getPublicKey();
const hash160hex = (h: string): string => Utils.toHex(Hash.hash160(Utils.toArray(h, 'hex')));
const changePKH = hash160hex(ownerPub);
const p2pkh = (pkh: string): string => '76a914' + pkh + '88ac';

const foreignKey = PrivateKey.fromHex('0000000000000000000000000000000000000000000000000000000000000007');
const foreignPKH = hash160hex(foreignKey.toPublicKey().toString());
const FOREIGN = { txid: 'cc'.repeat(32), outputIndex: 3, satoshis: 4000, script: p2pkh(foreignPKH) };

function setup() {
  const token = new RunarContract(artifact, [ownerPub, 5n]);
  const utxo = { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5000, script: token.getLockingScript() };
  const next = new RunarContract(artifact, [ownerPub, 5n]);
  next.setState({ owner: ownerPub, value: 6n });
  return { token, utxo, contScript: next.getLockingScript() };
}

/** A "wallet-built" tx: foreign funding input FIRST, contract input SECOND. */
function walletTx(
  utxo: { txid: string; outputIndex: number },
  outputs: Array<{ satoshis: number; script: string }>,
): Transaction {
  const tx = new Transaction();
  tx.addInput({
    sourceTXID: FOREIGN.txid, sourceOutputIndex: FOREIGN.outputIndex,
    unlockingScript: new UnlockingScript(), sequence: 0xffffffff,
  });
  tx.addInput({
    sourceTXID: utxo.txid, sourceOutputIndex: utxo.outputIndex,
    unlockingScript: new UnlockingScript(), sequence: 0xffffffff,
  });
  for (const o of outputs) {
    tx.addOutput({ satoshis: o.satoshis, lockingScript: LockingScript.fromHex(o.script) });
  }
  return tx;
}

/** Foreign P2PKH unlock for input 0 via the stock @bsv/sdk template. */
async function signForeign(tx: Transaction): Promise<void> {
  tx.inputs[0]!.unlockingScriptTemplate = new P2PKH().unlock(
    foreignKey, 'all', false, FOREIGN.satoshis, LockingScript.fromHex(FOREIGN.script),
  );
  await tx.sign();
}

/** Replay one input through the production Spend interpreter. */
function spendInput(tx: Transaction, i: number, lockScript: string, sats: number): boolean {
  const inp = tx.inputs[i]!;
  const spend = new Spend({
    sourceTXID: inp.sourceTXID!,
    sourceOutputIndex: inp.sourceOutputIndex,
    sourceSatoshis: sats,
    lockingScript: LockingScript.fromHex(lockScript),
    transactionVersion: tx.version,
    otherInputs: tx.inputs.filter((_, k) => k !== i),
    outputs: tx.outputs,
    inputIndex: i,
    unlockingScript: inp.unlockingScript!,
    inputSequence: inp.sequence ?? 0xffffffff,
    lockTime: tx.lockTime,
  });
  return !!spend.validate();
}

const bumpInput = (token: RunarContract, utxo: { txid: string; outputIndex: number; satoshis: number; script: string }, over: Record<string, unknown> = {}) => ({
  contract: token, method: 'bump', args: [null, 2000n], utxo, signer: ownerSigner,
  changePKH, changeAmount: 1000n, ...over,
});

describe('buildContractUnlock — wallet-built tx (#198)', () => {
  it('contract input at index 1 beside a foreign P2PKH input at 0: every input of the whole tx validates', async () => {
    const { token, utxo, contScript } = setup();
    const tx = walletTx(utxo, [
      { satoshis: 2000, script: contScript },
      { satoshis: 1000, script: p2pkh(changePKH) },
    ]);

    const { unlockingScript, preimage } = await buildContractUnlock(tx, 1, bumpInput(token, utxo));
    expect(preimage.length).toBeGreaterThan(0);
    tx.inputs[1]!.unlockingScript = UnlockingScript.fromHex(unlockingScript);
    await signForeign(tx);

    const hex = tx.toHex();
    const r = dryRunMultiContractInput(hex, 1, utxo.script, utxo.satoshis);
    expect(r.error).toBeUndefined();
    expect(r.valid).toBe(true);

    // Whole tx: the foreign P2PKH input AND the covenant input, via Spend.
    const reparsed = Transaction.fromHex(hex);
    expect(spendInput(reparsed, 0, FOREIGN.script, FOREIGN.satoshis)).toBe(true);
    expect(spendInput(reparsed, 1, utxo.script, utxo.satoshis)).toBe(true);
  });

  it('reads version, lockTime, sequences and a sourceTransaction-only foreign input from the tx; never mutates/caches the caller tx', async () => {
    const { token, utxo, contScript } = setup();
    // Foreign funding input expressed ONLY via sourceTransaction (no sourceTXID).
    const funding = new Transaction();
    funding.addOutput({ satoshis: FOREIGN.satoshis, lockingScript: LockingScript.fromHex(FOREIGN.script) });
    const tx = new Transaction(2, [], [], 500_000);
    tx.addInput({
      sourceTransaction: funding, sourceOutputIndex: 0,
      unlockingScript: new UnlockingScript(), sequence: 0xfffffffd,
    });
    tx.addInput({
      sourceTXID: utxo.txid, sourceOutputIndex: utxo.outputIndex,
      unlockingScript: new UnlockingScript(), sequence: 0xfffffffe,
    });
    tx.addOutput({ satoshis: 2000, lockingScript: LockingScript.fromHex(contScript) });
    tx.addOutput({ satoshis: 1000, lockingScript: LockingScript.fromHex(p2pkh(changePKH)) });

    const before = tx.toHex();
    const { unlockingScript } = await buildContractUnlock(tx, 1, bumpInput(token, utxo), { dryRun: true });
    // The caller's tx is untouched (neither mutated nor left with a stale cache).
    expect(tx.toHex()).toBe(before);
    expect(tx.inputs[1]!.unlockingScript!.toHex()).toBe('');

    tx.inputs[1]!.unlockingScript = UnlockingScript.fromHex(unlockingScript);
    tx.inputs[0]!.unlockingScriptTemplate = new P2PKH().unlock(foreignKey, 'all', false);
    await tx.sign();
    const reparsed = Transaction.fromHex(tx.toHex());
    expect(reparsed.version).toBe(2);
    expect(reparsed.lockTime).toBe(500_000);
    expect(spendInput(reparsed, 0, FOREIGN.script, FOREIGN.satoshis)).toBe(true);
    expect(spendInput(reparsed, 1, utxo.script, utxo.satoshis)).toBe(true);
  });

  it('dryRun:true validates through Spend before returning, and THROWS when the tx cannot match the covenant', async () => {
    const { token, utxo, contScript } = setup();
    const good = walletTx(utxo, [
      { satoshis: 2000, script: contScript },
      { satoshis: 1000, script: p2pkh(changePKH) },
    ]);
    await expect(buildContractUnlock(good, 1, bumpInput(token, utxo), { dryRun: true })).resolves.toBeTruthy();

    // Continuation sats differ from the `outputSatoshis` arg (2000): hashOutputs
    // cannot match, the on-chain OP_VERIFY would reject -> refuse.
    const bad = walletTx(utxo, [
      { satoshis: 1999, script: contScript },
      { satoshis: 1000, script: p2pkh(changePKH) },
    ]);
    await expect(
      buildContractUnlock(bad, 1, bumpInput(token, utxo), { dryRun: true }),
    ).rejects.toThrow(/offline validation FAILED for input 1/);
  });

  it('REFUSES a declared change the tx does not carry (amount mismatch / missing / wrong pkh)', async () => {
    const { token, utxo, contScript } = setup();
    const cont = { satoshis: 2000, script: contScript };
    // wallet change 900, declared 1000
    await expect(buildContractUnlock(
      walletTx(utxo, [cont, { satoshis: 900, script: p2pkh(changePKH) }]), 1, bumpInput(token, utxo),
    )).rejects.toThrow(/change/i);
    // declared 1000 but the tx has no change output at all
    await expect(buildContractUnlock(
      walletTx(utxo, [cont]), 1, bumpInput(token, utxo),
    )).rejects.toThrow(/change/i);
    // change pays a different pkh
    await expect(buildContractUnlock(
      walletTx(utxo, [cont, { satoshis: 1000, script: p2pkh(foreignPKH) }]), 1, bumpInput(token, utxo),
    )).rejects.toThrow(/change/i);
  });

  it('REFUSES changeAmount 0 when the tx nevertheless ends in a P2PKH change to changePKH (covenant would not commit it)', async () => {
    const { token, utxo, contScript } = setup();
    const tx = walletTx(utxo, [
      { satoshis: 2000, script: contScript },
      { satoshis: 1000, script: p2pkh(changePKH) },
    ]);
    await expect(buildContractUnlock(tx, 1, bumpInput(token, utxo, { changeAmount: 0n })))
      .rejects.toThrow(/change/i);
  });

  it('changeAmount 0 with NO wallet change output validates (the covenant commits no change)', async () => {
    const { token, utxo, contScript } = setup();
    const tx = walletTx(utxo, [{ satoshis: 2000, script: contScript }]);
    const { unlockingScript } = await buildContractUnlock(
      tx, 1, bumpInput(token, utxo, { changeAmount: 0n }), { dryRun: true },
    );
    tx.inputs[1]!.unlockingScript = UnlockingScript.fromHex(unlockingScript);
    await signForeign(tx);
    expect(dryRunMultiContractInput(tx.toHex(), 1, utxo.script, utxo.satoshis).valid).toBe(true);
  });

  it('REFUSES a changePKH that is not 20 bytes (PR B #213 gate) and a mis-sized fixed-width arg', async () => {
    const { token, utxo, contScript } = setup();
    const tx = walletTx(utxo, [
      { satoshis: 2000, script: contScript },
      { satoshis: 1000, script: p2pkh(changePKH) },
    ]);
    await expect(buildContractUnlock(tx, 1, bumpInput(token, utxo, { changePKH: changePKH.slice(2) })))
      .rejects.toThrow(/changePKH/);
    await expect(buildContractUnlock(tx, 1, bumpInput(token, utxo, { changePKH: changePKH + '00' })))
      .rejects.toThrow(/changePKH/);
    // N-045 width gate: `tag(sig, digest: Sha256, sats)` takes a 32-byte arg.
    const tag = (digest: string) =>
      buildContractUnlock(tx, 1, bumpInput(token, utxo, { method: 'tag', args: [null, digest, 2000n] }));
    await expect(tag('ab'.repeat(31))).rejects.toThrow(/arg 1 \(param 'digest'\)/);
    await expect(tag('ab'.repeat(33))).rejects.toThrow(/arg 1 \(param 'digest'\)/);
    // a correctly-sized digest passes the gate (and the unlock builds)
    await expect(tag('ab'.repeat(32))).resolves.toBeTruthy();
  });

  it('REFUSES a tx whose input at inputIndex is not the UTXO being spent, and an out-of-range index', async () => {
    const { token, utxo, contScript } = setup();
    const tx = walletTx(utxo, [
      { satoshis: 2000, script: contScript },
      { satoshis: 1000, script: p2pkh(changePKH) },
    ]);
    // input 0 is the foreign outpoint, not the contract UTXO
    await expect(buildContractUnlock(tx, 0, bumpInput(token, utxo))).rejects.toThrow(/outpoint/i);
    await expect(buildContractUnlock(tx, 5, bumpInput(token, utxo))).rejects.toThrow(/no input at index 5/);
  });
});

describe('buildContractUnlockSkeleton — fee sizing (#198)', () => {
  it('returns a placeholder unlock never shorter than, and within a few bytes of, the real one', async () => {
    const { token, utxo, contScript } = setup();
    const input = bumpInput(token, utxo);
    const tx = walletTx(utxo, [
      { satoshis: 2000, script: contScript },
      { satoshis: 1000, script: p2pkh(changePKH) },
    ]);
    const real = (await buildContractUnlock(tx, 1, input)).unlockingScript;
    const skel = buildContractUnlockSkeleton(input);
    expect(skel.length).toBe(skel.unlockingScript.length / 2);
    expect(skel.length).toBeGreaterThanOrEqual(real.length / 2);
    expect(skel.length - real.length / 2).toBeLessThanOrEqual(16);
  });
});
