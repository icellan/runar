/**
 * R-072 — `requireOutputP2PKH`'s hashOutputs commitment must be emitted on
 * EVERY control-flow path that reads `_serialisedOutputs`, not once per method.
 *
 * `requireOutputP2PKH(i, pkh, sats)` compiles to two separate assertions:
 *
 *   (1) hash256(_serialisedOutputs) === extractOutputHash(txPreimage)
 *   (2) substr(_serialisedOutputs, i*34, 34) === <amount ‖ 0x1976a914 ‖ pkh ‖ 0x88ac>
 *
 * `_serialisedOutputs` is a SPENDER-SUPPLIED witness. (2) alone says nothing
 * about the transaction — it is a statement about bytes the attacker chose.
 * Only (1) ties those bytes to the tx's real output set, and only on the path
 * where (1) actually executes.
 *
 * The lowerers used to emit (1) at most once per METHOD. An `if` whose two arms
 * each call the intrinsic therefore got (1) in the arm lowered first and none in
 * the other: the compiler counted "already emitted" against a path that does not
 * run when the other arm does. On chain exactly one arm executes, so a spend that
 * takes the uncommitted arm reaches (2) with `_serialisedOutputs` unconstrained
 * and can hand the covenant a fabricated output set. The bond is not paid and the
 * script still verifies.
 *
 * The auto-injected `checkPreimage` binding does NOT cover this. It proves
 * `txPreimage` is the real BIP-143 preimage of the spending tx — it never compares
 * `hash256(_serialisedOutputs)` against the `hashOutputs` field inside it. Nor
 * does a stateful method's continuation check: that one hashes the outputs the
 * SCRIPT builds, a different value from the witness, so it constrains the tx
 * without constraining the witness.
 *
 * This is an execution test, not a codegen test. `TestContract`'s ANF interpreter
 * mocks `checkPreimage` and cannot model a witness/tx disagreement at all, so the
 * bypass is invisible to it. The compiled bytes run on `@bsv/sdk`'s production
 * `Spend` interpreter against a real BIP-143 preimage.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import {
  LockingScript,
  UnlockingScript,
  Spend,
  Script,
  TransactionSignature,
} from '@bsv/sdk';

const PKH_A = 'aa'.repeat(20); // bond payee on the then-arm
const PKH_B = 'bb'.repeat(20); // bond payee on the else-arm
const PKH_ATTACKER = 'cc'.repeat(20);
const BOND_SATS = 1000;
const LOOT_SATS = 4000;

/**
 * A terminal stateful method — no state mutation and no `this.addOutput(...)`,
 * the one shape typecheck permits for `requireOutputP2PKH(0, ...)` (see the
 * Crit-3 / R-300 guards in 03-typecheck.ts). Both arms assert the same output
 * index; they differ only in the payee, so the two paths are symmetric and any
 * difference in what they enforce comes from the lowering, not the source.
 */
const SOURCE = `
import { StatefulSmartContract, ByteString, requireOutputP2PKH } from 'runar-lang';

class BondCovenant extends StatefulSmartContract {
  readonly payeeA: ByteString = '${PKH_A}';
  readonly payeeB: ByteString = '${PKH_B}';
  readonly bond: bigint = ${BOND_SATS}n;

  constructor() { super(); }

  public payBond(useA: bigint) {
    if (useA > 0n) {
      requireOutputP2PKH(0n, this.payeeA, this.bond);
    } else {
      requireOutputP2PKH(0n, this.payeeB, this.bond);
    }
  }
}
`;

// --- serialisation helpers -------------------------------------------------

function p2pkhScript(pkh: string): string {
  return '76a914' + pkh + '88ac';
}

/** BIP-143 output serialisation: 8-byte LE value ‖ CompactSize(len) ‖ script. */
function serialiseOutput(satoshis: number, scriptHex: string): string {
  const value = Buffer.alloc(8);
  value.writeBigUInt64LE(BigInt(satoshis));
  const len = scriptHex.length / 2;
  if (len >= 0xfd) throw new Error('helper only covers 1-byte CompactSize');
  return value.toString('hex') + len.toString(16).padStart(2, '0') + scriptHex;
}

function pushData(hex: string): string {
  const n = hex.length / 2;
  if (n === 0) return '00';
  if (n < 0x4c) return n.toString(16).padStart(2, '0') + hex;
  if (n <= 0xff) return '4c' + n.toString(16).padStart(2, '0') + hex;
  return (
    '4d' +
    (n & 0xff).toString(16).padStart(2, '0') +
    ((n >> 8) & 0xff).toString(16).padStart(2, '0') +
    hex
  );
}

function scriptNumber(n: number): string {
  if (n === 0) return '';
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.push(v & 0xff);
    v = Math.floor(v / 256);
  }
  if (bytes[bytes.length - 1]! & 0x80) bytes.push(0x00);
  return Buffer.from(bytes).toString('hex');
}

// --- harness ---------------------------------------------------------------

const SIGHASH_ALL_FORKID = 0x41;

const TX_CONTEXT = {
  sourceTXID: '11'.repeat(32),
  sourceOutputIndex: 0,
  sourceSatoshis: 5000,
  transactionVersion: 2,
  otherInputs: [] as never[],
  inputIndex: 0,
  inputSequence: 0xffffffff,
  lockTime: 0,
};

interface TxOutput {
  satoshis: number;
  scriptHex: string;
}

interface SpendResult {
  accepted: boolean;
  error?: string;
}

const compiled = compile(SOURCE, { fileName: 'BondCovenant.runar.ts' });
const errors = (compiled.diagnostics ?? []).filter((d) => d.severity === 'error');
const artifact = compiled.artifact;

/**
 * Execute a spend of the covenant on the real `@bsv/sdk` Spend engine.
 *
 * `realOutputs` are the outputs the spending transaction actually pays — they
 * drive the BIP-143 `hashOutputs` the engine's preimage carries. `witness` is
 * the `_serialisedOutputs` bytes the SPENDER chooses, which is the whole point:
 * nothing but assertion (1) forces the two to agree.
 */
function spend(useA: number, realOutputs: TxOutput[], witness: string): SpendResult {
  const lockingHex = artifact!.script;
  const codeSepIndex = artifact!.codeSeparatorIndex;
  // BIP-143 scriptCode is the locking script AFTER the executed
  // OP_CODESEPARATOR — the same slice the SDK's computeOpPushTx takes.
  const subscriptHex =
    codeSepIndex === undefined ? lockingHex : lockingHex.slice((codeSepIndex + 1) * 2);

  const outputs = realOutputs.map((o) => ({
    satoshis: o.satoshis,
    lockingScript: LockingScript.fromHex(o.scriptHex),
  }));

  const preimageHex = Buffer.from(
    TransactionSignature.formatBytes({
      ...TX_CONTEXT,
      outputs: outputs as never,
      subscript: Script.fromHex(subscriptHex) as never,
      scope: SIGHASH_ALL_FORKID,
    }) as unknown as number[],
  ).toString('hex');

  // Method params in ANF order: useA, txPreimage, _serialisedOutputs.
  const unlockingHex =
    pushData(scriptNumber(useA)) + pushData(preimageHex) + pushData(witness);

  try {
    const s = new Spend({
      ...TX_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      outputs: outputs as never,
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
    });
    return { accepted: s.validate() };
  } catch (e) {
    return { accepted: false, error: e instanceof Error ? e.message : String(e) };
  }
}

const bondToA: TxOutput = { satoshis: BOND_SATS, scriptHex: p2pkhScript(PKH_A) };
const bondToB: TxOutput = { satoshis: BOND_SATS, scriptHex: p2pkhScript(PKH_B) };
/** No bond anywhere: the whole input value goes to the spender. */
const lootToAttacker: TxOutput = {
  satoshis: LOOT_SATS,
  scriptHex: p2pkhScript(PKH_ATTACKER),
};

const witnessBondA = serialiseOutput(BOND_SATS, p2pkhScript(PKH_A));
const witnessBondB = serialiseOutput(BOND_SATS, p2pkhScript(PKH_B));
const witnessLoot = serialiseOutput(LOOT_SATS, p2pkhScript(PKH_ATTACKER));

describe('R-072: requireOutputP2PKH in both arms of an if', () => {
  it('compiles', () => {
    expect(errors.map((e) => e.message)).toEqual([]);
    expect(artifact).toBeDefined();
  });

  // --- the harness is honest -----------------------------------------------

  it('ACCEPTS an honest then-arm spend that really pays the bond', () => {
    const r = spend(1, [bondToA], witnessBondA);
    expect(r.error, r.error).toBeUndefined();
    expect(r.accepted).toBe(true);
  });

  it('ACCEPTS an honest else-arm spend that really pays the bond', () => {
    const r = spend(0, [bondToB], witnessBondB);
    expect(r.error, r.error).toBeUndefined();
    expect(r.accepted).toBe(true);
  });

  // --- the per-output assertion is live on both arms ------------------------

  it('REJECTS an else-arm spend whose witness is truthful but pays the wrong payee', () => {
    // Witness == the real output set, so assertion (1) holds; assertion (2)
    // fails. Proves the else-arm's bond check runs at all, so the bypass below
    // cannot be explained by a dead branch.
    const r = spend(0, [lootToAttacker], witnessLoot);
    expect(r.accepted).toBe(false);
  });

  // --- the commitment ------------------------------------------------------

  it('REJECTS a then-arm spend whose witness contradicts the real outputs', () => {
    // The commitment is present on this path, so the fabricated witness is
    // caught. This is the behaviour the else-arm must match.
    const r = spend(1, [lootToAttacker], witnessBondA);
    expect(r.accepted).toBe(false);
  });

  it('REJECTS an else-arm spend whose witness contradicts the real outputs', () => {
    // THE BYPASS. The transaction pays the whole input to the attacker and
    // contains no output to payeeB at all; the witness is a P2PKH-to-payeeB
    // output the spender simply invented. Without a commitment on this path the
    // covenant verifies it and the bond is never paid.
    const r = spend(0, [lootToAttacker], witnessBondB);
    expect(r.accepted).toBe(false);
  });
});
