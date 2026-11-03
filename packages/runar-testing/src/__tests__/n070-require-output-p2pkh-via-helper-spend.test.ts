/**
 * N-070 — `requireOutputP2PKH` called from a private helper must compile, and
 * the compiled covenant must enforce exactly what the direct call enforces.
 *
 * The intrinsic auto-injects a `_serialisedOutputs` witness param into the
 * method it is lowered in. ANF lowering inlined a private helper at the call
 * site only when the helper emitted outputs, so a helper that merely called
 * `requireOutputP2PKH` stayed a `method_call`: the witness param landed on the
 * helper's own ANF method, never on the public spending method, and stack
 * lowering refused the program ("method parameter '_serialisedOutputs' is not
 * on the stack"). Fail-closed, but a legitimate terminal covenant — the shape
 * typecheck explicitly permits — could not be factored into a helper. The F-075
 * typecheck guards already see through helpers; this was the lowering lagging.
 *
 * ORACLE. `@bsv/sdk`'s production `Spend` interpreter over a real BIP-143
 * preimage — never `TestContract`, whose interpreter mocks `checkPreimage` and
 * shares the compiler's model. The harness is R-072's, verbatim; the contract
 * is R-072's `BondCovenant` with the intrinsic moved into a parameterised
 * helper called from BOTH arms, so the test also covers helper-parameter
 * aliasing and the per-arm hashOutputs commitment under inlining.
 *
 * PROVES: the helper form compiles, emits the SAME bytes as the direct form,
 * accepts an honest spend on each arm, and rejects a spend whose witness
 * contradicts the real outputs and one that pays the wrong payee.
 * DOES NOT PROVE: cross-tier agreement (tests/n070-require-output-p2pkh-via-
 * helper.test.ts does that against the seven-tier golden), or anything about
 * `extractPrevOutputScript` in a helper, which is a separate intrinsic.
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
 * R-072's covenant with the intrinsic called directly in each arm. The payee is
 * read into a local first because a call evaluates its arguments BEFORE the
 * callee body runs: the inlined helper loads `this.payeeA` ahead of the
 * hashOutputs commitment, while `requireOutputP2PKH(0n, this.payeeA, ...)`
 * written inline loads it after. Same checks, different binding order, so the
 * like-for-like direct form is the one that binds the argument first.
 */
const DIRECT_SOURCE = `
import { StatefulSmartContract, ByteString, requireOutputP2PKH } from 'runar-lang';

class BondCovenant extends StatefulSmartContract {
  readonly payeeA: ByteString = '${PKH_A}';
  readonly payeeB: ByteString = '${PKH_B}';
  readonly bond: bigint = ${BOND_SATS}n;

  constructor() { super(); }

  public payBond(useA: bigint) {
    if (useA > 0n) {
      const pa: ByteString = this.payeeA;
      requireOutputP2PKH(0n, pa, this.bond);
    } else {
      const pb: ByteString = this.payeeB;
      requireOutputP2PKH(0n, pb, this.bond);
    }
  }
}
`;

/** The same covenant with the intrinsic delegated to a private helper. */
const HELPER_SOURCE = `
import { StatefulSmartContract, ByteString, requireOutputP2PKH } from 'runar-lang';

class BondCovenant extends StatefulSmartContract {
  readonly payeeA: ByteString = '${PKH_A}';
  readonly payeeB: ByteString = '${PKH_B}';
  readonly bond: bigint = ${BOND_SATS}n;

  constructor() { super(); }

  private pay(payee: ByteString): void {
    requireOutputP2PKH(0n, payee, this.bond);
  }

  public payBond(useA: bigint) {
    if (useA > 0n) {
      this.pay(this.payeeA);
    } else {
      this.pay(this.payeeB);
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

const compiled = compile(HELPER_SOURCE, { fileName: 'BondCovenant.runar.ts' });
const errors = (compiled.diagnostics ?? []).filter((d) => d.severity === 'error');
const artifact = compiled.artifact;
const direct = compile(DIRECT_SOURCE, { fileName: 'BondCovenant.runar.ts' });

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

describe('N-070: requireOutputP2PKH delegated to a private helper', () => {
  it('compiles', () => {
    expect(errors.map((e) => e.message)).toEqual([]);
    expect(artifact).toBeDefined();
  });

  it('emits byte-identical script to the direct call', () => {
    expect(direct.success, JSON.stringify(direct.diagnostics)).toBe(true);
    expect(artifact!.script).toBe(direct.artifact!.script);
  });

  it('puts _serialisedOutputs on the public method ABI, after txPreimage', () => {
    const m = artifact!.abi.methods.find((x) => x.name === 'payBond')!;
    expect(m.params.map((p) => p.name)).toEqual(['useA', 'txPreimage', '_serialisedOutputs']);
  });

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

  it('REJECTS a spend whose truthful witness pays the wrong payee', () => {
    const r = spend(0, [lootToAttacker], witnessLoot);
    expect(r.accepted).toBe(false);
  });

  it('REJECTS a then-arm spend whose witness contradicts the real outputs', () => {
    const r = spend(1, [lootToAttacker], witnessBondA);
    expect(r.accepted).toBe(false);
  });

  it('REJECTS an else-arm spend whose witness contradicts the real outputs', () => {
    const r = spend(0, [lootToAttacker], witnessBondB);
    expect(r.accepted).toBe(false);
  });
});
