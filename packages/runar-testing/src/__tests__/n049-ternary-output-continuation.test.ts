/**
 * N-049 (EXT-2 "TernaryToll") — an output intrinsic inside a ternary arm must
 * never compile to a continuation that leaves that output out of hashOutputs.
 *
 * `lowerTernaryExpr` lowered each arm into a sub-context whose output refs were
 * dropped, so `c ? this.addRawOutput(p, payee) : this.addRawOutput(p, refund)`
 * built the payout but the auto-injected continuation
 * `hash256(cat(outputs..., change)) === extractOutputHash(txPreimage)` covered
 * only the state output and the change.
 *
 * THE ATTACK, run on @bsv/sdk's production `Spend` against a real BIP-143
 * preimage: a spend that simply omits the payout and keeps its value as change.
 * Before the fix the TS-compiled covenant ACCEPTED it. After the fix the TS
 * reference refuses the contract (pass 2, and pass 4 when the validator is
 * skipped), so no such script can be deployed.
 *
 * The CONTROL is the same payout written as an if/else statement, whose
 * lowering merges each arm's output refs into the parent. It runs through the
 * identical harness and must accept the honest spend and reject the omission,
 * which also proves the harness builds the outputs, change and preimage
 * correctly.
 *
 * What this proves: the TS reference emits no script that lets a spender drop
 * a ternary-arm payout, through compile() or the unvalidated public API, and
 * the if/else form commits to its payout on chain.
 * What it does not prove: the other six tiers (their refusals are pinned by
 * conformance negative N174 and each tier's own unit tests; the if/else
 * control compiles byte-identically in all seven per
 * conformance/negatives/ternary-output-control.test.ts).
 */

import { describe, it, expect } from 'vitest';
import {
  LockingScript,
  UnlockingScript,
  Script,
  TransactionSignature,
} from '@bsv/sdk';
import { newConsensusSpend, CONSENSUS_TX_VERSION } from '../consensus-spend.js';
import { serializeState } from 'runar-sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { compile, parse, lowerToANF, compileFromANF } from 'runar-compiler';

const PKH_PAYEE = 'aa'.repeat(20);
const PKH_REFUND = 'bb'.repeat(20);
const PKH_CHANGE = 'cc'.repeat(20);
const PAY_SATS = 700;
const STATE_SATS = 1000;
const INPUT_SATS = 10_000;
const CHANGE_SATS = 5_000;

const contract = (payout: string) => `import { StatefulSmartContract, ByteString } from 'runar-lang';

class TernaryPay extends StatefulSmartContract {
  count: bigint = 0n;
  readonly payee: ByteString = '76a914${PKH_PAYEE}88ac';
  readonly refund: ByteString = '76a914${PKH_REFUND}88ac';

  constructor() { super(); }

  public pay() {
    this.addOutput(${STATE_SATS}n, this.count + 1n);
${payout}
  }
}
`;

/** The finding's shape: the payout chosen by a ternary over two intrinsics. */
const TERNARY = contract(
  `    this.count >= 0n ? this.addRawOutput(${PAY_SATS}n, this.payee) : this.addRawOutput(${PAY_SATS}n, this.refund);`,
);

/** Control: the same payout as an if/else statement. */
const IF_ELSE = contract(
  `    if (this.count >= 0n) {
      this.addRawOutput(${PAY_SATS}n, this.payee);
    } else {
      this.addRawOutput(${PAY_SATS}n, this.refund);
    }`,
);

const REFUSAL = 'cannot be called inside a conditional (ternary) expression arm';

// --- serialisation helpers ---------------------------------------------------

function p2pkh(pkh: string): string {
  return '76a914' + pkh + '88ac';
}

function pushData(hex: string): string {
  const n = hex.length / 2;
  if (n === 0) return '00';
  if (n < 0x4c) return n.toString(16).padStart(2, '0') + hex;
  if (n <= 0xff) return '4c' + n.toString(16).padStart(2, '0') + hex;
  if (n <= 0xffff) {
    return '4d' + (n & 0xff).toString(16).padStart(2, '0') +
      ((n >> 8) & 0xff).toString(16).padStart(2, '0') + hex;
  }
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return '4e' + b.toString('hex') + hex;
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

// --- harness -----------------------------------------------------------------

const SIGHASH_ALL_FORKID = 0x41;

const TX_CONTEXT = {
  sourceTXID: '11'.repeat(32),
  sourceOutputIndex: 0,
  sourceSatoshis: INPUT_SATS,
  // F-055: version 1, as every SDK-built tx; version 2 puts Spend in relaxed mode.
  transactionVersion: CONSENSUS_TX_VERSION,
  otherInputs: [] as never[],
  inputIndex: 0,
  inputSequence: 0xffffffff,
  lockTime: 0,
};

interface TxOutput {
  satoshis: number;
  scriptHex: string;
}

function stateScript(artifact: RunarArtifact, count: bigint): string {
  return artifact.script + '6a' + serializeState(artifact.stateFields!, { count });
}

/**
 * Spend the covenant (state count = 0) on the real `Spend` engine with the
 * given transaction outputs. `changeSats` is the `_changeAmount` witness; the
 * change output itself must be among `outputs` for an honest spend.
 */
function spend(
  artifact: RunarArtifact,
  outputs: TxOutput[],
  changeSats: number,
): { accepted: boolean; error?: string } {
  const lockingHex = stateScript(artifact, 0n);
  const sep = artifact.codeSeparatorIndex;
  const subscriptHex = sep === undefined ? lockingHex : lockingHex.slice((sep + 1) * 2);
  const txOutputs = outputs.map((o) => ({
    satoshis: o.satoshis,
    lockingScript: LockingScript.fromHex(o.scriptHex),
  }));
  const preimageHex = Buffer.from(
    TransactionSignature.formatBytes({
      ...TX_CONTEXT,
      outputs: txOutputs as never,
      subscript: Script.fromHex(subscriptHex) as never,
      scope: SIGHASH_ALL_FORKID,
    }) as unknown as number[],
  ).toString('hex');

  // Stateful unlock layout (runar-sdk buildStatefulPrefix):
  // [_codePart] _changePKH _changeAmount txPreimage.
  const method = artifact.abi.methods.find((m) => m.name === 'pay')!;
  expect(method.params.map((p) => p.name)).toEqual(['_changePKH', '_changeAmount', 'txPreimage']);
  expect((method as { usesCodePart?: boolean }).usesCodePart).toBe(true);
  const unlockingHex =
    pushData(artifact.script) +
    pushData(PKH_CHANGE) + pushData(scriptNumber(changeSats)) + pushData(preimageHex);

  try {
    const s = newConsensusSpend({
      ...TX_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      outputs: txOutputs as never,
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
    });
    return { accepted: s.validate() };
  } catch (e) {
    return { accepted: false, error: e instanceof Error ? e.message : String(e) };
  }
}

function honestOutputs(artifact: RunarArtifact): TxOutput[] {
  return [
    { satoshis: STATE_SATS, scriptHex: stateScript(artifact, 1n) },
    { satoshis: PAY_SATS, scriptHex: p2pkh(PKH_PAYEE) },
    { satoshis: CHANGE_SATS, scriptHex: p2pkh(PKH_CHANGE) },
  ];
}

/** The payout dropped; its value is pocketed as extra change. */
const STOLEN_CHANGE = CHANGE_SATS + PAY_SATS;
function omittingOutputs(artifact: RunarArtifact): TxOutput[] {
  return [
    { satoshis: STATE_SATS, scriptHex: stateScript(artifact, 1n) },
    { satoshis: STOLEN_CHANGE, scriptHex: p2pkh(PKH_CHANGE) },
  ];
}

function tsCompile(source: string) {
  return compile(source, { fileName: 'TernaryPay.runar.ts', disableConstantFolding: true });
}

describe('N-049: ternary-arm outputs and the continuation hash (TS reference)', () => {
  it('control: if/else payout — honest spend ACCEPTED, omission REJECTED', () => {
    const r = tsCompile(IF_ELSE);
    expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
    const artifact = r.artifact!;
    const honest = spend(artifact, honestOutputs(artifact), CHANGE_SATS);
    expect(honest.error, honest.error).toBeUndefined();
    expect(honest.accepted).toBe(true);
    expect(spend(artifact, omittingOutputs(artifact), STOLEN_CHANGE).accepted).toBe(false);
  });

  it('ternary payout: compile() emits no script that lets the spender drop it', () => {
    const r = tsCompile(TERNARY);
    if (r.success && r.artifact) {
      // Pre-fix path: the attack must not verify.
      const omit = spend(r.artifact, omittingOutputs(r.artifact), STOLEN_CHANGE);
      expect(omit.accepted, 'TS-compiled covenant ACCEPTED a spend that omits the ternary payout').toBe(false);
    }
    expect(r.success, 'TS compiled an output intrinsic inside a ternary arm').toBe(false);
    expect(r.diagnostics.map((d) => d.message).join('\n')).toContain(REFUSAL);
  });

  it('ternary payout: the unvalidated public API (parse -> lowerToANF -> compileFromANF) refuses too', () => {
    const p = parse(TERNARY, 'TernaryPay.runar.ts');
    expect(p.errors).toEqual([]);
    let refusal: string | undefined;
    let artifact: RunarArtifact | undefined;
    try {
      const out = compileFromANF(lowerToANF(p.contract!));
      const control = tsCompile(IF_ELSE).artifact!;
      artifact = { ...control, script: out.scriptHex, codeSeparatorIndex: out.codeSeparatorIndices![0] };
    } catch (e) {
      refusal = e instanceof Error ? e.message : String(e);
    }
    if (artifact) {
      const omit = spend(artifact, omittingOutputs(artifact), STOLEN_CHANGE);
      expect(omit.accepted, 'TS-lowered covenant ACCEPTED a spend that omits the ternary payout').toBe(false);
    }
    expect(artifact, 'TS lowered an output intrinsic inside a ternary arm').toBeUndefined();
    expect(refusal).toContain(REFUSAL);
  });
});
