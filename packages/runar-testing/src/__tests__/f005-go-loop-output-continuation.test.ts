/**
 * F-005 / CL-BUG-186 — the Go tier must not compile an output intrinsic inside
 * a `for` body into a continuation that leaves that output out of hashOutputs.
 *
 * `lowerForStatement` (compilers/go/frontend/anf_lower.go) lowers the loop body
 * into a sub-context and drops it. Every addOutput / addRawOutput / addDataOutput
 * in the body registers its ref on that sub-context, so the refs never reach the
 * method's output list — the only input to the auto-injected continuation
 * `hash256(cat(outputs..., change)) === extractOutputHash(txPreimage)`.
 *
 * R-127's validator rule is meant to keep such contracts out of lowering, but
 * it is a syntactic search that does not look inside array literals. The body
 * `const xs = [this.addRawOutput(PAY_SATS, this.payee)];` passes parse,
 * validate and typecheck, and the Go CLI compiled it to a continuation over
 * cat(<state output>, <change>) — the two per-iteration payouts are not in it.
 *
 * THE ATTACK, run on @bsv/sdk's production `Spend` against a real BIP-143
 * preimage: a spend that simply omits both payouts and keeps their value as
 * change. Before the fix the Go-compiled covenant ACCEPTED it (and rejected the
 * honest spend that pays them). After the fix the Go compiler refuses the
 * contract with R-127's diagnostic, so no such script can be deployed.
 *
 * A control contract with the same two payouts written at the TOP level of the
 * method runs through the identical harness: it accepts the honest spend and
 * rejects the omission. That proves the harness builds the outputs, the change
 * and the preimage correctly, so the bypass result is not a harness artefact.
 *
 * What this proves: the Go tier no longer emits a script whose continuation
 * lets a spender drop loop-body outputs, for the array-literal shape that slips
 * past R-127 and for the plain shape R-127 already catches.
 * What it does not prove: anything about the other six tiers. The TS reference
 * compiles the array-literal shape too (its validator shares the gap); that is
 * reported to the dispatcher, not fixed here.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
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

const REPO = join(__dirname, '..', '..', '..', '..');
const GO_BIN = join(REPO, 'compilers', 'go', 'runar-go');
const TMP = mkdtempSync(join(tmpdir(), 'runar-f005-'));

const PKH_PAYEE = 'aa'.repeat(20);
const PKH_CHANGE = 'cc'.repeat(20);
const PAY_SATS = 700;
const STATE_SATS = 1000;
const INPUT_SATS = 10_000;
const CHANGE_SATS = 5_000;

const HEAD = `import { StatefulSmartContract, ByteString } from 'runar-lang';
`;

/** The bypass: two loop payouts hidden from R-127 inside an array literal. */
const LOOP_ARRAY_LITERAL = `${HEAD}
class LoopPay extends StatefulSmartContract {
  count: bigint = 0n;
  readonly payee: ByteString = '76a914${PKH_PAYEE}88ac';

  constructor() { super(); }

  public pay() {
    this.addOutput(${STATE_SATS}n, this.count + 1n);
    for (let i = 0n; i < 2n; i++) {
      const xs = [this.addRawOutput(${PAY_SATS}n, this.payee)];
    }
  }
}
`;

/** The brief's literal shape (R-127 already refuses it). */
const LOOP_DIRECT = LOOP_ARRAY_LITERAL.replace(
  `const xs = [this.addRawOutput(${PAY_SATS}n, this.payee)];`,
  `this.addRawOutput(${PAY_SATS}n, this.payee);`,
);

/** Control: the same two payouts at the method's top level. */
const TOP_LEVEL_CONTROL = `${HEAD}
class LoopPay extends StatefulSmartContract {
  count: bigint = 0n;
  readonly payee: ByteString = '76a914${PKH_PAYEE}88ac';

  constructor() { super(); }

  public pay() {
    this.addOutput(${STATE_SATS}n, this.count + 1n);
    this.addRawOutput(${PAY_SATS}n, this.payee);
    this.addRawOutput(${PAY_SATS}n, this.payee);
  }
}
`;

const REFUSAL = 'cannot be called inside a loop body';

// --- Go compiler -------------------------------------------------------------

let seq = 0;
function goCompile(source: string): { artifact?: RunarArtifact; output: string } {
  if (!existsSync(GO_BIN)) {
    throw new Error(`missing ${GO_BIN} — build it with: cd compilers/go && go build -o runar-go .`);
  }
  const file = join(TMP, `LoopPay-${seq++}.runar.ts`);
  writeFileSync(file, source);
  const r = spawnSync(GO_BIN, ['--source', file], {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  if (r.error) throw new Error(`runar-go failed to start: ${r.error.message}`);
  const output = `${r.stdout ?? ''}${r.stderr ?? ''}`;
  if (r.status !== 0) return { output };
  return { artifact: JSON.parse(r.stdout) as RunarArtifact, output };
}

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
    { satoshis: PAY_SATS, scriptHex: p2pkh(PKH_PAYEE) },
    { satoshis: CHANGE_SATS, scriptHex: p2pkh(PKH_CHANGE) },
  ];
}

/** Both payouts dropped; their value is pocketed as extra change. */
const STOLEN_CHANGE = CHANGE_SATS + 2 * PAY_SATS;
function omittingOutputs(artifact: RunarArtifact): TxOutput[] {
  return [
    { satoshis: STATE_SATS, scriptHex: stateScript(artifact, 1n) },
    { satoshis: STOLEN_CHANGE, scriptHex: p2pkh(PKH_CHANGE) },
  ];
}

describe('F-005: Go loop-body outputs and the continuation hash', () => {
  it('control: top-level payouts — honest spend ACCEPTED, omission REJECTED', () => {
    const { artifact, output } = goCompile(TOP_LEVEL_CONTROL);
    expect(artifact, output).toBeDefined();
    const honest = spend(artifact!, honestOutputs(artifact!), CHANGE_SATS);
    expect(honest.error, honest.error).toBeUndefined();
    expect(honest.accepted).toBe(true);
    const omit = spend(artifact!, omittingOutputs(artifact!), STOLEN_CHANGE);
    expect(omit.accepted).toBe(false);
  });

  it('array-literal loop payouts: no Go-compiled script lets the spender drop them', () => {
    const { artifact, output } = goCompile(LOOP_ARRAY_LITERAL);
    if (artifact) {
      // Pre-fix path. The attack must not verify, and the honest spend must.
      const omit = spend(artifact, omittingOutputs(artifact), STOLEN_CHANGE);
      expect(
        omit.accepted,
        'Go-compiled covenant ACCEPTED a spend that omits both loop payouts',
      ).toBe(false);
      const honest = spend(artifact, honestOutputs(artifact), CHANGE_SATS);
      expect(honest.accepted, 'Go-compiled covenant REJECTED the honest spend').toBe(true);
    }
    // Loop outputs cannot be committed per iteration (one ANF name, N unrolled
    // slots), so the only correct outcome is a refusal.
    expect(artifact, 'Go compiled an output intrinsic inside a loop body').toBeUndefined();
    expect(output).toContain(REFUSAL);
    expect(output).toContain('addRawOutput');
  });

  it("the brief's direct shape is refused", () => {
    const { artifact, output } = goCompile(LOOP_DIRECT);
    expect(artifact).toBeUndefined();
    expect(output).toContain(REFUSAL);
  });
});

/**
 * N-006 — the same attack on the TS reference, through its public API.
 *
 * compile() refuses the array-literal shape at R-127 (F-063 taught the
 * validator to walk array literals). But `parse`, `lowerToANF` and
 * `compileFromANF` are all public exports, and that chain runs no validator:
 * before the N-006 backstop, `lowerForStatement` dropped the loop body's output
 * refs and `compileFromANF` emitted a covenant whose continuation hash covers
 * only the state output and the change. The script is run here on the same
 * `Spend` harness as the Go tier, with the ABI/state layout taken from the
 * TS-compiled top-level control (identical method signature and state field).
 *
 * What this proves: no TS pass-4 path emits a script that lets a spender drop
 * loop-body outputs, even when validation is skipped; top-level payouts still
 * accept the honest spend and reject the omission.
 * What it does not prove: the other five tiers; their pass-4 backstops are
 * pinned by unit tests in each tier's own suite.
 */
describe('N-006: TS reference, validator skipped (parse -> lowerToANF -> compileFromANF)', () => {
  function tsControl(): RunarArtifact {
    const r = compile(TOP_LEVEL_CONTROL, { fileName: 'LoopPay.runar.ts', disableConstantFolding: true });
    expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
    return r.artifact!;
  }

  it('control: TS top-level payouts — honest spend ACCEPTED, omission REJECTED', () => {
    const artifact = tsControl();
    const honest = spend(artifact, honestOutputs(artifact), CHANGE_SATS);
    expect(honest.error, honest.error).toBeUndefined();
    expect(honest.accepted).toBe(true);
    expect(spend(artifact, omittingOutputs(artifact), STOLEN_CHANGE).accepted).toBe(false);
  });

  it('array-literal loop payouts: no unvalidated TS lowering lets the spender drop them', () => {
    const p = parse(LOOP_ARRAY_LITERAL, 'LoopPay.runar.ts');
    expect(p.errors).toEqual([]);
    let refusal: string | undefined;
    let artifact: RunarArtifact | undefined;
    try {
      const r = compileFromANF(lowerToANF(p.contract!));
      artifact = { ...tsControl(), script: r.scriptHex, codeSeparatorIndex: r.codeSeparatorIndices![0] };
    } catch (e) {
      refusal = e instanceof Error ? e.message : String(e);
    }
    if (artifact) {
      // Pre-fix path: the attack must not verify.
      const omit = spend(artifact, omittingOutputs(artifact), STOLEN_CHANGE);
      expect(
        omit.accepted,
        'TS-lowered covenant ACCEPTED a spend that omits both loop payouts',
      ).toBe(false);
    }
    expect(artifact, 'TS lowered an output intrinsic inside a loop body').toBeUndefined();
    expect(refusal).toContain(REFUSAL);
    expect(refusal).toContain('addRawOutput');
  });
});
