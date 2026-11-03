/**
 * F-355 — coverage gap: multiple `checkPreimage` calls in one method, each of
 * which emits its own `OP_CODESEPARATOR` (05-stack-lower.ts's non-`_codePart`
 * scheme — see `scriptLevelCodeSeparator` in `lowerToStack`), had no test
 * that actually ran a program with more than one call through a real
 * transaction signature check. The existing coverage was:
 *   - `05-stack-lower.test.ts` locates the FIRST separator with `findIndex`
 *     (only ever one call per probe).
 *   - `audit-2026-04-30-remaining.test.ts` (F7) compiles a `checkPreimage`
 *     inside a branch/loop/helper and asserts only `not.toThrow()` — it never
 *     executes the compiled bytes, so it cannot tell a correct per-call
 *     scriptCode from one that accidentally reused another call's.
 *
 * This file closes that gap for the "one check at statement level, one check
 * inside an `if` arm" shape by running the COMPILED script through `@bsv/sdk`'s
 * `Spend` (via `newConsensusSpend`), each `OP_CHECKSIGVERIFY` deriving its
 * signature from a BIP-143 preimage whose `subscript` is built from THIS
 * call's own `codeSeparatorIndices` entry (`artifact.codeSeparatorIndices[i]
 * + 1` — one past the `OP_CODESEPARATOR` byte itself; empirically confirmed
 * against this interpreter, see the cross tests below).
 *
 * Proves: for `TwoChecks.go`, the compiler emits exactly two call-site
 * separators (one at statement level, one inside the `if` arm); the spend
 * succeeds when each check's preimage is built against ITS OWN separator's
 * scriptCode; and it fails when either preimage is built against the OTHER
 * call's scriptCode instead — i.e. the two checks are not accidentally
 * sharing or swapping their separator-relative scriptCode. Also covers the
 * untaken-arm path (`flag=false`): the first check alone still binds
 * correctly and the second call's separator is simply never executed.
 *
 * Does not prove: the `scriptLevelCodeSeparator=true` scheme (stateful
 * contracts using `_codePart`), where every method shares ONE separator at
 * script offset 1 and `push_codesep_index` always resolves to 1 regardless
 * of how many `checkPreimage` calls a method makes — a different construction
 * with a different correctness argument, out of scope for this item. Does
 * not prove anything about a check inside a loop with more than one
 * iteration consuming the SAME preimage binding — the affine checker already
 * refuses reuse of a `SigHashPreimage` value across iterations
 * (`03-typecheck.test.ts:1067`), so that shape never reaches codegen. Does
 * not prove behaviour under any sighash flag other than the default
 * ALL|FORKID, or anything about the field-extractor builtins
 * (`extractScriptCode` etc.) — those parse bytes out of the PUSHED preimage
 * and do not depend on separator placement at all.
 */

import { describe, it, expect } from 'vitest';
import { LockingScript, TransactionSignature } from '@bsv/sdk';
import { ScriptExecutionContract } from '../script-execution.js';
import { CONSENSUS_SPEND_CONTEXT } from '../consensus-spend.js';

const SOURCE = `
import { SmartContract, assert, checkPreimage } from 'runar-lang';
import type { SigHashPreimage } from 'runar-lang';

class TwoChecks extends SmartContract {
  constructor() { super(); }
  public go(pre1: SigHashPreimage, flag: boolean, pre2: SigHashPreimage) {
    assert(checkPreimage(pre1));
    if (flag) {
      assert(checkPreimage(pre2));
    } else {
      assert(true);
    }
  }
}
`;

const SCOPE = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;

function contract(): ScriptExecutionContract {
  return ScriptExecutionContract.fromSource(SOURCE, {}, 'TwoChecks.runar.ts');
}

/**
 * Build the genuine BIP-143 preimage whose scriptCode is the compiled
 * script's bytes starting one past the `OP_CODESEPARATOR` at `sepByteOffset`.
 * `+1` skips the separator opcode byte itself — confirmed empirically: with
 * `+0` (including the separator byte) OP_CHECKSIGVERIFY rejects every case;
 * only `+1` validates the matched (call, separator) pairs.
 */
function preimageHexForSeparator(scriptHex: string, sepByteOffset: number): string {
  const scriptBytes = Buffer.from(scriptHex, 'hex');
  const subscriptBytes = scriptBytes.subarray(sepByteOffset + 1);
  const subscript = LockingScript.fromBinary(Array.from(subscriptBytes));
  const preimageBytes = TransactionSignature.formatBytes({
    ...CONSENSUS_SPEND_CONTEXT,
    otherInputs: [],
    outputs: [],
    subscript,
    scope: SCOPE,
  });
  return Buffer.from(preimageBytes as unknown as number[]).toString('hex');
}

describe('F-355: multiple checkPreimage calls in one method, run through @bsv/sdk Spend', () => {
  it('compiles to exactly two call-site OP_CODESEPARATORs, in source order', () => {
    const c = contract();
    const indices = c.artifact.codeSeparatorIndices;
    expect(indices).toBeDefined();
    expect(indices!.length).toBe(2);
    expect(indices![1]).toBeGreaterThan(indices![0]!);
  });

  it('flag=true: accepts when each check is paired with its own scriptCode', () => {
    const c = contract();
    const [sep1, sep2] = c.artifact.codeSeparatorIndices!;
    const pre1 = preimageHexForSeparator(c.scriptHex, sep1!);
    const pre2 = preimageHexForSeparator(c.scriptHex, sep2!);
    const r = c.execute('go', [pre1, true, pre2]);
    expect(r.error, r.error).toBeUndefined();
    expect(r.success).toBe(true);
  });

  it("flag=true: rejects when the SECOND check is paired with the FIRST call's scriptCode", () => {
    const c = contract();
    const [sep1, sep2] = c.artifact.codeSeparatorIndices!;
    const pre1 = preimageHexForSeparator(c.scriptHex, sep1!);
    const pre2WrongSep = preimageHexForSeparator(c.scriptHex, sep1!); // should be sep2
    expect(sep2).toBeDefined();
    const r = c.execute('go', [pre1, true, pre2WrongSep]);
    expect(r.success).toBe(false);
  });

  it("flag=true: rejects when the FIRST check is paired with the SECOND call's scriptCode", () => {
    const c = contract();
    const [sep1, sep2] = c.artifact.codeSeparatorIndices!;
    const pre1WrongSep = preimageHexForSeparator(c.scriptHex, sep2!); // should be sep1
    const pre2 = preimageHexForSeparator(c.scriptHex, sep2!);
    expect(sep1).toBeDefined();
    const r = c.execute('go', [pre1WrongSep, true, pre2]);
    expect(r.success).toBe(false);
  });

  it('flag=false: accepts on the first check alone (the if-arm, and its separator, never execute)', () => {
    const c = contract();
    const [sep1] = c.artifact.codeSeparatorIndices!;
    const pre1 = preimageHexForSeparator(c.scriptHex, sep1!);
    // pre2 is pushed (the method still takes 3 args) but never read on this path.
    const r = c.execute('go', [pre1, false, '']);
    expect(r.error, r.error).toBeUndefined();
    expect(r.success).toBe(true);
  });

  it("flag=false: rejects when the first check is paired with the second call's scriptCode", () => {
    const c = contract();
    const [, sep2] = c.artifact.codeSeparatorIndices!;
    const pre1WrongSep = preimageHexForSeparator(c.scriptHex, sep2!);
    const r = c.execute('go', [pre1WrongSep, false, '']);
    expect(r.success).toBe(false);
  });
});
