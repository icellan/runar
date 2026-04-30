/**
 * RED test for issue #36 — `lowerIf` branch reconciliation drops branch-private
 * temps and duplicate-named slots.
 *
 * https://github.com/icellan/runar/issues/36
 *
 * The verbatim StackTrackerReproV10min contract from the issue compiles to
 * bytecode that PASSES under `TestContract.fromSource` (interpreter on the AST)
 * but FAILS under `@bsv/sdk`'s `Spend.validate` with
 *   "OP_SPLIT requires the first stack item to be a non-negative number…"
 * at PC 139.
 *
 * Root cause: `StackMap.namedSlots()` returns `Set<string>`, which collapses
 * both anonymous branch-private temps (null slots) and duplicate-named slots
 * (e.g. an outer-protected `p` that is PICK'd via `bringToTop(consume=false)`
 * and then reassigned inside the branch). The four reconciliation sites in
 * `lowerIf` under-count and the post-ENDIF `OP_PUSH d + OP_ROLL d+1 + OP_DROP`
 * cleanup hits the wrong slot at runtime. Downstream `OP_SPLIT` then aborts.
 *
 * This test reproduces the divergence end-to-end through the compiled script.
 */

import { describe, it, expect } from 'vitest';
import { ScriptExecutionContract } from '../script-execution.js';
import { TestContract } from '../test-contract.js';

// ---------------------------------------------------------------------------
// Verbatim contract source from issue #36
// ---------------------------------------------------------------------------

const SOURCE = `
import { SmartContract, assert, substr, bin2num, num2bin, cat } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class StackTrackerReproV10min extends SmartContract {
  constructor() { super(); }

  public verifyMneeTxContainsBothOutputs(
    rawTx: ByteString,
    expectedMneeOutputBytes: ByteString,
    expectedExtraDataOutputBytes: ByteString,
  ) {
    let p: bigint = 46n;

    const outCount: bigint = bin2num(cat(substr(rawTx, p, 1n), num2bin(0n, 1n)));
    assert(outCount < 0xfdn);
    assert(outCount <= 8n);
    p = p + 1n;

    let foundMnee: boolean = false;
    let foundExtra: boolean = false;

    if (0n < outCount) {
      const scriptLen: bigint = bin2num(cat(substr(rawTx, p + 8n, 1n), num2bin(0n, 1n)));
      assert(scriptLen < 0xfdn);
      const blobLen: bigint = 8n + 1n + scriptLen;
      const blob: ByteString = substr(rawTx, p, blobLen);
      if (blob === expectedMneeOutputBytes) { foundMnee = true; }
      if (blob === expectedExtraDataOutputBytes) { foundExtra = true; }
      p = p + blobLen;
    }
    if (1n < outCount) {
      const scriptLen: bigint = bin2num(cat(substr(rawTx, p + 8n, 1n), num2bin(0n, 1n)));
      assert(scriptLen < 0xfdn);
      const blobLen: bigint = 8n + 1n + scriptLen;
      const blob: ByteString = substr(rawTx, p, blobLen);
      if (blob === expectedMneeOutputBytes) { foundMnee = true; }
      if (blob === expectedExtraDataOutputBytes) { foundExtra = true; }
      p = p + blobLen;
    }

    assert(foundMnee);
    assert(foundExtra);
  }

  public other(x: ByteString) { assert(x === x); }
}

export default StackTrackerReproV10min;
`;

// ---------------------------------------------------------------------------
// Synthetic 116-byte 1-input / 2-output BSV tx from the issue body.
//
// Layout (matches the contract's p = 46n start-of-output-count assumption):
//   4   version       01000000
//   1   inputCount    01
//   32  prev txid     aa*32
//   4   prev vout     00000000
//   1   scriptLen     00            (empty input script — total input = 41 bytes)
//   4   sequence      ffffffff
//   1   outputCount   02            ← p starts here at offset 46
//   34  output 0      e803000000000000 19 76a914 aa*20 88ac
//   31  output 1      0000000000000000 16 6a14 bb*20
//   4   locktime      00000000
//
// Total: 4+1+32+4+1+4+1+34+31+4 = 116 bytes.
// ---------------------------------------------------------------------------

const RAW_TX_HEX =
  '01000000' +
  '01' +
  'aa'.repeat(32) +
  '00000000' +
  '00' +
  'ffffffff' +
  '02' +
  // output 0: 1000 sats P2PKH(aa*20)
  'e803000000000000' + '19' + '76a914' + 'aa'.repeat(20) + '88ac' +
  // output 1: 0 sats OP_RETURN(bb*20)
  '0000000000000000' + '16' + '6a14' + 'bb'.repeat(20) +
  '00000000';

// 34-byte output-0 blob (value || scriptLen || script)
const EXPECTED_MNEE_HEX =
  'e803000000000000' + '19' + '76a914' + 'aa'.repeat(20) + '88ac';

// 31-byte output-1 blob (value || scriptLen || script)
const EXPECTED_EXTRA_HEX =
  '0000000000000000' + '16' + '6a14' + 'bb'.repeat(20);

// Sanity: byte counts before sending into the compiler.
const TX_BYTES = RAW_TX_HEX.length / 2;
const MNEE_BYTES = EXPECTED_MNEE_HEX.length / 2;
const EXTRA_BYTES = EXPECTED_EXTRA_HEX.length / 2;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('issue #36 — lowerIf reconciliation drops branch-private temps + dup-named slots', () => {
  it('synthetic tx is the expected 116/34/31 byte shape', () => {
    expect(TX_BYTES).toBe(116);
    expect(MNEE_BYTES).toBe(34);
    expect(EXTRA_BYTES).toBe(31);
  });

  it('interpreter accepts the V10min walker (control — proves AST semantics are sound)', () => {
    const c = TestContract.fromSource(
      SOURCE,
      {},
      'StackTrackerReproV10min.runar.ts',
    );
    const r = c.call('verifyMneeTxContainsBothOutputs', {
      rawTx: RAW_TX_HEX,
      expectedMneeOutputBytes: EXPECTED_MNEE_HEX,
      expectedExtraDataOutputBytes: EXPECTED_EXTRA_HEX,
    });
    expect(r.success).toBe(true);
  });

  it('compiled script accepts the V10min walker through @bsv/sdk Spend.validate', () => {
    const c = ScriptExecutionContract.fromSource(
      SOURCE,
      {},
      'StackTrackerReproV10min.runar.ts',
    );
    const result = c.execute('verifyMneeTxContainsBothOutputs', [
      RAW_TX_HEX,
      EXPECTED_MNEE_HEX,
      EXPECTED_EXTRA_HEX,
    ]);
    expect(result.success, result.error).toBe(true);
  });
});
