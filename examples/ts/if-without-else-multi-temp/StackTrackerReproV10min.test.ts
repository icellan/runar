import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, runDifferentialExecution } from 'runar-testing';

/**
 * R-106 — `if-without-else-multi-temp` had no test in any of the nine formats.
 *
 * It is a stack-tracker repro: two `if` blocks with no `else`, each declaring
 * several temporaries and reassigning locals declared outside them. An
 * if-without-else has to leave the stack in the same shape on both paths, and
 * "several temporaries" is where a tracker that mis-counts them shows up.
 *
 * The witness is built here rather than copied: 46 bytes of prefix, an output
 * count, then two length-prefixed output blobs, which is the layout the
 * contract walks. Building it in the test is what makes the boundary cases
 * below constructible at all.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'StackTrackerReproV10min.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

/** 8-byte amount ‖ 1-byte scriptLen ‖ script. */
function output(script: number[]): Uint8Array {
  return Uint8Array.from([...new Array(8).fill(0), script.length, ...script]);
}
function rawTx(outCount: number, outs: Uint8Array[]): Uint8Array {
  const parts = [new Uint8Array(46), Uint8Array.from([outCount]), ...outs];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    buf.set(p, at);
    at += p.length;
  }
  return buf;
}

const MNEE = output([0x6a, 0x01, 0x02]);
const EXTRA = output([0x51]);
const TX = rawTx(2, [MNEE, EXTRA]);

describe('StackTrackerReproV10min (two if-without-else blocks)', () => {
  it('accepts a tx containing both expected outputs', () => {
    const c = TestContract.fromSource(source, {}, FILE);
    const r = c.call('verifyMneeTxContainsBothOutputs', {
      rawTx: TX,
      expectedMneeOutputBytes: MNEE,
      expectedExtraDataOutputBytes: EXTRA,
    });
    expect(r.success, r.error).toBe(true);
  });

  it('rejects when the second output is not the expected one', () => {
    const other = output([0x52]);
    const tx = rawTx(2, [MNEE, other]);
    const c = TestContract.fromSource(source, {}, FILE);
    expect(
      c.call('verifyMneeTxContainsBothOutputs', {
        rawTx: tx,
        expectedMneeOutputBytes: MNEE,
        expectedExtraDataOutputBytes: EXTRA,
      }).success,
    ).toBe(false);
  });

  it('rejects a single-output tx — the second if simply does not run', () => {
    const tx = rawTx(1, [MNEE]);
    const c = TestContract.fromSource(source, {}, FILE);
    expect(
      c.call('verifyMneeTxContainsBothOutputs', {
        rawTx: tx,
        expectedMneeOutputBytes: MNEE,
        expectedExtraDataOutputBytes: EXTRA,
      }).success,
      'with outCount = 1 the second block is skipped, so foundExtra stays false',
    ).toBe(false);
  });

  it('rejects an output count above the declared bound', () => {
    const tx = rawTx(9, [MNEE, EXTRA]);
    const c = TestContract.fromSource(source, {}, FILE);
    expect(
      c.call('verifyMneeTxContainsBothOutputs', {
        rawTx: tx,
        expectedMneeOutputBytes: MNEE,
        expectedExtraDataOutputBytes: EXTRA,
      }).success,
      'the contract asserts outCount <= 8',
    ).toBe(false);
  });

  it('the interpreter and the ScriptVM agree on the accepting case', () => {
    const r = runDifferentialExecution({
      source,
      fileName: FILE,
      method: 'verifyMneeTxContainsBothOutputs',
      args: [TX, MNEE, EXTRA],
    });
    expect(
      r.agrees,
      `a stack-tracker repro is exactly where source and script drift apart — ` +
        `interpreter=${r.interpreterAccepted} vm=${r.vmAccepted} ` +
        `${r.interpreterError ?? ''} ${r.vmError ?? ''}`,
    ).toBe(true);
  });
});
