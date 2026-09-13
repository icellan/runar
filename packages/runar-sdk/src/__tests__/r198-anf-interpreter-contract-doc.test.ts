import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * R-198 / CL-DOC-017 — the ANF-interpreter contract document contradicted
 * itself, and the code.
 *
 * One section read "`add_raw_output` simulation — supported (pass-through
 * only)". Three others said the opposite: the per-kind matrix listed it as
 * **skipped** in TS, Zig and Java; the "intentional skips" summary grouped it
 * with the on-chain-only kinds; and the closing notes called it "explicitly out
 * of scope across all seven SDKs". The implementations agree with the FIRST
 * one — every interpreter that implements the kind records the output and
 * mirrors it into the ordered state-class list (finding G1).
 *
 * A document that contradicts itself is worse than one that is merely stale:
 * a reader who finds the wrong half stops there. This pins the corrected half
 * against the code, so the claim cannot drift back while the behaviour stays.
 */

const REPO = resolve(__dirname, '../../../..');
const DOC = resolve(REPO, 'packages/runar-sdk/docs/anf-interpreter-contract.md');

/** Does an interpreter really record add_raw_output? */
function recordsRawOutput(relPath: string, marker: RegExp): boolean {
  return marker.test(readFileSync(resolve(REPO, relPath), 'utf-8'));
}

describe('R-198 the ANF-interpreter contract matches the interpreters', () => {
  it('the interpreters do record add_raw_output (else the doc would be right)', () => {
    expect(
      recordsRawOutput('packages/runar-sdk/src/anf-interpreter.ts', /case 'add_raw_output':[\s\S]{0,900}rawOutputs\.push/),
      'the TS interpreter no longer records add_raw_output — re-check the doc before editing this test',
    ).toBe(true);
    expect(
      recordsRawOutput(
        'packages/runar-java/src/main/java/runar/lang/sdk/AnfInterpreter.java',
        /case "add_raw_output":[\s\S]{0,900}rawOutputs\.add/,
      ),
    ).toBe(true);
  });

  it('the document no longer calls add_raw_output skipped or out of scope', () => {
    const text = readFileSync(DOC, 'utf-8');
    const offenders = text
      .split('\n')
      .map((line, i) => ({ line, n: i + 1 }))
      .filter(({ line }) => /add_raw_output/.test(line))
      // The corrected text quotes the old claims to explain what changed, so
      // only an assertion counts — a line that says it IS skipped or IS out of
      // scope, not one that says it used to say so.
      .filter(({ line }) => /\*\*skipped\*\*|explicitly out of scope|is \*\*not\*\* recorded/.test(line))
      .filter(({ line }) => !/R-198|previously said|used to say|corrected this line|NOT among them/.test(line));

    expect(
      offenders.map((o) => `anf-interpreter-contract.md:${o.n}`),
      'the document still says add_raw_output is skipped / out of scope, but every ' +
        'interpreter records it (anf-interpreter.ts, AnfInterpreter.java, ' +
        'sdk_anf_interpreter.zig). Fix the document or the code, not this test.',
    ).toEqual([]);
  });
});
