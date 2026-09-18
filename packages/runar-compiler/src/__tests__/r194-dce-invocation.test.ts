import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * R-194 / CL-GAP-004 — `optimizer/dce.ts` described itself as "the canonical,
 * standalone DCE pass" and is not standalone.
 *
 * Its only caller is `optimizeEC` in `optimizer/anf-ec.ts`, at the end of the
 * function and AFTER `if (!anyChanged) return program;`. A program the EC
 * optimizer does not touch is therefore never DCE'd. Go's `anf_optimize.go`
 * does the same, so there is no parity risk — the architecture claim was simply
 * false, and a false claim about where a pass runs is how the next person
 * reasons wrongly about what reaches codegen.
 *
 * The gate turns out to be load-bearing. Measured by moving the call ahead of
 * the early exit: the TS tier then fails to COMPILE 11 of the 78 conformance
 * fixtures. Not byte movement — outright failure. So DCE as written removes
 * bindings stack lowering still needs, and "make it standalone" is a defect to
 * fix inside DCE before it is a wiring change (N-140).
 *
 * This test pins the two facts the header now states, so the description and
 * the code cannot drift apart again.
 */

const SRC = resolve(__dirname, '..', 'optimizer');

describe('R-194 the DCE header describes where DCE actually runs', () => {
  it('the header no longer claims to be a standalone pass', () => {
    const dce = readFileSync(resolve(SRC, 'dce.ts'), 'utf8');
    const header = dce.slice(0, dce.indexOf('*/'));
    expect(
      header,
      'dce.ts calls itself standalone again; its only caller is still optimizeEC',
    ).not.toMatch(/standalone DCE pass/);
  });

  it('optimizeEC is still the only caller, and still calls it after the early exit', () => {
    const ec = readFileSync(resolve(SRC, 'anf-ec.ts'), 'utf8');
    const earlyExit = ec.indexOf('if (!anyChanged) return program;');
    const call = ec.indexOf('eliminateDeadBindings(result)');
    expect(earlyExit, 'the anyChanged early exit is gone').toBeGreaterThan(-1);
    expect(call, 'optimizeEC no longer calls eliminateDeadBindings').toBeGreaterThan(-1);
    expect(
      call,
      'the DCE call moved ahead of the early exit. That is the change N-140 ' +
        'describes, and it breaks 11 of 78 conformance fixtures as written — ' +
        'fix DCE first, then move the call, then update dce.ts and this test.',
    ).toBeGreaterThan(earlyExit);
  });

  it('the header names the caller, so a reader does not have to grep', () => {
    const dce = readFileSync(resolve(SRC, 'dce.ts'), 'utf8');
    expect(dce.slice(0, dce.indexOf('*/'))).toMatch(/anf-ec\.ts/);
  });
});
