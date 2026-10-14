import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * N-264 — seven-tier gate: call depth x nesting must not overflow the host
 * stack.
 *
 * Private methods are inlined at every call site, so F-213's per-method nesting
 * bound (MAX_SOURCE_NESTING = 128) and N-180's call-depth bound
 * (MAX_CALL_DEPTH = 128) compose MULTIPLICATIVELY: a chain of D helpers that
 * each call the next under K nested ifs is D*K nested ifs after inlining, with
 * every method inside both bounds. Measured on the CLIs before the fix at
 * D=32 x 120 (3,840 nested ifs):
 *
 *   rust   SIGABRT (stack overflow); on a 2 MiB thread stack already at D=8
 *   zig    segfault (stack overflow in stack_lower's if-lowering) from D=16
 *   java   uncaught StackOverflowError from D=16
 *   ruby   SystemStackError from D=16
 *   python `maximum recursion depth exceeded`; ts `Maximum call stack size exceeded`
 *   go     compiled (goroutine stacks grow)
 *
 * User decision R106: lower iteratively, with an explicit work stack, in every
 * tier. The source is remediation-logs/N-180/compgen.py's shape; the pinned
 * digest is sha256 of the script hex the UNMODIFIED Go compiler printed for it
 * (at 5b75534ec, before any N-264 change), whose D=8 output all seven tiers
 * already agreed on.
 *
 * Proves, for every available tier in both fold modes: D=32 x 120 compiles —
 * a real verdict, no signal, within the harness timeout — to Go's bytes.
 * Does not prove: the deepest admissible chain (D=127; every tier's own N-264
 * test pins it except Zig, whose quadratic arm-splicing memory is a separate
 * defect), other surfaces (the composition is surface-independent: it happens
 * after parsing), nor that Go's deep output is right beyond agreeing at D=8.
 */

/** Each case spawns every tier once; the deep compile itself takes seconds. */
const CASE_TIMEOUT_MS = 600_000;
const GO_DIGEST_D32 = 'edf53286692322f6787832929bb6aaf18d2b686e9bef2ad4683cbaf3e8a25fc2';

/** remediation-logs/N-180/compgen.py, verbatim. */
function comp(d: number, k: number): string {
  const body = (i: number) =>
    '  let r: bigint = x;\n'
    + Array.from({ length: k }, (_, j) => `  if (x > ${j}n) {\n`).join('')
    + `  r = this.m${i + 1}(x);\n` + '  }\n'.repeat(k)
    + '  return r;\n';
  const ms = Array.from({ length: d }, (_, i) => ` private m${i}(x: bigint): bigint {\n${body(i)} }\n`).join('');
  return "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n"
    + ms + ` private m${d}(x: bigint): bigint { return x; }\n public verify(a: bigint) { assert(this.m0(a) == this.t); }\n}\n`;
}

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

let file = '';
beforeAll(() => {
  file = join(mkdtempSync(join(tmpdir(), 'n264-composite-')), 'comp32k120.runar.ts');
  writeFileSync(file, comp(32, 120));
});

describe('N-264 seven-tier composite call depth x nesting', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    it(`D=32 x 120 (${mode}): every tier compiles it to Go's bytes`, () => {
      for (const tier of tiers) {
        const hex = compileHex(tier, file);
        expect(createHash('sha256').update(hex).digest('hex'), `${tier.id} on D=32 x 120`).toBe(GO_DIGEST_D32);
      }
    }, CASE_TIMEOUT_MS);
  }
});
