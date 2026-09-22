/**
 * Bounded-exhaustive peephole equivalence sweep (TS-GAP-008).
 *
 * For every rule in `PEEPHOLE_RULES`, emit the rule's PATTERN op-sequence and
 * its REPLACEMENT to Bitcoin Script bytes, execute both through the `ScriptVM`
 * over a script-number edge domain that stresses CScriptNum encoding, and
 * assert an IDENTICAL stack effect: same success flag AND same full final
 * stack (hex). A divergence here is a real peephole soundness bug.
 *
 * This is the empirical bridge for Lean Phase 3b: only 6 of ~28 peephole rules
 * carry Lean idempotence skeletons; this sweep gives operational evidence for
 * all of them (or a clearly-logged, justified skip for the ones whose operands
 * need real crypto / tx-sighash context that the numeric ScriptVM cannot
 * supply).
 *
 * Stack-effect observable: `VMResult` exposes the full final `stack`
 * (Uint8Array[]), so we compare the entire stack — strictly stronger than the
 * stack-top-only comparison sketched in the plan. No VM change was needed.
 */

import { describe, it, expect } from 'vitest';
// @ts-expect-error vitest resolves this via alias (runar-testing is not a tsc dep of runar-compiler)
import { ScriptVM, bytesToHex } from 'runar-testing';
import type { StackOp } from '../ir/index.js';
import { emitMethod } from '../passes/06-emit.js';
import { PEEPHOLE_RULES, type PeepholeRuleSpec } from '../optimizer/peephole-rules.js';
import { optimizeStackIR } from '../optimizer/peephole.js';
import { compile } from '../index.js';

// ---------------------------------------------------------------------------
// Edge domains
// ---------------------------------------------------------------------------

/** Script-number edge domain: zero, ±small, the ±sign-byte boundaries, and
 *  the ±2^31−1 CScriptNum extremes. */
const EDGE_NUM: bigint[] = [
  0n, 1n, -1n, 127n, -127n, 128n, -128n, 255n, -255n, 256n, 65535n,
  2147483647n, -2147483647n,
];

/** Boolean edge domain — the canonical operand set for OP_NOT-idempotence. */
const EDGE_BOOL: bigint[] = [0n, 1n];

/** Bytes edge domain for hash-preimage rules: empty, 1-byte, 32-byte,
 *  and the 520-byte MAX_SCRIPT_ELEMENT_SIZE boundary. */
const EDGE_BYTES: Uint8Array[] = [
  new Uint8Array(0),
  Uint8Array.from([0xab]),
  new Uint8Array(32).fill(0xcd),
  new Uint8Array(520).fill(0xef),
];

// A truthy sentinel parked at the BOTTOM of every witness so (a) `success`
// reflects the rule's own result rather than an incidental empty stack, and
// (b) an underflowing replacement that dips below its declared inputs shows up
// as a full-stack length mismatch.
const SENTINEL: StackOp = { op: 'push', value: 1n };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Turn a StackOp[] into script hex via the real emit entry point. */
function emitOps(ops: StackOp[]): string {
  return emitMethod({ name: 'sweep', ops, maxStackDepth: 0 }).scriptHex;
}

interface Effect {
  success: boolean;
  stack: string[];
}

function runEffect(ops: StackOp[]): Effect {
  const r = new ScriptVM().executeHex(emitOps(ops));
  return { success: r.success, stack: r.stack.map(bytesToHex) };
}

function effectsEqual(a: Effect, b: Effect): boolean {
  if (a.success !== b.success) return false;
  if (a.stack.length !== b.stack.length) return false;
  for (let i = 0; i < a.stack.length; i++) {
    if (a.stack[i] !== b.stack[i]) return false;
  }
  return true;
}

function cartesian(domain: bigint[], k: number): bigint[][] {
  if (k === 0) return [[]];
  const rest = cartesian(domain, k - 1);
  return domain.flatMap((d) => rest.map((r) => [d, ...r]));
}

const push = (v: bigint): StackOp => ({ op: 'push', value: v });
const opc = (code: string): StackOp => ({ op: 'opcode', code });

/**
 * Assert pattern ≡ replacement (same stack effect) for a concrete witness.
 * Throws a precise, reproducible message on the FIRST divergence.
 */
function assertEquivalent(
  ruleName: string,
  label: string,
  witness: StackOp[],
  pattern: StackOp[],
  replacement: StackOp[],
): void {
  const before = runEffect([...witness, ...pattern]);
  const after = runEffect([...witness, ...replacement]);
  if (!effectsEqual(before, after)) {
    throw new Error(
      `peephole rule '${ruleName}' is NOT stack-effect preserving for ${label}\n` +
        `  pattern     → success=${before.success} stack=[${before.stack.join(', ')}]\n` +
        `  replacement → success=${after.success} stack=[${after.stack.join(', ')}]`,
    );
  }
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

describe('peephole rules preserve stack effect (bounded-exhaustive, TS-GAP-008)', () => {
  const covered: string[] = [];
  const skipped: string[] = [];

  for (const rule of PEEPHOLE_RULES) {
    const sweep = rule.sweep;

    if (sweep.kind === 'skip') {
      skipped.push(rule.name);
      it(`${rule.name}: SKIP (${sweep.reason.split(';')[0]})`, () => {
        // Non-silent skip: name the rule + reason so it is visible in output.
        // eslint-disable-next-line no-console
        console.log(`SKIP peephole sweep: ${rule.name} — ${sweep.reason}`);
        expect(true).toBe(true);
      });
      continue;
    }

    covered.push(rule.name);

    it(`${rule.name}: pattern ≡ replacement over edge domain`, () => {
      if (sweep.kind === 'stack') {
        const domain = sweep.domain === 'bool' ? EDGE_BOOL : EDGE_NUM;
        for (const inputs of cartesian(domain, sweep.inputs)) {
          const witness = [SENTINEL, ...inputs.map(push)];
          assertEquivalent(rule.name, `inputs=[${inputs.join(',')}]`, witness, rule.pattern, rule.replacement);
        }
        return;
      }

      if (sweep.kind === 'bytes') {
        for (const val of EDGE_BYTES) {
          const witness: StackOp[] = [SENTINEL, { op: 'push', value: val }];
          assertEquivalent(rule.name, `bytes(len=${val.length})`, witness, rule.pattern, rule.replacement);
        }
        return;
      }

      if (sweep.kind === 'fold-bin') {
        const op = sweep.op;
        for (const a of EDGE_NUM) {
          for (const b of EDGE_NUM) {
            const folded =
              op === 'OP_ADD' ? a + b : op === 'OP_SUB' ? a - b : a * b;
            const pattern = [push(a), push(b), opc(op)];
            const replacement = [push(folded)];
            assertEquivalent(rule.name, `a=${a} b=${b}`, [SENTINEL], pattern, replacement);
          }
        }
        return;
      }

      // fold-chain: push a, OP, push b, OP  ≡  push(a+b), OP  over one base x.
      const op = sweep.op;
      for (const a of EDGE_NUM) {
        for (const b of EDGE_NUM) {
          const pattern = [push(a), opc(op), push(b), opc(op)];
          const replacement = [push(a + b), opc(op)];
          for (const x of EDGE_NUM) {
            assertEquivalent(rule.name, `x=${x} a=${a} b=${b}`, [SENTINEL, push(x)], pattern, replacement);
          }
        }
      }
    });
  }

  it('covers every peephole rule (sweep or documented skip)', () => {
    expect(covered.length + skipped.length).toBe(PEEPHOLE_RULES.length);
    // eslint-disable-next-line no-console
    console.log(
      `peephole bounded-exhaustive: swept ${covered.length}/${PEEPHOLE_RULES.length} rules; ` +
        `skipped ${skipped.length} (${skipped.join(', ') || 'none'})`,
    );
  });
});

// ---------------------------------------------------------------------------
// Documented precondition: OP_NOT, OP_NOT elimination is boolean-idempotence.
// ---------------------------------------------------------------------------

describe('not-not-elim precondition (C17 — the guard that closed TS-GAP-008)', () => {
  const notNot = PEEPHOLE_RULES.find((r) => r.name === 'not-not-elim') as PeepholeRuleSpec;

  it('is a true identity over the full numeric domain — the producer normalises', () => {
    // The rule window now includes the canonical-boolean PRODUCER, so it holds
    // for every operand, not merely the {0,1} edge domain the old 2-op version
    // needed as an unchecked precondition.
    for (const a of EDGE_NUM) {
      for (const b of EDGE_BOOL) {
        assertEquivalent(
          'not-not-elim',
          `a=${a} b=${b}`,
          [SENTINEL, push(a), push(b)],
          notNot.pattern,
          notNot.replacement,
        );
      }
    }
  });

  it('a BARE OP_NOT pair is NOT a numeric identity — which is why the rule carries its producer', () => {
    // This is the divergence the guard exists to prevent: on a non-canonical
    // operand `OP_NOT OP_NOT` normalises to 1 while deleting it leaves 5.
    const bare = [opc('OP_NOT'), opc('OP_NOT')];
    const kept = runEffect([SENTINEL, push(5n), ...bare]);
    const deleted = runEffect([SENTINEL, push(5n)]);
    expect(kept.stack.at(-1)).toBe('01'); // NOT(NOT(5)) = 1
    expect(deleted.stack.at(-1)).toBe('05'); // untouched 5
    expect(effectsEqual(kept, deleted)).toBe(false);
  });

  it('the optimizer therefore leaves a bare OP_NOT pair in place', () => {
    const ops = [push(5n), opc('OP_NOT'), opc('OP_NOT')];
    expect(runEffect(optimizeStackIR(ops))).toEqual(runEffect(ops));
  });
});

// ---------------------------------------------------------------------------
// F-001: numeric-identity rules must not delete ScriptNum validation.
// ---------------------------------------------------------------------------

describe('F-001: PUSH 0;OP_ADD / PUSH 0;OP_SUB / OP_NEGATE;OP_NEGATE keep the opcode', () => {
  // `x + 0`, `x - 0` and `-(-x)` are numeric identities over INTEGERS, but the
  // opcode is not a no-op over STACK ELEMENTS: OP_ADD / OP_SUB / OP_NEGATE
  // decode their operand as a CScriptNum — rejecting a non-minimal encoding —
  // and push back the minimal re-encoding. A witness-supplied bigint parameter
  // reaches the stack with no other normalisation, so deleting the opcode lets
  // a spend succeed (and write raw, non-canonical bytes into state) that the
  // unoptimised script rejects. The edge sweep above cannot see this: its
  // domain is canonical script numbers only.
  //
  // Proves: for each of the three windows, on non-canonical operand encodings
  // (negative zero, non-minimal 0 and 1, a redundant sign byte), the optimised
  // op-sequence has exactly the stack effect of the unoptimised one under the
  // real @bsv/sdk interpreter — in strict-encoding mode (the unoptimised script
  // REJECTS) and in relaxed mode (it NORMALISES the value) — and a compiled
  // contract keeps the opcode in both fold modes.
  // Does NOT prove: anything about the interpreter's numeric SIZE limit
  // (@bsv/sdk enforces none), nor about peephole rules other than these three,
  // nor that other tiers match (their own optimizer tests cover that).
  const NON_CANONICAL: Uint8Array[] = [
    Uint8Array.from([0x80]), // negative zero
    Uint8Array.from([0x00]), // non-minimal 0
    Uint8Array.from([0x01, 0x00]), // non-minimal 1
    Uint8Array.from([0x05, 0x00, 0x00, 0x80]), // non-minimal -5
  ];
  const WINDOWS: Array<[string, StackOp[]]> = [
    ['PUSH 0, OP_ADD', [push(0n), opc('OP_ADD')]],
    ['PUSH 0, OP_SUB', [push(0n), opc('OP_SUB')]],
    ['OP_NEGATE, OP_NEGATE', [opc('OP_NEGATE'), opc('OP_NEGATE')]],
  ];

  for (const [label, window] of WINDOWS) {
    it(`${label}: optimised ≡ unoptimised on non-canonical operands`, () => {
      for (const bytes of NON_CANONICAL) {
        const ops: StackOp[] = [SENTINEL, { op: 'push', value: bytes }, ...window];
        const optimised = optimizeStackIR(ops);
        const hex = bytesToHex(bytes);
        for (const strictEncoding of [true, false]) {
          const run = (o: StackOp[]): Effect => {
            const r = new ScriptVM({ flags: { strictEncoding } }).executeHex(emitOps(o));
            return { success: r.success, stack: r.stack.map(bytesToHex) };
          };
          const before = run(ops);
          // The opcode observably acts on this operand — rejected when strict,
          // re-encoded when relaxed — so deleting it is not an identity.
          if (strictEncoding) expect(before.success, `${label} on ${hex} (strict)`).toBe(false);
          else expect(before.stack.at(-1), `${label} on ${hex} (relaxed)`).not.toBe(hex);
          expect(run(optimised), `${label} on ${hex} (strict=${strictEncoding})`).toEqual(before);
        }
      }
    });
  }

  it('a compiled contract keeps OP_0 OP_ADD, OP_0 OP_SUB and OP_NEGATE OP_NEGATE', () => {
    const source = `import { SmartContract, assert } from 'runar-lang';
export class F001 extends SmartContract {
  readonly t: bigint;
  constructor(t: bigint) { super(t); this.t = t; }
  public unlock(x: bigint, y: bigint, z: bigint) {
    assert(x + 0n === this.t);
    assert(y - 0n === this.t);
    assert(-(-z) === this.t);
  }
}`;
    for (const disableConstantFolding of [true, false]) {
      const r = compile(source, { fileName: 'F001.runar.ts', disableConstantFolding });
      expect(r.success).toBe(true);
      const asm = r.scriptAsm!;
      expect(asm).toContain('OP_0 OP_ADD');
      expect(asm).toContain('OP_0 OP_SUB');
      expect(asm).toContain('OP_NEGATE OP_NEGATE');
    }
  });
});
