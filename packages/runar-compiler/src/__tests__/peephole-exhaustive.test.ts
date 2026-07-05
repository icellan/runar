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

describe('not-not-elim precondition (documents TS-GAP-008 residual)', () => {
  const notNot = PEEPHOLE_RULES.find((r) => r.name === 'not-not-elim') as PeepholeRuleSpec;

  it('is a true identity over the boolean domain {0,1}', () => {
    for (const x of EDGE_BOOL) {
      assertEquivalent('not-not-elim', `x=${x}`, [SENTINEL, push(x)], notNot.pattern, notNot.replacement);
    }
  });

  it('is NOT a numeric identity — normalises a non-canonical bool (e.g. 5 → 1)', () => {
    // Removing OP_NOT OP_NOT is only sound because the compiler emits it on
    // bool-typed operands. On a non-canonical operand the two op-sequences
    // diverge numerically; this asserts that divergence so the precondition
    // is documented, not hidden.
    const pattern = runEffect([SENTINEL, push(5n), ...notNot.pattern]);
    const replacement = runEffect([SENTINEL, push(5n), ...notNot.replacement]);
    expect(pattern.stack.at(-1)).toBe('01'); // NOT(NOT(5)) = 1
    expect(replacement.stack.at(-1)).toBe('05'); // untouched 5
    expect(effectsEqual(pattern, replacement)).toBe(false);
  });
});
