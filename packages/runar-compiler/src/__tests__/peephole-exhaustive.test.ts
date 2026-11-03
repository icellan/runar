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
 * all of them. The two signature-verification fusions, whose operands need
 * real crypto / tx-sighash context the numeric edge domain cannot supply, are
 * swept with real signed witnesses on the @bsv/sdk `Spend` engine (F-226; they
 * used to be a `SKIP` whose body was `expect(true).toBe(true)`).
 *
 * Stack-effect observable: `VMResult` exposes the full final `stack`
 * (Uint8Array[]), so we compare the entire stack — strictly stronger than the
 * stack-top-only comparison sketched in the plan. No VM change was needed.
 */

import { describe, it, expect } from 'vitest';
// @ts-expect-error vitest resolves this via alias (runar-testing is not a tsc dep of runar-compiler)
import { ScriptVM, bytesToHex, testKey } from 'runar-testing';
import {
  Hash,
  LockingScript,
  PrivateKey,
  Spend,
  TransactionSignature,
  UnlockingScript,
} from '@bsv/sdk';
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

/**
 * F-345: `PEEPHOLE_RULES` is a documentation mirror that `optimizeStackIR`
 * never reads, so comparing its pattern against its replacement says nothing
 * about the runtime matcher. Also run what `optimizeStackIR` really emits for
 * the pattern window: it must behave like the unfused pattern (and so like the
 * documented replacement) on this witness, and it must be the documented
 * rewrite — `optimizeStackIR(pattern)` equals `optimizeStackIR(replacement)`,
 * i.e. the replacement up to any later peephole step (fold-chain to a sum of 1
 * goes on to OP_1ADD). The second check is what catches a matcher that was
 * deleted or no longer fires: the untouched pattern behaves like itself.
 */
function assertRuntimeRule(
  ruleName: string,
  label: string,
  witness: StackOp[],
  pattern: StackOp[],
  replacement: StackOp[],
): void {
  assertEquivalent(ruleName, label, witness, pattern, replacement);
  const optimised = optimizeStackIR(pattern);
  const before = runEffect([...witness, ...pattern]);
  const actual = runEffect([...witness, ...optimised]);
  if (!effectsEqual(before, actual)) {
    throw new Error(
      `optimizeStackIR's rewrite for '${ruleName}' is NOT stack-effect preserving for ${label}\n` +
        `  emitted     → ${JSON.stringify(optimised, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v))}\n` +
        `  pattern     → success=${before.success} stack=[${before.stack.join(', ')}]\n` +
        `  optimised   → success=${actual.success} stack=[${actual.stack.join(', ')}]`,
    );
  }
  expect(optimised, `optimizeStackIR no longer applies '${ruleName}' to its window (${label})`).toEqual(
    optimizeStackIR(replacement),
  );
}

// ---------------------------------------------------------------------------
// Real-crypto witnesses for the signature-verification fusions (F-226)
// ---------------------------------------------------------------------------

/** One spend context, used both to SIGN and to VERIFY, so the two cannot
 *  drift. Version 1: the version every SDK-built transaction carries. */
const SIG_CTX = {
  sourceTXID: '00'.repeat(32),
  sourceOutputIndex: 0,
  sourceSatoshis: 100_000,
  transactionVersion: 1,
  inputIndex: 0,
  inputSequence: 0xffffffff,
  lockTime: 0,
} as const;

const hexBytes = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, 'hex'));
const pushBytes = (b: Uint8Array): StackOp => ({ op: 'push', value: b });
const pubKeyOf = (name: string): Uint8Array => hexBytes(testKey(name).pubKey);

/** Real DER+sighash-byte signature by `keyName` over the BIP-143 digest of a
 *  spend of `lockingHex` (the subscript; the fragments carry no
 *  OP_CODESEPARATOR). */
function signFor(keyName: string, lockingHex: string): Uint8Array {
  const scope = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;
  const preimage = TransactionSignature.formatBytes({
    ...SIG_CTX,
    otherInputs: [],
    outputs: [],
    subscript: LockingScript.fromHex(lockingHex),
    scope,
  });
  // OP_CHECKSIG hashes twice; `sign()` does one sha256 internally.
  const digest = Hash.sha256(Array.from(preimage));
  const sig = PrivateKey.fromHex(testKey(keyName).privKey).sign(digest);
  return new Uint8Array(new TransactionSignature(sig.r, sig.s, scope).toChecksigFormat());
}

/** A witness slot: a real signature by a named key over THIS arm's locking
 *  script, or fixed bytes (empty sig, non-null dummy). */
type SigSlot = { signWith: string } | Uint8Array;

/** Run `unlocking` against `locking` on the real @bsv/sdk engine. A failed
 *  script's residual stack has no consensus meaning, so it is reported empty;
 *  on success the full final stack is reported. */
function runSigSpend(slots: SigSlot[], locking: StackOp[], isRelaxed: boolean): Effect {
  const lockingHex = emitOps(locking);
  const unlocking = slots.map((s) => pushBytes(s instanceof Uint8Array ? s : signFor(s.signWith, lockingHex)));
  const spend = new Spend({
    ...SIG_CTX,
    lockingScript: LockingScript.fromHex(lockingHex),
    unlockingScript: UnlockingScript.fromHex(emitOps(unlocking)),
    otherInputs: [],
    outputs: [],
    isRelaxed,
  });
  let success = false;
  try {
    success = spend.validate();
  } catch {
    success = false;
  }
  return { success, stack: success ? spend.stack.map((b) => bytesToHex(Uint8Array.from(b))) : [] };
}

interface SigCase {
  label: string;
  slots: SigSlot[];
  /** Expected verdict of the UNOPTIMISED pattern under strict consensus rules —
   *  pins that each witness really exercises accept or reject. */
  strictAccept: boolean;
}

const EMPTY = new Uint8Array(0);

/** Witness set + locking-script framing per signature fusion kind. The
 *  trailing `push 1` makes the VERIFY form's success observable and keeps the
 *  clean-stack rule satisfied; a fused op that leaves a residue fails it. */
const SIG_SWEEPS: Record<'checksig' | 'checkmultisig', { frame: (ops: StackOp[]) => StackOp[]; cases: SigCase[] }> = {
  checksig: {
    frame: (ops) => [pushBytes(pubKeyOf('alice')), ...ops, push(1n)],
    cases: [
      { label: 'valid sig by the key', slots: [{ signWith: 'alice' }], strictAccept: true },
      { label: 'well-formed sig by the wrong key', slots: [{ signWith: 'bob' }], strictAccept: false },
      { label: 'empty sig', slots: [EMPTY], strictAccept: false },
    ],
  },
  checkmultisig: {
    frame: (ops) => [
      push(2n), pushBytes(pubKeyOf('alice')), pushBytes(pubKeyOf('bob')), push(2n),
      ...ops,
      push(1n),
    ],
    cases: [
      { label: '2-of-2 valid', slots: [EMPTY, { signWith: 'alice' }, { signWith: 'bob' }], strictAccept: true },
      { label: 'sigs in the wrong order', slots: [EMPTY, { signWith: 'bob' }, { signWith: 'alice' }], strictAccept: false },
      { label: 'one sig by a third key', slots: [EMPTY, { signWith: 'alice' }, { signWith: 'charlie' }], strictAccept: false },
      { label: 'empty sigs', slots: [EMPTY, EMPTY, EMPTY], strictAccept: false },
      { label: 'non-null dummy', slots: [Uint8Array.from([0x01]), { signWith: 'alice' }, { signWith: 'bob' }], strictAccept: false },
    ],
  },
};

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

describe('peephole rules preserve stack effect (bounded-exhaustive, TS-GAP-008)', () => {
  const covered: string[] = [];

  for (const rule of PEEPHOLE_RULES) {
    const sweep = rule.sweep;

    covered.push(rule.name);

    if (sweep.kind === 'checksig' || sweep.kind === 'checkmultisig') {
      // F-226. Proves: for each witness (valid, and each well-formed way of
      // being invalid), the fused form — BOTH the documented replacement and
      // what `optimizeStackIR` actually emits for the window — has the same
      // verdict as the unfused pattern on the real @bsv/sdk engine, in strict
      // and relaxed mode, and the same final stack on success; and the
      // unfused pattern accepts exactly the valid witness under strict rules.
      // Does NOT prove: equivalence for sighash types other than ALL|FORKID,
      // for m-of-n shapes other than 1-of-1 / 2-of-2, or inside a script that
      // carries OP_CODESEPARATOR.
      const { frame, cases } = SIG_SWEEPS[sweep.kind];
      it(`${rule.name}: pattern ≡ replacement on real signed witnesses`, () => {
        const optimised = optimizeStackIR(rule.pattern);
        // F-345: the runtime matcher still performs the documented fusion.
        expect(optimised, `optimizeStackIR no longer applies '${rule.name}' to its window`).toEqual(
          optimizeStackIR(rule.replacement),
        );
        for (const c of cases) {
          for (const isRelaxed of [false, true]) {
            const mode = isRelaxed ? 'relaxed' : 'strict';
            const before = runSigSpend(c.slots, frame(rule.pattern), isRelaxed);
            if (!isRelaxed) expect(before.success, `${rule.name} pattern on ${c.label} (strict)`).toBe(c.strictAccept);
            expect(runSigSpend(c.slots, frame(rule.replacement), isRelaxed), `${rule.name} replacement on ${c.label} (${mode})`).toEqual(before);
            expect(runSigSpend(c.slots, frame(optimised), isRelaxed), `${rule.name} optimizeStackIR on ${c.label} (${mode})`).toEqual(before);
          }
        }
      });
      continue;
    }

    // F-345. Proves: for every witness in the edge domain, the documented
    // replacement AND what `optimizeStackIR` actually emits for the window
    // have the unfused pattern's full stack effect on the ScriptVM, and the
    // runtime matcher still performs the documented rewrite. Does NOT prove:
    // anything about windows embedded in longer programs (overlapping matches,
    // raw_bytes spans, if-branches), operands outside the edge domains, or
    // other tiers' optimizers.
    it(`${rule.name}: pattern ≡ replacement ≡ optimizeStackIR(pattern) over edge domain`, () => {
      if (sweep.kind === 'stack') {
        const domain = sweep.domain === 'bool' ? EDGE_BOOL : EDGE_NUM;
        for (const inputs of cartesian(domain, sweep.inputs)) {
          const witness = [SENTINEL, ...inputs.map(push)];
          assertRuntimeRule(rule.name, `inputs=[${inputs.join(',')}]`, witness, rule.pattern, rule.replacement);
        }
        return;
      }

      if (sweep.kind === 'bytes') {
        for (const val of EDGE_BYTES) {
          const witness: StackOp[] = [SENTINEL, { op: 'push', value: val }];
          assertRuntimeRule(rule.name, `bytes(len=${val.length})`, witness, rule.pattern, rule.replacement);
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
            assertRuntimeRule(rule.name, `a=${a} b=${b}`, [SENTINEL], pattern, replacement);
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
            assertRuntimeRule(rule.name, `x=${x} a=${a} b=${b}`, [SENTINEL, push(x)], pattern, replacement);
          }
        }
      }
    });
  }

  it('covers every peephole rule', () => {
    expect(covered.length).toBe(PEEPHOLE_RULES.length);
    // eslint-disable-next-line no-console
    console.log(`peephole bounded-exhaustive: swept ${covered.length}/${PEEPHOLE_RULES.length} rules`);
  });
});

// ---------------------------------------------------------------------------
// N-298: F-392's opcode-string form (push(depth), {op:'opcode', code:'OP_ROLL'
// | 'OP_PICK'}) for the Roll{0,1,2}/Pick{0,1} small-depth rules.
//
// `PEEPHOLE_RULES` (peephole-rules.ts) only encodes the TYPED form of each
// window (`{op:'roll', depth:0}`, `{op:'pick', depth:0}`, ...), so the sweep
// above never drives `optimizeStackIR` through the opcode-string branch each
// of these five matchers also accepts (`isOpcode(ops[1], 'OP_ROLL' |
// 'OP_PICK')`). mutation id `peephole-f392-roll0-opcode-form-matches-pick`
// flips the Roll{0} rule's opcode check from 'OP_ROLL' to 'OP_PICK', which
// makes it wrongly intercept `push(0n), {op:'opcode', code:'OP_PICK'}` (which
// must become `dup`, not be erased) and simultaneously stops matching its own
// `push(0n), {op:'opcode', code:'OP_ROLL'}` window at all. Both are real
// matcher divergences caught below by running `optimizeStackIR` for real
// (`assertRuntimeRule`), not by comparing the declarative mirror to itself.
//
// Proves: for each of the five small-depth rules, the opcode-string form of
// its window is matched by the SAME rule (and none other), and
// `optimizeStackIR`'s output for it has the typed form's documented stack
// effect over the numeric edge domain.
// Does NOT prove: anything about an opcode-string Roll/Pick at a depth this
// corpus does not target (the rules only special-case depth 0/1/2), or about
// an opcode-string window embedded in a longer program.
// ---------------------------------------------------------------------------
describe('F-392: opcode-string-form Roll/Pick windows match the SAME rule as their typed form', () => {
  const OPCODE_FORM_CASES: Array<{
    name: string;
    depth: bigint;
    code: 'OP_ROLL' | 'OP_PICK';
    replacement: StackOp[];
  }> = [
    { name: 'opcode-form-roll0', depth: 0n, code: 'OP_ROLL', replacement: [] },
    { name: 'opcode-form-roll1', depth: 1n, code: 'OP_ROLL', replacement: [{ op: 'swap' }] },
    { name: 'opcode-form-roll2', depth: 2n, code: 'OP_ROLL', replacement: [{ op: 'rot' }] },
    { name: 'opcode-form-pick0', depth: 0n, code: 'OP_PICK', replacement: [{ op: 'dup' }] },
    { name: 'opcode-form-pick1', depth: 1n, code: 'OP_PICK', replacement: [{ op: 'over' }] },
  ];

  for (const c of OPCODE_FORM_CASES) {
    it(`push(${c.depth}n), {opcode:${c.code}} ≡ replacement over edge domain`, () => {
      const pattern: StackOp[] = [push(c.depth), opc(c.code)];
      for (const inputs of cartesian(EDGE_NUM, Number(c.depth) + 1)) {
        const witness = [SENTINEL, ...inputs.map(push)];
        assertRuntimeRule(c.name, `inputs=[${inputs.join(',')}]`, witness, pattern, c.replacement);
      }
    });
  }
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
