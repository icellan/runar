/**
 * Declarative description of the peephole optimizer's rewrite rules.
 *
 * This is a DOCUMENTATION-ONLY mirror of the hand-written matchers in
 * `peephole.ts`. It changes NO runtime behavior — `optimizeStackIR` does not
 * import or consult this table. Its sole purpose is to make each rule's
 * `pattern → replacement` shape enumerable so the bounded-exhaustive
 * equivalence sweep in `__tests__/peephole-exhaustive.test.ts` can execute
 * every rule's op-sequence against its replacement through the `ScriptVM` and
 * assert an identical stack effect (the empirical bridge for Lean Phase 3b,
 * finding TS-GAP-008).
 *
 * Each entry is cross-checked against the corresponding matcher in
 * `peephole.ts`; the `pattern`/`replacement` op arrays are exactly what the
 * matcher inspects and returns (using a representative constant where the
 * matcher fixes one). If a rule is edited in `peephole.ts`, update the peer
 * entry here and the sweep will re-verify it.
 *
 * The `sweep` descriptor tells the test how to exercise a rule:
 *  - `stack`      — the window consumes `inputs` items from the pre-existing
 *                   stack; sweep those over the `domain` edge set.
 *  - `bytes`      — operand is opaque bytes (a hash preimage); sweep over a
 *                   bytes edge domain instead of script numbers.
 *  - `fold-bin`   — `push a, push b, OP` ≡ `push (a OP b)`; sweep the two
 *                   embedded constants `a`,`b` (this is where CScriptNum
 *                   encoding edge cases bite).
 *  - `fold-chain` — `push a, OP, push b, OP` ≡ `push (a+b), OP` over one base
 *                   input; sweep `a`,`b`, and the base.
 *  - `skip`       — the rule's operands require signature / tx-sighash context
 *                   the numeric ScriptVM cannot supply; the fusion equivalence
 *                   is instead covered by the go-sdk real-crypto
 *                   `script_execution_test.go` path (never silently skipped —
 *                   the sweep logs a SKIP line naming the rule + reason).
 */

import type { StackOp } from '../ir/index.js';

const opc = (code: string): StackOp => ({ op: 'opcode', code });
const push = (value: bigint): StackOp => ({ op: 'push', value });

export type PeepholeSweep =
  | { kind: 'stack'; inputs: number; domain: 'num' | 'bool' }
  | { kind: 'bytes'; inputs: number }
  | { kind: 'fold-bin'; op: 'OP_ADD' | 'OP_SUB' | 'OP_MUL' }
  | { kind: 'fold-chain'; op: 'OP_ADD' | 'OP_SUB' }
  | { kind: 'skip'; reason: string };

export interface PeepholeRuleSpec {
  /** Human-readable rule name (matches the comment in peephole.ts). */
  name: string;
  /** The op-window the matcher inspects (representative constants inlined). */
  pattern: StackOp[];
  /** The ops the matcher returns for that window. */
  replacement: StackOp[];
  /**
   * Base stack items the window consumes below its own pushes. 0 for rules
   * whose operands are all pattern-internal pushes (dead-push, fold-bin).
   */
  stackInputs: number;
  /** How the bounded-exhaustive sweep should exercise this rule. */
  sweep: PeepholeSweep;
}

/**
 * Faithful description of every rule in `peephole.ts`, in source order.
 */
export const PEEPHOLE_RULES: PeepholeRuleSpec[] = [
  // PUSH x, DROP → [] (any push; representative value 7).
  {
    name: 'push-drop-elim',
    pattern: [push(7n), { op: 'drop' }],
    replacement: [],
    stackInputs: 0,
    sweep: { kind: 'stack', inputs: 0, domain: 'num' },
  },
  // DUP, DROP → []
  {
    name: 'dup-drop-elim',
    pattern: [{ op: 'dup' }, { op: 'drop' }],
    replacement: [],
    stackInputs: 1,
    sweep: { kind: 'stack', inputs: 1, domain: 'num' },
  },
  // SWAP, SWAP → []
  {
    name: 'swap-swap-elim',
    pattern: [{ op: 'swap' }, { op: 'swap' }],
    replacement: [],
    stackInputs: 2,
    sweep: { kind: 'stack', inputs: 2, domain: 'num' },
  },
  // PUSH 1, OP_ADD → OP_1ADD
  {
    name: 'push1-add-to-1add',
    pattern: [push(1n), opc('OP_ADD')],
    replacement: [opc('OP_1ADD')],
    stackInputs: 1,
    sweep: { kind: 'stack', inputs: 1, domain: 'num' },
  },
  // PUSH 1, OP_SUB → OP_1SUB
  {
    name: 'push1-sub-to-1sub',
    pattern: [push(1n), opc('OP_SUB')],
    replacement: [opc('OP_1SUB')],
    stackInputs: 1,
    sweep: { kind: 'stack', inputs: 1, domain: 'num' },
  },
  // PUSH 0, OP_ADD → [] (x + 0 = x)
  {
    name: 'push0-add-elim',
    pattern: [push(0n), opc('OP_ADD')],
    replacement: [],
    stackInputs: 1,
    sweep: { kind: 'stack', inputs: 1, domain: 'num' },
  },
  // PUSH 0, OP_SUB → [] (x - 0 = x)
  {
    name: 'push0-sub-elim',
    pattern: [push(0n), opc('OP_SUB')],
    replacement: [],
    stackInputs: 1,
    sweep: { kind: 'stack', inputs: 1, domain: 'num' },
  },
  // OP_NOT, OP_NOT → []  (double logical negation)
  //
  // IMPORTANT: this is boolean-idempotence, NOT numeric identity. For a
  // non-canonical operand (e.g. 5) `OP_NOT OP_NOT` normalises to 1 while the
  // empty replacement leaves 5. The compiler only emits OP_NOT for `!` / `!==`
  // whose operand is bool-typed, so the sweep exercises it over the boolean
  // edge domain {0,1} — its actual precondition. See the exhaustive test's
  // note and TS-GAP-008 report for the residual (narrow) risk if a
  // non-canonical witness-supplied bool ever reaches this rule.
  {
    name: 'not-not-elim',
    pattern: [opc('OP_NOT'), opc('OP_NOT')],
    replacement: [],
    stackInputs: 1,
    sweep: { kind: 'stack', inputs: 1, domain: 'bool' },
  },
  // OP_NEGATE, OP_NEGATE → []  (numeric identity for all integers)
  {
    name: 'negate-negate-elim',
    pattern: [opc('OP_NEGATE'), opc('OP_NEGATE')],
    replacement: [],
    stackInputs: 1,
    sweep: { kind: 'stack', inputs: 1, domain: 'num' },
  },
  // OP_EQUAL, OP_VERIFY → OP_EQUALVERIFY
  {
    name: 'equal-verify-fuse',
    pattern: [opc('OP_EQUAL'), opc('OP_VERIFY')],
    replacement: [opc('OP_EQUALVERIFY')],
    stackInputs: 2,
    sweep: { kind: 'stack', inputs: 2, domain: 'num' },
  },
  // OP_CHECKSIG, OP_VERIFY → OP_CHECKSIGVERIFY
  {
    name: 'checksig-verify-fuse',
    pattern: [opc('OP_CHECKSIG'), opc('OP_VERIFY')],
    replacement: [opc('OP_CHECKSIGVERIFY')],
    stackInputs: 2,
    sweep: {
      kind: 'skip',
      reason:
        'OP_CHECKSIG needs sig+pubkey+tx-sighash context; ScriptVM uses a mock always-true checksig, so accept/reject cannot be exercised over a numeric edge domain. The X;VERIFY≡XVERIFY fusion is covered by the go-sdk real-crypto script_execution_test.go path.',
    },
  },
  // OP_NUMEQUAL, OP_VERIFY → OP_NUMEQUALVERIFY
  {
    name: 'numequal-verify-fuse',
    pattern: [opc('OP_NUMEQUAL'), opc('OP_VERIFY')],
    replacement: [opc('OP_NUMEQUALVERIFY')],
    stackInputs: 2,
    sweep: { kind: 'stack', inputs: 2, domain: 'num' },
  },
  // OP_CHECKMULTISIG, OP_VERIFY → OP_CHECKMULTISIGVERIFY
  {
    name: 'checkmultisig-verify-fuse',
    pattern: [opc('OP_CHECKMULTISIG'), opc('OP_VERIFY')],
    replacement: [opc('OP_CHECKMULTISIGVERIFY')],
    stackInputs: 0,
    sweep: {
      kind: 'skip',
      reason:
        'OP_CHECKMULTISIG needs real crypto plus a multi-element multisig stack layout (dummy/sigs/m/keys/n); not expressible over a numeric edge domain. Fusion equivalence is covered by the go-sdk real-crypto script_execution_test.go path.',
    },
  },
  // OP_DUP, OP_DROP → []  (opcode form of dup-drop)
  {
    name: 'opdup-opdrop-elim',
    pattern: [opc('OP_DUP'), opc('OP_DROP')],
    replacement: [],
    stackInputs: 1,
    sweep: { kind: 'stack', inputs: 1, domain: 'num' },
  },
  // OVER, OVER → OP_2DUP
  {
    name: 'over-over-to-2dup',
    pattern: [{ op: 'over' }, { op: 'over' }],
    replacement: [opc('OP_2DUP')],
    stackInputs: 2,
    sweep: { kind: 'stack', inputs: 2, domain: 'num' },
  },
  // DROP, DROP → OP_2DROP
  {
    name: 'drop-drop-to-2drop',
    pattern: [{ op: 'drop' }, { op: 'drop' }],
    replacement: [opc('OP_2DROP')],
    stackInputs: 2,
    sweep: { kind: 'stack', inputs: 2, domain: 'num' },
  },
  // PUSH 0, Roll{0} → []  (roll depth 0 is a no-op on the top item)
  {
    name: 'push0-roll0-elim',
    pattern: [push(0n), { op: 'roll', depth: 0 }],
    replacement: [],
    stackInputs: 1,
    sweep: { kind: 'stack', inputs: 1, domain: 'num' },
  },
  // PUSH 1, Roll{1} → Swap
  {
    name: 'push1-roll1-to-swap',
    pattern: [push(1n), { op: 'roll', depth: 1 }],
    replacement: [{ op: 'swap' }],
    stackInputs: 2,
    sweep: { kind: 'stack', inputs: 2, domain: 'num' },
  },
  // PUSH 2, Roll{2} → Rot
  {
    name: 'push2-roll2-to-rot',
    pattern: [push(2n), { op: 'roll', depth: 2 }],
    replacement: [{ op: 'rot' }],
    stackInputs: 3,
    sweep: { kind: 'stack', inputs: 3, domain: 'num' },
  },
  // PUSH 0, Pick{0} → Dup
  {
    name: 'push0-pick0-to-dup',
    pattern: [push(0n), { op: 'pick', depth: 0 }],
    replacement: [{ op: 'dup' }],
    stackInputs: 1,
    sweep: { kind: 'stack', inputs: 1, domain: 'num' },
  },
  // PUSH 1, Pick{1} → Over
  {
    name: 'push1-pick1-to-over',
    pattern: [push(1n), { op: 'pick', depth: 1 }],
    replacement: [{ op: 'over' }],
    stackInputs: 2,
    sweep: { kind: 'stack', inputs: 2, domain: 'num' },
  },
  // OP_SHA256, OP_SHA256 → OP_HASH256
  {
    name: 'sha256-sha256-to-hash256',
    pattern: [opc('OP_SHA256'), opc('OP_SHA256')],
    replacement: [opc('OP_HASH256')],
    stackInputs: 1,
    sweep: { kind: 'bytes', inputs: 1 },
  },
  // PUSH 0, OP_NUMEQUAL → OP_NOT  (both compute x == 0)
  {
    name: 'push0-numequal-to-not',
    pattern: [push(0n), opc('OP_NUMEQUAL')],
    replacement: [opc('OP_NOT')],
    stackInputs: 1,
    sweep: { kind: 'stack', inputs: 1, domain: 'num' },
  },
  // PUSH(a), PUSH(b), OP_ADD → PUSH(a+b)
  {
    name: 'fold-add',
    pattern: [push(3n), push(7n), opc('OP_ADD')],
    replacement: [push(10n)],
    stackInputs: 0,
    sweep: { kind: 'fold-bin', op: 'OP_ADD' },
  },
  // PUSH(a), PUSH(b), OP_SUB → PUSH(a-b)
  {
    name: 'fold-sub',
    pattern: [push(7n), push(3n), opc('OP_SUB')],
    replacement: [push(4n)],
    stackInputs: 0,
    sweep: { kind: 'fold-bin', op: 'OP_SUB' },
  },
  // PUSH(a), PUSH(b), OP_MUL → PUSH(a*b)
  {
    name: 'fold-mul',
    pattern: [push(3n), push(7n), opc('OP_MUL')],
    replacement: [push(21n)],
    stackInputs: 0,
    sweep: { kind: 'fold-bin', op: 'OP_MUL' },
  },
  // PUSH(a), OP_ADD, PUSH(b), OP_ADD → PUSH(a+b), OP_ADD
  {
    name: 'fold-chain-add',
    pattern: [push(3n), opc('OP_ADD'), push(7n), opc('OP_ADD')],
    replacement: [push(10n), opc('OP_ADD')],
    stackInputs: 1,
    sweep: { kind: 'fold-chain', op: 'OP_ADD' },
  },
  // PUSH(a), OP_SUB, PUSH(b), OP_SUB → PUSH(a+b), OP_SUB
  {
    name: 'fold-chain-sub',
    pattern: [push(3n), opc('OP_SUB'), push(7n), opc('OP_SUB')],
    replacement: [push(10n), opc('OP_SUB')],
    stackInputs: 1,
    sweep: { kind: 'fold-chain', op: 'OP_SUB' },
  },
];
