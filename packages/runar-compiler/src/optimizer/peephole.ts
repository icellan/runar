/**
 * Peephole optimizer — runs on Stack IR before emission.
 *
 * Scans for short sequences of stack operations that can be replaced with
 * fewer or cheaper opcodes. Applies rules iteratively until a fixed point
 * is reached (no more changes).
 */

import type { StackOp, PushOp, OpcodeOp } from '../ir/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isPush(op: StackOp): op is PushOp {
  return op.op === 'push';
}

function isOpcode(op: StackOp, code?: string): op is OpcodeOp {
  if (op.op !== 'opcode') return false;
  if (code !== undefined) return op.code === code;
  return true;
}

function isPushBigInt(op: StackOp, n: bigint): boolean {
  return isPush(op) && typeof op.value === 'bigint' && op.value === n;
}

function isPushZero(op: StackOp): boolean {
  return isPushBigInt(op, 0n);
}

function isPushOne(op: StackOp): boolean {
  return isPushBigInt(op, 1n);
}

// ---------------------------------------------------------------------------
// Peephole rules
// ---------------------------------------------------------------------------

/** A peephole rule: matches a window of ops and returns a replacement (or null). */
interface PeepholeRule {
  /** Number of ops this rule inspects. */
  windowSize: number;
  /** Try to match and return replacement ops, or null if no match. */
  match(ops: StackOp[]): StackOp[] | null;
}

const rules: PeepholeRule[] = [
  // -------------------------------------------------------------------------
  // Dead value elimination: PUSH x, DROP → remove both
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (isPush(ops[0]!) && ops[1]!.op === 'drop') {
        return [];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // DUP, DROP → remove both
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (ops[0]!.op === 'dup' && ops[1]!.op === 'drop') {
        return [];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // SWAP, SWAP → remove both (identity)
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (ops[0]!.op === 'swap' && ops[1]!.op === 'swap') {
        return [];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // PUSH 1, OP_ADD → OP_1ADD
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (isPushOne(ops[0]!) && isOpcode(ops[1]!, 'OP_ADD')) {
        return [{ op: 'opcode', code: 'OP_1ADD' }];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // PUSH 1, OP_SUB → OP_1SUB
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (isPushOne(ops[0]!) && isOpcode(ops[1]!, 'OP_SUB')) {
        return [{ op: 'opcode', code: 'OP_1SUB' }];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // PUSH 0, OP_ADD → remove both (identity: x + 0 = x)
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (isPushZero(ops[0]!) && isOpcode(ops[1]!, 'OP_ADD')) {
        return [];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // PUSH 0, OP_SUB → remove both (identity: x - 0 = x)
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (isPushZero(ops[0]!) && isOpcode(ops[1]!, 'OP_SUB')) {
        return [];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // OP_NOT, OP_NOT → remove both (double negation)
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (isOpcode(ops[0]!, 'OP_NOT') && isOpcode(ops[1]!, 'OP_NOT')) {
        return [];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // OP_NEGATE, OP_NEGATE → remove both (double negation)
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (isOpcode(ops[0]!, 'OP_NEGATE') && isOpcode(ops[1]!, 'OP_NEGATE')) {
        return [];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // OP_EQUAL, OP_VERIFY → OP_EQUALVERIFY
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (isOpcode(ops[0]!, 'OP_EQUAL') && isOpcode(ops[1]!, 'OP_VERIFY')) {
        return [{ op: 'opcode', code: 'OP_EQUALVERIFY' }];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // OP_CHECKSIG, OP_VERIFY → OP_CHECKSIGVERIFY
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (isOpcode(ops[0]!, 'OP_CHECKSIG') && isOpcode(ops[1]!, 'OP_VERIFY')) {
        return [{ op: 'opcode', code: 'OP_CHECKSIGVERIFY' }];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // OP_NUMEQUAL, OP_VERIFY → OP_NUMEQUALVERIFY
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (isOpcode(ops[0]!, 'OP_NUMEQUAL') && isOpcode(ops[1]!, 'OP_VERIFY')) {
        return [{ op: 'opcode', code: 'OP_NUMEQUALVERIFY' }];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // OP_CHECKMULTISIG, OP_VERIFY → OP_CHECKMULTISIGVERIFY
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (isOpcode(ops[0]!, 'OP_CHECKMULTISIG') && isOpcode(ops[1]!, 'OP_VERIFY')) {
        return [{ op: 'opcode', code: 'OP_CHECKMULTISIGVERIFY' }];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // OP_DUP, OP_DROP → remove both (but not if DUP is needed elsewhere)
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (isOpcode(ops[0]!, 'OP_DUP') && isOpcode(ops[1]!, 'OP_DROP')) {
        return [];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // PUSH x, OP_DROP → remove both (same as generic push/drop but for opcode pushes)
  // -------------------------------------------------------------------------
  // Already covered by the first rule.

  // -------------------------------------------------------------------------
  // OP_OVER, OP_OVER → OP_2DUP
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (ops[0]!.op === 'over' && ops[1]!.op === 'over') {
        return [{ op: 'opcode', code: 'OP_2DUP' }];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // OP_DROP, OP_DROP → OP_2DROP
  // -------------------------------------------------------------------------
  {
    windowSize: 2,
    match(ops) {
      if (ops[0]!.op === 'drop' && ops[1]!.op === 'drop') {
        return [{ op: 'opcode', code: 'OP_2DROP' }];
      }
      return null;
    },
  },

  // -------------------------------------------------------------------------
  // SWAP, ROT → equivalent to a single ROT, SWAP in some patterns.
  // This is left as a future optimization.
  // -------------------------------------------------------------------------

  // =========================================================================
  // New 2-op rules: Roll/Pick depth simplification
  // The stack lowerer emits PUSH(depth) + Roll/Pick pairs. These rules
  // consume both the push and the roll/pick, replacing with a single opcode.
  // =========================================================================

  // PUSH 0, Roll{0} → remove both (no-op)
  {
    windowSize: 2,
    match(ops) {
      if (isPushBigInt(ops[0]!, 0n) && ops[1]!.op === 'roll' && ops[1]!.depth === 0) return [];
      return null;
    },
  },

  // PUSH 1, Roll{1} → Swap
  {
    windowSize: 2,
    match(ops) {
      if (isPushBigInt(ops[0]!, 1n) && ops[1]!.op === 'roll' && ops[1]!.depth === 1) return [{ op: 'swap' }];
      return null;
    },
  },

  // PUSH 2, Roll{2} → Rot
  {
    windowSize: 2,
    match(ops) {
      if (isPushBigInt(ops[0]!, 2n) && ops[1]!.op === 'roll' && ops[1]!.depth === 2) return [{ op: 'rot' }];
      return null;
    },
  },

  // PUSH 0, Pick{0} → Dup
  {
    windowSize: 2,
    match(ops) {
      if (isPushBigInt(ops[0]!, 0n) && ops[1]!.op === 'pick' && ops[1]!.depth === 0) return [{ op: 'dup' }];
      return null;
    },
  },

  // PUSH 1, Pick{1} → Over
  {
    windowSize: 2,
    match(ops) {
      if (isPushBigInt(ops[0]!, 1n) && ops[1]!.op === 'pick' && ops[1]!.depth === 1) return [{ op: 'over' }];
      return null;
    },
  },

  // =========================================================================
  // New 2-op rules
  // =========================================================================

  // SHA256, SHA256 → HASH256
  {
    windowSize: 2,
    match(ops) {
      if (isOpcode(ops[0]!, 'OP_SHA256') && isOpcode(ops[1]!, 'OP_SHA256')) {
        return [{ op: 'opcode', code: 'OP_HASH256' }];
      }
      return null;
    },
  },

  // PUSH 0, NUMEQUAL → NOT
  {
    windowSize: 2,
    match(ops) {
      if (isPushZero(ops[0]!) && isOpcode(ops[1]!, 'OP_NUMEQUAL')) {
        return [{ op: 'opcode', code: 'OP_NOT' }];
      }
      return null;
    },
  },

  // NOTE: PUSH 1, MUL identity rule is intentionally omitted.
  // In Bitcoin Script, PUSH 1 OP_MUL forces byte-to-number coercion.
  // SLH-DSA codegen relies on this behavior.

  // =========================================================================
  // New 3-op rules: constant folding
  // =========================================================================

  // PUSH(a), PUSH(b), ADD → PUSH(a+b)
  {
    windowSize: 3,
    match(ops) {
      if (isPush(ops[0]!) && typeof ops[0]!.value === 'bigint' &&
          isPush(ops[1]!) && typeof ops[1]!.value === 'bigint' &&
          isOpcode(ops[2]!, 'OP_ADD')) {
        const a = (ops[0]! as PushOp).value as bigint;
        const b = (ops[1]! as PushOp).value as bigint;
        return [{ op: 'push', value: a + b }];
      }
      return null;
    },
  },

  // PUSH(a), PUSH(b), SUB → PUSH(a-b)
  {
    windowSize: 3,
    match(ops) {
      if (isPush(ops[0]!) && typeof ops[0]!.value === 'bigint' &&
          isPush(ops[1]!) && typeof ops[1]!.value === 'bigint' &&
          isOpcode(ops[2]!, 'OP_SUB')) {
        const a = (ops[0]! as PushOp).value as bigint;
        const b = (ops[1]! as PushOp).value as bigint;
        return [{ op: 'push', value: a - b }];
      }
      return null;
    },
  },

  // PUSH(a), PUSH(b), MUL → PUSH(a*b)
  {
    windowSize: 3,
    match(ops) {
      if (isPush(ops[0]!) && typeof ops[0]!.value === 'bigint' &&
          isPush(ops[1]!) && typeof ops[1]!.value === 'bigint' &&
          isOpcode(ops[2]!, 'OP_MUL')) {
        const a = (ops[0]! as PushOp).value as bigint;
        const b = (ops[1]! as PushOp).value as bigint;
        return [{ op: 'push', value: a * b }];
      }
      return null;
    },
  },

  // =========================================================================
  // New 4-op rules: chain folding
  // =========================================================================

  // PUSH(a), ADD, PUSH(b), ADD → PUSH(a+b), ADD
  {
    windowSize: 4,
    match(ops) {
      if (isPush(ops[0]!) && typeof ops[0]!.value === 'bigint' &&
          isOpcode(ops[1]!, 'OP_ADD') &&
          isPush(ops[2]!) && typeof ops[2]!.value === 'bigint' &&
          isOpcode(ops[3]!, 'OP_ADD')) {
        const a = (ops[0]! as PushOp).value as bigint;
        const b = (ops[2]! as PushOp).value as bigint;
        return [{ op: 'push', value: a + b }, { op: 'opcode', code: 'OP_ADD' }];
      }
      return null;
    },
  },

  // PUSH(a), SUB, PUSH(b), SUB → PUSH(a+b), SUB
  {
    windowSize: 4,
    match(ops) {
      if (isPush(ops[0]!) && typeof ops[0]!.value === 'bigint' &&
          isOpcode(ops[1]!, 'OP_SUB') &&
          isPush(ops[2]!) && typeof ops[2]!.value === 'bigint' &&
          isOpcode(ops[3]!, 'OP_SUB')) {
        const a = (ops[0]! as PushOp).value as bigint;
        const b = (ops[2]! as PushOp).value as bigint;
        return [{ op: 'push', value: a + b }, { op: 'opcode', code: 'OP_SUB' }];
      }
      return null;
    },
  },
];

// ---------------------------------------------------------------------------
// Peephole optimizer entry point
// ---------------------------------------------------------------------------

/**
 * Apply peephole optimization rules to a list of stack ops.
 *
 * Rules are applied in a single left-to-right pass, then the entire pass
 * is repeated until no more changes occur (fixed-point iteration).
 *
 * If-ops are recursively optimized: the then/else branches are each
 * optimized independently.
 */
export function optimizeStackIR(ops: StackOp[]): StackOp[] {
  // First, recursively optimize nested if-blocks
  let current = ops.map(op => optimizeNestedIf(op));

  const MAX_ITERATIONS = 100;
  let iteration = 0;

  while (iteration < MAX_ITERATIONS) {
    const result = applyOnePass(current);
    if (!result.changed) break;
    current = result.ops;
    iteration++;
  }

  return current;
}

/**
 * Recursively optimize if-op branches.
 */
function optimizeNestedIf(op: StackOp): StackOp {
  if (op.op === 'if') {
    const optimizedThen = optimizeStackIR(op.then);
    const optimizedElse = op.else ? optimizeStackIR(op.else) : undefined;
    return {
      op: 'if',
      then: optimizedThen,
      else: optimizedElse,
    };
  }
  return op;
}

/**
 * Apply all peephole rules in a single left-to-right scan.
 * Tries wider windows first (greedy) for maximum reduction.
 */
function applyOnePass(ops: StackOp[]): { ops: StackOp[]; changed: boolean } {
  const result: StackOp[] = [];
  let changed = false;
  let i = 0;

  // Organize rules by window size for efficient matching
  const rulesBySize = new Map<number, PeepholeRule[]>();
  for (const rule of rules) {
    const list = rulesBySize.get(rule.windowSize) ?? [];
    list.push(rule);
    rulesBySize.set(rule.windowSize, list);
  }
  const windowSizes = [...rulesBySize.keys()].sort((a, b) => b - a); // largest first

  while (i < ops.length) {
    // Altstack round-trip elimination is disabled for now.
    // The safety check (net stack effect = 0) is necessary but not sufficient:
    // removing DUP+TOALTSTACK shifts items on the main stack, which invalidates
    // PICK/ROLL depths in the middle ops. Enabling this requires full stack
    // depth simulation which is future work.

    let matched = false;

    // Try rules from largest window to smallest
    for (const size of windowSizes) {
      if (i + size > ops.length) continue;

      const sizeRules = rulesBySize.get(size)!;
      const window = ops.slice(i, i + size);

      for (const rule of sizeRules) {
        const replacement = rule.match(window);
        if (replacement !== null) {
          result.push(...replacement);
          i += size;
          changed = true;
          matched = true;
          break;
        }
      }

      if (matched) break;
    }

    if (!matched) {
      result.push(ops[i]!);
      i++;
    }
  }

  return { ops: result, changed };
}

// ---------------------------------------------------------------------------
// Altstack round-trip elimination — DISABLED pending full stack simulation.
// See plan for details on implementing safe DUP TOALTSTACK <middle> FROMALTSTACK
// elimination. Requires precise stack depth tracking to avoid corrupting
// SLH-DSA and EC codegen patterns.
// ---------------------------------------------------------------------------
