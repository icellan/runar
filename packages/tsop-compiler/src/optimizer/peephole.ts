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
 */
function applyOnePass(ops: StackOp[]): { ops: StackOp[]; changed: boolean } {
  const result: StackOp[] = [];
  let changed = false;
  let i = 0;

  while (i < ops.length) {
    let matched = false;

    // Try each rule, largest window first
    for (const rule of rules) {
      if (i + rule.windowSize > ops.length) continue;

      const window = ops.slice(i, i + rule.windowSize);
      const replacement = rule.match(window);

      if (replacement !== null) {
        result.push(...replacement);
        i += rule.windowSize;
        changed = true;
        matched = true;
        break;
      }
    }

    if (!matched) {
      result.push(ops[i]!);
      i++;
    }
  }

  return { ops: result, changed };
}
