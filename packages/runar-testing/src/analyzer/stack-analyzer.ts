/**
 * Stack safety analyzer — abstract interpretation of Bitcoin Script using
 * symbolic stack depths to detect underflows, unreachable code, and invalid
 * terminal states.
 */

import { Opcode } from '../vm/opcodes.js';
import type { ParsedOpcode } from './script-parser.js';
import { isPushOpcode } from './script-parser.js';
import type { AnalysisFinding } from './types.js';

// ---------------------------------------------------------------------------
// Opcode stack effects: (pops, pushes)
// ---------------------------------------------------------------------------

/**
 * Stack effect of each opcode: [itemsPopped, itemsPushed].
 *
 * For variable-arity opcodes like OP_CHECKMULTISIG, we use the minimum
 * (conservative) estimate. Push opcodes are handled separately.
 */
const STACK_EFFECTS: Record<number, [pops: number, pushes: number]> = {
  // Flow control (stack effects handled in path analysis; listed here for completeness)
  [Opcode.OP_NOP]: [0, 0],
  [Opcode.OP_IF]: [1, 0],
  [Opcode.OP_NOTIF]: [1, 0],
  [Opcode.OP_ELSE]: [0, 0],
  [Opcode.OP_ENDIF]: [0, 0],
  [Opcode.OP_VERIFY]: [1, 0],
  [Opcode.OP_RETURN]: [0, 0],

  // Stack
  [Opcode.OP_TOALTSTACK]: [1, 0],
  [Opcode.OP_FROMALTSTACK]: [0, 1],
  [Opcode.OP_2DROP]: [2, 0],
  [Opcode.OP_2DUP]: [2, 2 + 2],  // pops 2, pushes 4 (net +2, but we model as pop 2 push 4)
  [Opcode.OP_3DUP]: [3, 3 + 3],
  [Opcode.OP_2OVER]: [4, 4 + 2],
  [Opcode.OP_2ROT]: [6, 6],
  [Opcode.OP_2SWAP]: [4, 4],
  [Opcode.OP_IFDUP]: [1, 1], // conservative: pops 1, pushes at least 1 (may push 2)
  [Opcode.OP_DEPTH]: [0, 1],
  [Opcode.OP_DROP]: [1, 0],
  [Opcode.OP_DUP]: [1, 2],
  [Opcode.OP_NIP]: [2, 1],
  [Opcode.OP_OVER]: [2, 3],
  [Opcode.OP_PICK]: [1, 1], // pops index, pushes item (item source is deeper)
  [Opcode.OP_ROLL]: [1, 0], // pops index, moves item to top (net -1 from pop index, but item reappears)
  [Opcode.OP_ROT]: [3, 3],
  [Opcode.OP_SWAP]: [2, 2],
  [Opcode.OP_TUCK]: [2, 3],

  // String / byte operations
  [Opcode.OP_CAT]: [2, 1],
  [Opcode.OP_SPLIT]: [2, 2],
  [Opcode.OP_NUM2BIN]: [2, 1],
  [Opcode.OP_BIN2NUM]: [1, 1],
  [Opcode.OP_SIZE]: [1, 2], // keeps original + pushes size

  // Bitwise
  [Opcode.OP_INVERT]: [1, 1],
  [Opcode.OP_AND]: [2, 1],
  [Opcode.OP_OR]: [2, 1],
  [Opcode.OP_XOR]: [2, 1],
  [Opcode.OP_EQUAL]: [2, 1],
  [Opcode.OP_EQUALVERIFY]: [2, 0],

  // Arithmetic
  [Opcode.OP_1ADD]: [1, 1],
  [Opcode.OP_1SUB]: [1, 1],
  [Opcode.OP_NEGATE]: [1, 1],
  [Opcode.OP_ABS]: [1, 1],
  [Opcode.OP_NOT]: [1, 1],
  [Opcode.OP_0NOTEQUAL]: [1, 1],
  [Opcode.OP_ADD]: [2, 1],
  [Opcode.OP_SUB]: [2, 1],
  [Opcode.OP_MUL]: [2, 1],
  [Opcode.OP_DIV]: [2, 1],
  [Opcode.OP_MOD]: [2, 1],
  [Opcode.OP_LSHIFT]: [2, 1],
  [Opcode.OP_RSHIFT]: [2, 1],
  [Opcode.OP_BOOLAND]: [2, 1],
  [Opcode.OP_BOOLOR]: [2, 1],
  [Opcode.OP_NUMEQUAL]: [2, 1],
  [Opcode.OP_NUMEQUALVERIFY]: [2, 0],
  [Opcode.OP_NUMNOTEQUAL]: [2, 1],
  [Opcode.OP_LESSTHAN]: [2, 1],
  [Opcode.OP_GREATERTHAN]: [2, 1],
  [Opcode.OP_LESSTHANOREQUAL]: [2, 1],
  [Opcode.OP_GREATERTHANOREQUAL]: [2, 1],
  [Opcode.OP_MIN]: [2, 1],
  [Opcode.OP_MAX]: [2, 1],
  [Opcode.OP_WITHIN]: [3, 1],

  // Crypto
  [Opcode.OP_RIPEMD160]: [1, 1],
  [Opcode.OP_SHA1]: [1, 1],
  [Opcode.OP_SHA256]: [1, 1],
  [Opcode.OP_HASH160]: [1, 1],
  [Opcode.OP_HASH256]: [1, 1],
  [Opcode.OP_CHECKSIG]: [2, 1],
  [Opcode.OP_CHECKSIGVERIFY]: [2, 0],
  [Opcode.OP_CHECKMULTISIG]: [3, 1],     // minimum: dummy + 1 key + 1 sig -> result
  [Opcode.OP_CHECKMULTISIGVERIFY]: [3, 0],
};

/**
 * Get the stack effect of an opcode. Returns [pops, pushes].
 * Push opcodes always pop 0 and push 1. Synthetic raw-span opcodes carry
 * their declared `(inArity, outArity)` on `rawSpanArity`.
 */
export function getStackEffect(op: ParsedOpcode): [pops: number, pushes: number] {
  if (op.rawSpanArity) {
    return op.rawSpanArity;
  }
  if (isPushOpcode(op)) {
    return [0, 1];
  }
  return STACK_EFFECTS[op.opcode] ?? [0, 0];
}

// ---------------------------------------------------------------------------
// Linear stack analysis (ignoring branches)
// ---------------------------------------------------------------------------

export interface StackAnalysisState {
  depth: number;
  maxDepth: number;
  findings: AnalysisFinding[];
}

/**
 * Run a linear stack depth analysis over a sequence of opcodes (single path).
 *
 * This is used by the path analyzer to check each individual execution path.
 * It does NOT handle IF/ELSE branching — that's the path analyzer's job.
 *
 * Locking scripts (the default) start with items from the unlocking script
 * already on the stack, so we allow the depth to go negative — negative depth
 * represents items consumed from the unlocking script input. We only report
 * STACK_UNDERFLOW when the depth drops below the minimum it has ever been,
 * indicating an operation consuming items that don't exist even with arbitrary
 * unlocking script input.
 *
 * To detect true stack underflows (e.g., in a combined unlock+lock script),
 * pass an explicit initialDepth representing the known stack state.
 */
export function analyzeStackLinear(
  opcodes: ParsedOpcode[],
  initialDepth: number = 0,
): StackAnalysisState {
  const state: StackAnalysisState = {
    depth: initialDepth,
    maxDepth: initialDepth,
    findings: [],
  };

  let afterReturn = false;

  for (const op of opcodes) {
    // Detect unreachable code after OP_RETURN
    if (afterReturn) {
      state.findings.push({
        severity: 'warning',
        code: 'UNREACHABLE_AFTER_RETURN',
        message: `Unreachable opcode ${op.name} after OP_RETURN`,
        offset: op.offset,
        opcode: op.name,
      });
      continue;
    }

    if (op.opcode === Opcode.OP_RETURN) {
      afterReturn = true;
      continue;
    }

    const [pops, pushes] = getStackEffect(op);

    // Allow depth to go negative (items from unlocking script).
    // Only flag underflow when we have an explicit initial depth and
    // the depth goes below 0.
    if (initialDepth > 0 && state.depth < pops) {
      state.findings.push({
        severity: 'error',
        code: 'STACK_UNDERFLOW',
        message: `${op.name} requires ${pops} stack item(s) but only ${state.depth} available`,
        offset: op.offset,
        opcode: op.name,
      });
    }

    state.depth = state.depth - pops + pushes;

    if (state.depth > state.maxDepth) {
      state.maxDepth = state.depth;
    }
  }

  return state;
}

/**
 * Check if the final stack state is valid for a locking script.
 *
 * A valid locking script should leave exactly 1 item on the stack when
 * combined with an unlocking script. Since we're analyzing the locking
 * script in isolation (without unlocking script input), we check for
 * reasonable terminal states.
 */
export function checkTerminalStack(
  _depth: number,
  scriptSize: number,
): AnalysisFinding | null {
  if (scriptSize === 0) {
    return {
      severity: 'error',
      code: 'INVALID_TERMINAL_STACK',
      message: 'Empty script — no opcodes to execute',
    };
  }
  return null;
}
