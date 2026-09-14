/**
 * R-285 (CL-GAP-075) — net stack effect of a Stack-IR op sequence.
 *
 * `ECTracker` (and its BN254 / P-256 / P-384 peers) models the stack as a
 * list of names and updates it from HAND-DECLARED arities: `rawBlock` is told
 * what it consumes and produces, and `emitIf` is told whether the branch
 * yields a result. Nothing checked those declarations against the opcodes
 * actually emitted. The 257-step secp256k1 ladder is built entirely out of
 * those two primitives, so a single miscounted arm would desynchronise every
 * subsequent PICK/ROLL depth — and produce a wrong script, not an error.
 *
 * This module supplies the missing cross-check: the real net effect of a
 * sequence, computed from the opcodes themselves.
 *
 * It REFUSES to model an opcode it does not know. A table that quietly
 * returned 0 for an unrecognised name would make every caller vacuously
 * green, which is the failure mode this check exists to prevent.
 */
import type { StackOp } from '../ir/stack-ir.js';

/** Thrown when a sequence contains something this module cannot account for. */
export class UnmodelledStackOpError extends Error {
  constructor(public readonly what: string) {
    super(`stackDelta: no stack effect modelled for ${what}`);
    this.name = 'UnmodelledStackOpError';
  }
}

/**
 * `[popped, pushed]` per opcode name.
 *
 * Mirrors `STACK_EFFECTS` in `packages/runar-testing/src/analyzer/
 * stack-analyzer.ts`, which is keyed by opcode BYTE and is consumed by the
 * script analyzer. Duplicated rather than imported because `runar-testing`
 * depends on `runar-compiler`, not the other way round;
 * `tests/r285-ec-branch-arms-balance.test.ts` pins the two against each other.
 *
 * The branch opcodes are deliberately absent — `OP_IF` / `OP_NOTIF` /
 * `OP_ELSE` / `OP_ENDIF` appear in raw spans and are handled structurally by
 * `stackDelta`, not by table lookup.
 */
const OPCODE_EFFECTS: Readonly<Record<string, readonly [number, number]>> = {
  OP_NOP: [0, 0], OP_VERIFY: [1, 0], OP_RETURN: [0, 0], OP_CODESEPARATOR: [0, 0],

  OP_TOALTSTACK: [1, 0], OP_FROMALTSTACK: [0, 1],
  OP_2DROP: [2, 0], OP_2DUP: [2, 4], OP_3DUP: [3, 6], OP_2OVER: [4, 6],
  OP_2ROT: [6, 6], OP_2SWAP: [4, 4], OP_IFDUP: [1, 1], OP_DEPTH: [0, 1],
  OP_DROP: [1, 0], OP_DUP: [1, 2], OP_NIP: [2, 1], OP_OVER: [2, 3],
  // OP_PICK pops the index and pushes a copy (net 0); OP_ROLL pops the index
  // and MOVES the item to the top (net -1).
  OP_PICK: [1, 1], OP_ROLL: [1, 0], OP_ROT: [3, 3], OP_SWAP: [2, 2], OP_TUCK: [2, 3],

  OP_CAT: [2, 1], OP_SPLIT: [2, 2], OP_NUM2BIN: [2, 1], OP_BIN2NUM: [1, 1], OP_SIZE: [1, 2],

  OP_INVERT: [1, 1], OP_AND: [2, 1], OP_OR: [2, 1], OP_XOR: [2, 1],
  OP_EQUAL: [2, 1], OP_EQUALVERIFY: [2, 0],

  OP_1ADD: [1, 1], OP_1SUB: [1, 1], OP_2MUL: [1, 1], OP_2DIV: [1, 1],
  OP_NEGATE: [1, 1], OP_ABS: [1, 1], OP_NOT: [1, 1], OP_0NOTEQUAL: [1, 1],
  OP_ADD: [2, 1], OP_SUB: [2, 1], OP_MUL: [2, 1], OP_DIV: [2, 1], OP_MOD: [2, 1],
  OP_LSHIFT: [2, 1], OP_RSHIFT: [2, 1], OP_BOOLAND: [2, 1], OP_BOOLOR: [2, 1],
  OP_NUMEQUAL: [2, 1], OP_NUMEQUALVERIFY: [2, 0], OP_NUMNOTEQUAL: [2, 1],
  OP_LESSTHAN: [2, 1], OP_GREATERTHAN: [2, 1],
  OP_LESSTHANOREQUAL: [2, 1], OP_GREATERTHANOREQUAL: [2, 1],
  OP_MIN: [2, 1], OP_MAX: [2, 1], OP_WITHIN: [3, 1],

  OP_RIPEMD160: [1, 1], OP_SHA1: [1, 1], OP_SHA256: [1, 1],
  OP_HASH160: [1, 1], OP_HASH256: [1, 1],
  OP_CHECKSIG: [2, 1], OP_CHECKSIGVERIFY: [2, 0],
  OP_CHECKMULTISIG: [3, 1], OP_CHECKMULTISIGVERIFY: [3, 0],
};

/** Opcode names this module knows. Exported so tests can diff the table. */
export function modelledOpcodes(): string[] {
  return Object.keys(OPCODE_EFFECTS).sort();
}

/** Raw branch opcodes, handled structurally rather than by arity. */
const BRANCH_OPEN = new Set(['OP_IF', 'OP_NOTIF']);

function codeOf(op: StackOp): string | null {
  return op.op === 'opcode' ? (op as { code: string }).code : null;
}

/**
 * Net change in stack depth produced by `ops`.
 *
 * Both branch forms are handled:
 *   - the structural `{ op: 'if', then, else }` Stack-IR node, and
 *   - a raw `OP_IF … OP_ELSE … OP_ENDIF` span inside an opcode run, which the
 *     varint and push-data encoders emit directly.
 *
 * In both cases the two arms must agree; a branch whose arms leave different
 * depths has no single net effect, and every depth computed after it — every
 * PICK and ROLL — would be wrong on one of the two paths.
 *
 * @throws UnmodelledStackOpError on an opcode or op kind with no modelled effect.
 * @throws Error when a branch's arms disagree.
 */
export function stackDelta(ops: readonly StackOp[]): number {
  let delta = 0;
  let i = 0;

  while (i < ops.length) {
    const op = ops[i]!;
    const code = codeOf(op);

    if (code !== null && BRANCH_OPEN.has(code)) {
      const span = readRawBranch(ops, i);
      const thenDelta = stackDelta(span.then);
      const elseDelta = stackDelta(span.else);
      if (thenDelta !== elseDelta) {
        throw new Error(
          `stackDelta: raw ${code} arms leave different depths ` +
          `(then ${thenDelta}, else ${elseDelta})`,
        );
      }
      delta += thenDelta - 1; // the branch opcode consumes its condition
      i = span.next;
      continue;
    }

    delta += singleOpDelta(op);
    i++;
  }

  return delta;
}

function singleOpDelta(op: StackOp): number {
  switch (op.op) {
    // Each of these puts exactly one new item on the stack.
    case 'push':
    case 'placeholder':
    case 'push_codesep_index':
    case 'raw_bytes':
    case 'dup':
    case 'over':
    case 'tuck':
      return 1;
    case 'drop':
    case 'nip':
      return -1;
    case 'swap':
    case 'rot':
      return 0;
    // The depth operand is pushed as a separate `push` op immediately before,
    // so from this op's own point of view ROLL consumes it and PICK trades it
    // for the copy.
    case 'roll':
      return -1;
    case 'pick':
      return 0;
    case 'verify_code_part_len':
      return -1;
    case 'if': {
      const node = op as unknown as { then?: StackOp[]; else?: StackOp[] };
      const thenDelta = stackDelta(node.then ?? []);
      const elseDelta = stackDelta(node.else ?? []);
      if (thenDelta !== elseDelta) {
        throw new Error(
          `stackDelta: if arms leave different depths (then ${thenDelta}, else ${elseDelta})`,
        );
      }
      return thenDelta - 1; // OP_IF consumes the condition
    }
    case 'opcode': {
      const code = (op as { code: string }).code;
      const effect = OPCODE_EFFECTS[code];
      if (!effect) throw new UnmodelledStackOpError(`opcode '${code}'`);
      return effect[1] - effect[0];
    }
    default:
      throw new UnmodelledStackOpError(`op kind '${(op as { op: string }).op}'`);
  }
}

/** Split a raw `OP_IF … [OP_ELSE …] OP_ENDIF` span starting at `start`. */
function readRawBranch(
  ops: readonly StackOp[],
  start: number,
): { then: StackOp[]; else: StackOp[]; next: number } {
  const thenOps: StackOp[] = [];
  const elseOps: StackOp[] = [];
  let target = thenOps;
  let nesting = 0;
  let i = start + 1;

  for (; i < ops.length; i++) {
    const code = codeOf(ops[i]!);
    if (code !== null && BRANCH_OPEN.has(code)) {
      nesting++;
    } else if (code === 'OP_ENDIF') {
      if (nesting === 0) return { then: thenOps, else: elseOps, next: i + 1 };
      nesting--;
    } else if (code === 'OP_ELSE' && nesting === 0) {
      target = elseOps;
      continue;
    }
    target.push(ops[i]!);
  }

  throw new Error('stackDelta: raw OP_IF span is not closed by OP_ENDIF');
}
