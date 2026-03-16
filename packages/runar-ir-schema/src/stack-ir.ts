/**
 * Stack IR — the low-level stack-machine representation (Pass 5 output).
 *
 * Each method is lowered to a flat sequence of stack operations that map
 * almost 1-to-1 to Bitcoin Script opcodes.  This representation is
 * compiler-specific (not part of the conformance boundary).
 */

// ---------------------------------------------------------------------------
// Program structure
// ---------------------------------------------------------------------------

export interface StackProgram {
  contractName: string;
  methods: StackMethod[];
}

export interface StackMethod {
  name: string;
  ops: StackOp[];
  maxStackDepth: number;
}

/** Optional source location for debug source maps. */
export interface StackSourceLoc {
  file: string;
  line: number;
  column: number;
}

// ---------------------------------------------------------------------------
// Stack operations (discriminated on `op`)
// ---------------------------------------------------------------------------

export interface PushOp {
  op: 'push';
  value: Uint8Array | bigint | boolean;
  sourceLoc?: StackSourceLoc;
}

export interface DupOp {
  op: 'dup';
  sourceLoc?: StackSourceLoc;
}

export interface SwapOp {
  op: 'swap';
  sourceLoc?: StackSourceLoc;
}

export interface RollOp {
  op: 'roll';
  depth: number;
  sourceLoc?: StackSourceLoc;
}

export interface PickOp {
  op: 'pick';
  depth: number;
  sourceLoc?: StackSourceLoc;
}

export interface DropOp {
  op: 'drop';
  sourceLoc?: StackSourceLoc;
}

export interface OpcodeOp {
  op: 'opcode';
  code: string; // e.g. 'OP_ADD', 'OP_CHECKSIG'
  sourceLoc?: StackSourceLoc;
}

export interface IfOp {
  op: 'if';
  then: StackOp[];
  else?: StackOp[];
  sourceLoc?: StackSourceLoc;
}

export interface NipOp {
  op: 'nip';
  sourceLoc?: StackSourceLoc;
}

export interface OverOp {
  op: 'over';
  sourceLoc?: StackSourceLoc;
}

export interface RotOp {
  op: 'rot';
  sourceLoc?: StackSourceLoc;
}

export interface TuckOp {
  op: 'tuck';
  sourceLoc?: StackSourceLoc;
}

export interface PlaceholderOp {
  op: 'placeholder';
  paramIndex: number;
  paramName: string;
  sourceLoc?: StackSourceLoc;
}

export type StackOp =
  | PushOp
  | DupOp
  | SwapOp
  | RollOp
  | PickOp
  | DropOp
  | OpcodeOp
  | IfOp
  | NipOp
  | OverOp
  | RotOp
  | TuckOp
  | PlaceholderOp;
