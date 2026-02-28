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

// ---------------------------------------------------------------------------
// Stack operations (discriminated on `op`)
// ---------------------------------------------------------------------------

export interface PushOp {
  op: 'push';
  value: Uint8Array | bigint | boolean;
}

export interface DupOp {
  op: 'dup';
}

export interface SwapOp {
  op: 'swap';
}

export interface RollOp {
  op: 'roll';
  depth: number;
}

export interface PickOp {
  op: 'pick';
  depth: number;
}

export interface DropOp {
  op: 'drop';
}

export interface OpcodeOp {
  op: 'opcode';
  code: string; // e.g. 'OP_ADD', 'OP_CHECKSIG'
}

export interface IfOp {
  op: 'if';
  then: StackOp[];
  else?: StackOp[];
}

export interface NipOp {
  op: 'nip';
}

export interface OverOp {
  op: 'over';
}

export interface RotOp {
  op: 'rot';
}

export interface TuckOp {
  op: 'tuck';
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
  | TuckOp;
