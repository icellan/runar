/**
 * Stack IR -- the low-level stack-machine representation (Pass 5 output).
 *
 * Each method is lowered to a flat sequence of stack operations that map
 * almost 1-to-1 to Bitcoin Script opcodes.
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
  /** True if the unlocking script is prefixed with `_codePart` (issue #100). */
  usesCodePart?: boolean;
  /** True if this method's lowering needs the script-level OP_CODESEPARATOR
   *  the emitter places at offset 1 of the locking script (R-010).
   *
   *  Equal to `usesCodePart`: only a method that authenticates a `_codePart`
   *  witness needs `scriptCode` widened to cover the whole script. Methods
   *  that verify a preimage but never touch `_codePart` do not, and widening
   *  it for them would move the user's `checkSig` to the far side of the
   *  separator — which the stateless SDK signing path does not expect. */
  needsCodeSeparator?: boolean;
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

export interface PushCodeSepIndexOp {
  op: 'push_codesep_index';
  sourceLoc?: StackSourceLoc;
}

/**
 * R-095 — pin `SIZE(_codePart)` against the code part's own DEPLOYED byte
 * length.
 *
 * Consumes nothing: expects the numeric `SIZE(_codePart)` on top of the stack
 * and leaves it there, aborting via OP_VERIFY when the claimed code part is
 * not the length the deployed script actually has.
 *
 * The length is not known when the stack lowerer runs (byte offsets only
 * exist after `emit`), so the emitter resolves it: it reserves a
 * FIXED-WIDTH 9-byte sequence
 *
 *     OP_DUP <04 LL LL LL LL> OP_BIN2NUM (OP_NUMEQUAL|OP_GREATERTHANOREQUAL) OP_VERIFY
 *
 * and back-patches `LL LL LL LL` (little-endian) plus the comparison opcode
 * once the whole script has been emitted. The width is fixed so that the
 * patched value can never change the length it is describing — a minimal
 * script-number push would be self-referential.
 *
 * `delta` is the deploy-time byte GROWTH of the template's OP_0 placeholders,
 * so `deployedCodeLen = emittedTemplateLen + delta`. `exact` says whether
 * every placeholder's growth is type-determined:
 *
 *  - `exact: true`  → `SIZE(_codePart) == emittedLen + delta` (OP_NUMEQUAL).
 *  - `exact: false` → `SIZE(_codePart) >= emittedLen + delta`
 *    (OP_GREATERTHANOREQUAL). A variable-width readonly constructor argument
 *    (`bigint`, `ByteString`) has no compile-time width, and placeholder
 *    growth is never negative, so the sum is still a sound LOWER bound.
 */
export interface VerifyCodePartLenOp {
  op: 'verify_code_part_len';
  /** Deploy-time byte growth of the template's OP_0 placeholders. */
  delta: number;
  /** true → exact equality pin; false → lower-bound pin. */
  exact: boolean;
  sourceLoc?: StackSourceLoc;
}

/**
 * Opaque raw byte span produced by lowering a `raw_script` ANF node.
 *
 * Emitted verbatim by the emit pass. Treated as a hard barrier by every
 * windowed optimizer (peephole) — rules must never bridge across an
 * adjacent `raw_bytes`. Stack effect is declared via `in_arity` /
 * `out_arity`; the analyzer reads these to keep depth tracking sound
 * without inspecting the contents.
 */
export interface RawBytesOp {
  op: 'raw_bytes';
  bytes: Uint8Array;
  in_arity: number;
  out_arity: number;
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
  | PlaceholderOp
  | PushCodeSepIndexOp
  | VerifyCodePartLenOp
  | RawBytesOp;
