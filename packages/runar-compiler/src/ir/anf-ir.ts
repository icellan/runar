/**
 * ANF IR -- A-Normal Form intermediate representation (Pass 4 output).
 *
 * Every compound expression is decomposed into a flat sequence of
 * let-bindings whose right-hand sides are *simple* values: constants,
 * variable references, a single primitive operation, or a branch/loop.
 */

// ---------------------------------------------------------------------------
// Shared codegen selectors
// ---------------------------------------------------------------------------

/**
 * Which Any-S OP_PUSH_TX preimage-binding construction a `check_preimage` node
 * emits. `'lowS'` (default) is the low-S blob that ships today (byte-identical);
 * `'all'` is the compact non-low-S blob, valid only for spends with nVersion !=
 * 0x01000000. Declared per method via the `@bindingVariant` directive.
 */
export type BindingVariant = 'lowS' | 'all';

// ---------------------------------------------------------------------------
// Program structure
// ---------------------------------------------------------------------------

export interface ANFProgram {
  contractName: string;
  properties: ANFProperty[];
  methods: ANFMethod[];
}

export interface ANFProperty {
  name: string;
  type: string;
  readonly: boolean;
  initialValue?: string | bigint | boolean;
}

export interface ANFMethod {
  name: string;
  params: ANFParam[];
  body: ANFBinding[];
  isPublic: boolean;
}

export interface ANFParam {
  name: string;
  type: string;
}

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

/**
 * A single let-binding: `let <name> = <value>`
 *
 * Names follow the pattern `t0`, `t1`, ... and are scoped per method.
 */
export interface ANFBinding {
  name: string;
  value: ANFValue;
  /** Debug-only: source location of the originating AST node. Not part of conformance. */
  sourceLoc?: { file: string; line: number; column: number };
}

// ---------------------------------------------------------------------------
// ANF value types (discriminated on `kind`)
// ---------------------------------------------------------------------------

export interface LoadParam {
  kind: 'load_param';
  name: string;
}

export interface LoadProp {
  kind: 'load_prop';
  name: string;
}

export interface LoadConst {
  kind: 'load_const';
  value: string | bigint | boolean;
}

export interface BinOp {
  kind: 'bin_op';
  op: string;
  left: string;   // reference to a temp name
  right: string;  // reference to a temp name
  result_type?: string; // operand type hint: "bytes" for ByteString/PubKey/Sig/Sha256 etc., omitted for numeric
}

export interface UnaryOp {
  kind: 'unary_op';
  op: string;
  operand: string; // reference to a temp name
  result_type?: string; // operand type hint: "bytes" for ByteString, omitted for numeric
}

export interface Call {
  kind: 'call';
  func: string;
  args: string[]; // references to temp names
}

export interface MethodCall {
  kind: 'method_call';
  object: string;  // reference to a temp name
  method: string;
  args: string[];  // references to temp names
}

export interface If {
  kind: 'if';
  cond: string;             // reference to a temp name
  then: ANFBinding[];
  else: ANFBinding[];
  /**
   * The ordered list of named slots BOTH arms leave behind — the `if`'s
   * multi-result contract (see `appendBranchResults` in 04-anf-lower.ts).
   *
   * `results[0]` is the DEEPEST of the block, `results[n-1]` the top. Entries
   * name either a branch-merged LOCAL or a contract PROPERTY written inside an
   * arm; stack lowering tells them apart from the contract's property list, so
   * the wire format stays a plain array of strings.
   *
   * When present, both arms end with the normalisation block that materialises
   * exactly these slots in exactly this order, and stack lowering trims each
   * arm to `results.length` slots and adopts them BY THE DECLARED ORDER rather
   * than inferring the count from a trailing `__merge$` block or the arms'
   * relative depths. That inference is what produced the 2026-08 branch
   * miscompile family: an arm that reordered its slots (a property write
   * beneath a rebound local) or that rebound its local IN PLACE while the other
   * arm pushed a fresh one left `lowerIf` registering ONE stackMap name for two
   * physical results, or padding the shorter arm with an EMPTY placeholder that
   * the parent then read as the merged value.
   *
   * ABSENT (not `[]`) when the `if` carries at most one result — a plain value
   * `if`, a ternary, an arm that emits output bytes, or an `if` without an
   * `else` — so every golden that never took the multi-result path keeps its
   * bytes. Absent and empty mean the same thing; emit it only when non-empty.
   */
  results?: string[];
}

export interface Loop {
  kind: 'loop';
  count: number;
  body: ANFBinding[];
  iterVar: string;
  // Iterator start value and step direction (issue #121). The loop is unrolled
  // `count` times; on iteration `i` (0-based) the iterator variable holds
  // `start + i * step`. Zero-start counting-up loops carry `start = 0n` and
  // `step = 1`, which reproduces the historical `i = 0..count-1` lowering
  // byte-for-byte. Countdown loops carry `step = -1`.
  start: bigint;
  step: 1 | -1;
}

export interface Assert {
  kind: 'assert';
  value: string; // reference to a temp name
  // Optional marker: set to `true` only on the auto-injected
  // `hash256(continuationOutputs) === extractOutputHash(txPreimage)` assert
  // emitted by the StatefulSmartContract lowering (04-anf-lower.ts).
  // Off-chain SDK interpreters use this to skip the equality check
  // (which has no way to hold without script-bytes-aware codegen) without
  // resorting to positional or structural heuristics that misfire on
  // developer-written covenant asserts whose IR shape is identical.
  // Absent => developer code.
  isAutoInjectedStateCheck?: boolean;
}

export interface UpdateProp {
  kind: 'update_prop';
  name: string;
  value: string; // reference to a temp name
}

export interface GetStateScript {
  kind: 'get_state_script';
}

export interface CheckPreimage {
  kind: 'check_preimage';
  preimage: string; // reference to a temp name
  /**
   * Issue #123: BIP-143 sighash flag the on-chain OP_PUSH_TX binding appends to
   * the derived signature (so the node re-derives the tx sighash under this
   * flag). Absent = default `ALL|FORKID` (0x41), byte-identical to the pinned
   * cross-tier binding blob. Only set for a method that declares a non-default
   * `@sighash` mode, keeping golden ANF unchanged for every existing contract.
   */
  sighashFlag?: number;
  /**
   * The Any-S binding construction to emit. Absent = default `'lowS'` (the low-S
   * blob, byte-identical to the pinned cross-tier binding). Only set for a method
   * that declares `@bindingVariant all`, keeping golden ANF unchanged for every
   * existing contract.
   */
  bindingVariant?: BindingVariant;
}

export interface DeserializeState {
  kind: 'deserialize_state';
  preimage: string; // reference to a temp name holding the verified preimage
}

export interface AddOutput {
  kind: 'add_output';
  satoshis: string;       // reference to a temp holding satoshis bigint
  stateValues: string[];  // references to temps, one per mutable property in declaration order
  preimage: string;       // reference to a temp holding the verified preimage (for codePart extraction)
}

export interface AddRawOutput {
  kind: 'add_raw_output';
  satoshis: string;      // reference to a temp holding satoshis bigint
  scriptBytes: string;   // reference to a temp holding ByteString script
}

/**
 * AddDataOutput — records an additional transaction output that is NOT a
 * state continuation. The output is included in the auto-computed
 * continuation hash (hashOutputs) in declaration order, after state
 * outputs and before the change output. The emit shape is identical to
 * `add_raw_output`: amount(8LE) + varint(scriptLen) + scriptBytes.
 *
 * Distinguished from `add_raw_output` only at the continuation-hash
 * composition stage: `add_data_output` refs are concatenated AFTER all
 * `add_output` (state) refs and BEFORE the change output.
 */
export interface AddDataOutput {
  kind: 'add_data_output';
  satoshis: string;      // reference to a temp holding satoshis bigint
  scriptBytes: string;   // reference to a temp holding ByteString script
}

export interface ArrayLiteral {
  kind: 'array_literal';
  elements: string[];    // references to temp names
}

/**
 * RawScript — an opaque opcode-byte span with declared stack arity.
 *
 * Bytes are emitted verbatim during stack lowering and Bitcoin Script emit;
 * no re-encoding takes place. The compiler treats this node as a hard
 * barrier: the EC algebraic optimizer, the peephole optimizer, and the
 * static analyzer all leave it untouched, and dead-code elimination
 * treats it as side-effecting.
 *
 * Used by the `asm({...})` surface syntax and by the decompiler when a
 * span of bytes can't be lifted to higher-level Rúnar source. Keeping
 * the IR byte-canonical (not mnemonic-based) makes cross-compiler
 * conformance trivial.
 */
export interface RawScript {
  kind: 'raw_script';
  bytes: string;     // hex string of the verbatim opcode bytes
  in_arity: number;  // stack elements consumed
  out_arity: number; // stack elements produced
}

export type ANFValue =
  | LoadParam
  | LoadProp
  | LoadConst
  | BinOp
  | UnaryOp
  | Call
  | MethodCall
  | If
  | Loop
  | Assert
  | UpdateProp
  | GetStateScript
  | CheckPreimage
  | DeserializeState
  | AddOutput
  | AddRawOutput
  | AddDataOutput
  | ArrayLiteral
  | RawScript;

/**
 * Name prefix for the temporaries 04-anf-lower appends to BOTH arms of an
 * if-statement that merges two or more locals (`appendMergedLocalResults`).
 *
 * Emitted by `appendBranchResults` (04-anf-lower) for — and ONLY for — an `if`
 * that declares `results`. Both arms end with an identical 2K-binding block:
 * K copies into `__merge$0..K-1`, then K rebinds of the declared results from
 * those temps. That makes each arm hold exactly `results`, in `results` order,
 * whichever arm ran and whichever of them that arm actually assigned.
 *
 * The block is a MATERIALISATION MECHANISM, not a signal. Stack lowering reads
 * the node's `results` list — it does not count or recognise this block, and
 * has not since the multi-result branch node landed (the `countMergedLocalResults`
 * inference it used to do is deleted in all seven tiers). The prefix survives
 * in two roles only: naming the temps, and letting the lowerer REFUSE an ANF
 * that carries the block without `results`, which is a pre-multi-result wire
 * format no current compiler can produce.
 *
 * The prefix is part of the ANF wire format: all seven compilers emit and
 * recognise the same block.
 */
export const MERGED_LOCAL_TEMP_PREFIX = '__merge$';
