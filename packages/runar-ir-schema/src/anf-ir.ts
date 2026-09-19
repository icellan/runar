/**
 * ANF IR — A-Normal Form intermediate representation (Pass 4 output).
 *
 * This is the **canonical conformance boundary** for Rúnar compilers.
 * Two compilers that accept the same Rúnar source MUST produce
 * byte-identical ANF IR (when serialised with canonical JSON).
 *
 * Every compound expression is decomposed into a flat sequence of
 * let-bindings whose right-hand sides are *simple* values: constants,
 * variable references, a single primitive operation, or a branch/loop.
 */

/** Which Any-S OP_PUSH_TX preimage-binding construction a check_preimage node emits. */
export type BindingVariant = 'lowS' | 'all';

// ---------------------------------------------------------------------------
// Program structure
// ---------------------------------------------------------------------------

export interface ANFProgram {
  contractName: string;
  properties: ANFProperty[];
  methods: ANFMethod[];
}

/**
 * One FixedArray nesting level on a synthetic scalar leaf. Outermost level
 * first. `base` is the property name one level up (`grid`, then `grid__0`),
 * `index` this leaf's position at that level, `length` that level's arity.
 */
export interface ANFSyntheticArrayLevel {
  base: string;
  index: number;
  length: number;
}

export interface ANFProperty {
  name: string;
  type: string;
  readonly: boolean;
  initialValue?: string | bigint | boolean;
  /**
   * N-095: present only on a scalar leaf minted by the expand-fixed-arrays
   * pass. The artifact assembler consumes one level per pass to regroup the
   * synthetic siblings back into a single FixedArray state/ABI entry, so this
   * is load-bearing wire data: an ANF that drops it still compiles to the same
   * script bytes but degrades the SDK's `state.grid` accessor into N raw
   * scalars. The TS frontend reads the chain off the AST
   * (`PropertyNode.__syntheticArrayChain`) instead and has no ANF-input mode,
   * so it is the one tier that need not emit it.
   */
  syntheticArrayChain?: ANFSyntheticArrayLevel[];
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
// Bindings — the core of the ANF representation
// ---------------------------------------------------------------------------

/**
 * A single let-binding:  `let <name> = <value>`
 *
 * Names follow the pattern `t0`, `t1`, … and are scoped per method.
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
   * Ordered named result slots both arms leave (`results[0]` deepest). Entries
   * name a branch-merged local or an arm-written contract property. Absent
   * when the `if` carries at most one result — see the copy of this type in
   * `packages/runar-compiler/src/ir/anf-ir.ts` for the full contract.
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
  // `step = 1`, reproducing the historical `i = 0..count-1` lowering exactly.
  // Countdown loops carry `step = -1`.
  start: bigint;
  step: 1 | -1;
}

export interface Assert {
  kind: 'assert';
  value: string; // reference to a temp name
  // Optional marker: set to `true` only on the auto-injected
  // `hash256(continuationOutputs) === extractOutputHash(txPreimage)` assert
  // emitted by the StatefulSmartContract lowering. Off-chain SDK
  // interpreters use it to skip the equality check without resorting to
  // structural heuristics. Absent => developer code.
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
  /** Absent = default `'lowS'`. Only set for `@bindingVariant all`. */
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
 * Mirrors the definition in `packages/runar-compiler/src/ir/anf-ir.ts`.
 * The IR stores resolved bytes (not mnemonics) so cross-compiler
 * conformance reduces to byte equality.
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
