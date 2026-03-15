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
}

export interface Loop {
  kind: 'loop';
  count: number;
  body: ANFBinding[];
  iterVar: string;
}

export interface Assert {
  kind: 'assert';
  value: string; // reference to a temp name
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
}

export interface DeserializeState {
  kind: 'deserialize_state';
  preimage: string; // reference to a temp name holding the verified preimage
}

export interface AddOutput {
  kind: 'add_output';
  satoshis: string;       // reference to a temp holding satoshis bigint
  stateValues: string[];  // references to temps, one per mutable property in declaration order
}

export interface AddRawOutput {
  kind: 'add_raw_output';
  satoshis: string;      // reference to a temp holding satoshis bigint
  scriptBytes: string;   // reference to a temp holding ByteString script
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
  | AddRawOutput;
