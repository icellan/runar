/**
 * Rúnar Artifact — the final compiled output of a Rúnar compiler (Pass 6).
 *
 * This is what gets consumed by wallets, SDKs, and deployment tooling.
 * It bundles the locking script, ABI metadata, optional debug info,
 * and (for stateful contracts) state field descriptors.
 */

import type { ANFProgram } from './anf-ir.js';
import type { StackProgram } from './stack-ir.js';

// ---------------------------------------------------------------------------
// ABI
// ---------------------------------------------------------------------------

export interface ABIParam {
  name: string;
  type: string;
  /**
   * Present when this ABI param represents an expanded FixedArray<T, N>.
   * Callers can pass a plain array of length N; the SDK will flatten it
   * into the underlying positional slots by `syntheticNames` order.
   */
  fixedArray?: {
    elementType: string;
    length: number;
    syntheticNames: string[];
  };
}

export interface ABIConstructor {
  params: ABIParam[];
}

export interface ABIMethod {
  name: string;
  params: ABIParam[];
  isPublic: boolean;
  /** True for stateful contract methods that don't mutate state (no continuation output). */
  isTerminal?: boolean;
}

export interface ABI {
  constructor: ABIConstructor;
  methods: ABIMethod[];
}

// ---------------------------------------------------------------------------
// Source map
// ---------------------------------------------------------------------------

export interface SourceMapping {
  opcodeIndex: number;
  sourceFile: string;
  line: number;
  column: number;
}

export interface SourceMap {
  mappings: SourceMapping[];
}

// ---------------------------------------------------------------------------
// Stateful contracts
// ---------------------------------------------------------------------------

/**
 * A compile-time default value for a state field.
 *
 * For scalar state fields this is a single `string | bigint | boolean`.
 * For grouped FixedArray state fields the assembler stores a real
 * JS array of element-typed values so the SDK can consume it without
 * parsing a stringified tuple. For nested FixedArrays (e.g.
 * `FixedArray<FixedArray<bigint, 2>, 2>`) the initial value is a
 * recursive nested array that mirrors the declared shape.
 */
export type StateFieldInitialValue =
  | string
  | bigint
  | boolean
  | ReadonlyArray<StateFieldInitialValue>;

export interface StateField {
  name: string;
  type: string;
  index: number;
  initialValue?: StateFieldInitialValue;
  /**
   * For state fields representing an expanded FixedArray<T, N>:
   * - `type` is the user-facing type string (e.g. `FixedArray<bigint, 9>`)
   * - `fixedArray.elementType` is the element primitive type (e.g. `bigint`)
   * - `fixedArray.length` is N
   * - `fixedArray.syntheticNames` is the flat list of underlying scalar
   *   state-field names (`Board__0`..`Board__8`), in order.
   *
   * Runtime SDKs use this to flatten and unflatten arrays on state read/write.
   */
  fixedArray?: {
    elementType: string;
    length: number;
    syntheticNames: string[];
  };
}

// ---------------------------------------------------------------------------
// Constructor slots
// ---------------------------------------------------------------------------

export interface ConstructorSlot {
  paramIndex: number;
  byteOffset: number;
}

export interface CodeSepIndexSlot {
  /** Byte offset of the OP_0 placeholder in the template script */
  byteOffset: number;
  /** The template-relative codeSeparatorIndex value this placeholder represents */
  codeSepIndex: number;
}

// ---------------------------------------------------------------------------
// Raw script spans
// ---------------------------------------------------------------------------

/**
 * Byte range in the locking script produced by a `raw_script` ANF node
 * (surfaced in source as `asm({ body, in_arity, out_arity })`).
 *
 * The static analyzer treats these spans as opaque — it does not walk the
 * opcodes inside, since `raw_bytes` is a peephole barrier and the contents
 * may be arbitrary bytes that don't form a well-formed opcode stream. The
 * declared `inArity` / `outArity` carry the stack-effect contract so depth
 * tracking remains sound across the span.
 */
export interface RawScriptSpan {
  /** Byte offset of the span start in the locking script. */
  offset: number;
  /** Total length of the span, in bytes. */
  length: number;
  /** Number of stack values consumed before the span executes. */
  inArity: number;
  /** Number of stack values left on the stack after the span executes. */
  outArity: number;
}

// ---------------------------------------------------------------------------
// Top-level artifact
// ---------------------------------------------------------------------------

export interface RunarArtifact {
  /** Schema version, e.g. "runar-v0.1.0" */
  version: string;

  /** Semver of the compiler that produced this artifact */
  compilerVersion: string;

  /** Name of the compiled contract */
  contractName: string;

  /** Public ABI (constructor + methods) */
  abi: ABI;

  /** Hex-encoded locking script */
  script: string;

  /** Human-readable assembly (space-separated opcodes) */
  asm: string;

  /** Optional source-level debug mappings */
  sourceMap?: SourceMap;

  /** Optional IR snapshots for debugging / conformance checking */
  ir?: {
    anf?: ANFProgram;
    stack?: StackProgram;
  };

  /** ANF IR for SDK state computation (always included for stateful contracts) */
  anf?: ANFProgram;

  /** State field descriptors (present only for stateful contracts) */
  stateFields?: StateField[];

  /** Byte offsets of constructor parameter placeholders in the script */
  constructorSlots?: ConstructorSlot[];

  /** Byte offsets of codeSepIndex placeholders in the script (OP_0 placeholders
   *  that the SDK must replace with the adjusted codeSeparatorIndex). */
  codeSepIndexSlots?: CodeSepIndexSlot[];

  /** Byte offset of OP_CODESEPARATOR in the locking script (for BIP-143 sighash) */
  codeSeparatorIndex?: number;

  /** Per-method OP_CODESEPARATOR byte offsets (index 0 = first public method, etc.). */
  codeSeparatorIndices?: number[];

  /** Byte ranges produced by `raw_script` ANF nodes (opaque to the analyzer). */
  rawScriptSpans?: RawScriptSpan[];

  /** ISO-8601 build timestamp */
  buildTimestamp: string;
}
