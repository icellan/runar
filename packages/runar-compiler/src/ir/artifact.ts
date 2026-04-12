/**
 * Artifact IR types — type definitions for the compiled artifact.
 *
 * These mirror the types in runar-ir-schema/artifact.ts and are defined
 * locally so the compiler package can be built independently.
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
   * Callers can pass a plain array of length N; the SDK flattens it
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
 * Scalar state fields use `string | bigint | boolean`. Grouped
 * FixedArray state fields use a real JS array of element values; the
 * SDK consumes it directly without parsing a stringified tuple.
 */
export type StateFieldInitialValue =
  | string
  | bigint
  | boolean
  | ReadonlyArray<string | bigint | boolean>;

export interface StateField {
  name: string;
  type: string;
  index: number;
  initialValue?: StateFieldInitialValue;
  /**
   * For state fields representing an expanded FixedArray<T, N>:
   * - `type` is the user-facing type string (e.g. `FixedArray<bigint, 9>`)
   * - `fixedArray.elementType` is the element primitive type
   * - `fixedArray.length` is N
   * - `fixedArray.syntheticNames` is the flat list of underlying scalar
   *   state-field names, in order.
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

  /** ISO-8601 build timestamp */
  buildTimestamp: string;
}
