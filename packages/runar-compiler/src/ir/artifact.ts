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
  /** True if the unlocking script is prefixed with `_codePart` (issue #100). */
  usesCodePart?: boolean;
  /**
   * Issue #123: the BIP-143 sighash type this method's preimage/covenant is
   * built under (from a `@sighash` directive), e.g. `0x43` for SINGLE|FORKID.
   * Absent = default `ALL|FORKID` (0x41); the SDK falls back to 0x41 so
   * existing artifacts are unchanged and older SDKs keep working.
   */
  sigHashType?: number;
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
 * SDK consumes it directly without parsing a stringified tuple. For
 * nested FixedArrays (e.g. `FixedArray<FixedArray<bigint, 2>, 2>`)
 * the initial value is a recursive nested array that mirrors the
 * declared shape.
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

  // -- Byte-layout descriptors (additive; mirror the SDK's serializeState) --

  /** Wire encoding of the serialized field in the OP_RETURN state tail. */
  encoding?: 'num2bin-le8' | 'bool1' | 'raw' | 'pushdata';
  /** Byte offset from the byte AFTER the OP_RETURN separator. Omitted when
   *  any preceding field is variable-length. */
  byteOffset?: number;
  /** Serialized length in bytes. Omitted for variable-length fields. */
  byteLength?: number;
  /** NEGATIVE byte offset from the END of the locking script. Omitted when
   *  this or any following field is variable-length. */
  tailOffset?: number;
}

// ---------------------------------------------------------------------------
// Constructor slots
// ---------------------------------------------------------------------------

/**
 * One deploy-baked constructor slot: a 1-byte OP_0 placeholder in the
 * template script. The optional verification-descriptor fields carry
 * value-INDEPENDENT metadata (name/type/encoding); the SDK's
 * `resolveSlotLayout(artifact, constructorArgs)` resolves concrete deployed
 * offsets/lengths for given args.
 */
export interface ConstructorSlot {
  paramIndex: number;
  byteOffset: number;
  /** Constructor parameter name (matches `abi.constructor.params[paramIndex].name`). */
  name?: string;
  /** ABI type of the parameter (e.g. `PubKey`, `bigint`, `ByteString`). */
  type?: string;
  /** How the deploy-time value is encoded when spliced into the slot. */
  valueEncoding?: 'data' | 'scriptnum' | 'bool';
  /** For fixed-size data types only: baked value length in bytes. */
  fixedValueByteLength?: number;
  /** For fixed-size data types only: push-header bytes preceding the value. */
  fixedPushHeaderBytes?: number;
}

export interface CodeSepIndexSlot {
  /** Byte offset of the OP_0 placeholder in the template script */
  byteOffset: number;
  /** The template-relative codeSeparatorIndex value this placeholder represents */
  codeSepIndex: number;
}

// ---------------------------------------------------------------------------
// Template digest (slot-excised script identity)
// ---------------------------------------------------------------------------

/** One piece of the slot-excised template identity. */
export interface TemplateDigestPiece {
  kind: 'code' | 'slot';
  /** For kind 'slot': the excised slot's constructor param name. */
  slot?: string;
  /** For kind 'slot': the slot's TEMPLATE byte offset. */
  byteOffset?: number;
}

/**
 * Recipe for recomputing the contract's slot-excised template hash:
 * hash256 over the resolved code part with every constructor slot's VALUE
 * bytes removed (push headers stay in the hashed template).
 */
export interface TemplateDigest {
  algorithm: 'hash256-excised-slots';
  pieces: TemplateDigestPiece[];
}

/**
 * Byte range in the locking script produced by a `raw_script` ANF node
 * (surfaced in source as `asm({ body, in_arity, out_arity })`). The static
 * analyzer reads these spans so it can skip the contents — the bytes are
 * opaque, peephole-barrier-protected, and not guaranteed to form a
 * well-formed opcode stream. The declared `inArity` / `outArity` carry
 * the stack-effect contract so depth tracking remains sound across the
 * span without walking it.
 */
export interface RawScriptSpan {
  offset: number;
  length: number;
  inArity: number;
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

  /**
   * The base class the contract extends. Authoritative stateful signal for
   * the issue-#42 terminal sighash subscript trim (a StatefulSmartContract
   * with zero mutable fields still needs the trim).
   */
  parentClass?: 'SmartContract' | 'StatefulSmartContract' | 'UnsafeSmartContract';

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

  /** Byte offsets of constructor parameter placeholders in the script,
   *  enriched with verification-descriptor metadata (name/type/encoding). */
  constructorSlots?: ConstructorSlot[];

  /** Recipe for recomputing the slot-excised template identity hash. */
  templateDigest?: TemplateDigest;

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

  /**
   * Unsound primitives this artifact's script reaches, if any.
   *
   * R-245: declared in `runar-ir-schema` and read by the SDKs
   * (`runar-sdk/src/unsound-primitives.ts`) and by all six native tiers, and
   * MISSING from this declaration and its sibling — three copies of one wire
   * type, two of them narrower than the format. A narrower interface does not
   * fail to compile in TypeScript: an object carrying the field still satisfies
   * it, and the field just cannot be read or set through this view.
   *
   * Absent (not empty) on every artifact that reaches no such builtin.
   */
  unsoundPrimitives?: string[];
}
