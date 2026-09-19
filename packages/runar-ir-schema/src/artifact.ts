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
  /** True if the unlocking script is prefixed with `_codePart` (issue #100). */
  usesCodePart?: boolean;
  /**
   * Issue #123: BIP-143 sighash type from a `@sighash` directive (e.g. `0x43`
   * for SINGLE|FORKID). Absent = default `ALL|FORKID` (0x41).
   */
  sigHashType?: number;
  /**
   * `@bindingVariant all` on this public method. Absent = default `lowS`.
   * The SDK refuses `call()` when this is `'all'` (nVersion=1 spends reject
   * the compact blob); it does not bump tx.version.
   */
  bindingVariant?: 'all';
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

  // -- Byte-layout descriptors (additive; mirror the SDK's serializeState) --
  //
  // Stateful contracts serialize state as `<code> OP_RETURN <field0>...<fieldN>`
  // in `index` order. These fields let a verifier locate a state value inside
  // a companion input's locking script without re-deriving the layout.

  /**
   * Wire encoding of the serialized field:
   *  - 'num2bin-le8': bigint — 8 raw bytes, little-endian sign-magnitude
   *                   (OP_NUM2BIN 8 semantics; sign bit = MSB of last byte).
   *  - 'bool1':       bool — 1 raw byte (0x00 / 0x01).
   *  - 'raw':         fixed-size byte types — raw bytes, no framing
   *                   (PubKey 33, Addr/Ripemd160 20, Sha256 32, Point 64).
   *  - 'pushdata':    variable-length types — push-data framed (length
   *                   prefix + bytes); byte length is value-dependent.
   */
  encoding?: 'num2bin-le8' | 'bool1' | 'raw' | 'pushdata';
  /** Byte offset from the byte AFTER the OP_RETURN separator. Omitted when
   *  any preceding field is variable-length. */
  byteOffset?: number;
  /** Serialized length in bytes (for fixedArray fields: total across all
   *  flattened leaves). Omitted for variable-length fields. */
  byteLength?: number;
  /** NEGATIVE byte offset from the END of the locking script (the state
   *  tail is the script's suffix, so `scriptLen + tailOffset` is the
   *  field's start). Omitted when this or any following field is
   *  variable-length. */
  tailOffset?: number;
}

// ---------------------------------------------------------------------------
// Constructor slots
// ---------------------------------------------------------------------------

/**
 * One deploy-baked constructor slot: a 1-byte OP_0 placeholder in the
 * TEMPLATE script (`artifact.script`) that the SDK replaces with the
 * encoded constructor arg at deploy time.
 *
 * The verification-descriptor fields (`name`, `type`, `valueEncoding`,
 * `fixedValueByteLength`, `fixedPushHeaderBytes`) are additive metadata that
 * make cross-contract verification MECHANICAL: a consuming contract (or
 * off-chain verifier) that inspects a companion input's parent transaction
 * can locate each baked readonly value without re-deriving offsets by
 * diffing/`indexOf`-ing compiled scripts — which is fragile and encoding-
 * sensitive (bigint values 1..16 bake as a single OP_N opcode byte, 0 bakes
 * as OP_0, and >=17 bakes as a multi-byte push that shifts every downstream
 * offset).
 *
 * DESIGN SPLIT (value-independence): the compiler cannot know the byte
 * length a slot occupies after deployment — that depends on the VALUE baked
 * at deploy time (a 33-byte PubKey push vs. a 1-byte OP_N). So the artifact
 * carries only value-INDEPENDENT metadata here, and the SDK's
 * `resolveSlotLayout(artifact, constructorArgs)` / `computeTemplateHash(
 * artifact, constructorArgs)` resolve concrete offsets/lengths/hashes for
 * GIVEN args.
 */
export interface ConstructorSlot {
  /** Index into `abi.constructor.params`. */
  paramIndex: number;
  /** Byte offset of the 1-byte OP_0 placeholder in the template script. */
  byteOffset: number;
  /** Constructor parameter name (matches `abi.constructor.params[paramIndex].name`). */
  name?: string;
  /** ABI type of the parameter (e.g. `PubKey`, `bigint`, `ByteString`). */
  type?: string;
  /**
   * How the deploy-time value is encoded when spliced into the slot:
   *  - 'data':      raw data push (push header + value bytes). Fixed-size
   *                 types (PubKey 33B, Sha256 32B, ...) always take
   *                 header 1B + value NB; variable-length ByteString
   *                 header size depends on the value length.
   *  - 'scriptnum': minimally-encoded Script number. 0 → OP_0 (1 opcode
   *                 byte), 1..16 → single OP_N opcode byte (0x50+N),
   *                 -1 → OP_1NEGATE, else 1-byte header + LE
   *                 sign-magnitude bytes.
   *  - 'bool':      single opcode byte (OP_TRUE / OP_0).
   */
  valueEncoding?: 'data' | 'scriptnum' | 'bool';
  /** For fixed-size data types only: the baked value length in bytes
   *  (PubKey 33, Sha256 32, Addr/Ripemd160 20, Point 64). */
  fixedValueByteLength?: number;
  /** For fixed-size data types only: the push-header length in bytes that
   *  precedes the value (1 for all lengths <= 75). */
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

/**
 * One piece of the slot-excised template identity.
 *
 * The resolved code part (template with constructor args spliced in) is
 * split at every constructor slot's VALUE bytes: `code` pieces are the
 * byte runs kept in the template (including each slot's push header, whose
 * presence pins the baked value's length), `slot` pieces are the excised
 * value bytes. A verifier recomputes the template hash by concatenating
 * the `code` pieces of a candidate script — using the concrete boundaries
 * from the SDK's `resolveSlotLayout` — and hashing the result.
 */
export interface TemplateDigestPiece {
  kind: 'code' | 'slot';
  /** For kind 'slot': the excised slot's constructor param name. */
  slot?: string;
  /** For kind 'slot': the slot's TEMPLATE byte offset (disambiguates
   *  multiple slots baked from the same parameter). */
  byteOffset?: number;
}

/**
 * Recipe for recomputing the contract's slot-excised template hash.
 *
 * `hash256-excised-slots`: hash256 (double SHA-256) over the resolved code
 * part with every constructor slot's VALUE bytes removed. Push headers of
 * 'data'/'scriptnum' pushes remain in the hashed template; single-opcode
 * encodings (OP_N / OP_0 / OP_1NEGATE / bool) contribute no header and the
 * opcode byte itself is excised.
 */
export interface TemplateDigest {
  algorithm: 'hash256-excised-slots';
  /** Alternating code/slot pieces, in script order (starts and ends with a
   *  `code` piece; boundary `code` pieces may be empty byte runs). */
  pieces: TemplateDigestPiece[];
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

  /**
   * The base class the contract extends. Distinguishes stateful contracts
   * (which auto-inject `checkPreimage` at method entry, placing the user
   * `checkSig` AFTER the OP_CODESEPARATOR) from stateless / unsafe contracts.
   *
   * This is the authoritative stateful signal for the issue-#42 terminal
   * sighash subscript trim: a `StatefulSmartContract` with zero mutable
   * fields still needs the trim, even though its `stateFields` array is
   * empty. Older artifacts that predate this field omit it.
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
   * Builtins reached by this script that the project does not claim are sound
   * (R-062 / CL-BUG-105). Today the only member is `verifySP1FRI`, whose
   * codegen is a documented proof-of-concept with stubbed protocol algebra.
   *
   * The compiler already REFUSES to emit such a script unless the author wrote
   * `@acknowledgeUnsoundSP1FriVerifier` or the invoker passed
   * `--acknowledge-unsound-sp1-fri`. That acknowledgement stopped at whoever
   * ran the compiler: the artifact handed on afterwards looked like any other,
   * and every SDK funded it without a word. Present here, the fact travels with
   * the artifact, and each SDK's deploy path refuses to fund it unless the
   * caller acknowledges the same list.
   *
   * Absent (not empty) on every artifact that reaches no such builtin, so
   * nothing else in the repo is affected.
   */
  unsoundPrimitives?: string[];
}
