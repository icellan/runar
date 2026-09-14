/**
 * Artifact assembler — produces the final RunarArtifact from compiled data.
 *
 * The artifact is the JSON document consumed by wallets, SDKs, and
 * deployment tooling. It bundles the locking script (hex + ASM), ABI
 * metadata, optional debug info (source map, IR snapshots), and state
 * field descriptors for stateful contracts.
 */

import type {
  ContractNode,
  TypeNode,
  ParamNode,
  PropertyNode,
  StackProgram,
  ANFProgram,
} from '../ir/index.js';
import { computeSideEffectSummary, continuationShape } from '../passes/side-effect-summary.js';
import { SIGHASH_DEFAULT } from '../passes/sighash-directive.js';
import { abiValueEncoding, annotateStateFieldLayout, STATE_FIELD_WIDTHS } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Artifact types (mirroring runar-ir-schema/artifact.ts)
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
}

export interface ABI {
  constructor: ABIConstructor;
  methods: ABIMethod[];
}

export interface SourceMapping {
  opcodeIndex: number;
  sourceFile: string;
  line: number;
  column: number;
}

export interface SourceMap {
  mappings: SourceMapping[];
}

/**
 * A compile-time default value for a state field.
 *
 * For scalar state fields this is a single `string | bigint | boolean`.
 * For grouped FixedArray state fields the assembler stores a real
 * JS array of element-typed values so the SDK can consume it without
 * parsing a stringified tuple. For nested FixedArrays the value is a
 * recursive nested array mirroring the declared shape.
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
  byteOffset: number;
  codeSepIndex: number;
}

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
 * analyzer treats these spans as opaque; the declared `inArity` / `outArity`
 * carry the stack-effect contract so depth tracking remains sound across
 * the span without inspecting its contents.
 */
export interface RawScriptSpan {
  offset: number;
  length: number;
  inArity: number;
  outArity: number;
}

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

  /** Byte offsets of codeSepIndex placeholders in the script */
  codeSepIndexSlots?: CodeSepIndexSlot[];

  /** Byte offset of OP_CODESEPARATOR in the locking script (for BIP-143 sighash).
   *  For multi-method contracts, use codeSeparatorIndices instead. */
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

// ---------------------------------------------------------------------------
// Assembly options
// ---------------------------------------------------------------------------

export interface AssembleOptions {
  /** Include ANF and Stack IR in the artifact for debugging. */
  includeIR?: boolean;
  /** Include source map in the artifact. */
  includeSourceMap?: boolean;
  /** Source mappings from the emitter. */
  sourceMappings?: SourceMapping[];
  /** Override the compiler version string. */
  compilerVersion?: string;
  /** Constructor parameter placeholder byte offsets from the emitter. */
  constructorSlots?: ConstructorSlot[];
  /** CodeSepIndex placeholder byte offsets from the emitter. */
  codeSepIndexSlots?: CodeSepIndexSlot[];
  /** Byte offset of OP_CODESEPARATOR in the locking script. */
  codeSeparatorIndex?: number;
  /** Per-method OP_CODESEPARATOR byte offsets. */
  codeSeparatorIndices?: number[];
  /** Byte ranges produced by raw_script ANF nodes (from emitter). */
  rawScriptSpans?: RawScriptSpan[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * The artifact build time, as an ISO-8601 string.
 *
 * Honours SOURCE_DATE_EPOCH (https://reproducible-builds.org/specs/source-date-epoch/):
 * when it holds a Unix seconds value, that instant is stamped instead of the
 * clock, so two builds of the same source produce byte-identical artifacts.
 * Without it, the wall clock, exactly as before.
 *
 * R-212: the Go tier honoured this and the other six did not, so six of seven
 * artifacts could not be reproduced — and reproducing the artifact is how
 * someone other than the author checks that a published locking script is what
 * the published source compiles to. A malformed value is ignored rather than
 * failing the build: the variable is an environment convention, not input.
 */
function buildTimestamp(): string {
  const raw = process.env.SOURCE_DATE_EPOCH;
  if (raw !== undefined && /^\d+$/.test(raw.trim())) {
    const seconds = Number(raw.trim());
    if (Number.isSafeInteger(seconds)) {
      return new Date(seconds * 1000).toISOString();
    }
  }
  return new Date().toISOString();
}

const ARTIFACT_VERSION = 'runar-v1.0.0-rc.1';
const DEFAULT_COMPILER_VERSION = '1.0.0-rc.1';

// ---------------------------------------------------------------------------
// Type serialization
// ---------------------------------------------------------------------------

/**
 * Serialize a TypeNode to its string representation for the ABI.
 */
function typeToString(type: TypeNode): string {
  switch (type.kind) {
    case 'primitive_type':
      return type.name;
    case 'fixed_array_type':
      return `FixedArray<${typeToString(type.element)}, ${type.length}>`;
    case 'custom_type':
      return type.name;
  }
}

// ---------------------------------------------------------------------------
// FixedArray re-grouping
// ---------------------------------------------------------------------------
//
// Pass 3b (expand-fixed-arrays) expands a property like
// `Board: FixedArray<bigint, 9>` into 9 scalar siblings `Board__0..Board__8`.
// For nested arrays `Grid: FixedArray<FixedArray<bigint, 2>, 2>` it expands
// into 4 scalar leaves `Grid__0__0, Grid__0__1, Grid__1__0, Grid__1__1`.
// The downstream passes (ANF, stack, emit) see and operate on those scalars.
//
// For the user-facing ABI and state-field list we re-group those synthetic
// siblings back into a single logical entry tagged `fixedArray` so the
// SDK can present the array-shaped API — including nested arrays, which
// the SDK exposes as nested JS arrays (`[[0n,0n],[0n,0n]]`).
//
// Grouping is marker-driven, NOT pattern-driven: every participating
// entry must carry a `__syntheticArrayChain` attached at expansion time.
// This means a user-written contract with hand-named properties
// `user__0`, `user__1`, `user__2` of the same type will NOT be grouped
// — the chain is missing, so the regrouper leaves them as independent
// scalars. Without this guard the regrouper would silently miscompile
// into a bogus `FixedArray<T,3>` ABI entry.
//
// The regrouper runs iteratively: each pass collapses one level of the
// innermost FixedArray (peeling one entry off the end of every chain)
// and wraps the resulting group's type in one more `FixedArray<...,N>`
// layer. Repeat until no entry has any remaining chain.
// ---------------------------------------------------------------------------

interface ChainEntry {
  base: string;
  index: number;
  length: number;
}

/**
 * Internal representation of a field going through the iterative
 * regrouping loop. `name`, `type` and `fixedArray` hold the current
 * (possibly already partially-grouped) user-facing view; `chain` is
 * the still-to-be-consumed nesting levels (innermost = last).
 *
 * `initialValue` is widened to the recursive `StateFieldInitialValue`
 * so intermediate groups can nest JS arrays as the regroup climbs
 * outward.
 */
interface RegroupEntry {
  name: string;
  type: string;
  chain: ChainEntry[];
  initialValue?: StateFieldInitialValue;
  fixedArray?: {
    elementType: string;
    length: number;
    syntheticNames: string[];
  };
  /** Source declaration index (only meaningful for state fields). */
  index?: number;
}

/**
 * Run one pass of the iterative regrouper: find maximal runs whose
 * innermost (last) chain entries match — same `base`, same `length`,
 * contiguous `index = 0..length-1`, same `type` — and collapse each
 * into a single entry whose `type` is wrapped in one more FixedArray
 * layer, whose chain has that innermost level popped off, and whose
 * `initialValue` is the collapsed JS array (if every child had one).
 *
 * Entries whose chain is empty or whose innermost marker doesn't
 * start a run are left alone. Returns `true` if at least one group
 * was formed, so the caller knows whether to iterate again.
 */
function regroupOnePass(entries: RegroupEntry[]): { out: RegroupEntry[]; changed: boolean } {
  const out: RegroupEntry[] = [];
  let changed = false;
  let i = 0;
  while (i < entries.length) {
    const entry = entries[i]!;
    const chainLen = entry.chain.length;
    if (chainLen === 0) {
      out.push(entry);
      i++;
      continue;
    }
    const marker = entry.chain[chainLen - 1]!;
    if (marker.index !== 0) {
      // R-289: a sibling that reaches the head of the loop has no run head
      // before it — the head consumes its whole run and advances past it, so
      // index != 0 here means the chain did not come from pass 3b. Pushing it
      // through as a scalar publishes an ABI the SDK reads as N independent
      // fields instead of one array, with no diagnostic.
      throw new Error(
        `malformed synthetic-array chain on '${entry.name}': element ${marker.index} ` +
          `of '${marker.base}' appears without the element 0 that starts its run. ` +
          `Synthetic-array chains are written by the expand-fixed-arrays pass; ` +
          `this IR did not come from it.`,
      );
    }

    // Greedily extend: every follower must share the same innermost
    // {base, length}, carry the expected index = k, and have the
    // identical current `type` (so runs of mixed-type children cannot
    // spuriously collapse).
    const runEntries: RegroupEntry[] = [entry];
    let k = 1;
    let j = i + 1;
    while (j < entries.length && k < marker.length) {
      const next = entries[j]!;
      if (next.chain.length === 0) break;
      const m2 = next.chain[next.chain.length - 1]!;
      if (
        m2.base !== marker.base ||
        m2.length !== marker.length ||
        m2.index !== k ||
        next.type !== entry.type
      ) {
        break;
      }
      runEntries.push(next);
      k++;
      j++;
    }

    if (runEntries.length !== marker.length) {
      // R-289: a well-formed expansion always emits all N siblings
      // contiguously, so a short run means the chain was not written by pass
      // 3b. Leaving them ungrouped published an ABI the SDK reads as N
      // independent fields instead of one array — a wrong state layout from an
      // artifact the compiler called valid.
      throw new Error(
        `malformed synthetic-array chain on '${entry.name}': '${marker.base}' declares ` +
          `${marker.length} elements but the contiguous run has ${runEntries.length}. ` +
          `Synthetic-array chains are written by the expand-fixed-arrays pass; ` +
          `this IR did not come from it.`,
      );
    }

    // Collapse this run into one intermediate entry. The parent chain
    // (levels still to be consumed above this one) is the shared
    // `entry.chain.slice(0, -1)`.
    const innerType = entry.type;
    const groupedType = `FixedArray<${innerType}, ${marker.length}>`;

    // For leaf-level groups (no prior fixedArray), the synthetic names
    // are the leaf property names. For higher-level groups collapsing
    // already-grouped children, we flatten the child synthetic names
    // in declaration order so the final state-field descriptor has a
    // flat leaf list the SDK can walk linearly.
    const syntheticNames: string[] = [];
    for (const e of runEntries) {
      if (e.fixedArray) {
        syntheticNames.push(...e.fixedArray.syntheticNames);
      } else {
        syntheticNames.push(e.name);
      }
    }

    // Collapse initial values: every child must have one. At leaf
    // level the child value is a scalar; at higher levels it is
    // already a (possibly nested) array, produced by the previous
    // regroup pass.
    let collapsedInit: StateFieldInitialValue | undefined = undefined;
    const allHaveInit = runEntries.every(e => e.initialValue !== undefined);
    if (allHaveInit) {
      collapsedInit = runEntries.map(e => e.initialValue as StateFieldInitialValue);
    }

    const grouped: RegroupEntry = {
      name: marker.base,
      type: groupedType,
      chain: entry.chain.slice(0, -1),
      fixedArray: {
        elementType: innerType,
        length: marker.length,
        syntheticNames,
      },
      index: runEntries[0]!.index,
    };
    if (collapsedInit !== undefined) {
      grouped.initialValue = collapsedInit;
    }

    out.push(grouped);
    i = j;
    changed = true;
  }
  return { out, changed };
}

/**
 * Iteratively regroup synthetic FixedArray runs until no entry has any
 * remaining chain. Each pass consumes one nesting level. Returns the
 * final entries, which for nested arrays carry `fixedArray` metadata
 * whose `elementType` is itself a `FixedArray<...>` string and whose
 * `syntheticNames` is the flat leaf list.
 */
function regroupSyntheticRuns(entries: RegroupEntry[]): RegroupEntry[] {
  let current = entries;
  // Guard against pathological loops: the deepest legal chain is
  // bounded by how many FixedArray levels the user nested. Cap at
  // 1024 just to make runaway bugs surface as a hard error instead
  // of an infinite loop.
  for (let iter = 0; iter < 1024; iter++) {
    const { out, changed } = regroupOnePass(current);
    current = out;
    if (!changed) return current;
  }
  throw new Error('regroupSyntheticRuns: exceeded iteration cap (pathological chain nesting?)');
}

// ---------------------------------------------------------------------------
// ABI extraction
// ---------------------------------------------------------------------------

/**
 * Extract the ABI from a ContractNode.
 *
 * The ABI describes the constructor parameters and all public methods
 * with their parameter names and types.
 */
function extractABI(contract: ContractNode): ABI {
  // Constructor — map params to raw ABIParams then re-group expanded arrays
  const rawConstructorParams: ABIParam[] = contract.constructor.params.map(paramToABI);
  const constructorParams = regroupAbiParams(rawConstructorParams);

  const isStateful = contract.parentClass === 'StatefulSmartContract';

  // Single source of truth for continuation requirements — same
  // classifier the ANF pass uses, so ABI params cannot diverge from
  // the locking script's auto-injected parameter list.
  const sideEffects = isStateful ? computeSideEffectSummary(contract) : null;

  // Methods
  const methods: ABIMethod[] = contract.methods.map(method => {
    const params = regroupAbiParams(method.params.map(paramToABI));
    const isPublic = method.visibility === 'public';
    let needsChange = false;

    if (isStateful && isPublic && sideEffects) {
      const effects = sideEffects.get(method.name) ?? {
        mutatesState: false,
        hasStateOutput: false,
        hasDataOutput: false,
        usesPreimage: false,
      };
      const shape = continuationShape(effects);
      needsChange = shape.needsChange;
      if (needsChange) {
        params.push({ name: '_changePKH', type: 'Ripemd160' });
        params.push({ name: '_changeAmount', type: 'bigint' });
      }
      if (shape.needsNewAmount) {
        params.push({ name: '_newAmount', type: 'bigint' });
      }
      params.push({ name: 'txPreimage', type: 'SigHashPreimage' });
    }

    const result: ABIMethod = { name: method.name, params, isPublic };

    // For stateful contracts, mark terminal methods (no state mutation, no addOutput)
    if (isStateful && isPublic && !needsChange) {
      result.isTerminal = true;
    }

    // Issue #123: carry a non-default @sighash mode into the ABI so the SDK
    // builds the BIP-143 preimage under the same flags the covenant expects.
    // Omitted for the default (0x41) → existing artifacts are byte-identical.
    if (isPublic && method.sighashType !== undefined && method.sighashType !== SIGHASH_DEFAULT) {
      result.sigHashType = method.sighashType;
    }

    return result;
  });

  return {
    constructor: { params: constructorParams },
    methods,
  };
}

function paramToABI(param: ParamNode): ABIParam {
  return {
    name: param.name,
    type: typeToString(param.type),
  };
}

/**
 * Re-group contiguous synthetic FixedArray params back into a single
 * (possibly nested) FixedArray-typed ABI param. `ParamNode` never
 * carries the synthetic chain (FixedArray is not allowed as a method
 * or constructor parameter), so in practice this is a no-op — but we
 * still run the regrouper so the type signature is consistent with
 * state-field regrouping and so any future auto-generated constructor
 * that does propagate markers Just Works.
 */
function regroupAbiParams(
  params: Array<ABIParam & { __chain?: ChainEntry[] }>,
): ABIParam[] {
  const entries: RegroupEntry[] = params.map(p => ({
    name: p.name,
    type: p.type,
    chain: p.__chain ? [...p.__chain] : [],
  }));
  const regrouped = regroupSyntheticRuns(entries);
  return regrouped.map(e => {
    const out: ABIParam = { name: e.name, type: e.type };
    if (e.fixedArray) {
      out.fixedArray = {
        elementType: e.fixedArray.elementType,
        length: e.fixedArray.length,
        syntheticNames: [...e.fixedArray.syntheticNames],
      };
    }
    return out;
  });
}

// ---------------------------------------------------------------------------
// State field extraction
// ---------------------------------------------------------------------------

/**
 * Extract state fields from contract properties.
 *
 * State fields are non-readonly properties. They can be mutated during
 * contract execution and must be serialized into the next UTXO's locking
 * script for stateful contracts.
 *
 * If ANF properties are provided, initialValue is read from them. For
 * nested FixedArray properties the expand-fixed-arrays pass attaches a
 * `__syntheticArrayChain` to each leaf, and the iterative regrouper
 * collapses the resulting runs back into a nested FixedArray state
 * field whose `initialValue` is a nested JS array mirroring the
 * declared shape.
 */
function extractStateFields(properties: PropertyNode[], anfProgram?: ANFProgram): StateField[] {
  // Step 1: build the flat per-property regroup entries from mutable
  // properties, carrying the full synthetic-array chain so the
  // iterative regrouper can collapse nested arrays level by level.
  const flat: RegroupEntry[] = [];
  for (let i = 0; i < properties.length; i++) {
    const prop = properties[i]!;
    if (prop.readonly) continue;

    const entry: RegroupEntry = {
      name: prop.name,
      type: typeToString(prop.type),
      chain: prop.__syntheticArrayChain ? [...prop.__syntheticArrayChain] : [],
      index: i, // property position = constructor arg index
    };

    if (anfProgram) {
      const anfProp = anfProgram.properties.find(p => p.name === prop.name);
      if (anfProp?.initialValue !== undefined) {
        entry.initialValue = anfProp.initialValue as StateFieldInitialValue;
      }
    }

    flat.push(entry);
  }

  // Step 2: iteratively re-group synthetic runs. Each pass collapses
  // one level of the innermost FixedArray. Runs with empty chains
  // stay as scalar state fields. Nested arrays collapse bottom-up
  // into a single entry whose `fixedArray.elementType` is itself a
  // `FixedArray<...,N>` string and whose `syntheticNames` list is the
  // flat leaf list.
  const regrouped = regroupSyntheticRuns(flat);
  const out: StateField[] = [];
  for (const e of regrouped) {
    const field: StateField = {
      name: e.name,
      type: e.type,
      index: e.index ?? 0,
    };
    if (e.initialValue !== undefined) {
      field.initialValue = e.initialValue;
    }
    if (e.fixedArray) {
      field.fixedArray = {
        elementType: e.fixedArray.elementType,
        length: e.fixedArray.length,
        syntheticNames: [...e.fixedArray.syntheticNames],
      };
    }
    out.push(field);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Verification-descriptor enrichment
// ---------------------------------------------------------------------------


/**
 * Enrich raw emitter constructor slots with value-INDEPENDENT verification
 * metadata: param name/type, value encoding, and — for fixed-size data
 * types (PubKey, Sha256, ...) — the exact value length and push-header
 * length. Widths come from the shared `STATE_FIELD_WIDTHS` table (the same
 * table the state serializer uses), so slot and state descriptors cannot
 * drift apart.
 */
function enrichConstructorSlots(
  slots: ConstructorSlot[],
  abi: ABI,
): ConstructorSlot[] {
  return slots.map(slot => {
    const out: ConstructorSlot = { paramIndex: slot.paramIndex, byteOffset: slot.byteOffset };
    const param = abi.constructor.params[slot.paramIndex];
    if (!param) return out;
    out.name = param.name;
    out.type = param.type;
    out.valueEncoding = abiValueEncoding(param.type);
    if (out.valueEncoding === 'data') {
      const width = STATE_FIELD_WIDTHS[param.type];
      if (width && width.encoding === 'raw') {
        out.fixedValueByteLength = width.size;
        // <= 75 bytes is a direct push (1 header byte); wider needs
        // OP_PUSHDATA1 (2). P384Point is 96, so this cannot be hardcoded to 1.
        out.fixedPushHeaderBytes = width.size <= 75 ? 1 : 2;
      }
    }
    return out;
  });
}

/**
 * Build the slot-excised template digest recipe: alternating code/slot
 * pieces in script order (slots deduped by template byte offset — the same
 * placeholder cannot be excised twice).
 */
function buildTemplateDigest(slots: ConstructorSlot[]): TemplateDigest {
  const seen = new Set<number>();
  const ordered = [...slots]
    .sort((a, b) => a.byteOffset - b.byteOffset)
    .filter(s => (seen.has(s.byteOffset) ? false : (seen.add(s.byteOffset), true)));

  const pieces: TemplateDigestPiece[] = [{ kind: 'code' }];
  for (const s of ordered) {
    const piece: TemplateDigestPiece = { kind: 'slot', byteOffset: s.byteOffset };
    if (s.name !== undefined) piece.slot = s.name;
    pieces.push(piece);
    pieces.push({ kind: 'code' });
  }
  return { algorithm: 'hash256-excised-slots', pieces };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Assemble the final RunarArtifact from all compilation outputs.
 *
 * @param contract     The parsed AST contract node (for ABI/state extraction).
 * @param anfProgram   The ANF IR (for optional inclusion in artifact).
 * @param stackProgram The Stack IR (for optional inclusion in artifact).
 * @param scriptHex    The hex-encoded Bitcoin Script locking script.
 * @param scriptAsm    The human-readable ASM representation.
 * @param options      Optional settings (include IR, source map, etc).
 * @returns The complete RunarArtifact ready for serialization.
 */
export function assembleArtifact(
  contract: ContractNode,
  anfProgram: ANFProgram,
  stackProgram: StackProgram,
  scriptHex: string,
  scriptAsm: string,
  options?: AssembleOptions,
): RunarArtifact {
  const abi = extractABI(contract);
  // Propagate stack-lowering's authoritative `_codePart` decision into the ABI
  // so the SDK can supply `_codePart` for terminal var-length reads (issue #100).
  for (const m of abi.methods) {
    const sm = stackProgram.methods.find(s => s.name === m.name);
    if (sm?.usesCodePart) {
      m.usesCodePart = true;
    }
  }
  // Annotate state fields with their byte layout (encoding/byteOffset/
  // byteLength/tailOffset) so verifiers can locate state values in a
  // companion input's locking script without re-deriving the layout.
  const stateFields = annotateStateFieldLayout(
    extractStateFields(contract.properties, anfProgram),
  ) as StateField[];
  const compilerVersion = options?.compilerVersion ?? DEFAULT_COMPILER_VERSION;

  const artifact: RunarArtifact = {
    version: ARTIFACT_VERSION,
    compilerVersion,
    contractName: contract.name,
    parentClass: contract.parentClass,
    abi,
    script: scriptHex,
    asm: scriptAsm,
    buildTimestamp: buildTimestamp(),
  };

  // Optional source map
  if (options?.includeSourceMap && options.sourceMappings) {
    artifact.sourceMap = {
      mappings: options.sourceMappings,
    };
  }

  // Optional IR snapshots
  if (options?.includeIR) {
    artifact.ir = {
      anf: anfProgram,
      stack: stackProgram,
    };
  }

  // State fields (only if the contract has mutable state)
  if (stateFields.length > 0) {
    artifact.stateFields = stateFields;
    // Always include ANF IR for stateful contracts — the SDK uses it
    // to auto-compute state transitions without requiring manual newState.
    artifact.anf = anfProgram;
  }

  // Constructor slots (only if there are placeholder byte offsets), enriched
  // with verification-descriptor metadata + the template digest recipe.
  if (options?.constructorSlots && options.constructorSlots.length > 0) {
    artifact.constructorSlots = enrichConstructorSlots(options.constructorSlots, abi);
    artifact.templateDigest = buildTemplateDigest(artifact.constructorSlots);
  }

  // CodeSepIndex slots (only if there are placeholder byte offsets)
  if (options?.codeSepIndexSlots && options.codeSepIndexSlots.length > 0) {
    artifact.codeSepIndexSlots = options.codeSepIndexSlots;
  }

  // OP_CODESEPARATOR byte offsets (only for stateful contracts)
  if (options?.codeSeparatorIndex !== undefined) {
    artifact.codeSeparatorIndex = options.codeSeparatorIndex;
  }
  if (options?.codeSeparatorIndices && options.codeSeparatorIndices.length > 0) {
    artifact.codeSeparatorIndices = options.codeSeparatorIndices;
  }

  if (options?.rawScriptSpans && options.rawScriptSpans.length > 0) {
    artifact.rawScriptSpans = options.rawScriptSpans;
  }

  return artifact;
}

/**
 * Serialize an artifact to a canonical JSON string.
 *
 * Uses 2-space indentation for readability. BigInt values are serialized
 * as strings with an "n" suffix (e.g. "42n") since JSON does not support
 * BigInt natively.
 */
export function serializeArtifact(artifact: RunarArtifact): string {
  return JSON.stringify(artifact, bigintReplacer, 2);
}

/**
 * Deserialize an artifact from a JSON string.
 */
export function deserializeArtifact(json: string): RunarArtifact {
  return JSON.parse(json, bigintReviver) as RunarArtifact;
}

// ---------------------------------------------------------------------------
// BigInt JSON serialization helpers
// ---------------------------------------------------------------------------

function bigintReplacer(_key: string, value: unknown): unknown {
  if (typeof value === 'bigint') {
    return `${value}n`;
  }
  return value;
}

function bigintReviver(_key: string, value: unknown): unknown {
  if (typeof value === 'string' && /^-?\d+n$/.test(value)) {
    return BigInt(value.slice(0, -1));
  }
  return value;
}

