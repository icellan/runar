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
  Statement,
  Expression,
  StackProgram,
  ANFProgram,
} from '../ir/index.js';

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
}

export interface ConstructorSlot {
  paramIndex: number;
  byteOffset: number;
}

export interface CodeSepIndexSlot {
  byteOffset: number;
  codeSepIndex: number;
}

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

  /** Byte offsets of codeSepIndex placeholders in the script */
  codeSepIndexSlots?: CodeSepIndexSlot[];

  /** Byte offset of OP_CODESEPARATOR in the locking script (for BIP-143 sighash).
   *  For multi-method contracts, use codeSeparatorIndices instead. */
  codeSeparatorIndex?: number;

  /** Per-method OP_CODESEPARATOR byte offsets (index 0 = first public method, etc.). */
  codeSeparatorIndices?: number[];

  /** BitcoinSX text representation (available when emitSX option is true) */
  sx?: string;

  /** ISO-8601 build timestamp */
  buildTimestamp: string;
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
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ARTIFACT_VERSION = 'runar-v0.4.4';
const DEFAULT_COMPILER_VERSION = '0.4.4';

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
      out.push(entry);
      i++;
      continue;
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
      // Partial or broken run — defensive. A well-formed expansion
      // always emits all N siblings contiguously, so this only fires
      // on bugs/malformed inputs. Leave them ungrouped.
      out.push(entry);
      i++;
      continue;
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
  const mutablePropNames = isStateful
    ? new Set(contract.properties.filter(p => !p.readonly).map(p => p.name))
    : new Set<string>();

  // Methods
  const methods: ABIMethod[] = contract.methods.map(method => {
    const params = regroupAbiParams(method.params.map(paramToABI));
    const isPublic = method.visibility === 'public';
    let needsChange = false;

    if (isStateful && isPublic) {
      // Methods that mutate state or call addOutput need change output params
      needsChange = methodMutatesState(method.body, mutablePropNames) ||
                    methodHasAddOutput(method.body);
      if (needsChange) {
        params.push({ name: '_changePKH', type: 'Ripemd160' });
        params.push({ name: '_changeAmount', type: 'bigint' });
      }
      // Single-output continuation methods need _newAmount to allow changing UTXO satoshis.
      // Methods using addOutput already specify amounts explicitly per output.
      const needsNewAmount = methodMutatesState(method.body, mutablePropNames) &&
                             !methodHasAddOutput(method.body);
      if (needsNewAmount) {
        params.push({ name: '_newAmount', type: 'bigint' });
      }
      params.push({ name: 'txPreimage', type: 'SigHashPreimage' });
    }

    const result: ABIMethod = { name: method.name, params, isPublic };

    // For stateful contracts, mark terminal methods (no state mutation, no addOutput)
    if (isStateful && isPublic && !needsChange) {
      result.isTerminal = true;
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
  const stateFields = extractStateFields(contract.properties, anfProgram);
  const compilerVersion = options?.compilerVersion ?? DEFAULT_COMPILER_VERSION;

  const artifact: RunarArtifact = {
    version: ARTIFACT_VERSION,
    compilerVersion,
    contractName: contract.name,
    abi,
    script: scriptHex,
    asm: scriptAsm,
    buildTimestamp: new Date().toISOString(),
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

  // Constructor slots (only if there are placeholder byte offsets)
  if (options?.constructorSlots && options.constructorSlots.length > 0) {
    artifact.constructorSlots = options.constructorSlots;
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

// ---------------------------------------------------------------------------
// Change output detection (mirrors logic in 04-anf-lower.ts)
// ---------------------------------------------------------------------------

function methodMutatesState(stmts: Statement[], mutableProps: Set<string>): boolean {
  for (const stmt of stmts) {
    if (stmtMutatesState(stmt, mutableProps)) return true;
  }
  return false;
}

function stmtMutatesState(stmt: Statement, mutableProps: Set<string>): boolean {
  switch (stmt.kind) {
    case 'assignment':
      if (stmt.target.kind === 'property_access' && mutableProps.has(stmt.target.property)) {
        return true;
      }
      return false;
    case 'expression_statement':
      return exprMutatesState(stmt.expression, mutableProps);
    case 'if_statement':
      return methodMutatesState(stmt.then, mutableProps) ||
             (stmt.else ? methodMutatesState(stmt.else, mutableProps) : false);
    case 'for_statement':
      return stmtMutatesState(stmt.update, mutableProps) ||
             methodMutatesState(stmt.body, mutableProps);
    default:
      return false;
  }
}

function exprMutatesState(expr: Expression, mutableProps: Set<string>): boolean {
  if (expr.kind === 'increment_expr' || expr.kind === 'decrement_expr') {
    if (expr.operand.kind === 'property_access' && mutableProps.has(expr.operand.property)) {
      return true;
    }
  }
  return false;
}

function methodHasAddOutput(stmts: Statement[]): boolean {
  for (const stmt of stmts) {
    if (stmtHasAddOutput(stmt)) return true;
  }
  return false;
}

function stmtHasAddOutput(stmt: Statement): boolean {
  switch (stmt.kind) {
    case 'expression_statement':
      return exprHasAddOutput(stmt.expression);
    case 'if_statement':
      return methodHasAddOutput(stmt.then) ||
             (stmt.else ? methodHasAddOutput(stmt.else) : false);
    case 'for_statement':
      return methodHasAddOutput(stmt.body);
    default:
      return false;
  }
}

function exprHasAddOutput(expr: Expression): boolean {
  if (expr.kind === 'call_expr' && expr.callee.kind === 'property_access' && expr.callee.property === 'addOutput') {
    return true;
  }
  return false;
}
