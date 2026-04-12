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

export interface StateField {
  name: string;
  type: string;
  index: number;
  initialValue?: string | bigint | boolean;
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
// The downstream passes (ANF, stack, emit) see and operate on those scalars.
//
// For the user-facing ABI and state-field list we re-group contiguous
// `<base>__<i>` runs (i = 0..N-1, same type) back into a single logical
// entry tagged `fixedArray` so the SDK can present the array-shaped API.
// ---------------------------------------------------------------------------

const SYNTHETIC_ARRAY_SUFFIX_RE = /^(.+?)__(\d+)$/;

interface RunDescriptor<T> {
  baseName: string;
  elementType: string;
  entries: T[]; // contiguous expanded entries
}

/**
 * Walk a list of (name, type) entries and find maximal contiguous runs of
 * `<base>__<i>` entries starting from i = 0, where all entries share the
 * same base name and the same element type. Returns a list that either
 * references the original entry (ungrouped) or a run descriptor. Runs
 * shorter than 2 elements are not grouped (a single `Foo__0` is
 * indistinguishable from a normal user-named property).
 */
function detectSyntheticRuns<T extends { name: string; type: string }>(
  entries: T[],
): Array<T | RunDescriptor<T>> {
  const result: Array<T | RunDescriptor<T>> = [];
  let i = 0;
  while (i < entries.length) {
    const entry = entries[i]!;
    const match = entry.name.match(SYNTHETIC_ARRAY_SUFFIX_RE);
    if (!match || match[2] !== '0') {
      result.push(entry);
      i++;
      continue;
    }
    const base = match[1]!;
    const elementType = entry.type;

    // Extend the run while names are `<base>__<k>` with k = next expected
    // and type matches the element type.
    const runEntries: T[] = [entry];
    let k = 1;
    let j = i + 1;
    while (j < entries.length) {
      const next = entries[j]!;
      const m2 = next.name.match(SYNTHETIC_ARRAY_SUFFIX_RE);
      if (!m2 || m2[1] !== base || m2[2] !== String(k) || next.type !== elementType) {
        break;
      }
      runEntries.push(next);
      k++;
      j++;
    }

    if (runEntries.length >= 2) {
      result.push({
        baseName: base,
        elementType,
        entries: runEntries,
      });
      i = j;
    } else {
      result.push(entry);
      i++;
    }
  }
  return result;
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
 * Re-group contiguous `<base>__<i>` params that came from FixedArray
 * expansion back into a single FixedArray-typed ABI param.
 */
function regroupAbiParams(params: ABIParam[]): ABIParam[] {
  const runs = detectSyntheticRuns(params);
  const out: ABIParam[] = [];
  for (const entry of runs) {
    if ('entries' in entry) {
      const grouped: ABIParam = {
        name: entry.baseName,
        type: `FixedArray<${entry.elementType}, ${entry.entries.length}>`,
        fixedArray: {
          elementType: entry.elementType,
          length: entry.entries.length,
          syntheticNames: entry.entries.map(e => e.name),
        },
      };
      out.push(grouped);
    } else {
      out.push(entry);
    }
  }
  return out;
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
 * If ANF properties are provided, initialValue is read from them.
 */
function extractStateFields(properties: PropertyNode[], anfProgram?: ANFProgram): StateField[] {
  // Step 1: build the flat per-property state fields exactly as before.
  const flat: StateField[] = [];
  for (let i = 0; i < properties.length; i++) {
    const prop = properties[i]!;
    if (!prop.readonly) {
      const field: StateField = {
        name: prop.name,
        type: typeToString(prop.type),
        index: i, // property position = constructor arg index
      };

      if (anfProgram) {
        const anfProp = anfProgram.properties.find(p => p.name === prop.name);
        if (anfProp?.initialValue !== undefined) {
          field.initialValue = anfProp.initialValue;
        }
      }

      flat.push(field);
    }
  }

  // Step 2: re-group contiguous `<base>__<i>` runs into a single FixedArray
  // state field so the SDK presents `state.Board = [...]` instead of 9
  // separate scalar fields. The grouped field's `index` is the index of
  // the first element — still positionally meaningful for any fallback
  // constructor-index lookup in the SDK.
  const runs = detectSyntheticRuns(flat);
  const grouped: StateField[] = [];
  for (const entry of runs) {
    if ('entries' in entry) {
      const first = entry.entries[0]!;
      const field: StateField = {
        name: entry.baseName,
        type: `FixedArray<${entry.elementType}, ${entry.entries.length}>`,
        index: first.index,
        fixedArray: {
          elementType: entry.elementType,
          length: entry.entries.length,
          syntheticNames: entry.entries.map(e => e.name),
        },
      };
      // If every element has a compile-time initialValue, surface it as a
      // literal JSON-serializable array so the SDK can pre-populate
      // `state.<name>`. Mixed states (some with initializers, some without)
      // are omitted and left for constructor-arg resolution.
      const allHaveInit = entry.entries.every(e => e.initialValue !== undefined);
      if (allHaveInit) {
        // Use a JSON-string representation of the tuple; the SDK decodes it.
        // We cannot use a JS array directly because the StateField.initialValue
        // type is `string | bigint | boolean`. Encode as `[v0,v1,...]` with
        // bigint suffix "n" preserved.
        const parts = entry.entries.map(e => {
          const v = e.initialValue;
          if (typeof v === 'bigint') return `${v}n`;
          if (typeof v === 'boolean') return String(v);
          if (typeof v === 'string') return JSON.stringify(v);
          return 'null';
        });
        field.initialValue = `[${parts.join(',')}]`;
      }
      grouped.push(field);
    } else {
      grouped.push(entry);
    }
  }

  return grouped;
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
