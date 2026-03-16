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
}

export interface ConstructorSlot {
  paramIndex: number;
  byteOffset: number;
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
  /** Byte offset of OP_CODESEPARATOR in the locking script. */
  codeSeparatorIndex?: number;
  /** Per-method OP_CODESEPARATOR byte offsets. */
  codeSeparatorIndices?: number[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ARTIFACT_VERSION = 'runar-v0.1.0';
const DEFAULT_COMPILER_VERSION = '0.1.0';

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
// ABI extraction
// ---------------------------------------------------------------------------

/**
 * Extract the ABI from a ContractNode.
 *
 * The ABI describes the constructor parameters and all public methods
 * with their parameter names and types.
 */
function extractABI(contract: ContractNode): ABI {
  // Constructor
  const constructorParams: ABIParam[] = contract.constructor.params.map(paramToABI);

  const isStateful = contract.parentClass === 'StatefulSmartContract';
  const mutablePropNames = isStateful
    ? new Set(contract.properties.filter(p => !p.readonly).map(p => p.name))
    : new Set<string>();

  // Methods
  const methods: ABIMethod[] = contract.methods.map(method => {
    const params = method.params.map(paramToABI);
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
  const stateFields: StateField[] = [];

  for (let i = 0; i < properties.length; i++) {
    const prop = properties[i]!;
    if (!prop.readonly) {
      const field: StateField = {
        name: prop.name,
        type: typeToString(prop.type),
        index: i, // property position = constructor arg index
      };

      // Include initialValue from ANF property if present
      if (anfProgram) {
        const anfProp = anfProgram.properties.find(p => p.name === prop.name);
        if (anfProp?.initialValue !== undefined) {
          field.initialValue = anfProp.initialValue;
        }
      }

      stateFields.push(field);
    }
  }

  return stateFields;
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
