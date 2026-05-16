import { readFileSync } from 'node:fs';
import type { ContractNode, TypeNode } from 'runar-ir-schema';
import { compile, expandFixedArrays } from 'runar-compiler';
import { RunarInterpreter } from './interpreter/index.js';
import type { RunarValue, InterpreterResult } from './interpreter/index.js';
import { bytesToHex } from './vm/utils.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface TestCallResult {
  success: boolean;
  error?: string;
  outputs: OutputSnapshot[];
}

export interface OutputSnapshot {
  satoshis: bigint;
  [key: string]: unknown;
}

export interface MockPreimage {
  locktime: bigint;
  amount: bigint;
  version: bigint;
  sequence: bigint;
}

// ---------------------------------------------------------------------------
// Value conversion
// ---------------------------------------------------------------------------

function extractInitializerValue(expr: { kind: string; value?: unknown; op?: string; operand?: { kind: string; value?: unknown } }): unknown {
  switch (expr.kind) {
    case 'bigint_literal': return expr.value as bigint;
    case 'bool_literal': return expr.value as boolean;
    case 'bytestring_literal': return expr.value as string;
    case 'unary_expr':
      if (expr.op === '-' && expr.operand?.kind === 'bigint_literal') {
        return -(expr.operand.value as bigint);
      }
      return undefined;
    default: return undefined;
  }
}

function toRunarValue(val: unknown): RunarValue {
  if (typeof val === 'bigint') return { kind: 'bigint', value: val };
  if (typeof val === 'boolean') return { kind: 'boolean', value: val };
  if (typeof val === 'string') {
    // Hex string -> bytes
    const bytes = new Uint8Array(val.length / 2);
    for (let i = 0; i < val.length; i += 2) {
      bytes[i / 2] = parseInt(val.substring(i, i + 2), 16);
    }
    return { kind: 'bytes', value: bytes };
  }
  if (val instanceof Uint8Array) return { kind: 'bytes', value: val };
  throw new Error(`Cannot convert ${typeof val} to RunarValue`);
}

function fromRunarValue(val: RunarValue): unknown {
  switch (val.kind) {
    case 'bigint': return val.value;
    case 'boolean': return val.value;
    case 'bytes': return bytesToHex(val.value);
    case 'void': return undefined;
  }
}

// ---------------------------------------------------------------------------
// FixedArray shape support
// ---------------------------------------------------------------------------

type FixedArrayShape =
  | { kind: 'scalar' }
  | { kind: 'array'; length: number; element: FixedArrayShape };

function shapeFromType(type: TypeNode): FixedArrayShape {
  if (type.kind === 'fixed_array_type') {
    return { kind: 'array', length: type.length, element: shapeFromType(type.element) };
  }
  return { kind: 'scalar' };
}

function setRunarProp(
  out: Record<string, RunarValue>,
  baseName: string,
  shape: FixedArrayShape | undefined,
  value: unknown,
): void {
  if (!shape || shape.kind === 'scalar') {
    out[baseName] = toRunarValue(value);
    return;
  }
  if (!Array.isArray(value)) {
    throw new Error(`Property '${baseName}' is FixedArray; expected array, got ${typeof value}`);
  }
  if (value.length !== shape.length) {
    throw new Error(`Property '${baseName}' expected ${shape.length} elements, got ${value.length}`);
  }
  for (let i = 0; i < shape.length; i++) {
    setRunarProp(out, `${baseName}__${i}`, shape.element, value[i]);
  }
}

function getRunarProp(
  baseName: string,
  shape: FixedArrayShape | undefined,
  flat: Record<string, RunarValue>,
): unknown {
  if (!shape || shape.kind === 'scalar') {
    const val = flat[baseName];
    return val !== undefined ? fromRunarValue(val) : undefined;
  }
  const arr: unknown[] = [];
  for (let i = 0; i < shape.length; i++) {
    arr.push(getRunarProp(`${baseName}__${i}`, shape.element, flat));
  }
  return arr;
}

// ---------------------------------------------------------------------------
// TestContract
// ---------------------------------------------------------------------------

export class TestContract {
  private readonly contract: ContractNode;
  private readonly interpreter: RunarInterpreter;
  private readonly shapeMap: Map<string, FixedArrayShape>;
  private readonly syntheticLeafPrefixes: string[];

  private constructor(
    contract: ContractNode,
    interpreter: RunarInterpreter,
    shapeMap: Map<string, FixedArrayShape>,
  ) {
    this.contract = contract;
    this.interpreter = interpreter;
    this.shapeMap = shapeMap;
    this.syntheticLeafPrefixes = Array.from(shapeMap.keys()).map(name => `${name}__`);
    this.interpreter.setContract(contract);
  }

  private isSyntheticLeaf(key: string): boolean {
    return this.syntheticLeafPrefixes.some(prefix => key.startsWith(prefix));
  }

  /**
   * Create a test contract from source code in any supported format.
   *
   * Pass `fileName` with the appropriate extension to select the parser:
   * - `.runar.ts` — TypeScript (default)
   * - `.runar.sol` — Solidity-like
   * - `.runar.move` — Move-style
   */
  static fromSource(source: string, initialState: Record<string, unknown> = {}, fileName?: string): TestContract {

    const result = compile(source, { typecheckOnly: true, fileName });
    if (!result.success || !result.contract) {
      const errors = result.diagnostics
        .filter(d => d.severity === 'error')
        .map(d => d.message)
        .join('\n');
      throw new Error(`Compilation failed:\n${errors}`);
    }

    // Snapshot FixedArray property shapes from the pre-expansion AST.
    // Synthetic leaf names follow the compiler's convention `${name}__${i}`
    // (recursively), see compilers/.../03b-expand-fixed-arrays.ts.
    const shapeMap = new Map<string, FixedArrayShape>();
    for (const prop of result.contract.properties) {
      if (prop.type.kind === 'fixed_array_type') {
        shapeMap.set(prop.name, shapeFromType(prop.type));
      }
    }

    const expanded = expandFixedArrays(result.contract);
    if (expanded.errors.length > 0) {
      throw new Error(
        `FixedArray expansion failed:\n${expanded.errors.map(e => e.message).join('\n')}`,
      );
    }
    const contract = expanded.contract;

    const props: Record<string, RunarValue> = {};

    // Auto-populate initial values from property initializers. After
    // expandFixedArrays, every property is scalar — array literals have
    // already been distributed across the synthetic siblings.
    for (const prop of contract.properties) {
      if (prop.initializer && !(prop.name in initialState)) {
        const val = extractInitializerValue(prop.initializer);
        if (val !== undefined) {
          props[prop.name] = toRunarValue(val);
        }
      }
    }

    for (const [key, value] of Object.entries(initialState)) {
      setRunarProp(props, key, shapeMap.get(key), value);
    }

    const interpreter = new RunarInterpreter(props);
    // Cast through unknown: runar-compiler's ContractNode may have slightly
    // wider type unions than runar-ir-schema's (e.g. "void" PrimitiveTypeName).
    return new TestContract(contract as unknown as ContractNode, interpreter, shapeMap);
  }

  /**
   * Create a test contract from a file path.
   */
  static fromFile(filePath: string, initialState: Record<string, unknown> = {}): TestContract {
    const source = readFileSync(filePath, 'utf8');
    return TestContract.fromSource(source, initialState, filePath);
  }

  /**
   * Call a public method on the contract.
   */
  call(methodName: string, args: Record<string, unknown> = {}): TestCallResult {
    this.interpreter.resetOutputs();

    const runarArgs: Record<string, RunarValue> = {};
    for (const [key, value] of Object.entries(args)) {
      runarArgs[key] = toRunarValue(value);
    }

    const result: InterpreterResult = this.interpreter.executeMethod(
      this.contract,
      methodName,
      runarArgs,
    );

    const rawOutputs = this.interpreter.getOutputs();
    const outputs: OutputSnapshot[] = rawOutputs.map(out => {
      const snapshot: OutputSnapshot = {
        satoshis: out.satoshis.kind === 'bigint' ? out.satoshis.value : 0n,
      };
      for (const [topName, shape] of this.shapeMap) {
        snapshot[topName] = getRunarProp(topName, shape, out.stateValues);
      }
      for (const [key, val] of Object.entries(out.stateValues)) {
        if (this.shapeMap.has(key) || this.isSyntheticLeaf(key)) continue;
        snapshot[key] = fromRunarValue(val);
      }
      return snapshot;
    });

    return {
      success: result.success,
      error: result.error,
      outputs,
    };
  }

  /**
   * Get the current contract state as plain JavaScript values.
   */
  get state(): Record<string, unknown> {
    const runarState = this.interpreter.getState();
    const result: Record<string, unknown> = {};
    for (const [topName, shape] of this.shapeMap) {
      result[topName] = getRunarProp(topName, shape, runarState);
    }
    for (const [key, val] of Object.entries(runarState)) {
      if (this.shapeMap.has(key) || this.isSyntheticLeaf(key)) continue;
      result[key] = fromRunarValue(val);
    }
    return result;
  }

  /**
   * Configure mock preimage values for testing time locks, amounts, etc.
   */
  setMockPreimage(overrides: Partial<MockPreimage>): void {
    const converted: Record<string, bigint> = {};
    for (const [k, v] of Object.entries(overrides)) {
      converted[k] = v as bigint;
    }
    this.interpreter.setMockPreimage(converted);
  }

  /**
   * Configure mock preimage byte fields (hashPrevouts, outpoint, etc.).
   */
  setMockPreimageBytes(overrides: Record<string, Uint8Array>): void {
    this.interpreter.setMockPreimageBytes(overrides);
  }
}
