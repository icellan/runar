import { readFileSync } from 'node:fs';
import type { ContractNode } from 'runar-ir-schema';
import { compile } from 'runar-compiler';
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
// TestContract
// ---------------------------------------------------------------------------

export class TestContract {
  private readonly contract: ContractNode;
  private readonly interpreter: RunarInterpreter;

  private constructor(contract: ContractNode, interpreter: RunarInterpreter) {
    this.contract = contract;
    this.interpreter = interpreter;
    this.interpreter.setContract(contract);
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

    const props: Record<string, RunarValue> = {};

    // Auto-populate initial values from property initializers
    for (const prop of result.contract.properties) {
      if (prop.initializer && !(prop.name in initialState)) {
        const val = extractInitializerValue(prop.initializer);
        if (val !== undefined) {
          props[prop.name] = toRunarValue(val);
        }
      }
    }

    for (const [key, value] of Object.entries(initialState)) {
      props[key] = toRunarValue(value);
    }

    const interpreter = new RunarInterpreter(props);
    // Cast through unknown: runar-compiler's ContractNode may have slightly
    // wider type unions than runar-ir-schema's (e.g. "void" PrimitiveTypeName).
    return new TestContract(result.contract as unknown as ContractNode, interpreter);
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
      for (const [key, val] of Object.entries(out.stateValues)) {
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
    for (const [key, val] of Object.entries(runarState)) {
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
