/**
 * TSOP test helpers.
 *
 * Provides a TestSmartContract wrapper that loads compiled artifacts and
 * executes them in the Script VM, plus assertion helpers for test suites.
 */

import type { TSOPArtifact, ABIMethod, ABIParam } from 'tsop-ir-schema';
import { ScriptVM, hexToBytes, bytesToHex, encodeScriptNumber } from './vm/index.js';
import type { VMResult, VMOptions } from './vm/index.js';

// ---------------------------------------------------------------------------
// TestSmartContract
// ---------------------------------------------------------------------------

/**
 * A test wrapper around a compiled TSOP artifact.
 *
 * Loads the artifact's locking script and ABI, then lets you call public
 * methods against the Script VM.
 */
export class TestSmartContract {
  private readonly artifact: TSOPArtifact;
  readonly constructorArgs: unknown[];
  private readonly lockingScript: Uint8Array;
  private vmOptions: VMOptions;

  private constructor(
    artifact: TSOPArtifact,
    constructorArgs: unknown[],
    vmOptions: VMOptions = {},
  ) {
    this.artifact = artifact;
    this.constructorArgs = constructorArgs;
    this.lockingScript = hexToBytes(artifact.script);
    this.vmOptions = vmOptions;
  }

  /**
   * Create a test contract instance from a compiled artifact.
   *
   * @param artifact        - The compiled TSOP artifact.
   * @param constructorArgs - Arguments matching the artifact's ABI constructor.
   * @param vmOptions       - Optional VM configuration.
   */
  static fromArtifact(
    artifact: TSOPArtifact,
    constructorArgs: unknown[],
    vmOptions: VMOptions = {},
  ): TestSmartContract {
    return new TestSmartContract(artifact, constructorArgs, vmOptions);
  }

  /**
   * Execute a public method and return the VM result.
   *
   * The method arguments are encoded into an unlocking script that pushes
   * them onto the stack, followed by a method selector index.  The locking
   * script is then executed against this stack.
   *
   * @param methodName - Name of the public method.
   * @param args       - Method arguments in ABI order.
   */
  call(methodName: string, args: unknown[]): VMResult {
    const unlockingScript = this.buildUnlockingScript(methodName, args);
    const vm = new ScriptVM(this.vmOptions);
    return vm.execute(unlockingScript, this.lockingScript);
  }

  /**
   * Get the raw locking script bytes.
   */
  getLockingScript(): Uint8Array {
    return this.lockingScript.slice();
  }

  /**
   * Get the locking script as a hex string.
   */
  getLockingScriptHex(): string {
    return this.artifact.script;
  }

  /**
   * Build an unlocking script for a method call.
   *
   * The unlocking script pushes each argument onto the stack (in reverse
   * ABI order so they appear in the correct order after being popped by
   * the locking script), then pushes the method selector index.
   *
   * @param methodName - Name of the public method.
   * @param args       - Method arguments in ABI order.
   */
  buildUnlockingScript(methodName: string, args: unknown[]): Uint8Array {
    // Find the method in the ABI.
    const methodIdx = this.artifact.abi.methods.findIndex(
      (m) => m.name === methodName && m.isPublic,
    );
    if (methodIdx === -1) {
      throw new Error(
        `Method '${methodName}' not found in artifact '${this.artifact.contractName}'`,
      );
    }
    const method = this.artifact.abi.methods[methodIdx]!;

    if (args.length !== method.params.length) {
      throw new Error(
        `Method '${methodName}' expects ${method.params.length} args, got ${args.length}`,
      );
    }

    // Encode each argument as script push data.
    const pushes: Uint8Array[] = [];
    for (let i = 0; i < args.length; i++) {
      const param = method.params[i]!;
      const arg = args[i];
      pushes.push(encodeArgument(arg, param));
    }

    // Push the method selector (index among public methods).
    const publicMethods = this.artifact.abi.methods.filter((m) => m.isPublic);
    const publicIdx = publicMethods.findIndex((m) => m.name === methodName);
    if (publicIdx !== -1 && publicMethods.length > 1) {
      pushes.push(encodePushData(encodeScriptNumber(BigInt(publicIdx))));
    }

    // Concatenate all pushes into a single script.
    return concatUint8Arrays(pushes);
  }

  /**
   * Get the artifact's ABI.
   */
  getABI(): { methods: ABIMethod[] } {
    return { methods: this.artifact.abi.methods };
  }

  /**
   * Get the contract name.
   */
  getContractName(): string {
    return this.artifact.contractName;
  }
}

// ---------------------------------------------------------------------------
// Argument encoding
// ---------------------------------------------------------------------------

function encodeArgument(arg: unknown, param: ABIParam): Uint8Array {
  switch (param.type) {
    case 'bigint': {
      const n = typeof arg === 'bigint' ? arg : BigInt(arg as number);
      return encodePushData(encodeScriptNumber(n));
    }
    case 'boolean': {
      const b = arg as boolean;
      return b ? new Uint8Array([0x51]) : new Uint8Array([0x00]);
    }
    case 'ByteString':
    case 'PubKey':
    case 'Sig':
    case 'Sha256':
    case 'Ripemd160':
    case 'Addr':
    case 'SigHashPreimage': {
      // Expect hex string.
      const hex = arg as string;
      const bytes = hexToBytes(hex);
      return encodePushData(bytes);
    }
    default:
      throw new Error(`Unsupported parameter type: ${param.type}`);
  }
}

/**
 * Wrap raw bytes in the appropriate push opcode sequence.
 */
function encodePushData(data: Uint8Array): Uint8Array {
  if (data.length === 0) {
    // OP_0
    return new Uint8Array([0x00]);
  }

  if (data.length <= 75) {
    // Direct push: <length> <data>
    const result = new Uint8Array(1 + data.length);
    result[0] = data.length;
    result.set(data, 1);
    return result;
  }

  if (data.length <= 255) {
    // OP_PUSHDATA1
    const result = new Uint8Array(2 + data.length);
    result[0] = 0x4c;
    result[1] = data.length;
    result.set(data, 2);
    return result;
  }

  if (data.length <= 65535) {
    // OP_PUSHDATA2
    const result = new Uint8Array(3 + data.length);
    result[0] = 0x4d;
    result[1] = data.length & 0xff;
    result[2] = (data.length >> 8) & 0xff;
    result.set(data, 3);
    return result;
  }

  // OP_PUSHDATA4
  const result = new Uint8Array(5 + data.length);
  result[0] = 0x4e;
  result[1] = data.length & 0xff;
  result[2] = (data.length >> 8) & 0xff;
  result[3] = (data.length >> 16) & 0xff;
  result[4] = (data.length >> 24) & 0xff;
  result.set(data, 5);
  return result;
}

function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const arr of arrays) {
    totalLength += arr.length;
  }
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/**
 * Assert that a VM execution was successful (top of stack is truthy).
 * Throws an error with details if it failed.
 */
export function expectScriptSuccess(result: VMResult): void {
  if (!result.success) {
    const stackHex = result.stack.map((s) => bytesToHex(s)).join(', ');
    throw new Error(
      `Expected script success but got failure.\n` +
        `  Error: ${result.error ?? '(stack top is falsy)'}\n` +
        `  Stack: [${stackHex}]\n` +
        `  Ops executed: ${result.opsExecuted}`,
    );
  }
}

/**
 * Assert that a VM execution failed.
 * Throws an error if execution succeeded.
 */
export function expectScriptFailure(result: VMResult): void {
  if (result.success) {
    const stackHex = result.stack.map((s) => bytesToHex(s)).join(', ');
    throw new Error(
      `Expected script failure but execution succeeded.\n` +
        `  Stack: [${stackHex}]\n` +
        `  Ops executed: ${result.opsExecuted}`,
    );
  }
}

/**
 * Assert that the top of the stack equals the expected bytes.
 */
export function expectStackTop(result: VMResult, expected: Uint8Array): void {
  if (result.stack.length === 0) {
    throw new Error(
      `Expected stack top to be ${bytesToHex(expected)} but stack is empty`,
    );
  }

  const top = result.stack[result.stack.length - 1]!;
  if (!arraysEqual(top, expected)) {
    throw new Error(
      `Expected stack top: ${bytesToHex(expected)}\n` +
        `  Actual stack top: ${bytesToHex(top)}`,
    );
  }
}

/**
 * Assert that the top of the stack equals a given script number.
 */
export function expectStackTopNum(result: VMResult, expected: bigint): void {
  expectStackTop(result, encodeScriptNumber(expected));
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
