/**
 * Rúnar test helpers.
 *
 * Provides a TestSmartContract wrapper that loads compiled artifacts and
 * executes them in the Script VM, plus assertion helpers for test suites.
 */

import type { RunarArtifact, ABIMethod, ABIParam } from 'runar-ir-schema';
import { ScriptVM, hexToBytes, bytesToHex, encodeScriptNumber } from './vm/index.js';
import type { VMResult, VMOptions } from './vm/index.js';

// ---------------------------------------------------------------------------
// TestSmartContract
// ---------------------------------------------------------------------------

/**
 * A test wrapper around a compiled Rúnar artifact.
 *
 * Loads the artifact's locking script and ABI, then lets you call public
 * methods against the Script VM.
 */
export class TestSmartContract {
  private readonly artifact: RunarArtifact;
  readonly constructorArgs: unknown[];
  private readonly lockingScript: Uint8Array;
  private readonly lockingScriptHex: string;
  private vmOptions: VMOptions;

  private constructor(
    artifact: RunarArtifact,
    constructorArgs: unknown[],
    vmOptions: VMOptions = {},
  ) {
    this.artifact = artifact;
    this.constructorArgs = constructorArgs;
    this.lockingScriptHex = bakeConstructorArgsIntoScript(
      artifact,
      constructorArgs,
    );
    this.lockingScript = hexToBytes(this.lockingScriptHex);
    this.vmOptions = vmOptions;
  }

  /**
   * Create a test contract instance from a compiled artifact.
   *
   * @param artifact        - The compiled Rúnar artifact.
   * @param constructorArgs - Arguments matching the artifact's ABI constructor.
   * @param vmOptions       - Optional VM configuration.
   */
  static fromArtifact(
    artifact: RunarArtifact,
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
   * Get the locking script as a hex string (with constructor args baked in).
   */
  getLockingScriptHex(): string {
    return this.lockingScriptHex;
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
// Constructor arg baking
// ---------------------------------------------------------------------------

/**
 * Apply the artifact's `constructorSlots` AND `codeSepIndexSlots`
 * substitutions so the locking script carries the real constructor values
 * and adjusted codeSeparatorIndex values instead of OP_0 placeholders
 * (mirrors runar-sdk's `RunarContract.buildCodeScript` exactly).
 *
 * Previously `fromArtifact` stored `constructorArgs` but executed the raw
 * placeholder script, so any comparison against a baked readonly value
 * failed with `OP_EQUALVERIFY failed` and no hint as to why. The first fix
 * baked `constructorSlots` only; `codeSepIndexSlots` (emitted for stateful
 * contracts with variable-length state fields) were still left as OP_0,
 * diverging from the deployed script bytes.
 *
 * - No `constructorSlots` and no `codeSepIndexSlots`: the raw script is
 *   returned unchanged. Passing non-empty args is fine when the ABI
 *   declares constructor params — unreferenced readonly properties are
 *   eliminated by the compiler and simply have no placeholder to fill.
 * - `constructorSlots` present: every slot's `paramIndex` must resolve to a
 *   provided arg, and the arg count must match the ABI constructor's param
 *   count; otherwise this throws instead of silently running placeholders.
 * - `codeSepIndexSlots` present: each OP_0 placeholder is replaced with the
 *   adjusted codeSeparatorIndex (template index shifted by constructor-arg
 *   expansion and earlier codeSepIndex slot expansions), exactly as the
 *   SDK does at deploy time.
 * - `codePartLenSlots` present (N-051): each 4-byte code-part length field
 *   gets the baked code length, exactly as the SDK does at deploy time.
 */
function bakeConstructorArgsIntoScript(
  artifact: RunarArtifact,
  constructorArgs: unknown[],
): string {
  const slots = artifact.constructorSlots;
  const hasConstructorSlots = !!slots && slots.length > 0;
  const hasCodeSepSlots =
    !!artifact.codeSepIndexSlots && artifact.codeSepIndexSlots.length > 0;
  if (!hasConstructorSlots && !hasCodeSepSlots) {
    return artifact.script;
  }

  const abiParams = artifact.abi.constructor?.params ?? [];
  if (hasConstructorSlots && constructorArgs.length !== abiParams.length) {
    throw new Error(
      `TestSmartContract.fromArtifact: contract '${artifact.contractName}' ` +
        `expects ${abiParams.length} constructor arg(s) ` +
        `(${abiParams.map((p) => p.name).join(', ')}), got ${constructorArgs.length}`,
    );
  }

  type Substitution = { byteOffset: number; encoded: string };
  const subs: Substitution[] = [];

  if (hasConstructorSlots) {
    for (const slot of slots!) {
      const value = constructorArgs[slot.paramIndex];
      if (value === undefined) {
        const paramName = abiParams[slot.paramIndex]?.name ?? `#${slot.paramIndex}`;
        throw new Error(
          `TestSmartContract.fromArtifact: missing constructor arg '${paramName}' ` +
            `(paramIndex ${slot.paramIndex}) required by a constructorSlot of ` +
            `contract '${artifact.contractName}'`,
        );
      }
      subs.push({
        byteOffset: slot.byteOffset,
        encoded: encodeConstructorValueHex(value),
      });
    }
  }

  if (hasCodeSepSlots) {
    for (const rs of resolvedCodeSepSlotValues(artifact, constructorArgs)) {
      subs.push({
        byteOffset: rs.templateByteOffset,
        encoded: encodeConstructorValueHex(BigInt(rs.adjustedValue)),
      });
    }
  }

  // Substitute in descending byte-offset order so earlier splices don't
  // invalidate later offsets.
  subs.sort((a, b) => b.byteOffset - a.byteOffset);
  let script = artifact.script;
  for (const sub of subs) {
    const hexOffset = sub.byteOffset * 2;
    // Replace the 1-byte OP_0 placeholder (2 hex chars) with the encoded push.
    script = script.slice(0, hexOffset) + sub.encoded + script.slice(hexOffset + 2);
  }

  // N-051: write the deployed code-part length into every deploy-time
  // `verify_code_part_len` field, as the SDK does (`patchCodePartLenSlots`).
  // The 4-byte field is fixed-width, so no offset moves.
  const codeLen = script.length / 2;
  let le = '';
  for (let i = 0; i < 4; i++) le += ((codeLen >>> (8 * i)) & 0xff).toString(16).padStart(2, '0');
  for (const slot of artifact.codePartLenSlots ?? []) {
    let shift = 0;
    for (const s of subs) {
      if (s.byteOffset < slot.byteOffset) shift += s.encoded.length / 2 - 1;
    }
    const at = (slot.byteOffset + shift) * 2;
    script = script.slice(0, at) + le + script.slice(at + 8);
  }
  return script;
}

/**
 * Resolve the adjusted codeSep index values for all codeSepIndex slots,
 * processing them in ascending template byte-offset order so that each
 * slot's value correctly accounts for earlier slots' expansions.
 *
 * Mirror of runar-sdk `RunarContract._resolvedCodeSepSlotValues` — a pure
 * function of (artifact, constructorArgs). `encodeConstructorValueHex`
 * encodes bigints identically to the SDK's `encodeScriptNumber`
 * (OP_0 / OP_1..OP_16 / OP_1NEGATE / sign-magnitude LE push), so the
 * computed shifts are byte-exact.
 */
function resolvedCodeSepSlotValues(
  artifact: RunarArtifact,
  constructorArgs: unknown[],
): Array<{ templateByteOffset: number; adjustedValue: number }> {
  if (!artifact.codeSepIndexSlots || artifact.codeSepIndexSlots.length === 0) {
    return [];
  }
  // Sort by template byte offset ascending (left-to-right in the script)
  const sorted = [...artifact.codeSepIndexSlots].sort(
    (a, b) => a.byteOffset - b.byteOffset,
  );
  const result: Array<{ templateByteOffset: number; adjustedValue: number }> = [];
  for (const slot of sorted) {
    // Compute the fully-adjusted codeSep index: constructor expansion +
    // expansion from earlier codeSepIndex slots that precede this slot's
    // codeSepIndex.
    let shift = 0;
    if (artifact.constructorSlots) {
      for (const cs of artifact.constructorSlots) {
        if (cs.byteOffset < slot.codeSepIndex) {
          const encoded = encodeConstructorValueHex(constructorArgs[cs.paramIndex]);
          shift += encoded.length / 2 - 1;
        }
      }
    }
    for (const prev of result) {
      if (prev.templateByteOffset < slot.codeSepIndex) {
        const prevEncoded = encodeConstructorValueHex(BigInt(prev.adjustedValue));
        shift += prevEncoded.length / 2 - 1;
      }
    }
    result.push({
      templateByteOffset: slot.byteOffset,
      adjustedValue: slot.codeSepIndex + shift,
    });
  }
  return result;
}

/**
 * Encode a constructor value as a Bitcoin Script push element (hex).
 * Mirrors runar-sdk's `encodeArg`.
 */
function encodeConstructorValueHex(value: unknown): string {
  if (typeof value === 'bigint' || typeof value === 'number') {
    const n = typeof value === 'bigint' ? value : BigInt(value);
    if (n === 0n) return '00'; // OP_0
    if (n >= 1n && n <= 16n) return (0x50 + Number(n)).toString(16); // OP_1..OP_16
    if (n === -1n) return '4f'; // OP_1NEGATE
    return bytesToHex(encodePushData(encodeScriptNumber(n)));
  }
  if (typeof value === 'boolean') {
    return value ? '51' : '00';
  }
  if (typeof value === 'string') {
    // Hex-encoded data (ByteString / PubKey / Sha256 / ...)
    return bytesToHex(encodePushData(hexToBytes(value)));
  }
  throw new Error(
    `TestSmartContract.fromArtifact: unsupported constructor arg type '${typeof value}'`,
  );
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
