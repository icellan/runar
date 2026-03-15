/**
 * ScriptExecutionContract — compile Rúnar contracts with baked constructor args
 * and execute them through the BSV SDK's production-grade Script interpreter.
 *
 * Unlike TestContract (which uses the reference interpreter on the AST),
 * this class validates that the **compiled Bitcoin Script hex** actually
 * executes correctly end-to-end.
 */

import type { RunarArtifact, ABIMethod, ABIParam } from 'runar-ir-schema';
import { compile } from 'runar-compiler';
import type { CompileOptions } from 'runar-compiler';
import { encodeScriptNumber, hexToBytes, bytesToHex } from './vm/utils.js';

// BSV SDK imports (peer dependency)
import {
  LockingScript,
  UnlockingScript,
  Spend,
  PrivateKey,
  Hash,
  TransactionSignature,
} from '@bsv/sdk';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ScriptExecResult {
  success: boolean;
  error?: string;
}

// ---------------------------------------------------------------------------
// ScriptExecutionContract
// ---------------------------------------------------------------------------

export class ScriptExecutionContract {
  readonly artifact: RunarArtifact;
  readonly scriptHex: string;

  private constructor(artifact: RunarArtifact, scriptHex: string) {
    this.artifact = artifact;
    this.scriptHex = scriptHex;
  }

  /**
   * Compile a Rúnar contract source with baked constructor args and return a
   * ScriptExecutionContract ready for script execution testing.
   */
  static fromSource(
    source: string,
    constructorArgs: Record<string, bigint | boolean | string>,
    fileName?: string,
    compileOptions?: Partial<CompileOptions>,
  ): ScriptExecutionContract {
    const result = compile(source, { fileName, constructorArgs, ...compileOptions });
    if (!result.success || !result.artifact || !result.scriptHex) {
      const errors = result.diagnostics
        .filter(d => d.severity === 'error')
        .map(d => d.message)
        .join('\n');
      throw new Error(`Compilation failed:\n${errors}`);
    }

    return new ScriptExecutionContract(result.artifact, result.scriptHex);
  }

  /**
   * Execute a public method with the given arguments against the compiled
   * locking script using BSV SDK's Spend interpreter.
   *
   * For pure-computation contracts (no checkSig / checkPreimage).
   */
  execute(methodName: string, args: unknown[]): ScriptExecResult {
    const unlockingHex = this.buildUnlockingScriptHex(methodName, args);
    return executeScripts(unlockingHex, this.scriptHex);
  }

  /**
   * Execute a method that uses checkSig by constructing a real transaction
   * context with a valid DER signature from the given private key.
   *
   * For P2PKH-style contracts:
   *   `args` should include the signature placeholder (will be replaced)
   *   and the public key.
   *
   * This method builds a proper sighash preimage so OP_CHECKSIG succeeds.
   */
  executeSigned(
    methodName: string,
    args: unknown[],
    sigArgIndex: number,
    privateKey: PrivateKey,
  ): ScriptExecResult {
    this.findMethod(methodName); // validate method exists
    const lockingScript = LockingScript.fromHex(this.scriptHex);

    // Build the unlocking script without the signature first, to get the
    // correct subscript for sighash computation.
    const scope =
      TransactionSignature.SIGHASH_ALL |
      TransactionSignature.SIGHASH_FORKID;

    // Compute sighash preimage
    const preimageBytes = TransactionSignature.formatBytes({
      sourceTXID: '00'.repeat(32),
      sourceOutputIndex: 0,
      sourceSatoshis: 100000,
      transactionVersion: 2,
      otherInputs: [],
      outputs: [],
      inputIndex: 0,
      subscript: lockingScript,
      inputSequence: 0xffffffff,
      lockTime: 0,
      scope,
    });

    // OP_CHECKSIG internally computes hash256(preimage) = sha256(sha256(preimage)).
    // PrivateKey.sign() does one sha256 internally, so we pre-hash once to
    // get sha256(sha256(preimage)) = hash256(preimage) as the final digest.
    const singleHash = Hash.sha256(Array.from(preimageBytes));
    const sig = privateKey.sign(singleHash);
    const txSig = new TransactionSignature(sig.r, sig.s, scope);
    const sigDer = txSig.toChecksigFormat();
    const sigHex = bytesToHex(new Uint8Array(sigDer));

    // Replace the signature argument
    const resolvedArgs = [...args];
    resolvedArgs[sigArgIndex] = sigHex;

    // Build the unlocking script with the real signature
    const unlockingHex = this.buildUnlockingScriptHex(
      methodName,
      resolvedArgs,
    );

    // Execute with the same tx context used for signing
    const unlocking = UnlockingScript.fromHex(unlockingHex);
    const spend = new Spend({
      sourceTXID: '00'.repeat(32),
      sourceOutputIndex: 0,
      sourceSatoshis: 100000,
      lockingScript,
      transactionVersion: 2,
      otherInputs: [],
      outputs: [],
      unlockingScript: unlocking,
      inputIndex: 0,
      inputSequence: 0xffffffff,
      lockTime: 0,
    });

    try {
      const ok = spend.validate();
      return { success: ok };
    } catch (e: unknown) {
      return {
        success: false,
        error: e instanceof Error ? e.message : String(e),
      };
    }
  }

  /**
   * Get the compressed public key hex for a private key (convenience helper).
   */
  static pubKeyHex(privateKey: PrivateKey): string {
    const pub = privateKey.toPublicKey();
    return pub.encode(true, 'hex') as string;
  }

  /**
   * Compute hash160 of a compressed public key (convenience helper).
   */
  static pubKeyHashHex(privateKey: PrivateKey): string {
    const pub = privateKey.toPublicKey();
    const encoded = pub.encode(true) as number[];
    const h160 = Hash.hash160(encoded) as number[];
    return bytesToHex(new Uint8Array(h160));
  }

  // -------------------------------------------------------------------------
  // Private
  // -------------------------------------------------------------------------

  private findMethod(methodName: string): ABIMethod {
    const method = this.artifact.abi.methods.find(
      m => m.name === methodName && m.isPublic,
    );
    if (!method) {
      throw new Error(
        `Method '${methodName}' not found in '${this.artifact.contractName}'`,
      );
    }
    return method;
  }

  private buildUnlockingScriptHex(
    methodName: string,
    args: unknown[],
  ): string {
    const method = this.findMethod(methodName);

    if (args.length !== method.params.length) {
      throw new Error(
        `Method '${methodName}' expects ${method.params.length} args, got ${args.length}`,
      );
    }

    const pushes: Uint8Array[] = [];
    for (let i = 0; i < args.length; i++) {
      const param = method.params[i]!;
      pushes.push(encodeArgument(args[i], param));
    }

    // Push method selector if there are multiple public methods
    const publicMethods = this.artifact.abi.methods.filter(m => m.isPublic);
    const publicIdx = publicMethods.findIndex(m => m.name === methodName);
    if (publicIdx !== -1 && publicMethods.length > 1) {
      pushes.push(encodePushData(encodeScriptNumber(BigInt(publicIdx))));
    }

    const bytes = concatUint8Arrays(pushes);
    return bytesToHex(bytes);
  }
}

// ---------------------------------------------------------------------------
// Script execution helper
// ---------------------------------------------------------------------------

function executeScripts(
  unlockingHex: string,
  lockingHex: string,
): ScriptExecResult {
  const lockingScript = LockingScript.fromHex(lockingHex);
  const unlockingScript = UnlockingScript.fromHex(unlockingHex);

  const spend = new Spend({
    sourceTXID: '00'.repeat(32),
    sourceOutputIndex: 0,
    sourceSatoshis: 100000,
    lockingScript,
    transactionVersion: 2, // relaxed mode (no strict encoding checks)
    otherInputs: [],
    outputs: [],
    unlockingScript,
    inputIndex: 0,
    inputSequence: 0xffffffff,
    lockTime: 0,
  });

  try {
    const ok = spend.validate();
    return { success: ok };
  } catch (e: unknown) {
    return {
      success: false,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

// ---------------------------------------------------------------------------
// Argument encoding (same logic as helpers.ts but standalone)
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
      const hex = arg as string;
      const bytes = hexToBytes(hex);
      return encodePushData(bytes);
    }
    default:
      throw new Error(`Unsupported parameter type: ${param.type}`);
  }
}

function encodePushData(data: Uint8Array): Uint8Array {
  if (data.length === 0) {
    return new Uint8Array([0x00]); // OP_0
  }

  if (data.length <= 75) {
    const result = new Uint8Array(1 + data.length);
    result[0] = data.length;
    result.set(data, 1);
    return result;
  }

  if (data.length <= 255) {
    const result = new Uint8Array(2 + data.length);
    result[0] = 0x4c; // OP_PUSHDATA1
    result[1] = data.length;
    result.set(data, 2);
    return result;
  }

  if (data.length <= 65535) {
    const result = new Uint8Array(3 + data.length);
    result[0] = 0x4d; // OP_PUSHDATA2
    result[1] = data.length & 0xff;
    result[2] = (data.length >> 8) & 0xff;
    result.set(data, 3);
    return result;
  }

  const result = new Uint8Array(5 + data.length);
  result[0] = 0x4e; // OP_PUSHDATA4
  result[1] = data.length & 0xff;
  result[2] = (data.length >> 8) & 0xff;
  result[3] = (data.length >> 16) & 0xff;
  result[4] = (data.length >> 24) & 0xff;
  result.set(data, 5);
  return result;
}

function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const arr of arrays) totalLength += arr.length;
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
