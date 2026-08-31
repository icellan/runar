/**
 * Bitcoin Script Virtual Machine for BSV.
 *
 * This is NOT a custom VM: the execution core is the upstream `@bsv/sdk`
 * `Spend` interpreter — the same production engine that validates real BSV
 * transactions. `ScriptVM` only
 *
 *   1. builds a synthetic single-input transaction context so bare scripts
 *      (with no real tx) can be run,
 *   2. drives `Spend.step()` one opcode at a time — the TS equivalent of the
 *      Go tier's `go-sdk/script/interpreter` `Debugger` hook — so the stack can
 *      be observed per opcode (step-mode debugger, used by `runar-cli debug`),
 *   3. applies the harness-level DoS bounds (`maxOps`, `maxStackSize`,
 *      `maxScriptSize`, `InputLimits.MAX_SCRIPT_BYTES`), and
 *   4. shapes the result into {@link VMResult}.
 *
 * Every opcode's semantics — arithmetic, byte-string ops, OP_LSHIFT/OP_RSHIFT
 * truncation, OP_NUM2BIN sign handling, OP_RETURN termination, real ECDSA for
 * OP_CHECKSIG / OP_CHECKMULTISIG — comes from `Spend`. Nothing here reimplements
 * an opcode. This matters because `ScriptVM` is the script-semantics half of the
 * source-vs-script differential oracle (`oracle/differential-execution.ts`): an
 * oracle written by the same project it grades is not independent.
 *
 * ## Signatures are REAL — there is no mock checksig
 *
 * The previous hand-rolled VM took a `checkSigCallback` that defaulted to
 * `() => true`, i.e. every `OP_CHECKSIG` passed. That is fail-open: a contract
 * whose only guard is a signature check "verified" against nothing. `Spend`
 * performs real secp256k1 verification against the BIP-143 sighash of the
 * synthetic context below, so a script containing `OP_CHECKSIG` only succeeds
 * when the caller supplies a signature that is genuinely valid for that context
 * (see `oracle/real-crypto-execution.ts`, which builds exactly such witnesses).
 * `checkSigCallback` is gone; there is no hand-written signature path.
 *
 * ## Accept rule and the consensus wrappers
 *
 * `ScriptVM`'s contract is "execute these bytes and report the final stack", so
 * `success` means *no evaluation error and a truthy top-of-stack* — the same
 * rule the previous VM used, and the rule that lets `executeHex()` run a bare
 * opcode fragment that legitimately leaves several items on the stack.
 *
 * The three consensus rules that `Spend.validate()` layers ON TOP of evaluation
 * — push-only unlocking scripts, the clean-stack rule, and minimal-push /
 * low-S encoding — are deliberately NOT applied here, because they are
 * meaningless for a fragment. They are enforced where a whole spend is being
 * judged: `oracle/tri-modal-execution.ts` (strict `Spend.validate()` leg) and
 * `oracle/real-crypto-execution.ts`. Pass `flags.strictEncoding` to turn the
 * encoding rules back on for this VM.
 */

import { LockingScript, UnlockingScript, Spend } from '@bsv/sdk';
import { opcodeName } from './opcodes.js';
import { isTruthy, hexToBytes } from './utils.js';
import { InputLimits, CanonicalJsonError } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

export interface VMResult {
  success: boolean;
  stack: Uint8Array[];
  altStack: Uint8Array[];
  error?: string;
  opsExecuted: number;
  maxStackDepth: number;
}

export interface VMOptions {
  /** Maximum number of non-push opcodes to execute (default 500_000). */
  maxOps?: number;
  /** Maximum number of items on the main + alt stack (default 1_000). */
  maxStackSize?: number;
  /** Maximum script size in bytes (default: unlimited for BSV). */
  maxScriptSize?: number;
  /** Behavioural flags. */
  flags?: VMFlags;
}

export interface VMFlags {
  /**
   * Apply the upstream engine's strict-encoding consensus rules: minimally
   * encoded pushes, minimally encoded script numbers, and low-S signatures.
   * Default `false` (relaxed), matching the permissiveness callers rely on when
   * executing hand-written opcode fragments.
   */
  strictEncoding?: boolean;
}

/** Result of a single step in the VM. */
export interface StepResult {
  /** Byte offset of the opcode that was executed. */
  offset: number;
  /** Name of the opcode (e.g. 'OP_ADD', 'OP_DUP', 'PUSH_20'). */
  opcode: string;
  /** Main stack after this opcode. */
  mainStack: Uint8Array[];
  /** Alt stack after this opcode. */
  altStack: Uint8Array[];
  /** Set if the opcode caused an error (e.g. OP_VERIFY on false). */
  error?: string;
  /** Which script is executing. */
  context: 'unlocking' | 'locking';
}

// ---------------------------------------------------------------------------
// Synthetic transaction context
// ---------------------------------------------------------------------------

/**
 * `Spend` needs a transaction to compute the BIP-143 sighash for OP_CHECKSIG.
 * A bare script has none, so we supply a deterministic single-input, zero-output
 * spend of a null outpoint. Identical in shape to the context used by
 * `oracle/real-crypto-execution.ts`, so a signature built for one validates on
 * the other. `transactionVersion` is 1 so that `Spend`'s relaxation switch stays
 * under our control via `flags.strictEncoding` (it auto-relaxes for version > 1).
 */
const SYNTHETIC_SOURCE_TXID = '00'.repeat(32);
const SYNTHETIC_SOURCE_SATOSHIS = 100_000;
const SYNTHETIC_TX_VERSION = 1;

/**
 * The synthetic spend context, exported so anything that needs to SIGN for this
 * VM derives the BIP-143 preimage from the same values the VM verifies against
 * instead of copying them. The version differs from
 * `oracle/real-crypto-execution.ts` (1 here, 2 there) and version is part of the
 * preimage, so a signature built against the wrong one silently fails to verify
 * — a copy that drifts would look like a codegen defect.
 */
export const SYNTHETIC_SPEND_CONTEXT = {
  sourceTXID: SYNTHETIC_SOURCE_TXID,
  sourceOutputIndex: 0,
  sourceSatoshis: SYNTHETIC_SOURCE_SATOSHIS,
  transactionVersion: SYNTHETIC_TX_VERSION,
  inputIndex: 0,
  inputSequence: 0xffffffff,
  lockTime: 0,
} as const;

/** Opcodes above OP_16 count towards the operation limit (consensus rule). */
const OP_16 = 0x60;
const OP_PUSHDATA1 = 0x4c;
const OP_PUSHDATA2 = 0x4d;
const OP_PUSHDATA4 = 0x4e;
const OP_IF = 0x63;
const OP_NOTIF = 0x64;
const OP_VERIF = 0x65;
const OP_VERNOTIF = 0x66;
const OP_ENDIF = 0x68;
const OP_RETURN = 0x6a;

// ---------------------------------------------------------------------------
// Script execution error (harness-level: limits, not opcode semantics)
// ---------------------------------------------------------------------------

class ScriptError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScriptError';
  }
}

/**
 * `ScriptEvaluationError.message` embeds a full hex dump of both stacks, which
 * for a 900 KB SLH-DSA script is megabytes of noise. Keep the first line and
 * strip the fixed prefix so the reported error stays readable and still names
 * the offending opcode.
 */
function describeError(e: unknown): string {
  const raw = e instanceof Error ? e.message : String(e);
  const firstLine = raw.split('\n', 1)[0] ?? raw;
  return firstLine.startsWith('Script evaluation error: ')
    ? firstLine.slice('Script evaluation error: '.length)
    : firstLine;
}

// ---------------------------------------------------------------------------
// Chunk byte offsets
// ---------------------------------------------------------------------------

/**
 * Byte offset of every chunk `Script.parseChunks` produces, plus a trailing
 * sentinel equal to the script length (so `offsets[i + 1]` is always defined).
 *
 * `Spend`'s program counter is a CHUNK index; callers of the step API
 * (`runar-cli debug`, source-map lookups) want a BYTE offset. This mirrors
 * `Script.parseChunks` exactly — including its post-Genesis behaviour of
 * swallowing everything after a top-level OP_RETURN into that chunk, and its
 * clamping of pushes that run past the end of the script — so chunk indices
 * line up one-for-one.
 */
function chunkByteOffsets(script: Uint8Array): number[] {
  const offsets: number[] = [];
  const length = script.length;
  let pos = 0;
  let inConditionalBlock = 0;

  while (pos < length) {
    offsets.push(pos);
    const op = script[pos++] ?? 0;

    if (op === OP_RETURN && inConditionalBlock === 0) {
      break; // rest of the script is this chunk's data
    }
    if (op === OP_IF || op === OP_NOTIF || op === OP_VERIF || op === OP_VERNOTIF) {
      inConditionalBlock++;
    } else if (op === OP_ENDIF) {
      inConditionalBlock--;
    }

    if (op > 0 && op < OP_PUSHDATA1) {
      pos = Math.min(pos + op, length);
    } else if (op === OP_PUSHDATA1) {
      const len = pos < length ? (script[pos++] ?? 0) : 0;
      pos = Math.min(pos + len, length);
    } else if (op === OP_PUSHDATA2) {
      const len = (script[pos] ?? 0) | ((script[pos + 1] ?? 0) << 8);
      pos = Math.min(pos + 2, length);
      pos = Math.min(pos + len, length);
    } else if (op === OP_PUSHDATA4) {
      const len =
        (((script[pos] ?? 0) |
          ((script[pos + 1] ?? 0) << 8) |
          ((script[pos + 2] ?? 0) << 16) |
          ((script[pos + 3] ?? 0) << 24)) >>>
        0);
      pos = Math.min(pos + 4, length);
      pos = Math.min(pos + len, length);
    }
  }

  offsets.push(length);
  return offsets;
}

/** Human-readable name for a parsed chunk's opcode. */
function chunkOpcodeName(op: number): string {
  if (op >= 0x01 && op <= 0x4b) return `PUSH_${op}`;
  if (op === OP_PUSHDATA1) return 'OP_PUSHDATA1';
  if (op === OP_PUSHDATA2) return 'OP_PUSHDATA2';
  if (op === OP_PUSHDATA4) return 'OP_PUSHDATA4';
  return opcodeName(op);
}

function toBytes(items: number[][]): Uint8Array[] {
  return items.map((i) => Uint8Array.from(i));
}

// ---------------------------------------------------------------------------
// VM
// ---------------------------------------------------------------------------

interface Position {
  context: 'unlocking' | 'locking';
  chunkIndex: number;
}

export class ScriptVM {
  private readonly maxOps: number;
  private readonly maxStackSize: number;
  private readonly maxScriptSize: number;
  readonly flags: VMFlags;

  /** The upstream engine. `null` before the first execute/load. */
  private spend: Spend | null = null;
  private unlockingOffsets: number[] = [0];
  private lockingOffsets: number[] = [0];
  private unlockingLength = 0;
  private lockingLength = 0;

  private _opsExecuted = 0;
  private _maxStackDepth = 0;
  private _isComplete = false;
  private _isSuccess = false;
  private _stepError: string | undefined;

  constructor(options: VMOptions = {}) {
    this.maxOps = options.maxOps ?? 500_000;
    this.maxStackSize = options.maxStackSize ?? 1_000;
    this.maxScriptSize = options.maxScriptSize ?? Number.MAX_SAFE_INTEGER;
    this.flags = options.flags ?? {};
  }

  // -------------------------------------------------------------------------
  // Public API — one-shot execution
  // -------------------------------------------------------------------------

  /**
   * Execute combined unlocking + locking script.
   *
   * The unlocking script is executed first; its resulting stack is the initial
   * stack for the locking script, and the locking script's outcome determines
   * success. This is exactly `Spend`'s own two-phase evaluation.
   */
  execute(unlockingScript: Uint8Array, lockingScript: Uint8Array): VMResult {
    this.assertScriptBytesUnderLimit(unlockingScript);
    this.assertScriptBytesUnderLimit(lockingScript);
    if (
      unlockingScript.length > this.maxScriptSize ||
      lockingScript.length > this.maxScriptSize
    ) {
      this.loadInternal(new Uint8Array(0), new Uint8Array(0));
      return this.buildResult('Script size exceeds maximum');
    }
    this.loadInternal(unlockingScript, lockingScript);
    return this.runToEnd();
  }

  /**
   * Execute a single script (convenience for testing) — modelled as an empty
   * unlocking script followed by `script` as the locking script.
   */
  executeScript(script: Uint8Array): VMResult {
    return this.execute(new Uint8Array(0), script);
  }

  /**
   * Execute a script from a hex string.
   */
  executeHex(scriptHex: string): VMResult {
    return this.executeScript(hexToBytes(scriptHex));
  }

  /**
   * DoS-bound: reject scripts that exceed {@link InputLimits.MAX_SCRIPT_BYTES}
   * BEFORE the interpreter starts. Each opcode iteration is cheap but a
   * multi-megabyte script would still pin the event loop; the largest
   * legitimate compiled Rúnar script (SLH-DSA-SHA2-256s, ~900 KB) fits
   * comfortably under the 1 MiB cap.
   */
  private assertScriptBytesUnderLimit(script: Uint8Array): void {
    if (script.length > InputLimits.MAX_SCRIPT_BYTES) {
      throw new CanonicalJsonError(
        'bytes',
        `ScriptVM: script length ${script.length} exceeds InputLimits.MAX_SCRIPT_BYTES (${InputLimits.MAX_SCRIPT_BYTES})`,
        { limit: InputLimits.MAX_SCRIPT_BYTES, actual: script.length },
      );
    }
  }

  // -------------------------------------------------------------------------
  // Public API — step mode
  // -------------------------------------------------------------------------

  /**
   * Load scripts for step-by-step execution.
   * Call `step()` repeatedly to advance one opcode at a time.
   */
  load(unlockingScript: Uint8Array, lockingScript: Uint8Array): void {
    this.assertScriptBytesUnderLimit(unlockingScript);
    this.assertScriptBytesUnderLimit(lockingScript);
    this.loadInternal(unlockingScript, lockingScript);
  }

  /**
   * Load scripts from hex strings for step-by-step execution.
   */
  loadHex(unlockingScriptHex: string, lockingScriptHex: string): void {
    this.load(
      unlockingScriptHex ? hexToBytes(unlockingScriptHex) : new Uint8Array(0),
      hexToBytes(lockingScriptHex),
    );
  }

  /**
   * Execute one opcode and return the step result.
   * Returns null once execution is complete.
   */
  step(): StepResult | null {
    const spend = this.spend;
    if (this._isComplete || !spend) return null;

    const pos = this.peekPosition();
    if (pos === null) {
      // Both scripts exhausted.
      this._isComplete = true;
      if (spend.ifStack.length > 0) {
        this._stepError = 'Unbalanced OP_IF/OP_ENDIF';
        this._isSuccess = false;
        return {
          offset: this.pc,
          opcode: 'END',
          mainStack: toBytes(spend.stack),
          altStack: toBytes(spend.altStack),
          error: this._stepError,
          context: spend.context === 'UnlockingScript' ? 'unlocking' : 'locking',
        };
      }
      this._isSuccess = this.topIsTruthy();
      return null;
    }

    const chunks = this.chunksFor(pos.context);
    const offsets = pos.context === 'unlocking' ? this.unlockingOffsets : this.lockingOffsets;
    const offset = offsets[pos.chunkIndex] ?? 0;
    const opcode = chunkOpcodeName(chunks[pos.chunkIndex]?.op ?? 0);

    try {
      this.countOp(chunks[pos.chunkIndex]?.op ?? 0);
      spend.step();
      this.afterStep();
      return {
        offset,
        opcode,
        mainStack: toBytes(spend.stack),
        altStack: toBytes(spend.altStack),
        context: pos.context,
      };
    } catch (e) {
      const msg = e instanceof ScriptError ? e.message : describeError(e);
      this._stepError = msg;
      this._isComplete = true;
      this._isSuccess = false;
      return {
        offset,
        opcode,
        mainStack: toBytes(spend.stack),
        altStack: toBytes(spend.altStack),
        error: msg,
        context: pos.context,
      };
    }
  }

  /** Current program counter (byte offset in the active script). */
  get pc(): number {
    const pos = this.peekPosition();
    if (pos === null) {
      const spend = this.spend;
      if (!spend) return 0;
      return spend.context === 'UnlockingScript' ? this.unlockingLength : this.lockingLength;
    }
    const offsets = pos.context === 'unlocking' ? this.unlockingOffsets : this.lockingOffsets;
    return offsets[pos.chunkIndex] ?? 0;
  }

  /** Which script is currently executing. */
  get context(): 'unlocking' | 'locking' {
    const pos = this.peekPosition();
    if (pos !== null) return pos.context;
    const spend = this.spend;
    if (!spend) return 'locking';
    return spend.context === 'UnlockingScript' ? 'unlocking' : 'locking';
  }

  /** Current main stack (copy). */
  get currentStack(): Uint8Array[] {
    return this.spend ? toBytes(this.spend.stack) : [];
  }

  /** Current alt stack (copy). */
  get currentAltStack(): Uint8Array[] {
    return this.spend ? toBytes(this.spend.altStack) : [];
  }

  /** Whether execution has completed (success or error). */
  get isComplete(): boolean {
    return this._isComplete;
  }

  /** Whether execution completed successfully (top of stack is truthy). */
  get isSuccess(): boolean {
    return this._isSuccess;
  }

  /**
   * Byte offset just after the most recently executed OP_CODESEPARATOR in the
   * currently running script (-1 if none executed yet). This is the scriptCode
   * start position for subsequent signature ops per post-Genesis BSV semantics.
   *
   * `Spend` tracks the separator as a CHUNK index (and uses
   * `chunks.slice(idx + 1)` as the subscript); this converts it to the byte
   * offset of that next chunk.
   */
  get lastCodeSeparator(): number {
    const spend = this.spend;
    if (!spend || spend.lastCodeSeparator === null) return -1;
    const inUnlocking = spend.context === 'UnlockingScript';
    const offsets = inUnlocking ? this.unlockingOffsets : this.lockingOffsets;
    const fallback = inUnlocking ? this.unlockingLength : this.lockingLength;
    return offsets[spend.lastCodeSeparator + 1] ?? fallback;
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private loadInternal(unlockingScript: Uint8Array, lockingScript: Uint8Array): void {
    this.unlockingOffsets = chunkByteOffsets(unlockingScript);
    this.lockingOffsets = chunkByteOffsets(lockingScript);
    this.unlockingLength = unlockingScript.length;
    this.lockingLength = lockingScript.length;
    this._opsExecuted = 0;
    this._maxStackDepth = 0;
    this._isComplete = false;
    this._isSuccess = false;
    this._stepError = undefined;

    this.spend = new Spend({
      sourceTXID: SYNTHETIC_SOURCE_TXID,
      sourceOutputIndex: 0,
      sourceSatoshis: SYNTHETIC_SOURCE_SATOSHIS,
      lockingScript: new LockingScript([], lockingScript, undefined, false),
      transactionVersion: SYNTHETIC_TX_VERSION,
      otherInputs: [],
      outputs: [],
      unlockingScript: new UnlockingScript([], unlockingScript, undefined, false),
      inputIndex: 0,
      inputSequence: 0xffffffff,
      lockTime: 0,
      isRelaxed: this.flags.strictEncoding !== true,
    });
  }

  private chunksFor(context: 'unlocking' | 'locking'): { op: number; data?: number[] }[] {
    const spend = this.spend!;
    return (context === 'unlocking' ? spend.unlockingScript : spend.lockingScript).chunks;
  }

  /**
   * The chunk `Spend.step()` is about to execute, mirroring the context switch
   * in `step()`'s prologue. `null` once both scripts are exhausted.
   */
  private peekPosition(): Position | null {
    const spend = this.spend;
    if (!spend) return null;
    let inUnlocking = spend.context === 'UnlockingScript';
    let pc = spend.programCounter;
    if (inUnlocking && pc >= spend.unlockingScript.chunks.length) {
      inUnlocking = false;
      pc = 0;
    }
    const chunks = inUnlocking ? spend.unlockingScript.chunks : spend.lockingScript.chunks;
    if (pc >= chunks.length) return null;
    return { context: inUnlocking ? 'unlocking' : 'locking', chunkIndex: pc };
  }

  /** Consensus op counting: everything above OP_16 counts. */
  private countOp(op: number): void {
    if (op <= OP_16) return;
    this._opsExecuted++;
    if (this._opsExecuted > this.maxOps) {
      throw new ScriptError(`Operation limit exceeded (max ${this.maxOps})`);
    }
  }

  /** Harness stack bound + depth tracking, applied after each opcode. */
  private afterStep(): void {
    const spend = this.spend!;
    const depth = spend.stack.length + spend.altStack.length;
    if (depth > this._maxStackDepth) this._maxStackDepth = depth;
    if (depth > this.maxStackSize) {
      throw new ScriptError('Stack size limit exceeded');
    }
  }

  private topIsTruthy(): boolean {
    const spend = this.spend;
    if (!spend || spend.stack.length === 0) return false;
    return isTruthy(Uint8Array.from(spend.stack[spend.stack.length - 1]!));
  }

  /**
   * Drive `Spend` to completion. Mirrors `Spend.validate()`'s evaluation loop
   * (without its consensus wrappers — see the module header), adding the
   * harness op/stack bounds between opcodes.
   */
  private runToEnd(): VMResult {
    const spend = this.spend!;
    try {
      for (;;) {
        const pos = this.peekPosition();
        if (pos === null) break;
        const chunks = this.chunksFor(pos.context);
        this.countOp(chunks[pos.chunkIndex]?.op ?? 0);
        if (!spend.step()) break;
        this.afterStep();
      }
      if (spend.ifStack.length > 0) {
        return this.buildResult('Unbalanced OP_IF/OP_ENDIF');
      }
      this._isComplete = true;
      this._isSuccess = this.topIsTruthy();
      return this.buildResult();
    } catch (e) {
      const msg = e instanceof ScriptError ? e.message : describeError(e);
      this._isComplete = true;
      this._isSuccess = false;
      this._stepError = msg;
      return this.buildResult(msg);
    }
  }

  private buildResult(error?: string): VMResult {
    const spend = this.spend;
    const stack = spend ? toBytes(spend.stack) : [];
    const altStack = spend ? toBytes(spend.altStack) : [];
    const success = !error && stack.length > 0 && isTruthy(stack[stack.length - 1]!);
    return {
      success,
      stack,
      altStack,
      error,
      opsExecuted: this._opsExecuted,
      maxStackDepth: this._maxStackDepth,
    };
  }
}
