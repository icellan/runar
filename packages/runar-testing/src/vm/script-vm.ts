/**
 * Bitcoin Script Virtual Machine for BSV.
 *
 * Executes raw Bitcoin Script bytes and returns the final stack state.
 * Implements all opcodes in the BSV opcode set including re-enabled ops
 * (OP_CAT, OP_SPLIT, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT,
 *  OP_AND, OP_OR, OP_XOR, OP_NUM2BIN, OP_BIN2NUM).
 */

import { createHash } from 'node:crypto';
import { Opcode, opcodeName } from './opcodes.js';
import {
  encodeScriptNumber,
  decodeScriptNumber,
  isTruthy,
  hexToBytes,
} from './utils.js';

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
  /**
   * Optional callback for OP_CHECKSIG / OP_CHECKSIGVERIFY.
   * If not provided, checksig always returns true (mock mode).
   */
  checkSigCallback?: (sig: Uint8Array, pubkey: Uint8Array) => boolean;
}

export interface VMFlags {
  /** Enable BSV sighash fork-id semantics. */
  enableSighashForkId?: boolean;
  /** Enable BSV re-enabled opcodes (CAT, SPLIT, MUL, etc). Default true. */
  enableOpCodes?: boolean;
  /** Require strict DER / pubkey encoding. */
  strictEncoding?: boolean;
}

// ---------------------------------------------------------------------------
// Script execution error
// ---------------------------------------------------------------------------

class ScriptError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScriptError';
  }
}

// ---------------------------------------------------------------------------
// VM implementation
// ---------------------------------------------------------------------------

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

export class ScriptVM {
  private stack: Uint8Array[] = [];
  private altStack: Uint8Array[] = [];
  /**
   * If-stack tracks whether we are in an executing branch.
   * true = executing, false = not executing (skip until OP_ELSE/OP_ENDIF).
   */
  private ifStack: boolean[] = [];
  private opsExecuted = 0;
  private maxStackDepth = 0;

  private readonly maxOps: number;
  private readonly maxStackSize: number;
  private readonly maxScriptSize: number;
  readonly flags: VMFlags;
  private readonly checkSigCallback: (sig: Uint8Array, pubkey: Uint8Array) => boolean;

  // Step mode state
  private _script: Uint8Array | null = null;
  private _lockingScript: Uint8Array | null = null;
  private _pc = 0;
  private _context: 'unlocking' | 'locking' = 'locking';
  private _isComplete = false;
  private _isSuccess = false;
  private _stepError: string | undefined;

  constructor(options: VMOptions = {}) {
    this.maxOps = options.maxOps ?? 500_000;
    this.maxStackSize = options.maxStackSize ?? 1_000;
    this.maxScriptSize = options.maxScriptSize ?? Number.MAX_SAFE_INTEGER;
    this.flags = options.flags ?? { enableOpCodes: true };
    this.checkSigCallback = options.checkSigCallback ?? (() => true);
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Execute combined unlocking + locking script.
   *
   * The unlocking script is executed first.  Its resulting stack is then
   * used as the initial stack for the locking script.  The final result
   * of the locking script determines success.
   */
  execute(unlockingScript: Uint8Array, lockingScript: Uint8Array): VMResult {
    this.reset();

    // Run unlocking script.
    const unlockResult = this.runScript(unlockingScript);
    if (unlockResult.error) {
      return unlockResult;
    }

    // The stack carries over; the alt stack should be empty after
    // each script execution in real Bitcoin, but we allow it for testing.

    // Run locking script.
    const lockResult = this.runScript(lockingScript);
    return lockResult;
  }

  /**
   * Execute a single script (convenience for testing).
   */
  executeScript(script: Uint8Array): VMResult {
    this.reset();
    return this.runScript(script);
  }

  /**
   * Execute a script from a hex string.
   */
  executeHex(scriptHex: string): VMResult {
    return this.executeScript(hexToBytes(scriptHex));
  }

  // -------------------------------------------------------------------------
  // Step mode API
  // -------------------------------------------------------------------------

  /**
   * Load scripts for step-by-step execution.
   * Call `step()` repeatedly to advance one opcode at a time.
   */
  load(unlockingScript: Uint8Array, lockingScript: Uint8Array): void {
    this.reset();
    this._lockingScript = lockingScript;
    this._script = unlockingScript.length > 0 ? unlockingScript : lockingScript;
    this._context = unlockingScript.length > 0 ? 'unlocking' : 'locking';
    this._pc = 0;
    this._isComplete = false;
    this._isSuccess = false;
    this._stepError = undefined;
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
   * Returns null if execution is already complete.
   */
  step(): StepResult | null {
    if (this._isComplete || !this._script) return null;

    const script = this._script;
    const offset = this._pc;

    // Check if we've reached the end of the current script
    if (this._pc >= script.length) {
      if (this._context === 'unlocking' && this._lockingScript) {
        // Switch from unlocking to locking script
        this._script = this._lockingScript;
        this._context = 'locking';
        this._pc = 0;
        return this.step(); // Recurse to step into locking script
      }

      // End of locking script — check if/else balance and determine success
      if (this.ifStack.length !== 0) {
        this._stepError = 'Unbalanced OP_IF/OP_ENDIF';
        this._isComplete = true;
        this._isSuccess = false;
        return {
          offset,
          opcode: 'END',
          mainStack: [...this.stack],
          altStack: [...this.altStack],
          error: this._stepError,
          context: this._context,
        };
      }

      this._isComplete = true;
      this._isSuccess = this.stack.length > 0 && isTruthy(this.stack[this.stack.length - 1]!);
      return null;
    }

    const byte = script[this._pc]!;
    const opName = this.getOpcodeName(byte);

    try {
      this._pc = this.executeOneOpcode(script, this._pc);

      return {
        offset,
        opcode: opName,
        mainStack: [...this.stack],
        altStack: [...this.altStack],
        context: this._context,
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      this._stepError = msg;
      this._isComplete = true;
      this._isSuccess = false;
      return {
        offset,
        opcode: opName,
        mainStack: [...this.stack],
        altStack: [...this.altStack],
        error: msg,
        context: this._context,
      };
    }
  }

  /** Current program counter (byte offset in the active script). */
  get pc(): number { return this._pc; }

  /** Which script is currently executing. */
  get context(): 'unlocking' | 'locking' { return this._context; }

  /** Current main stack (copy). */
  get currentStack(): Uint8Array[] { return [...this.stack]; }

  /** Current alt stack (copy). */
  get currentAltStack(): Uint8Array[] { return [...this.altStack]; }

  /** Whether execution has completed (success or error). */
  get isComplete(): boolean { return this._isComplete; }

  /** Whether execution completed successfully (top of stack is truthy). */
  get isSuccess(): boolean { return this._isSuccess; }

  /**
   * Get a human-readable name for the opcode at the given position.
   */
  private getOpcodeName(byte: number): string {
    if (byte >= 0x01 && byte <= 0x4b) return `PUSH_${byte}`;
    if (byte === 0x4c) return 'OP_PUSHDATA1';
    if (byte === 0x4d) return 'OP_PUSHDATA2';
    if (byte === 0x4e) return 'OP_PUSHDATA4';
    return opcodeName(byte) ?? `OP_UNKNOWN_0x${byte.toString(16)}`;
  }

  /**
   * Execute a single opcode at the given position in the script.
   * Returns the new position after the opcode (and any push data).
   *
   * This is the step-mode equivalent of one iteration of runScript's loop.
   * It delegates to runScript with a single-byte-offset trick: we run
   * from `pos` and stop after one opcode by using an internal flag.
   */
  private executeOneOpcode(script: Uint8Array, pos: number): number {
    const byte = script[pos]!;
    let i = pos + 1;

    // Push data: 0x01..0x4b
    if (byte >= 0x01 && byte <= 0x4b) {
      if (this.isExecuting()) {
        if (i + byte > script.length) throw new ScriptError('Push data extends past end of script');
        this.push(script.slice(i, i + byte));
      }
      return i + byte;
    }

    // OP_0
    if (byte === Opcode.OP_0) {
      if (this.isExecuting()) this.push(new Uint8Array(0));
      return i;
    }

    // OP_PUSHDATA1
    if (byte === Opcode.OP_PUSHDATA1) {
      if (i >= script.length) throw new ScriptError('OP_PUSHDATA1: missing length byte');
      const len = script[i]!; i++;
      if (this.isExecuting()) {
        if (i + len > script.length) throw new ScriptError('OP_PUSHDATA1: data extends past end of script');
        this.push(script.slice(i, i + len));
      }
      return i + len;
    }

    // OP_PUSHDATA2
    if (byte === Opcode.OP_PUSHDATA2) {
      if (i + 1 >= script.length) throw new ScriptError('OP_PUSHDATA2: missing length bytes');
      const len = script[i]! | (script[i + 1]! << 8); i += 2;
      if (this.isExecuting()) {
        if (i + len > script.length) throw new ScriptError('OP_PUSHDATA2: data extends past end of script');
        this.push(script.slice(i, i + len));
      }
      return i + len;
    }

    // OP_PUSHDATA4
    if (byte === Opcode.OP_PUSHDATA4) {
      if (i + 3 >= script.length) throw new ScriptError('OP_PUSHDATA4: missing length bytes');
      const len = script[i]! | (script[i + 1]! << 8) | (script[i + 2]! << 16) | (script[i + 3]! << 24);
      i += 4;
      if (this.isExecuting()) {
        if (i + len > script.length) throw new ScriptError('OP_PUSHDATA4: data extends past end of script');
        this.push(script.slice(i, i + len));
      }
      return i + len;
    }

    // OP_1NEGATE through OP_16
    if (byte >= Opcode.OP_1NEGATE && byte <= Opcode.OP_16) {
      if (this.isExecuting()) {
        if (byte === Opcode.OP_1NEGATE) this.pushNum(-1n);
        else this.pushNum(BigInt(byte - Opcode.OP_1 + 1));
      }
      return i;
    }

    // Flow control: handle if/else/endif directly (can't delegate to
    // runScript because of the ifStack balance check at end-of-script)
    if (byte === Opcode.OP_IF || byte === Opcode.OP_NOTIF) {
      if (this.isExecuting()) {
        const val = this.pop();
        this.ifStack.push(byte === Opcode.OP_IF ? isTruthy(val) : !isTruthy(val));
      } else {
        this.ifStack.push(false);
      }
      return i;
    }
    if (byte === Opcode.OP_ELSE) {
      if (this.ifStack.length === 0) throw new ScriptError('OP_ELSE without OP_IF');
      const last = this.ifStack.length - 1;
      // Only flip if all parent branches are executing
      const parentExec = this.ifStack.slice(0, last).every(v => v);
      this.ifStack[last] = parentExec && !this.ifStack[last]!;
      return i;
    }
    if (byte === Opcode.OP_ENDIF) {
      if (this.ifStack.length === 0) throw new ScriptError('OP_ENDIF without OP_IF');
      this.ifStack.pop();
      return i;
    }

    // Skip non-executing opcodes
    if (!this.isExecuting()) return i;

    // All remaining opcodes: delegate to runScript on a single-byte script.
    // Save and restore ifStack to bypass the end-of-script balance check.
    const savedIfStack = [...this.ifStack];
    this.ifStack = [];

    const result = this.runScript(new Uint8Array([byte]));

    this.ifStack = savedIfStack;

    if (result.error) throw new ScriptError(result.error);
    return i;
  }

  // -------------------------------------------------------------------------
  // Internal: reset state
  // -------------------------------------------------------------------------

  private reset(): void {
    this.stack = [];
    this.altStack = [];
    this.ifStack = [];
    this.opsExecuted = 0;
    this.maxStackDepth = 0;
    this._script = null;
    this._lockingScript = null;
    this._pc = 0;
    this._isComplete = false;
    this._isSuccess = false;
    this._stepError = undefined;
  }

  // -------------------------------------------------------------------------
  // Internal: build result
  // -------------------------------------------------------------------------

  private buildResult(error?: string): VMResult {
    const success =
      !error && this.stack.length > 0 && isTruthy(this.stack[this.stack.length - 1]!);
    return {
      success: error ? false : success,
      stack: [...this.stack],
      altStack: [...this.altStack],
      error,
      opsExecuted: this.opsExecuted,
      maxStackDepth: this.maxStackDepth,
    };
  }

  // -------------------------------------------------------------------------
  // Internal: update max stack depth
  // -------------------------------------------------------------------------

  private trackStackDepth(): void {
    const depth = this.stack.length + this.altStack.length;
    if (depth > this.maxStackDepth) {
      this.maxStackDepth = depth;
    }
  }

  // -------------------------------------------------------------------------
  // Internal: check stack size limit
  // -------------------------------------------------------------------------

  private checkStackSize(): void {
    if (this.stack.length + this.altStack.length > this.maxStackSize) {
      throw new ScriptError('Stack size limit exceeded');
    }
  }

  // -------------------------------------------------------------------------
  // Internal: whether we are in an executing branch
  // -------------------------------------------------------------------------

  private isExecuting(): boolean {
    return this.ifStack.every((v) => v);
  }

  // -------------------------------------------------------------------------
  // Stack helpers
  // -------------------------------------------------------------------------

  private push(item: Uint8Array): void {
    this.stack.push(item);
    this.trackStackDepth();
    this.checkStackSize();
  }

  private pop(): Uint8Array {
    if (this.stack.length === 0) {
      throw new ScriptError('Stack underflow');
    }
    return this.stack.pop()!;
  }

  private peek(offset = 0): Uint8Array {
    const idx = this.stack.length - 1 - offset;
    if (idx < 0) {
      throw new ScriptError('Stack underflow');
    }
    return this.stack[idx]!;
  }

  private pushNum(n: bigint): void {
    this.push(encodeScriptNumber(n));
  }

  private popNum(): bigint {
    return decodeScriptNumber(this.pop());
  }

  private pushBool(b: boolean): void {
    this.push(b ? new Uint8Array([1]) : new Uint8Array(0));
  }

  // -------------------------------------------------------------------------
  // Internal: run a single script
  // -------------------------------------------------------------------------

  private runScript(script: Uint8Array): VMResult {
    if (script.length > this.maxScriptSize) {
      return this.buildResult('Script size exceeds maximum');
    }

    let i = 0;
    try {
      while (i < script.length) {
        const byte = script[i]!;
        i++;

        // ------------------------------------------------------------------
        // Push data: 0x01 .. 0x4b => push next N bytes
        // ------------------------------------------------------------------
        if (byte >= 0x01 && byte <= 0x4b) {
          if (this.isExecuting()) {
            if (i + byte > script.length) {
              throw new ScriptError('Push data extends past end of script');
            }
            this.push(script.slice(i, i + byte));
          }
          i += byte;
          continue;
        }

        // ------------------------------------------------------------------
        // OP_0 / OP_FALSE (0x00): push empty byte array
        // ------------------------------------------------------------------
        if (byte === Opcode.OP_0) {
          if (this.isExecuting()) {
            this.push(new Uint8Array(0));
          }
          continue;
        }

        // ------------------------------------------------------------------
        // OP_PUSHDATA1 (0x4c)
        // ------------------------------------------------------------------
        if (byte === Opcode.OP_PUSHDATA1) {
          if (i >= script.length) {
            throw new ScriptError('OP_PUSHDATA1: missing length byte');
          }
          const len = script[i]!;
          i++;
          if (this.isExecuting()) {
            if (i + len > script.length) {
              throw new ScriptError('OP_PUSHDATA1: data extends past end of script');
            }
            this.push(script.slice(i, i + len));
          }
          i += len;
          continue;
        }

        // ------------------------------------------------------------------
        // OP_PUSHDATA2 (0x4d)
        // ------------------------------------------------------------------
        if (byte === Opcode.OP_PUSHDATA2) {
          if (i + 1 >= script.length) {
            throw new ScriptError('OP_PUSHDATA2: missing length bytes');
          }
          const len = script[i]! | (script[i + 1]! << 8);
          i += 2;
          if (this.isExecuting()) {
            if (i + len > script.length) {
              throw new ScriptError('OP_PUSHDATA2: data extends past end of script');
            }
            this.push(script.slice(i, i + len));
          }
          i += len;
          continue;
        }

        // ------------------------------------------------------------------
        // OP_PUSHDATA4 (0x4e)
        // ------------------------------------------------------------------
        if (byte === Opcode.OP_PUSHDATA4) {
          if (i + 3 >= script.length) {
            throw new ScriptError('OP_PUSHDATA4: missing length bytes');
          }
          const len =
            script[i]! |
            (script[i + 1]! << 8) |
            (script[i + 2]! << 16) |
            (script[i + 3]! << 24);
          i += 4;
          if (this.isExecuting()) {
            if (i + len > script.length) {
              throw new ScriptError('OP_PUSHDATA4: data extends past end of script');
            }
            this.push(script.slice(i, i + len));
          }
          i += len;
          continue;
        }

        // ------------------------------------------------------------------
        // OP_1NEGATE (0x4f): push -1
        // ------------------------------------------------------------------
        if (byte === Opcode.OP_1NEGATE) {
          if (this.isExecuting()) {
            this.pushNum(-1n);
          }
          continue;
        }

        // ------------------------------------------------------------------
        // OP_1 .. OP_16 (0x51 .. 0x60): push number 1..16
        // ------------------------------------------------------------------
        if (byte >= Opcode.OP_1 && byte <= Opcode.OP_16) {
          if (this.isExecuting()) {
            this.pushNum(BigInt(byte - Opcode.OP_1 + 1));
          }
          continue;
        }

        // ------------------------------------------------------------------
        // Flow control: OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF
        // ------------------------------------------------------------------
        if (byte === Opcode.OP_IF || byte === Opcode.OP_NOTIF) {
          this.countOp();
          if (this.isExecuting()) {
            const val = this.pop();
            let cond = isTruthy(val);
            if (byte === Opcode.OP_NOTIF) {
              cond = !cond;
            }
            this.ifStack.push(cond);
          } else {
            // Not executing — push false so we skip everything
            this.ifStack.push(false);
          }
          continue;
        }

        if (byte === Opcode.OP_ELSE) {
          if (this.ifStack.length === 0) {
            throw new ScriptError('OP_ELSE without matching OP_IF');
          }
          // Only flip if the parent branches are all executing.
          // Check if all parents (except the last) are executing.
          const parentExecuting =
            this.ifStack.length <= 1 ||
            this.ifStack.slice(0, -1).every((v) => v);
          if (parentExecuting) {
            this.ifStack[this.ifStack.length - 1] =
              !this.ifStack[this.ifStack.length - 1]!;
          }
          continue;
        }

        if (byte === Opcode.OP_ENDIF) {
          if (this.ifStack.length === 0) {
            throw new ScriptError('OP_ENDIF without matching OP_IF');
          }
          this.ifStack.pop();
          continue;
        }

        // ------------------------------------------------------------------
        // Skip opcodes if we are not executing
        // ------------------------------------------------------------------
        if (!this.isExecuting()) {
          continue;
        }

        // ------------------------------------------------------------------
        // From here on, we are always in an executing branch.
        // ------------------------------------------------------------------

        // OP_NOP (0x61)
        if (byte === Opcode.OP_NOP) {
          this.countOp();
          continue;
        }

        // OP_VERIFY (0x69)
        if (byte === Opcode.OP_VERIFY) {
          this.countOp();
          const val = this.pop();
          if (!isTruthy(val)) {
            throw new ScriptError('OP_VERIFY failed');
          }
          continue;
        }

        // OP_RETURN (0x6a)
        if (byte === Opcode.OP_RETURN) {
          throw new ScriptError('OP_RETURN encountered');
        }

        // ---------------------------------------------------------------
        // Stack operations
        // ---------------------------------------------------------------

        if (byte === Opcode.OP_TOALTSTACK) {
          this.countOp();
          this.altStack.push(this.pop());
          this.trackStackDepth();
          continue;
        }

        if (byte === Opcode.OP_FROMALTSTACK) {
          this.countOp();
          if (this.altStack.length === 0) {
            throw new ScriptError('Alt stack underflow');
          }
          this.push(this.altStack.pop()!);
          continue;
        }

        if (byte === Opcode.OP_2DROP) {
          this.countOp();
          this.pop();
          this.pop();
          continue;
        }

        if (byte === Opcode.OP_2DUP) {
          this.countOp();
          const b = this.peek(0);
          const a = this.peek(1);
          this.push(a.slice());
          this.push(b.slice());
          continue;
        }

        if (byte === Opcode.OP_3DUP) {
          this.countOp();
          const c = this.peek(0);
          const b = this.peek(1);
          const a = this.peek(2);
          this.push(a.slice());
          this.push(b.slice());
          this.push(c.slice());
          continue;
        }

        if (byte === Opcode.OP_2OVER) {
          this.countOp();
          const a = this.peek(3);
          const b = this.peek(2);
          this.push(a.slice());
          this.push(b.slice());
          continue;
        }

        if (byte === Opcode.OP_2ROT) {
          this.countOp();
          if (this.stack.length < 6) {
            throw new ScriptError('Stack underflow for OP_2ROT');
          }
          const idx = this.stack.length - 6;
          const a = this.stack.splice(idx, 2);
          this.stack.push(a[0]!, a[1]!);
          this.trackStackDepth();
          continue;
        }

        if (byte === Opcode.OP_2SWAP) {
          this.countOp();
          if (this.stack.length < 4) {
            throw new ScriptError('Stack underflow for OP_2SWAP');
          }
          const len = this.stack.length;
          // Swap positions: [... a b c d] -> [... c d a b]
          const a = this.stack[len - 4]!;
          const b = this.stack[len - 3]!;
          const c = this.stack[len - 2]!;
          const d = this.stack[len - 1]!;
          this.stack[len - 4] = c;
          this.stack[len - 3] = d;
          this.stack[len - 2] = a;
          this.stack[len - 1] = b;
          continue;
        }

        if (byte === Opcode.OP_IFDUP) {
          this.countOp();
          const top = this.peek();
          if (isTruthy(top)) {
            this.push(top.slice());
          }
          continue;
        }

        if (byte === Opcode.OP_DEPTH) {
          this.countOp();
          this.pushNum(BigInt(this.stack.length));
          continue;
        }

        if (byte === Opcode.OP_DROP) {
          this.countOp();
          this.pop();
          continue;
        }

        if (byte === Opcode.OP_DUP) {
          this.countOp();
          this.push(this.peek().slice());
          continue;
        }

        if (byte === Opcode.OP_NIP) {
          this.countOp();
          if (this.stack.length < 2) {
            throw new ScriptError('Stack underflow for OP_NIP');
          }
          this.stack.splice(this.stack.length - 2, 1);
          continue;
        }

        if (byte === Opcode.OP_OVER) {
          this.countOp();
          this.push(this.peek(1).slice());
          continue;
        }

        if (byte === Opcode.OP_PICK) {
          this.countOp();
          const n = Number(this.popNum());
          if (n < 0 || n >= this.stack.length) {
            throw new ScriptError(`OP_PICK: invalid index ${n}`);
          }
          this.push(this.peek(n).slice());
          continue;
        }

        if (byte === Opcode.OP_ROLL) {
          this.countOp();
          const n = Number(this.popNum());
          if (n < 0 || n >= this.stack.length) {
            throw new ScriptError(`OP_ROLL: invalid index ${n}`);
          }
          const idx = this.stack.length - 1 - n;
          const item = this.stack.splice(idx, 1)[0]!;
          this.stack.push(item);
          continue;
        }

        if (byte === Opcode.OP_ROT) {
          this.countOp();
          if (this.stack.length < 3) {
            throw new ScriptError('Stack underflow for OP_ROT');
          }
          const idx = this.stack.length - 3;
          const item = this.stack.splice(idx, 1)[0]!;
          this.stack.push(item);
          continue;
        }

        if (byte === Opcode.OP_SWAP) {
          this.countOp();
          if (this.stack.length < 2) {
            throw new ScriptError('Stack underflow for OP_SWAP');
          }
          const len = this.stack.length;
          const tmp = this.stack[len - 1]!;
          this.stack[len - 1] = this.stack[len - 2]!;
          this.stack[len - 2] = tmp;
          continue;
        }

        if (byte === Opcode.OP_TUCK) {
          this.countOp();
          if (this.stack.length < 2) {
            throw new ScriptError('Stack underflow for OP_TUCK');
          }
          const top = this.peek().slice();
          this.stack.splice(this.stack.length - 2, 0, top);
          this.trackStackDepth();
          this.checkStackSize();
          continue;
        }

        // ---------------------------------------------------------------
        // Byte string operations (BSV re-enabled)
        // ---------------------------------------------------------------

        if (
          this.flags.enableOpCodes === false &&
          byte >= Opcode.OP_CAT &&
          byte <= Opcode.OP_SIZE
        ) {
          throw new ScriptError('BSV re-enabled opcodes are disabled by flags');
        }

        if (byte === Opcode.OP_CAT) {
          this.countOp();
          const b2 = this.pop();
          const a2 = this.pop();
          const result = new Uint8Array(a2.length + b2.length);
          result.set(a2, 0);
          result.set(b2, a2.length);
          this.push(result);
          continue;
        }

        if (byte === Opcode.OP_SPLIT) {
          this.countOp();
          const pos = Number(this.popNum());
          const data = this.pop();
          if (pos < 0 || pos > data.length) {
            throw new ScriptError(`OP_SPLIT: position ${pos} out of range [0, ${data.length}]`);
          }
          this.push(data.slice(0, pos));
          this.push(data.slice(pos));
          continue;
        }

        if (byte === Opcode.OP_NUM2BIN) {
          this.countOp();
          const size = Number(this.popNum());
          const num = this.pop();
          if (size < 0) {
            throw new ScriptError('OP_NUM2BIN: negative size');
          }
          // Pad or trim the number to the requested byte size.
          const result = new Uint8Array(size);
          if (num.length === 0) {
            // Zero: just return zero-filled array
            this.push(result);
            continue;
          }
          if (num.length > size) {
            throw new ScriptError('OP_NUM2BIN: number too large for requested size');
          }
          result.set(num, 0);
          // If padding was needed, extend the sign bit.
          if (num.length < size) {
            const lastSrcByte = num[num.length - 1]!;
            const isNegative = (lastSrcByte & 0x80) !== 0;
            if (isNegative) {
              // Clear sign bit on the original last byte position in result.
              result[num.length - 1] = lastSrcByte & 0x7f;
              // Set sign bit on the new last byte.
              result[size - 1] = 0x80;
            }
          }
          this.push(result);
          continue;
        }

        if (byte === Opcode.OP_BIN2NUM) {
          this.countOp();
          const data = this.pop();
          // Convert to minimal encoding.
          const n = decodeScriptNumber(data);
          this.pushNum(n);
          continue;
        }

        if (byte === Opcode.OP_SIZE) {
          this.countOp();
          // Does NOT pop the element; pushes its size.
          const top = this.peek();
          this.pushNum(BigInt(top.length));
          continue;
        }

        // ---------------------------------------------------------------
        // Bitwise logic
        // ---------------------------------------------------------------

        if (byte === Opcode.OP_INVERT) {
          this.countOp();
          const a2 = this.pop();
          const result = new Uint8Array(a2.length);
          for (let j = 0; j < a2.length; j++) {
            result[j] = ~a2[j]! & 0xff;
          }
          this.push(result);
          continue;
        }

        if (byte === Opcode.OP_AND) {
          this.countOp();
          const b2 = this.pop();
          const a2 = this.pop();
          if (a2.length !== b2.length) {
            throw new ScriptError('OP_AND: operands must be same length');
          }
          const result = new Uint8Array(a2.length);
          for (let j = 0; j < a2.length; j++) {
            result[j] = a2[j]! & b2[j]!;
          }
          this.push(result);
          continue;
        }

        if (byte === Opcode.OP_OR) {
          this.countOp();
          const b2 = this.pop();
          const a2 = this.pop();
          if (a2.length !== b2.length) {
            throw new ScriptError('OP_OR: operands must be same length');
          }
          const result = new Uint8Array(a2.length);
          for (let j = 0; j < a2.length; j++) {
            result[j] = a2[j]! | b2[j]!;
          }
          this.push(result);
          continue;
        }

        if (byte === Opcode.OP_XOR) {
          this.countOp();
          const b2 = this.pop();
          const a2 = this.pop();
          if (a2.length !== b2.length) {
            throw new ScriptError('OP_XOR: operands must be same length');
          }
          const result = new Uint8Array(a2.length);
          for (let j = 0; j < a2.length; j++) {
            result[j] = a2[j]! ^ b2[j]!;
          }
          this.push(result);
          continue;
        }

        if (byte === Opcode.OP_EQUAL) {
          this.countOp();
          const b2 = this.pop();
          const a2 = this.pop();
          this.pushBool(arraysEqual(a2, b2));
          continue;
        }

        if (byte === Opcode.OP_EQUALVERIFY) {
          this.countOp();
          const b2 = this.pop();
          const a2 = this.pop();
          if (!arraysEqual(a2, b2)) {
            throw new ScriptError('OP_EQUALVERIFY failed');
          }
          continue;
        }

        // ---------------------------------------------------------------
        // Arithmetic
        // ---------------------------------------------------------------

        if (byte === Opcode.OP_1ADD) {
          this.countOp();
          this.pushNum(this.popNum() + 1n);
          continue;
        }

        if (byte === Opcode.OP_1SUB) {
          this.countOp();
          this.pushNum(this.popNum() - 1n);
          continue;
        }

        if (byte === Opcode.OP_NEGATE) {
          this.countOp();
          this.pushNum(-this.popNum());
          continue;
        }

        if (byte === Opcode.OP_ABS) {
          this.countOp();
          const n = this.popNum();
          this.pushNum(n < 0n ? -n : n);
          continue;
        }

        if (byte === Opcode.OP_NOT) {
          this.countOp();
          const n = this.popNum();
          this.pushBool(n === 0n);
          continue;
        }

        if (byte === Opcode.OP_0NOTEQUAL) {
          this.countOp();
          const n = this.popNum();
          this.pushBool(n !== 0n);
          continue;
        }

        if (byte === Opcode.OP_ADD) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushNum(a2 + b2);
          continue;
        }

        if (byte === Opcode.OP_SUB) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushNum(a2 - b2);
          continue;
        }

        if (byte === Opcode.OP_MUL) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushNum(a2 * b2);
          continue;
        }

        if (byte === Opcode.OP_DIV) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          if (b2 === 0n) {
            throw new ScriptError('OP_DIV: division by zero');
          }
          // Bitcoin uses truncation towards zero (same as BigInt division).
          this.pushNum(a2 / b2);
          continue;
        }

        if (byte === Opcode.OP_MOD) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          if (b2 === 0n) {
            throw new ScriptError('OP_MOD: division by zero');
          }
          this.pushNum(a2 % b2);
          continue;
        }

        if (byte === Opcode.OP_LSHIFT) {
          this.countOp();
          const shift = this.popNum();
          const val = this.pop(); // raw byte array, not number
          if (shift < 0n) {
            throw new ScriptError('OP_LSHIFT: negative shift');
          }
          const n = Number(shift);
          if (val.length === 0 || n === 0) { this.push(val); continue; }
          // Treat byte array as big-endian unsigned integer
          let num = 0n;
          for (let j = 0; j < val.length; j++) {
            num = (num << 8n) | BigInt(val[j]!);
          }
          // Shift left, mask to original byte count
          const bitLen = BigInt(val.length * 8);
          num = (num << BigInt(n)) & ((1n << bitLen) - 1n);
          // Convert back to big-endian bytes (same length)
          const result = new Uint8Array(val.length);
          for (let j = val.length - 1; j >= 0; j--) {
            result[j] = Number(num & 0xFFn);
            num >>= 8n;
          }
          this.push(result);
          continue;
        }

        if (byte === Opcode.OP_RSHIFT) {
          this.countOp();
          const shift = this.popNum();
          const val = this.pop(); // raw byte array, not number
          if (shift < 0n) {
            throw new ScriptError('OP_RSHIFT: negative shift');
          }
          const n = Number(shift);
          if (val.length === 0 || n === 0) { this.push(val); continue; }
          // Treat byte array as big-endian unsigned integer
          let num = 0n;
          for (let j = 0; j < val.length; j++) {
            num = (num << 8n) | BigInt(val[j]!);
          }
          // Shift right (zero-fill from MSB side)
          num = num >> BigInt(n);
          // Convert back to big-endian bytes (same length)
          const result2 = new Uint8Array(val.length);
          for (let j = val.length - 1; j >= 0; j--) {
            result2[j] = Number(num & 0xFFn);
            num >>= 8n;
          }
          this.push(result2);
          continue;
        }

        if (byte === Opcode.OP_BOOLAND) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushBool(a2 !== 0n && b2 !== 0n);
          continue;
        }

        if (byte === Opcode.OP_BOOLOR) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushBool(a2 !== 0n || b2 !== 0n);
          continue;
        }

        if (byte === Opcode.OP_NUMEQUAL) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushBool(a2 === b2);
          continue;
        }

        if (byte === Opcode.OP_NUMEQUALVERIFY) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          if (a2 !== b2) {
            throw new ScriptError('OP_NUMEQUALVERIFY failed');
          }
          continue;
        }

        if (byte === Opcode.OP_NUMNOTEQUAL) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushBool(a2 !== b2);
          continue;
        }

        if (byte === Opcode.OP_LESSTHAN) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushBool(a2 < b2);
          continue;
        }

        if (byte === Opcode.OP_GREATERTHAN) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushBool(a2 > b2);
          continue;
        }

        if (byte === Opcode.OP_LESSTHANOREQUAL) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushBool(a2 <= b2);
          continue;
        }

        if (byte === Opcode.OP_GREATERTHANOREQUAL) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushBool(a2 >= b2);
          continue;
        }

        if (byte === Opcode.OP_MIN) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushNum(a2 < b2 ? a2 : b2);
          continue;
        }

        if (byte === Opcode.OP_MAX) {
          this.countOp();
          const b2 = this.popNum();
          const a2 = this.popNum();
          this.pushNum(a2 > b2 ? a2 : b2);
          continue;
        }

        if (byte === Opcode.OP_WITHIN) {
          this.countOp();
          const max = this.popNum();
          const min = this.popNum();
          const x = this.popNum();
          this.pushBool(x >= min && x < max);
          continue;
        }

        // ---------------------------------------------------------------
        // Crypto
        // ---------------------------------------------------------------

        if (byte === Opcode.OP_RIPEMD160) {
          this.countOp();
          const data = this.pop();
          const hash = createHash('ripemd160').update(data).digest();
          this.push(new Uint8Array(hash));
          continue;
        }

        if (byte === Opcode.OP_SHA1) {
          this.countOp();
          const data = this.pop();
          const hash = createHash('sha1').update(data).digest();
          this.push(new Uint8Array(hash));
          continue;
        }

        if (byte === Opcode.OP_SHA256) {
          this.countOp();
          const data = this.pop();
          const hash = createHash('sha256').update(data).digest();
          this.push(new Uint8Array(hash));
          continue;
        }

        if (byte === Opcode.OP_HASH160) {
          this.countOp();
          const data = this.pop();
          const sha = createHash('sha256').update(data).digest();
          const hash = createHash('ripemd160').update(sha).digest();
          this.push(new Uint8Array(hash));
          continue;
        }

        if (byte === Opcode.OP_HASH256) {
          this.countOp();
          const data = this.pop();
          const sha1 = createHash('sha256').update(data).digest();
          const sha2 = createHash('sha256').update(sha1).digest();
          this.push(new Uint8Array(sha2));
          continue;
        }

        if (byte === Opcode.OP_CHECKSIG) {
          this.countOp();
          const pubkey = this.pop();
          const sig = this.pop();
          const valid = this.checkSigCallback(sig, pubkey);
          this.pushBool(valid);
          continue;
        }

        if (byte === Opcode.OP_CHECKSIGVERIFY) {
          this.countOp();
          const pubkey = this.pop();
          const sig = this.pop();
          const valid = this.checkSigCallback(sig, pubkey);
          if (!valid) {
            throw new ScriptError('OP_CHECKSIGVERIFY failed');
          }
          continue;
        }

        if (byte === Opcode.OP_CHECKMULTISIG) {
          this.countOp();
          this.executeCheckMultiSig(false);
          continue;
        }

        if (byte === Opcode.OP_CHECKMULTISIGVERIFY) {
          this.countOp();
          this.executeCheckMultiSig(true);
          continue;
        }

        // ---------------------------------------------------------------
        // Unknown opcode
        // ---------------------------------------------------------------
        throw new ScriptError(
          `Unknown or disabled opcode: 0x${byte.toString(16).padStart(2, '0')}`,
        );
      }

      // Check for unbalanced if/else/endif
      if (this.ifStack.length !== 0) {
        throw new ScriptError('Unbalanced OP_IF/OP_ENDIF');
      }

      return this.buildResult();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return this.buildResult(msg);
    }
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private countOp(): void {
    this.opsExecuted++;
    if (this.opsExecuted > this.maxOps) {
      throw new ScriptError(`Operation limit exceeded (max ${this.maxOps})`);
    }
  }

  /**
   * Execute OP_CHECKMULTISIG or OP_CHECKMULTISIGVERIFY.
   *
   * Stack layout (top-to-bottom):
   *   <n> <pubkey_n> ... <pubkey_1> <m> <sig_m> ... <sig_1> <dummy>
   */
  private executeCheckMultiSig(verify: boolean): void {
    const nKeys = Number(this.popNum());
    if (nKeys < 0 || nKeys > 20) {
      throw new ScriptError('OP_CHECKMULTISIG: invalid number of keys');
    }

    const pubkeys: Uint8Array[] = [];
    for (let j = 0; j < nKeys; j++) {
      pubkeys.push(this.pop());
    }

    const nSigs = Number(this.popNum());
    if (nSigs < 0 || nSigs > nKeys) {
      throw new ScriptError('OP_CHECKMULTISIG: invalid number of signatures');
    }

    const sigs: Uint8Array[] = [];
    for (let j = 0; j < nSigs; j++) {
      sigs.push(this.pop());
    }

    // Pop the dummy element (historic Bitcoin bug).
    this.pop();

    // Verify signatures in order.
    let keyIdx = 0;
    let valid = true;
    for (const sig of sigs) {
      let found = false;
      while (keyIdx < nKeys) {
        if (this.checkSigCallback(sig, pubkeys[keyIdx]!)) {
          found = true;
          keyIdx++;
          break;
        }
        keyIdx++;
      }
      if (!found) {
        valid = false;
        break;
      }
    }

    if (verify) {
      if (!valid) {
        throw new ScriptError('OP_CHECKMULTISIGVERIFY failed');
      }
    } else {
      this.pushBool(valid);
    }
  }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
