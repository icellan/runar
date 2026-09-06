/**
 * NEW-005: @bsv/sdk's `Spend` destroys the scripts it is given.
 *
 * `Spend` pushes a script chunk's `data` array onto its stack BY REFERENCE, and
 * at least one opcode mutates its operand in place — `OP_NUM2BIN` does
 * `rawnum[rawnum.length - 1] &= 0x7f` (see `Spend.js`) to strip the sign bit
 * before zero-padding. A stateful continuation serialises every mutable state
 * field with OP_NUM2BIN, so evaluating a call that writes a NEGATIVE
 * unlocking-script push into state permanently clears the sign bit of that push
 * inside the caller's own `Script` object: a `-34` push becomes `+34`.
 *
 * The corruption is invisible to serialisation. `Script.fromBinary` seeds
 * `rawBytesCache`/`hexCache` from the original bytes, and mutating
 * `chunks[i].data` does not invalidate them, so `toHex()` keeps returning the
 * true bytes and nothing wrong is ever broadcast. The damage is confined to the
 * NEXT in-memory evaluation of the same object, which sees the wrong value and
 * rejects a transaction the network accepts — a FALSE REJECTION.
 *
 * Every `new Spend(...)` must therefore be handed scripts it is free to
 * destroy. `fromHex` re-parses into fresh chunks with fresh `data` arrays.
 *
 * Only the two scripts `Spend` EXECUTES need detaching. The `outputs` array is
 * read solely by `TransactionSignature.formatBytes`, which serialises each
 * output's locking script and never pushes it, so passing `tx.outputs` by
 * reference is harmless (and cheaper than deep-copying every output script).
 */
import { LockingScript, UnlockingScript, type Script } from '@bsv/sdk';

/** A private copy of `script` that `Spend` may corrupt without consequence. */
export function detachLockingScript(script: Script): LockingScript {
  return LockingScript.fromHex(script.toHex());
}

/** A private copy of `script` that `Spend` may corrupt without consequence. */
export function detachUnlockingScript(script: Script): UnlockingScript {
  return UnlockingScript.fromHex(script.toHex());
}
