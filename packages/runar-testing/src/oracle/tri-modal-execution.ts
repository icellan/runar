/**
 * Tri-modal source-vs-script differential-execution oracle (issue #124).
 *
 * Extends the bi-modal {@link runDifferentialExecution} (AST-walking `RunarInterpreter`
 * vs. `ScriptVM`) with a strict, full-consensus `Spend.validate()` leg:
 *
 *   1. interpreter — the AST-walking `RunarInterpreter` (source semantics, our code).
 *   2. ScriptVM   — the upstream `@bsv/sdk` `Spend` engine driven opcode by
 *                   opcode, with `success` = "no evaluation error and a truthy
 *                   top of stack" and the consensus wrappers switched off (see
 *                   `vm/script-vm.ts`).
 *   3. Spend      — the SAME upstream engine via `Spend.validate()`, which adds
 *                   the consensus **clean-stack** rule (exactly one truthy item
 *                   must remain), the **push-only unlocking** rule, and
 *                   **minimal-push** encoding.
 *
 * NOTE ON INDEPENDENCE: legs (2) and (3) are now the same third-party engine,
 * so they are no longer independent implementations — that changed when
 * `ScriptVM` stopped being a hand-rolled interpreter and became a wrapper around
 * `Spend`. What leg (3) still adds over leg (2) is the consensus script-SHAPE
 * rules, so a (2) accept / (3) reject disagreement means the compiled script
 * evaluates fine but is not a valid spend on the network. Genuine engine
 * independence lives in leg (1), the ANF interpreter — a separate
 * implementation of the SOURCE semantics.
 *
 * Scope matches the bi-modal oracle: STATELESS, non-crypto contracts (no
 * `checkSig`, no sighash, no state continuation). For those, `Spend` never needs
 * a real transaction context, so we drive it with a synthetic single-input
 * spend built directly from the compiled locking script + the generated witness.
 */
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import { newConsensusSpend } from '../consensus-spend.js';
import {
  runDifferentialExecution,
  type DiffExecOptions,
  type DiffExecResult,
} from './differential-execution.js';

export interface TriModalExecResult extends DiffExecResult {
  /** Did the compiled script verify on the upstream @bsv/sdk `Spend` engine? */
  spendAccepted: boolean;
  /** `Spend` rejection / throw message, when it did not accept. */
  spendError?: string;
  /** interpreter === ScriptVM === Spend (all three agree on accept/reject). */
  agrees: boolean;
}

/**
 * Run the compiled locking script + witness through the upstream `@bsv/sdk`
 * `Spend` interpreter. `Spend.validate()` returns `true` on success and THROWS
 * (a `ScriptEvaluationError`) on any failure — including the clean-stack and
 * push-only consensus rules — so a throw is mapped to a reject.
 */
function runSpendEngine(
  lockingHex: string,
  witnessHex: string,
): { accepted: boolean; error?: string } {
  try {
    const spend = newConsensusSpend({
      sourceTXID: '00'.repeat(32),
      sourceOutputIndex: 0,
      sourceSatoshis: 1,
      lockingScript: LockingScript.fromHex(lockingHex),
      transactionVersion: 1,
      otherInputs: [],
      outputs: [],
      inputIndex: 0,
      unlockingScript: UnlockingScript.fromHex(witnessHex),
      inputSequence: 0xffffffff,
      lockTime: 0,
    });
    const ok = spend.validate();
    return { accepted: ok === true };
  } catch (e) {
    return { accepted: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Compile a generated (contract, args) once, then run the SAME deployed bytes
 * and witness through all three engines and report whether they agree on
 * accept/reject. Reuses {@link runDifferentialExecution} for the compile +
 * witness build + interpreter + ScriptVM legs, then layers the `Spend` engine
 * on the exact `lockingHex` / `witnessHex` it produced (no re-compile).
 */
export function runTriModalExecution(opts: DiffExecOptions): TriModalExecResult {
  const bi = runDifferentialExecution(opts);
  const spend = runSpendEngine(bi.lockingHex, bi.witnessHex);
  const agrees =
    bi.interpreterAccepted === bi.vmAccepted &&
    bi.vmAccepted === spend.accepted;
  return {
    ...bi,
    spendAccepted: spend.accepted,
    spendError: spend.error,
    agrees,
  };
}
