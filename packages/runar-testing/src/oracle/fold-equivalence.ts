/**
 * Fold-OFF ≡ fold-ON translation-validation oracle (TS-GAP-002).
 *
 * Cross-tier byte parity only proves the seven compilers AGREE with each
 * other; it cannot catch a miscompile all seven share. Constant folding is one
 * place such a shared bug could hide: fold-OFF is the golden-stamped path,
 * fold-ON is what every user actually deploys. This oracle compiles a contract
 * BOTH ways and executes each compiled script on the same witnesses, asserting
 * the two deployments accept/reject identically — and that each also agrees
 * with the ANF interpreter (a fold-independent source-semantics oracle). A
 * divergence on any witness is a real constant-fold bug.
 *
 * Implemented directly on top of `runDifferentialExecution`, reusing its
 * named-argument mapping, multi-method selector handling, constructor-arg
 * normalisation, interpreter execution and `ScriptVM` execution. Folding is
 * just its `disableConstantFolding` toggle, flipped per run.
 */
import type { WitnessSignMarker } from './differential-execution.js';
import { runDifferentialExecution, type WitnessArg } from './differential-execution.js';

export type { WitnessArg };

export interface FoldEqOptions {
  source: string;
  fileName: string; // selects the frontend parser
  method: string; // public method to spend through
  constructorArgs?: Record<string, unknown>;
  // Each inner array is one spend attempt (method args). A `WitnessSignMarker`
  // is resolved INSIDE `runDifferentialExecution`, once per fold mode — which is
  // what makes signed contracts work here at all: the sighash subscript is the
  // locking script, and folding changes those bytes, so fold-OFF and fold-ON
  // need signatures over their OWN scripts. Resolving per mode gives that for
  // free; a single pre-resolved signature would fail on whichever mode it was
  // not built for and read as a fold divergence.
  witnesses: (WitnessArg | WitnessSignMarker)[][];
}

export interface FoldEqDivergence {
  witness: string; // the VM unlocking-script hex (incl. any method selector)
  foldOff: boolean; // did the fold-OFF script accept?
  foldOn: boolean; // did the fold-ON script accept?
  interpreter: boolean; // source-semantics accept (fold-independent)
  reason: string;
}

export interface FoldEqResult {
  equivalent: boolean; // no witness diverged across fold modes / interpreter
  bytesDiffer: boolean; // did folding actually change the deployed bytes?
  foldOffHex: string;
  foldOnHex: string;
  divergences: FoldEqDivergence[];
}

export function runFoldEquivalence(opts: FoldEqOptions): FoldEqResult {
  const divergences: FoldEqDivergence[] = [];
  let foldOffHex = '';
  let foldOnHex = '';

  for (const args of opts.witnesses) {
    const common = {
      source: opts.source,
      fileName: opts.fileName,
      method: opts.method,
      args,
      constructorArgs: opts.constructorArgs,
    };
    // Compile + execute BOTH ways on the identical witness. Each call runs the
    // fold-independent ANF interpreter and the compiled script on ScriptVM.
    const off = runDifferentialExecution({ ...common, disableConstantFolding: true });
    const on = runDifferentialExecution({ ...common, disableConstantFolding: false });

    // The deployed bytes are constructor-arg-dependent but witness-independent,
    // so any run yields the same locking hex — capture it for `bytesDiffer`.
    foldOffHex = off.lockingHex;
    foldOnHex = on.lockingHex;

    // Translation-validation invariant: fold-OFF and fold-ON must accept/reject
    // identically, and each must match the fold-independent source semantics.
    const foldParity = off.vmAccepted === on.vmAccepted;
    const offAgrees = off.vmAccepted === off.interpreterAccepted;
    const onAgrees = on.vmAccepted === on.interpreterAccepted;

    if (!foldParity || !offAgrees || !onAgrees) {
      const reasons: string[] = [];
      if (!foldParity) {
        reasons.push(`fold-OFF vm=${off.vmAccepted} != fold-ON vm=${on.vmAccepted}`);
      }
      if (!offAgrees) {
        reasons.push(
          `fold-OFF vm=${off.vmAccepted} != interpreter=${off.interpreterAccepted} (${off.vmError ?? off.interpreterError ?? ''})`,
        );
      }
      if (!onAgrees) {
        reasons.push(
          `fold-ON vm=${on.vmAccepted} != interpreter=${on.interpreterAccepted} (${on.vmError ?? on.interpreterError ?? ''})`,
        );
      }
      divergences.push({
        witness: on.witnessHex,
        foldOff: off.vmAccepted,
        foldOn: on.vmAccepted,
        interpreter: on.interpreterAccepted,
        reason: reasons.join('; '),
      });
    }
  }

  return {
    equivalent: divergences.length === 0,
    bytesDiffer: foldOffHex !== foldOnHex,
    foldOffHex,
    foldOnHex,
    divergences,
  };
}
