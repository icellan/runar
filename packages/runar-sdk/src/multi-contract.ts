// ---------------------------------------------------------------------------
// runar-sdk/multi-contract.ts — cross-artifact transaction assembly
// ---------------------------------------------------------------------------
//
// `RunarContract.call()` builds a tx around ONE primary contract input (plus
// `additionalContractInputs` sharing the SAME artifact — the token-ft merge
// shape). Cross-contract composition — e.g. a settlement covenant at input 0
// consuming a token covenant at input 1, each compiled from a DIFFERENT
// artifact — previously required fully manual assembly against private
// helpers.
//
// `assembleMultiContractCall` is that manual assembly, made a first-class,
// typed surface. It builds and signs a transaction with N covenant inputs
// from N (potentially different) artifacts:
//
//   - the tx skeleton (all inputs with empty unlocks + the final outputs) is
//     built first; BIP-143 preimages never cover unlocking scripts, so every
//     per-input signature is computed against the skeleton in a single pass —
//     no fixpoint iteration;
//   - each input's OP_PUSH_TX preimage comes from ITS artifact's
//     code-separator layout (`computeOpPushTxWithCodeSep`). BUG-100: the
//     OP_PUSH_TX signature is derived ON-CHAIN from the preimage, so no
//     signature is pushed in the unlock — only the preimage;
//   - each input's user `Sig` params are signed over ITS codesep-trimmed
//     subscript (`getSubscriptForSigning`);
//   - each unlock replicates the compiled stateful layout exactly:
//     `[_codePart?] args... [_changePKH _changeAmount]
//     [_newAmount] txPreimage [selector]`;
//   - the signed tx is constructed FRESH from parts (inputs are never mutated
//     after `toHex()`), sidestepping the @bsv/sdk transaction hex cache.
//
// The caller owns output construction (continuation scripts, change, fees):
// with multiple covenants in one tx there is no single "the" continuation the
// SDK could infer — every input's covenant must independently agree with the
// final output set via its own hashOutputs binding.

import {
  Transaction as BsvTransaction,
  LockingScript,
  UnlockingScript,
  Spend,
} from '@bsv/sdk';
import type { RunarContract } from './contract.js';
import { encodeArg, encodePushData, encodeScriptNumber } from './contract.js';
import { assertFixedWidthValue } from './state.js';
import type { Signer } from './signers/index.js';
import type { UTXO } from './types.js';
import { isAutoInjectedWitnessParam, isSdkSuppliedParam } from './sdk-params.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** One covenant input of a multi-contract transaction. */
export interface MultiContractCallInput {
  /** The contract instance (its artifact + constructor args drive the unlock layout). */
  contract: RunarContract;
  /** Public method to invoke on this input. */
  method: string;
  /**
   * User-facing args in ABI order, EXCLUDING auto-injected params
   * (`txPreimage`, `_changePKH`, `_changeAmount`, `_newAmount`).
   * A `null` in a `Sig` position is signed automatically with `signer`.
   */
  args: unknown[];
  /** The UTXO this input spends. Defaults to `contract.getUtxo()`. */
  utxo?: UTXO;
  /** Signs `null` `Sig` args over the codesep-trimmed subscript. */
  signer?: Signer;
  /**
   * hash160 (hex) for the method's `_changePKH` param, when the ABI declares
   * one. Compiled stateful methods with `_changePKH` reconstruct
   * `<continuation><P2PKH change>` in hashOutputs unconditionally — the
   * spending tx must actually carry that change output.
   */
  changePKH?: string;
  /** Value for `_changeAmount` (satoshis of the change output). Default 0n. */
  changeAmount?: bigint;
  /** Value for `_newAmount` when the ABI declares it. Defaults to the UTXO's satoshis. */
  newAmount?: bigint;
}

/** One output of the multi-contract transaction (fully caller-specified). */
export interface MultiContractCallOutput {
  satoshis: number;
  /** Locking script hex (continuation script, P2PKH change, data output, ...). */
  script: string;
}

export interface AssembleMultiContractCallOptions {
  /** nLockTime of the assembled tx. Default 0. */
  lockTime?: number;
  /** nSequence for every input. Default 0xffffffff. */
  sequence?: number;
  /**
   * Validate every covenant input offline through @bsv/sdk's Spend
   * interpreter after assembly, throwing on the first failure. Strongly
   * recommended before broadcasting. Default true.
   */
  dryRun?: boolean;
}

export interface AssembledMultiContractCall {
  /** The fully-signed transaction. */
  tx: BsvTransaction;
  /** Raw tx hex (safe to broadcast if `dryRun` passed). */
  txHex: string;
  /** Per-input unlocking script hex, in input order. */
  unlocks: string[];
  /** Per-input BIP-143 preimage hex, in input order. */
  preimages: string[];
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/**
 * Build and sign a transaction whose inputs are N covenant UTXOs from N
 * (potentially different) artifacts, with a caller-specified output set.
 *
 * Input order in the tx is the order of `inputs`. Positional conventions
 * asserted by the contracts themselves (e.g. "I am input 0, my companion is
 * input 1") are the caller's responsibility to honor here.
 *
 * @throws if a method is unknown/non-public, an arg count mismatches, a UTXO
 *         or required signer/changePKH is missing, a method declares
 *         intent-intrinsic witness params (unsupported in v1), or — with
 *         `dryRun` (default) — an assembled input fails offline validation.
 */
export async function assembleMultiContractCall(
  inputs: MultiContractCallInput[],
  outputs: MultiContractCallOutput[],
  opts: AssembleMultiContractCallOptions = {},
): Promise<AssembledMultiContractCall> {
  if (inputs.length === 0) throw new Error('assembleMultiContractCall: at least one input required');
  if (outputs.length === 0) throw new Error('assembleMultiContractCall: at least one output required');
  const sequence = opts.sequence ?? 0xffffffff;
  const lockTime = opts.lockTime ?? 0;

  // Resolve UTXOs up front so every failure happens before any signing work.
  const utxos: UTXO[] = inputs.map((inp, i) => {
    const utxo = inp.utxo ?? inp.contract.getUtxo();
    if (!utxo) {
      throw new Error(
        `assembleMultiContractCall: input ${i} has no UTXO — pass \`utxo\` or deploy/connect the contract first`,
      );
    }
    return utxo;
  });

  // Fresh-build the tx for a given unlock set. Never mutate a Transaction
  // after toHex(): @bsv/sdk caches serialized hex, and a mutated-then-reused
  // instance serializes stale bytes.
  const build = (unlockHexes: string[]): BsvTransaction => {
    const tx = new BsvTransaction();
    tx.lockTime = lockTime;
    for (let i = 0; i < inputs.length; i++) {
      tx.addInput({
        sourceTXID: utxos[i]!.txid,
        sourceOutputIndex: utxos[i]!.outputIndex,
        unlockingScript: UnlockingScript.fromHex(unlockHexes[i] ?? ''),
        sequence,
      });
    }
    for (const out of outputs) {
      tx.addOutput({
        satoshis: out.satoshis,
        lockingScript: LockingScript.fromHex(out.script),
      });
    }
    return tx;
  };

  const skeleton = build(inputs.map(() => ''));
  const skeletonHex = skeleton.toHex();

  const unlocks: string[] = [];
  const preimages: string[] = [];

  for (let i = 0; i < inputs.length; i++) {
    const inp = inputs[i]!;
    const utxo = utxos[i]!;
    const artifact = inp.contract.artifact;
    const publicMethods = artifact.abi.methods.filter((m) => m.isPublic);
    const methodIndex = publicMethods.findIndex((m) => m.name === inp.method);
    if (methodIndex < 0) {
      throw new Error(
        `assembleMultiContractCall: input ${i}: public method '${inp.method}' not found on ${artifact.contractName}`,
      );
    }
    const method = publicMethods[methodIndex]!;

    const witnessParams = method.params.filter((p) => isAutoInjectedWitnessParam(p.name));
    if (witnessParams.length > 0) {
      throw new Error(
        `assembleMultiContractCall: input ${i}: method '${inp.method}' declares intent-intrinsic witness params ` +
        `(${witnessParams.map((p) => p.name).join(', ')}) — not supported by multi-contract assembly yet`,
      );
    }

    const methodNeedsChange = method.params.some((p) => p.name === '_changePKH');
    const methodNeedsNewAmount = method.params.some((p) => p.name === '_newAmount');
    const methodUsesCodePart = method.usesCodePart ?? methodNeedsChange;
    // Shared SDK-supplied-param predicate (N-149), the SAME one
    // RunarContract.prepareCall uses (N-411): non-empty stateFields. A
    // StatefulSmartContract with ZERO mutable fields has empty stateFields, so
    // its txPreimage is a user arg (pass null), as on the single-contract path.
    const isStateful = (artifact.stateFields?.length ?? 0) > 0;
    const userParams = method.params.filter((p) => !isSdkSuppliedParam(p, isStateful));
    if (userParams.length !== inp.args.length) {
      throw new Error(
        `assembleMultiContractCall: input ${i}: method '${inp.method}' expects ${userParams.length} args, got ${inp.args.length}`,
      );
    }
    if (methodNeedsChange && !inp.changePKH) {
      throw new Error(
        `assembleMultiContractCall: input ${i}: method '${inp.method}' requires \`changePKH\` (ABI declares _changePKH)`,
      );
    }

    // OP_PUSH_TX preimage against THIS artifact's codesep layout. BUG-100: the
    // signature is derived on-chain from the preimage, so only the preimage is
    // pushed (buildStatefulPrefix pushes no signature).
    const { preimageHex } = inp.contract.computeOpPushTxWithCodeSep(
      skeleton, i, utxo.script, utxo.satoshis, methodIndex,
    );

    // Resolve user args; sign null Sig params over the trimmed subscript.
    let argsHex = '';
    let preimageInArgs = false;
    for (let a = 0; a < userParams.length; a++) {
      let value = inp.args[a];
      if (userParams[a]!.type === 'Sig' && value === null) {
        if (!inp.signer) {
          throw new Error(
            `assembleMultiContractCall: input ${i}: arg ${a} is a null Sig but no \`signer\` was provided`,
          );
        }
        const trimmed = inp.contract.getSubscriptForSigning(utxo.script, methodIndex);
        value = await inp.signer.sign(skeletonHex, i, trimmed, utxo.satoshis);
      }
      // N-411: a zero-mutable StatefulSmartContract's txPreimage is a user
      // arg (null); it resolves to the preimage computed above.
      if (userParams[a]!.type === 'SigHashPreimage' && value === null) {
        value = preimageHex;
        preimageInArgs = true;
      }
      // This low-level surface only auto-resolves null `Sig` and
      // SigHashPreimage params. A null of
      // any other type would otherwise be encoded as the ASCII bytes of "null";
      // reject it with an actionable message instead (pass a concrete value).
      if (value === null || value === undefined) {
        throw new Error(
          `assembleMultiContractCall: input ${i}: arg ${a} (param '${userParams[a]!.name}': ${userParams[a]!.type}) is ${value}; only null Sig params are auto-signed — pass a concrete value for every other param`,
        );
      }
      // N-045 (defence in depth): a fixed-width arg must have its declared width.
      assertFixedWidthValue(
        value, userParams[a]!.type,
        `assembleMultiContractCall: input ${i}: arg ${a} (param '${userParams[a]!.name}')`,
      );
      argsHex += encodeArg(value);
    }

    let changeHex = '';
    if (methodNeedsChange) {
      changeHex = encodePushData(inp.changePKH!) + encodeScriptNumber(inp.changeAmount ?? 0n);
    }
    let newAmountHex = '';
    if (methodNeedsNewAmount) {
      newAmountHex = encodeScriptNumber(inp.newAmount ?? BigInt(utxo.satoshis));
    }
    const selectorHex = publicMethods.length > 1 ? encodeScriptNumber(BigInt(methodIndex)) : '';

    const unlock =
      inp.contract.buildStatefulPrefix('', methodUsesCodePart) +
      argsHex + changeHex + newAmountHex +
      (preimageInArgs ? '' : encodePushData(preimageHex)) +
      selectorHex;

    unlocks.push(unlock);
    preimages.push(preimageHex);
  }

  const tx = build(unlocks);
  const txHex = tx.toHex();

  if (opts.dryRun !== false) {
    for (let i = 0; i < inputs.length; i++) {
      const r = dryRunMultiContractInput(txHex, i, utxos[i]!.script, utxos[i]!.satoshis);
      if (!r.valid) {
        throw new Error(
          `assembleMultiContractCall: offline validation FAILED for input ${i} ` +
          `(${inputs[i]!.contract.artifact.contractName}.${inputs[i]!.method}): ${r.error ?? 'script invalid'}`,
        );
      }
    }
  }

  return { tx, txHex, unlocks, preimages };
}

/**
 * Offline validation of one input of a fully-assembled tx through @bsv/sdk's
 * production Spend interpreter (real OP_CHECKSIG, real BIP-143). Exported so
 * callers can re-validate independently before broadcast.
 */
export function dryRunMultiContractInput(
  txHex: string,
  inputIndex: number,
  utxoScriptHex: string,
  utxoSatoshis: number,
): { valid: boolean; error?: string } {
  const tx = BsvTransaction.fromHex(txHex);
  const input = tx.inputs[inputIndex];
  if (!input) return { valid: false, error: `no input at index ${inputIndex}` };
  const otherInputs = tx.inputs.filter((_, i) => i !== inputIndex);
  try {
    const spend = new Spend({
      sourceTXID: input.sourceTXID!,
      sourceOutputIndex: input.sourceOutputIndex,
      sourceSatoshis: utxoSatoshis,
      lockingScript: LockingScript.fromHex(utxoScriptHex),
      transactionVersion: tx.version,
      otherInputs,
      outputs: tx.outputs,
      inputIndex,
      unlockingScript: input.unlockingScript!,
      inputSequence: input.sequence ?? 0xffffffff,
      lockTime: tx.lockTime,
    });
    return { valid: !!spend.validate() };
  } catch (e) {
    return { valid: false, error: e instanceof Error ? e.message : String(e) };
  }
}
