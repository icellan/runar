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

  const unlocks: string[] = [];
  const preimages: string[] = [];

  for (let i = 0; i < inputs.length; i++) {
    const { unlockingScript, preimage } = await unlockForInput(
      skeleton, i, inputs[i]!, utxos[i]!, `assembleMultiContractCall: input ${i}`,
    );
    unlocks.push(unlockingScript);
    preimages.push(preimage);
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

// ---------------------------------------------------------------------------
// Per-input unlock builder (#198)
// ---------------------------------------------------------------------------

/** Options for {@link buildContractUnlock}. */
export interface BuildContractUnlockOptions {
  /**
   * Replay the built unlock through @bsv/sdk's Spend interpreter against the
   * given tx's EXACT outputs/inputs and throw when it does not validate.
   * Default false (the tx a wallet hands over may still change; callers that
   * hold the final tx should turn this on). Other inputs' unlocks are not
   * needed: each input is validated independently.
   */
  dryRun?: boolean;
}

const p2pkhScript = (pkhHex: string): string => '76a914' + pkhHex + '88ac';

/**
 * Copy the parts of `tx` a BIP-143 preimage commits to into a FRESH
 * transaction with empty unlocks. Never serializes (or mutates) the caller's
 * object: @bsv/sdk caches `toHex()`, and a wallet-built tx may carry inputs
 * with only a `sourceTransaction` / `unlockingScriptTemplate`.
 */
function snapshotSkeleton(tx: BsvTransaction, label: string): BsvTransaction {
  const sk = new BsvTransaction(tx.version, [], [], tx.lockTime);
  tx.inputs.forEach((inp, i) => {
    const sourceTXID = inp.sourceTXID ?? inp.sourceTransaction?.id('hex');
    if (!sourceTXID) {
      throw new Error(`${label}: tx input ${i} has neither sourceTXID nor sourceTransaction`);
    }
    sk.addInput({
      sourceTXID,
      sourceOutputIndex: inp.sourceOutputIndex,
      unlockingScript: new UnlockingScript(),
      sequence: inp.sequence ?? 0xffffffff,
    });
  });
  tx.outputs.forEach((out, i) => {
    if (out.satoshis === undefined || !out.lockingScript) {
      throw new Error(
        `${label}: tx output ${i} has no final satoshis/lockingScript (an unresolved wallet change output?)`,
      );
    }
    sk.addOutput({ satoshis: out.satoshis, lockingScript: out.lockingScript });
  });
  return sk;
}

/** Shared method/ABI resolution for the unlock builder and the sizing skeleton. */
function resolveUnlockMethod(inp: MultiContractCallInput, label: string) {
  const artifact = inp.contract.artifact;
  const publicMethods = artifact.abi.methods.filter((m) => m.isPublic);
  const methodIndex = publicMethods.findIndex((m) => m.name === inp.method);
  if (methodIndex < 0) {
    throw new Error(`${label}: public method '${inp.method}' not found on ${artifact.contractName}`);
  }
  const method = publicMethods[methodIndex]!;

  const witnessParams = method.params.filter((p) => isAutoInjectedWitnessParam(p.name));
  if (witnessParams.length > 0) {
    throw new Error(
      `${label}: method '${inp.method}' declares intent-intrinsic witness params ` +
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
      `${label}: method '${inp.method}' expects ${userParams.length} args, got ${inp.args.length}`,
    );
  }
  if (methodNeedsChange && !inp.changePKH) {
    throw new Error(
      `${label}: method '${inp.method}' requires \`changePKH\` (ABI declares _changePKH)`,
    );
  }
  // #213 (defence in depth): the covenant gates `_changePKH` at exactly 20
  // bytes; refuse anything else before building a transaction.
  if (methodNeedsChange) {
    assertFixedWidthValue(inp.changePKH, 'Ripemd160', `${label}: changePKH`);
  }
  return {
    artifact, publicMethods, methodIndex, method, userParams,
    methodNeedsChange, methodNeedsNewAmount, methodUsesCodePart,
  };
}

/**
 * The compiled covenant reconstructs `[state/raw outputs][data outputs]` and
 * then, iff `_changeAmount !== 0`, ONE trailing P2PKH(`_changePKH`,
 * `_changeAmount`). So for a non-zero declared change the LAST output of the
 * spending tx must be exactly that P2PKH; anything else can never satisfy the
 * covenant's hashOutputs and the funds would be stranded. Returns true when
 * the (zero-change) case is ambiguous and needs a definitive dry run: a
 * trailing P2PKH to `changePKH` is either a wallet change the covenant does
 * not commit, or a legitimate `addRawOutput(x, p2pkh(samePKH))`.
 */
function checkDeclaredChange(
  outputs: BsvTransaction['outputs'], changePKH: string, changeAmount: bigint, label: string,
): boolean {
  if (changeAmount < 0n) throw new Error(`${label}: changeAmount must be >= 0, got ${changeAmount}`);
  const last = outputs[outputs.length - 1];
  const lastIsChangeToPKH = !!last && last.lockingScript.toHex() === p2pkhScript(changePKH.toLowerCase());
  if (changeAmount !== 0n) {
    if (!last || !lastIsChangeToPKH || BigInt(last.satoshis ?? -1) !== changeAmount) {
      throw new Error(
        `${label}: declared change (${changeAmount} sats to P2PKH ${changePKH}) does not match the tx: ` +
        `the covenant requires the LAST output to be exactly that P2PKH change. ` +
        (last
          ? `The tx's last output is ${last.satoshis} sats to ${last.lockingScript.toHex()}. `
          : 'The tx has no outputs. ') +
        `A wallet-built tx must carry change at exactly _changeAmount/_changePKH (or declare changeAmount 0 ` +
        `and carry no change output); otherwise the spend cannot verify.`,
      );
    }
    return false;
  }
  return lastIsChangeToPKH;
}

async function unlockForInput(
  skeleton: BsvTransaction,
  inputIndex: number,
  inp: MultiContractCallInput,
  utxo: UTXO,
  label: string,
): Promise<{ unlockingScript: string; preimage: string; ambiguousZeroChange: boolean }> {
  const {
    publicMethods, methodIndex, userParams,
    methodNeedsChange, methodNeedsNewAmount, methodUsesCodePart,
  } = resolveUnlockMethod(inp, label);

  let ambiguousZeroChange = false;
  if (methodNeedsChange) {
    ambiguousZeroChange = checkDeclaredChange(
      skeleton.outputs, inp.changePKH!, inp.changeAmount ?? 0n, label,
    );
  }

  const skeletonHex = skeleton.toHex();

  // OP_PUSH_TX preimage against THIS artifact's codesep layout. BUG-100: the
  // signature is derived on-chain from the preimage, so only the preimage is
  // pushed (buildStatefulPrefix pushes no signature).
  const { preimageHex } = inp.contract.computeOpPushTxPreimageWithCodeSep(
    skeleton, inputIndex, utxo.script, utxo.satoshis, methodIndex,
  );

  // Resolve user args; sign null Sig params over the trimmed subscript.
  let argsHex = '';
  let preimageInArgs = false;
  for (let a = 0; a < userParams.length; a++) {
    let value = inp.args[a];
    if (userParams[a]!.type === 'Sig' && value === null) {
      if (!inp.signer) {
        throw new Error(`${label}: arg ${a} is a null Sig but no \`signer\` was provided`);
      }
      const trimmed = inp.contract.getSubscriptForSigning(utxo.script, methodIndex);
      value = await inp.signer.sign(skeletonHex, inputIndex, trimmed, utxo.satoshis);
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
        `${label}: arg ${a} (param '${userParams[a]!.name}': ${userParams[a]!.type}) is ${value}; only null Sig params are auto-signed — pass a concrete value for every other param`,
      );
    }
    // N-045 (defence in depth): a fixed-width arg must have its declared width.
    assertFixedWidthValue(
      value, userParams[a]!.type,
      `${label}: arg ${a} (param '${userParams[a]!.name}')`,
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

  const unlockingScript =
    inp.contract.buildStatefulPrefix('', methodUsesCodePart) +
    argsHex + changeHex + newAmountHex +
    (preimageInArgs ? '' : encodePushData(preimageHex)) +
    selectorHex;

  return { unlockingScript, preimage: preimageHex, ambiguousZeroChange };
}

/**
 * Build the unlocking script (and the BIP-143 preimage it embeds) for covenant
 * input `inputIndex` of a transaction that was built ELSEWHERE, e.g. by a
 * BRC-100 wallet that adds its own funding inputs and change. This is the
 * per-input step `assembleMultiContractCall` performs, and it is what that
 * function now calls.
 *
 * WALLET-FUNDING CAVEAT: the covenant verifies only if the tx's outputs are
 * EXACTLY what it hashes. Under the default ALL: its continuation(s), raw
 * outputs and data outputs in the contract's order from output 0, then (iff
 * the method declares `_changePKH`) change at exactly `_changeAmount` to
 * `_changePKH`. Under a SIGHASH_SINGLE method (the D25 default for a contract
 * whose continuation methods are all mutate-only; the ABI's `sigHashType`
 * base is 3 and the method takes no `_changePKH`): ONLY its continuation, at
 * the output index equal to `inputIndex`, so a wallet that puts its funding
 * input first lays out `[change, continuation]`; the change is uncommitted. A wallet's own change output must
 * therefore equal the declared change, or `changeAmount` must be 0 and no
 * change output may exist. This function REFUSES (throws) when a non-zero
 * declared change is not the tx's last output; when `changeAmount` is 0 but
 * the tx ends in a P2PKH to `changePKH` it validates the input through Spend
 * and refuses on failure. Pass `{ dryRun: true }` to validate every case
 * through Spend before returning. Fixed-width arguments and the 20-byte
 * `changePKH` are width-gated exactly as on the `call()` path.
 *
 * The passed `tx` is read, never mutated or serialized: a private skeleton is
 * built from its version, lockTime, input outpoints/sequences and outputs.
 * Inputs need `sourceTXID` or `sourceTransaction`; every output needs a final
 * `satoshis` (resolve wallet change first).
 *
 * @throws if the method/arity/UTXO/signer/changePKH/width checks fail, the
 *         input at `inputIndex` does not spend the UTXO, the declared change
 *         cannot match the tx, or an applicable dry run fails.
 */
export async function buildContractUnlock(
  tx: BsvTransaction,
  inputIndex: number,
  input: MultiContractCallInput,
  opts: BuildContractUnlockOptions = {},
): Promise<{ unlockingScript: string; preimage: string }> {
  const label = `buildContractUnlock: input ${inputIndex}`;
  const target = tx.inputs[inputIndex];
  if (!target) throw new Error(`${label}: no input at index ${inputIndex}`);
  const utxo = input.utxo ?? input.contract.getUtxo();
  if (!utxo) {
    throw new Error(`${label}: no UTXO — pass \`utxo\` or deploy/connect the contract first`);
  }
  const skeleton = snapshotSkeleton(tx, label);
  const sk = skeleton.inputs[inputIndex]!;
  if (sk.sourceTXID!.toLowerCase() !== utxo.txid.toLowerCase() || sk.sourceOutputIndex !== utxo.outputIndex) {
    throw new Error(
      `${label}: the tx input spends outpoint ${sk.sourceTXID}:${sk.sourceOutputIndex}, ` +
      `not the contract UTXO ${utxo.txid}:${utxo.outputIndex} — wrong inputIndex or UTXO`,
    );
  }

  const built = await unlockForInput(skeleton, inputIndex, input, utxo, label);

  if (opts.dryRun || built.ambiguousZeroChange) {
    const probe = snapshotSkeleton(tx, label);
    probe.inputs[inputIndex]!.unlockingScript = UnlockingScript.fromHex(built.unlockingScript);
    const r = dryRunMultiContractInput(probe.toHex(), inputIndex, utxo.script, utxo.satoshis);
    if (!r.valid) {
      throw new Error(
        `${label}: offline validation FAILED for input ${inputIndex} ` +
        `(${input.contract.artifact.contractName}.${input.method}): ${r.error ?? 'script invalid'}` +
        (built.ambiguousZeroChange
          ? ' — changeAmount is 0 but the tx ends in a P2PKH to changePKH that the covenant does not commit; ' +
            'declare that change amount or drop the output'
          : ''),
      );
    }
  }
  return { unlockingScript: built.unlockingScript, preimage: built.preimage };
}

/**
 * A placeholder unlocking script for covenant input `input.method`, for FEE
 * SIZING before the final tx exists (e.g. a BRC-100 `createAction`
 * `unlockingScriptLength`). Same layout as {@link buildContractUnlock}; null
 * `Sig` args become 73-byte zero pushes, the preimage a zero push of its exact
 * length for the UTXO script, and `_changeAmount`/`_newAmount` 8-byte numbers,
 * so `length` is an upper bound (never below the real unlock; a few bytes
 * above at most). Not a valid unlock: never broadcast it.
 */
export function buildContractUnlockSkeleton(
  input: MultiContractCallInput,
): { unlockingScript: string; length: number } {
  const label = 'buildContractUnlockSkeleton';
  const {
    publicMethods, methodIndex, userParams,
    methodNeedsChange, methodNeedsNewAmount, methodUsesCodePart,
  } = resolveUnlockMethod(input, label);
  const scriptHex = (input.utxo ?? input.contract.getUtxo())?.script ?? input.contract.getLockingScript();
  const subscriptLen = input.contract.getSubscriptForSigning(scriptHex, methodIndex).length / 2;
  const varintLen = subscriptLen < 0xfd ? 1 : subscriptLen <= 0xffff ? 3 : 5;
  const preimagePlaceholder = '00'.repeat(156 + varintLen + subscriptLen);

  let argsHex = '';
  let preimageInArgs = false;
  for (let a = 0; a < userParams.length; a++) {
    let value = input.args[a];
    if (userParams[a]!.type === 'Sig' && value === null) value = '00'.repeat(73);
    if (userParams[a]!.type === 'SigHashPreimage' && value === null) {
      value = preimagePlaceholder;
      preimageInArgs = true;
    }
    if (value === null || value === undefined) {
      throw new Error(`${label}: arg ${a} (param '${userParams[a]!.name}') is ${value}; pass a concrete value`);
    }
    argsHex += encodeArg(value);
  }
  const num8 = '08' + 'ff'.repeat(8);
  const changeHex = methodNeedsChange ? encodePushData(input.changePKH ?? '00'.repeat(20)) + num8 : '';
  const newAmountHex = methodNeedsNewAmount ? num8 : '';
  const selectorHex = publicMethods.length > 1 ? encodeScriptNumber(BigInt(methodIndex)) : '';
  const unlockingScript =
    input.contract.buildStatefulPrefix('', methodUsesCodePart) +
    argsHex + changeHex + newAmountHex +
    (preimageInArgs ? '' : encodePushData(preimagePlaceholder)) +
    selectorHex;
  return { unlockingScript, length: unlockingScript.length / 2 };
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
