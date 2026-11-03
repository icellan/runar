// ---------------------------------------------------------------------------
// runar-sdk/sdk-params.ts — which ABI params the SDK supplies itself
// ---------------------------------------------------------------------------
//
// Single source of truth shared by RunarContract.prepareCall (its user-arg
// arity filter), the typed-wrapper codegen (codegen/common.ts) and
// multi-contract assembly. A param the SDK supplies is never part of the
// caller's args array.
// ---------------------------------------------------------------------------

/**
 * Intent-intrinsic witness params the compiler auto-injects
 * (`extractPrevOutputScript` → `_prevOutScript_<i>`, `requireOutputP2PKH` →
 * `_serialisedOutputs`). Their values come from `setPrevOutScript` /
 * `setSerialisedOutputs`, for stateful AND stateless methods.
 */
export function isAutoInjectedWitnessParam(name: string): boolean {
  return name.startsWith('_prevOutScript_') || name === '_serialisedOutputs';
}

/**
 * True when the SDK supplies this param internally, so it is excluded from
 * the user-facing args array: the intent witnesses always, plus the stateful
 * continuation params (SigHashPreimage, `_changePKH`, `_changeAmount`,
 * `_newAmount`) on stateful contracts.
 */
export function isSdkSuppliedParam(
  p: { name: string; type: string },
  isStateful: boolean,
): boolean {
  if (isAutoInjectedWitnessParam(p.name)) return true;
  return isStateful && (
    p.type === 'SigHashPreimage' ||
    p.name === '_changePKH' ||
    p.name === '_changeAmount' ||
    p.name === '_newAmount'
  );
}
