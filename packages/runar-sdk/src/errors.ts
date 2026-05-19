// ---------------------------------------------------------------------------
// runar-sdk/errors.ts — Typed SDK errors
// ---------------------------------------------------------------------------

/**
 * Thrown when a deploy / call entry point or provider UTXO lookup
 * encounters a script that exceeds {@link InputLimits.MAX_SCRIPT_BYTES}.
 *
 * Guards fire BEFORE any heavy operation (signing, broadcasting) so that
 * pathological scripts cannot drive the SDK into expensive crypto work.
 */
export class ScriptSizeExceededError extends Error {
  readonly limit: number;
  readonly actual: number;
  readonly context: string;

  constructor(info: { limit: number; actual: number; context: string }) {
    super(
      `script exceeds MAX_SCRIPT_BYTES (limit=${info.limit}, actual=${info.actual}, context=${info.context})`,
    );
    this.name = 'ScriptSizeExceededError';
    this.limit = info.limit;
    this.actual = info.actual;
    this.context = info.context;
  }
}

/**
 * Assert that a script (hex string or byte length) is within the SDK's
 * MAX_SCRIPT_BYTES bound. Throws {@link ScriptSizeExceededError} otherwise.
 *
 * @param scriptHex hex-encoded script (2 hex chars per byte)
 * @param context human-readable origin string for the error message
 */
export function assertScriptHexUnderLimit(
  scriptHex: string,
  limit: number,
  context: string,
): void {
  // hex string is 2x the byte length; tolerate odd-length defensively
  const actualBytes = Math.ceil(scriptHex.length / 2);
  if (actualBytes > limit) {
    throw new ScriptSizeExceededError({ limit, actual: actualBytes, context });
  }
}

/**
 * Thrown when a method call requires a caller-supplied intent-intrinsic
 * witness value (auto-injected `_prevOutScript_<i>` or `_serialisedOutputs`)
 * that has not been set on the RunarContract.
 *
 * Auto-injected witness params come from the compiler when a contract method
 * uses `extractPrevOutputScript(i)` or `requireOutputP2PKH(...)`. The caller
 * must supply concrete bytes for each before invoking `call()` /
 * `prepareCall()` via {@link RunarContract.setPrevOutScript} and
 * {@link RunarContract.setSerialisedOutputs}.
 */
export class WitnessValueMissingError extends Error {
  readonly paramName: string;
  readonly methodName: string;
  readonly contractName: string;

  constructor(info: { paramName: string; methodName: string; contractName: string }) {
    super(
      `witness value missing for auto-injected param '${info.paramName}' on ${info.contractName}.${info.methodName} — call setPrevOutScript(i, bytes) or setSerialisedOutputs(bytes) before invoking the method`,
    );
    this.name = 'WitnessValueMissingError';
    this.paramName = info.paramName;
    this.methodName = info.methodName;
    this.contractName = info.contractName;
  }
}
