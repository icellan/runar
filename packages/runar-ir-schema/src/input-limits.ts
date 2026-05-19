/**
 * Shared DoS-bound input limits + typed error class used by all public
 * canonical-JSON / IR-loading entry points across the runar-ir-schema
 * package and its downstream consumers.
 *
 * Justifications:
 * - MAX_SCRIPT_BYTES = 4 MiB — the largest legitimate script measured by
 *   the script-size benchmark is `p384-wallet` at ~1.87 MB; 4 MiB gives
 *   ~2× headroom without enabling pathological 50 MB scripts. An earlier
 *   1 MiB cap incorrectly rejected p384-wallet — calibration bug caught
 *   by the script-size baseline (Major-2).
 * - MAX_IR_BYTES = 16 MiB — empirically the largest compiled-IR JSON
 *   observed during conformance is ~2 MiB (Mode 3 STARK contracts);
 *   16 MiB is 8× headroom.
 * - MAX_NESTING = 512 — JS engine stack typically tolerates ~10k frames;
 *   512 is well below crash threshold but accommodates legitimate deep
 *   covenant ANF.
 * - MAX_STRING_BYTES = 4 MiB — accommodates the largest checked-in hex
 *   pushdata (witness-assisted Groth16 VK) with ~3× headroom.
 */
export const InputLimits = {
  MAX_IR_BYTES: 16 * 1024 * 1024,       // 16 MiB — uncompressed ANF IR JSON
  MAX_SCRIPT_BYTES: 4 * 1024 * 1024,    // 4 MiB — single compiled Bitcoin Script
                                         // (p384-wallet hits ~1.87 MB; 2× headroom)
  MAX_NESTING: 512,                      // recursion depth for JSON / ANF traversal
  MAX_STRING_BYTES: 4 * 1024 * 1024,    // 4 MiB — single string field inside JSON
} as const;

export type InputLimitsKey = keyof typeof InputLimits;

/**
 * Thrown when a public canonical-JSON / IR-loading entry point detects
 * input that exceeds a documented InputLimits bound. Distinct typed
 * exception so callers can distinguish DoS-bound rejection from generic
 * RangeError / SyntaxError.
 */
export class CanonicalJsonError extends Error {
  readonly code: 'depth' | 'bytes' | 'string-bytes' | 'circular' | 'invalid';
  readonly limit?: number;
  readonly actual?: number;

  constructor(
    code: 'depth' | 'bytes' | 'string-bytes' | 'circular' | 'invalid',
    message: string,
    info?: { limit?: number; actual?: number },
  ) {
    super(message);
    this.name = 'CanonicalJsonError';
    this.code = code;
    this.limit = info?.limit;
    this.actual = info?.actual;
  }
}
