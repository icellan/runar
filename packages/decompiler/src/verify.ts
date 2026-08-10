/**
 * Forward-compile-and-compare oracle.
 *
 * Calls `runar-compiler`'s top-level `compile()` on a candidate source string
 * and byte-compares the result against a target script.
 */

import { compile, compileFromANF } from 'runar-compiler';
import type { ANFProgram } from 'runar-compiler';
import { hexToBytes } from 'runar-testing';
import type { VerifyResult } from './types.js';

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function firstDiff(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return i;
  return a.length === b.length ? -1 : n;
}

export interface VerifyOptions {
  /** Filename passed to the parser. Defaults to `_Recovered.runar.ts`. */
  fileName?: string;
  /** If true, disable constant folding when re-compiling. Default: false. */
  disableConstantFolding?: boolean;
  /**
   * Strict round-trip: disable peephole + EC optimizer + constant fold.
   * Used when comparing against bytes produced without those passes
   * (e.g. pre-peephole conformance fixtures, hand-rolled scripts).
   */
  strict?: boolean;
}

export function verifyDecompilation(
  target: Uint8Array,
  candidate: string,
  opts: VerifyOptions = {},
): VerifyResult {
  const fileName = opts.fileName ?? '_Recovered.runar.ts';
  const result = compile(candidate, {
    fileName,
    disableConstantFolding: opts.disableConstantFolding ?? opts.strict ?? false,
    disablePeephole: opts.strict ?? false,
    disableEcOptimizer: opts.strict ?? false,
  });

  if (!result.success || !result.scriptHex) {
    const errors = result.diagnostics.filter(d => d.severity === 'error');
    const message = errors.map(e => e.message).join('; ') || 'compilation failed';
    return { ok: false, kind: 'compile-error', message };
  }

  return compareBytes(target, hexToBytes(result.scriptHex));
}

/**
 * Verify a recovered ANF program by re-compiling it via `compileFromANF`
 * and byte-comparing against the target. Skips the TS parse step, so this
 * path works even before any `asm({...})` surface syntax lands.
 */
export function verifyDecompilationAnf(
  target: Uint8Array,
  candidate: ANFProgram,
  opts: VerifyOptions = {},
): VerifyResult {
  try {
    const result = compileFromANF(candidate, {
      disableConstantFolding: opts.disableConstantFolding ?? opts.strict ?? false,
      disablePeephole: opts.strict ?? false,
      disableEcOptimizer: opts.strict ?? false,
    });
    return compareBytes(target, hexToBytes(result.scriptHex));
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : String(e);
    return { ok: false, kind: 'compile-error', message };
  }
}

/** Minimal Bitcoin push encoding for a hex value (covers our recovered args). */
function pushData(hex: string): string {
  const len = hex.length / 2;
  if (len === 0) return '00';
  if (len <= 75) return len.toString(16).padStart(2, '0') + hex;
  if (len <= 255) return '4c' + len.toString(16).padStart(2, '0') + hex;
  throw new Error(`pushData: value too large to splice (${len} bytes)`);
}

/**
 * Splice constructor args into a compiled template at its `constructorSlots`,
 * mirroring Rúnar's deploy-time splice: each slot's 1-byte `OP_0` placeholder
 * is replaced by the minimal push of the arg. Slots are applied left-to-right
 * with a running offset shift.
 */
export function spliceConstructorArgs(
  templateHex: string,
  slots: Array<{ paramIndex: number; byteOffset: number }>,
  args: Record<number, string>,
): string {
  let out = templateHex;
  let shift = 0;
  for (const slot of [...slots].sort((a, b) => a.byteOffset - b.byteOffset)) {
    const val = args[slot.paramIndex];
    if (val === undefined) continue;
    const off = (slot.byteOffset + shift) * 2;
    const push = pushData(val);
    out = out.slice(0, off) + push + out.slice(off + 2); // replace the 1-byte placeholder
    shift += push.length / 2 - 1;
  }
  return out;
}

/**
 * Verify a compiling reconstruction that parameterizes constructor args: the
 * emitted source compiles to a TEMPLATE (placeholders at constructorSlots);
 * splicing the recovered `args` must reproduce the target byte-for-byte.
 */
export function verifyCompiling(
  target: Uint8Array,
  source: string,
  args: Record<number, string>,
  opts: VerifyOptions = {},
): VerifyResult {
  const result = compile(source, {
    fileName: opts.fileName ?? '_Recovered.runar.ts',
    disableConstantFolding: opts.disableConstantFolding ?? opts.strict ?? false,
    disablePeephole: opts.strict ?? false,
    disableEcOptimizer: opts.strict ?? false,
  });
  if (!result.success || !result.scriptHex) {
    const errors = result.diagnostics.filter((d) => d.severity === 'error');
    return {
      ok: false,
      kind: 'compile-error',
      message: errors.map((e) => e.message).join('; ') || 'compilation failed',
    };
  }
  const slots =
    (result as { artifact?: { constructorSlots?: Array<{ paramIndex: number; byteOffset: number }> } })
      .artifact?.constructorSlots ?? [];
  const spliced = spliceConstructorArgs(result.scriptHex, slots, args);
  return compareBytes(target, hexToBytes(spliced));
}

function compareBytes(target: Uint8Array, compiled: Uint8Array): VerifyResult {
  if (bytesEqual(compiled, target)) return { ok: true };
  const off = firstDiff(compiled, target);
  const sliceEnd = Math.min(off + 32, target.length);
  const candSliceEnd = Math.min(off + 32, compiled.length);
  return {
    ok: false,
    kind: 'byte-diff',
    divergenceOffset: off,
    targetSlice: target.slice(off, sliceEnd),
    candidateSlice: compiled.slice(off, candSliceEnd),
  };
}
