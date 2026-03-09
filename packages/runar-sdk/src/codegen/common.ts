// ---------------------------------------------------------------------------
// codegen/common.ts — ABI analysis utilities for code generation
// ---------------------------------------------------------------------------

import type { ABIMethod, RunarArtifact } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Param classification
// ---------------------------------------------------------------------------

export interface ClassifiedParam {
  name: string;
  /** The ABI type string (e.g. "bigint", "Sig", "PubKey") */
  abiType: string;
  /** The TypeScript type to use in generated code */
  tsType: string;
  /** True if this param is auto-computed by the SDK (SigHashPreimage, _changePKH, _changeAmount) */
  hidden: boolean;
}

const TS_TYPE_MAP: Record<string, string> = {
  bigint: 'bigint',
  boolean: 'boolean',
  Sig: 'string | null',
  PubKey: 'string | null',
  ByteString: 'string',
  Addr: 'string',
  Ripemd160: 'string',
  Sha256: 'string',
  Point: 'string',
  SigHashPreimage: 'string | null',
};

/**
 * Map an ABI type to a TypeScript type string.
 * Unknown types fall back to `unknown`.
 */
export function mapTypeToTS(abiType: string): string {
  return TS_TYPE_MAP[abiType] ?? 'unknown';
}

/**
 * Classify a method's params into user-visible and hidden (auto-computed).
 *
 * Hidden params are:
 * - Sig: always auto-computed from the connected signer (two-pass signing)
 * - SigHashPreimage: auto-computed for stateful contracts
 * - _changePKH, _changeAmount: auto-injected by SDK for stateful contracts
 *
 * Hidden params don't appear in the generated method signature.
 * Of these, Sig params are included in the args array as `null` (the SDK
 * auto-computes them), while SigHashPreimage/_changePKH/_changeAmount are
 * entirely SDK-internal and excluded from the args array.
 */
export function classifyParams(method: ABIMethod, isStateful: boolean): ClassifiedParam[] {
  return method.params.map((p) => {
    const hidden =
      p.type === 'Sig' ||
      (isStateful && (
        p.type === 'SigHashPreimage' ||
        p.name === '_changePKH' ||
        p.name === '_changeAmount' ||
        p.name === '_newAmount'
      ));
    return {
      name: p.name,
      abiType: p.type,
      tsType: mapTypeToTS(p.type),
      hidden,
    };
  });
}

/**
 * Get only the user-visible params for a method.
 */
export function getUserParams(method: ABIMethod, isStateful: boolean): ClassifiedParam[] {
  return classifyParams(method, isStateful).filter((p) => !p.hidden);
}

/**
 * Get params that match the SDK's args array — all params except the ones
 * the SDK handles entirely internally (SigHashPreimage, _changePKH,
 * _changeAmount) for stateful contracts.
 *
 * Sig params ARE included (passed as null for auto-computation by the SDK).
 * This matches the SDK's `userParams` filtering in `call()`/`prepareCall()`.
 */
export function getSdkArgParams(method: ABIMethod, isStateful: boolean): ClassifiedParam[] {
  return classifyParams(method, isStateful).filter((p) => {
    if (!isStateful) return true;
    return p.abiType !== 'SigHashPreimage' && p.name !== '_changePKH' && p.name !== '_changeAmount' && p.name !== '_newAmount';
  });
}

// ---------------------------------------------------------------------------
// Terminal detection
// ---------------------------------------------------------------------------

/**
 * Determine if a method is terminal (no state continuation output).
 *
 * Uses the explicit `isTerminal` flag if present, falls back to checking
 * for the absence of `_changePKH` in the params.
 */
export function isTerminalMethod(method: ABIMethod, isStateful: boolean): boolean {
  if (!isStateful) return true; // stateless contracts are always terminal
  if (method.isTerminal !== undefined) return method.isTerminal;
  // Fallback for older artifacts without isTerminal
  return !method.params.some((p) => p.name === '_changePKH');
}

// ---------------------------------------------------------------------------
// Artifact analysis
// ---------------------------------------------------------------------------

export function isStatefulArtifact(artifact: RunarArtifact): boolean {
  return artifact.stateFields !== undefined && artifact.stateFields.length > 0;
}

export function getPublicMethods(artifact: RunarArtifact): ABIMethod[] {
  return artifact.abi.methods.filter((m) => m.isPublic);
}

/** Reserved method names on the generated wrapper class. */
const RESERVED_NAMES = new Set(['connect', 'deploy', 'contract']);

/**
 * Generate a safe method name, avoiding collisions with wrapper class methods.
 */
export function safeMethodName(name: string): string {
  if (RESERVED_NAMES.has(name)) return `call${name.charAt(0).toUpperCase()}${name.slice(1)}`;
  return name;
}
