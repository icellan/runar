/**
 * SSA bindings → ANF program builder.
 *
 * Two construction paths:
 *
 *   - `lift(SsaMethod)` — passes the current SSA bindings through unchanged
 *     for the legacy raw_block / assert-chain emit-ts path. Used by the
 *     human-readable pretty-printer when no full ANF is needed.
 *
 *   - `buildRawScriptProgram(bytes, opts)` — produces a real ANFProgram
 *     wrapping the entire byte stream in a single `raw_script` ANF node.
 *     This is what the `--raw` decompile mode + the non-template fallback
 *     feed into `compileFromANF` for byte-identity verification.
 */

import type { ANFProgram } from 'runar-compiler';
import type { SsaMethod, SsaBinding } from './symexec.js';
import { bytesToHex } from 'runar-testing';

export interface LiftedMethod {
  index: number;
  bindings: SsaBinding[];
  result: string;
}

export function lift(method: SsaMethod): LiftedMethod {
  return {
    index: method.index,
    bindings: method.bindings,
    result: method.result,
  };
}

export interface BuildRawScriptOptions {
  contractName?: string;
  methodName?: string;
  /**
   * Override the inferred output arity. Defaults to 1 — the public-method
   * invariant requires a truthy top-of-stack at script end, so any
   * non-trivial wrapped span produces one final stack value.
   */
  outArity?: number;
  /** Override the inferred input arity. Defaults to 0. */
  inArity?: number;
}

/**
 * Build an `ANFProgram` whose single public method contains exactly one
 * `raw_script` binding wrapping the supplied opcode bytes. The output is
 * suitable for `compileFromANF` and the round-trip canary already verifies
 * byte-identity for every example + 8 hand-rolled scripts.
 */
export function buildRawScriptProgram(
  bytes: Uint8Array,
  opts: BuildRawScriptOptions = {},
): ANFProgram {
  const contractName = opts.contractName ?? '_Recovered';
  const methodName   = opts.methodName   ?? 'unlock';
  const inArity      = opts.inArity      ?? 0;
  const outArity     = opts.outArity     ?? 1;
  const hex = bytesToHex(bytes);
  return {
    contractName,
    properties: [],
    methods: [
      {
        name: methodName,
        params: [],
        isPublic: true,
        body: [
          {
            name: 't0',
            value: {
              kind: 'raw_script',
              bytes: hex,
              in_arity: inArity,
              out_arity: outArity,
            },
          },
        ],
      },
    ],
  };
}
