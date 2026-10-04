// ---------------------------------------------------------------------------
// runar-sdk/slot-layout.ts — resolve verification descriptors for GIVEN args
// ---------------------------------------------------------------------------
//
// The artifact's `constructorSlots` / `stateFields` / `templateDigest` carry
// value-INDEPENDENT descriptor metadata (the compiler cannot know how many
// bytes a slot occupies after deployment — that depends on the VALUE baked at
// deploy time: a 33-byte PubKey push vs. a single OP_N opcode byte). This
// module is the value-DEPENDENT half of that design split:
//
//   resolveSlotLayout(artifact, args)   → concrete slot offsets/lengths in the
//                                         deployed code part
//   computeTemplateHash(artifact, args) → hash256 of the code part with every
//                                         slot's VALUE bytes excised (the
//                                         template identity a companion-input
//                                         verifier checks)
//   resolveStateLayout(artifact)        → per-state-field byte layout in the
//                                         OP_RETURN state tail
//
// Encoding classes a verifier must distinguish (single-opcode encodings have
// NO push header — the opcode byte IS the value):
//   - 'data-push'      raw data push: 1/2/3/5-byte header + value bytes
//   - 'scriptnum-push' Script number >= 17 or <= -2: 1-byte header + LE
//                      sign-magnitude payload
//   - 'op-n'           bigint 1..16 → single opcode 0x51..0x60 (value = byte - 0x50)
//   - 'op-0'           bigint 0 / empty data → single 0x00 opcode
//   - 'op-1negate'     bigint -1 → single 0x4f opcode
//   - 'bool'           boolean → single 0x51 / 0x00 opcode
//
// NOTE: offsets are relative to the CODE PART (the locking script before any
// inscription envelope and before the OP_RETURN state tail) — the same bytes
// `RunarContract.getCodePartHex()` returns for a template-built contract.
// Inscription envelopes are appended AFTER the code part and do not shift
// slot offsets.

import { Hash, Utils } from '@bsv/sdk';
import type { RunarArtifact, ConstructorSlot, StateField } from 'runar-ir-schema';
import { annotateStateFieldLayout, totalStateByteLength } from 'runar-ir-schema';
import { encodeArg, encodeScriptNumber, patchCodePartLenSlots } from './contract.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ResolvedSlotEncoding =
  | 'data-push'
  | 'scriptnum-push'
  | 'op-n'
  | 'op-0'
  | 'op-1negate'
  | 'bool';

/** One constructor slot resolved against concrete constructor args. */
export interface ResolvedSlot {
  /** Constructor param name (from the enriched slot, falling back to the ABI). */
  name: string;
  /** Index into `abi.constructor.params`. */
  paramIndex: number;
  /** Byte offset of the 1-byte OP_0 placeholder in the TEMPLATE script. */
  templateByteOffset: number;
  /** Byte offset of the slot's first byte (push header, or the single
   *  opcode) in the RESOLVED code part. */
  byteOffset: number;
  /** Total encoded length in bytes (header + value; 1 for single-opcode
   *  encodings). */
  byteLength: number;
  /** Push-header length in bytes (0 for single-opcode encodings). */
  pushHeaderBytes: number;
  /** Byte offset of the VALUE bytes in the resolved code part. For
   *  single-opcode encodings this is the opcode byte itself (a verifier of
   *  an 'op-n' slot reads this byte and compares against 0x50 + N). */
  valueByteOffset: number;
  /** Length of the value bytes (1 for single-opcode encodings). */
  valueByteLength: number;
  /** How the value is encoded at this slot for THESE args. */
  encoding: ResolvedSlotEncoding;
}

export interface ResolvedSlotLayout {
  /** Resolved slots in ascending byteOffset order. */
  slots: ResolvedSlot[];
  /** Total length in bytes of the resolved code part. */
  codeByteLength: number;
}

/** State-tail layout resolved from an artifact. */
export interface ResolvedStateLayout {
  /** State fields annotated with encoding/byteOffset/byteLength/tailOffset,
   *  in serialization order. */
  fields: StateField[];
  /** Total serialized state length in bytes (after the OP_RETURN byte).
   *  Absent when any field is variable-length. */
  totalByteLength?: number;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const hash256hex = (hex: string): string =>
  Utils.toHex(Hash.hash256(Utils.toArray(hex, 'hex')));

/**
 * Resolve the adjusted codeSep index values for all codeSepIndex slots.
 * Mirrors RunarContract's private `_resolvedCodeSepSlotValues` — a pure
 * function of (artifact, constructorArgs); kept in sync by the layout
 * parity tests (`slot-layout.test.ts` asserts byte-identity against
 * `getCodePartHex()`, which exercises the contract-side twin).
 */
function resolvedCodeSepSlotValues(
  artifact: RunarArtifact,
  constructorArgs: unknown[],
): Array<{ templateByteOffset: number; adjustedValue: number }> {
  if (!artifact.codeSepIndexSlots || artifact.codeSepIndexSlots.length === 0) {
    return [];
  }
  const sorted = [...artifact.codeSepIndexSlots].sort((a, b) => a.byteOffset - b.byteOffset);
  const result: Array<{ templateByteOffset: number; adjustedValue: number }> = [];
  for (const slot of sorted) {
    let shift = 0;
    if (artifact.constructorSlots) {
      for (const cs of artifact.constructorSlots) {
        if (cs.byteOffset < slot.codeSepIndex) {
          const encoded = encodeArg(constructorArgs[cs.paramIndex]);
          shift += encoded.length / 2 - 1;
        }
      }
    }
    for (const prev of result) {
      if (prev.templateByteOffset < slot.codeSepIndex) {
        const prevEncoded = encodeScriptNumber(BigInt(prev.adjustedValue));
        shift += prevEncoded.length / 2 - 1;
      }
    }
    result.push({ templateByteOffset: slot.byteOffset, adjustedValue: slot.codeSepIndex + shift });
  }
  return result;
}

/** Classify the encoded slot bytes (see ResolvedSlotEncoding). */
function classifyEncoded(
  encodedHex: string,
  argValue: unknown,
): { encoding: ResolvedSlotEncoding; pushHeaderBytes: number } {
  const b0 = parseInt(encodedHex.slice(0, 2), 16);

  if (typeof argValue === 'boolean') {
    return { encoding: 'bool', pushHeaderBytes: 0 };
  }
  if (typeof argValue === 'bigint' || typeof argValue === 'number') {
    if (b0 === 0x00) return { encoding: 'op-0', pushHeaderBytes: 0 };
    if (b0 === 0x4f) return { encoding: 'op-1negate', pushHeaderBytes: 0 };
    if (b0 >= 0x51 && b0 <= 0x60) return { encoding: 'op-n', pushHeaderBytes: 0 };
    // Otherwise a script-number push. Derive the header width from the actual
    // push opcode rather than assuming 1 byte: a sign-magnitude payload > 75
    // bytes uses OP_PUSHDATA1/2/4 (2/3/5-byte headers), which would otherwise
    // shift the excision window and corrupt the template hash.
    if (b0 <= 0x4b) return { encoding: 'scriptnum-push', pushHeaderBytes: 1 };
    if (b0 === 0x4c) return { encoding: 'scriptnum-push', pushHeaderBytes: 2 };
    if (b0 === 0x4d) return { encoding: 'scriptnum-push', pushHeaderBytes: 3 };
    return { encoding: 'scriptnum-push', pushHeaderBytes: 5 }; // 0x4e
  }
  // Data (hex string): OP_0 for empty, else direct push / PUSHDATA1/2/4.
  if (b0 === 0x00) return { encoding: 'op-0', pushHeaderBytes: 0 };
  if (b0 <= 0x4b) return { encoding: 'data-push', pushHeaderBytes: 1 };
  if (b0 === 0x4c) return { encoding: 'data-push', pushHeaderBytes: 2 };
  if (b0 === 0x4d) return { encoding: 'data-push', pushHeaderBytes: 3 };
  return { encoding: 'data-push', pushHeaderBytes: 5 }; // 0x4e
}

interface Substitution {
  templateByteOffset: number;
  encodedHex: string;
  /** Present for constructor slots; absent for codeSepIndex slots. */
  slot?: ConstructorSlot;
}

/**
 * Assert that the template script actually carries the 1-byte OP_0
 * placeholder (0x00) at a slot's byteOffset. The descriptor anchor points
 * (`constructorSlots[].byteOffset`, `codeSepIndexSlots[].byteOffset`) are
 * trusted verbatim from the artifact JSON — a corrupted or mismatched
 * descriptor (wrong offsets for this script) would otherwise be spliced
 * over silently, yielding wrong layouts and a wrong template hash.
 */
function assertPlaceholderByte(
  artifact: RunarArtifact,
  byteOffset: number,
  slotKind: string,
  slotLabel: string,
): void {
  const byteHex = artifact.script.slice(byteOffset * 2, byteOffset * 2 + 2);
  if (byteHex !== '00') {
    throw new Error(
      `resolveSlotLayout: ${slotKind} ${slotLabel} expects an OP_0 placeholder ` +
        `(0x00) at byteOffset ${byteOffset} of the template script, found ` +
        `${byteHex === '' ? 'end-of-script' : `0x${byteHex}`} — ` +
        `the descriptor does not match this artifact's script (corrupted or ` +
        `mismatched artifact JSON)`,
    );
  }
}

/** All template substitutions (constructor slots + codeSepIndex slots). */
function collectSubstitutions(
  artifact: RunarArtifact,
  constructorArgs: unknown[],
): Substitution[] {
  const subs: Substitution[] = [];
  for (const slot of artifact.constructorSlots ?? []) {
    const abiParamName = artifact.abi.constructor.params[slot.paramIndex]?.name;
    if (slot.paramIndex >= constructorArgs.length) {
      throw new Error(
        `resolveSlotLayout: constructor slot for paramIndex ${slot.paramIndex} ` +
          `('${slot.name ?? abiParamName ?? '?'}') ` +
          `has no matching constructor arg (got ${constructorArgs.length} args)`,
      );
    }
    // An enriched slot's name must correspond to the ABI constructor param
    // at its paramIndex — a mismatch means the descriptor's slot metadata
    // and the ABI disagree about which value lands in this slot.
    if (slot.name !== undefined && slot.name !== abiParamName) {
      throw new Error(
        `resolveSlotLayout: constructor slot at byteOffset ${slot.byteOffset} ` +
          `is named '${slot.name}' but abi.constructor.params[${slot.paramIndex}] ` +
          `is ${abiParamName === undefined ? 'missing' : `named '${abiParamName}'`} — ` +
          `corrupted or mismatched descriptor`,
      );
    }
    assertPlaceholderByte(
      artifact,
      slot.byteOffset,
      'constructor slot',
      `'${slot.name ?? abiParamName ?? `param${slot.paramIndex}`}'`,
    );
    subs.push({
      templateByteOffset: slot.byteOffset,
      encodedHex: encodeArg(constructorArgs[slot.paramIndex]),
      slot,
    });
  }
  for (const rs of resolvedCodeSepSlotValues(artifact, constructorArgs)) {
    assertPlaceholderByte(
      artifact,
      rs.templateByteOffset,
      'codeSepIndex slot',
      `(adjusted value ${rs.adjustedValue})`,
    );
    subs.push({
      templateByteOffset: rs.templateByteOffset,
      encodedHex: encodeScriptNumber(BigInt(rs.adjustedValue)),
    });
  }
  subs.sort((a, b) => a.templateByteOffset - b.templateByteOffset);
  return subs;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Resolve the artifact's constructor slots against concrete constructor
 * args, returning exact byte offsets/lengths in the deployed code part.
 *
 * This is the mechanical replacement for hand-deriving offsets from a
 * compiled script with `indexOf`/byte-diffing: a downstream verifier
 * (e.g. a consuming covenant that template-checks a companion input's
 * parent-tx output) takes `valueByteOffset` / `valueByteLength` /
 * `encoding` from here instead.
 */
export function resolveSlotLayout(
  artifact: RunarArtifact,
  constructorArgs: unknown[],
): ResolvedSlotLayout {
  const subs = collectSubstitutions(artifact, constructorArgs);

  const slots: ResolvedSlot[] = [];
  let shift = 0;
  for (const sub of subs) {
    const byteOffset = sub.templateByteOffset + shift;
    const byteLength = sub.encodedHex.length / 2;
    if (sub.slot) {
      const { encoding, pushHeaderBytes } = classifyEncoded(
        sub.encodedHex,
        constructorArgs[sub.slot.paramIndex],
      );
      slots.push({
        name:
          sub.slot.name ??
          artifact.abi.constructor.params[sub.slot.paramIndex]?.name ??
          `param${sub.slot.paramIndex}`,
        paramIndex: sub.slot.paramIndex,
        templateByteOffset: sub.templateByteOffset,
        byteOffset,
        byteLength,
        pushHeaderBytes,
        valueByteOffset: byteOffset + pushHeaderBytes,
        valueByteLength: byteLength - pushHeaderBytes,
        encoding,
      });
    }
    shift += byteLength - 1; // each substitution replaces a 1-byte OP_0
  }

  return {
    slots,
    codeByteLength: artifact.script.length / 2 + shift,
  };
}

/**
 * Build the resolved code part (template with all substitutions spliced in)
 * — byte-identical to `RunarContract.getCodePartHex()` for a template-built
 * contract without an inscription envelope.
 */
export function buildResolvedCodeHex(
  artifact: RunarArtifact,
  constructorArgs: unknown[],
): string {
  const subs = collectSubstitutions(artifact, constructorArgs);
  let script = artifact.script;
  // Descending order so each splice doesn't invalidate earlier offsets.
  for (const sub of [...subs].sort((a, b) => b.templateByteOffset - a.templateByteOffset)) {
    const hexOffset = sub.templateByteOffset * 2;
    script = script.slice(0, hexOffset) + sub.encodedHex + script.slice(hexOffset + 2);
  }
  // N-051: deploy-time code-part length pins (no inscription envelope here).
  return patchCodePartLenSlots(
    artifact,
    script,
    subs.map((s) => ({ byteOffset: s.templateByteOffset, encoded: s.encodedHex })),
    script.length / 2,
  );
}

/**
 * Compute the slot-excised template hash for the artifact deployed with the
 * given constructor args: hash256 (hex) of the resolved code part with every
 * slot's VALUE bytes removed.
 *
 * Push headers of 'data-push'/'scriptnum-push' slots REMAIN in the hashed
 * template (pinning the baked value's length); single-opcode encodings
 * (op-n / op-0 / op-1negate / bool) have their opcode byte excised.
 *
 * The result is what a consuming covenant bakes as its expected companion
 * code hash (`templateDigest.algorithm === 'hash256-excised-slots'`), and
 * what an off-chain verifier recomputes from a candidate script using
 * `resolveSlotLayout` boundaries.
 */
export function computeTemplateHash(
  artifact: RunarArtifact,
  constructorArgs: unknown[],
): string {
  const code = buildResolvedCodeHex(artifact, constructorArgs);
  const { slots } = resolveSlotLayout(artifact, constructorArgs);

  // Excise value ranges in descending order.
  let template = code;
  for (const s of [...slots].sort((a, b) => b.valueByteOffset - a.valueByteOffset)) {
    template =
      template.slice(0, s.valueByteOffset * 2) +
      template.slice((s.valueByteOffset + s.valueByteLength) * 2);
  }
  return hash256hex(template);
}

/**
 * Resolve the state-tail byte layout for a stateful contract's artifact.
 *
 * Prefers the compiler-annotated `stateFields` layout when present; falls
 * back to computing it (via the shared `runar-ir-schema` width table) for
 * artifacts produced before descriptor emission. Returns fields in
 * serialization order.
 */
export function resolveStateLayout(artifact: RunarArtifact): ResolvedStateLayout {
  const fields = artifact.stateFields ?? [];
  const annotated = fields.every(f => f.encoding !== undefined)
    ? [...fields].sort((a, b) => a.index - b.index)
    : annotateStateFieldLayout(fields);
  const total = totalStateByteLength(fields);
  const result: ResolvedStateLayout = { fields: annotated };
  if (total !== undefined) result.totalByteLength = total;
  return result;
}
