// ---------------------------------------------------------------------------
// conformance/sdk-vertical/reference/readback.ts
// ---------------------------------------------------------------------------
//
// The READBACK side of the vertical pin: what `matchesArtifact` and
// `extractConstructorArgs` must say about a deployed locking script.
//
// For every case this derives, independently of any SDK:
//   - the honest deployed locking script (the spliced code part, plus the
//     OP_RETURN state tail for a stateful artifact), which every tier must
//     accept and read the case's own constructor args back out of;
//   - a set of TAMPERED scripts, each a self-consistent deployment with
//     exactly one defect at a constructor slot, which every tier must reject.
//
// A tamper is built by re-splicing the TEMPLATE with one slot's bytes
// overridden, so everything the defect does not touch stays honest: the
// codeSepIndex slots bake the value the tampered widths imply, and the
// codePartLen fields hold the tampered code-part length. A matcher can then
// only reject the tamper by checking the one thing it is there to test — a
// tamper that also broke an unrelated check would pass a matcher that lacks
// the check under test.
//
// Like the rest of reference/, this imports nothing from packages/**.
// ---------------------------------------------------------------------------

import type { RefArtifact, RefConstructorSlot } from './derive.js';
import { argValue, encodePushData, encodeScriptNumber, encodeSlotValue, type TypedArg, type ValueEncoding } from './encode.js';
import { walkScript } from './script.js';

/** A constructor arg as read back: `{type, value}` in input.json's
 *  conventions (decimal for integers, 'true'/'false', lowercase hex), with
 *  `type` the artifact's ABI param type. */
export interface ReadbackArg {
  type: string;
  value: string;
}

export interface ReadbackHonest {
  scriptHex: string;
  matches: true;
  /** Positional by paramIndex; null for a param with no constructor slot
   *  (a mutable state field), which extractConstructorArgs does not report. */
  args: Array<ReadbackArg | null>;
  extractRaises: false;
}

export interface ReadbackTamper {
  id: string;
  /** Which matchesArtifact rule this tamper exists to exercise. */
  class: 'non-push-at-slot' | 'repeat-ref-differs' | 'wrong-fixed-width' | 'missing-state';
  description: string;
  scriptHex: string;
  matches: false;
  /** Whether extractConstructorArgs must raise the tier's malformed-script
   *  error. When false the args it reports are not pinned: the script is not
   *  a deployment of this artifact, so there is no honest answer to compare. */
  extractRaises: boolean;
}

export interface ReadbackDerivation {
  honest: ReadbackHonest;
  tampers: ReadbackTamper[];
}

/** OP_NOP: an opcode encodeArg can never write at a constructor slot. */
const NON_PUSH = '61';

function abiEncoding(slot: RefConstructorSlot, abiType: string): ValueEncoding {
  if (slot.valueEncoding) return slot.valueEncoding;
  if (abiType === 'bigint' || abiType === 'int') return 'scriptnum';
  if (abiType === 'bool' || abiType === 'boolean') return 'bool';
  return 'data';
}

function le32(n: number): string {
  let s = '';
  for (let i = 0; i < 4; i++) s += ((n >>> (8 * i)) & 0xff).toString(16).padStart(2, '0');
  return s;
}

/**
 * Splice the template with the given bytes at each constructor slot (keyed by
 * template byte offset), then bake every codeSepIndex slot and codePartLen
 * field from the resulting widths — the same rules deploy follows, applied to
 * whatever bytes the slots hold.
 */
function spliceCodePart(artifact: RefArtifact, ctorHex: Map<number, string>): string {
  const subs: Array<{ at: number; hex: string }> = [];
  for (const slot of artifact.constructorSlots ?? []) {
    const hex = ctorHex.get(slot.byteOffset);
    if (hex === undefined) throw new Error(`no bytes for constructor slot at template byte ${slot.byteOffset}`);
    subs.push({ at: slot.byteOffset, hex });
  }
  const ctorSubs = [...subs];
  const baked: Array<{ at: number; hex: string }> = [];
  for (const cs of [...(artifact.codeSepIndexSlots ?? [])].sort((a, b) => a.byteOffset - b.byteOffset)) {
    let shift = 0;
    for (const c of ctorSubs) if (c.at < cs.codeSepIndex) shift += c.hex.length / 2 - 1;
    for (const p of baked) if (p.at < cs.codeSepIndex) shift += p.hex.length / 2 - 1;
    const hex = encodeScriptNumber(BigInt(cs.codeSepIndex + shift));
    baked.push({ at: cs.byteOffset, hex });
    subs.push({ at: cs.byteOffset, hex });
  }

  let code = artifact.script;
  for (const s of [...subs].sort((a, b) => b.at - a.at)) {
    code = code.slice(0, s.at * 2) + s.hex + code.slice(s.at * 2 + 2);
  }
  for (const f of artifact.codePartLenSlots ?? []) {
    let expand = 0;
    for (const s of subs) if (s.at < f.byteOffset) expand += s.hex.length / 2 - 1;
    const at = (f.byteOffset + expand) * 2;
    code = code.slice(0, at) + le32(code.length / 2) + code.slice(at + 8);
  }
  return code;
}

/**
 * The OP_RETURN state tail a stateful deployment carries, for the state-field
 * shapes this suite uses. Deliberately narrow: state framing is the C2 family
 * (conformance/sdk-output/tests/stateful-bytestring-op-n-state); this only
 * needs to put a well-formed tail behind the code part, and refuses any shape
 * whose framing it would have to guess.
 */
function stateTail(artifact: RefArtifact, args: TypedArg[]): string {
  const fields = [...(artifact.stateFields ?? [])].sort((a, b) => Number(a.index) - Number(b.index));
  let tail = '6a';
  for (const f of fields) {
    const pi = artifact.abi.constructor.params.findIndex((p) => p.name === f.name);
    const arg = args[pi];
    if (pi < 0 || arg === undefined) throw new Error(`state field '${String(f.name)}' has no constructor arg`);
    if (f.type !== 'ByteString' || f.encoding !== 'pushdata') {
      throw new Error(`readback reference does not encode state field '${String(f.name)}' (${String(f.type)}/${String(f.encoding)})`);
    }
    const v = argValue(arg) as string;
    // A 1-byte value is the OP_N-range framing question C2 owns; stay out of it.
    if (v.length / 2 < 2) throw new Error(`readback reference refuses 1-byte or empty state value for '${String(f.name)}'`);
    tail += encodePushData(v);
  }
  return tail;
}

/** The value extractConstructorArgs must report for an arg, as a string. */
function readbackValue(enc: ValueEncoding, arg: TypedArg): string {
  const v = argValue(arg);
  if (enc === 'scriptnum') return (v as bigint).toString(10);
  if (enc === 'bool') return v ? 'true' : 'false';
  return v as string;
}

/** A valid push of `hex` that differs from `notHex` (both encoded forms). */
function otherPush(honestHex: string, enc: ValueEncoding): string {
  if (enc === 'scriptnum') return honestHex === encodeScriptNumber(1000n) ? encodeScriptNumber(1001n) : encodeScriptNumber(1000n);
  if (enc === 'bool') return honestHex === '51' ? '00' : '51';
  return honestHex === '01ee' ? '01ef' : '01ee';
}

export function deriveReadback(artifact: RefArtifact, args: TypedArg[]): ReadbackDerivation {
  const params = artifact.abi.constructor.params;
  const slots = [...(artifact.constructorSlots ?? [])].sort((a, b) => a.byteOffset - b.byteOffset);
  const stateful = (artifact.stateFields ?? []).length > 0;
  const tail = stateful ? stateTail(artifact, args) : '';

  const honestHex = new Map<number, string>();
  for (const s of slots) honestHex.set(s.byteOffset, encodeSlotValue(abiEncoding(s, params[s.paramIndex]!.type), args[s.paramIndex]!));
  const honestCode = spliceCodePart(artifact, honestHex);

  const honestArgs: Array<ReadbackArg | null> = params.map((p, i) => {
    const s = slots.find((x) => x.paramIndex === i);
    if (!s) return null;
    return { type: p.type, value: readbackValue(abiEncoding(s, p.type), args[i]!) };
  });

  const tampers: ReadbackTamper[] = [];
  const withOverride = (over: Map<number, string>): string => {
    const m = new Map(honestHex);
    for (const [k, v] of over) m.set(k, v);
    return spliceCodePart(artifact, m) + tail;
  };
  const label = (s: RefConstructorSlot) => `${s.name ?? params[s.paramIndex]!.name}@${s.byteOffset}`;

  // 1. A non-push opcode at the first constructor slot in byte order: no
  //    deployment writes one, and extractConstructorArgs must refuse to report
  //    a value for it.
  if (slots.length > 0) {
    const s = slots[0]!;
    tampers.push({
      id: `non-push:${label(s)}`,
      class: 'non-push-at-slot',
      description: `OP_NOP (0x61) at the constructor slot ${label(s)} (template byte offset), all other slots honest`,
      scriptHex: withOverride(new Map([[s.byteOffset, NON_PUSH]])),
      matches: false,
      extractRaises: true,
    });
  }

  // 2. Per param referenced more than once: a non-push opcode at the SECOND
  //    reference only (the check runs at every occurrence, not just the one
  //    the value is read from), and a different valid push there.
  for (let pi = 0; pi < params.length; pi++) {
    const refs = slots.filter((s) => s.paramIndex === pi);
    if (refs.length < 2) continue;
    const second = refs[1]!;
    tampers.push({
      id: `non-push:${label(second)}`,
      class: 'non-push-at-slot',
      description: `OP_NOP (0x61) at ${label(second)}, the second reference of '${params[pi]!.name}'; the first reference is honest`,
      scriptHex: withOverride(new Map([[second.byteOffset, NON_PUSH]])),
      matches: false,
      extractRaises: true,
    });

    const enc = abiEncoding(second, params[pi]!.type);
    const honest = honestHex.get(second.byteOffset)!;
    let other: string;
    if (second.fixedValueByteLength !== undefined) {
      // Same width, different bytes: only the every-reference-agrees rule
      // can catch it.
      const v = argValue(args[pi]!) as string;
      const last = (parseInt(v.slice(-2), 16) ^ 0x01).toString(16).padStart(2, '0');
      other = encodePushData(v.slice(0, -2) + last);
    } else {
      other = otherPush(honest, enc);
    }
    tampers.push({
      id: `repeat-differs:${label(second)}`,
      class: 'repeat-ref-differs',
      description: `'${params[pi]!.name}' pushes ${other} at its second reference ${label(second)} but ${honest} at the first`,
      scriptHex: withOverride(new Map([[second.byteOffset, other]])),
      matches: false,
      extractRaises: false,
    });
  }

  // 3. Per param whose slots declare fixedValueByteLength: a push one byte
  //    short, written CONSISTENTLY at every reference so only the width rule
  //    can catch it.
  for (let pi = 0; pi < params.length; pi++) {
    const refs = slots.filter((s) => s.paramIndex === pi && s.fixedValueByteLength !== undefined);
    if (refs.length === 0) continue;
    const want = refs[0]!.fixedValueByteLength!;
    const v = argValue(args[pi]!) as string;
    if (v.length / 2 !== want) throw new Error(`arg for '${params[pi]!.name}' is not ${want} bytes`);
    const short = encodePushData(v.slice(0, -2));
    const over = new Map(refs.map((s) => [s.byteOffset, short] as [number, string]));
    tampers.push({
      id: `wrong-width:${params[pi]!.name}`,
      class: 'wrong-fixed-width',
      description: `'${params[pi]!.name}' pushes ${want - 1} bytes (its value minus the last byte) at every reference; the slots declare fixedValueByteLength ${want}`,
      scriptHex: withOverride(over),
      matches: false,
      extractRaises: false,
    });
  }

  // 4. Stateful: the honest code part with nothing after it.
  if (stateful) {
    tampers.push({
      id: 'missing-state',
      class: 'missing-state',
      description: 'the honest code part with no OP_RETURN state section after it',
      scriptHex: honestCode,
      matches: false,
      extractRaises: false,
    });
  }

  // Every script must decode cleanly and every tamper must differ from the
  // honest script — a tamper equal to the honest bytes would pin nothing.
  const honestScript = honestCode + tail;
  walkScript(honestScript);
  const seen = new Set<string>([honestScript]);
  for (const t of tampers) {
    walkScript(t.scriptHex);
    if (seen.has(t.scriptHex)) throw new Error(`tamper '${t.id}' duplicates another script`);
    seen.add(t.scriptHex);
  }

  return {
    honest: { scriptHex: honestScript, matches: true, args: honestArgs, extractRaises: false },
    tampers,
  };
}
