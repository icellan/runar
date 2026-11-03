// ---------------------------------------------------------------------------
// conformance/sdk-vertical/reference/derive.ts
// ---------------------------------------------------------------------------
//
// The vertical derivation: given ONLY a compiler artifact and a list of typed
// constructor args, independently produce
//
//   - the deployed code part (template with every slot spliced)
//   - the resolved byte layout of every constructor slot
//   - the deployed byte offsets of every OP_CODESEPARATOR
//
// and check the artifact's own claims against an opcode walk of the bytes it
// ships. Imports nothing from packages/** — see ../README.md.
//
// Two independent layers, deliberately:
//
//   SPEC layer   — encode.ts reproduces the wire format from its rules and
//                  the compiler's declared `valueEncoding`, so the expected
//                  bytes are computed rather than copied from a tier.
//   SEMANTIC layer — walkScript disassembles the FINISHED script and asks
//                  what stack item each slot actually pushes. This survives
//                  a legitimate change of encoding and still catches the
//                  fund-losing confusions (OP_0 vs `01 00`), because those
//                  change the pushed VALUE, not just its spelling.
// ---------------------------------------------------------------------------

import {
  decodeScriptNumber,
  findCodeSeparators,
  walkScript,
  type ScriptOp,
} from './script.js';
import { encodeScriptNumber, encodeSlotValue, expectedPushedHex, type TypedArg, type ValueEncoding } from './encode.js';

// ---------------------------------------------------------------------------
// Minimal artifact shape (a structural subset of RunarArtifact — declared
// here rather than imported so this tree stays independent of the compiler's
// own type definitions).
// ---------------------------------------------------------------------------

export interface RefConstructorSlot {
  paramIndex: number;
  byteOffset: number;
  name?: string;
  type?: string;
  valueEncoding?: ValueEncoding;
  fixedValueByteLength?: number;
  fixedPushHeaderBytes?: number;
}

export interface RefCodeSepIndexSlot {
  byteOffset: number;
  codeSepIndex: number;
}

export interface RefArtifact {
  contractName: string;
  parentClass?: string;
  script: string;
  abi: { constructor: { params: Array<{ name: string; type: string }> } };
  constructorSlots?: RefConstructorSlot[];
  codeSepIndexSlots?: RefCodeSepIndexSlot[];
  /** N-051: deploy-time `SIZE(_codePart)` length fields (4 bytes, LE). */
  codePartLenSlots?: Array<{ byteOffset: number }>;
  codeSeparatorIndex?: number;
  codeSeparatorIndices?: number[];
  stateFields?: Array<Record<string, unknown>> | null;
}

export interface Violation {
  code: string;
  message: string;
}

/** One constructor slot resolved against concrete args, in the DEPLOYED script. */
export interface ResolvedRefSlot {
  name: string;
  paramIndex: number;
  templateByteOffset: number;
  /** Offset in the deployed code part. */
  byteOffset: number;
  byteLength: number;
  headerBytes: number;
  valueByteOffset: number;
  valueByteLength: number;
  encoding: ValueEncoding;
  /** The stack item this slot pushes in the deployed script, lowercase hex. */
  pushedHex: string;
}

export interface VerticalDerivation {
  contractName: string;
  /** Deployed code part: template with all slots spliced. Excludes any
   *  OP_RETURN state tail (that is the C2 family's surface). */
  codePartHex: string;
  codePartByteLength: number;
  slots: ResolvedRefSlot[];
  /** OP_CODESEPARATOR offsets found by walking the TEMPLATE script. */
  templateCodeSeparators: number[];
  /** OP_CODESEPARATOR offsets found by walking the DEPLOYED code part. */
  deployedCodeSeparators: number[];
  /** Per codeSepIndex slot: the value it must bake, and the value actually
   *  baked in the deployed script. */
  codeSepSlotValues: Array<{
    templateByteOffset: number;
    templateCodeSepIndex: number;
    deployedByteOffset: number;
    expectedBakedValue: number;
    actualBakedValue: number;
  }>;
  violations: Violation[];
}

// ---------------------------------------------------------------------------
// Template-side checks (compiler-internal; no SDK involved)
// ---------------------------------------------------------------------------

/**
 * Check every claim the artifact makes about its OWN script bytes.
 *
 * This half needs no SDK at all — it is the compiler grading itself against
 * a disassembler it did not write. Before this suite, nothing in the repo
 * walked a compiled script and compared the result to `codeSeparatorIndices`
 * (see ../README.md, "What was missing").
 */
export function checkTemplateClaims(artifact: RefArtifact): Violation[] {
  const v: Violation[] = [];
  const script = artifact.script;

  let ops: ScriptOp[];
  try {
    ops = walkScript(script);
  } catch (err) {
    return [{ code: 'T1-template-undecodable', message: `template script does not decode: ${(err as Error).message}` }];
  }
  const boundaries = new Set(ops.map((o) => o.offset));
  const byOffset = new Map(ops.map((o) => [o.offset, o]));

  // --- T2/T3: every declared slot offset is a real, 1-byte OP_0 placeholder
  const placeholders: Array<{ kind: string; label: string; byteOffset: number }> = [];
  for (const s of artifact.constructorSlots ?? []) {
    placeholders.push({ kind: 'constructorSlot', label: s.name ?? `param${s.paramIndex}`, byteOffset: s.byteOffset });
  }
  for (const s of artifact.codeSepIndexSlots ?? []) {
    placeholders.push({ kind: 'codeSepIndexSlot', label: `codeSepIndex=${s.codeSepIndex}`, byteOffset: s.byteOffset });
  }
  for (const p of placeholders) {
    if (!boundaries.has(p.byteOffset)) {
      v.push({
        code: 'T2-slot-not-opcode-boundary',
        message:
          `${p.kind} '${p.label}' declares byteOffset ${p.byteOffset}, which is NOT an opcode ` +
          `boundary in the template script (it lands inside a push or past the end). ` +
          `An off-by-one offset that happens to point at a 0x00 data byte passes a ` +
          `"is the byte 0x00?" check and fails this one.`,
      });
      continue;
    }
    const op = byOffset.get(p.byteOffset)!;
    if (op.opcode !== 0x00 || op.byteLength !== 1) {
      v.push({
        code: 'T3-slot-not-op0',
        message:
          `${p.kind} '${p.label}' at byteOffset ${p.byteOffset} is opcode ` +
          `0x${op.opcode.toString(16).padStart(2, '0')} (${op.byteLength} bytes), expected the ` +
          `1-byte OP_0 placeholder`,
      });
    }
  }

  // --- T4: no two placeholders claim the same byte
  const seen = new Map<number, string>();
  for (const p of placeholders) {
    const prev = seen.get(p.byteOffset);
    if (prev !== undefined) {
      v.push({
        code: 'T4-duplicate-slot-offset',
        message: `byteOffset ${p.byteOffset} is claimed by both ${prev} and ${p.kind} '${p.label}'`,
      });
    }
    seen.set(p.byteOffset, `${p.kind} '${p.label}'`);
  }

  // --- T5: codeSeparatorIndices == the real OP_CODESEPARATOR positions
  const real = ops.filter((o) => o.opcode === 0xab).map((o) => o.offset);
  const declared = artifact.codeSeparatorIndices;
  if (real.length === 0) {
    if (declared !== undefined && declared.length > 0) {
      v.push({
        code: 'T5-codesep-indices-mismatch',
        message: `artifact declares codeSeparatorIndices ${JSON.stringify(declared)} but the script contains no OP_CODESEPARATOR`,
      });
    }
  } else if (declared === undefined) {
    v.push({
      code: 'T5-codesep-indices-missing',
      message: `script contains OP_CODESEPARATOR at ${JSON.stringify(real)} but the artifact declares no codeSeparatorIndices`,
    });
  } else if (declared.length !== real.length || declared.some((x, i) => x !== real[i])) {
    v.push({
      code: 'T5-codesep-indices-mismatch',
      message:
        `artifact declares codeSeparatorIndices ${JSON.stringify(declared)} but walking the ` +
        `template script finds OP_CODESEPARATOR at ${JSON.stringify(real)}. SDKs trim the ` +
        `sighash scriptCode at these offsets — a wrong index signs the wrong subscript and ` +
        `the output cannot be spent.`,
    });
  }

  // --- T6: codeSeparatorIndex is the LAST OP_CODESEPARATOR (06-emit.ts keeps
  //         overwriting it as it emits, so it ends up holding the final one)
  if (real.length === 0) {
    if (artifact.codeSeparatorIndex !== undefined) {
      v.push({
        code: 'T6-codesep-index-mismatch',
        message: `artifact declares codeSeparatorIndex ${artifact.codeSeparatorIndex} but the script contains no OP_CODESEPARATOR`,
      });
    }
  } else if (artifact.codeSeparatorIndex !== real[real.length - 1]) {
    v.push({
      code: 'T6-codesep-index-mismatch',
      message:
        `artifact declares codeSeparatorIndex ${artifact.codeSeparatorIndex}, expected ` +
        `${real[real.length - 1]} (the last real OP_CODESEPARATOR)`,
    });
  }

  // --- T7: every codeSepIndexSlot points at a real codesep
  for (const s of artifact.codeSepIndexSlots ?? []) {
    if (!real.includes(s.codeSepIndex)) {
      v.push({
        code: 'T7-codesep-slot-target-missing',
        message:
          `codeSepIndexSlot at byteOffset ${s.byteOffset} baked codeSepIndex ${s.codeSepIndex}, ` +
          `which is not the offset of any real OP_CODESEPARATOR (${JSON.stringify(real)})`,
      });
    }
  }

  // --- T9 (N-051): every `SIZE(_codePart)` pin is an equality, and every
  //         codePartLenSlot points at a pin's 4-byte length field. A lower
  //         bound (OP_GREATERTHANOREQUAL) lets a spender claim a truncated
  //         code part that ends at a 0x6a inside a baked readonly value.
  for (const o of ops) {
    if (o.opcode !== 0x04) continue;
    const tail = script.slice((o.offset + 5) * 2, (o.offset + 8) * 2);
    if (tail === '81a269' && o.offset > 0 && byOffset.get(o.offset - 1)?.opcode === 0x76) {
      v.push({
        code: 'T9-codepart-pin-lower-bound',
        message: `SIZE(_codePart) pin at byteOffset ${o.offset - 1} is OP_GREATERTHANOREQUAL — a lower bound, not the deployed length`,
      });
    }
  }
  for (const s of artifact.codePartLenSlots ?? []) {
    const push = byOffset.get(s.byteOffset - 1);
    const tail = script.slice((s.byteOffset + 4) * 2, (s.byteOffset + 7) * 2);
    if (push === undefined || push.opcode !== 0x04 || tail !== '819c69') {
      v.push({
        code: 'T9-codepart-len-slot-target',
        message:
          `codePartLenSlot at byteOffset ${s.byteOffset} does not point at the 4-byte length ` +
          `field of an OP_DUP <04 ..> OP_BIN2NUM OP_NUMEQUAL OP_VERIFY pin`,
      });
    }
  }

  // --- T8: slot descriptors agree with the ABI
  const params = artifact.abi?.constructor?.params ?? [];
  for (const s of artifact.constructorSlots ?? []) {
    const p = params[s.paramIndex];
    if (p === undefined) {
      v.push({
        code: 'T8-slot-param-out-of-range',
        message: `constructor slot at byteOffset ${s.byteOffset} has paramIndex ${s.paramIndex} but the ABI declares ${params.length} params`,
      });
      continue;
    }
    if (s.name !== undefined && s.name !== p.name) {
      v.push({
        code: 'T8-slot-name-mismatch',
        message: `constructor slot at byteOffset ${s.byteOffset} is named '${s.name}' but abi.constructor.params[${s.paramIndex}] is '${p.name}'`,
      });
    }
    if (s.type !== undefined && s.type !== p.type) {
      v.push({
        code: 'T8-slot-type-mismatch',
        message: `constructor slot at byteOffset ${s.byteOffset} declares type '${s.type}' but abi.constructor.params[${s.paramIndex}] ('${p.name}') is '${p.type}'`,
      });
    }
    if (s.valueEncoding !== undefined) {
      const wantEncoding = expectedEncodingForAbiType(p.type);
      if (s.valueEncoding !== wantEncoding) {
        v.push({
          code: 'T8-slot-encoding-mismatch',
          message:
            `constructor slot at byteOffset ${s.byteOffset} declares valueEncoding '${s.valueEncoding}' but ` +
            `abi.constructor.params[${s.paramIndex}] ('${p.name}') has type '${p.type}', which encodes as '${wantEncoding}'`,
        });
      }
    }
  }

  return v;
}

/** The `valueEncoding` an ABI param type implies, per the same rule
 *  `slotEncoding()` uses as its pre-descriptor fallback: bigint → scriptnum,
 *  bool → bool, everything else (ByteString/PubKey/Sig/Addr/...) → data. */
function expectedEncodingForAbiType(abiType: string): ValueEncoding {
  if (abiType === 'bigint' || abiType === 'int') return 'scriptnum';
  if (abiType === 'bool' || abiType === 'boolean') return 'bool';
  return 'data';
}

// ---------------------------------------------------------------------------
// Splice
// ---------------------------------------------------------------------------

interface Substitution {
  templateByteOffset: number;
  encodedHex: string;
  slot?: RefConstructorSlot;
  codeSep?: { templateCodeSepIndex: number; bakedValue: number };
}

function slotEncoding(slot: RefConstructorSlot, arg: TypedArg): ValueEncoding {
  if (slot.valueEncoding) return slot.valueEncoding;
  // Pre-descriptor artifacts: fall back to the arg's own type.
  if (arg.type === 'bigint' || arg.type === 'int') return 'scriptnum';
  if (arg.type === 'bool' || arg.type === 'boolean') return 'bool';
  return 'data';
}

/**
 * Build every template substitution.
 *
 * Both kinds replace a 1-byte OP_0, so each one shifts everything after it by
 * `encodedBytes - 1`. codeSepIndex slots are resolved left-to-right because a
 * slot's baked value depends on how much the substitutions BEFORE its target
 * codesep have already expanded the script.
 */
function collectSubstitutions(artifact: RefArtifact, args: TypedArg[]): Substitution[] {
  const subs: Substitution[] = [];

  for (const slot of artifact.constructorSlots ?? []) {
    const arg = args[slot.paramIndex];
    if (arg === undefined) {
      throw new Error(
        `constructor slot '${slot.name ?? slot.paramIndex}' needs args[${slot.paramIndex}] but only ${args.length} were supplied`,
      );
    }
    subs.push({
      templateByteOffset: slot.byteOffset,
      encodedHex: encodeSlotValue(slotEncoding(slot, arg), arg),
      slot,
    });
  }

  const ctorSubs = [...subs];
  const resolved: Array<{ templateByteOffset: number; bakedValue: number }> = [];
  for (const cs of [...(artifact.codeSepIndexSlots ?? [])].sort((a, b) => a.byteOffset - b.byteOffset)) {
    let shift = 0;
    for (const c of ctorSubs) {
      if (c.templateByteOffset < cs.codeSepIndex) shift += c.encodedHex.length / 2 - 1;
    }
    for (const prev of resolved) {
      if (prev.templateByteOffset < cs.codeSepIndex) {
        shift += encodeScriptNumber(BigInt(prev.bakedValue)).length / 2 - 1;
      }
    }
    const bakedValue = cs.codeSepIndex + shift;
    resolved.push({ templateByteOffset: cs.byteOffset, bakedValue });
    subs.push({
      templateByteOffset: cs.byteOffset,
      encodedHex: encodeScriptNumber(BigInt(bakedValue)),
      codeSep: { templateCodeSepIndex: cs.codeSepIndex, bakedValue },
    });
  }

  subs.sort((a, b) => a.templateByteOffset - b.templateByteOffset);
  return subs;
}

/**
 * Independently derive the deployed code part and every vertical claim about
 * it. `violations` is empty exactly when the artifact and the derived bytes
 * agree on every checked invariant.
 */
export function deriveVertical(artifact: RefArtifact, args: TypedArg[]): VerticalDerivation {
  const violations = checkTemplateClaims(artifact);

  // collectSubstitutions/encodeSlotValue throw when a slot's declared
  // valueEncoding disagrees with the ABI arg type it is fed (e.g. a
  // 'scriptnum' slot handed a ByteString arg) — deliberately, per
  // encode.ts's encodeSlotValue: taking the encoding class from the artifact
  // makes the compiler's declaration load-bearing. Left uncaught, that throw
  // used to escape all the way out of the runner/generator as a crash instead
  // of a reported violation, silently skipping generate.ts's "refusing to
  // write a golden" gate for exactly the artifacts that most need it.
  let subs: Substitution[];
  try {
    subs = collectSubstitutions(artifact, args);
  } catch (err) {
    violations.push({ code: 'D0-encode-failed', message: `failed to encode a constructor slot: ${(err as Error).message}` });
    return {
      contractName: artifact.contractName,
      codePartHex: artifact.script,
      codePartByteLength: artifact.script.length / 2,
      slots: [],
      templateCodeSeparators: [],
      deployedCodeSeparators: [],
      codeSepSlotValues: [],
      violations,
    };
  }

  // Splice descending so earlier offsets stay valid.
  let code = artifact.script;
  for (const s of [...subs].sort((a, b) => b.templateByteOffset - a.templateByteOffset)) {
    const at = s.templateByteOffset * 2;
    code = code.slice(0, at) + s.encodedHex + code.slice(at + 2);
  }

  // N-051: each deploy-time length field holds the deployed code-part length,
  // 4 bytes little-endian, overwritten in place (fixed width: no offset moves).
  for (const s of artifact.codePartLenSlots ?? []) {
    const len = code.length / 2;
    let le = '';
    for (let i = 0; i < 4; i++) le += ((len >>> (8 * i)) & 0xff).toString(16).padStart(2, '0');
    let expand = 0;
    for (const x of subs) if (x.templateByteOffset < s.byteOffset) expand += x.encodedHex.length / 2 - 1;
    const at = (s.byteOffset + expand) * 2;
    code = code.slice(0, at) + le + code.slice(at + 8);
  }

  // Resolve every substitution's deployed offset.
  const slots: ResolvedRefSlot[] = [];
  const codeSepSlotValues: VerticalDerivation['codeSepSlotValues'] = [];
  const deployedOffsetOfTemplate = new Map<number, number>();
  let shift = 0;
  for (const s of subs) {
    deployedOffsetOfTemplate.set(s.templateByteOffset, s.templateByteOffset + shift);
    shift += s.encodedHex.length / 2 - 1;
  }

  const templateCodeSeparators = (() => {
    try {
      return findCodeSeparators(artifact.script);
    } catch {
      return [];
    }
  })();

  // Deployed offset of an arbitrary template offset = itself plus the
  // expansion of every substitution that precedes it.
  const shiftBefore = (templateOffset: number): number => {
    let acc = 0;
    for (const s of subs) if (s.templateByteOffset < templateOffset) acc += s.encodedHex.length / 2 - 1;
    return acc;
  };

  let deployedOps: ScriptOp[];
  try {
    deployedOps = walkScript(code);
  } catch (err) {
    violations.push({
      code: 'D1-deployed-undecodable',
      message: `the spliced code part does not decode: ${(err as Error).message}`,
    });
    return {
      contractName: artifact.contractName,
      codePartHex: code,
      codePartByteLength: code.length / 2,
      slots: [],
      templateCodeSeparators,
      deployedCodeSeparators: [],
      codeSepSlotValues: [],
      violations,
    };
  }
  const deployedBoundaries = new Set(deployedOps.map((o) => o.offset));
  const deployedByOffset = new Map(deployedOps.map((o) => [o.offset, o]));

  for (const s of subs) {
    const at = deployedOffsetOfTemplate.get(s.templateByteOffset)!;

    if (!deployedBoundaries.has(at)) {
      violations.push({
        code: 'D2-slot-not-opcode-boundary',
        message: `substitution from template offset ${s.templateByteOffset} lands at deployed offset ${at}, which is not an opcode boundary`,
      });
      continue;
    }
    const op = deployedByOffset.get(at)!;

    if (op.byteLength !== s.encodedHex.length / 2) {
      violations.push({
        code: 'D2-slot-length-mismatch',
        message:
          `substitution at deployed offset ${at} occupies ${op.byteLength} bytes but the ` +
          `encoded value is ${s.encodedHex.length / 2} bytes — the slot payload does not fill its slot`,
      });
    }

    if (s.slot) {
      const arg = args[s.slot.paramIndex]!;
      const enc = slotEncoding(s.slot, arg);
      const wantPushed = expectedPushedHex(enc, arg);

      // SEMANTIC pin: what does this slot actually push at spend time?
      if (op.pushedHex !== wantPushed) {
        violations.push({
          code: 'D2-slot-pushes-wrong-value',
          message:
            `constructor slot '${s.slot.name ?? s.slot.paramIndex}' at deployed offset ${at} ` +
            `pushes 0x${op.pushedHex || '<empty>'} but the deploy-time value is ` +
            `0x${wantPushed || '<empty>'}. (OP_0 pushes the EMPTY item; a 1-byte 0x00 must be ` +
            `the direct push '0100'.)`,
        });
      }

      // The compiler's declared fixed layout, checked against real bytes.
      if (s.slot.fixedPushHeaderBytes !== undefined && op.headerBytes !== s.slot.fixedPushHeaderBytes) {
        violations.push({
          code: 'D3-fixed-header-mismatch',
          message:
            `slot '${s.slot.name ?? s.slot.paramIndex}' declares fixedPushHeaderBytes ` +
            `${s.slot.fixedPushHeaderBytes} but the deployed push header is ${op.headerBytes} bytes`,
        });
      }
      if (s.slot.fixedValueByteLength !== undefined) {
        const actualValueBytes = op.pushedHex.length / 2;
        if (actualValueBytes !== s.slot.fixedValueByteLength) {
          violations.push({
            code: 'D3-fixed-length-mismatch',
            message:
              `slot '${s.slot.name ?? s.slot.paramIndex}' declares fixedValueByteLength ` +
              `${s.slot.fixedValueByteLength} but the deployed slot carries ${actualValueBytes} value bytes`,
          });
        }
      }

      slots.push({
        name: s.slot.name ?? artifact.abi.constructor.params[s.slot.paramIndex]?.name ?? `param${s.slot.paramIndex}`,
        paramIndex: s.slot.paramIndex,
        templateByteOffset: s.templateByteOffset,
        byteOffset: at,
        byteLength: op.byteLength,
        headerBytes: op.headerBytes,
        valueByteOffset: at + op.headerBytes,
        valueByteLength: op.pushedHex.length / 2,
        encoding: enc,
        pushedHex: op.pushedHex,
      });
    }

    if (s.codeSep) {
      const wantDeployedCodesep = s.codeSep.templateCodeSepIndex + shiftBefore(s.codeSep.templateCodeSepIndex);
      const actualBaked = Number(decodeScriptNumber(op.pushedHex));
      codeSepSlotValues.push({
        templateByteOffset: s.templateByteOffset,
        templateCodeSepIndex: s.codeSep.templateCodeSepIndex,
        deployedByteOffset: at,
        expectedBakedValue: wantDeployedCodesep,
        actualBakedValue: actualBaked,
      });
      if (actualBaked !== wantDeployedCodesep) {
        violations.push({
          code: 'D5-baked-codesep-index-wrong',
          message:
            `the codeSepIndex slot at deployed offset ${at} bakes ${actualBaked}, but the ` +
            `OP_CODESEPARATOR it refers to sits at deployed byte offset ${wantDeployedCodesep}`,
        });
      }
    }
  }

  // --- D4: deployed codesep positions == template positions shifted by the splice
  const deployedCodeSeparators = deployedOps.filter((o) => o.opcode === 0xab).map((o) => o.offset);
  const expectedDeployed = templateCodeSeparators.map((t) => t + shiftBefore(t));
  if (
    deployedCodeSeparators.length !== expectedDeployed.length ||
    deployedCodeSeparators.some((x, i) => x !== expectedDeployed[i])
  ) {
    violations.push({
      code: 'D4-deployed-codesep-shift-wrong',
      message:
        `after splicing, OP_CODESEPARATOR is at ${JSON.stringify(deployedCodeSeparators)} but the ` +
        `artifact's indices ${JSON.stringify(templateCodeSeparators)} shifted by the constructor-arg ` +
        `expansion predict ${JSON.stringify(expectedDeployed)}`,
    });
  }

  return {
    contractName: artifact.contractName,
    codePartHex: code,
    codePartByteLength: code.length / 2,
    slots,
    templateCodeSeparators,
    deployedCodeSeparators,
    codeSepSlotValues,
    violations,
  };
}

// ---------------------------------------------------------------------------
// Checking an EXTERNAL (tier-produced) script against an already-good derivation
// ---------------------------------------------------------------------------

/**
 * Check a tier's deployed script bytes against a KNOWN-GOOD derivation of the
 * same artifact + args (`derived.violations` must already be empty), without
 * re-deriving anything: walk `tierHex` and ask, at each of `derived.slots`'
 * OWN deployed byte offsets, whether it pushes the same value the good
 * derivation says that slot must push.
 *
 * This is the semantic half of the vertical pin applied to bytes that did NOT
 * come from `deriveVertical` itself — e.g. a hypothetical SDK's own splice —
 * so it can name the fault (`D2-slot-pushes-wrong-value`, naming the slot)
 * even when the two byte strings were produced by entirely different splice
 * algorithms and may disagree on total length.
 */
export function checkDeployedAgainstDerivation(derived: VerticalDerivation, tierHex: string): Violation[] {
  const v: Violation[] = [];
  let ops: ScriptOp[];
  try {
    ops = walkScript(tierHex);
  } catch (err) {
    return [{ code: 'D1-deployed-undecodable', message: `tier script does not decode: ${(err as Error).message}` }];
  }
  const boundaries = new Set(ops.map((o) => o.offset));
  const byOffset = new Map(ops.map((o) => [o.offset, o]));

  for (const s of derived.slots) {
    if (!boundaries.has(s.byteOffset)) {
      v.push({
        code: 'D2-slot-not-opcode-boundary',
        message: `constructor slot '${s.name}' expected at deployed offset ${s.byteOffset} is not an opcode boundary in the tier script`,
      });
      continue;
    }
    const op = byOffset.get(s.byteOffset)!;
    if (op.pushedHex !== s.pushedHex) {
      v.push({
        code: 'D2-slot-pushes-wrong-value',
        message:
          `constructor slot '${s.name}' at deployed offset ${s.byteOffset} pushes ` +
          `0x${op.pushedHex || '<empty>'} but the deploy-time value is 0x${s.pushedHex || '<empty>'}.`,
      });
    }
  }

  return v;
}
