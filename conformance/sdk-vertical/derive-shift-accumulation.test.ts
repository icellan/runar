// ---------------------------------------------------------------------------
// conformance/sdk-vertical/derive-shift-accumulation.test.ts
// ---------------------------------------------------------------------------
//
// Coverage for the codeSepIndex shift-accumulation loop in
// `collectSubstitutions` (reference/derive.ts, the `for (const cs of ...
// codeSepIndexSlots)` block) and its seven SDK counterparts, driven by a
// HAND-BUILT artifact of a shape the compiler can no longer emit.
//
// Why a hand-built artifact:
//
//   R-010 (c2846d87, "authenticate `_codePart` against the executing script")
//   moved code-separator emission out of `lowerCheckPreimage` and into the
//   emitter, which prepends `OP_NOP, OP_CODESEPARATOR` at byte offsets 0 and 1
//   of any contract in which a public method uses `_codePart`
//   (06-emit.ts:552-553). `codeSepIndexSlots` are emitted only by the
//   variable-length state deserializer (05-stack-lower.ts:3639), which runs
//   only when `_codePart` is on the stack — which is exactly the condition that
//   puts the separator at offset 1. So every slot a current compiler can emit
//   targets offset 1, which precedes every constructor slot, and the
//   accumulated shift is always 0: no fixture reaches the loop's interesting
//   path any more (see vertical-pins.test.ts, describe P0-1).
//
//   The loop is not dead code, though. It ships in all seven SDKs, and it is
//   what a pre-R-010 artifact — one compiled before c2846d87, or a contract
//   already deployed on-chain and being re-derived — still needs. Deleting it
//   is a separate decision; leaving it UNTESTED is not an option, because the
//   failure mode is silent: a wrong baked index signs the wrong subscript and
//   the output cannot be spent.
//
// The artifact below reproduces the pre-R-010 layout (per-method separators
// well inside the script, preceded by a constructor slot) and pins the two
// baked values against numbers computed BY HAND in the comments, so the test
// fails if the loop stops accumulating rather than merely disagreeing with
// itself.
// ---------------------------------------------------------------------------

import { describe, expect, it } from 'vitest';

import { deriveVertical, type RefArtifact } from './reference/derive.js';
import { encodePushData, encodeScriptNumber, type TypedArg } from './reference/encode.js';

// --- Synthetic template layout ---------------------------------------------
//
//   @0            OP_0                    constructor slot 'tag' (ByteString)
//   @1 .. @741    OP_1 filler
//   @742          OP_CODESEPARATOR        separator A
//   @743          OP_0                    codeSepIndexSlot -> A
//   @744 .. @999  OP_1 filler
//   @1000         OP_CODESEPARATOR        separator B
//   @1001         OP_0                    codeSepIndexSlot -> B
//   @1002         OP_1 filler
//
// 742 is the value the pre-R-010 `codesep-tag-zero` golden actually carried
// (its `codeSeparatorIndices` were [6, 742, 1471] before c2846d87), so this is
// a real historical shape, not an invented one.

const SEP_A = 742;
const SEP_B = 1000;

const OP_0 = '00';
const OP_1 = '51';
const OP_CODESEPARATOR = 'ab';

function buildTemplate(): string {
  let hex = OP_0; // @0 — ctor slot
  hex += OP_1.repeat(SEP_A - 1); // @1 .. @741
  hex += OP_CODESEPARATOR; // @742
  hex += OP_0; // @743 — codesep slot A
  hex += OP_1.repeat(SEP_B - (SEP_A + 2)); // @744 .. @999
  hex += OP_CODESEPARATOR; // @1000
  hex += OP_0; // @1001 — codesep slot B
  hex += OP_1; // @1002
  return hex;
}

const SCRIPT = buildTemplate();

const ARTIFACT: RefArtifact = {
  contractName: 'PreR010CodeSepShape',
  parentClass: 'StatefulSmartContract',
  script: SCRIPT,
  abi: { constructor: { params: [{ name: 'tag', type: 'ByteString' }] } },
  constructorSlots: [
    { paramIndex: 0, byteOffset: 0, name: 'tag', type: 'ByteString', valueEncoding: 'data' },
  ],
  codeSepIndexSlots: [
    { byteOffset: SEP_A + 1, codeSepIndex: SEP_A },
    { byteOffset: SEP_B + 1, codeSepIndex: SEP_B },
  ],
  codeSeparatorIndex: SEP_B,
  codeSeparatorIndices: [SEP_A, SEP_B],
};

// 3 raw bytes -> `03 aa bb cc`, a 4-byte push replacing a 1-byte OP_0, so this
// arg expands the script by 3 bytes at offset 0.
const ARGS: TypedArg[] = [{ type: 'ByteString', value: 'aabbcc' }];

// Hand-computed expectations.
//
//   ctor slot @0        encodes to 4 bytes -> +3
//   slot A targets 742: only the ctor slot precedes 742          -> 742 + 3 = 745
//   baked 745 encodes as `02 e9 02` (3 bytes) -> +2
//   slot B targets 1000: ctor slot (+3) and slot A's own bake (+2) precede it
//                                                                -> 1000 + 5 = 1005
const EXPECTED_A = 745;
const EXPECTED_B = 1005;

describe('derive.ts shift accumulation (pre-R-010 artifact shape the compiler can no longer emit)', () => {
  it('the fixture is well formed: 4-byte ctor push, 3-byte bake for slot A', () => {
    // Guards the hand-computed constants above against a change in the
    // encoders: if either of these moves, EXPECTED_A/EXPECTED_B are stale and
    // the arithmetic below must be redone rather than re-derived from the
    // code under test.
    expect(encodePushData('aabbcc')).toBe('03aabbcc');
    expect(encodeScriptNumber(BigInt(EXPECTED_A)).length / 2).toBe(3);
    expect(SCRIPT.length / 2).toBe(SEP_B + 3);
  });

  it('accumulates the constructor-slot expansion into the first baked index', () => {
    const derived = deriveVertical(ARTIFACT, ARGS);
    expect(derived.violations).toEqual([]);
    expect(derived.codeSepSlotValues[0]).toMatchObject({
      templateByteOffset: SEP_A + 1,
      templateCodeSepIndex: SEP_A,
      expectedBakedValue: EXPECTED_A,
      actualBakedValue: EXPECTED_A,
    });
  });

  it('accumulates a PRECEDING codesep slot bake into the second baked index', () => {
    // This is the half no constructor-slot-only fixture can reach: slot B's
    // shift includes the expansion of slot A's OWN baked push, not just the
    // constructor args.
    const derived = deriveVertical(ARTIFACT, ARGS);
    expect(derived.violations).toEqual([]);
    expect(derived.codeSepSlotValues[1]).toMatchObject({
      templateByteOffset: SEP_B + 1,
      templateCodeSepIndex: SEP_B,
      expectedBakedValue: EXPECTED_B,
      actualBakedValue: EXPECTED_B,
    });
  });

  it('each baked index equals the deployed byte offset of the separator it names', () => {
    // The point of the whole mechanism, stated end to end: after the splice,
    // the number baked into the script must be where the OP_CODESEPARATOR
    // actually landed. `deployedCodeSeparators` is found by walking the
    // spliced bytes, so this cross-checks the loop against a disassembler
    // rather than against itself.
    const derived = deriveVertical(ARTIFACT, ARGS);
    expect(derived.violations).toEqual([]);
    expect(derived.deployedCodeSeparators).toEqual([EXPECTED_A, EXPECTED_B]);
    expect(derived.codeSepSlotValues.map((v) => v.actualBakedValue)).toEqual([EXPECTED_A, EXPECTED_B]);
  });

  it('isolates the codesep-slot half of the accumulation when the ctor arg does not expand', () => {
    // Same artifact, ctor arg `0x05` — MINIMALDATA-collapsed to the single
    // opcode OP_5, so the constructor slot contributes NO shift at all. Slot A
    // therefore bakes its template index unchanged, while slot B still moves,
    // by exactly the 2 bytes slot A's own baked push (`02 e6 02`) added ahead
    // of it. A tier that accumulated only constructor slots and ignored
    // previously resolved codesep slots passes the shifted case above by luck
    // and fails here.
    const derived = deriveVertical(ARTIFACT, [{ type: 'ByteString', value: '05' }]);
    expect(derived.violations).toEqual([]);
    expect(encodeScriptNumber(BigInt(SEP_A)).length / 2).toBe(3); // 742 -> `02 e6 02`
    expect(derived.codeSepSlotValues.map((v) => v.actualBakedValue)).toEqual([SEP_A, SEP_B + 2]);
    expect(derived.deployedCodeSeparators).toEqual([SEP_A, SEP_B + 2]);
  });
});
