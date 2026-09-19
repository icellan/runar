/**
 * `Sig` and `SigHashPreimage` state fields are push-data-framed variable-length
 * state — exactly like `ByteString` — on BOTH the write and the read side.
 *
 * Three separate defects converged on the same type list:
 *
 *  1. WRITE != READ inside one script. `lowerAddOutput` /
 *     `lowerComputeStateBytes` tested the literal string `'ByteString'` before
 *     emitting `emitPushDataEncode`, while the reader
 *     (`lowerDeserializeState`) push-data-DECODES every variable-length type.
 *     A mutating method therefore wrote the continuation state RAW and the
 *     next spend's reader took the DER `0x30` byte as a length-48 push. Deploy
 *     succeeded, the first spend succeeded, and the UTXO that spend created
 *     was unspendable — fund loss.
 *
 *  2. `computeUsesCodePart` filtered mutable properties on `'ByteString'`
 *     alone, so for a TERMINAL method reading a mutable `Sig` field
 *     `usesCodePart` stayed false, `lowerDeserializeState` hit its
 *     `!stackMap.has('_codePart')` shortcut and pushed NO mutable property, and
 *     every `load_prop` fell through to the DEPLOY-TIME constructor
 *     placeholder. (Fixed for the Rust tier only in bc6cf19a / R-015.)
 *
 *  3. TypeScript could not compile such a contract at all —
 *     `lowerDeserializeState`'s size table had no `Sig` / `SigHashPreimage`
 *     case and threw `deserialize_state: unsupported type`, while
 *     `02-validate.ts` explicitly permits both as state-property types. A
 *     1-vs-6 frontend-parity break.
 *
 * The target encoding is settled by the deploy-time writer: all seven SDKs'
 * `encodeStateValue` (packages/runar-sdk/src/state.ts and peers) enumerate the
 * fixed-size types (PubKey, Addr, Ripemd160, Sha256, Point, P256Point,
 * P384Point) and push-data-frame everything else, so `Sig` and
 * `SigHashPreimage` carry a length prefix that only the variable-length read
 * path can decode.
 *
 * The lock used throughout: a `Sig` (or `SigHashPreimage`) state field must
 * lower BYTE-IDENTICALLY to the same contract with a `ByteString` field — that
 * path was already correct, so the assertion discriminates between the two
 * lowerings rather than restating something true of every contract. `RabinSig`
 * and `RabinPubKey` are the negative controls: bigint aliases stored as a
 * fixed 8-byte NUM2BIN word, which must NOT join the variable-length set.
 *
 * Executed (rather than merely lowered) coverage of the same fix lives in
 * `packages/runar-testing/src/__tests__/sig-state-varlen-vm.test.ts`, which
 * deploys and spends these contracts on the real `@bsv/sdk` Script VM.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { parse } from '../passes/01-parse.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import { compile } from '../index.js';
import type { StackProgram } from '../ir/index.js';

/** Mutating method — drives the state-continuation WRITE path (defect 1). */
function mutatingSource(propType: string): string {
  return `import { StatefulSmartContract } from 'runar-lang';
class VarLenStateWrite extends StatefulSmartContract {
  tag: ${propType};
  constructor(tag: ${propType}) { super(tag); this.tag = tag; }
  public update(next: ${propType}) { this.tag = next; }
}`;
}

/** Terminal method reading the field — drives `computeUsesCodePart` (defect 2). */
function terminalSource(propType: string): string {
  return `import { StatefulSmartContract, assert, len } from 'runar-lang';
class VarLenStateRead extends StatefulSmartContract {
  tag: ${propType};
  constructor(tag: ${propType}) { super(tag); this.tag = tag; }
  public check(expected: bigint) { assert(len(this.tag) === expected); }
}`;
}

/** Terminal read that compares the field against a same-typed parameter. */
function terminalSameTypeSource(propType: string): string {
  return `import { StatefulSmartContract, assert } from 'runar-lang';
class VarLenStateRead extends StatefulSmartContract {
  tag: ${propType};
  constructor(tag: ${propType}) { super(tag); this.tag = tag; }
  public check(expected: ${propType}) { assert(this.tag === expected); }
}`;
}

function compileToStack(source: string): StackProgram {
  const parsed = parse(source);
  if (!parsed.contract) {
    throw new Error(`parse failed: ${parsed.errors.map(e => e.message).join('; ')}`);
  }
  return lowerToStack(lowerToANF(parsed.contract));
}

function hexOf(source: string, fileName: string): string {
  const result = compile(source, { fileName, disableConstantFolding: true });
  if (!result.success || typeof result.scriptHex !== 'string') {
    throw new Error(`compile failed: ${result.diagnostics.map(d => d.message).join('; ')}`);
  }
  return result.scriptHex.toLowerCase();
}

function abiUsesCodePart(source: string, fileName: string, method: string): boolean {
  const result = compile(source, { fileName, disableConstantFolding: true });
  if (!result.success || !result.artifact) {
    throw new Error(`compile failed: ${result.diagnostics.map(d => d.message).join('; ')}`);
  }
  const entry = result.artifact.abi.methods.find(m => m.name === method);
  if (!entry) throw new Error(`method '${method}' missing from the ABI`);
  return entry.usesCodePart === true;
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

const VAR_LEN_TYPES = ['Sig', 'SigHashPreimage'] as const;

const WRITE_FILE = 'VarLenStateWrite.runar.ts';
const READ_FILE = 'VarLenStateRead.runar.ts';

describe('Sig / SigHashPreimage are push-data-framed variable-length state', () => {
  // -------------------------------------------------------------------------
  // Defect 3 — the TS tier could not lower these contracts at all.
  // -------------------------------------------------------------------------
  describe('defect 3: the TypeScript tier lowers them (frontend parity)', () => {
    for (const t of VAR_LEN_TYPES) {
      it(`lowers a mutating method on a ${t} state field`, () => {
        expect(() => compileToStack(mutatingSource(t))).not.toThrow();
      });

      it(`lowers a terminal read of a ${t} state field`, () => {
        expect(() => compileToStack(terminalSource(t))).not.toThrow();
      });

      it(`compiles a ${t} state field end-to-end to script hex`, () => {
        expect(() => hexOf(mutatingSource(t), WRITE_FILE)).not.toThrow();
      });
    }
  });

  // -------------------------------------------------------------------------
  // Defect 1 — the continuation WRITE must push-data-frame the value, so the
  // READ path in the next spend can decode it.
  // -------------------------------------------------------------------------
  describe('defect 1: the continuation write matches the read', () => {
    for (const t of VAR_LEN_TYPES) {
      it(`a mutating method on a ${t} field lowers identically to ByteString`, () => {
        expect(hexOf(mutatingSource(t), WRITE_FILE)).toBe(
          hexOf(mutatingSource('ByteString'), WRITE_FILE),
        );
      });
    }
  });

  // -------------------------------------------------------------------------
  // Defect 2 — a TERMINAL method reading the field needs `_codePart`.
  // -------------------------------------------------------------------------
  describe('defect 2: a terminal read takes the _codePart implicit parameter', () => {
    it('control: a ByteString field already does', () => {
      const program = compileToStack(terminalSource('ByteString'));
      expect(program.methods.find(m => m.name === 'check')?.usesCodePart).toBe(true);
      expect(abiUsesCodePart(terminalSource('ByteString'), READ_FILE, 'check')).toBe(true);
    });

    for (const t of VAR_LEN_TYPES) {
      it(`a ${t} field sets usesCodePart in the Stack IR`, () => {
        const program = compileToStack(terminalSource(t));
        expect(program.methods.find(m => m.name === 'check')?.usesCodePart).toBe(true);
      });

      it(`a ${t} field advertises _codePart in the compiled ABI`, () => {
        expect(abiUsesCodePart(terminalSource(t), READ_FILE, 'check')).toBe(true);
      });

      it(`a terminal read of a ${t} field lowers identically to ByteString`, () => {
        expect(hexOf(terminalSource(t), READ_FILE)).toBe(
          hexOf(terminalSource('ByteString'), READ_FILE),
        );
      });
    }

    it('negative control: a terminal read of a RabinSig field does NOT need _codePart', () => {
      // Fixed-width state is extracted at a compile-time offset, so the
      // deserializer never needs the code part. If this ever flipped to true
      // the "identical to ByteString" assertions above would stop
      // discriminating between the two lowerings.
      const program = compileToStack(terminalSameTypeSource('RabinSig'));
      expect(program.methods.find(m => m.name === 'check')?.usesCodePart).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Controls — every state type OTHER than Sig / SigHashPreimage must be
  // byte-identical to the Sig/SigHashPreimage build. The digests below are
  // sha256 of the fold-OFF script hex; a moved byte anywhere else in the
  // state-type tables breaks one. They were re-stamped once, for W1's 3-byte
  // zero-pad before the auto-injected sighash-type pin's OP_BIN2NUM — a change
  // that hits EVERY stateful script equally, which is why the equalities the
  // controls encode (bigint == RabinSig == RabinPubKey, and ByteString ==
  // curve-point-state-width's own ByteString digest) all survive it.
  //
  // `RabinSig` / `RabinPubKey` are the load-bearing entries: they are the
  // types this change must NOT touch.
  // -------------------------------------------------------------------------
  describe('controls: every other state type is byte-unchanged', () => {
    const TERMINAL_PINS: Record<string, string> = {
      bigint: '785d8f69691b7f96628b34ff5221ba1a8326aeb83229cc1aa8b6ca6b48870a21',
      // W3 / BoolBamboozle re-stamp: `check(expected: boolean)` is a public
      // method with a `boolean` parameter, so its entry now carries the
      // 9-byte ABI-domain gate. The other six rows are unmoved, which is the
      // point of the control — the gate is scoped to boolean PARAMS and does
      // not touch state encoding for any type, boolean included.
      boolean: '9fec1ff6a7c3f3fcb6b8dd554d1a61008589427be8ffa6849da94dd561620e3a',
      RabinSig: '785d8f69691b7f96628b34ff5221ba1a8326aeb83229cc1aa8b6ca6b48870a21',
      RabinPubKey: '785d8f69691b7f96628b34ff5221ba1a8326aeb83229cc1aa8b6ca6b48870a21',
      PubKey: '006609c7f3c136bea9d4396af412100effebb331049e59c9b3fe0bc2ecbb0e71',
      Sha256: '8552b481afb50361fbd43f0a58ad187dde568ab29d09066b6ec0842ea4fb9a5b',
      Addr: 'ae21dcf5b719b3d82ef42d593d8aa802b802e01de900219a9f15523af71ccc90',
    };

    const WRITE_PINS: Record<string, string> = {
      ByteString: '9868c0d2a60553456bfe622a313fc88bc57379a0ab2c96221eda29bb2da3a3ad',
      PubKey: 'c804a19a59c6632d248ab4db5805ac742541c5b786b889f5cf78c2424e0d8b9c',
      bigint: 'bd83c832749091ccf375b763df0977d39bcbd62eff0f7d5544d3a19e2de6501f',
      // W3 / BoolBamboozle re-stamp: `update(next: boolean)` takes a `boolean`
      // parameter and so gains the 9-byte ABI-domain gate. `bigint` and
      // `RabinSig` still agree with each other, which is the equality this
      // table exists to defend.
      boolean: '12f92c710002e4a46d07b4b7436f850cbb82f7400637992795b12bc7e59a86f2',
      RabinSig: 'bd83c832749091ccf375b763df0977d39bcbd62eff0f7d5544d3a19e2de6501f',
    };

    for (const [type, digest] of Object.entries(TERMINAL_PINS)) {
      it(`terminal read of a ${type} field is byte-unchanged`, () => {
        expect(sha256(hexOf(terminalSameTypeSource(type), READ_FILE))).toBe(digest);
      });
    }

    for (const [type, digest] of Object.entries(WRITE_PINS)) {
      it(`mutating method on a ${type} field is byte-unchanged`, () => {
        expect(sha256(hexOf(mutatingSource(type), WRITE_FILE))).toBe(digest);
      });
    }

    it('the ByteString control read path is byte-unchanged', () => {
      expect(sha256(hexOf(terminalSource('ByteString'), READ_FILE))).toBe(
        '91b84e4bb625d0ac7c83dc095de0f51932e3664c44062a0f7ee1caed747d6a43',
      );
    });
  });
});
