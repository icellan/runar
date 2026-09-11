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
  // byte-identical to the pre-fix build. The digests below are sha256 of the
  // fold-OFF script hex, captured from the build immediately before this
  // change; a moved byte anywhere else in the state-type tables breaks one.
  //
  // `RabinSig` / `RabinPubKey` are the load-bearing entries: they are the
  // types this change must NOT touch.
  // -------------------------------------------------------------------------
  describe('controls: every other state type is byte-unchanged', () => {
    const TERMINAL_PINS: Record<string, string> = {
      bigint: 'e258b5415ff46c5786dc1e665a3132eee36e784c485afaf6f96d500b386e2ddd',
      boolean: '807484bded138b4fd1494f01d8c58ef12289529d726c2c93815078167ad8de26',
      RabinSig: 'e258b5415ff46c5786dc1e665a3132eee36e784c485afaf6f96d500b386e2ddd',
      RabinPubKey: 'e258b5415ff46c5786dc1e665a3132eee36e784c485afaf6f96d500b386e2ddd',
      PubKey: 'cfa28ff1c0308373ad9c17057fdc4fcfdb9ed8c6ffe409ee3be03f90d55a0d1f',
      Sha256: '62e80b36d93a8f86ef70c4f67af5968128767d2be4a8efb1e5437c16e34feba9',
      Addr: 'a48253052aa95a1e06b380b91f948645436d587ff8a1d43c557b7daecfe30d2d',
    };

    const WRITE_PINS: Record<string, string> = {
      ByteString: 'bccc912ffd7cfdd944c37162ac3a5561f95c0fe464a1d0dcff0ed571eb82d624',
      PubKey: 'a2bcebd69d25e711ebf834c4d848d2cf2961453b063b7b7280060d249f8110ba',
      bigint: 'a84c9329687c21088de066e0021c2aa106acc612bc0b0a53a0c206471e69da08',
      boolean: '958fdff43c43bdbe1ad8511ea5685e37b2440be8b394bf7bfc95680a0ad418c4',
      RabinSig: 'a84c9329687c21088de066e0021c2aa106acc612bc0b0a53a0c206471e69da08',
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
        'd839d16658e2556ea82fae143338fb4c0d4de25c58a91347e2823e313b9abb71',
      );
    });
  });
});
