/**
 * `RabinSig` / `RabinPubKey` are `bigint` ALIASES. A mutable one is stored in
 * the state section as a bare 8-byte OP_NUM2BIN word — on BOTH sides.
 *
 * This tier has been right since `31276a06`, which widened the writer AND the
 * reader together. `e06f8c2c` then widened only Go's reader, and Rust, Python,
 * Ruby and Java followed Go — five tiers whose state SERIALIZER tested the
 * literal `bigint` while their `isNumericStateType` peer (and the deserialize
 * size table, and the fixed state-section length) already said 8.
 *
 * That is the same writer/reader split as `Sig` (6dc1979b), with the same fund
 * loss: a writer that emits a value's MINIMAL script-number encoding into a
 * section the reader splits at a fixed 8 bytes builds, for essentially every
 * real value, a continuation its own script cannot re-read. Deploy succeeds,
 * the first spend succeeds, and the UTXO that spend creates is dead.
 *
 * This file pins the reference so the convergence cannot be "fixed" backwards
 * by narrowing TypeScript to the four-tier shape. The cross-tier half lives in
 * `cross-compiler.test.ts` ("mutable Rabin state is a fixed 8-byte word in all
 * 7 tiers"), which lowers this same ANF through every backend.
 *
 * NOT settled here: whether the Rabin types should ultimately be 8-byte numeric
 * or push-data framed. The SDK's `serializeState` frames them
 * (`runar-sdk/src/__tests__/state-curve-point-width.test.ts`), a third encoding
 * that disagrees with all seven compilers' readers. That decision moves all
 * seven compilers together; the invariant asserted here — writer agrees with
 * its own reader — holds under either answer.
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/** Mutating method, implicit continuation — the compute-state-bytes writer. */
function writeSource(propType: string): string {
  return `import { StatefulSmartContract } from 'runar-lang';
class RabinStateWrite extends StatefulSmartContract {
  tag: ${propType};
  constructor(tag: ${propType}) { super(tag); this.tag = tag; }
  public update(next: ${propType}): void { this.tag = next; }
}`;
}

/** Mutating method with an EXPLICIT addOutput — the add-output writer. */
function addOutputSource(propType: string): string {
  return `import { StatefulSmartContract } from 'runar-lang';
class RabinStateAddOutput extends StatefulSmartContract {
  tag: ${propType};
  constructor(tag: ${propType}) { super(tag); this.tag = tag; }
  public update(next: ${propType}): void { this.tag = next; this.addOutput(1000n, next); }
}`;
}

const SHAPES = [
  { label: 'implicit continuation', build: writeSource, file: 'RabinStateWrite.runar.ts' },
  { label: 'explicit addOutput', build: addOutputSource, file: 'RabinStateAddOutput.runar.ts' },
] as const;

const RABIN_TYPES = ['RabinSig', 'RabinPubKey'] as const;

function compiled(source: string, fileName: string): { hex: string; asm: string } {
  const result = compile(source, { fileName, disableConstantFolding: true });
  if (!result.success || typeof result.scriptHex !== 'string') {
    throw new Error(`compile failed: ${result.diagnostics.map(d => d.message).join('; ')}`);
  }
  return { hex: result.scriptHex.toLowerCase(), asm: result.scriptAsm as string };
}

/** How many fixed 8-byte NUM2BIN words the emitted script writes. */
function eightByteWords(asm: string): number {
  return (asm.match(/\bOP_8 OP_NUM2BIN\b/g) ?? []).length;
}

describe('mutable RabinSig / RabinPubKey state is a fixed 8-byte word', () => {
  // -------------------------------------------------------------------------
  // The decisive equality: the writer emits exactly what the reader splits.
  // `bigint` is the reference because its writer and reader are known to agree.
  // -------------------------------------------------------------------------
  describe('lowers identically to bigint', () => {
    for (const { label, build, file } of SHAPES) {
      for (const propType of RABIN_TYPES) {
        it(`${label}: ${propType}`, () => {
          expect(compiled(build(propType), file).hex).toBe(compiled(build('bigint'), file).hex);
        });
      }
    }
  });

  // -------------------------------------------------------------------------
  // The writer-side assertion, stated directly rather than via the equality:
  // the serializer must emit an OP_8 OP_NUM2BIN for this field. A tier whose
  // writer tests the literal `bigint` emits nothing there and loses a word.
  // -------------------------------------------------------------------------
  describe('the serializer emits an 8-byte NUM2BIN word for the field', () => {
    for (const { label, build, file } of SHAPES) {
      const framed = eightByteWords(compiled(build('ByteString'), file).asm);
      const numeric = eightByteWords(compiled(build('bigint'), file).asm);

      it(`${label}: a bigint field adds one 8-byte word over the framed control`, () => {
        // Guards the counts below: without this the equality could be met by
        // both shapes emitting zero.
        expect(numeric).toBe(framed + 1);
      });

      for (const propType of RABIN_TYPES) {
        it(`${label}: a ${propType} field emits the same count as bigint`, () => {
          expect(eightByteWords(compiled(build(propType), file).asm)).toBe(numeric);
        });
      }
    }
  });

  // -------------------------------------------------------------------------
  // Controls — the equality must stay discriminating. `ByteString` and `Sig`
  // are push-data framed; `PubKey` is 33 raw bytes.
  // -------------------------------------------------------------------------
  describe('other state types stay distinct from bigint', () => {
    for (const { label, build, file } of SHAPES) {
      for (const propType of ['ByteString', 'Sig', 'PubKey'] as const) {
        it(`${label}: ${propType}`, () => {
          expect(compiled(build(propType), file).hex).not.toBe(compiled(build('bigint'), file).hex);
        });
      }
    }
  });
});
