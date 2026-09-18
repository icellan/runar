/**
 * `P256Point` and `P384Point` are FIXED-WIDTH raw state, not push-data-framed
 * state — 64 and 96 bytes respectively, exactly like `Point` is 64.
 *
 * `packages/runar-lang/src/types.ts` defines all three as `ByteString`
 * subtypes with a hard width, and their cast constructors enforce it
 * (`assertHexLength(hex, 64, 'P256Point')`, `assertHexLength(hex, 96,
 * 'P384Point')`). There is no shape in which either carries a length the
 * reader could not know at compile time, so framing them would cost a byte
 * (or three) for nothing.
 *
 * All seven compiler backends already agree on this and have from the start:
 * a mutable `P256Point` field lowers BYTE-IDENTICALLY to a mutable `Point`
 * field, and a mutable `P384Point` field lowers to neither that nor the
 * push-data-framed `ByteString` shape. This file pins that down so the
 * compiler side cannot be "fixed" toward the framed encoding.
 *
 * It matters because the READER of these bytes — every SDK's
 * `encodeStateValue` / `decodeStateValue`, and the shared
 * `STATE_FIELD_WIDTHS` table in `runar-ir-schema` — enumerates the fixed-size
 * types as `PubKey, Addr, Ripemd160, Sha256, Point` and omits both curve-point
 * types, so it frames them. That is a writer-vs-reader split of the same class
 * as `Sig` / `SigHashPreimage` (6dc1979b), with the sides reversed: there the
 * SDK was right and the compiler wrong, here the compiler is right. The
 * executed consequence is that the SDK deploys a 65-byte (P256Point) or
 * 98-byte (P384Point) state section where the compiled script reads 64 / 96
 * raw, and the first spend fails on the real Script VM.
 *
 * The discriminating lock is `P256Point` === `Point`: that single equality
 * distinguishes fixed-64 from framed, and it would break the instant anyone
 * routed `P256Point` through `isVariableLengthStateType`. `ByteString` and
 * `Sig` are the framed controls (byte-unchanged since 6dc1979b); `PubKey` and
 * `Sha256` are the other-width fixed controls.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { compile } from '../index.js';

/** Mutating method — drives the state-continuation WRITE path. */
function mutatingSource(propType: string): string {
  return `import { StatefulSmartContract } from 'runar-lang';
class CurvePointStateWrite extends StatefulSmartContract {
  tag: ${propType};
  constructor(tag: ${propType}) { super(tag); this.tag = tag; }
  public update(next: ${propType}) { this.tag = next; }
}`;
}

/** Terminal method reading the field — drives the deserialize READ path. */
function terminalSource(propType: string): string {
  return `import { StatefulSmartContract, assert, len } from 'runar-lang';
class CurvePointStateRead extends StatefulSmartContract {
  tag: ${propType};
  constructor(tag: ${propType}) { super(tag); this.tag = tag; }
  public check(expected: bigint) { assert(len(this.tag) === expected); }
}`;
}

const WRITE_FILE = 'CurvePointStateWrite.runar.ts';
const READ_FILE = 'CurvePointStateRead.runar.ts';

function hexOf(source: string, fileName: string): string {
  const result = compile(source, { fileName, disableConstantFolding: true });
  if (!result.success || typeof result.scriptHex !== 'string') {
    throw new Error(`compile failed: ${result.diagnostics.map(d => d.message).join('; ')}`);
  }
  return result.scriptHex.toLowerCase();
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

const SHAPES = [
  { label: 'mutating write', build: mutatingSource, file: WRITE_FILE },
  { label: 'terminal read', build: terminalSource, file: READ_FILE },
] as const;

describe('P256Point / P384Point are fixed-width raw state', () => {
  // -------------------------------------------------------------------------
  // The decisive equality: P256Point is Point's width, so it is Point's bytes.
  // -------------------------------------------------------------------------
  describe('P256Point lowers identically to Point (both fixed 64)', () => {
    for (const { label, build, file } of SHAPES) {
      it(`${label}`, () => {
        expect(hexOf(build('P256Point'), file)).toBe(hexOf(build('Point'), file));
      });
    }
  });

  // -------------------------------------------------------------------------
  // Neither curve-point type may join the push-data-framed set.
  // -------------------------------------------------------------------------
  describe('neither type is push-data framed', () => {
    for (const { label, build, file } of SHAPES) {
      for (const t of ['P256Point', 'P384Point'] as const) {
        it(`${label}: a ${t} field does NOT lower like ByteString`, () => {
          expect(hexOf(build(t), file)).not.toBe(hexOf(build('ByteString'), file));
        });

        it(`${label}: a ${t} field does NOT lower like Sig`, () => {
          // Sig IS framed (6dc1979b). Asserting the inequality separately from
          // ByteString keeps this honest if the two ever diverge.
          expect(hexOf(build(t), file)).not.toBe(hexOf(build('Sig'), file));
        });
      }
    }
  });

  // -------------------------------------------------------------------------
  // P384Point is its OWN width (96) — not 64, not 33, not 32, not framed.
  // -------------------------------------------------------------------------
  describe('P384Point is a width of its own', () => {
    for (const { label, build, file } of SHAPES) {
      for (const other of ['Point', 'P256Point', 'PubKey', 'Sha256'] as const) {
        it(`${label}: P384Point differs from ${other}`, () => {
          expect(hexOf(build('P384Point'), file)).not.toBe(hexOf(build(other), file));
        });
      }
    }
  });

  // -------------------------------------------------------------------------
  // Byte-invariance pins. Captured from the build at which all seven tiers
  // were measured byte-identical (see cross-compiler.test.ts). A change to any
  // of these means the lowering moved; if that is intended, re-measure all
  // seven tiers before re-stamping.
  // -------------------------------------------------------------------------
  describe('byte-invariance pins (all seven tiers agreed on these)', () => {
    const PINS: Array<{ shape: 0 | 1; type: string; digest: string; hexLen: number }> = [
      // W1 added a 3-byte zero-pad (`01 00 7e`) before the auto-injected
      // sighash-type pin's OP_BIN2NUM, so every shape here is 6 hex chars
      // longer than it was; the discriminating equalities are unchanged.
      { shape: 0, type: 'Point', digest: '8d309734', hexLen: 1360 },
      { shape: 0, type: 'P256Point', digest: '8d309734', hexLen: 1360 },
      { shape: 0, type: 'P384Point', digest: '0aa41b99', hexLen: 1360 },
      { shape: 0, type: 'PubKey', digest: 'c0ba2f04', hexLen: 1360 },
      { shape: 0, type: 'Sha256', digest: '2e528831', hexLen: 1360 },
      { shape: 0, type: 'ByteString', digest: '5f873f91', hexLen: 1616 },
      { shape: 0, type: 'Sig', digest: '5f873f91', hexLen: 1616 },
      { shape: 1, type: 'Point', digest: 'a1e544fa', hexLen: 942 },
      { shape: 1, type: 'P256Point', digest: 'a1e544fa', hexLen: 942 },
      { shape: 1, type: 'P384Point', digest: '69b87cde', hexLen: 942 },
      { shape: 1, type: 'PubKey', digest: '75d147d3', hexLen: 942 },
      { shape: 1, type: 'Sha256', digest: 'e2b1b50e', hexLen: 942 },
      { shape: 1, type: 'ByteString', digest: 'ecfc6f7a', hexLen: 1270 },
      { shape: 1, type: 'Sig', digest: 'ecfc6f7a', hexLen: 1270 },
    ];

    for (const pin of PINS) {
      const shape = SHAPES[pin.shape];
      it(`${shape.label}: ${pin.type} → ${pin.digest} (${pin.hexLen} hex chars)`, () => {
        const hex = hexOf(shape.build(pin.type), shape.file);
        expect(hex.length).toBe(pin.hexLen);
        expect(sha256(hex).slice(0, 8)).toBe(pin.digest);
      });
    }
  });
});
