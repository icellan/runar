/**
 * R-087 — the ANF hex decoders in stack lowering must reject malformed hex.
 *
 * `--ir` is a documented input surface: `loadANFFromJSON` is explicitly
 * shallow ("Does NOT perform deep schema validation — downstream
 * stack-lowering will reject malformed IR with an explicit error"), and
 * `lowerCheckMultiSig` states the same division of labour ("Checking in the
 * lowerer (rather than the typechecker) also covers the `--ir` input path,
 * which never runs a typecheck"). Two decoders in `05-stack-lower.ts` broke
 * that contract.
 *
 * `parseInt(s, 16)` is not a validator. It decodes a valid PREFIX and ignores
 * the rest, skips leading whitespace, and accepts a sign:
 *
 *     parseInt('0g', 16) === 0     parseInt('a!', 16) === 10
 *     parseInt(' f', 16) === 15    parseInt('+f', 16) === 15
 *
 * `decodeHexBytes` (the `raw_script` path) did carry a `Number.isNaN` guard,
 * but NaN only appears when the FIRST character is invalid, so every partially
 * invalid pair walked straight past it. `hexToBytes` (the `load_const` push
 * path) had no check at all, and `new Uint8Array([NaN])[0]` is 0, so even a
 * fully invalid pair became the byte 0x00.
 *
 * The consequence is not a crash — it is a DIFFERENT LOCKING SCRIPT, produced
 * silently. Measured on the pre-fix HEAD with `--disable-constant-folding`,
 * tampering one `load_const` of the control contract (`aabb` -> …):
 *
 *     control  'aabb'  ts 02aabb87   go 02aabb87
 *     '0gbb'           ts 0200bb87   go REJECTS (encoding/hex: invalid byte)
 *     'ggbb'           ts 0200bb87   go REJECTS
 *     'a!bb'           ts 020abb87   go REJECTS
 *     ' fbb'           ts 020fbb87   go REJECTS
 *     '+fbb'           ts 020fbb87   go REJECTS
 *
 * Go uses `encoding/hex.DecodeString`, which is strict, so TS is the lone
 * outlier: five malformed inputs, five silently wrong scripts, no diagnostic.
 *
 * This is reachable ONLY through `--ir`. The source path is already guarded —
 * a `"0gbb" as ByteString` literal is rejected by the frontend with
 * "ByteString literal '0gbb' contains non-hex characters" — which is why this
 * lives here and not in `conformance/negatives/` (that corpus drives each
 * tier's `--source` CLI and cannot express a malformed-IR input).
 */
import { describe, it, expect } from 'vitest';
import { compile, loadANFFromJSON, compileFromANF } from '../index.js';

/** Contract whose only const is the ByteString we tamper with. */
const CONTROL_SOURCE = `
class B extends SmartContract {
  readonly h: ByteString;
  constructor(h: ByteString) { super(h); this.h = h; }
  public go(x: ByteString): void {
    assert(x == ("aabb" as ByteString));
  }
}`;

/** The script the untampered IR lowers to. Also produced by the Go tier. */
const CONTROL_HEX = '02aabb87';

/**
 * Every shape `parseInt(_, 16)` mis-decodes instead of rejecting. Each entry
 * is the byte `parseInt` produced pre-fix, kept in the table so a regression
 * that reintroduces leniency is recognisable by its output, not just by a
 * missing throw.
 */
const MALFORMED: { hex: string; preFixByte: string; why: string }[] = [
  { hex: '0gbb', preFixByte: '00', why: "valid prefix '0', rest ignored" },
  { hex: 'ggbb', preFixByte: '00', why: 'NaN, coerced to 0 by Uint8Array' },
  { hex: 'a!bb', preFixByte: '0a', why: "valid prefix 'a', rest ignored" },
  { hex: ' fbb', preFixByte: '0f', why: 'leading whitespace skipped' },
  { hex: '+fbb', preFixByte: '0f', why: 'leading sign accepted' },
];

function controlIrJson(): string {
  const r = compile(CONTROL_SOURCE, { fileName: 'B.runar.ts', disableConstantFolding: true });
  const errs = (r.diagnostics ?? []).filter((d) => d.severity === 'error');
  expect(errs, 'the control source must compile').toEqual([]);
  return JSON.stringify(r.anf, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v));
}

/**
 * Lower an IR JSON string. Returns the hex, or the rejection message.
 *
 * The `--ir` entry points report failure by THROWING, not by diagnostics:
 * `loadANFFromJSON` throws on a malformed envelope and `CompileFromANFResult`
 * carries no `diagnostics` field at all (it is `scriptHex` / `scriptAsm` /
 * `anf` / offsets — an IR program has no `ContractNode`, so there is no ABI
 * layer to attach diagnostics to). A `.diagnostics` branch here would be dead
 * code that silently never runs, so the `catch` is the whole error surface.
 */
function lowerIr(json: string): { hex?: string; error?: string } {
  try {
    const r = compileFromANF(loadANFFromJSON(json), { disableConstantFolding: true });
    return { hex: r.scriptHex };
  } catch (e) {
    return { error: String(e) };
  }
}

/**
 * A `raw_script` binding reaches the OTHER decoder (`decodeHexBytes`). Built
 * by hand because no TypeScript surface syntax emits one with arbitrary hex.
 */
function rawScriptIr(bytesHex: string): string {
  return JSON.stringify({
    contractName: 'R',
    properties: [{ name: 'k', type: 'bigint', readonly: true }],
    methods: [
      {
        name: 'constructor',
        params: [{ name: 'k', type: 'bigint' }],
        body: [
          { name: 'c0', value: { kind: 'load_prop', name: 'k' } },
          { name: 'c1', value: { kind: 'call', func: 'super', args: ['c0'] } },
          { name: 'c2', value: { kind: 'load_prop', name: 'k' } },
          { name: 'c3', value: { kind: 'update_prop', name: 'k', value: 'c2' } },
        ],
        isPublic: false,
      },
      {
        name: 'go',
        params: [{ name: 'x', type: 'bigint' }],
        body: [
          { name: 't0', value: { kind: 'load_param', name: 'x' } },
          { name: 't1', value: { kind: 'raw_script', bytes: bytesHex, in_arity: 1, out_arity: 1 } },
          { name: 't2', value: { kind: 'assert', value: 't1' } },
        ],
        isPublic: true,
      },
    ],
  });
}

describe('R-087 — malformed hex in external ANF IR is rejected, not mis-decoded', () => {
  // -- controls -------------------------------------------------------------

  it('CONTROL: the untampered IR lowers to the pinned script', () => {
    expect(lowerIr(controlIrJson())).toEqual({ hex: CONTROL_HEX });
  });

  it('CONTROL: a well-formed raw_script blob still lowers', () => {
    const r = lowerIr(rawScriptIr('7551'));
    expect(r.error, 'valid hex must not be rejected').toBeUndefined();
    expect(r.hex).toContain('7551');
  });

  it('CONTROL: uppercase hex is valid and must keep working', () => {
    const json = controlIrJson().replace('"aabb"', '"AABB"');
    expect(lowerIr(json)).toEqual({ hex: CONTROL_HEX });
  });

  // -- the defect -----------------------------------------------------------

  describe.each(MALFORMED)('load_const value $hex ($why)', ({ hex, preFixByte }) => {
    it('is rejected rather than decoded to a different script', () => {
      const json = controlIrJson().replace('"aabb"', JSON.stringify(hex));
      const r = lowerIr(json);
      expect(
        r.hex,
        `malformed hex '${hex}' silently lowered to ${r.hex} ` +
          `(pre-fix it decoded byte 0x${preFixByte} instead of failing)`,
      ).toBeUndefined();
      expect(r.error).toMatch(/hex/i);
    });
  });

  describe.each(MALFORMED)('raw_script bytes $hex ($why)', ({ hex }) => {
    it('is rejected rather than decoded to a different script', () => {
      const r = lowerIr(rawScriptIr(hex));
      expect(r.hex, `malformed raw_script hex '${hex}' silently lowered to ${r.hex}`).toBeUndefined();
      expect(r.error).toMatch(/hex/i);
    });
  });

  // -- odd length was already rejected; keep it that way --------------------

  it('an odd-length load_const value is still rejected', () => {
    const json = controlIrJson().replace('"aabb"', '"aab"');
    expect(lowerIr(json).error).toMatch(/hex/i);
  });

  it('an odd-length raw_script blob is still rejected', () => {
    expect(lowerIr(rawScriptIr('755')).error).toMatch(/hex/i);
  });
});
