import { describe, it, expect } from 'vitest';
import { compileFromANF, loadANFFromJSON } from '../index.js';

/**
 * N-212 — a bare JSON integer wider than 2^53 on the `--from-ir` boundary.
 *
 * Decision R82: every tier parses such an integer EXACTLY. Go, Python and Ruby
 * `--emit-ir` write an oversize property initializer as a bare JSON number, so
 * the reference tier must be able to read what its peers write.
 *
 * Before: `JSON.parse` rounded the token to a double before any Rúnar code saw
 * it, and `coerceNumericBigInts` refused anything past
 * `Number.MAX_SAFE_INTEGER`. That was fail-closed, but it refused correct IR
 * four peers compiled exactly. The loader now reads the verbatim token through
 * the reviver's `context.source` (Node >= 21) for `load_const.value` and
 * `initialValue`. On a runtime without `context.source` the digits are
 * unrecoverable, and the old refusal stands. This file asserts that branch
 * instead of skipping it.
 *
 * Proves: on this runtime a bare secp256k1 order in either position compiles
 * to the exact push, byte-identical to the `"…n"` string form. Values inside
 * the safe range keep compiling as before.
 * Does not prove: the other six tiers agree. That is
 * conformance/negatives/ir-bare-big-integer.test.ts.
 */

const N = '115792089237316195423570985008687907852837564279074904382605163141518161494337';
const N_PUSH = '21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00';

let hasSource = false;
JSON.parse('1', function (this: unknown, _k: string, v: unknown, ctx?: { source?: string }) {
  hasSource = ctx?.source === '1';
  return v;
} as never);

const irFor = (literalJson: string, where: 'load_const' | 'initialValue'): string => {
  const props =
    where === 'initialValue'
      ? `[{"name":"n","type":"bigint","readonly":true,"initialValue":${literalJson}}]`
      : '[]';
  const loadN =
    where === 'initialValue'
      ? '{"kind":"load_prop","name":"n"}'
      : `{"kind":"load_const","value":${literalJson}}`;
  return `{"contractName":"NumArm","parentClass":"SmartContract","properties":${props},"methods":[
    {"name":"constructor","isPublic":false,"params":[],"body":[{"name":"t0","value":{"kind":"call","func":"super","args":[]}}]},
    {"name":"unlock","isPublic":true,"params":[{"name":"x","type":"bigint"}],"body":[
      {"name":"t0","value":{"kind":"load_param","name":"x"}},
      {"name":"t1","value":${loadN}},
      {"name":"t2","value":{"kind":"bin_op","op":"===","left":"t0","right":"t1"}},
      {"name":"t3","value":{"kind":"assert","value":"t2"}}]}]}`;
};

const hex = (ir: string) => compileFromANF(loadANFFromJSON(ir)).scriptHex;

describe('N-212: bare JSON integers beyond 2^53 on --from-ir', () => {
  for (const where of ['load_const', 'initialValue'] as const) {
    it(`${where}: a bare secp256k1 order is compiled exactly (or refused without context.source)`, () => {
      const ir = irFor(N, where);
      if (!hasSource) {
        expect(() => loadANFFromJSON(ir)).toThrow(/safe-integer precision/);
        return;
      }
      const got = hex(ir);
      expect(got.startsWith(N_PUSH), got).toBe(true);
      expect(got).toBe(hex(irFor(`"${N}n"`, where)));
    });

    it(`${where}: 2^53+1 is not rounded to 2^53`, () => {
      const ir = irFor('9007199254740993', where);
      if (!hasSource) {
        expect(() => loadANFFromJSON(ir)).toThrow(/safe-integer precision/);
        return;
      }
      expect(hex(ir).startsWith('0701000000000020')).toBe(true);
    });

    it(`${where}: control — 2^53-1 compiles as before`, () => {
      expect(hex(irFor('9007199254740991', where)).startsWith('07ffffffffffff1f')).toBe(true);
    });
  }
});
