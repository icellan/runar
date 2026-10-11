/**
 * The TypeScript `--ir` loader must consume the repo's own IR goldens.
 *
 * `loadANFFromJSON`'s contract says so in as many words:
 *
 *   "The Go / Rust / Python emitters use plain numbers for safe integer
 *    values and decimal strings for big numbers. This loader accepts both
 *    shapes so a TS `--from-ir` invocation can consume IR produced by any
 *    peer compiler."
 *
 * It did not. The JSON reviver converted the TS emitter's own `"42n"` strings
 * and nothing else, so a plain JSON number arrived downstream as a JS
 * `number`, missed both the `bigint` and `boolean` arms of `pushValue`, and
 * was handed to `hexToBytes` — which threw `Invalid hex string length:
 * undefined`. Measured against the 78 checked-in `expected-ir.json` files
 * before the fix: 26 loaded and matched their golden hex exactly, 52 threw.
 *
 * The damage was not the crash. It was that TypeScript could not be wired
 * into `conformance --ir-parity`, which drives the six native tiers only —
 * so the TS tier's IR path had no cross-tier comparison at all, and a
 * `_codePart` divergence (R-287) sat there undetected.
 *
 * This test is the comparison that was missing: every golden, loaded and
 * compiled by the TS tier, must reproduce `expected-script.hex` byte for
 * byte. The goldens were stamped fold-OFF, so folding stays disabled.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileFromANF, loadANFFromJSON } from '../packages/runar-compiler/src/index.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixturesDir = join(repoRoot, 'conformance', 'tests');

interface Golden { name: string; irPath: string; hexPath: string }

const goldens: Golden[] = readdirSync(fixturesDir)
  .sort()
  .map(name => ({
    name,
    irPath: join(fixturesDir, name, 'expected-ir.json'),
    hexPath: join(fixturesDir, name, 'expected-script.hex'),
  }))
  .filter(g => existsSync(g.irPath) && existsSync(g.hexPath));

describe('TS --ir loader vs the conformance goldens', () => {
  it('finds the golden corpus', () => {
    // Anti-vacuity: an empty list would make every assertion below a no-op,
    // which is exactly how a path typo hides a regression.
    expect(goldens.length).toBeGreaterThanOrEqual(70);
  });

  it.each(goldens.map(g => [g.name, g] as const))(
    '%s: loads and compiles to the golden hex',
    (_name, golden) => {
      const anf = loadANFFromJSON(readFileSync(golden.irPath, 'utf8'));
      const result = compileFromANF(anf, { disableConstantFolding: true });
      expect(result.scriptHex).toBe(readFileSync(golden.hexPath, 'utf8').trim());
    },
  );
});

describe('loadANFFromJSON number handling', () => {
  const wrap = (methodBody: string) => `{
    "contractName": "N",
    "properties": [],
    "methods": [{ "name": "m", "isPublic": true, "params": [], "body": ${methodBody} }]
  }`;

  it('decodes a plain JSON number as a bigint, not a hex string', () => {
    const anf = loadANFFromJSON(wrap('[{"name":"t0","value":{"kind":"load_const","value":65}}]'));
    const value = (anf.methods[0]!.body[0]!.value as { value: unknown }).value;
    expect(typeof value).toBe('bigint');
    expect(value).toBe(65n);
  });

  it('still decodes the TS emitter\'s own "42n" strings', () => {
    const anf = loadANFFromJSON(wrap('[{"name":"t0","value":{"kind":"load_const","value":"42n"}}]'));
    expect((anf.methods[0]!.body[0]!.value as { value: unknown }).value).toBe(42n);
  });

  it('leaves a hex ByteString const a string', () => {
    const anf = loadANFFromJSON(wrap('[{"name":"t0","value":{"kind":"load_const","value":"aabb"}}]'));
    expect((anf.methods[0]!.body[0]!.value as { value: unknown }).value).toBe('aabb');
  });

  it('leaves a boolean const a boolean', () => {
    const anf = loadANFFromJSON(wrap('[{"name":"t0","value":{"kind":"load_const","value":true}}]'));
    expect((anf.methods[0]!.body[0]!.value as { value: unknown }).value).toBe(true);
  });

  it('decodes 2^53+1 exactly rather than compiling the value JSON.parse already rounded (or refuses it without context.source)', () => {
    // 9007199254740993 (2^53 + 1) does not survive JSON.parse as a number —
    // it rounds to 9007199254740992. N-212 (R82: parse exactly everywhere)
    // reads the undamaged token from the reviver's `context.source`
    // (Node >= 21) for the `value` / `initialValue` positions and returns
    // the exact BigInt instead of silently compiling the rounded value. On a
    // runtime without `context.source` the digits are unrecoverable and the
    // pre-N-212 refusal is still the correct answer — asserted here, not
    // skipped, same as packages/runar-compiler/src/__tests__/n212-ir-bare-big-integer.test.ts.
    //
    // Proves: on this runtime, loadANFFromJSON yields the exact bigint
    // 9007199254740993n for a bare too-large JSON integer, not 2^53 and not
    // a JS number.
    // Does not prove: the compiled script hex (see n212-ir-bare-big-integer.test.ts),
    // other tiers, or the `initialValue` / `loop.start` positions.
    let hasSource = false;
    JSON.parse('1', function (this: unknown, _k: string, v: unknown, ctx?: { source?: string }) {
      hasSource = ctx?.source === '1';
      return v;
    } as never);

    const tooBig = wrap('[{"name":"t0","value":{"kind":"load_const","value":9007199254740993}}]');
    if (!hasSource) {
      expect(() => loadANFFromJSON(tooBig)).toThrow(/safe-integer precision/);
      return;
    }
    const value = (loadANFFromJSON(tooBig).methods[0]!.body[0]!.value as { value: unknown }).value;
    expect(typeof value).toBe('bigint');
    expect(value).toBe(9007199254740993n);
  });

  it('decodes a numeric loop start as a bigint', () => {
    const anf = loadANFFromJSON(wrap(
      '[{"name":"t0","value":{"kind":"loop","count":2,"body":[],"iterVar":"i","start":0,"step":1}}]',
    ));
    expect(typeof (anf.methods[0]!.body[0]!.value as { start: unknown }).start).toBe('bigint');
  });

  it('decodes a numeric property initialValue as a bigint', () => {
    const anf = loadANFFromJSON(`{
      "contractName": "N",
      "properties": [{ "name": "c", "type": "bigint", "readonly": false, "initialValue": 7 }],
      "methods": []
    }`);
    expect(anf.properties[0]!.initialValue).toBe(7n);
  });
});
