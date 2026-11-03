import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';

/**
 * F-069 — the nine PriceBet variants of the flagship end2end example must be
 * the SAME contract.
 *
 * The Move copy once declared `resource struct PriceBet`, which the Move
 * frontend (by design) lowers to StatefulSmartContract. That silently turned
 * the Move variant into a stateful covenant — extra txPreimage unlocking
 * parameter, checkPreimage + sighash-type asserts, OP_CODESEPARATOR — while
 * the other eight variants are stateless. The per-format business-logic tests
 * run through the interpreter with mocked preimage checks, so they never saw
 * the difference.
 *
 * Proves: through the real TS compiler, all nine sources parse to the same
 * contract name and parentClass (SmartContract), expose the same public ABI,
 * and emit byte-identical locking-script hex (constant folding at its default).
 *
 * Does not prove: that the other six compiler tiers agree (that is the
 * conformance suite's job), nor that the script is correct on-chain — only
 * that the nine example sources describe one contract.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));

const VARIANTS: readonly string[] = [
  'ts/PriceBet.runar.ts',
  'sol/PriceBet.runar.sol',
  'move/PriceBet.runar.move',
  'go/PriceBet.runar.go',
  'rust/PriceBet.runar.rs',
  'python/PriceBet.runar.py',
  'zig/PriceBet.runar.zig',
  'ruby/PriceBet.runar.rb',
  'java/src/main/java/runar/end2end/PriceBet.runar.java',
];

function compileVariant(rel: string) {
  const path = join(__dirname, rel);
  const result = compile(readFileSync(path, 'utf8'), { fileName: path });
  const errors = result.diagnostics.filter((d) => d.severity === 'error');
  expect(errors, `${rel} failed to compile`).toEqual([]);
  expect(result.contract, `${rel} produced no AST`).not.toBeNull();
  expect(result.scriptHex, `${rel} produced no script`).toBeTruthy();
  return {
    name: result.contract!.name,
    parentClass: result.contract!.parentClass,
    abi: JSON.stringify(result.artifact?.abi),
    scriptHex: result.scriptHex!,
  };
}

describe('PriceBet end2end example: all nine formats are one contract', () => {
  const reference = compileVariant(VARIANTS[0]!);

  it('the TS reference is a stateless SmartContract', () => {
    expect(reference.name).toBe('PriceBet');
    expect(reference.parentClass).toBe('SmartContract');
  });

  for (const rel of VARIANTS.slice(1)) {
    it(`${rel} matches the TS variant (name, parentClass, ABI, script hex)`, () => {
      const v = compileVariant(rel);
      expect(v.name).toBe(reference.name);
      expect(v.parentClass).toBe(reference.parentClass);
      expect(v.abi).toBe(reference.abi);
      expect(v.scriptHex).toBe(reference.scriptHex);
    });
  }
});

/**
 * F-148 (CL-GAP-141) — the nine PriceBet sources are a conformance fixture.
 *
 * The block above compiles all nine sources through the TS compiler only.
 * The repo's cross-tier invariant (all seven compilers emit byte-identical
 * ANF IR and script hex from every one of the nine surfaces) is enforced by
 * the conformance suite, and no conformance/tests/<fixture>/source.json
 * pointed at these files, so the Go, Rust, Python, Zig, Ruby and Java
 * compilers were never held to the TS bytes for the flagship example.
 *
 * Proves: exactly one conformance fixture declares these nine files as its
 * nine `sources` (one per extension, no other files), with no `compilers`
 * allowlist and no `parserSkip`, so it is in scope for the full 7-tier
 * ANF/hex parity and parser-only checks, and it carries both goldens.
 *
 * Does not prove: that the tiers agree (the conformance runner does that when
 * it runs the fixture), nor that the goldens are right on-chain (the fixture's
 * real-crypto witness does that).
 */
const REPO_ROOT = resolve(__dirname, '../..');
const CONFORMANCE_TESTS = join(REPO_ROOT, 'conformance/tests');
const EXT_OF = (rel: string) => rel.slice(rel.indexOf('.runar.'));

describe('PriceBet end2end example: wired into the cross-tier conformance suite', () => {
  const wanted = new Map(VARIANTS.map((rel) => [EXT_OF(rel), resolve(__dirname, rel)]));

  const referencing = readdirSync(CONFORMANCE_TESTS)
    .filter((d) => existsSync(join(CONFORMANCE_TESTS, d, 'source.json')))
    .filter((d) => {
      const cfg = JSON.parse(readFileSync(join(CONFORMANCE_TESTS, d, 'source.json'), 'utf8')) as {
        sources?: Record<string, string>;
      };
      return Object.values(cfg.sources ?? {}).some((p) =>
        [...wanted.values()].includes(resolve(CONFORMANCE_TESTS, d, p)),
      );
    });

  it('exactly one conformance fixture references the end2end PriceBet sources', () => {
    expect(referencing, 'no conformance fixture points at examples/end2end-example/*/PriceBet.*').toHaveLength(1);
  });

  it('that fixture declares all nine sources, unscoped, with both goldens', () => {
    expect(referencing).toHaveLength(1);
    const dir = join(CONFORMANCE_TESTS, referencing[0]!);
    const cfg = JSON.parse(readFileSync(join(dir, 'source.json'), 'utf8')) as Record<string, unknown> & {
      sources: Record<string, string>;
    };
    const declared = new Map(Object.entries(cfg.sources).map(([ext, p]) => [ext, resolve(dir, p)]));
    expect(declared).toEqual(wanted);
    expect(cfg.compilers, 'a compilers allowlist would exempt tiers from ANF/hex parity').toBeUndefined();
    expect(cfg.parserSkip, 'parserSkip would exempt formats from parser-only parity').toBeUndefined();
    expect(existsSync(join(dir, 'expected-ir.json'))).toBe(true);
    expect(existsSync(join(dir, 'expected-script.hex'))).toBe(true);
  });
});
