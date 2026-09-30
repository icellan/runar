import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
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
