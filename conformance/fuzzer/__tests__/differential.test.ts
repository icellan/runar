/**
 * F-169: `differential.ts`'s `compileTsSource` compared the TS CLI's
 * human-readable chatter against the other six tiers' real compiled output,
 * in BOTH comparison modes:
 *
 *   - IR mode: it ran the CLI with `--ir --disable-constant-folding`. The TS
 *     CLI's `--ir` means "embed the IR inside the artifact JSON FILE" — it
 *     prints `Compiling: ...` / `Artifact written: ...` chatter to stdout,
 *     never the IR itself (packages/runar-cli/src/commands/compile.ts). Every
 *     other tier's `--emit-ir` has the opposite contract: stdout carries
 *     ONLY the IR (see compilers/go/main.go: "stdout carries only the IR").
 *     So in an all-tiers run, `ts` (always `outputs[0]`, the comparison
 *     reference) never matched anything; with no native binaries built, `ts`
 *     was the only output, `outputs.length < 2`, and the run reported zero
 *     mismatches having compared nothing.
 *   - hex mode: `compileTsSource`'s hex branch never pushed `--hex` at all
 *     (`if (!hex) args.push('--ir')` only ever adds a flag for the non-hex
 *     case), so hex-compare mode ALSO ran the CLI's default mode and got the
 *     same chatter, not a hex string.
 *
 * `conformance/fuzzer/ir-differential.ts` already solved the IR-mode half of
 * this the same way this file's fix does: compile in-process via
 * runar-compiler's `compile()`, which hands back the ANF object directly —
 * there is no stdout contract to get wrong.
 *
 * This test drives the already-exported `runDifferentialFuzzing` with only
 * the `ts` tier selected, so the per-program `tsOutput` field is populated
 * and directly inspectable in both modes without needing to export any new
 * internals.
 *
 * What this test PROVES: `tsOutput` in IR mode is parseable JSON shaped like
 * real ANF IR (not CLI chatter), AND survives `canonicalize()` with nested
 * content intact (a method's `body` keeps its bindings — see the second
 * `it()` below for why that second half matters); `tsOutput` in hex mode is
 * a bare lowercase hex string (not chatter).
 *
 * What this test does NOT prove: that `ts`'s output actually AGREES with any
 * other tier's output byte-for-byte — only the `ts` tier is selected here,
 * so no cross-tier comparison runs. Cross-tier IR/hex parity for the
 * contract-level generator is covered by `ir-differential.ts`'s own suite.
 */
import { describe, it, expect } from 'vitest';
import { runDifferentialFuzzing } from '../differential.js';

describe('runDifferentialFuzzing ts tier output (F-169)', () => {
  it('IR mode: tsOutput is parseable ANF IR JSON whose nested bindings keep their fields, not CLI chatter', async () => {
    const results = await runDifferentialFuzzing(3, { compilers: ['ts'], seed: 1 });
    const withOutput = results.filter((r) => r.tsOutput !== undefined);
    expect(withOutput.length).toBeGreaterThan(0);

    for (const r of withOutput) {
      const output = r.tsOutput!;
      let parsed: unknown;
      expect(() => {
        parsed = JSON.parse(output);
      }).not.toThrow();

      // Real ANF IR root shape (packages/runar-compiler/src/ir/anf-ir.ts):
      // { contractName, properties, methods }. CLI chatter ("Compiling:
      // .../  Artifact written: ...") is neither valid JSON nor shaped like
      // this.
      const root = parsed as { contractName?: unknown; methods?: unknown };
      expect(typeof root.contractName).toBe('string');
      expect(Array.isArray(root.methods)).toBe(true);
      const methods = root.methods as Array<{ name?: unknown; body?: unknown }>;
      expect(methods.length).toBeGreaterThan(0);

      // Nested content must survive canonicalize(). Its previous
      // implementation, `JSON.stringify(obj, Object.keys(obj).sort(), 2)`,
      // used the ROOT's sorted keys as the stringify replacer — but an ARRAY
      // replacer is a property ALLOW-LIST applied at EVERY nesting depth, not
      // a key sort. Seeded with `['contractName', 'methods', 'properties']`,
      // every object nested below the root that has none of those three keys
      // (every method, every binding) serialized as `{}`. A method would
      // still report `typeof name === 'string'` to be false and `body` to be
      // undefined, which the assertions below catch.
      const method = methods[0];
      expect(typeof method.name).toBe('string');
      expect(Array.isArray(method.body)).toBe(true);
      const body = method.body as Array<{ value?: { kind?: unknown } }>;
      expect(body.length).toBeGreaterThan(0);
      expect(typeof body[0]!.value?.kind).toBe('string');
    }
  });

  it('hex mode: tsOutput is a bare lowercase hex string, not CLI chatter', async () => {
    const results = await runDifferentialFuzzing(3, {
      compilers: ['ts'],
      seed: 1,
      compareHex: true,
    });
    const withOutput = results.filter((r) => r.tsOutput !== undefined);
    expect(withOutput.length).toBeGreaterThan(0);
    for (const r of withOutput) {
      expect(r.tsOutput).toMatch(/^[0-9a-f]+$/);
    }
  });
});
