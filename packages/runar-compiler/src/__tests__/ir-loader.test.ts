/**
 * IR Loader tests — F-289 / CL-GAP-015.
 *
 * This file used to define its own `loadANFFromJson` + `KNOWN_KINDS` set
 * inside the test (a toy re-implementation "analogous to" the real loader)
 * and exercised that copy exclusively. Its only runtime import was `vitest`;
 * the `../ir/index.js` import was types-only. So none of its 19 `it()`
 * blocks ever called production code, and the toy copy's `KNOWN_KINDS` had
 * already drifted from the real ANF kind set (missing `add_data_output`,
 * `array_literal`, `raw_script`) with nothing able to notice.
 *
 * Fixed by importing the real TS `--from-ir` entry point directly:
 * `loadANFFromJSON` (packages/runar-cli's `compile --from-ir` calls this;
 * Go/Rust/Python/Zig/Ruby/Java each ship an equivalent `LoadIRFromBytes` /
 * `load_ir` / `compile_from_ir_bytes`). `compileFromANF` is pulled in for the
 * one case (unknown ANF kind) that the loader itself does not reject — see
 * below.
 *
 * Several of the original assertions encoded behavior the toy loader
 * invented rather than behavior the real loader has. Measured against
 * `loadANFFromJSON` (`packages/runar-compiler/src/index.ts` +
 * `ir/anf-required-fields.ts`):
 *   - Empty `contractName` / method name / param name / param type /
 *     property name / property type do NOT throw. The real loader's
 *     `assertRequiredIrFields` (N-069) checks a field's PRESENCE and JSON
 *     TYPE, not non-emptiness — an empty string is a valid string. Six of
 *     the toy file's `it()` blocks asserted a stricter rule that production
 *     code was never written to enforce. That's a real question (should an
 *     empty identifier be legal IR?) but it's a design decision for a
 *     separate item, not something this test-quality fix should silently
 *     tighten across all seven tiers. Rewritten below to pin the current,
 *     real behavior instead of a fictional one, with this note attached.
 *   - An unknown `kind` does NOT throw inside `loadANFFromJSON`. The loader
 *     does no kind-allowlist check at all (deliberately: the comment on
 *     `checkValue`'s `default` case says "Unknown kinds are refused
 *     elsewhere"); it's `compileFromANF` → stack-lowering's dispatch switch
 *     that throws "Unknown ANF kind '...' encountered in
 *     stack-lower.collectRefs". Rewritten to prove the garbage-kind-is-
 *     eventually-rejected intent against the place that actually enforces
 *     it, rather than against a loader-level check that doesn't exist.
 *   - `load_const`'s JSON-number values ARE converted to `bigint` by the
 *     real loader's `coerceNumericBigInts` (so is a property's
 *     `initialValue`); the toy loader's comment claimed "bigint conversion
 *     is caller's job" and left them as plain `number`. Updated to assert
 *     the real (bigint) result.
 *   - Malformed JSON throws `"input is not valid JSON: ..."`, not the toy
 *     loader's `"invalid IR JSON: ..."`. Regex updated to match.
 * Every other assertion (loop-count bounds, minimal valid IR, the
 * structural round-trips) already held against the real loader unchanged;
 * those are kept verbatim, just pointed at the real function.
 *
 * What this file proves: `loadANFFromJSON` — the function the TS tier's
 * `--from-ir` path actually calls — accepts well-formed ANF IR JSON (plain
 * and with nested if/loop bindings), coerces the three bigint-typed fields
 * correctly, and refuses a negative or over-maximum loop count and malformed
 * JSON; and that an unknown ANF kind, while not rejected by the loader
 * itself, is rejected before any script bytes are produced for it
 * (`compileFromANF`).
 * What this file does not prove: that identifiers may not be empty (they
 * currently can be — see above), that the `runar-cli compile --from-ir`
 * process boundary behaves the same (that's the CLI's own test surface), or
 * full schema coverage of every ANF value kind (see the dedicated
 * `n069-ir-required-fields.test.ts`, `n087-ir-parent-class.test.ts`,
 * `n096-ir-synthetic-array-chain.test.ts`, `n101-ir-stateful-scaffold.test.ts`,
 * `r126-add-output-arity-ir.test.ts`, `f283-ir-loop-product-bound.test.ts`,
 * and `n065-reserved-names.test.ts`, which already exercise the real loader
 * for those specific rules).
 */

import { describe, it, expect } from 'vitest';
import { loadANFFromJSON, compileFromANF } from '../index.js';
import type { ANFProgram } from '../ir/index.js';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('IR Loader: loadANFFromJSON (the real --from-ir entry point)', () => {
  // -------------------------------------------------------------------------
  // Minimal valid IR
  // -------------------------------------------------------------------------

  describe('minimal valid IR', () => {
    it('loads an IR with empty methods list and no properties (row 315)', () => {
      // An IR with no methods and no properties is structurally valid.
      const json = JSON.stringify({
        contractName: 'Empty',
        properties: [],
        methods: [],
      });
      const program = loadANFFromJSON(json);
      expect(program.contractName).toBe('Empty');
      expect(program.properties).toHaveLength(0);
      expect(program.methods).toHaveLength(0);
    });

    it('loads a minimal valid ANF IR JSON into the correct structure', () => {
      const json = JSON.stringify({
        contractName: 'P2PKH',
        properties: [
          { name: 'pubKeyHash', type: 'Addr', readonly: true },
        ],
        methods: [
          {
            name: 'constructor',
            params: [{ name: 'pubKeyHash', type: 'Addr' }],
            body: [],
            isPublic: false,
          },
          {
            name: 'unlock',
            params: [
              { name: 'sig', type: 'Sig' },
              { name: 'pubKey', type: 'PubKey' },
            ],
            body: [
              { name: 't0', value: { kind: 'load_param', name: 'pubKey' } },
              { name: 't1', value: { kind: 'call', func: 'hash160', args: ['t0'] } },
              { name: 't2', value: { kind: 'load_prop', name: 'pubKeyHash' } },
              { name: 't3', value: { kind: 'bin_op', op: '===', left: 't1', right: 't2' } },
              { name: 't4', value: { kind: 'assert', value: 't3' } },
            ],
            isPublic: true,
          },
        ],
      });

      const program = loadANFFromJSON(json);
      expect(program.contractName).toBe('P2PKH');
      expect(program.properties).toHaveLength(1);
      expect(program.properties[0]!.name).toBe('pubKeyHash');
      expect(program.methods).toHaveLength(2);
      expect(program.methods[1]!.name).toBe('unlock');
      expect(program.methods[1]!.body).toHaveLength(5);
    });
  });

  // -------------------------------------------------------------------------
  // Constant decoding
  // -------------------------------------------------------------------------

  describe('constants decoded correctly', () => {
    it('converts an integer constant (JSON number) in load_const to bigint', () => {
      // Real behavior, NOT the toy loader's: `coerceNumericBigInts` converts
      // `load_const.value` JSON numbers to `bigint` because ANF's
      // `LoadConst.value` is typed `bigint`. The toy loader's comment
      // ("bigint conversion is caller's job") described its own design, not
      // production's.
      const json = JSON.stringify({
        contractName: 'ConstTest',
        properties: [],
        methods: [
          {
            name: 'check',
            params: [{ name: 'x', type: 'bigint' }],
            body: [
              { name: 't0', value: { kind: 'load_const', value: 42 } },
            ],
            isPublic: true,
          },
        ],
      });

      const program = loadANFFromJSON(json);
      const t0 = program.methods[0]!.body[0]!;
      expect(t0.value.kind).toBe('load_const');
      const value = (t0.value as { kind: string; value: unknown }).value;
      expect(typeof value).toBe('bigint');
      expect(value).toBe(42n);
    });

    it('preserves boolean constant in load_const', () => {
      const json = JSON.stringify({
        contractName: 'BoolTest',
        properties: [],
        methods: [
          {
            name: 'check',
            params: [],
            body: [
              { name: 't0', value: { kind: 'load_const', value: true } },
            ],
            isPublic: true,
          },
        ],
      });

      const program = loadANFFromJSON(json);
      const t0 = program.methods[0]!.body[0]!;
      expect((t0.value as { kind: string; value: unknown }).value).toBe(true);
    });

    it('preserves hex string constant in load_const', () => {
      const json = JSON.stringify({
        contractName: 'HexTest',
        properties: [],
        methods: [
          {
            name: 'check',
            params: [],
            body: [
              { name: 't0', value: { kind: 'load_const', value: 'deadbeef' } },
            ],
            isPublic: true,
          },
        ],
      });

      const program = loadANFFromJSON(json);
      const t0 = program.methods[0]!.body[0]!;
      expect((t0.value as { kind: string; value: unknown }).value).toBe('deadbeef');
    });
  });

  // -------------------------------------------------------------------------
  // Unknown ANF kind — the loader does not check it; compileFromANF does
  // -------------------------------------------------------------------------

  describe('unknown ANF kind', () => {
    it('is NOT rejected by loadANFFromJSON itself, but is rejected before any script is produced', () => {
      // `loadANFFromJSON` runs `checkValue` (anf-required-fields.ts), whose
      // `default` case explicitly defers kind validation: "Unknown kinds are
      // refused elsewhere." Confirmed here: loading does not throw.
      const json = JSON.stringify({
        contractName: 'Bad',
        properties: [],
        methods: [
          {
            name: 'check',
            params: [],
            body: [
              { name: 't0', value: { kind: 'bogus_kind' } },
              { name: 't1', value: { kind: 'assert', value: 't0' } },
            ],
            isPublic: true,
          },
        ],
      });

      const program = loadANFFromJSON(json);
      expect(program.methods[0]!.body[0]!.value.kind).toBe('bogus_kind');

      // "Elsewhere" is compileFromANF -> stack-lowering's exhaustive kind
      // dispatch, which has no catch-all and throws on anything it doesn't
      // recognize. This is where garbage kind data actually gets refused.
      expect(() => compileFromANF(program)).toThrow(/Unknown ANF kind 'bogus_kind'/);
    });
  });

  // -------------------------------------------------------------------------
  // Empty names/types: NOT rejected by the real loader (toy-loader-only
  // behavior — documented explicitly per remediation brief F-289)
  // -------------------------------------------------------------------------

  describe('empty identifiers: accepted by the real loader (not toy-loader-only anymore)', () => {
    // The original file's six "empty X -> error" tests asserted a rule the
    // toy loader invented. `assertRequiredIrFields` (the real check) only
    // validates presence and JSON type, not non-emptiness, so an empty
    // string satisfies "is a string" and passes. These are kept — now
    // pinning the REAL, current behavior rather than a fictional stricter
    // one — so a future change that starts rejecting empty identifiers (a
    // legitimate, separate hardening item) shows up here as a deliberate,
    // visible diff instead of silently passing either way.

    it('does not throw for an empty contractName', () => {
      const json = JSON.stringify({ contractName: '', properties: [], methods: [] });
      expect(() => loadANFFromJSON(json)).not.toThrow();
    });

    it('does not throw for an empty method name', () => {
      const json = JSON.stringify({
        contractName: 'Test',
        properties: [],
        methods: [{ name: '', params: [], body: [], isPublic: false }],
      });
      expect(() => loadANFFromJSON(json)).not.toThrow();
    });

    it('does not throw for an empty method param name', () => {
      const json = JSON.stringify({
        contractName: 'Test',
        properties: [],
        methods: [
          {
            name: 'check',
            params: [{ name: '', type: 'bigint' }],
            body: [],
            isPublic: true,
          },
        ],
      });
      expect(() => loadANFFromJSON(json)).not.toThrow();
    });

    it('does not throw for an empty method param type', () => {
      const json = JSON.stringify({
        contractName: 'Test',
        properties: [],
        methods: [
          {
            name: 'check',
            params: [{ name: 'x', type: '' }],
            body: [],
            isPublic: true,
          },
        ],
      });
      expect(() => loadANFFromJSON(json)).not.toThrow();
    });

    it('does not throw for an empty property name', () => {
      const json = JSON.stringify({
        contractName: 'Test',
        properties: [{ name: '', type: 'bigint', readonly: true }],
        methods: [],
      });
      expect(() => loadANFFromJSON(json)).not.toThrow();
    });

    it('does not throw for an empty property type', () => {
      const json = JSON.stringify({
        contractName: 'Test',
        properties: [{ name: 'x', type: '', readonly: true }],
        methods: [],
      });
      expect(() => loadANFFromJSON(json)).not.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // Validation errors the real loader DOES enforce: loop bounds (F-283 /
  // CL-BUG-088). These assertions already held against production code
  // unchanged; only the loader under test has changed.
  // -------------------------------------------------------------------------

  describe('negative loop count → error', () => {
    it('throws when a loop binding has count < 0', () => {
      const json = JSON.stringify({
        contractName: 'Test',
        properties: [],
        methods: [
          {
            name: 'run',
            params: [],
            body: [
              { name: 't0', value: { kind: 'loop', count: -1, iterVar: 'i', body: [] } },
            ],
            isPublic: true,
          },
        ],
      });
      expect(() => loadANFFromJSON(json)).toThrow(/negative loop count/i);
    });
  });

  describe('excessive loop count → error', () => {
    it('throws when a loop binding has count exceeding the maximum', () => {
      // Count intentionally hard-coded (not MAX_LOOP_COUNT + 1): this test
      // exists to catch a regression in the PRODUCTION bound itself, so it
      // must not import the same constant the code under test reads — an
      // off-by-one or weakened bound in production would move both together
      // and this test would stay green. 10001 is the first value above the
      // documented limit of 10000 (F-283 / CL-BUG-088).
      const json = JSON.stringify({
        contractName: 'Test',
        properties: [],
        methods: [
          {
            name: 'run',
            params: [],
            body: [
              {
                name: 't0',
                value: { kind: 'loop', count: 10001, iterVar: 'i', body: [] },
              },
            ],
            isPublic: true,
          },
        ],
      });
      expect(() => loadANFFromJSON(json)).toThrow(/exceeding maximum/i);
    });
  });

  // -------------------------------------------------------------------------
  // Invalid JSON
  // -------------------------------------------------------------------------

  describe('invalid JSON → error', () => {
    it('throws for malformed JSON input', () => {
      // Real message is "input is not valid JSON: ...", not the toy loader's
      // "invalid IR JSON: ...".
      expect(() => loadANFFromJSON('{not valid json')).toThrow(/not valid JSON/i);
    });

    it('throws for completely empty input', () => {
      expect(() => loadANFFromJSON('')).toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // Round-trip: JSON serialize + deserialize preserves structure
  // -------------------------------------------------------------------------

  describe('round-trip: serialize → deserialize preserves all fields', () => {
    it('preserves contractName, properties, and methods', () => {
      const original: ANFProgram = {
        contractName: 'RoundTrip',
        properties: [
          { name: 'target', type: 'bigint', readonly: true },
        ],
        methods: [
          {
            name: 'constructor',
            params: [{ name: 'target', type: 'bigint' }],
            body: [],
            isPublic: false,
          },
          {
            name: 'check',
            params: [{ name: 'x', type: 'bigint' }],
            body: [
              { name: 't0', value: { kind: 'load_param', name: 'x' } },
              { name: 't1', value: { kind: 'load_const', value: 42n } },
              { name: 't2', value: { kind: 'bin_op', op: '===', left: 't0', right: 't1' } },
              { name: 't3', value: { kind: 'assert', value: 't2' } },
            ],
            isPublic: true,
          },
        ],
      };

      // Serialize: bigints need to be converted to numbers for JSON (the
      // native non-TS emitters do the same for safe-integer values).
      const json = JSON.stringify(original, (_k, v) =>
        typeof v === 'bigint' ? Number(v) : v,
      );

      const loaded = loadANFFromJSON(json);

      expect(loaded.contractName).toBe(original.contractName);
      expect(loaded.properties).toHaveLength(original.properties.length);
      expect(loaded.properties[0]!.name).toBe('target');
      expect(loaded.properties[0]!.type).toBe('bigint');
      expect(loaded.methods).toHaveLength(original.methods.length);
      expect(loaded.methods[1]!.name).toBe('check');
      expect(loaded.methods[1]!.body).toHaveLength(4);
    });

    it('preserves initialValue field on a property', () => {
      const json = JSON.stringify({
        contractName: 'InitTest',
        properties: [
          { name: 'value', type: 'bigint', readonly: true, initialValue: 100 },
        ],
        methods: [
          {
            name: 'check',
            params: [],
            body: [
              { name: 't0', value: { kind: 'load_const', value: true } },
              { name: 't1', value: { kind: 'assert', value: 't0' } },
            ],
            isPublic: true,
          },
        ],
      });

      const program = loadANFFromJSON(json);
      expect(program.properties).toHaveLength(1);
      const prop = program.properties[0]!;
      // initialValue is preserved from JSON. The real loader coerces it to
      // bigint (ANFProperty.initialValue is bigint-typed); Number(...) works
      // whether the underlying value is a number or a bigint.
      expect(prop.initialValue).toBeDefined();
      expect(Number(prop.initialValue)).toBe(100);
    });

    it('preserves if and loop binding nodes through round-trip', () => {
      const json = JSON.stringify({
        contractName: 'Nested',
        properties: [],
        methods: [
          {
            name: 'test',
            params: [],
            body: [
              { name: 'cond', value: { kind: 'load_const', value: true } },
              {
                name: 'ifExpr',
                value: {
                  kind: 'if',
                  cond: 'cond',
                  then: [
                    { name: 't', value: { kind: 'load_const', value: 1 } },
                  ],
                  else: [
                    { name: 'e', value: { kind: 'load_const', value: 2 } },
                  ],
                },
              },
              {
                name: 'loopExpr',
                value: {
                  kind: 'loop',
                  count: 5,
                  iterVar: 'i',
                  body: [
                    { name: 'lb', value: { kind: 'load_const', value: 0 } },
                  ],
                },
              },
            ],
            isPublic: true,
          },
        ],
      });

      const program = loadANFFromJSON(json);
      expect(program.contractName).toBe('Nested');
      expect(program.methods).toHaveLength(1);

      const body = program.methods[0]!.body;
      expect(body).toHaveLength(3);

      // if-binding survived
      const ifBinding = body[1]!;
      expect((ifBinding.value as unknown as Record<string, unknown>)['kind']).toBe('if');
      expect((ifBinding.value as unknown as Record<string, unknown>)['cond']).toBe('cond');
      const thenBindings = (ifBinding.value as unknown as Record<string, unknown>)['then'] as unknown[];
      const elseBindings = (ifBinding.value as unknown as Record<string, unknown>)['else'] as unknown[];
      expect(thenBindings).toHaveLength(1);
      expect(elseBindings).toHaveLength(1);

      // loop-binding survived
      const loopBinding = body[2]!;
      expect((loopBinding.value as unknown as Record<string, unknown>)['kind']).toBe('loop');
      expect((loopBinding.value as unknown as Record<string, unknown>)['count']).toBe(5);
      expect((loopBinding.value as unknown as Record<string, unknown>)['iterVar']).toBe('i');
      const loopBody = (loopBinding.value as unknown as Record<string, unknown>)['body'] as unknown[];
      expect(loopBody).toHaveLength(1);
    });
  });
});
