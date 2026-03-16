/**
 * IR Loader unit tests.
 *
 * The TypeScript compiler does not ship a separate file-based IR loader (it
 * operates on in-memory ANFProgram objects produced by the ANF lowering pass).
 * However, ANF IR is exchanged with Go/Rust/Python compilers as JSON, so we
 * validate JSON round-trips and structural constraints here.
 *
 * This file implements a minimal `loadANFFromJson` helper (analogous to Go's
 * `LoadIRFromBytes`) and exercises the same test cases that Go and Rust cover.
 */

import { describe, it, expect } from 'vitest';
import type {
  ANFProgram,
  ANFBinding,
  ANFValue,
} from '../ir/index.js';

// ---------------------------------------------------------------------------
// Minimal IR loader — JSON parse + structural validation
// (mirrors the Go `LoadIRFromBytes` / `ValidateIR` API)
// ---------------------------------------------------------------------------

const MAX_LOOP_COUNT = 10000;

const KNOWN_KINDS = new Set([
  'load_param',
  'load_prop',
  'load_const',
  'bin_op',
  'unary_op',
  'call',
  'method_call',
  'if',
  'loop',
  'assert',
  'update_prop',
  'get_state_script',
  'check_preimage',
  'deserialize_state',
  'add_output',
  'add_raw_output',
]);

/**
 * Parse and validate an ANF IR JSON string.
 *
 * Throws an Error if the JSON is malformed, structurally invalid, or violates
 * any of the IR constraints (empty names, unknown kinds, loop bounds, etc.).
 */
function loadANFFromJson(json: string): ANFProgram {
  // 1. Parse JSON
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch (e: unknown) {
    throw new Error(`invalid IR JSON: ${e instanceof Error ? e.message : String(e)}`);
  }

  const program = raw as ANFProgram;

  // 2. Structural validation
  validateIR(program);

  return program;
}

function validateIR(program: ANFProgram): void {
  if (!program.contractName) {
    throw new Error('IR validation: contractName is required');
  }

  for (let i = 0; i < (program.properties ?? []).length; i++) {
    const prop = program.properties[i]!;
    if (!prop.name) {
      throw new Error(`IR validation: property[${i}] has empty name`);
    }
    if (!prop.type) {
      throw new Error(`IR validation: property ${prop.name} has empty type`);
    }
  }

  for (let i = 0; i < (program.methods ?? []).length; i++) {
    const method = program.methods[i]!;
    if (!method.name) {
      throw new Error(`IR validation: method[${i}] has empty name`);
    }
    for (let j = 0; j < (method.params ?? []).length; j++) {
      const param = method.params[j]!;
      if (!param.name) {
        throw new Error(`IR validation: method ${method.name} param[${j}] has empty name`);
      }
      if (!param.type) {
        throw new Error(`IR validation: method ${method.name} param ${param.name} has empty type`);
      }
    }
    validateBindings(method.body ?? [], method.name);
  }
}

function validateBindings(bindings: ANFBinding[], methodName: string): void {
  for (let i = 0; i < bindings.length; i++) {
    const binding = bindings[i]!;
    if (!binding.name) {
      throw new Error(`IR validation: method ${methodName} binding[${i}] has empty name`);
    }
    const kind = (binding.value as unknown as Record<string, unknown>)['kind'] as string | undefined;
    if (!kind) {
      throw new Error(`IR validation: method ${methodName} binding ${binding.name} has empty kind`);
    }
    if (!KNOWN_KINDS.has(kind)) {
      throw new Error(
        `IR validation: method ${methodName} binding ${binding.name} has unknown kind "${kind}"`,
      );
    }

    // Validate nested bindings
    if (kind === 'if') {
      const ifVal = binding.value as { then?: ANFBinding[]; else?: ANFBinding[] };
      validateBindings(ifVal.then ?? [], methodName);
      validateBindings(ifVal.else ?? [], methodName);
    }
    if (kind === 'loop') {
      const loopVal = binding.value as { count?: number; body?: ANFBinding[] };
      const count = loopVal.count ?? 0;
      if (count < 0) {
        throw new Error(
          `IR validation: method ${methodName} binding ${binding.name} has negative loop count ${count}`,
        );
      }
      if (count > MAX_LOOP_COUNT) {
        throw new Error(
          `IR validation: method ${methodName} binding ${binding.name} has loop count ${count} exceeding maximum ${MAX_LOOP_COUNT}`,
        );
      }
      validateBindings(loopVal.body ?? [], methodName);
    }
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('IR Loader: loadANFFromJson', () => {
  // -------------------------------------------------------------------------
  // Minimal valid IR
  // -------------------------------------------------------------------------

  describe('minimal valid IR', () => {
    it('loads an IR with empty methods list and no properties (row 315)', () => {
      // An IR with no methods and no properties should be structurally valid.
      // (The validator only rejects empty names, not empty collections.)
      const json = JSON.stringify({
        contractName: 'Empty',
        properties: [],
        methods: [],
      });
      const program = loadANFFromJson(json);
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

      const program = loadANFFromJson(json);
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
    it('preserves integer constant (JSON number) in load_const', () => {
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

      const program = loadANFFromJson(json);
      const t0 = program.methods[0]!.body[0]!;
      expect(t0.value.kind).toBe('load_const');
      // JSON numbers arrive as JS numbers here (bigint conversion is caller's job)
      expect((t0.value as { kind: string; value: unknown }).value).toBe(42);
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

      const program = loadANFFromJson(json);
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

      const program = loadANFFromJson(json);
      const t0 = program.methods[0]!.body[0]!;
      expect((t0.value as { kind: string; value: unknown }).value).toBe('deadbeef');
    });
  });

  // -------------------------------------------------------------------------
  // Validation errors: unknown kind
  // -------------------------------------------------------------------------

  describe('unknown ANF kind → error', () => {
    it('throws for a binding with an unknown kind', () => {
      const json = JSON.stringify({
        contractName: 'Bad',
        properties: [],
        methods: [
          {
            name: 'check',
            params: [],
            body: [
              { name: 't0', value: { kind: 'bogus_kind' } },
            ],
            isPublic: true,
          },
        ],
      });

      expect(() => loadANFFromJson(json)).toThrow(/unknown kind.*bogus_kind/i);
    });
  });

  // -------------------------------------------------------------------------
  // Validation errors: empty fields
  // -------------------------------------------------------------------------

  describe('empty contractName → error', () => {
    it('throws when contractName is empty string', () => {
      const json = JSON.stringify({
        contractName: '',
        properties: [],
        methods: [],
      });
      expect(() => loadANFFromJson(json)).toThrow(/contractName is required/i);
    });
  });

  describe('empty method name → error', () => {
    it('throws when a method has an empty name', () => {
      const json = JSON.stringify({
        contractName: 'Test',
        properties: [],
        methods: [
          { name: '', params: [], body: [], isPublic: false },
        ],
      });
      expect(() => loadANFFromJson(json)).toThrow(/empty name/i);
    });
  });

  describe('empty param name → error', () => {
    it('throws when a method param has an empty name', () => {
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
      expect(() => loadANFFromJson(json)).toThrow(/empty name/i);
    });
  });

  describe('empty param type → error', () => {
    it('throws when a method param has an empty type', () => {
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
      expect(() => loadANFFromJson(json)).toThrow(/empty type/i);
    });
  });

  describe('empty property name → error', () => {
    it('throws when a property has an empty name', () => {
      const json = JSON.stringify({
        contractName: 'Test',
        properties: [{ name: '', type: 'bigint', readonly: true }],
        methods: [],
      });
      expect(() => loadANFFromJson(json)).toThrow(/empty name/i);
    });
  });

  describe('empty property type → error', () => {
    it('throws when a property has an empty type', () => {
      const json = JSON.stringify({
        contractName: 'Test',
        properties: [{ name: 'x', type: '', readonly: true }],
        methods: [],
      });
      expect(() => loadANFFromJson(json)).toThrow(/empty type/i);
    });
  });

  // -------------------------------------------------------------------------
  // Validation errors: loop bounds
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
      expect(() => loadANFFromJson(json)).toThrow(/negative loop count/i);
    });
  });

  describe('excessive loop count → error', () => {
    it(`throws when a loop binding has count > ${MAX_LOOP_COUNT}`, () => {
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
                value: { kind: 'loop', count: MAX_LOOP_COUNT + 1, iterVar: 'i', body: [] },
              },
            ],
            isPublic: true,
          },
        ],
      });
      expect(() => loadANFFromJson(json)).toThrow(/exceeding maximum/i);
    });
  });

  // -------------------------------------------------------------------------
  // Invalid JSON
  // -------------------------------------------------------------------------

  describe('invalid JSON → error', () => {
    it('throws for malformed JSON input', () => {
      expect(() => loadANFFromJson('{not valid json')).toThrow(/invalid IR JSON/i);
    });

    it('throws for completely empty input', () => {
      expect(() => loadANFFromJson('')).toThrow();
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
              { name: 't0', value: { kind: 'load_param', name: 'x' } as ANFValue },
              { name: 't1', value: { kind: 'load_const', value: 42n } as ANFValue },
              { name: 't2', value: { kind: 'bin_op', op: '===', left: 't0', right: 't1' } as ANFValue },
              { name: 't3', value: { kind: 'assert', value: 't2' } as ANFValue },
            ],
            isPublic: true,
          },
        ],
      };

      // Serialize: bigints need to be converted to numbers for JSON
      const json = JSON.stringify(original, (_k, v) =>
        typeof v === 'bigint' ? Number(v) : v,
      );

      const loaded = loadANFFromJson(json);

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

      const program = loadANFFromJson(json);
      expect(program.properties).toHaveLength(1);
      const prop = program.properties[0]!;
      // initialValue is preserved from JSON (as a number/bigint depending on context)
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

      const program = loadANFFromJson(json);
      expect(program.contractName).toBe('Nested');
      expect(program.methods).toHaveLength(1);

      const body = program.methods[0]!.body;
      expect(body).toHaveLength(3);

      // if-binding survived
      const ifBinding = body[1]!;
      expect((ifBinding.value as unknown as Record<string, unknown>)['kind']).toBe('if');
      expect((ifBinding.value as unknown as Record<string, unknown>)['cond']).toBe('cond');
      const thenBindings = (ifBinding.value as unknown as Record<string, unknown>)['then'] as ANFBinding[];
      const elseBindings = (ifBinding.value as unknown as Record<string, unknown>)['else'] as ANFBinding[];
      expect(thenBindings).toHaveLength(1);
      expect(elseBindings).toHaveLength(1);

      // loop-binding survived
      const loopBinding = body[2]!;
      expect((loopBinding.value as unknown as Record<string, unknown>)['kind']).toBe('loop');
      expect((loopBinding.value as unknown as Record<string, unknown>)['count']).toBe(5);
      expect((loopBinding.value as unknown as Record<string, unknown>)['iterVar']).toBe('i');
      const loopBody = (loopBinding.value as unknown as Record<string, unknown>)['body'] as ANFBinding[];
      expect(loopBody).toHaveLength(1);
    });
  });
});
