import { describe, it, expect } from 'vitest';
import { validateANF } from '../validators.js';

// ---------------------------------------------------------------------------
// F-038 / F-065 / F-066 / F-070 / F-088 — `parentClass` on the program and
// `sigHashType` on a method are wire data.
//
// Both used to be in-memory carriers only (Go `json:"-"`, Rust `serde(skip)`,
// Python/Ruby/Java exclusion lists), so an `--emit-ir` -> `--ir` round trip
// produced an artifact with no `parentClass` (the SDK then skips the issue-#44
// subscript trim for a StatefulSmartContract with zero mutable fields) and no
// method `sigHashType` (the SDK then signs a SINGLE|FORKID covenant's preimage
// as ALL|FORKID). Both keys are declared here so every tier can carry them.
//
// What this proves: the canonical schema accepts the two keys with their legal
// values and refuses anything else under those names. What it does not prove:
// that any tier emits or reads them (conformance/ir-roundtrip does that).
// ---------------------------------------------------------------------------

function program(extra: Record<string, unknown>, methodExtra: Record<string, unknown> = {}) {
  return {
    contractName: 'P',
    properties: [{ name: 'pk', type: 'PubKey', readonly: true }],
    methods: [
      {
        name: 'unlock',
        params: [{ name: 'sig', type: 'Sig' }],
        body: [{ name: 't0', value: { kind: 'load_param', name: 'sig' } }],
        isPublic: true,
        ...methodExtra,
      },
    ],
    ...extra,
  };
}

describe('F-038: ANFProgram.parentClass', () => {
  it.each(['SmartContract', 'StatefulSmartContract', 'UnsafeSmartContract'])(
    'accepts %s',
    (parentClass) => {
      const result = validateANF(program({ parentClass }));
      expect(result.valid ? [] : result.errors).toEqual([]);
    },
  );

  it('still accepts a program without it (IR written before F-038)', () => {
    expect(validateANF(program({})).valid).toBe(true);
  });

  it.each([['Contract'], [''], [1], [null]])('rejects %j', (parentClass) => {
    expect(validateANF(program({ parentClass })).valid).toBe(false);
  });

  it('rejects the snake_case spelling', () => {
    expect(validateANF(program({ parent_class: 'SmartContract' })).valid).toBe(false);
  });
});

describe('F-065 / F-088: ANFMethod.sigHashType', () => {
  it.each([0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3])('accepts the FORKID mode %i', (sigHashType) => {
    const result = validateANF(program({}, { sigHashType }));
    expect(result.valid ? [] : result.errors).toEqual([]);
  });

  // 0x01/0x03: no FORKID (deploy-to-brick on BSV); 0x40: no base type;
  // 0x44: an unknown base type; '0x43': a string.
  it.each([[0x01], [0x03], [0x40], [0x44], [0x100], ['0x43']])('rejects %j', (sigHashType) => {
    expect(validateANF(program({}, { sigHashType })).valid).toBe(false);
  });

  it('rejects the snake_case spelling', () => {
    expect(validateANF(program({}, { sighash_type: 0x43 })).valid).toBe(false);
  });
});
