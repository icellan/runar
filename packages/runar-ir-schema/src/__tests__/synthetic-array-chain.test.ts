import { describe, it, expect } from 'vitest';
import { validateANF } from '../validators.js';

// ---------------------------------------------------------------------------
// N-095 — `syntheticArrayChain` on ANFProperty.
//
// The expand-fixed-arrays pass desugars a `FixedArray` property into scalar
// siblings and hangs a chain of `{base, index, length}` levels off each leaf.
// Every native tier's artifact assembler regroups those siblings back into a
// single (possibly nested) FixedArray state field by reading that chain off
// the ANF -- NOT off the AST -- so the field is load-bearing on the wire:
// drop it and the SDK's `state.grid` accessor degrades into four raw scalars.
//
// `$defs.ANFProperty` is `additionalProperties: false`, so until the field is
// declared here every tier that emits it fails its own schema. The spelling is
// `syntheticArrayChain`: `ANFProperty`'s only other optional field is
// `initialValue` (lowerCamelCase), the regrouped artifact field is already
// `fixedArray.syntheticNames`, and the schema's three snake_case fields
// (`result_type`, `in_arity`, `out_arity`) live on BinOp/UnaryOp/RawScript,
// not here. The `__`-prefix is a TS *AST* convention for compiler-internal
// annotations and has no business on the wire.
// ---------------------------------------------------------------------------

function programWithProperty(prop: Record<string, unknown>) {
  return {
    contractName: 'Grid2x2',
    properties: [prop],
    methods: [
      {
        name: 'set00',
        params: [{ name: 'v', type: 'bigint' }],
        body: [{ name: 't0', value: { kind: 'load_param', name: 'v' } }],
        isPublic: true,
      },
    ],
  };
}

const CHAIN = [
  { base: 'grid', index: 0, length: 2 },
  { base: 'grid__0', index: 0, length: 2 },
];

describe('N-095: ANFProperty.syntheticArrayChain', () => {
  it('accepts the canonical camelCase spelling', () => {
    const result = validateANF(
      programWithProperty({
        name: 'grid__0__0',
        type: 'bigint',
        readonly: false,
        initialValue: 0,
        syntheticArrayChain: CHAIN,
      }),
    );
    expect(result.valid ? [] : result.errors).toEqual([]);
  });

  it('still accepts a property with no chain at all', () => {
    const result = validateANF(
      programWithProperty({ name: 'count', type: 'bigint', readonly: false }),
    );
    expect(result.valid).toBe(true);
  });

  it.each(['__syntheticArrayChain', 'synthetic_array_chain'])(
    'rejects the divergent spelling %s',
    (key) => {
      const result = validateANF(
        programWithProperty({
          name: 'grid__0__0',
          type: 'bigint',
          readonly: false,
          [key]: CHAIN,
        }),
      );
      expect(result.valid).toBe(false);
    },
  );

  it('requires base/index/length on every level', () => {
    for (const bad of [
      [{ index: 0, length: 2 }],
      [{ base: 'grid', length: 2 }],
      [{ base: 'grid', index: 0 }],
      [{ base: 'grid', index: 0, length: 2, extra: 1 }],
      [{ base: 'grid', index: '0', length: 2 }],
    ]) {
      const result = validateANF(
        programWithProperty({
          name: 'grid__0__0',
          type: 'bigint',
          readonly: false,
          syntheticArrayChain: bad,
        }),
      );
      expect(result.valid, JSON.stringify(bad)).toBe(false);
    }
  });
});
