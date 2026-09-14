/**
 * R-246 (CL-GAP-084), the TypeScript half.
 *
 * `validatePropertyType` refuses any `custom_type` and accepts a
 * `primitive_type` whose name is not in VALID_PRIMITIVE_TYPES — unless it is
 * spelled `void`:
 *
 *   case 'primitive_type':
 *     if (!VALID_PRIMITIVE_TYPES.has(type.name)) {
 *       if (type.name === 'void') { …error… }   // and nothing else
 *     }
 *     break;
 *
 * One property, two spellings of the same unknown name, two answers. The finding
 * was filed against the Python tier; go, ruby and this one share it verbatim,
 * while rust, java and zig already refuse both.
 *
 * No parser produces a `primitive_type` with an unknown name today — they all
 * map an unrecognised name to `custom_type` — but `validate()` takes an AST, and
 * the frontend is not the only thing that builds one.
 */

import { describe, it, expect } from 'vitest';
import { validate } from '../passes/02-validate.js';
import type { ContractNode, TypeNode } from '../ir/index.js';

const LOC = { file: 'Probe.runar.ts', line: 1, column: 1 };

function contractWithPropertyType(type: TypeNode): ContractNode {
  return {
    kind: 'contract',
    name: 'Probe',
    parentClass: 'SmartContract',
    properties: [{ kind: 'property', name: 'p', type, readonly: true, sourceLocation: LOC }],
    constructor: {
      kind: 'method',
      name: 'constructor',
      params: [],
      body: [],
      isPublic: true,
      sourceLocation: LOC,
    },
    methods: [],
    sourceFile: 'Probe.runar.ts',
    sourceLocation: LOC,
  } as unknown as ContractNode;
}

/** Only the diagnostics about the property's TYPE. */
function propertyTypeErrors(type: TypeNode): string[] {
  return validate(contractWithPropertyType(type))
    .errors.map((d) => d.message)
    .filter((m) => /type/i.test(m));
}

const prim = (name: string): TypeNode =>
  ({ kind: 'primitive_type', name } as unknown as TypeNode);
const custom = (name: string): TypeNode =>
  ({ kind: 'custom_type', name } as unknown as TypeNode);
const array = (element: TypeNode, length: number): TypeNode =>
  ({ kind: 'fixed_array_type', element, length } as unknown as TypeNode);

describe('R-246: an unknown property type is refused however it is spelled', () => {
  it('accepts a valid primitive (without this, "refuse everything" passes)', () => {
    expect(propertyTypeErrors(prim('bigint'))).toEqual([]);
  });

  it('refuses an unknown custom type — the half that already worked', () => {
    expect(propertyTypeErrors(custom('Foobarium')).join('\n')).toMatch(/Foobarium/);
  });

  it("refuses 'void'", () => {
    expect(propertyTypeErrors(prim('void')).join('\n')).toMatch(/void/i);
  });

  it('refuses an unknown PRIMITIVE type as well', () => {
    const errs = propertyTypeErrors(prim('Foobarium'));
    expect(
      errs.join('\n'),
      'an unknown primitive_type passed validation while the identical name as a ' +
        'custom_type is refused',
    ).toMatch(/Foobarium/);
  });

  it('reaches a FixedArray element type', () => {
    expect(propertyTypeErrors(array(prim('Foobarium'), 3)).join('\n')).toMatch(/Foobarium/);
  });

  it('still accepts a valid FixedArray', () => {
    expect(propertyTypeErrors(array(prim('bigint'), 3))).toEqual([]);
  });
});
