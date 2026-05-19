/**
 * Item 4 — ANF kind dispatch coverage gate.
 *
 * Companion to `unknown-anf-kind.test.ts` (Item 3 — proves the *negative*:
 * every dispatch site throws `UnknownANFKindError` when handed a kind
 * outside the schema). This file proves the *positive*: every kind that
 * IS in the schema is handled by every dispatch site (i.e. none of them
 * throw `UnknownANFKindError` for any in-schema kind).
 *
 * The combination prevents a regression where a developer adds a new
 * ANFValue variant and forgets to wire it into one of the dispatch sites
 * listed in CLAUDE.md § "Adding a New ANF Value Kind". Without this
 * gate, the omitted site would silently fall through to the
 * `UnknownANFKindError` throw (good — caught at runtime) but only if a
 * test happens to exercise that kind through that site. This file
 * eliminates the "happens to" by enumerating the cross product.
 *
 * Type-level gate: `ALL_ANF_KINDS` is checked against `ANFValue['kind']`
 * via two `Exclude<...>` checks below. Adding a kind to the schema
 * without listing it here makes the test file fail to typecheck.
 * Listing a kind here that's not in the schema does the same.
 */

import { describe, it, expect } from 'vitest';
import { UnknownANFKindError } from 'runar-ir-schema';
import type {
  ANFProgram,
  ANFMethod,
  ANFProperty,
  ANFBinding,
  ANFValue,
} from '../ir/index.js';
import { foldConstants, eliminateDeadBindings } from '../optimizer/constant-fold.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import { remapValueRefs } from '../passes/04-anf-lower.js';
import { minimalValueFor, type AnfKind } from './anf-kind-factories.js';

// ---------------------------------------------------------------------------
// Enumerated kinds
// ---------------------------------------------------------------------------

const ALL_ANF_KINDS = [
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
  'add_data_output',
  'array_literal',
  'raw_script',
] as const;

type ListedKind = (typeof ALL_ANF_KINDS)[number];

// Type-level coverage gate. Both `Exclude` results MUST be `never`:
//   - MissingKinds = kinds in the schema but not in ALL_ANF_KINDS
//   - ExtraKinds   = kinds in ALL_ANF_KINDS but not in the schema
// A failure here means tsc / vitest will refuse to compile this file,
// blocking the change at CI time before any test even runs.
type MissingKinds = Exclude<ANFValue['kind'], ListedKind>;
type ExtraKinds = Exclude<ListedKind, ANFValue['kind']>;
const _missingMustBeNever: MissingKinds extends never ? true : never = true;
const _extraMustBeNever: ExtraKinds extends never ? true : never = true;
// Suppress unused-locals warnings without weakening the gate.
void _missingMustBeNever;
void _extraMustBeNever;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Wrap a dispatch call. The contract: it MUST NOT throw
 * `UnknownANFKindError`. Any *other* error is acceptable — it proves the
 * dispatch reached a real handler rather than a silent default. The
 * factories build syntactically valid values but make no effort to
 * satisfy semantic preconditions (referenced names existing on the
 * stack, builtin functions being known, etc.), so downstream errors are
 * the expected case for several kinds.
 */
function expectNoUnknownKind(fn: () => unknown, kind: AnfKind, site: string): void {
  let caught: unknown;
  try {
    fn();
  } catch (e) {
    caught = e;
  }
  if (caught instanceof UnknownANFKindError) {
    throw new Error(
      `Dispatch site '${site}' threw UnknownANFKindError for in-schema kind '${kind}' ` +
        `(missing case in the switch). Error: ${caught.message}`,
    );
  }
}

/**
 * Build a single-method, single-binding program around the supplied
 * value. Includes a `prop0` property so kinds that touch properties
 * (`load_prop`, `update_prop`) have something to resolve against.
 */
function makeProgram(value: ANFValue): ANFProgram {
  const body: ANFBinding[] = [{ name: 't0', value }];
  const method: ANFMethod = {
    name: 'm',
    params: [{ name: 'p0', type: 'bigint' }],
    body,
    isPublic: true,
  };
  const properties: ANFProperty[] = [
    { name: 'prop0', type: 'bigint', readonly: false },
  ];
  return {
    contractName: 'CovTest',
    properties,
    methods: [method],
  };
}

// ---------------------------------------------------------------------------
// Tests — cross product of (kind, dispatch site)
// ---------------------------------------------------------------------------

describe('ANF kind dispatch coverage (Item 4)', () => {
  for (const kind of ALL_ANF_KINDS) {
    describe(`kind '${kind}'`, () => {
      it('foldConstants (constant-fold.foldValue)', () => {
        const program = makeProgram(minimalValueFor(kind));
        expectNoUnknownKind(
          () => foldConstants(program),
          kind,
          'constant-fold.foldValue',
        );
      });

      it('eliminateDeadBindings (collectRefsFromValue + hasSideEffect)', () => {
        const program = makeProgram(minimalValueFor(kind));
        expectNoUnknownKind(
          () => eliminateDeadBindings(program),
          kind,
          'constant-fold.{collectRefsFromValue,hasSideEffect}',
        );
      });

      it('lowerToStack (collectRefs + lowerBinding)', () => {
        const program = makeProgram(minimalValueFor(kind));
        expectNoUnknownKind(
          () => lowerToStack(program),
          kind,
          'stack-lower.{collectRefs,lowerBinding}',
        );
      });

      it('remapValueRefs (anf-lower.remapValueRefs)', () => {
        expectNoUnknownKind(
          () => remapValueRefs(minimalValueFor(kind), {}),
          kind,
          'anf-lower.remapValueRefs',
        );
      });
    });
  }

  it('ALL_ANF_KINDS has no duplicates', () => {
    const seen = new Set<string>();
    for (const k of ALL_ANF_KINDS) {
      expect(seen.has(k)).toBe(false);
      seen.add(k);
    }
    expect(seen.size).toBe(ALL_ANF_KINDS.length);
  });

  it('ALL_ANF_KINDS enumerates exactly the schema (length sanity)', () => {
    // 19 kinds at time of writing; this guard catches accidental drift
    // alongside the type-level Exclude<> gates above (belt-and-braces).
    expect(ALL_ANF_KINDS.length).toBe(19);
  });
});
