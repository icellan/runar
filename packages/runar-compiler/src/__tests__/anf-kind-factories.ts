/**
 * Minimal-value factories per ANF kind, used by
 * `anf-kind-enumeration.test.ts` to drive every TS dispatch site with a
 * *valid* value of every kind in the `ANFValue` discriminated union.
 *
 * "Valid" here means: structurally well-formed per the schema in
 * `packages/runar-ir-schema/src/anf-ir.ts`. The factories are NOT
 * required to produce a *semantically* meaningful value — the
 * enumeration test only checks that the dispatch site does not throw
 * `UnknownANFKindError`. Other downstream errors (stack underflow,
 * unknown builtin, etc.) are acceptable: they prove the kind reached a
 * handler other than the silent-default / unknown-kind branch.
 *
 * If a new ANFValue variant is added, add a factory here AND add the
 * kind to `ALL_ANF_KINDS` in `anf-kind-enumeration.test.ts`. The
 * type-level coverage check there will fail the build if you miss step
 * two; this file will fail to compile if you miss step one.
 */

import type { ANFValue } from '../ir/index.js';

export type AnfKind = ANFValue['kind'];

/** Build a minimal valid value of the given kind. */
export function minimalValueFor(kind: AnfKind): ANFValue {
  switch (kind) {
    case 'load_param':
      return { kind: 'load_param', name: 'p0' };
    case 'load_prop':
      return { kind: 'load_prop', name: 'prop0' };
    case 'load_const':
      return { kind: 'load_const', value: 0n };
    case 'bin_op':
      return { kind: 'bin_op', op: '+', left: 'a', right: 'b' };
    case 'unary_op':
      return { kind: 'unary_op', op: '-', operand: 'a' };
    case 'call':
      return { kind: 'call', func: 'sha256', args: ['a'] };
    case 'method_call':
      return { kind: 'method_call', object: 'self', method: 'm', args: [] };
    case 'if':
      return { kind: 'if', cond: 'c', then: [], else: [] };
    case 'loop':
      return { kind: 'loop', count: 1, body: [], iterVar: 'i' };
    case 'assert':
      return { kind: 'assert', value: 'v' };
    case 'update_prop':
      return { kind: 'update_prop', name: 'prop0', value: 'v' };
    case 'get_state_script':
      return { kind: 'get_state_script' };
    case 'check_preimage':
      return { kind: 'check_preimage', preimage: 'pi' };
    case 'deserialize_state':
      return { kind: 'deserialize_state', preimage: 'pi' };
    case 'add_output':
      return {
        kind: 'add_output',
        satoshis: 'sats',
        stateValues: ['v'],
        preimage: 'pi',
      };
    case 'add_raw_output':
      return { kind: 'add_raw_output', satoshis: 'sats', scriptBytes: 'sb' };
    case 'add_data_output':
      return { kind: 'add_data_output', satoshis: 'sats', scriptBytes: 'sb' };
    case 'array_literal':
      return { kind: 'array_literal', elements: ['a', 'b'] };
    case 'raw_script':
      // Empty span with declared zero arity — the simplest legal raw_script.
      return { kind: 'raw_script', bytes: '', in_arity: 0, out_arity: 0 };
    default: {
      // Exhaustiveness guard — TypeScript will flag a missing case here
      // if a new ANFValue variant is added to the schema.
      const _exhaustive: never = kind;
      throw new Error(`minimalValueFor: missing case for kind '${_exhaustive as string}'`);
    }
  }
}
