/**
 * The complete ANF node-kind vocabulary, in one place.
 *
 * Extracted from `anf-kind-enumeration.test.ts` under R-098 so that a second
 * consumer — `spec-coverage.test.ts`, which requires `spec/ir-format.md` to
 * document every kind — reads the same list rather than keeping a copy. A
 * second copy of a vocabulary is a second thing to drift, and drift between the
 * spec and the implementation is exactly what R-098 is.
 *
 * The type-level gate that keeps this list honest against `ANFValue['kind']`
 * stays in `anf-kind-enumeration.test.ts`, which imports this.
 */
export const ALL_ANF_KINDS = [
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
