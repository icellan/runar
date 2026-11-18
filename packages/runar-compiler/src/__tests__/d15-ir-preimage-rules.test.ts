import { describe, it, expect } from 'vitest';
import type { ANFMethod, ANFProgram } from '../ir/index.js';
import { irPreimageRuleErrors } from '../passes/ir-preimage-rules.js';

/**
 * D15 rule internals: the IR preimage rules resolve a `method_call` exactly as
 * stack lowering inlines it (the LAST non-public, non-constructor method of
 * that name) and memoise per method body, never per name. The loaders also
 * refuse duplicate method names outright (ir-preimage-rules conformance test);
 * this pins the rule itself, so it never depends on that uniqueness alone.
 *
 * What it does not prove: the other six tiers' ports (their loaders refuse the
 * duplicate first; conformance/negatives/ir-preimage-rules.test.ts).
 */

const GK010 = "public method 'spend' must assert checkPreimage(p) on every path";
const D14 = (fn: string) => `${fn}() needs a checked SigHashPreimage`;

const m = (name: string, isPublic: boolean, params: ANFMethod['params'], body: ANFMethod['body']): ANFMethod =>
  ({ name, isPublic, params, body }) as ANFMethod;
const yes = (n: string): ANFMethod['body'] => [
  { name: `${n}c`, value: { kind: 'load_const', value: true } },
  { name: `${n}a`, value: { kind: 'assert', value: `${n}c` } },
] as ANFMethod['body'];
const prog = (methods: ANFMethod[]): ANFProgram =>
  ({ contractName: 'Dup', properties: [], methods }) as unknown as ANFProgram;

const spend = m('spend', true, [{ name: 'p', type: 'SigHashPreimage' }], [
  { name: 't0', value: { kind: 'load_param', name: 'p' } },
  { name: 't1', value: { kind: 'load_const', value: '@this' } },
  { name: 't2', value: { kind: 'method_call', object: 't1', method: 'check', args: ['t0'] } },
  ...yes('s'),
] as ANFMethod['body']);
const checked = m('check', false, [{ name: 'q', type: 'SigHashPreimage' }], [
  { name: 'k0', value: { kind: 'load_param', name: 'q' } },
  { name: 'k1', value: { kind: 'check_preimage', preimage: 'k0' } },
  { name: 'k2', value: { kind: 'assert', value: 'k1' } },
] as ANFMethod['body']);
const unchecked = m('check', false, [{ name: 'q', type: 'SigHashPreimage' }], yes('u'));

describe('D15: the IR preimage rule follows stack lowering, not names', () => {
  it('a checked twin declared first does not vouch for the unchecked one stack lowering inlines', () => {
    expect(irPreimageRuleErrors(prog([spend, checked, unchecked]))).toContain(GK010);
  });

  it('the checked body stack lowering inlines (the last one) does count', () => {
    expect(irPreimageRuleErrors(prog([spend, unchecked, checked]))).not.toContain(GK010);
  });

  it('a public method sharing a private helper\'s name does not hide the helper\'s call-site rule', () => {
    const extracting = m('check', false, [{ name: 'q', type: 'SigHashPreimage' }], [
      { name: 'e0', value: { kind: 'load_param', name: 'q' } },
      { name: 'e1', value: { kind: 'call', func: 'extractAmount', args: ['e0'] } },
      ...yes('e'),
    ] as ANFMethod['body']);
    const caller = m('spend', true, [{ name: 'x', type: 'ByteString' }], [
      { name: 't0', value: { kind: 'load_param', name: 'x' } },
      { name: 't1', value: { kind: 'load_const', value: '@this' } },
      { name: 't2', value: { kind: 'method_call', object: 't1', method: 'check', args: ['t0'] } },
      ...yes('s'),
    ] as ANFMethod['body']);
    const publicTwin = m('check', true, [], yes('v'));
    const errors = irPreimageRuleErrors(prog([caller, extracting, publicTwin]));
    expect(errors.some((e) => e.startsWith(D14('check')))).toBe(true);
  });
});
