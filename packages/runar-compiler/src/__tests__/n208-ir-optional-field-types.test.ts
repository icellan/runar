import { describe, it, expect } from 'vitest';
import { loadANFFromJSON } from '../index.js';

/**
 * N-208 — `loadANFFromJSON` refuses a wrong-typed optional field instead of
 * silently treating it as absent.
 *
 * The cross-tier `ir-rejection-parity` gate (`conformance/negatives/ir/`,
 * fixtures `I60`/`I61`) found that THIS tier — the one `anf-required-fields.ts`
 * is ported FROM — was also fail-open for `assert.isAutoInjectedStateCheck`:
 * a non-boolean value here is read elsewhere as `=== true` (strict), so the
 * STRING `"true"` silently becomes `false` with no diagnostic, the same gap
 * N-208 closed in Python, Ruby and Java's own `--ir` loaders. Per the
 * remediation's escalation rule, the reference tier is fixed here too.
 *
 * `bin_op.result_type` was already refused elsewhere in this tier's pipeline
 * (I60 passed before this fix) and `add_output.preimage` has no lowerer that
 * reads a non-string value today; both gain the same explicit optional-field
 * type check here for the same reason N-069 / F-038 check `parentClass` /
 * `sigHashType` in this same module: a present value of the wrong JSON type
 * should never read the same as an absent one.
 *
 * Proves: each field, given a value of the wrong JSON type, is refused by
 * `loadANFFromJSON` with the `IR validation: <path> must be <type>, got
 * <type>` diagnostic this module already uses -- and a correctly-typed or
 * absent value is still accepted.
 * Does not prove: the other six tiers (their own suites do), or that these
 * are the only fields this gap applied to.
 */

function program(body: unknown[]): unknown {
  return {
    contractName: 'X',
    properties: [],
    methods: [
      {
        name: 'run',
        isPublic: true,
        params: [],
        body,
      },
    ],
  };
}

describe('N-208: loadANFFromJSON refuses wrong-typed optional fields', () => {
  it('accepts a valid bin_op.result_type', () => {
    const body = [
      { name: 't0', value: { kind: 'load_const', value: 1 } },
      { name: 't1', value: { kind: 'load_const', value: 1 } },
      {
        name: 't2',
        value: { kind: 'bin_op', op: '===', left: 't0', right: 't1', result_type: 'bytes' },
      },
      { name: 't3', value: { kind: 'assert', value: 't2' } },
    ];
    expect(() => loadANFFromJSON(JSON.stringify(program(body)))).not.toThrow();
  });

  it('refuses a wrong-typed bin_op.result_type', () => {
    const body = [
      { name: 't0', value: { kind: 'load_const', value: 1 } },
      { name: 't1', value: { kind: 'load_const', value: 1 } },
      {
        name: 't2',
        value: { kind: 'bin_op', op: '===', left: 't0', right: 't1', result_type: 1 },
      },
      { name: 't3', value: { kind: 'assert', value: 't2' } },
    ];
    expect(() => loadANFFromJSON(JSON.stringify(program(body)))).toThrow(
      'IR validation: methods[0].body[2].value.result_type must be a string, got number',
    );
  });

  it('accepts a valid assert.isAutoInjectedStateCheck', () => {
    const body = [
      { name: 't0', value: { kind: 'load_const', value: true } },
      { name: 't1', value: { kind: 'assert', value: 't0', isAutoInjectedStateCheck: true } },
    ];
    expect(() => loadANFFromJSON(JSON.stringify(program(body)))).not.toThrow();
  });

  it('defaults an absent assert.isAutoInjectedStateCheck to false (not refused)', () => {
    const body = [
      { name: 't0', value: { kind: 'load_const', value: true } },
      { name: 't1', value: { kind: 'assert', value: 't0' } },
    ];
    expect(() => loadANFFromJSON(JSON.stringify(program(body)))).not.toThrow();
  });

  it('refuses a wrong-typed assert.isAutoInjectedStateCheck', () => {
    const body = [
      { name: 't0', value: { kind: 'load_const', value: true } },
      {
        name: 't1',
        value: { kind: 'assert', value: 't0', isAutoInjectedStateCheck: 'true' },
      },
    ];
    expect(() => loadANFFromJSON(JSON.stringify(program(body)))).toThrow(
      'IR validation: methods[0].body[1].value.isAutoInjectedStateCheck must be a boolean, got string',
    );
  });

  it('refuses a wrong-typed add_output.preimage', () => {
    // add_output is a stateful-only node; this program never reaches the
    // StatefulSmartContract scaffold check because the required-fields pass
    // (where this fix lives) runs first and raises before it.
    const body = [
      { name: 't0', value: { kind: 'load_const', value: 1 } },
      {
        name: 't1',
        value: { kind: 'add_output', satoshis: 't0', stateValues: [], preimage: 123 },
      },
    ];
    expect(() => loadANFFromJSON(JSON.stringify(program(body)))).toThrow(
      'IR validation: methods[0].body[1].value.preimage must be a string, got number',
    );
  });
});
