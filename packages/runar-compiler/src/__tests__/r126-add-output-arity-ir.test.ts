import { describe, it, expect } from 'vitest';
import { loadANFFromJSON } from '../index.js';

/**
 * R-126 / CL-BUG-164 — an `add_output` node whose `stateValues` list does not
 * match the contract's mutable-property list.
 *
 * The SOURCE pipeline counts addOutput arity in the typechecker (gated by
 * `conformance/negatives/N20`, `N23` and `N26`). The `--ir` path runs no
 * frontend at all, so such a node reaches stack lowering directly — and every
 * tier's `lowerAddOutput` serializes with the MIN of the two lists:
 *
 *     for i := 0; i < len(stateValues) && i < len(stateProps); i++
 *
 * Under-arity therefore emits an output whose OP_RETURN payload carries fewer
 * state fields than the contract has, and over-arity silently drops the
 * surplus. Measured through each tier's own `--ir` CLI on a two-mutable-field
 * contract (correct arity = 1394 hexchars):
 *
 *     go / rust / zig / ruby / python / java   ACCEPTED both
 *       under-arity  1388 hexchars
 *       over-arity   1396 hexchars
 *
 * All six, not four: an earlier hand-rolled probe of mine mis-invoked the
 * Python and Java CLIs and read their usage/echo output as a rejection. The
 * numbers above come from the conformance tier harness, which uses the same
 * argv the positive `--ir-parity` run uses.
 *
 * CL-BUG-164 settled the cost: every SDK's StateSerializer writes ALL mutable
 * fields, so a short-payload continuation is spendable only by a hand-crafted
 * transaction, and the successor it produces is permanently unspendable
 * because the next call's `deserialize_state` slices at fixed offsets.
 *
 * The invariant is safe to enforce: across all 101 checked-in IR files in the
 * repo, all 19 `add_output` nodes already satisfy it exactly.
 *
 * The six native tiers are gated by
 * `conformance/negatives/ir/I12-add-output-under-arity.ir.json` and
 * `I13-add-output-over-arity.ir.json`. This file is the reference tier's half.
 */

const program = (stateValues: string[], props: Array<[string, boolean]>) =>
  JSON.stringify({
    contractName: 'AddOutputArity',
    properties: props.map(([name, readonly]) => ({ name, type: 'bigint', readonly })),
    methods: [
      {
        name: 'bump',
        isPublic: true,
        params: [{ name: 'n', type: 'bigint' }],
        body: [
          { name: 't0', value: { kind: 'load_const', value: 1000 } },
          { name: 't1', value: { kind: 'load_prop', name: 'a' } },
          { name: 't2', value: { kind: 'load_prop', name: 'b' } },
          { name: 't3', value: { kind: 'add_output', satoshis: 't0', stateValues, preimage: '' } },
        ],
      },
    ],
  });

const TWO_MUTABLE: Array<[string, boolean]> = [['a', false], ['b', false]];

describe('R-126 add_output state-value arity on the --ir path', () => {
  it('accepts the exact arity', () => {
    expect(() => loadANFFromJSON(program(['t1', 't2'], TWO_MUTABLE))).not.toThrow();
  });

  it('refuses an UNDER-arity node instead of emitting a short payload', () => {
    expect(() => loadANFFromJSON(program(['t1'], TWO_MUTABLE))).toThrow(
      /add_output.*1 state value.*2 mutable propert/s,
    );
  });

  it('refuses an OVER-arity node instead of dropping the surplus', () => {
    expect(() => loadANFFromJSON(program(['t1', 't2', 't2'], TWO_MUTABLE))).toThrow(
      /add_output.*3 state value.*2 mutable propert/s,
    );
  });

  it('counts MUTABLE properties only — readonly ones are not serialized', () => {
    const props: Array<[string, boolean]> = [['a', false], ['owner', true], ['b', false]];
    expect(() => loadANFFromJSON(program(['t1', 't2'], props))).not.toThrow();
    expect(() => loadANFFromJSON(program(['t1', 't2', 't2'], props))).toThrow(/add_output/);
  });

  it('names the method, so a multi-method program says WHICH one is wrong', () => {
    let message = '';
    try {
      loadANFFromJSON(program(['t1'], TWO_MUTABLE));
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toContain('bump');
  });

  it('sees an add_output nested inside an if-branch', () => {
    const nested = JSON.stringify({
      contractName: 'Nested',
      properties: [
        { name: 'a', type: 'bigint', readonly: false },
        { name: 'b', type: 'bigint', readonly: false },
      ],
      methods: [
        {
          name: 'maybe',
          isPublic: true,
          params: [{ name: 'n', type: 'bigint' }],
          body: [
            { name: 't0', value: { kind: 'load_param', name: 'n' } },
            {
              name: 't1',
              value: {
                kind: 'if',
                cond: 't0',
                then: [
                  { name: 't2', value: { kind: 'load_const', value: 1000 } },
                  {
                    name: 't3',
                    value: { kind: 'add_output', satoshis: 't2', stateValues: ['t0'], preimage: '' },
                  },
                ],
                else: [],
              },
            },
          ],
        },
      ],
    });
    expect(() => loadANFFromJSON(nested)).toThrow(/add_output/);
  });
});

/**
 * R-164 / CL-BUG-134 — `super` outside a constructor, checked at the same trust
 * boundary and for the same reason: the loader is where IR from outside the
 * compiler enters.
 *
 * `super` emits no opcodes but stack lowering pushes a model slot for it
 * anyway, so every later PICK/ROLL depth is off by one. Measured on the Go tier
 * against the same IR with the binding deleted:
 *
 *     with super     0000 53 7a 53 7a a0 7777    PUSH 3; OP_ROLL, twice
 *     without super  0000 7b 7b a0 77            OP_ROT, twice
 *
 * The six native tiers are gated by
 * `conformance/negatives/ir/I14-super-outside-constructor.ir.json`.
 */
describe('R-164 super() outside a constructor', () => {
  const withSuper = (methodName: string) =>
    JSON.stringify({
      contractName: 'SuperProbe',
      properties: [{ name: 'a', type: 'bigint', readonly: true }],
      methods: [
        {
          name: methodName,
          isPublic: methodName !== 'constructor',
          params: [{ name: 'x', type: 'bigint' }],
          body: [
            { name: 't0', value: { kind: 'load_prop', name: 'a' } },
            { name: 't1', value: { kind: 'call', func: 'super', args: ['t0'] } },
          ],
        },
      ],
    });

  it('refuses it in a public method', () => {
    expect(() => loadANFFromJSON(withSuper('go'))).toThrow(/super\(\).*constructor/s);
  });

  it('names the method, so a multi-method program says which one', () => {
    let message = '';
    try {
      loadANFFromJSON(withSuper('spend'));
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toContain("'spend'");
  });

  it('accepts it in the constructor — the only place it means anything', () => {
    expect(() => loadANFFromJSON(withSuper('constructor'))).not.toThrow();
  });

  it('sees it nested inside an if-branch', () => {
    const nested = JSON.stringify({
      contractName: 'SuperProbe',
      properties: [{ name: 'a', type: 'bigint', readonly: true }],
      methods: [
        {
          name: 'go',
          isPublic: true,
          params: [{ name: 'x', type: 'bigint' }],
          body: [
            { name: 't0', value: { kind: 'load_param', name: 'x' } },
            {
              name: 't1',
              value: {
                kind: 'if',
                cond: 't0',
                then: [{ name: 't2', value: { kind: 'call', func: 'super', args: [] } }],
                else: [],
              },
            },
          ],
        },
      ],
    });
    expect(() => loadANFFromJSON(nested)).toThrow(/super\(\)/);
  });
});
