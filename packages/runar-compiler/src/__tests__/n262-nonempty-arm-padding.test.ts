import { describe, it, expect } from 'vitest';
import { compileFromANF, loadANFFromJSON } from '../index.js';

/**
 * N-262 — `lowerIf` phase 3 must refuse to pad a NON-EMPTY arm.
 *
 * Phase 3 balances the two arms of an OP_IF by pushing an OP_0 on the
 * shallower one. Padding an arm that has NO bindings is the legitimate #99
 * fallback (the arm computed nothing, so the placeholder stands in for the
 * result the spender did not produce). Padding an arm that DID compute
 * something is not: the arms disagree on depth for a reason phase 3 cannot
 * see, and the OP_0 becomes a value the post-ENDIF code reads — the
 * OP_0-in-the-taken-arm shape. Go has refused this since R-161; the other six
 * tiers padded silently.
 *
 * The program below is hand-built `--ir` input: an arm whose last binding is a
 * non-terminal `assert` ends one slot shallower than a sibling arm that leaves
 * a value, and no source form is needed to reach it.
 *
 * Proves: both padding directions throw the shared internal-codegen sentence
 * (same words as compilers/go/codegen/stack.go), and padding an EMPTY arm
 * still compiles. Does not prove: that no source program reaches the guard
 * (golden/conformance runs cover the corpus), nor that the sentence matches
 * byte for byte in the other tiers (their own tests pin it).
 */

const VALUE_ARM = [{ name: 'a', value: { kind: 'load_const', value: 1 } }];
const ASSERT_ARM = [
  { name: 'k', value: { kind: 'load_const', value: 1 } },
  { name: 'k2', value: { kind: 'assert', value: 'k' } },
];

function ir(thenArm: unknown[], elseArm: unknown[]): string {
  return JSON.stringify({
    contractName: 'P',
    properties: [],
    methods: [
      {
        name: 'm',
        isPublic: true,
        params: [{ name: 'x', type: 'bigint' }],
        body: [
          { name: 't0', value: { kind: 'load_param', name: 'x' } },
          { name: 't1', value: { kind: 'load_const', value: 0 } },
          { name: 't2', value: { kind: 'bin_op', op: '>', left: 't0', right: 't1' } },
          { name: 't3', value: { kind: 'if', cond: 't2', then: thenArm, else: elseArm } },
          { name: 't4', value: { kind: 'assert', value: 't3' } },
        ],
      },
    ],
  });
}

function compileIR(json: string) {
  return compileFromANF(loadANFFromJSON(json), { disableConstantFolding: true });
}

describe('N-262: lowerIf refuses to pad a non-empty arm', () => {
  it('refuses a non-empty else arm that is shallower than the then arm', () => {
    expect(() => compileIR(ir(VALUE_ARM, ASSERT_ARM))).toThrow(
      /internal codegen error: conditional needs 1 placeholder push\(es\) to balance a NON-EMPTY else arm \(then depth 1 != else depth 0\).*binding="t3"/i,
    );
  });

  it('refuses a non-empty then arm that is shallower than the else arm', () => {
    expect(() => compileIR(ir(ASSERT_ARM, VALUE_ARM))).toThrow(
      /internal codegen error: conditional needs 1 placeholder push\(es\) to balance a NON-EMPTY then arm \(else depth 1 != then depth 0\).*binding="t3"/i,
    );
  });

  it('still pads an EMPTY else arm (the legitimate #99 fallback)', () => {
    expect(compileIR(ir(VALUE_ARM, [])).scriptHex).toMatch(/^[0-9a-f]+$/);
  });
});
