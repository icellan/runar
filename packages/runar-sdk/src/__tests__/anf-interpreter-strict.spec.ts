import { describe, it, expect } from 'vitest';
import {
  computeNewState,
  computeNewStateAndDataOutputs,
  executeStrict,
  AssertionFailureError,
} from '../anf-interpreter.js';
import * as RunarSdk from '../index.js';
import type { ANFProgram } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Helper: small P2PKH-like guard contract.
//
// Stateful contract `Guard { value: bigint }` exposing `bump(amount)` which:
//   1. asserts amount > 0
//   2. asserts amount < 1000  (compound assert via two bin_ops)
//   3. value = value + amount
//
// Two failure modes for the strict-mode tests:
//   - amount == 0 fails the first assert
//   - amount == 5000 fails the second assert
//
// Lenient mode must accept all three (good, bad-low, bad-high) inputs because
// asserts are skipped — preserving the existing default contract.
// ---------------------------------------------------------------------------

function makeGuardANF(): ANFProgram {
  return {
    contractName: 'Guard',
    properties: [
      { name: 'value', type: 'bigint', readonly: false },
    ],
    methods: [{
      name: 'bump',
      params: [
        { name: 'amount', type: 'bigint' },
        { name: '_changePKH', type: 'Ripemd160' },
        { name: '_changeAmount', type: 'bigint' },
        { name: '_newAmount', type: 'bigint' },
        { name: 'txPreimage', type: 'SigHashPreimage' },
      ],
      body: [
        // assert(amount > 0)
        { name: 't0', value: { kind: 'load_param', name: 'amount' } },
        { name: 't1', value: { kind: 'load_const', value: 0n } },
        { name: 't2', value: { kind: 'bin_op', op: '>', left: 't0', right: 't1' } },
        { name: 'assertPositive', value: { kind: 'assert', value: 't2' } },
        // assert(amount < 1000)
        { name: 't3', value: { kind: 'load_const', value: 1000n } },
        { name: 't4', value: { kind: 'bin_op', op: '<', left: 't0', right: 't3' } },
        { name: 'assertBounded', value: { kind: 'assert', value: 't4' } },
        // value = value + amount
        { name: 't5', value: { kind: 'load_prop', name: 'value' } },
        { name: 't6', value: { kind: 'bin_op', op: '+', left: 't5', right: 't0' } },
        { name: 't7', value: { kind: 'update_prop', name: 'value', value: 't6' } },
      ],
      isPublic: true,
    }],
  };
}

describe('ANF interpreter strict mode — assert enforcement', () => {
  const anf = makeGuardANF();

  it('lenient computeNewState passes for valid input', () => {
    const result = computeNewState(anf, 'bump', { value: 10n }, { amount: 5n });
    expect(result.value).toBe(15n);
  });

  it('lenient computeNewState passes even when asserts would fail (amount=0)', () => {
    // The whole point of lenient mode: existing callers don't silently
    // start throwing. value still mutates.
    const result = computeNewState(anf, 'bump', { value: 10n }, { amount: 0n });
    expect(result.value).toBe(10n);
  });

  it('lenient computeNewState passes even when second assert would fail (amount=5000)', () => {
    const result = computeNewState(anf, 'bump', { value: 10n }, { amount: 5000n });
    expect(result.value).toBe(5010n);
  });

  it('strict executeStrict passes for valid input', () => {
    const result = executeStrict(anf, 'bump', { value: 10n }, { amount: 5n });
    expect(result.state.value).toBe(15n);
    expect(result.dataOutputs).toEqual([]);
  });

  it('strict executeStrict throws AssertionFailureError on first failing assert (amount=0)', () => {
    expect(() => executeStrict(anf, 'bump', { value: 10n }, { amount: 0n }))
      .toThrow(AssertionFailureError);
    try {
      executeStrict(anf, 'bump', { value: 10n }, { amount: 0n });
    } catch (e) {
      expect(e).toBeInstanceOf(AssertionFailureError);
      const err = e as AssertionFailureError;
      expect(err.methodName).toBe('bump');
      // First assert binding name is 'assertPositive'.
      expect(err.bindingName).toBe('assertPositive');
      expect(err.message).toContain('bump');
      expect(err.message).toContain('assertPositive');
    }
  });

  it('strict executeStrict throws AssertionFailureError on second failing assert (amount=5000)', () => {
    expect(() => executeStrict(anf, 'bump', { value: 10n }, { amount: 5000n }))
      .toThrow(AssertionFailureError);
    try {
      executeStrict(anf, 'bump', { value: 10n }, { amount: 5000n });
    } catch (e) {
      expect(e).toBeInstanceOf(AssertionFailureError);
      const err = e as AssertionFailureError;
      expect(err.bindingName).toBe('assertBounded');
    }
  });

  it('strict mode does NOT verify signatures (checkSig still mocks true)', () => {
    // P2PKH-style guard: assert(checkSig(sig, pk)) — strict mode keeps
    // checkSig mocked, so any sig+pk pair passes. This is documented
    // behaviour: strict mode only enforces explicit assert predicates,
    // never crypto.
    const sigANF: ANFProgram = {
      contractName: 'SigGuard',
      properties: [{ name: 'value', type: 'bigint', readonly: false }],
      methods: [{
        name: 'unlock',
        params: [
          { name: 'sig', type: 'Sig' },
          { name: 'pk', type: 'PubKey' },
        ],
        body: [
          { name: 'sigArg', value: { kind: 'load_param', name: 'sig' } },
          { name: 'pkArg', value: { kind: 'load_param', name: 'pk' } },
          { name: 'sigOk', value: { kind: 'call', func: 'checkSig', args: ['sigArg', 'pkArg'] } },
          { name: 'assertSig', value: { kind: 'assert', value: 'sigOk' } },
          { name: 'one', value: { kind: 'load_const', value: 1n } },
          { name: 'upd', value: { kind: 'update_prop', name: 'value', value: 'one' } },
        ],
        isPublic: true,
      }],
    };
    // Garbage sig + garbage pk would fail real ECDSA verification; strict
    // mode must still pass because checkSig is mocked.
    const result = executeStrict(
      sigANF,
      'unlock',
      { value: 0n },
      { sig: 'deadbeef', pk: 'cafebabe' },
    );
    expect(result.state.value).toBe(1n);
  });

  it('strict mode evaluates assert built-in call (not just assert ANF nodes)', () => {
    // Some lowering paths emit `call(assert, ...)` rather than the
    // dedicated `assert` ANF node — strict mode covers both.
    const callANF: ANFProgram = {
      contractName: 'CallAssert',
      properties: [{ name: 'value', type: 'bigint', readonly: false }],
      methods: [{
        name: 'check',
        params: [{ name: 'flag', type: 'bool' }],
        body: [
          { name: 'arg', value: { kind: 'load_param', name: 'flag' } },
          { name: 'callAssert', value: { kind: 'call', func: 'assert', args: ['arg'] } },
          { name: 'one', value: { kind: 'load_const', value: 1n } },
          { name: 'upd', value: { kind: 'update_prop', name: 'value', value: 'one' } },
        ],
        isPublic: true,
      }],
    };

    // Lenient ignores
    expect(computeNewState(callANF, 'check', { value: 0n }, { flag: false }).value).toBe(1n);

    // Strict throws on falsy flag
    expect(() => executeStrict(callANF, 'check', { value: 0n }, { flag: false }))
      .toThrow(AssertionFailureError);

    // Strict passes on truthy flag
    expect(executeStrict(callANF, 'check', { value: 0n }, { flag: true }).state.value).toBe(1n);
  });

  it('lenient computeNewStateAndDataOutputs returns the same state as before (no regression)', () => {
    // Sanity check that existing entry point's data-output shape is intact.
    const result = computeNewStateAndDataOutputs(anf, 'bump', { value: 10n }, { amount: 0n });
    expect(result.state.value).toBe(10n);
    expect(result.dataOutputs).toEqual([]);
  });

  it('strict-mode symbols are re-exported from the package entry point', () => {
    // Guards against the original regression where executeStrict +
    // AssertionFailureError were defined in anf-interpreter.ts but never
    // re-exported from runar-sdk's index, so external consumers couldn't
    // reach them.
    expect(typeof RunarSdk.executeStrict).toBe('function');
    expect(RunarSdk.executeStrict).toBe(executeStrict);
    expect(RunarSdk.AssertionFailureError).toBe(AssertionFailureError);
    // End-to-end: invoke the package-entry symbol and confirm it throws
    // the same error type the direct import does.
    expect(() => RunarSdk.executeStrict(anf, 'bump', { value: 10n }, { amount: 0n }))
      .toThrow(RunarSdk.AssertionFailureError);
  });
});
