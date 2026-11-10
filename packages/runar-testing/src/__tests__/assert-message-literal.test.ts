/**
 * `assert(condition, "message")` is the documented two-argument form
 * (docs/language-reference.md "Assert": "message is stripped at compile
 * time"; spec/grammar.md: `assert(condition: boolean, message?: string)`), and
 * the typechecker's own test writes `assert(a > 0n, "must be positive")`.
 *
 * The TypeScript parser lowers every string literal to `bytestring_literal`
 * (string literals ARE hex ByteStrings everywhere else in the language), and
 * the interpreter evaluated the message with the other call arguments — so
 * `TestContract` hex-decoded it and threw `Invalid hex character: m` for any
 * human-readable message, on every call of the method, whether or not the
 * assert held. Compilation was unaffected (the message never reaches the
 * script), so the documented form compiled and could not be unit-tested.
 *
 * The interpreter now evaluates the condition alone and reports a literal
 * message verbatim.
 *
 * Proves: a passing call with a human-readable message succeeds; a failing
 * call reports the literal message as written, including one that is valid
 * hex; the one-argument form still reports 'assert failed'; both forms
 * compile to the same script.
 * Does NOT prove: anything about on-chain execution (the message never
 * reaches the script), or how other tiers' test interpreters report assert
 * messages.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { TestContract } from '../index.js';

const withMessage = (message: string) => `
import { SmartContract, assert } from 'runar-lang';

class Guard extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public check(a: bigint) {
    assert(a === this.x, "${message}");
  }
}
`;

describe('assert(cond, "message") in the interpreter', () => {
  it('compiles to the same script as the one-argument form (the message is stripped)', () => {
    const withMsg = compile(withMessage('must match x'), { fileName: 'Guard.runar.ts' });
    const without = compile(withMessage('').replace(', ""', ''), { fileName: 'Guard.runar.ts' });
    expect(withMsg.success).toBe(true);
    expect(without.success).toBe(true);
    expect(withMsg.artifact!.script).toBe(without.artifact!.script);
  });

  it('a passing call is not failed by a human-readable message', () => {
    const contract = TestContract.fromSource(withMessage('must match x'), { x: 5n });
    const result = contract.call('check', { a: 5n });
    expect(result.error).toBeUndefined();
    expect(result.success).toBe(true);
  });

  it('a failing call reports the message verbatim', () => {
    const contract = TestContract.fromSource(withMessage('must match x'), { x: 5n });
    const result = contract.call('check', { a: 4n });
    expect(result.success).toBe(false);
    expect(String(result.error)).toBe('must match x');
  });

  it('a message that happens to be valid hex is still reported as written', () => {
    const contract = TestContract.fromSource(withMessage('deadbeef'), { x: 5n });
    const result = contract.call('check', { a: 4n });
    expect(result.success).toBe(false);
    expect(String(result.error)).toBe('deadbeef');
  });

  it('the one-argument form still reports "assert failed"', () => {
    const contract = TestContract.fromSource(withMessage('').replace(', ""', ''), { x: 5n });
    const result = contract.call('check', { a: 4n });
    expect(result.success).toBe(false);
    expect(String(result.error)).toBe('assert failed');
  });
});
