import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { typecheck } from '../passes/03-typecheck.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import type { ContractNode } from '../ir/index.js';

/**
 * R-290 — `inlinePrivateMethodCall` used to emit a `load_const '@void'`
 * sentinel when the inlined body produced no bindings.
 *
 * No tier's stack lowering recognises `'@void'` (unlike `'@this'`, which IS
 * special-cased), so the sentinel survived pass 4 and died in the hex decoder:
 * Go said `invalid byte: U+0040 '@'`, Rust said `invalid hex string length: 5`.
 * Neither names the method or the problem, and both fire only because the
 * string happens to be odd-length and non-hex — an even-length sentinel would
 * decode to zeros in Rust's `from_str_radix(..).unwrap_or(0)` and reach the
 * script.
 *
 * It is reachable. The side-effect summary resolves a called name through a
 * LAST-WINS map and caches the result under that name, while
 * `getPrivateMethod` returns the FIRST match. Declare the public caller BEFORE
 * two same-named privates and the two disagree: the summary describes the
 * output-emitting `helper` (so `shouldInlinePrivate` is true) while the
 * lowerer inlines the empty one.
 */
const EMPTY_INLINED_BODY = `
class R290Void extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(x: bigint) {
    this.count = x;
    this.helper();
  }

  private helper(): void {
  }

  private helper(): void {
    this.addOutput(1000n, this.count);
  }
}
`;

/**
 * Control: the ordinary shape — one private helper that really does emit an
 * output. The inlining path must still work; a refusal that simply rejected
 * every inlined private would pass the test above.
 */
const CONTROL_EMITTING_HELPER = `
class R290Control extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(x: bigint) {
    this.count = x;
    this.helper();
  }

  private helper(): void {
    this.addOutput(1000n, this.count);
  }
}
`;

function parseContract(source: string): ContractNode {
  const result = parse(source);
  if (!result.contract) {
    throw new Error(`Parse failed: ${result.errors.map(e => e.message).join(', ')}`);
  }
  return result.contract;
}

describe('R-290: the @void sentinel', () => {
  it('reaches pass 4 — nothing upstream rejects the duplicate declaration', () => {
    // If this ever starts failing, the refusal test below stops testing pass 4.
    expect(typecheck(parseContract(EMPTY_INLINED_BODY)).errors).toHaveLength(0);
  });

  it('refuses an empty inlined body instead of emitting a sentinel', () => {
    expect(() => lowerToANF(parseContract(EMPTY_INLINED_BODY))).toThrow(
      /private method 'helper' was inlined but produced no bindings/,
    );
  });

  it('emits no @void anywhere for an ordinary inlined helper', () => {
    const program = lowerToANF(parseContract(CONTROL_EMITTING_HELPER));
    // The ANF carries BigInt literals, which JSON.stringify refuses.
    const serialised = JSON.stringify(program, (_k, v) =>
      typeof v === 'bigint' ? v.toString() : v,
    );
    expect(serialised).not.toContain('@void');
  });

  it('still inlines a private helper that does emit bindings', () => {
    expect(() => lowerToANF(parseContract(CONTROL_EMITTING_HELPER))).not.toThrow();
  });
});
