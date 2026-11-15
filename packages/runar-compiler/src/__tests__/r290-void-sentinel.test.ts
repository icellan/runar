import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { validate } from '../passes/02-validate.js';
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
 *
 * GK-BUG-015: 02-validate now refuses a repeated method name, so a SOURCE with
 * two `helper` bodies never reaches pass 4 through `compile()`. `lowerToANF` is
 * a public export, so the backstop is still pinned on a hand-built duplicate:
 * the source declares `helper` and `helper2` and the test renames the second
 * on the parsed AST.
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

  private helper2(): void {
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
  /** The duplicate the source cannot spell any more, built on the parsed AST. */
  const handBuiltDuplicate = (): ContractNode => {
    const contract = parseContract(EMPTY_INLINED_BODY);
    const second = contract.methods.find((m) => m.name === 'helper2')!;
    second.name = 'helper';
    return contract;
  };

  it('validate refuses the hand-built duplicate (GK-BUG-015)', () => {
    expect(validate(handBuiltDuplicate()).errors.map((e) => e.message)).toContain(
      "method 'helper' is already declared in this contract and cannot be re-declared",
    );
  });

  it('refuses an empty inlined body instead of emitting a sentinel', () => {
    expect(() => lowerToANF(handBuiltDuplicate())).toThrow(
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
