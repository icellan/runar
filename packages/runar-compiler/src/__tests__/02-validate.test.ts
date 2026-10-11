import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { validate } from '../passes/02-validate.js';
import type { ValidationResult } from '../passes/02-validate.js';
import type { ContractNode } from '../ir/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseContract(source: string): ContractNode {
  const result = parse(source);
  if (!result.contract) {
    throw new Error(`Parse failed: ${result.errors.map(e => e.message).join(', ')}`);
  }
  return result.contract;
}

function validateSource(source: string): ValidationResult {
  const contract = parseContract(source);
  return validate(contract);
}

function hasError(result: ValidationResult, substring: string): boolean {
  return result.errors.some(e => e.message.includes(substring));
}

// ---------------------------------------------------------------------------
// Valid contracts
// ---------------------------------------------------------------------------

const VALID_P2PKH = `
class P2PKH extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public unlock(sig: Sig) {
    assert(checkSig(sig, this.pk));
  }
}
`;

const VALID_COUNTER = `
class Counter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    this.count = this.count + 1n;
  }
}
`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Pass 2: Validate', () => {
  describe('valid contracts', () => {
    it('passes validation for a valid P2PKH contract', () => {
      const result = validateSource(VALID_P2PKH);
      expect(result.errors).toEqual([]);
    });

    it('passes validation for a valid stateful Counter contract', () => {
      const result = validateSource(VALID_COUNTER);
      expect(result.errors).toEqual([]);
    });

    it('passes validation for a contract with multiple public methods', () => {
      const source = `
        class Multi extends SmartContract {
          readonly pk1: PubKey;
          readonly pk2: PubKey;

          constructor(pk1: PubKey, pk2: PubKey) {
            super(pk1, pk2);
            this.pk1 = pk1;
            this.pk2 = pk2;
          }

          public spend1(sig: Sig) {
            assert(checkSig(sig, this.pk1));
          }

          public spend2(sig: Sig) {
            assert(checkSig(sig, this.pk2));
          }
        }
      `;
      const result = validateSource(source);
      expect(result.errors).toEqual([]);
    });

    it('passes validation when public method ends with if/else both ending in assert', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          public m(sig: Sig, flag: boolean) {
            if (flag) {
              assert(checkSig(sig, this.pk));
            } else {
              assert(false);
            }
          }
        }
      `;
      const result = validateSource(source);
      expect(result.errors).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  // Public method must end with assert
  // ---------------------------------------------------------------------------

  describe('public method must end with assert', () => {
    it('reports error when public method does not end with assert()', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            const b: bigint = a + 1n;
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "must end with an assert() call")).toBe(true);
    });

    it('reports error when public method ends with a non-assert call', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          public m(sig: Sig) {
            checkSig(sig, this.pk);
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "must end with an assert() call")).toBe(true);
    });

    it('does not report error for private method without assert', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          helper(a: bigint): bigint {
            return a + 1n;
          }

          public m() {
            assert(true);
          }
        }
      `;
      const result = validateSource(source);
      expect(result.errors).toEqual([]);
    });

    it('reports error when empty public method body', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m() {}
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "must end with an assert() call")).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Contract must have at least one public method
  // ---------------------------------------------------------------------------

  describe('no public methods', () => {
    it('reports error when no method has the public modifier', () => {
      const source = `
        class Locked extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, 'no public methods')).toBe(true);
    });

    it('reports error when a contract has no methods at all', () => {
      const source = `
        class Empty extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, 'no public methods')).toBe(true);
    });

    it('does not report when at least one method is public', () => {
      const result = validateSource(VALID_P2PKH);
      expect(hasError(result, 'no public methods')).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // For loop with non-constant bound
  // ---------------------------------------------------------------------------

  describe('for loop bounds', () => {
    it('reports error for for-loop with non-constant bound (property access)', () => {
      const source = `
        class C extends SmartContract {
          readonly n: bigint;

          constructor(n: bigint) {
            super(n);
            this.n = n;
          }

          public m() {
            let sum: bigint = 0n;
            for (let i: bigint = 0n; i < this.n; i++) {
              sum = sum + i;
            }
            assert(sum >= 0n);
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "compile-time constant")).toBe(true);
    });

    it('accepts for-loop with bigint literal bound', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m() {
            let sum: bigint = 0n;
            for (let i: bigint = 0n; i < 10n; i++) {
              sum = sum + i;
            }
            assert(sum >= 0n);
          }
        }
      `;
      const result = validateSource(source);
      // Should not report "compile-time constant" error
      expect(hasError(result, "compile-time constant")).toBe(false);
    });

    it('accepts for-loop with identifier bound (treated as possibly const)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m() {
            const N: bigint = 10n;
            let sum: bigint = 0n;
            for (let i: bigint = 0n; i < N; i++) {
              sum = sum + i;
            }
            assert(sum >= 0n);
          }
        }
      `;
      const result = validateSource(source);
      // Identifier is treated as potentially const, so should pass
      expect(hasError(result, "compile-time constant")).toBe(false);
    });

    it('accepts a for-loop with a non-zero start value (issue #121)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m() {
            let sum: bigint = 0n;
            for (let i: bigint = 1n; i <= 3n; i++) {
              sum = sum + i;
            }
            assert(sum > 0n);
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, 'must start at 0')).toBe(false);
    });

    it('accepts a countdown for-loop (issue #121)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m() {
            let sum: bigint = 0n;
            for (let i: bigint = 3n; i > 0n; i--) {
              sum = sum + i;
            }
            assert(sum > 0n);
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, 'countdown')).toBe(false);
    });

    it('accepts a zero-start counting-up for-loop', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m() {
            let sum: bigint = 0n;
            for (let i: bigint = 0n; i <= 3n; i++) {
              sum = sum + i;
            }
            assert(sum > 0n);
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, 'must start at 0')).toBe(false);
      expect(hasError(result, 'countdown')).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Constructor must call super()
  // ---------------------------------------------------------------------------

  describe('constructor validation', () => {
    it('reports error when constructor does not call super()', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            this.x = x;
          }

          public m() {
            assert(true);
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "must call super()")).toBe(true);
    });

    it('reports error when super() is not the first statement', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            this.x = x;
            super(x);
          }

          public m() {
            assert(true);
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "must call super()")).toBe(true);
    });

    it('reports error when property is not assigned in constructor', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          readonly y: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m() {
            assert(true);
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "Property 'y' must be assigned")).toBe(true);
    });

    it('reports no error when all properties are assigned', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          readonly y: bigint;

          constructor(x: bigint, y: bigint) {
            super(x, y);
            this.x = x;
            this.y = y;
          }

          public m() {
            assert(true);
          }
        }
      `;
      const result = validateSource(source);
      expect(result.errors).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  // Property type validation
  // ---------------------------------------------------------------------------

  describe('property type validation', () => {
    it('reports error for void property type', () => {
      const source = `
        class C extends SmartContract {
          readonly x: void;

          constructor() {
            super();
            this.x = 0n;
          }

          public m() { assert(true); }
        }
      `;
      // The parse should succeed but validate should catch void property.
      // F-226: the contract is asserted unconditionally — the old
      // `if (parseResult.contract)` guard let a parser that dropped the
      // contract pass this test having asserted nothing. Proves validate
      // rejects a void property on a parsed contract; does not prove which
      // pass would catch it if the parser itself started rejecting `void`.
      const parseResult = parse(source);
      expect(parseResult.contract).not.toBeNull();
      const result = validate(parseResult.contract!);
      expect(hasError(result, "void")).toBe(true);
    });

    it('reports error when SmartContract has a non-readonly property', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          amount: bigint;

          constructor(pk: PubKey, amount: bigint) {
            super(pk, amount);
            this.pk = pk;
            this.amount = amount;
          }

          public m(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "readonly")).toBe(true);
    });

    it('allows non-readonly properties in StatefulSmartContract', () => {
      const source = `
        class C extends StatefulSmartContract {
          count: bigint;

          constructor(count: bigint) {
            super(count);
            this.count = count;
          }

          public increment() {
            this.count = this.count + 1n;
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "readonly")).toBe(false);
    });

    it('reports error for unsupported custom type in property', () => {
      const source = `
        class C extends SmartContract {
          readonly x: SomeCustomType;

          constructor(x: SomeCustomType) {
            super(x);
            this.x = x;
          }

          public m() { assert(true); }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "Unsupported type")).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Recursion detection
  // ---------------------------------------------------------------------------

  describe('recursion detection', () => {
    it('detects direct recursion', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            this.m(a);
            assert(true);
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "Recursion detected")).toBe(true);
    });

    it('detects indirect recursion (A -> B -> A)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          helper1(a: bigint): bigint {
            return this.helper2(a);
          }

          helper2(a: bigint): bigint {
            return this.helper1(a);
          }

          public m() {
            assert(true);
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "Recursion detected")).toBe(true);
    });

    it('does not flag non-recursive method calls', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          helper(a: bigint): bigint {
            return a + 1n;
          }

          public m(a: bigint) {
            const b: bigint = this.helper(a);
            assert(b > 0n);
          }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "Recursion detected")).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // StatefulSmartContract validation
  // ---------------------------------------------------------------------------

  describe('StatefulSmartContract', () => {
    it('does not require public methods to end with assert()', () => {
      const source = `
        class Counter extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment() { this.count++; }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "must end with an assert() call")).toBe(false);
    });

    it('still requires assert-ending for regular SmartContract public methods', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() {}
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "must end with an assert() call")).toBe(true);
    });

    it('warns when manually calling checkPreimage in StatefulSmartContract', () => {
      const source = `
        class Counter extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment(txPreimage: SigHashPreimage) {
            assert(checkPreimage(txPreimage));
            this.count++;
          }
        }
      `;
      const result = validateSource(source);
      expect(result.warnings.some(w => w.message.includes('auto-injects checkPreimage'))).toBe(true);
    });

    it('warns when manually calling getStateScript in StatefulSmartContract', () => {
      const source = `
        class Counter extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment() {
            this.count++;
            assert(hash256(this.getStateScript()) === extractOutputHash(this.txPreimage));
          }
        }
      `;
      const result = validateSource(source);
      expect(result.warnings.some(w => w.message.includes('auto-injects state continuation'))).toBe(true);
    });

    it('warns when StatefulSmartContract has no mutable properties', () => {
      const source = `
        class C extends StatefulSmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() { assert(true); }
        }
      `;
      const result = validateSource(source);
      expect(result.warnings.some(w => w.message.includes('no mutable properties'))).toBe(true);
    });

    it('errors when txPreimage is declared as an explicit property', () => {
      const source = `
        class C extends StatefulSmartContract {
          count: bigint;
          txPreimage: SigHashPreimage;
          constructor(count: bigint, txPreimage: SigHashPreimage) {
            super(count, txPreimage);
            this.count = count;
            this.txPreimage = txPreimage;
          }
          public m() { this.count++; }
        }
      `;
      const result = validateSource(source);
      expect(hasError(result, "implicit property")).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Contract name validation (row 98)
// ---------------------------------------------------------------------------

describe('Validator: contract name validation', () => {
  it('errors when contractName is empty (row 98)', () => {
    // Manually construct a ContractNode with an empty name (can't be produced by the parser,
    // but the validator must guard against this for robustness).
    const contract: import('../ir/index.js').ContractNode = {
      kind: 'contract',
      name: '',
      parentClass: 'SmartContract',
      properties: [],
      methods: [],
      sourceFile: 'test.runar.ts',
      constructor: {
        kind: 'method',
        name: 'constructor',
        visibility: 'public',
        params: [],
        body: [],
        sourceLocation: { file: 'test.runar.ts', line: 1, column: 0 },
      },
    };
    const result = validate(contract);
    expect(result.errors.some(e => e.message.toLowerCase().includes('name'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// F-063: array-literal elements are walked by every validator walker
// ---------------------------------------------------------------------------
//
// `array_literal` was missing from validateExpression, collectMethodCallsInExpr,
// walkExpr and subExpressions, so anything written INSIDE `[...]` (the only
// place checkMultiSig's arguments can be written) escaped every rule those
// walkers enforce. Each test puts the offending construct in an array element
// and asserts the rule the validator already enforces outside one.
//
// Proves: the validator itself refuses these shapes (with the same diagnostic
// it gives the un-nested form). Does not prove: anything about typecheck or
// codegen — the cross-tier CLI verdicts live in conformance/negatives N99+.

describe('Validator: array-literal elements are walked (F-063)', () => {
  it('detects recursion through a self-call inside an array literal', () => {
    const result = validateSource(`
      class C extends SmartContract {
        readonly pk: PubKey;
        constructor(pk: PubKey) { super(pk); this.pk = pk; }
        h(s: Sig): PubKey { assert(checkMultiSig([s], [this.h(s)])); return this.pk; }
        public unlock(s: Sig) { assert(checkMultiSig([s], [this.h(s)])); }
      }
    `);
    expect(hasError(result, 'Recursion detected')).toBe(true);
  });

  it('rejects an odd-length ByteString literal inside an array literal', () => {
    const result = validateSource(`
      class C extends SmartContract {
        readonly pk: PubKey;
        constructor(pk: PubKey) { super(pk); this.pk = pk; }
        public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, toByteString('abc')])); }
      }
    `);
    expect(hasError(result, "ByteString literal 'abc' has odd length (3)")).toBe(true);
  });

  it('rejects a non-hex ByteString literal inside an array literal', () => {
    const result = validateSource(`
      class C extends SmartContract {
        readonly pk: PubKey;
        constructor(pk: PubKey) { super(pk); this.pk = pk; }
        public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, toByteString('zz')])); }
      }
    `);
    expect(hasError(result, "ByteString literal 'zz' contains non-hex characters")).toBe(true);
  });

  it('rejects a readonly-property increment inside an array literal (walkExpr)', () => {
    const result = validateSource(`
      class C extends SmartContract {
        readonly n: bigint;
        readonly pk: PubKey;
        constructor(n: bigint, pk: PubKey) { super(n, pk); this.n = n; this.pk = pk; }
        public unlock(s: Sig) { const a = [this.n++]; assert(checkSig(s, this.pk)); }
      }
    `);
    expect(hasError(result, "Cannot assign to readonly property 'n'")).toBe(true);
  });

  it('rejects an output intrinsic inside an array literal in a loop body (subExpressions)', () => {
    const result = validateSource(`
      class C extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        public step() {
          for (let i = 0n; i < 2n; i++) {
            const a = [this.addOutput(1000n, this.count)];
          }
          assert(true);
        }
      }
    `);
    expect(hasError(result, "Output intrinsic 'addOutput'")).toBe(true);
  });
});

describe('Validator: ByteString property initializer hex validation (F-265)', () => {
  // Proves: a malformed ByteString literal used as a PROPERTY INITIALIZER is
  // caught here, at the property's own source location, instead of surviving
  // this pass and only surfacing two passes later as an opaque stack-lowering
  // error with no location. `isLiteralExpression` only checks the literal's
  // SHAPE (is it a ByteStringLiteral at all); it never validated the hex
  // FORMAT, because that check lives in `validateExpression`'s
  // `bytestring_literal` arm, which method bodies reach via the statement
  // walk but a property initializer never did.
  //
  // Does not prove: anything about Rust or any other tier (see the Rust
  // peer test in validator.rs and the cross-tier parity fixture in
  // conformance/negatives), or about non-ByteString initializer defects.

  it('rejects an odd-length ByteString literal used as a property initializer', () => {
    const result = validateSource(`
      class BadHexInit extends SmartContract {
        readonly k: ByteString = "zzz" as ByteString;
        constructor() { super(); }
        public unlock() { assert(this.k === this.k); }
      }
    `);
    expect(hasError(result, "ByteString literal 'zzz' has odd length (3)")).toBe(true);
  });

  it('rejects a non-hex (even-length) ByteString literal used as a property initializer', () => {
    const result = validateSource(`
      class BadHexInit2 extends SmartContract {
        readonly k: ByteString = "zz" as ByteString;
        constructor() { super(); }
        public unlock() { assert(this.k === this.k); }
      }
    `);
    expect(hasError(result, "ByteString literal 'zz' contains non-hex characters")).toBe(true);
  });

  it('rejects an odd-length ByteString literal inside a toByteString(...) property initializer', () => {
    const result = validateSource(`
      class BadHexInit3 extends SmartContract {
        readonly k: ByteString = toByteString('zzz');
        constructor() { super(); }
        public unlock() { assert(this.k === this.k); }
      }
    `);
    expect(hasError(result, "ByteString literal 'zzz' has odd length (3)")).toBe(true);
  });
});
