import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { typecheck } from '../passes/03-typecheck.js';
import type { TypeCheckResult } from '../passes/03-typecheck.js';
import type { ContractNode } from '../ir/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseContract(source: string, fileName?: string): ContractNode {
  const result = parse(source, fileName);
  if (!result.contract) {
    throw new Error(`Parse failed: ${result.errors.map(e => e.message).join(', ')}`);
  }
  return result.contract;
}

function typecheckSource(source: string): TypeCheckResult {
  const contract = parseContract(source);
  return typecheck(contract);
}

function hasError(result: TypeCheckResult, substring: string): boolean {
  return result.errors.some(e => e.message.includes(substring));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Pass 3: Type-Check', () => {
  // ---------------------------------------------------------------------------
  // Valid contracts type-check successfully
  // ---------------------------------------------------------------------------

  describe('valid contracts', () => {
    it('type-checks a valid P2PKH contract', () => {
      const source = `
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
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('type-checks a contract with bigint arithmetic', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            const b: bigint = a + this.x;
            const c: bigint = b * 2n;
            assert(c > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('type-checks a contract with boolean logic', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          public m(sig: Sig) {
            const isValid: boolean = checkSig(sig, this.pk);
            assert(isValid);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('type-checks hash function calls', () => {
      const source = `
        class C extends SmartContract {
          readonly h: Sha256;

          constructor(h: Sha256) {
            super(h);
            this.h = h;
          }

          public m(data: ByteString) {
            assert(sha256(data) === this.h);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  // Wrong type for checkSig arguments
  // ---------------------------------------------------------------------------

  describe('checkSig type errors', () => {
    it('reports error when checkSig receives wrong argument types', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          public m(val: bigint) {
            assert(checkSig(val, this.pk));
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "expected 'Sig'")).toBe(true);
    });

    it('reports error when checkSig second arg is not PubKey', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(sig: Sig) {
            assert(checkSig(sig, this.x));
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "expected 'PubKey'")).toBe(true);
    });

    it('reports error when checkSig has wrong number of args', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          public m(sig: Sig) {
            assert(checkSig(sig));
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "expects 2 argument")).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Bigint arithmetic type rules
  // ---------------------------------------------------------------------------

  describe('bigint arithmetic type rules', () => {
    it('reports error when adding boolean to bigint', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(flag: boolean) {
            const result: bigint = this.x + flag;
            assert(result > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "must be bigint")).toBe(true);
    });

    it('reports error when using arithmetic operator on ByteString', () => {
      const source = `
        class C extends SmartContract {
          readonly x: ByteString;

          constructor(x: ByteString) {
            super(x);
            this.x = x;
          }

          public m(data: ByteString) {
            const result: bigint = data - this.x;
            assert(result > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "must be bigint")).toBe(true);
    });

    it('allows bigint subtraction', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            const diff: bigint = a - this.x;
            assert(diff >= 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('allows bigint multiplication and division', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            const product: bigint = a * 2n;
            const quotient: bigint = product / this.x;
            const remainder: bigint = product % this.x;
            assert(quotient >= 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('allows bitwise operators on bigint', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            const b1: bigint = a & this.x;
            const b2: bigint = a | this.x;
            const b3: bigint = a ^ this.x;
            assert(b1 >= 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('reports error for bitwise op on boolean', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(flag: boolean) {
            const b: bigint = flag & this.x;
            assert(b >= 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "must be bigint or ByteString")).toBe(true);
    });

    it('allows bitwise operators on ByteString operands', () => {
      const source = `
        class C extends SmartContract {
          readonly mask: ByteString;

          constructor(mask: ByteString) {
            super(mask);
            this.mask = mask;
          }

          public m(data: ByteString) {
            const b1: ByteString = data & this.mask;
            const b2: ByteString = data | this.mask;
            const b3: ByteString = data ^ this.mask;
            assert(len(b1) > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('allows ~ (bitwise NOT) on ByteString', () => {
      const source = `
        class C extends SmartContract {
          readonly data: ByteString;

          constructor(data: ByteString) {
            super(data);
            this.data = data;
          }

          public m() {
            const inv: ByteString = ~this.data;
            assert(len(inv) > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('reports error for mixed bigint & ByteString in bitwise op', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(data: ByteString) {
            const b: ByteString = data & this.x;
            assert(len(b) > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  // ---------------------------------------------------------------------------
  // ByteString concatenation with +
  // ---------------------------------------------------------------------------

  describe('ByteString concatenation with +', () => {
    it('allows ByteString + ByteString (concatenation via OP_CAT)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: ByteString;

          constructor(x: ByteString) {
            super(x);
            this.x = x;
          }

          public m(y: ByteString) {
            const z: ByteString = this.x + y;
            assert(len(z) > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('allows PubKey + ByteString (byte family concatenation)', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          public m(data: ByteString) {
            const z: ByteString = this.pk + data;
            assert(len(z) > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('rejects bigint + ByteString (mixed types)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(data: ByteString) {
            const z: ByteString = this.x + data;
            assert(true);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(hasError(result, "must be bigint")).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Comparison operators return boolean
  // ---------------------------------------------------------------------------

  describe('comparison operators return boolean', () => {
    it('comparison operators return boolean, usable in assert', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            assert(a > this.x);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('equality operator returns boolean', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            assert(a === this.x);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('inequality operator returns boolean', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            assert(a !== this.x);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('reports error when comparing incompatible types with ===', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          public m(a: bigint) {
            assert(a === this.pk);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "Cannot compare")).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Logical operators
  // ---------------------------------------------------------------------------

  describe('logical operators', () => {
    it('allows boolean && boolean', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          public m(sig: Sig, a: bigint) {
            assert(checkSig(sig, this.pk) && a > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('reports error for bigint in logical operator', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            assert(a && this.x > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "must be boolean")).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Unary operators
  // ---------------------------------------------------------------------------

  describe('unary operators', () => {
    it('allows ! on boolean', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            assert(!(a === 0n));
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('reports error for ! on bigint', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            assert(!a);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "must be boolean")).toBe(true);
    });

    it('allows unary - on bigint', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            const neg: bigint = -a;
            assert(neg < 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  // If condition type checking
  // ---------------------------------------------------------------------------

  describe('if condition type checking', () => {
    it('reports error when if condition is not boolean', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            if (a) {
              assert(true);
            } else {
              assert(false);
            }
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "must be boolean")).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Variable type inference
  // ---------------------------------------------------------------------------

  describe('variable type inference', () => {
    it('reports error when assigning wrong type to declared variable', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m() {
            const flag: boolean = 42n;
            assert(flag);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "not assignable")).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // assert() type checking
  // ---------------------------------------------------------------------------

  describe('assert type checking', () => {
    it('reports error when assert condition is not boolean', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            assert(a);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "must be boolean")).toBe(true);
    });

    it('allows assert with 2 arguments (condition + message)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint) {
            assert(a > 0n, "must be positive");
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  // Property access type resolution
  // ---------------------------------------------------------------------------

  describe('property access type resolution', () => {
    it('resolves this.x to the property type', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          public m(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const result = typecheckSource(source);
      // checkSig expects (Sig, PubKey) and this.pk is PubKey: should pass
      expect(result.errors).toEqual([]);
    });

    it('reports error for accessing non-existent property', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m() {
            const val: bigint = this.nonexistent;
            assert(val > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "does not exist")).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Subtyping: ByteString domain types
  // ---------------------------------------------------------------------------

  describe('subtyping', () => {
    it('allows PubKey where ByteString is expected (subtype)', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          public m() {
            const h: Sha256 = sha256(this.pk);
            assert(true);
          }
        }
      `;
      // sha256 expects ByteString, PubKey is a subtype of ByteString
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  // Builtin function type checking
  // ---------------------------------------------------------------------------

  describe('builtin function type checking', () => {
    it('checks sha256 argument type', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m() {
            const h: Sha256 = sha256(this.x);
            assert(true);
          }
        }
      `;
      const result = typecheckSource(source);
      // sha256 expects ByteString, but this.x is bigint
      expect(hasError(result, "expected 'ByteString'")).toBe(true);
    });

    it('checks num2bin argument types', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m() {
            const bs: ByteString = num2bin(this.x, 4n);
            assert(true);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  // F-265: substr() literal negative start is a compile-time error
  //
  // substr(witness, start, len) lowers to a raw OP_SPLIT argument. No pass
  // enforced start >= 0: a literal negative start (`substr(a, -5n, 3n)`)
  // type-checked as 'bigint' (the standard subtype loop never inspects a
  // literal's VALUE) and compiled to a script that aborts at runtime --
  // `-5n` minimal-encodes to `<85>`, which OP_SPLIT rejects as out of range.
  //
  // Proves: a literal (bare or unary-negated BigIntLiteral) negative start
  // is now a compile-time diagnostic, mirroring the existing
  // extractPrevOutputScript/requireOutputP2PKH "must be >= 0" literal-bound
  // pattern above. Does not prove: anything about a NON-literal negative
  // start (e.g. a variable or computed expression) -- that remains a
  // runtime abort, same as before, because the stack model has no static
  // value range for a non-literal; that is unchanged pre-existing scope.
  // ---------------------------------------------------------------------------

  describe('F-265: substr() literal start bound', () => {
    it('rejects a literal negative start', () => {
      const source = `
        class C extends SmartContract {
          readonly a: ByteString;

          constructor(a: ByteString) {
            super(a);
            this.a = a;
          }

          public unlock() {
            assert(substr(this.a, -5n, 3n) === this.a);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, 'substr() argument 2 (start) must be >= 0; got -5')).toBe(true);
    });

    it('accepts a non-negative literal start', () => {
      const source = `
        class C extends SmartContract {
          readonly a: ByteString;

          constructor(a: ByteString) {
            super(a);
            this.a = a;
          }

          public unlock() {
            assert(substr(this.a, 0n, 3n) === this.a);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('accepts a non-literal (variable) start unchanged', () => {
      const source = `
        class C extends SmartContract {
          readonly a: ByteString;

          constructor(a: ByteString) {
            super(a);
            this.a = a;
          }

          public unlock(n: bigint) {
            assert(substr(this.a, n, 3n) === this.a);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  // Affine type enforcement
  // ---------------------------------------------------------------------------

  describe('affine type enforcement', () => {
    it('allows using a Sig once in checkSig', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          public m(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('reports error when using a Sig twice in two checkSig calls', () => {
      const source = `
        class C extends SmartContract {
          readonly pk1: PubKey;
          readonly pk2: PubKey;

          constructor(pk1: PubKey, pk2: PubKey) {
            super(pk1, pk2);
            this.pk1 = pk1;
            this.pk2 = pk2;
          }

          public m(sig: Sig) {
            assert(checkSig(sig, this.pk1));
            assert(checkSig(sig, this.pk2));
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "affine value 'sig' has already been consumed")).toBe(true);
    });

    it('reports error when using a SigHashPreimage twice in checkPreimage', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(preimage: SigHashPreimage) {
            assert(checkPreimage(preimage));
            assert(checkPreimage(preimage));
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "affine value 'preimage' has already been consumed")).toBe(true);
    });

    it('allows a non-affine type (PubKey) to be reused freely', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;

          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }

          public m(sig1: Sig, sig2: Sig) {
            assert(checkSig(sig1, this.pk));
            assert(checkSig(sig2, this.pk));
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('allows different Sig values in separate checkSig calls', () => {
      const source = `
        class C extends SmartContract {
          readonly pk1: PubKey;
          readonly pk2: PubKey;

          constructor(pk1: PubKey, pk2: PubKey) {
            super(pk1, pk2);
            this.pk1 = pk1;
            this.pk2 = pk2;
          }

          public m(sig1: Sig, sig2: Sig) {
            assert(checkSig(sig1, this.pk1));
            assert(checkSig(sig2, this.pk2));
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    // F-110: a bounded loop is unrolled `count` times (04-anf-lower
    // `lowerForStatement`), so a consumption written once in the body is
    // executed once per iteration. The checker used to walk the body once and
    // accept a Sig consumed inside a 2-iteration loop while refusing the same
    // two consumptions written out sequentially.
    //
    // Proves: a consumption inside a loop that runs two or more times, of an
    // affine value bound OUTSIDE that loop (param, alias of a param, property),
    // gets the same diagnostic as a sequential double use — including through a
    // count-1 loop nested in a repeating one — while count-0/1 loops and
    // per-iteration values (`sigs[i]`, a local bound inside the body) stay legal.
    // Does not prove: anything about consumption inside private helpers called
    // from the loop (the affine checker is intra-method; that is a separate gap),
    // nor what the emitted script does at runtime.
    describe('F-110: affine consumption inside repeating loops', () => {
      const wrap = (params: string, body: string) => `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public m(${params}) {
            ${body}
          }
        }
      `;

      it('refuses a Sig consumed in a 2-iteration loop body', () => {
        const result = typecheckSource(wrap('sig: Sig',
          'for (let i = 0n; i < 2n; i++) { assert(checkSig(sig, this.pk)); }'));
        expect(hasError(result, "affine value 'sig' has already been consumed")).toBe(true);
      });

      it('refuses a SigHashPreimage consumed in a counting-down loop', () => {
        const result = typecheckSource(wrap('preimage: SigHashPreimage',
          'for (let i = 3n; i > 0n; i--) { assert(checkPreimage(preimage)); }'));
        expect(hasError(result, "affine value 'preimage' has already been consumed")).toBe(true);
      });

      it('refuses an alias of an outer Sig declared inside the loop body', () => {
        const result = typecheckSource(wrap('sig: Sig',
          'for (let i = 0n; i <= 1n; i++) { const s: Sig = sig; assert(checkSig(s, this.pk)); }'));
        expect(hasError(result, "affine value 's' has already been consumed")).toBe(true);
      });

      it('refuses a count-1 inner loop nested in a 2-iteration outer loop', () => {
        const result = typecheckSource(wrap('sig: Sig',
          'for (let i = 0n; i < 2n; i++) { for (let j = 0n; j < 1n; j++) { assert(checkSig(sig, this.pk)); } }'));
        expect(hasError(result, "affine value 'sig' has already been consumed")).toBe(true);
      });

      it('allows a Sig consumed in a single-iteration loop', () => {
        const result = typecheckSource(wrap('sig: Sig',
          'for (let i = 0n; i < 1n; i++) { assert(checkSig(sig, this.pk)); }'));
        expect(result.errors).toEqual([]);
      });

      it('allows nested single-iteration loops', () => {
        const result = typecheckSource(wrap('sig: Sig',
          'for (let i = 5n; i >= 5n; i--) { for (let j = 0n; j <= 0n; j++) { assert(checkSig(sig, this.pk)); } }'));
        expect(result.errors).toEqual([]);
      });

      it('still refuses a single-iteration loop that follows an earlier consumption', () => {
        const result = typecheckSource(wrap('sig: Sig',
          'assert(checkSig(sig, this.pk)); for (let i = 0n; i < 1n; i++) { assert(checkSig(sig, this.pk)); }'));
        expect(hasError(result, "affine value 'sig' has already been consumed")).toBe(true);
      });

      it('allows a distinct Sig per iteration via an indexed array', () => {
        const result = typecheckSource(wrap('sigs: FixedArray<Sig, 2>',
          'for (let i = 0n; i < 2n; i++) { assert(checkSig(sigs[i], this.pk)); }'));
        expect(result.errors).toEqual([]);
      });

      it('allows a Sig bound inside the loop body and consumed once per iteration', () => {
        const result = typecheckSource(wrap('sigs: FixedArray<Sig, 2>',
          'for (let i = 0n; i < 2n; i++) { const s: Sig = sigs[i]; assert(checkSig(s, this.pk)); }'));
        expect(result.errors).toEqual([]);
      });
    });

    // F-222: the then and else arms of an if are mutually exclusive, so a Sig
    // consumed once in each arm is consumed once on every path. The checker
    // used to walk both arms against one shared consumed set and flag the
    // else-arm use as a double consumption.
    //
    // Proves: a value consumed once per arm (directly, through an alias, or in
    // nested ifs) typechecks clean, and every shape where SOME path consumes
    // twice is still refused: consumed in an arm and again after the if (then
    // arm, else arm, both arms, nested arm, via an alias), consumed before and
    // again inside an arm, twice inside one arm, and once per arm inside a
    // 2-iteration loop.
    // Does not prove: the ternary expression form (`c ? checkSig(..) :
    // checkSig(..)`), which is not an if_statement and is still refused; nor
    // anything about the emitted script (see the F-222 execution test).
    describe('F-222: affine consumption across mutually exclusive if/else arms', () => {
      const wrap = (body: string) => `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public m(sig: Sig, flag: boolean) {
            ${body}
          }
        }
      `;
      const DOUBLE = "affine value 'sig' has already been consumed";

      it('allows a Sig consumed once in each of the then and else arms', () => {
        const result = typecheckSource(wrap(
          'if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); }'));
        expect(result.errors).toEqual([]);
      });

      it('allows an alias consumed in one arm and the original in the other', () => {
        const result = typecheckSource(wrap(
          'if (flag) { const a: Sig = sig; assert(checkSig(a, this.pk)); } else { assert(checkSig(sig, this.pk)); }'));
        expect(result.errors).toEqual([]);
      });

      it('allows one consumption per arm across nested if/else', () => {
        const result = typecheckSource(wrap(
          'if (flag) { assert(checkSig(sig, this.pk)); } else { if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } }'));
        expect(result.errors).toEqual([]);
      });

      it('refuses a Sig consumed in the then arm and again after the if', () => {
        const result = typecheckSource(wrap(
          'if (flag) { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk));'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a Sig consumed in the else arm and again after the if', () => {
        const result = typecheckSource(wrap(
          'if (flag) { assert(true); } else { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk));'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a Sig consumed in both arms and again after the if', () => {
        const result = typecheckSource(wrap(
          'if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk));'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a Sig consumed in a nested arm and again after the outer if', () => {
        const result = typecheckSource(wrap(
          'if (flag) { if (flag) { assert(checkSig(sig, this.pk)); } } else { assert(true); } assert(checkSig(sig, this.pk));'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses an alias consumed in an arm and the original again after the if', () => {
        const result = typecheckSource(wrap(
          'const a: Sig = sig; if (flag) { assert(checkSig(a, this.pk)); } else { assert(true); } assert(checkSig(sig, this.pk));'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a Sig consumed before the if and again inside an arm', () => {
        const result = typecheckSource(wrap(
          'assert(checkSig(sig, this.pk)); if (flag) { assert(checkSig(sig, this.pk)); } assert(true);'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a Sig consumed twice inside the then arm', () => {
        const result = typecheckSource(wrap(
          'if (flag) { assert(checkSig(sig, this.pk)); assert(checkSig(sig, this.pk)); } else { assert(true); }'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a Sig consumed twice inside the else arm', () => {
        const result = typecheckSource(wrap(
          'if (flag) { assert(true); } else { assert(checkSig(sig, this.pk)); assert(checkSig(sig, this.pk)); }'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a Sig consumed once per arm inside a 2-iteration loop', () => {
        const result = typecheckSource(wrap(
          'for (let i = 0n; i < 2n; i++) { if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } } assert(true);'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });
    });

    // N-109: private helpers are inlined (04-anf-lower), so a helper that
    // consumes its Sig parameter consumes the caller's argument at every call
    // site. The checker was intra-method: `this.h(sig); this.h(sig);` and
    // `this.h(sig)` in a 2-iteration loop typechecked although the inlined
    // script runs checkSig on the same Sig twice.
    //
    // Proves: a call to a contract method consumes the arguments at the
    // parameter positions that method consumes (directly, through an alias, in
    // an if arm, or transitively through another helper), with the same
    // diagnostic as a sequential double use, including per loop iteration; a
    // single call, and a helper that takes a Sig without consuming it, stay legal.
    // Does not prove: a helper consuming a PROPERTY (`checkSig(this.sig, ..)` in
    // a helper called twice) — the summary covers parameters only; nor
    // untracked argument expressions (`this.h(sigs[i])`), nor the emitted script.
    describe('N-109: affine consumption through private helper calls', () => {
      const wrap = (helpers: string, params: string, body: string) => `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          ${helpers}
          public m(${params}) {
            ${body}
          }
        }
      `;
      const H = 'private h(s: Sig): void { assert(checkSig(s, this.pk)); }';
      const DOUBLE = "affine value 'sig' has already been consumed";

      it('refuses the same Sig passed to a consuming helper twice', () => {
        const result = typecheckSource(wrap(H, 'sig: Sig', 'this.h(sig); this.h(sig);'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a consuming helper called once in a 2-iteration loop', () => {
        const result = typecheckSource(wrap(H, 'sig: Sig',
          'for (let i = 0n; i < 2n; i++) { this.h(sig); } assert(true);'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a Sig consumed directly and again through a helper', () => {
        const result = typecheckSource(wrap(H, 'sig: Sig',
          'assert(checkSig(sig, this.pk)); this.h(sig);'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a helper that consumes transitively through another helper', () => {
        const result = typecheckSource(wrap(
          `${H} private g(t: bigint, s2: Sig): void { assert(t > 0n); this.h(s2); }`,
          'sig: Sig', 'this.g(1n, sig); this.g(2n, sig);'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a helper that consumes an alias of its parameter', () => {
        const result = typecheckSource(wrap(
          'private h(s: Sig): void { const a: Sig = s; assert(checkSig(a, this.pk)); }',
          'sig: Sig', 'this.h(sig); this.h(sig);'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a SigHashPreimage consumed by a helper twice', () => {
        const result = typecheckSource(wrap(
          'private p(x: SigHashPreimage): void { assert(checkPreimage(x)); }',
          'preimage: SigHashPreimage', 'this.p(preimage); this.p(preimage);'));
        expect(hasError(result, "affine value 'preimage' has already been consumed")).toBe(true);
      });

      it('allows a single call to a consuming helper', () => {
        const result = typecheckSource(wrap(H, 'sig: Sig', 'this.h(sig);'));
        expect(result.errors).toEqual([]);
      });

      it('allows a consuming helper called once per if/else arm', () => {
        const result = typecheckSource(wrap(H, 'sig: Sig, flag: boolean',
          'if (flag) { this.h(sig); } else { this.h(sig); }'));
        expect(result.errors).toEqual([]);
      });

      it('allows two different Sigs through the same consuming helper', () => {
        const result = typecheckSource(wrap(H, 'sig1: Sig, sig2: Sig', 'this.h(sig1); this.h(sig2);'));
        expect(result.errors).toEqual([]);
      });

      it('allows a helper that takes a Sig without consuming it to be called twice', () => {
        const result = typecheckSource(wrap(
          'private n(s: Sig): bigint { return len(s); }',
          'sig: Sig', 'assert(this.n(sig) > 0n); assert(this.n(sig) > 0n); assert(checkSig(sig, this.pk));'));
        expect(result.errors).toEqual([]);
      });
    });

    // N-288: the N-109 summary covered PARAMETERS only. A helper that consumes
    // a PROPERTY (`checkSig(this.sig, ..)`, `checkPreimage(this.txPreimage)`)
    // is inlined at every call site, so calling it twice consumes the property
    // twice, yet `this.h(); this.h();` typechecked while the direct
    // `checkSig(this.sig, ..)` twice was refused.
    //
    // Proves: a call to a contract method consumes every property that method
    // consumes (directly, through an alias, or transitively through another
    // helper), refused with the diagnostic a direct double use of the property
    // gets, including per loop iteration and after a direct consume; a single
    // call, one call per if/else arm, and a helper that only reads the property
    // stay legal.
    // Does not prove: the emitted script; untracked argument expressions.
    describe('N-288: affine consumption of a property through private helper calls', () => {
      const wrap = (helpers: string, params: string, body: string) => `
        class C extends SmartContract {
          readonly pk: PubKey;
          readonly sig: Sig;
          constructor(pk: PubKey, sig: Sig) { super(pk, sig); this.pk = pk; this.sig = sig; }
          ${helpers}
          public m(${params}) {
            ${body}
            assert(true);
          }
        }
      `;
      const H = 'private h(): void { assert(checkSig(this.sig, this.pk)); }';
      const DOUBLE = "affine value 'this.sig' has already been consumed";

      it('refuses a helper that consumes this.sig called twice', () => {
        const result = typecheckSource(wrap(H, '', 'this.h(); this.h();'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a helper that consumes this.sig called once in a 2-iteration loop', () => {
        const result = typecheckSource(wrap(H, '', 'for (let i = 0n; i < 2n; i++) { this.h(); }'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses this.sig consumed directly and again through a helper', () => {
        const result = typecheckSource(wrap(H, '', 'assert(checkSig(this.sig, this.pk)); this.h();'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a helper that consumes this.sig transitively through another helper', () => {
        const result = typecheckSource(wrap(
          `${H} private g(t: bigint): void { assert(t > 0n); this.h(); }`,
          '', 'this.g(1n); this.g(2n);'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a helper that consumes an alias of this.sig called twice', () => {
        const result = typecheckSource(wrap(
          'private h(): void { const a: Sig = this.sig; assert(checkSig(a, this.pk)); }',
          '', 'this.h(); this.h();'));
        expect(hasError(result, DOUBLE)).toBe(true);
      });

      it('refuses a stateful helper that consumes this.txPreimage called twice', () => {
        const result = typecheckSource(`
          class C extends StatefulSmartContract {
            count: bigint;
            constructor(count: bigint) { super(count); this.count = count; }
            private h(): void { assert(checkPreimage(this.txPreimage)); }
            public inc() {
              this.h();
              this.h();
              this.count = this.count + 1n;
            }
          }
        `);
        expect(hasError(result, "affine value 'this.txPreimage' has already been consumed")).toBe(true);
      });

      it('allows a single call to a helper that consumes this.sig', () => {
        const result = typecheckSource(wrap(H, '', 'this.h();'));
        expect(result.errors).toEqual([]);
      });

      it('allows a helper that consumes this.sig called once per if/else arm', () => {
        const result = typecheckSource(wrap(H, 'flag: boolean',
          'if (flag) { this.h(); } else { this.h(); }'));
        expect(result.errors).toEqual([]);
      });

      it('allows a helper that only reads this.sig to be called twice', () => {
        const result = typecheckSource(wrap(
          'private n(): bigint { return len(this.sig); }',
          '', 'assert(this.n() > 0n); assert(this.n() > 0n); assert(checkSig(this.sig, this.pk));'));
        expect(result.errors).toEqual([]);
      });
    });
  });

  // ---------------------------------------------------------------------------
  // Unknown function rejection
  // ---------------------------------------------------------------------------

  describe('unknown function rejection', () => {
    it('rejects Math.floor (non-Rúnar member expression call)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const b: bigint = Math.floor(a);
            assert(b > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "Unknown function 'Math.floor'")).toBe(true);
    });

    it('rejects console.log (non-Rúnar member expression call)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            console.log(a);
            assert(a > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "Unknown function 'console.log'")).toBe(true);
    });

    it('rejects unknown standalone function calls', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const b: bigint = someRandomFunc(a);
            assert(b > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "Unknown function 'someRandomFunc'")).toBe(true);
    });

    // F-208: Rúnar has no first-class functions. A bound local variable used
    // as a callee used to fall into the "local variable" branch and return
    // '<unknown>' with NO diagnostic, silently accepting the call.
    it('rejects a local variable used as a function call', () => {
      const source = `
        class C extends SmartContract {
          readonly a: bigint;
          constructor(a: bigint) { super(a); this.a = a; }
          public m(a: bigint) {
            const f: bigint = a;
            const r = f(a, a, a);
            assert(this.a >= 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "is not callable")).toBe(true);
    });

    it('allows known Rúnar builtins', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public m(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('allows split builtin on ByteString', () => {
      const source = `
        class C extends SmartContract {
          readonly data: ByteString;
          constructor(data: ByteString) { super(data); this.data = data; }
          public m() {
            const left: ByteString = split(this.data, 10n);
            assert(len(left) === 10n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('allows calls to private contract methods', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          helper(a: bigint): bigint { return a + 1n; }
          public m(a: bigint) {
            const b: bigint = this.helper(a);
            assert(b > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  // Undefined variable detection
  // ---------------------------------------------------------------------------

  describe('undefined variable detection', () => {
    it('reports error for typo in constructor assignment', () => {
      const source = `
        class C extends SmartContract {
          readonly pubKeyHash: Ripemd160;
          constructor(pubKeyHash: Ripemd160) {
            super(pubKeyHash);
            this.pubKeyHash = pubKeyHashhhhh;
          }
          public unlock(sig: Sig, pk: PubKey) {
            assert(checkSig(sig, pk));
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "Undefined variable 'pubKeyHashhhhh'")).toBe(true);
    });

    it('reports error for undefined variable in method body', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const b: bigint = undeclaredVar + a;
            assert(b > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "Undefined variable 'undeclaredVar'")).toBe(true);
    });

    it('reports error for undefined variable used as function argument', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public m(sig: Sig) {
            assert(checkSig(sig, nonExistentPubKey));
          }
        }
      `;
      const result = typecheckSource(source);
      expect(hasError(result, "Undefined variable 'nonExistentPubKey'")).toBe(true);
    });

    it('does not report error for defined local variables', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const b: bigint = a + 1n;
            assert(b > 0n);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('does not report error for for-loop variables', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() {
            for (let i: bigint = 0n; i < 10n; i++) {
              assert(i >= 0n);
            }
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('does not report error for known global constants (EC_P, EC_N, EC_G)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            assert(a < EC_N);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });

    it('does not report error for SigHash namespace', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            assert(a === SigHash.ALL);
          }
        }
      `;
      const result = typecheckSource(source);
      expect(result.errors).toEqual([]);
    });
  });

  // -------------------------------------------------------------------------
  // addOutput via member_expr (Python/Move/Go format parsers)
  // -------------------------------------------------------------------------

  describe('addOutput via member_expr callee', () => {
    it('accepts this.addOutput() in stateful Python contract', () => {
      const py = `
from runar import StatefulSmartContract, PubKey, Sig, Bigint, Readonly, ByteString, public, assert_, check_sig

class Token(StatefulSmartContract):
    owner: PubKey
    balance: Bigint
    token_id: Readonly[ByteString]

    def __init__(self, owner: PubKey, balance: Bigint, token_id: ByteString):
        super().__init__(owner, balance, token_id)
        self.owner = owner
        self.balance = balance
        self.token_id = token_id

    @public
    def send(self, sig: Sig, to: PubKey, output_satoshis: Bigint):
        assert_(check_sig(sig, self.owner))
        self.add_output(output_satoshis, to, self.balance)
`;
      const contract = parseContract(py, 'Token.runar.py');
      const result = typecheck(contract);
      expect(result.errors).toEqual([]);
    });

    it('accepts this.addRawOutput() in stateful Python contract', () => {
      const py = `
from runar import StatefulSmartContract, PubKey, Sig, Bigint, ByteString, public, assert_, check_sig

class Vault(StatefulSmartContract):
    owner: PubKey
    balance: Bigint

    def __init__(self, owner: PubKey, balance: Bigint):
        super().__init__(owner, balance)
        self.owner = owner
        self.balance = balance

    @public
    def withdraw(self, sig: Sig, script: ByteString, sats: Bigint):
        assert_(check_sig(sig, self.owner))
        self.add_raw_output(sats, script)
`;
      const contract = parseContract(py, 'Vault.runar.py');
      const result = typecheck(contract);
      expect(result.errors).toEqual([]);
    });

    it('rejects addOutput in stateless Python contract', () => {
      const py = `
from runar import SmartContract, Bigint, public, assert_

class Bad(SmartContract):
    x: Bigint

    def __init__(self, x: Bigint):
        super().__init__(x)
        self.x = x

    @public
    def check(self, sats: Bigint):
        self.add_output(sats, 0)
`;
      const contract = parseContract(py, 'Bad.runar.py');
      const result = typecheck(contract);
      expect(hasError(result, 'addOutput() is only available in StatefulSmartContract')).toBe(true);
    });
  });
});
