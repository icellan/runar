import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { typecheck } from '../passes/03-typecheck.js';
import type { TypeCheckResult } from '../passes/03-typecheck.js';
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
});
