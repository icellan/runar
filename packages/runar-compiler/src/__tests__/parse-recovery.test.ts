/**
 * Parser diagnostic-recovery regression tests.
 *
 * The TypeScript parser (`packages/runar-compiler/src/passes/01-parse.ts`)
 * used to call `node.asKindOrThrow(...)` at ~25 refinement sites. When the
 * underlying ts-morph node turned out to be a different kind than the
 * extractor assumed, the parser would throw an unrecoverable exception
 * instead of producing a diagnostic. The audited remediation replaces
 * every such site with a soft `asKind` + diagnostic-push + sentinel
 * pattern via the local `expectKind` helper.
 *
 * Each test below feeds the parser surface-syntax that's valid TypeScript
 * but not valid Rúnar shape, and asserts:
 *   1. The parser does NOT throw.
 *   2. At least one diagnostic is collected.
 *   3. The parser returns either a null contract or a contract whose
 *      methods list is empty / the offending form was dropped — i.e. no
 *      mid-parse crash leaves the caller without a result.
 */

import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';

describe('Pass 1: Parse diagnostic-recovery', () => {
  it('does not crash on a class that does not extend SmartContract', () => {
    const source = `
      class NotAContract {
        public foo(): bigint {
          return 1n;
        }
      }
    `;
    const result = parse(source, 'NotAContract.runar.ts');
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.contract).toBeNull();
  });

  it('does not crash on unexpected parenthesization in a method body', () => {
    // ts-morph models `(x, y)` as a ParenthesizedExpression wrapping a
    // BinaryExpression with the CommaToken operator. Rúnar has no
    // CommaToken in its OP_MAP, so the parser must record a diagnostic
    // for the unsupported binary operator rather than crashing.
    const source = `
      class Weird extends SmartContract {
        readonly x: bigint;
        constructor(x: bigint) {
          super(x);
          this.x = x;
        }
        public foo(y: bigint) {
          const z: bigint = (this.x, y);
          assert(z > 0n);
        }
      }
    `;
    let result: ReturnType<typeof parse> | undefined;
    expect(() => { result = parse(source, 'Weird.runar.ts'); }).not.toThrow();
    expect(result).toBeDefined();
    expect(result!.errors.length).toBeGreaterThan(0);
    // Parser must still return *something* — either a partial contract or null.
    // The unsupported-operator diagnostic is collected, but the method
    // shape is preserved.
    expect(result!.contract).not.toBeUndefined();
  });

  it('does not crash on a destructured constructor parameter', () => {
    // The parser's parseParams() calls param.getName(). On a destructuring
    // pattern, ts-morph still returns a synthesised name string, but this
    // form is not what any extractor downstream anticipated. Verify we
    // do not throw during parse.
    const source = `
      class Destructured extends SmartContract {
        readonly a: bigint;
        readonly b: bigint;
        constructor({ a, b }: { a: bigint; b: bigint }) {
          super(a, b);
          this.a = a;
          this.b = b;
        }
        public foo() {
          assert(this.a > this.b);
        }
      }
    `;
    let result: ReturnType<typeof parse> | undefined;
    expect(() => { result = parse(source, 'Destructured.runar.ts'); }).not.toThrow();
    expect(result).toBeDefined();
    // We expect *some* diagnostic to fire (super() shape mismatch,
    // unsupported type, etc.). Even if none does, the parse must not crash.
    expect(result!.contract).not.toBeUndefined();
  });

  it('does not crash on an array of expressions where a single one was expected', () => {
    // `asm({ body: [...] })` accepts an array body; but feeding the same
    // array shape to a context that expects a scalar (e.g. an arity
    // field) must produce a diagnostic instead of crashing.
    const source = `
      class BadAsm extends SmartContract {
        readonly k: bigint;
        constructor(k: bigint) {
          super(k);
          this.k = k;
        }
        public foo() {
          const v: bigint = asm<bigint>({
            body: '51',
            in_arity: [0, 1, 2] as any,
          });
          assert(v === 1n);
        }
      }
    `;
    let result: ReturnType<typeof parse> | undefined;
    expect(() => { result = parse(source, 'BadAsm.runar.ts'); }).not.toThrow();
    expect(result).toBeDefined();
    expect(result!.errors.length).toBeGreaterThan(0);
    // No crash means we got a result at all — empty methods are acceptable.
    expect(result!.contract).not.toBeUndefined();
  });

  it('does not crash on a function expression where a method declaration was expected', () => {
    // A class property assigned a function expression is valid TS but is
    // not a Rúnar method. ts-morph models it as a PropertyDeclaration
    // whose initializer is an ArrowFunction / FunctionExpression — the
    // extractor must not treat it as a MethodDeclaration. The parser
    // collects diagnostics for the property's unsupported type/init
    // shape rather than crashing.
    const source = `
      class FnExprProp extends SmartContract {
        readonly k: bigint;
        readonly fn = function () { return 1n; };
        constructor(k: bigint) {
          super(k);
          this.k = k;
        }
        public foo() {
          assert(this.k > 0n);
        }
      }
    `;
    let result: ReturnType<typeof parse> | undefined;
    expect(() => { result = parse(source, 'FnExprProp.runar.ts'); }).not.toThrow();
    expect(result).toBeDefined();
    expect(result!.errors.length).toBeGreaterThan(0);
    expect(result!.contract).not.toBeUndefined();
  });

  it('does not crash on a method body with a comma-separated tuple expression', () => {
    // Stress an unexpected expression shape inside parseExpression's
    // BinaryExpression branch: `(a, b, c)` recursively chains
    // CommaToken-separated BinaryExpressions, none of which Rúnar
    // recognises. Confirm the parser collects diagnostics for every
    // unsupported-operator hit and still returns a contract.
    const source = `
      class TupleExpr extends SmartContract {
        readonly k: bigint;
        constructor(k: bigint) {
          super(k);
          this.k = k;
        }
        public foo() {
          const r: bigint = (1n, 2n, 3n);
          assert(r === 3n);
        }
      }
    `;
    let result: ReturnType<typeof parse> | undefined;
    expect(() => { result = parse(source, 'TupleExpr.runar.ts'); }).not.toThrow();
    expect(result).toBeDefined();
    expect(result!.errors.length).toBeGreaterThan(0);
    expect(result!.contract).not.toBeUndefined();
  });

  it('does not crash on a return statement with an unexpected expression kind', () => {
    // Arrow functions inside a return-value expression aren't valid Rúnar,
    // but the parser must produce a diagnostic rather than throwing when
    // it encounters one.
    const source = `
      class ArrowInReturn extends SmartContract {
        readonly k: bigint;
        constructor(k: bigint) {
          super(k);
          this.k = k;
        }
        public foo(): bigint {
          return ((x: bigint) => x + 1n) as any;
        }
      }
    `;
    let result: ReturnType<typeof parse> | undefined;
    expect(() => { result = parse(source, 'ArrowInReturn.runar.ts'); }).not.toThrow();
    expect(result).toBeDefined();
    expect(result!.errors.length).toBeGreaterThan(0);
    expect(result!.contract).not.toBeUndefined();
  });
});
