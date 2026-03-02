import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import type {
  BinaryExpr,
  CallExpr,
  MemberExpr,
  Identifier,
  BigIntLiteral,
  BoolLiteral,
  ByteStringLiteral,
  UnaryExpr,
  IfStatement,
  ForStatement,
  VariableDeclStatement,
  ExpressionStatement,
  ReturnStatement,
  TernaryExpr,
} from '../ir/index.js';

// ---------------------------------------------------------------------------
// Helper: a minimal P2PKH contract
// ---------------------------------------------------------------------------

const P2PKH_SOURCE = `
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

// ---------------------------------------------------------------------------
// Parsing a simple P2PKH contract
// ---------------------------------------------------------------------------

describe('Pass 1: Parse', () => {
  describe('P2PKH contract structure', () => {
    it('parses a P2PKH contract and returns a ContractNode', () => {
      const result = parse(P2PKH_SOURCE);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.kind).toBe('contract');
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('extracts the contract name', () => {
      const result = parse(P2PKH_SOURCE);
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('sets the sourceFile to the default when none is provided', () => {
      const result = parse(P2PKH_SOURCE);
      expect(result.contract!.sourceFile).toBe('contract.ts');
    });

    it('uses a custom fileName when provided', () => {
      const result = parse(P2PKH_SOURCE, 'p2pkh.ts');
      expect(result.contract!.sourceFile).toBe('p2pkh.ts');
    });
  });

  // ---------------------------------------------------------------------------
  // Properties
  // ---------------------------------------------------------------------------

  describe('properties', () => {
    it('extracts a single readonly property', () => {
      const result = parse(P2PKH_SOURCE);
      const contract = result.contract!;
      expect(contract.properties).toHaveLength(1);

      const pk = contract.properties[0]!;
      expect(pk.kind).toBe('property');
      expect(pk.name).toBe('pk');
      expect(pk.readonly).toBe(true);
      expect(pk.type.kind).toBe('primitive_type');
      if (pk.type.kind === 'primitive_type') {
        expect(pk.type.name).toBe('PubKey');
      }
    });

    it('detects non-readonly properties', () => {
      const source = `
        class Counter extends SmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment() { this.count = this.count + 1n; assert(true); }
        }
      `;
      const result = parse(source);
      const contract = result.contract!;
      expect(contract.properties[0]!.readonly).toBe(false);
    });

    it('extracts property type correctly for bigint', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() { assert(true); }
        }
      `;
      const result = parse(source);
      const prop = result.contract!.properties[0]!;
      expect(prop.type).toEqual({ kind: 'primitive_type', name: 'bigint' });
    });

    it('extracts property type for boolean', () => {
      const source = `
        class C extends SmartContract {
          readonly flag: boolean;
          constructor(flag: boolean) { super(flag); this.flag = flag; }
          public m() { assert(true); }
        }
      `;
      const result = parse(source);
      const prop = result.contract!.properties[0]!;
      expect(prop.type).toEqual({ kind: 'primitive_type', name: 'boolean' });
    });

    it('extracts primitive domain types (Sha256, Ripemd160, etc.)', () => {
      const source = `
        class C extends SmartContract {
          readonly h: Sha256;
          constructor(h: Sha256) { super(h); this.h = h; }
          public m() { assert(true); }
        }
      `;
      const result = parse(source);
      const prop = result.contract!.properties[0]!;
      expect(prop.type.kind).toBe('primitive_type');
      if (prop.type.kind === 'primitive_type') {
        expect(prop.type.name).toBe('Sha256');
      }
    });

    it('reports an error for properties without type annotations', () => {
      const source = `
        class C extends SmartContract {
          readonly x = 0n;
          constructor() { super(); }
          public m() { assert(true); }
        }
      `;
      const result = parse(source);
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors.some(e => e.message.includes('explicit type annotation'))).toBe(true);
    });

    it('parses multiple properties', () => {
      const source = `
        class Escrow extends SmartContract {
          readonly pk1: PubKey;
          readonly pk2: PubKey;
          readonly amount: bigint;
          constructor(pk1: PubKey, pk2: PubKey, amount: bigint) {
            super(pk1, pk2, amount);
            this.pk1 = pk1;
            this.pk2 = pk2;
            this.amount = amount;
          }
          public release(sig: Sig) { assert(checkSig(sig, this.pk1)); }
        }
      `;
      const result = parse(source);
      expect(result.contract!.properties).toHaveLength(3);
      expect(result.contract!.properties.map(p => p.name)).toEqual(['pk1', 'pk2', 'amount']);
    });
  });

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  describe('constructor', () => {
    it('parses constructor parameters', () => {
      const result = parse(P2PKH_SOURCE);
      const ctor = result.contract!.constructor;
      expect(ctor.kind).toBe('method');
      expect(ctor.name).toBe('constructor');
      expect(ctor.params).toHaveLength(1);
      expect(ctor.params[0]!.name).toBe('pk');
      expect(ctor.params[0]!.type).toEqual({ kind: 'primitive_type', name: 'PubKey' });
    });

    it('parses constructor body statements', () => {
      const result = parse(P2PKH_SOURCE);
      const ctor = result.contract!.constructor;
      expect(ctor.body.length).toBeGreaterThanOrEqual(2);

      // First statement: super(pk)
      const superCall = ctor.body[0]!;
      expect(superCall.kind).toBe('expression_statement');

      // Second statement: this.pk = pk
      const assignment = ctor.body[1]!;
      expect(assignment.kind).toBe('assignment');
    });

    it('reports an error when no constructor is present', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          public m() { assert(true); }
        }
      `;
      const result = parse(source);
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors.some(e => e.message.includes('must have a constructor'))).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Methods
  // ---------------------------------------------------------------------------

  describe('methods', () => {
    it('parses a public method with the correct visibility', () => {
      const result = parse(P2PKH_SOURCE);
      const contract = result.contract!;
      expect(contract.methods).toHaveLength(1);
      const unlock = contract.methods[0]!;
      expect(unlock.name).toBe('unlock');
      expect(unlock.visibility).toBe('public');
    });

    it('parses method parameters', () => {
      const result = parse(P2PKH_SOURCE);
      const unlock = result.contract!.methods[0]!;
      expect(unlock.params).toHaveLength(1);
      expect(unlock.params[0]!.name).toBe('sig');
      expect(unlock.params[0]!.type).toEqual({ kind: 'primitive_type', name: 'Sig' });
    });

    it('defaults to private visibility when no modifier is present', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          helper(a: bigint): bigint { return a + 1n; }
          public m() { assert(true); }
        }
      `;
      const result = parse(source);
      const helper = result.contract!.methods.find(m => m.name === 'helper');
      expect(helper).toBeDefined();
      expect(helper!.visibility).toBe('private');
    });

    it('parses multiple methods', () => {
      const source = `
        class Multi extends SmartContract {
          readonly pk1: PubKey;
          readonly pk2: PubKey;
          constructor(pk1: PubKey, pk2: PubKey) {
            super(pk1, pk2);
            this.pk1 = pk1;
            this.pk2 = pk2;
          }
          public spend1(sig: Sig) { assert(checkSig(sig, this.pk1)); }
          public spend2(sig: Sig) { assert(checkSig(sig, this.pk2)); }
        }
      `;
      const result = parse(source);
      expect(result.contract!.methods).toHaveLength(2);
      expect(result.contract!.methods.map(m => m.name)).toEqual(['spend1', 'spend2']);
    });
  });

  // ---------------------------------------------------------------------------
  // Expressions
  // ---------------------------------------------------------------------------

  describe('expressions', () => {
    it('parses binary operations', () => {
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
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      // First statement: const b = a + 1n
      const decl = method.body[0] as VariableDeclStatement;
      expect(decl.kind).toBe('variable_decl');
      const init = decl.init as BinaryExpr;
      expect(init.kind).toBe('binary_expr');
      expect(init.op).toBe('+');
    });

    it('parses call expressions', () => {
      const result = parse(P2PKH_SOURCE);
      const method = result.contract!.methods[0]!;
      // assert(checkSig(sig, this.pk))
      const exprStmt = method.body[0] as ExpressionStatement;
      expect(exprStmt.kind).toBe('expression_statement');
      const assertCall = exprStmt.expression as CallExpr;
      expect(assertCall.kind).toBe('call_expr');
      expect((assertCall.callee as Identifier).name).toBe('assert');

      // Inner call: checkSig(sig, this.pk)
      const checkSigCall = assertCall.args[0] as CallExpr;
      expect(checkSigCall.kind).toBe('call_expr');
      expect((checkSigCall.callee as Identifier).name).toBe('checkSig');
      expect(checkSigCall.args).toHaveLength(2);
    });

    it('parses property access (this.x) as property_access node', () => {
      const result = parse(P2PKH_SOURCE);
      const method = result.contract!.methods[0]!;
      const exprStmt = method.body[0] as ExpressionStatement;
      const assertCall = exprStmt.expression as CallExpr;
      const checkSigCall = assertCall.args[0] as CallExpr;
      // Second arg is this.pk
      const thisPk = checkSigCall.args[1]!;
      expect(thisPk.kind).toBe('property_access');
      if (thisPk.kind === 'property_access') {
        expect(thisPk.property).toBe('pk');
      }
    });

    it('parses unary expressions', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) { assert(!(a === 0n)); }
        }
      `;
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      const exprStmt = method.body[0] as ExpressionStatement;
      const assertCall = exprStmt.expression as CallExpr;
      const notExpr = assertCall.args[0] as UnaryExpr;
      expect(notExpr.kind).toBe('unary_expr');
      expect(notExpr.op).toBe('!');
    });

    it('parses bigint literals', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() { const a: bigint = 42n; assert(a > 0n); }
        }
      `;
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      const lit = decl.init as BigIntLiteral;
      expect(lit.kind).toBe('bigint_literal');
      expect(lit.value).toBe(42n);
    });

    it('parses boolean literals', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() { assert(true); }
        }
      `;
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      const exprStmt = method.body[0] as ExpressionStatement;
      const assertCall = exprStmt.expression as CallExpr;
      const boolLit = assertCall.args[0] as BoolLiteral;
      expect(boolLit.kind).toBe('bool_literal');
      expect(boolLit.value).toBe(true);
    });

    it('parses string literals as bytestring_literal', () => {
      const source = `
        class C extends SmartContract {
          readonly x: ByteString;
          constructor(x: ByteString) { super(x); this.x = x; }
          public m() { const h: ByteString = "abcd"; assert(true); }
        }
      `;
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      const lit = decl.init as ByteStringLiteral;
      expect(lit.kind).toBe('bytestring_literal');
      expect(lit.value).toBe('abcd');
    });

    it('parses ternary expressions', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const b: bigint = a > 0n ? a : -a;
            assert(b > 0n);
          }
        }
      `;
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      const ternary = decl.init as TernaryExpr;
      expect(ternary.kind).toBe('ternary_expr');
    });

    it('parses member expressions (non-this)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() { const v: bigint = SigHash.ALL; assert(v > 0n); }
        }
      `;
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      const memberExpr = decl.init as MemberExpr;
      expect(memberExpr.kind).toBe('member_expr');
      expect(memberExpr.property).toBe('ALL');
      expect((memberExpr.object as Identifier).name).toBe('SigHash');
    });

    it('parses comparison operators producing correct BinaryOp', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            assert(a >= 0n);
          }
        }
      `;
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      const exprStmt = method.body[0] as ExpressionStatement;
      const assertCall = exprStmt.expression as CallExpr;
      const cmp = assertCall.args[0] as BinaryExpr;
      expect(cmp.kind).toBe('binary_expr');
      expect(cmp.op).toBe('>=');
    });
  });

  // ---------------------------------------------------------------------------
  // Statements
  // ---------------------------------------------------------------------------

  describe('statements', () => {
    it('parses variable declarations with const', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() { const a: bigint = 1n; assert(a > 0n); }
        }
      `;
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      expect(decl.kind).toBe('variable_decl');
      expect(decl.name).toBe('a');
      expect(decl.mutable).toBe(false);
    });

    it('parses variable declarations with let', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() { let a: bigint = 1n; a = a + 1n; assert(a > 0n); }
        }
      `;
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      expect(decl.kind).toBe('variable_decl');
      expect(decl.mutable).toBe(true);
    });

    it('parses if/else statements', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            if (a > 0n) {
              assert(true);
            } else {
              assert(false);
            }
          }
        }
      `;
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      const ifStmt = method.body[0] as IfStatement;
      expect(ifStmt.kind).toBe('if_statement');
      expect(ifStmt.then.length).toBeGreaterThan(0);
      expect(ifStmt.else).toBeDefined();
      expect(ifStmt.else!.length).toBeGreaterThan(0);
    });

    it('parses for loops', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() {
            let sum: bigint = 0n;
            for (let i: bigint = 0n; i < 10n; i++) {
              sum = sum + i;
            }
            assert(sum > 0n);
          }
        }
      `;
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      // body[0] is let sum = 0n, body[1] is the for loop
      const forStmt = method.body[1] as ForStatement;
      expect(forStmt.kind).toBe('for_statement');
      expect(forStmt.init.name).toBe('i');
      expect(forStmt.body.length).toBeGreaterThan(0);
    });

    it('parses return statements', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          helper(a: bigint): bigint { return a + 1n; }
          public m() { assert(true); }
        }
      `;
      const result = parse(source);
      const helper = result.contract!.methods.find(m => m.name === 'helper')!;
      const retStmt = helper.body[0] as ReturnStatement;
      expect(retStmt.kind).toBe('return_statement');
      expect(retStmt.value).toBeDefined();
    });

    it('parses assignment statements (this.x = ...)', () => {
      const result = parse(P2PKH_SOURCE);
      const ctor = result.contract!.constructor;
      // super(pk) then this.pk = pk
      const assignment = ctor.body[1]!;
      expect(assignment.kind).toBe('assignment');
      if (assignment.kind === 'assignment') {
        expect(assignment.target.kind).toBe('property_access');
        if (assignment.target.kind === 'property_access') {
          expect(assignment.target.property).toBe('pk');
        }
      }
    });

    it('parses compound assignment (+=) as assignment with binary op', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() {
            let a: bigint = 1n;
            a += 2n;
            assert(a > 0n);
          }
        }
      `;
      const result = parse(source);
      const method = result.contract!.methods[0]!;
      const assignStmt = method.body[1]!;
      expect(assignStmt.kind).toBe('assignment');
      if (assignStmt.kind === 'assignment') {
        expect(assignStmt.value.kind).toBe('binary_expr');
        if (assignStmt.value.kind === 'binary_expr') {
          expect(assignStmt.value.op).toBe('+');
        }
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Error handling
  // ---------------------------------------------------------------------------

  describe('error handling', () => {
    it('returns error when no class is found', () => {
      const source = `const x = 42;`;
      const result = parse(source);
      expect(result.contract).toBeNull();
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]!.message).toContain('No class extending SmartContract');
    });

    it('returns error when class does not extend SmartContract', () => {
      const source = `
        class NotAContract {
          readonly x: bigint;
          constructor(x: bigint) { this.x = x; }
        }
      `;
      const result = parse(source);
      expect(result.contract).toBeNull();
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors.some(e => e.message.includes('No class extending SmartContract'))).toBe(true);
    });

    it('reports an error for multiple SmartContract subclasses', () => {
      const source = `
        class A extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() { assert(true); }
        }
        class B extends SmartContract {
          readonly y: bigint;
          constructor(y: bigint) { super(y); this.y = y; }
          public m() { assert(true); }
        }
      `;
      const result = parse(source);
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors.some(e => e.message.includes('Only one SmartContract subclass'))).toBe(true);
    });

    it('returns error diagnostics with source location info', () => {
      const source = `const x = 42;`;
      const result = parse(source);
      const err = result.errors[0]!;
      expect(err.loc).toBeDefined();
      expect(err.loc!.file).toBe('contract.ts');
      expect(typeof err.loc!.line).toBe('number');
      expect(typeof err.loc!.column).toBe('number');
    });

    it('warns about == usage and maps it to ===', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            assert(a == 0n);
          }
        }
      `;
      const result = parse(source);
      const warnings = result.errors.filter(e => e.severity === 'warning');
      expect(warnings.some(w => w.message.includes('Use === instead of =='))).toBe(true);
      // The expression should still be parsed as ===
      const method = result.contract!.methods[0]!;
      const exprStmt = method.body[0] as ExpressionStatement;
      const assertCall = exprStmt.expression as CallExpr;
      const cmp = assertCall.args[0] as BinaryExpr;
      expect(cmp.op).toBe('===');
    });
  });

  // ---------------------------------------------------------------------------
  // Type parsing
  // ---------------------------------------------------------------------------

  describe('type parsing', () => {
    it('parses FixedArray types', () => {
      const source = `
        class C extends SmartContract {
          readonly arr: FixedArray<bigint, 3>;
          constructor(arr: FixedArray<bigint, 3>) {
            super(arr);
            this.arr = arr;
          }
          public m() { assert(true); }
        }
      `;
      const result = parse(source);
      const prop = result.contract!.properties[0]!;
      expect(prop.type.kind).toBe('fixed_array_type');
      if (prop.type.kind === 'fixed_array_type') {
        expect(prop.type.length).toBe(3);
        expect(prop.type.element).toEqual({ kind: 'primitive_type', name: 'bigint' });
      }
    });

    it('parses void return type in method context', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(): void { assert(true); }
        }
      `;
      // This should parse without errors (void is a valid return type)
      const result = parse(source);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  // StatefulSmartContract
  // ---------------------------------------------------------------------------

  describe('StatefulSmartContract', () => {
    it('parses a class extending StatefulSmartContract', () => {
      const source = `
        class Counter extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment() { this.count++; }
        }
      `;
      const result = parse(source);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.name).toBe('Counter');
    });

    it('sets parentClass to StatefulSmartContract', () => {
      const source = `
        class Counter extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment() { this.count++; }
        }
      `;
      const result = parse(source);
      expect(result.contract!.parentClass).toBe('StatefulSmartContract');
    });

    it('sets parentClass to SmartContract for regular contracts', () => {
      const source = `
        class P2PKH extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) { assert(checkSig(sig, this.pk)); }
        }
      `;
      const result = parse(source);
      expect(result.contract!.parentClass).toBe('SmartContract');
    });

    it('does not include txPreimage in parsed properties', () => {
      const source = `
        class Counter extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment() { this.count++; }
        }
      `;
      const result = parse(source);
      expect(result.contract!.properties.map(p => p.name)).toEqual(['count']);
    });
  });
});
