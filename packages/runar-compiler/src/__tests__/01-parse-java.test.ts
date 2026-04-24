import { describe, it, expect } from 'vitest';
import { parseJavaSource } from '../passes/01-parse-java.js';
import { parse } from '../passes/01-parse.js';
import type {
  AssignmentStatement,
  BigIntLiteral,
  BinaryExpr,
  BoolLiteral,
  ByteStringLiteral,
  CallExpr,
  ExpressionStatement,
  ForStatement,
  Identifier,
  IfStatement,
  MemberExpr,
  PropertyAccessExpr,
  ReturnStatement,
  TernaryExpr,
  UnaryExpr,
  VariableDeclStatement,
} from '../ir/index.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const P2PKH_JAVA = `
package runar.examples.p2pkh;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;
import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

class P2PKH extends SmartContract {
    @Readonly Addr pubKeyHash;

    P2PKH(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
`;

const COUNTER_JAVA = `
package runar.examples.counter;

import java.math.BigInteger;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;

import static runar.lang.Builtins.assertThat;

class Counter extends StatefulSmartContract {
    BigInteger count;

    Counter(BigInteger count) {
        super(count);
        this.count = count;
    }

    @Public
    void increment() {
        this.count = this.count + BigInteger.ONE;
    }

    @Public
    void decrement() {
        assertThat(this.count > BigInteger.ZERO);
        this.count = this.count - BigInteger.ONE;
    }
}
`;

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('Java Parser', () => {
  describe('contract structure', () => {
    it('parses a P2PKH contract and returns a ContractNode', () => {
      const result = parseJavaSource(P2PKH_JAVA, 'P2PKH.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.kind).toBe('contract');
      expect(result.contract!.name).toBe('P2PKH');
      expect(result.contract!.parentClass).toBe('SmartContract');
      expect(result.contract!.sourceFile).toBe('P2PKH.runar.java');
    });

    it('uses default fileName when none provided', () => {
      const result = parseJavaSource(P2PKH_JAVA);
      expect(result.contract!.sourceFile).toBe('contract.runar.java');
    });

    it('parses StatefulSmartContract', () => {
      const result = parseJavaSource(COUNTER_JAVA, 'Counter.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract!.parentClass).toBe('StatefulSmartContract');
      expect(result.contract!.name).toBe('Counter');
    });

    it('dispatches to the Java parser via the top-level parse()', () => {
      const result = parse(P2PKH_JAVA, 'P2PKH.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract!.name).toBe('P2PKH');
    });
  });

  // -------------------------------------------------------------------------
  // Properties & annotations
  // -------------------------------------------------------------------------

  describe('properties', () => {
    it('marks @Readonly fields readonly', () => {
      const result = parseJavaSource(P2PKH_JAVA, 'P2PKH.runar.java');
      const pk = result.contract!.properties[0]!;
      expect(pk.name).toBe('pubKeyHash');
      expect(pk.readonly).toBe(true);
      expect(pk.type).toEqual({ kind: 'primitive_type', name: 'Addr' });
      expect(pk.initializer).toBeUndefined();
    });

    it('treats unannotated fields as mutable (StatefulSmartContract state)', () => {
      const result = parseJavaSource(COUNTER_JAVA, 'Counter.runar.java');
      const count = result.contract!.properties[0]!;
      expect(count.name).toBe('count');
      expect(count.readonly).toBe(false);
      expect(count.type).toEqual({ kind: 'primitive_type', name: 'bigint' });
    });

    it('maps Bigint/BigInteger alias to bigint', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint threshold;
    C(Bigint threshold) { super(threshold); this.threshold = threshold; }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      const p = result.contract!.properties[0]!;
      expect(p.type).toEqual({ kind: 'primitive_type', name: 'bigint' });
    });

    it('parses a property with BigInteger.ZERO initializer', () => {
      const src = `
class Counter extends StatefulSmartContract {
    BigInteger count = BigInteger.ZERO;
    @Readonly PubKey owner;
    Counter(PubKey owner) { super(owner); this.owner = owner; }
}
`;
      const result = parseJavaSource(src, 'Counter.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const props = result.contract!.properties;
      expect(props).toHaveLength(2);
      const count = props.find(p => p.name === 'count')!;
      expect(count.initializer).toBeDefined();
      expect(count.initializer!.kind).toBe('bigint_literal');
      if (count.initializer!.kind === 'bigint_literal') {
        expect(count.initializer!.value).toBe(0n);
      }
    });

    it('excludes initialized properties from the synthetic constructor', () => {
      const src = `
class C extends StatefulSmartContract {
    BigInteger count = BigInteger.ZERO;
    @Readonly PubKey owner;
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      // No explicit constructor, so one was synthesised.
      const ctor = result.contract!.constructor;
      expect(ctor.name).toBe('constructor');
      // Only `owner` should appear as a param; `count` has an initializer.
      expect(ctor.params.map(p => p.name)).toEqual(['owner']);
    });
  });

  // -------------------------------------------------------------------------
  // Constructor
  // -------------------------------------------------------------------------

  describe('constructor', () => {
    it('emits super(...) call as first body statement', () => {
      const result = parseJavaSource(P2PKH_JAVA, 'P2PKH.runar.java');
      const ctor = result.contract!.constructor;
      expect(ctor.name).toBe('constructor');
      expect(ctor.params).toHaveLength(1);
      expect(ctor.params[0]!.name).toBe('pubKeyHash');
      expect(ctor.body.length).toBeGreaterThanOrEqual(2);

      const first = ctor.body[0] as ExpressionStatement;
      expect(first.kind).toBe('expression_statement');
      const call = first.expression as CallExpr;
      expect((call.callee as Identifier).name).toBe('super');
      expect(call.args).toHaveLength(1);
      expect((call.args[0] as Identifier).name).toBe('pubKeyHash');
    });

    it('translates this.x = y into AssignmentStatement with PropertyAccess target', () => {
      const result = parseJavaSource(P2PKH_JAVA, 'P2PKH.runar.java');
      const ctor = result.contract!.constructor;
      const assign = ctor.body[1] as AssignmentStatement;
      expect(assign.kind).toBe('assignment');
      const target = assign.target as PropertyAccessExpr;
      expect(target.kind).toBe('property_access');
      expect(target.property).toBe('pubKeyHash');
    });
  });

  // -------------------------------------------------------------------------
  // Methods
  // -------------------------------------------------------------------------

  describe('methods', () => {
    it('parses @Public methods as public', () => {
      const result = parseJavaSource(P2PKH_JAVA, 'P2PKH.runar.java');
      const unlock = result.contract!.methods[0]!;
      expect(unlock.name).toBe('unlock');
      expect(unlock.visibility).toBe('public');
      expect(unlock.params.map(p => p.name)).toEqual(['sig', 'pubKey']);
      expect(unlock.params[0]!.type).toEqual({ kind: 'primitive_type', name: 'Sig' });
      expect(unlock.params[1]!.type).toEqual({ kind: 'primitive_type', name: 'PubKey' });
    });

    it('treats non-@Public methods as private', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    BigInteger helper(BigInteger a) {
        return a + BigInteger.ONE;
    }

    @Public
    void check() { assertThat(true); }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      const helper = result.contract!.methods.find(m => m.name === 'helper')!;
      const check = result.contract!.methods.find(m => m.name === 'check')!;
      expect(helper.visibility).toBe('private');
      expect(check.visibility).toBe('public');
    });

    it('parses method bodies that static-import builtins', () => {
      const result = parseJavaSource(P2PKH_JAVA, 'P2PKH.runar.java');
      const unlock = result.contract!.methods[0]!;
      expect(unlock.body).toHaveLength(2);

      const first = unlock.body[0] as ExpressionStatement;
      const assertCall = first.expression as CallExpr;
      expect((assertCall.callee as Identifier).name).toBe('assertThat');

      // hash160(pubKey).equals(pubKeyHash) → call(MemberExpr(call(hash160,…),equals),…)
      const equalsCall = assertCall.args[0] as CallExpr;
      const equalsCallee = equalsCall.callee as MemberExpr;
      expect(equalsCallee.property).toBe('equals');
      const hash160Call = equalsCallee.object as CallExpr;
      expect((hash160Call.callee as Identifier).name).toBe('hash160');
    });
  });

  // -------------------------------------------------------------------------
  // Expressions
  // -------------------------------------------------------------------------

  describe('expressions', () => {
    it('maps BigInteger.valueOf(N) to BigIntLiteral(N)', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint threshold;
    C(Bigint threshold) { super(threshold); this.threshold = threshold; }

    @Public
    void check(Bigint x) {
        assertThat(x == BigInteger.valueOf(7));
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const cmp = assertCall.args[0] as BinaryExpr;
      expect(cmp.kind).toBe('binary_expr');
      expect(cmp.op).toBe('===');
      expect((cmp.left as Identifier).name).toBe('x');
      expect(cmp.right.kind).toBe('bigint_literal');
      if (cmp.right.kind === 'bigint_literal') {
        expect(cmp.right.value).toBe(7n);
      }
    });

    it('maps BigInteger.{ZERO,ONE,TWO,TEN} to BigIntLiteral', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    @Public
    void m() {
        assertThat(BigInteger.ZERO == BigInteger.ZERO);
        assertThat(BigInteger.ONE == BigInteger.ONE);
        assertThat(BigInteger.TWO == BigInteger.TWO);
        assertThat(BigInteger.TEN == BigInteger.TEN);
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const method = result.contract!.methods[0]!;
      const values = [0n, 1n, 2n, 10n];
      method.body.forEach((stmt, i) => {
        const call = (stmt as ExpressionStatement).expression as CallExpr;
        const cmp = call.args[0] as BinaryExpr;
        expect((cmp.left as BigIntLiteral).value).toBe(values[i]);
        expect((cmp.right as BigIntLiteral).value).toBe(values[i]);
      });
    });

    it('maps ByteString.fromHex("deadbeef") to ByteStringLiteral', () => {
      const src = `
class C extends SmartContract {
    @Readonly ByteString magic;
    C(ByteString magic) { super(magic); this.magic = magic; }

    @Public
    void check() {
        assertThat(magic.equals(ByteString.fromHex("deadbeef")));
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const equalsCall = assertCall.args[0] as CallExpr;
      const arg = equalsCall.args[0] as ByteStringLiteral;
      expect(arg.kind).toBe('bytestring_literal');
      expect(arg.value).toBe('deadbeef');
    });

    it('maps this.foo to PropertyAccessExpr', () => {
      const result = parseJavaSource(COUNTER_JAVA, 'Counter.runar.java');
      // increment body: this.count = this.count + BigInteger.ONE;
      const inc = result.contract!.methods.find(m => m.name === 'increment')!;
      const assign = inc.body[0] as AssignmentStatement;
      expect((assign.target as PropertyAccessExpr).property).toBe('count');
      const bin = assign.value as BinaryExpr;
      expect(bin.op).toBe('+');
      expect((bin.left as PropertyAccessExpr).property).toBe('count');
      expect((bin.right as BigIntLiteral).value).toBe(1n);
    });

    it('maps == to === and != to !==', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    @Public
    void m(Bigint a) {
        assertThat(a == BigInteger.ZERO);
        assertThat(a != BigInteger.ONE);
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const method = result.contract!.methods[0]!;
      const eqCmp = ((method.body[0] as ExpressionStatement).expression as CallExpr).args[0] as BinaryExpr;
      expect(eqCmp.op).toBe('===');
      const neCmp = ((method.body[1] as ExpressionStatement).expression as CallExpr).args[0] as BinaryExpr;
      expect(neCmp.op).toBe('!==');
    });

    it('maps arithmetic, comparison, logical, bitwise, and shift operators', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    @Public
    void m(Bigint a, Bigint b) {
        assertThat((a + b) > 0);
        assertThat((a - b) < 10);
        assertThat((a * b) >= 0);
        assertThat((a / b) <= 5);
        assertThat((a % b) == 0);
        assertThat((a & b) > 0);
        assertThat((a | b) > 0);
        assertThat((a ^ b) > 0);
        assertThat((a << 1) > 0);
        assertThat((a >> 1) > 0);
        assertThat((a > 0) && (b > 0));
        assertThat((a > 0) || (b > 0));
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const method = result.contract!.methods[0]!;
      const ops = ['+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>', '&&', '||'];
      method.body.slice(0, ops.length).forEach((s, i) => {
        const arg = ((s as ExpressionStatement).expression as CallExpr).args[0] as BinaryExpr;
        // Each outer assertThat argument is either a comparison or the direct
        // boolean expression; extract the appropriate child for verification.
        const binaryOp = ops[i];
        const actual = extractOperator(arg, binaryOp!);
        expect(actual, `case ${binaryOp}`).toBe(true);
      });
    });

    it('parses unary operators (!, -, ~, prefix/postfix ++/--)', () => {
      const src = `
class C extends StatefulSmartContract {
    BigInteger count;
    C(BigInteger count) { super(count); this.count = count; }

    @Public
    void m(boolean flag, BigInteger a) {
        assertThat(!flag);
        assertThat(-a < 0);
        assertThat(~a != 0);
        this.count = ++this.count;
        this.count = this.count--;
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const m = result.contract!.methods[0]!;

      const notCall = ((m.body[0] as ExpressionStatement).expression as CallExpr).args[0] as UnaryExpr;
      expect(notCall.kind).toBe('unary_expr');
      expect(notCall.op).toBe('!');

      const negCmp = ((m.body[1] as ExpressionStatement).expression as CallExpr).args[0] as BinaryExpr;
      expect((negCmp.left as UnaryExpr).op).toBe('-');

      const bitNotCmp = ((m.body[2] as ExpressionStatement).expression as CallExpr).args[0] as BinaryExpr;
      expect((bitNotCmp.left as UnaryExpr).op).toBe('~');

      // `++this.count` → prefix increment
      const prefixAssign = m.body[3] as AssignmentStatement;
      const incr = prefixAssign.value as { kind: 'increment_expr'; prefix: boolean };
      expect(incr.kind).toBe('increment_expr');
      expect(incr.prefix).toBe(true);

      // `this.count--` → postfix decrement
      const postfixAssign = m.body[4] as AssignmentStatement;
      const decr = postfixAssign.value as { kind: 'decrement_expr'; prefix: boolean };
      expect(decr.kind).toBe('decrement_expr');
      expect(decr.prefix).toBe(false);
    });

    it('parses ternary conditional', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    @Public
    void m(boolean flag) {
        assertThat(flag ? true : false);
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const m = result.contract!.methods[0]!;
      const arg = ((m.body[0] as ExpressionStatement).expression as CallExpr).args[0] as TernaryExpr;
      expect(arg.kind).toBe('ternary_expr');
      expect((arg.consequent as BoolLiteral).value).toBe(true);
      expect((arg.alternate as BoolLiteral).value).toBe(false);
    });

    it('parses array literal via new T[]{...}', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    @Public
    void m() {
        BigInteger arr = new BigInteger[]{BigInteger.valueOf(1), BigInteger.valueOf(2), BigInteger.valueOf(3)};
        assertThat(true);
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const m = result.contract!.methods[0]!;
      const decl = m.body[0] as VariableDeclStatement;
      expect(decl.kind).toBe('variable_decl');
      expect(decl.init.kind).toBe('array_literal');
      if (decl.init.kind === 'array_literal') {
        expect(decl.init.elements).toHaveLength(3);
        expect((decl.init.elements[0]! as BigIntLiteral).value).toBe(1n);
      }
    });

    it('parses array (index) access', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    @Public
    void m(FixedArray<BigInteger, 3> arr) {
        assertThat(arr[0] > BigInteger.ZERO);
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const m = result.contract!.methods[0]!;
      const call = (m.body[0] as ExpressionStatement).expression as CallExpr;
      const cmp = call.args[0] as BinaryExpr;
      expect(cmp.left.kind).toBe('index_access');
    });

    it('parses FixedArray<T, N> parameter type', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    @Public
    void m(FixedArray<BigInteger, 3> arr) {
        assertThat(true);
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const m = result.contract!.methods[0]!;
      expect(m.params[0]!.type).toEqual({
        kind: 'fixed_array_type',
        element: { kind: 'primitive_type', name: 'bigint' },
        length: 3,
      });
    });
  });

  // -------------------------------------------------------------------------
  // Statements
  // -------------------------------------------------------------------------

  describe('statements', () => {
    it('parses if/else', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    @Public
    void m(Bigint a) {
        if (a > BigInteger.ZERO) {
            assertThat(true);
        } else {
            assertThat(false);
        }
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const m = result.contract!.methods[0]!;
      const ifStmt = m.body[0] as IfStatement;
      expect(ifStmt.kind).toBe('if_statement');
      expect(ifStmt.then.length).toBeGreaterThan(0);
      expect(ifStmt.else).toBeDefined();
    });

    it('parses for loop with literal bound', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    @Public
    void m() {
        BigInteger sum = BigInteger.ZERO;
        for (BigInteger i = BigInteger.ZERO; i < BigInteger.TEN; i = i + BigInteger.ONE) {
            sum = sum + i;
        }
        assertThat(sum > BigInteger.ZERO);
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const m = result.contract!.methods[0]!;
      const forStmt = m.body[1] as ForStatement;
      expect(forStmt.kind).toBe('for_statement');
      expect(forStmt.init.name).toBe('i');
    });

    it('parses return statements in private helpers', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    BigInteger helper(BigInteger a) {
        return a + BigInteger.ONE;
    }

    @Public
    void m() { assertThat(true); }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const helper = result.contract!.methods.find(m => m.name === 'helper')!;
      const ret = helper.body[0] as ReturnStatement;
      expect(ret.kind).toBe('return_statement');
      expect(ret.value).toBeDefined();
    });

    it('parses a variable declaration with initializer', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    @Public
    void m(Bigint a, Bigint b) {
        BigInteger sum = a + b;
        assertThat(sum > BigInteger.ZERO);
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const m = result.contract!.methods[0]!;
      const decl = m.body[0] as VariableDeclStatement;
      expect(decl.kind).toBe('variable_decl');
      expect(decl.name).toBe('sum');
      expect(decl.type).toEqual({ kind: 'primitive_type', name: 'bigint' });
      expect(decl.init.kind).toBe('binary_expr');
    });
  });

  // -------------------------------------------------------------------------
  // Error cases
  // -------------------------------------------------------------------------

  describe('error handling', () => {
    it('rejects a class missing the extends clause', () => {
      const src = `class Bad { @Readonly Addr pkh; }`;
      const result = parseJavaSource(src, 'Bad.runar.java');
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]!.message).toMatch(/extend/i);
    });

    it('rejects a class extending an unknown base class', () => {
      const src = `class Bad extends Frobulator { }`;
      const result = parseJavaSource(src, 'Bad.runar.java');
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors.length).toBeGreaterThan(0);
      expect(errors.some(e => e.message.includes('Frobulator'))).toBe(true);
    });

    it('rejects unsupported annotations', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    @Deprecated
    @Public
    void m() { assertThat(true); }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      expect(result.errors.some(e => e.severity === 'error' && e.message.includes('@Deprecated'))).toBe(true);
    });

    it('rejects while loops', () => {
      const src = `
class C extends SmartContract {
    @Readonly Bigint x;
    C(Bigint x) { super(x); this.x = x; }

    @Public
    void m() {
        while (true) { assertThat(true); }
    }
}
`;
      const result = parseJavaSource(src, 'C.runar.java');
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors.length).toBeGreaterThan(0);
    });
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Given a binary expression that may be either a direct use of the target
 * operator or one wrapped inside a comparison (`(a OP b) > 0`), verify that
 * the operator appears somewhere in the expression tree.
 */
function extractOperator(expr: BinaryExpr, op: string): boolean {
  function walk(e: unknown): boolean {
    if (!e || typeof e !== 'object') return false;
    const node = e as { kind?: string; op?: string; left?: unknown; right?: unknown };
    if (node.kind === 'binary_expr' && node.op === op) return true;
    return walk(node.left) || walk(node.right);
  }
  return walk(expr);
}
