import { describe, it, expect } from 'vitest';
import { parseMoveSource } from '../passes/01-parse-move.js';
import type {
  BinaryExpr,
  CallExpr,
  Identifier,
  BigIntLiteral,
  BoolLiteral,
  UnaryExpr,
  IfStatement,
  VariableDeclStatement,
  ExpressionStatement,
  ReturnStatement,
} from '../ir/index.js';

// ---------------------------------------------------------------------------
// Helper: basic P2PKH in Move-like syntax
// ---------------------------------------------------------------------------

const P2PKH_MOVE = `
module P2PKH {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig};

    struct P2PKH {
        pk: PubKey,
    }

    public fun unlock(contract: &P2PKH, sig: Sig) {
        assert!(check_sig(sig, contract.pk), 0);
    }
}
`;

// ---------------------------------------------------------------------------
// Contract structure
// ---------------------------------------------------------------------------

describe('Move Parser', () => {
  describe('contract structure', () => {
    it('parses a P2PKH contract and returns a ContractNode', () => {
      const result = parseMoveSource(P2PKH_MOVE);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.kind).toBe('contract');
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('sets parentClass to SmartContract for non-resource structs', () => {
      const result = parseMoveSource(P2PKH_MOVE);
      expect(result.contract!.parentClass).toBe('SmartContract');
    });

    it('uses default fileName when none provided', () => {
      const result = parseMoveSource(P2PKH_MOVE);
      expect(result.contract!.sourceFile).toBe('contract.runar.move');
    });

    it('uses custom fileName when provided', () => {
      const result = parseMoveSource(P2PKH_MOVE, 'p2pkh.runar.move');
      expect(result.contract!.sourceFile).toBe('p2pkh.runar.move');
    });

    it('skips use declarations', () => {
      const result = parseMoveSource(P2PKH_MOVE);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('sets parentClass to StatefulSmartContract for resource struct', () => {
      const move = `
module Counter {
    resource struct Counter {
        count: &mut bigint,
    }

    public fun increment(contract: &mut Counter) {
        contract.count = contract.count + 1;
    }
}
`;
      const result = parseMoveSource(move);
      expect(result.contract!.parentClass).toBe('StatefulSmartContract');
    });

    it('sets parentClass to StatefulSmartContract when mutable fields present', () => {
      const move = `
module Counter {
    struct Counter {
        count: &mut bigint,
    }

    public fun increment(contract: &mut Counter) {
        contract.count = contract.count + 1;
    }
}
`;
      const result = parseMoveSource(move);
      expect(result.contract!.parentClass).toBe('StatefulSmartContract');
    });
  });

  // ---------------------------------------------------------------------------
  // Properties
  // ---------------------------------------------------------------------------

  describe('properties', () => {
    it('extracts a readonly property from struct', () => {
      const result = parseMoveSource(P2PKH_MOVE);
      const contract = result.contract!;
      expect(contract.properties).toHaveLength(1);
      const pk = contract.properties[0]!;
      expect(pk.kind).toBe('property');
      expect(pk.name).toBe('pk');
      expect(pk.readonly).toBe(true);
      expect(pk.type).toEqual({ kind: 'primitive_type', name: 'PubKey' });
    });

    it('marks &mut fields as non-readonly', () => {
      const move = `
module C {
    struct C {
        count: &mut bigint,
        max_count: bigint,
    }
    public fun m(contract: &mut C) {
        assert!(true, 0);
    }
}
`;
      const result = parseMoveSource(move);
      expect(result.contract!.properties[0]!.readonly).toBe(false);
      expect(result.contract!.properties[0]!.name).toBe('count');
      expect(result.contract!.properties[1]!.readonly).toBe(true);
      expect(result.contract!.properties[1]!.name).toBe('maxCount'); // snake_case -> camelCase
    });

    it('parses multiple properties', () => {
      const move = `
module Escrow {
    struct Escrow {
        pk1: PubKey,
        pk2: PubKey,
        amount: bigint,
    }
    public fun release(contract: &Escrow, sig: Sig) {
        assert!(check_sig(sig, contract.pk1), 0);
    }
}
`;
      const result = parseMoveSource(move);
      expect(result.contract!.properties).toHaveLength(3);
      expect(result.contract!.properties.map(p => p.name)).toEqual(['pk1', 'pk2', 'amount']);
    });

    it('converts snake_case property names to camelCase', () => {
      const move = `
module C {
    struct C {
        max_count: bigint,
        pub_key_hash: Addr,
    }
    public fun m(contract: &C) {
        assert!(true, 0);
    }
}
`;
      const result = parseMoveSource(move);
      expect(result.contract!.properties[0]!.name).toBe('maxCount');
      expect(result.contract!.properties[1]!.name).toBe('pubKeyHash');
    });

    it('maps Move types to Rúnar types', () => {
      const move = `
module C {
    struct C {
        a: u64,
        b: u128,
        c: bool,
        d: address,
    }
    public fun m(contract: &C) {
        assert!(true, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const props = result.contract!.properties;
      expect(props[0]!.type).toEqual({ kind: 'primitive_type', name: 'bigint' });
      expect(props[1]!.type).toEqual({ kind: 'primitive_type', name: 'bigint' });
      expect(props[2]!.type).toEqual({ kind: 'primitive_type', name: 'boolean' });
      expect(props[3]!.type).toEqual({ kind: 'primitive_type', name: 'Addr' });
    });
  });

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  describe('constructor', () => {
    it('auto-generates constructor from struct fields', () => {
      const result = parseMoveSource(P2PKH_MOVE);
      const ctor = result.contract!.constructor;
      expect(ctor.kind).toBe('method');
      expect(ctor.name).toBe('constructor');
      expect(ctor.params).toHaveLength(1);
      expect(ctor.params[0]!.name).toBe('pk');
    });
  });

  // ---------------------------------------------------------------------------
  // Methods
  // ---------------------------------------------------------------------------

  describe('methods', () => {
    it('parses a public method', () => {
      const result = parseMoveSource(P2PKH_MOVE);
      expect(result.contract!.methods).toHaveLength(1);
      const unlock = result.contract!.methods[0]!;
      expect(unlock.name).toBe('unlock');
      expect(unlock.visibility).toBe('public');
    });

    it('skips contract/self parameter', () => {
      const result = parseMoveSource(P2PKH_MOVE);
      const unlock = result.contract!.methods[0]!;
      // "contract: &P2PKH" should be skipped, only "sig: Sig" remains
      expect(unlock.params).toHaveLength(1);
      expect(unlock.params[0]!.name).toBe('sig');
    });

    it('defaults to private for non-public functions', () => {
      const move = `
module C {
    struct C { x: bigint }
    fun helper(a: bigint): bigint { return a + 1; }
    public fun m(contract: &C) { assert!(true, 0); }
}
`;
      const result = parseMoveSource(move);
      const helper = result.contract!.methods.find(m => m.name === 'helper');
      expect(helper).toBeDefined();
      expect(helper!.visibility).toBe('private');
    });

    it('converts snake_case method names to camelCase', () => {
      const move = `
module C {
    struct C { x: bigint }
    public fun do_something(contract: &C) { assert!(true, 0); }
}
`;
      const result = parseMoveSource(move);
      expect(result.contract!.methods[0]!.name).toBe('doSomething');
    });

    it('converts snake_case parameter names to camelCase', () => {
      const move = `
module C {
    struct C { x: bigint }
    public fun m(contract: &C, my_param: bigint) { assert!(true, 0); }
}
`;
      const result = parseMoveSource(move);
      expect(result.contract!.methods[0]!.params[0]!.name).toBe('myParam');
    });
  });

  // ---------------------------------------------------------------------------
  // Expressions
  // ---------------------------------------------------------------------------

  describe('expressions', () => {
    it('parses binary operations', () => {
      const move = `
module C {
    struct C { x: bigint }
    public fun m(contract: &C, a: bigint, b: bigint) {
        let sum = a + b;
        assert!(sum > 0, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      const init = decl.init as BinaryExpr;
      expect(init.kind).toBe('binary_expr');
      expect(init.op).toBe('+');
    });

    it('maps == to === and != to !==', () => {
      const move = `
module C {
    struct C { x: bigint }
    public fun m(contract: &C, a: bigint) {
        assert!(a == 42, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const cmp = assertCall.args[0] as BinaryExpr;
      expect(cmp.op).toBe('===');
    });

    it('parses assert! as assert()', () => {
      const move = `
module C {
    struct C { x: bigint }
    public fun m(contract: &C) {
        assert!(true, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      expect(assertCall.kind).toBe('call_expr');
      expect((assertCall.callee as Identifier).name).toBe('assert');
    });

    it('parses assert_eq! as assert(a === b)', () => {
      const move = `
module C {
    struct C { target: bigint }
    public fun m(contract: &C, a: bigint) {
        assert_eq!(a, contract.target);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      expect((assertCall.callee as Identifier).name).toBe('assert');
      const cmp = assertCall.args[0] as BinaryExpr;
      expect(cmp.op).toBe('===');
    });

    it('parses number literals as bigint', () => {
      const move = `
module C {
    struct C { x: bigint }
    public fun m(contract: &C) {
        let a = 42;
        assert!(a > 0, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      const lit = decl.init as BigIntLiteral;
      expect(lit.kind).toBe('bigint_literal');
      expect(lit.value).toBe(42n);
    });

    it('parses boolean literals', () => {
      const move = `
module C {
    struct C { x: bigint }
    public fun m(contract: &C) {
        assert!(true, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const boolLit = assertCall.args[0] as BoolLiteral;
      expect(boolLit.kind).toBe('bool_literal');
      expect(boolLit.value).toBe(true);
    });

    it('parses contract.field as property_access', () => {
      const move = `
module C {
    struct C { target: bigint }
    public fun m(contract: &C, a: bigint) {
        assert!(a == contract.target, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const cmp = assertCall.args[0] as BinaryExpr;
      expect(cmp.right.kind).toBe('property_access');
      if (cmp.right.kind === 'property_access') {
        expect(cmp.right.property).toBe('target');
      }
    });

    it('parses unary operators', () => {
      const move = `
module C {
    struct C { x: bigint }
    public fun m(contract: &C, flag: bool) {
        assert!(!flag, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const notExpr = assertCall.args[0] as UnaryExpr;
      expect(notExpr.kind).toBe('unary_expr');
      expect(notExpr.op).toBe('!');
    });

    it('resolves module::function path to just function name', () => {
      const move = `
module C {
    use runar::crypto::{hash160};
    struct C { pk: PubKey }
    public fun m(contract: &C, data: ByteString) {
        let h = runar::hash160(data);
        assert!(true, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      // runar::hash160(data) should become just hash160(data)
      expect(decl.init.kind).toBe('call_expr');
      if (decl.init.kind === 'call_expr') {
        expect(decl.init.callee.kind).toBe('identifier');
        if (decl.init.callee.kind === 'identifier') {
          expect(decl.init.callee.name).toBe('hash160');
        }
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Statements
  // ---------------------------------------------------------------------------

  describe('statements', () => {
    it('parses let declarations', () => {
      const move = `
module C {
    struct C { x: bigint }
    public fun m(contract: &C) {
        let a: bigint = 42;
        assert!(a > 0, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      expect(decl.kind).toBe('variable_decl');
      expect(decl.name).toBe('a');
      expect(decl.mutable).toBe(false);
    });

    it('parses let mut declarations', () => {
      const move = `
module C {
    struct C { x: bigint }
    public fun m(contract: &C) {
        let mut a: bigint = 0;
        a = a + 1;
        assert!(a > 0, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      expect(decl.kind).toBe('variable_decl');
      expect(decl.mutable).toBe(true);
    });

    it('parses assignment to contract fields', () => {
      const move = `
module C {
    struct C { count: &mut bigint }
    public fun m(contract: &mut C) {
        contract.count = contract.count + 1;
        assert!(true, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const assignStmt = method.body[0]!;
      expect(assignStmt.kind).toBe('assignment');
      if (assignStmt.kind === 'assignment') {
        expect(assignStmt.target.kind).toBe('property_access');
      }
    });

    it('parses if/else statements', () => {
      const move = `
module C {
    struct C { x: bigint }
    public fun m(contract: &C, a: bigint) {
        if (a > 0) {
            assert!(true, 0);
        } else {
            assert!(false, 0);
        }
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const ifStmt = method.body[0] as IfStatement;
      expect(ifStmt.kind).toBe('if_statement');
      expect(ifStmt.then.length).toBeGreaterThan(0);
      expect(ifStmt.else).toBeDefined();
    });

    it('parses return statements', () => {
      const move = `
module C {
    struct C { x: bigint }
    fun helper(a: bigint): bigint {
        return a + 1;
    }
    public fun m(contract: &C) { assert!(true, 0); }
}
`;
      const result = parseMoveSource(move);
      const helper = result.contract!.methods.find(m => m.name === 'helper')!;
      const retStmt = helper.body[0] as ReturnStatement;
      expect(retStmt.kind).toBe('return_statement');
      expect(retStmt.value).toBeDefined();
    });

    it('parses compound assignment (+=)', () => {
      const move = `
module C {
    struct C { x: bigint }
    public fun m(contract: &C) {
        let mut a: bigint = 1;
        a += 2;
        assert!(a > 0, 0);
    }
}
`;
      const result = parseMoveSource(move);
      const method = result.contract!.methods[0]!;
      const assignStmt = method.body[1]!;
      expect(assignStmt.kind).toBe('assignment');
      if (assignStmt.kind === 'assignment') {
        expect(assignStmt.value.kind).toBe('binary_expr');
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Full contract: Arithmetic conformance
  // ---------------------------------------------------------------------------

  describe('conformance: arithmetic', () => {
    it('parses the arithmetic Move contract', () => {
      const move = `
module Arithmetic {
    use runar::types::{Int};

    struct Arithmetic {
        target: Int,
    }

    public fun verify(contract: &Arithmetic, a: Int, b: Int) {
        let sum = a + b;
        let diff = a - b;
        let prod = a * b;
        let quot = a / b;
        let result = sum + diff + prod + quot;
        assert_eq!(result, contract.target);
    }
}
`;
      const result = parseMoveSource(move);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const contract = result.contract!;
      expect(contract.name).toBe('Arithmetic');
      expect(contract.properties).toHaveLength(1);
      expect(contract.methods).toHaveLength(1);
      expect(contract.methods[0]!.params).toHaveLength(2);
      expect(contract.methods[0]!.body.length).toBeGreaterThanOrEqual(6);
    });
  });
});
