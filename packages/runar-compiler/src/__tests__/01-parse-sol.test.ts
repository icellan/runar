import { describe, it, expect } from 'vitest';
import { parseSolSource } from '../passes/01-parse-sol.js';
import type {
  BinaryExpr,
  CallExpr,
  Identifier,
  BigIntLiteral,
  BoolLiteral,
  UnaryExpr,
  IfStatement,
  ForStatement,
  VariableDeclStatement,
  ExpressionStatement,
  ReturnStatement,
} from '../ir/index.js';

// ---------------------------------------------------------------------------
// Helper: basic P2PKH in Solidity-like syntax
// ---------------------------------------------------------------------------

const P2PKH_SOL = `
pragma runar ^0.1.0;

contract P2PKH is SmartContract {
    PubKey immutable pk;

    constructor(PubKey _pk) {
        pk = _pk;
    }

    function unlock(Sig sig) public {
        require(checkSig(sig, pk));
    }
}
`;

// ---------------------------------------------------------------------------
// Contract structure
// ---------------------------------------------------------------------------

describe('Solidity Parser', () => {
  describe('contract structure', () => {
    it('parses a P2PKH contract and returns a ContractNode', () => {
      const result = parseSolSource(P2PKH_SOL);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.kind).toBe('contract');
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('sets parentClass to SmartContract', () => {
      const result = parseSolSource(P2PKH_SOL);
      expect(result.contract!.parentClass).toBe('SmartContract');
    });

    it('uses default fileName when none provided', () => {
      const result = parseSolSource(P2PKH_SOL);
      expect(result.contract!.sourceFile).toBe('contract.runar.sol');
    });

    it('uses custom fileName when provided', () => {
      const result = parseSolSource(P2PKH_SOL, 'p2pkh.runar.sol');
      expect(result.contract!.sourceFile).toBe('p2pkh.runar.sol');
    });

    it('skips pragma statement', () => {
      const result = parseSolSource(P2PKH_SOL);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('parses StatefulSmartContract', () => {
      const sol = `
contract Counter is StatefulSmartContract {
    bigint count;
    constructor(bigint _count) { count = _count; }
    function increment() public { count = count + 1; }
}
`;
      const result = parseSolSource(sol);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract!.parentClass).toBe('StatefulSmartContract');
    });
  });

  // ---------------------------------------------------------------------------
  // Properties
  // ---------------------------------------------------------------------------

  describe('properties', () => {
    it('extracts an immutable property as readonly', () => {
      const result = parseSolSource(P2PKH_SOL);
      const contract = result.contract!;
      expect(contract.properties).toHaveLength(1);
      const pk = contract.properties[0]!;
      expect(pk.kind).toBe('property');
      expect(pk.name).toBe('pk');
      expect(pk.readonly).toBe(true);
      expect(pk.type).toEqual({ kind: 'primitive_type', name: 'PubKey' });
    });

    it('parses non-immutable property as non-readonly', () => {
      const sol = `
contract C is SmartContract {
    bigint count;
    constructor(bigint _count) { count = _count; }
    function m() public { require(true); }
}
`;
      const result = parseSolSource(sol);
      expect(result.contract!.properties[0]!.readonly).toBe(false);
    });

    it('parses multiple properties', () => {
      const sol = `
contract Escrow is SmartContract {
    PubKey immutable pk1;
    PubKey immutable pk2;
    bigint immutable amount;
    constructor(PubKey _pk1, PubKey _pk2, bigint _amount) {
        pk1 = _pk1; pk2 = _pk2; amount = _amount;
    }
    function release(Sig sig) public { require(checkSig(sig, pk1)); }
}
`;
      const result = parseSolSource(sol);
      expect(result.contract!.properties).toHaveLength(3);
      expect(result.contract!.properties.map(p => p.name)).toEqual(['pk1', 'pk2', 'amount']);
    });

    it('maps Solidity types to Rúnar types', () => {
      const sol = `
contract C is SmartContract {
    uint256 immutable x;
    bool immutable f;
    address immutable a;
    bytes immutable b;
    constructor(uint256 _x, bool _f, address _a, bytes _b) {
        x = _x; f = _f; a = _a; b = _b;
    }
    function m() public { require(true); }
}
`;
      const result = parseSolSource(sol);
      const props = result.contract!.properties;
      // uint256 -> bigint
      expect(props[0]!.type).toEqual({ kind: 'primitive_type', name: 'bigint' });
      // bool -> boolean
      expect(props[1]!.type).toEqual({ kind: 'primitive_type', name: 'boolean' });
      // address -> Addr
      expect(props[2]!.type).toEqual({ kind: 'primitive_type', name: 'Addr' });
      // bytes -> ByteString
      expect(props[3]!.type).toEqual({ kind: 'primitive_type', name: 'ByteString' });
    });

    it('parses array type as FixedArray', () => {
      const sol = `
contract C is SmartContract {
    bigint[3] immutable arr;
    constructor(bigint[3] _arr) { arr = _arr; }
    function m() public { require(true); }
}
`;
      const result = parseSolSource(sol);
      const prop = result.contract!.properties[0]!;
      expect(prop.type.kind).toBe('fixed_array_type');
      if (prop.type.kind === 'fixed_array_type') {
        expect(prop.type.length).toBe(3);
        expect(prop.type.element).toEqual({ kind: 'primitive_type', name: 'bigint' });
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  describe('constructor', () => {
    it('parses explicit constructor', () => {
      const result = parseSolSource(P2PKH_SOL);
      const ctor = result.contract!.constructor;
      expect(ctor.kind).toBe('method');
      expect(ctor.name).toBe('constructor');
      expect(ctor.params).toHaveLength(1);
      // Solidity strips _ prefix from param names
      expect(ctor.params[0]!.name).toBe('pk');
    });

    it('constructor body contains property assignments', () => {
      const result = parseSolSource(P2PKH_SOL);
      const ctor = result.contract!.constructor;
      // At minimum, the assignment pk = _pk
      const assignment = ctor.body.find(s => s.kind === 'assignment');
      expect(assignment).toBeDefined();
    });

    it('auto-generates constructor when not present', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    function m() public { require(true); }
}
`;
      const result = parseSolSource(sol);
      expect(result.contract!.constructor).toBeDefined();
      expect(result.contract!.constructor.name).toBe('constructor');
    });
  });

  // ---------------------------------------------------------------------------
  // Methods
  // ---------------------------------------------------------------------------

  describe('methods', () => {
    it('parses a public method', () => {
      const result = parseSolSource(P2PKH_SOL);
      expect(result.contract!.methods).toHaveLength(1);
      const unlock = result.contract!.methods[0]!;
      expect(unlock.name).toBe('unlock');
      expect(unlock.visibility).toBe('public');
    });

    it('defaults to private visibility', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function helper(bigint a) returns (bigint) { return a + 1; }
    function m() public { require(true); }
}
`;
      const result = parseSolSource(sol);
      const helper = result.contract!.methods.find(m => m.name === 'helper');
      expect(helper).toBeDefined();
      expect(helper!.visibility).toBe('private');
    });

    it('parses method parameters', () => {
      const result = parseSolSource(P2PKH_SOL);
      const unlock = result.contract!.methods[0]!;
      expect(unlock.params).toHaveLength(1);
      expect(unlock.params[0]!.name).toBe('sig');
      expect(unlock.params[0]!.type).toEqual({ kind: 'primitive_type', name: 'Sig' });
    });
  });

  // ---------------------------------------------------------------------------
  // Expressions
  // ---------------------------------------------------------------------------

  describe('expressions', () => {
    it('parses binary arithmetic', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function m(bigint a, bigint b) public {
        bigint sum = a + b;
        require(sum > 0);
    }
}
`;
      const result = parseSolSource(sol);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      expect(decl.kind).toBe('variable_decl');
      const init = decl.init as BinaryExpr;
      expect(init.kind).toBe('binary_expr');
      expect(init.op).toBe('+');
    });

    it('maps == to === and != to !==', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function m(bigint a) public {
        require(a == 42);
        require(a != 0);
    }
}
`;
      const result = parseSolSource(sol);
      const method = result.contract!.methods[0]!;
      // First require: a == 42 -> assert(a === 42)
      const stmt1 = method.body[0] as ExpressionStatement;
      const assert1 = stmt1.expression as CallExpr;
      const cmp1 = assert1.args[0] as BinaryExpr;
      expect(cmp1.op).toBe('===');

      // Second require: a != 0 -> assert(a !== 0)
      const stmt2 = method.body[1] as ExpressionStatement;
      const assert2 = stmt2.expression as CallExpr;
      const cmp2 = assert2.args[0] as BinaryExpr;
      expect(cmp2.op).toBe('!==');
    });

    it('parses unary operators', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function m(bool flag) public {
        require(!flag);
    }
}
`;
      const result = parseSolSource(sol);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const notExpr = assertCall.args[0] as UnaryExpr;
      expect(notExpr.kind).toBe('unary_expr');
      expect(notExpr.op).toBe('!');
    });

    it('parses function calls', () => {
      const result = parseSolSource(P2PKH_SOL);
      const method = result.contract!.methods[0]!;
      // require(checkSig(sig, pk))
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      expect(assertCall.kind).toBe('call_expr');
      const innerCall = assertCall.args[0] as CallExpr;
      expect(innerCall.kind).toBe('call_expr');
      expect((innerCall.callee as Identifier).name).toBe('checkSig');
    });

    it('parses number literals as bigint', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function m() public {
        bigint a = 42;
        require(a > 0);
    }
}
`;
      const result = parseSolSource(sol);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      const lit = decl.init as BigIntLiteral;
      expect(lit.kind).toBe('bigint_literal');
      expect(lit.value).toBe(42n);
    });

    it('parses boolean literals', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function m() public { require(true); }
}
`;
      const result = parseSolSource(sol);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const boolLit = assertCall.args[0] as BoolLiteral;
      expect(boolLit.kind).toBe('bool_literal');
      expect(boolLit.value).toBe(true);
    });

    it('parses hex string literals', () => {
      const sol = `
contract C is SmartContract {
    ByteString immutable x;
    constructor(ByteString _x) { x = _x; }
    function m() public {
        ByteString h = 0xabcd;
        require(true);
    }
}
`;
      const result = parseSolSource(sol);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      expect(decl.init.kind).toBe('bytestring_literal');
      if (decl.init.kind === 'bytestring_literal') {
        expect(decl.init.value).toBe('abcd');
      }
    });

    it('parses property access via this.x', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable target;
    constructor(bigint _target) { target = _target; }
    function m(bigint a) public {
        require(a == this.target);
    }
}
`;
      const result = parseSolSource(sol);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const cmp = assertCall.args[0] as BinaryExpr;
      expect(cmp.right.kind).toBe('property_access');
    });

    it('handles operator precedence correctly', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function m(bigint a, bigint b) public {
        bigint result = a + b * 2;
        require(result > 0);
    }
}
`;
      const result = parseSolSource(sol);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      // a + (b * 2), not (a + b) * 2
      const addExpr = decl.init as BinaryExpr;
      expect(addExpr.op).toBe('+');
      expect(addExpr.right.kind).toBe('binary_expr');
      if (addExpr.right.kind === 'binary_expr') {
        expect(addExpr.right.op).toBe('*');
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Statements
  // ---------------------------------------------------------------------------

  describe('statements', () => {
    it('parses require -> assert', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function m(bigint a) public {
        require(a > 0);
    }
}
`;
      const result = parseSolSource(sol);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      expect(assertCall.kind).toBe('call_expr');
      expect((assertCall.callee as Identifier).name).toBe('assert');
    });

    it('parses if/else statements', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function m(bigint a) public {
        if (a > 0) {
            require(true);
        } else {
            require(false);
        }
    }
}
`;
      const result = parseSolSource(sol);
      const method = result.contract!.methods[0]!;
      const ifStmt = method.body[0] as IfStatement;
      expect(ifStmt.kind).toBe('if_statement');
      expect(ifStmt.then.length).toBeGreaterThan(0);
      expect(ifStmt.else).toBeDefined();
    });

    it('parses for loops', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function m() public {
        let bigint sum = 0;
        for (bigint i = 0; i < 10; i++) {
            sum = sum + i;
        }
        require(sum > 0);
    }
}
`;
      const result = parseSolSource(sol);
      const method = result.contract!.methods[0]!;
      const forStmt = method.body[1] as ForStatement;
      expect(forStmt.kind).toBe('for_statement');
      expect(forStmt.init.name).toBe('i');
    });

    it('parses return statements', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function helper(bigint a) returns (bigint) { return a + 1; }
    function m() public { require(true); }
}
`;
      const result = parseSolSource(sol);
      const helper = result.contract!.methods.find(m => m.name === 'helper')!;
      const retStmt = helper.body[0] as ReturnStatement;
      expect(retStmt.kind).toBe('return_statement');
      expect(retStmt.value).toBeDefined();
    });

    it('parses compound assignment (+=)', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function m() public {
        let bigint a = 1;
        a += 2;
        require(a > 0);
    }
}
`;
      const result = parseSolSource(sol);
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

    it('parses increment/decrement', () => {
      const sol = `
contract C is SmartContract {
    bigint immutable x;
    constructor(bigint _x) { x = _x; }
    function m() public {
        let bigint a = 1;
        a++;
        require(a > 0);
    }
}
`;
      const result = parseSolSource(sol);
      const method = result.contract!.methods[0]!;
      const incStmt = method.body[1] as ExpressionStatement;
      expect(incStmt.expression.kind).toBe('increment_expr');
    });
  });

  // ---------------------------------------------------------------------------
  // Full contract: Arithmetic conformance
  // ---------------------------------------------------------------------------

  describe('conformance: arithmetic', () => {
    it('parses the arithmetic Solidity contract', () => {
      const sol = `
pragma runar ^0.1.0;

contract Arithmetic is SmartContract {
    bigint immutable target;

    constructor(bigint _target) {
        target = _target;
    }

    function verify(bigint a, bigint b) public {
        bigint sum = a + b;
        bigint diff = a - b;
        bigint prod = a * b;
        bigint quot = a / b;
        bigint result = sum + diff + prod + quot;
        require(result == target);
    }
}
`;
      const result = parseSolSource(sol);
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
