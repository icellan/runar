import { describe, it, expect } from 'vitest';
import { parseGoSource } from '../passes/01-parse-go.js';
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
// Helper: basic P2PKH in Go syntax
// ---------------------------------------------------------------------------

const P2PKH_GO = `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type P2PKH struct {
	runar.SmartContract
	PubKeyHash runar.Addr \`runar:"readonly"\`
}

func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
	runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))
}
`;

// ---------------------------------------------------------------------------
// Contract structure
// ---------------------------------------------------------------------------

describe('Go Parser', () => {
  describe('contract structure', () => {
    it('parses a P2PKH contract and returns a ContractNode', () => {
      const result = parseGoSource(P2PKH_GO);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.kind).toBe('contract');
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('sets parentClass to SmartContract', () => {
      const result = parseGoSource(P2PKH_GO);
      expect(result.contract!.parentClass).toBe('SmartContract');
    });

    it('uses default fileName when none provided', () => {
      const result = parseGoSource(P2PKH_GO);
      expect(result.contract!.sourceFile).toBe('contract.runar.go');
    });

    it('uses custom fileName when provided', () => {
      const result = parseGoSource(P2PKH_GO, 'p2pkh.runar.go');
      expect(result.contract!.sourceFile).toBe('p2pkh.runar.go');
    });

    it('skips package and import declarations', () => {
      const result = parseGoSource(P2PKH_GO);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('parses StatefulSmartContract', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type Counter struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

func (c *Counter) Increment() {
	c.Count++
}
`;
      const result = parseGoSource(go);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract!.parentClass).toBe('StatefulSmartContract');
    });
  });

  // ---------------------------------------------------------------------------
  // Properties
  // ---------------------------------------------------------------------------

  describe('properties', () => {
    it('extracts a readonly property from struct tag', () => {
      const result = parseGoSource(P2PKH_GO);
      const contract = result.contract!;
      expect(contract.properties).toHaveLength(1);
      const pkh = contract.properties[0]!;
      expect(pkh.kind).toBe('property');
      expect(pkh.name).toBe('pubKeyHash'); // PascalCase -> camelCase
      expect(pkh.readonly).toBe(true);
      expect(pkh.type).toEqual({ kind: 'primitive_type', name: 'Addr' });
    });

    it('parses non-tagged property as non-readonly', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type Counter struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

func (c *Counter) Increment() { c.Count++ }
`;
      const result = parseGoSource(go);
      expect(result.contract!.properties[0]!.readonly).toBe(false);
    });

    it('parses multiple properties', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type Escrow struct {
	runar.SmartContract
	Pk1    runar.PubKey \`runar:"readonly"\`
	Pk2    runar.PubKey \`runar:"readonly"\`
	Amount runar.Bigint \`runar:"readonly"\`
}

func (c *Escrow) Release(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Pk1))
}
`;
      const result = parseGoSource(go);
      expect(result.contract!.properties).toHaveLength(3);
      expect(result.contract!.properties.map(p => p.name)).toEqual(['pk1', 'pk2', 'amount']);
    });

    it('converts PascalCase property names to camelCase', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct {
	runar.SmartContract
	PubKeyHash runar.Addr \`runar:"readonly"\`
	MaxCount   runar.Bigint \`runar:"readonly"\`
}

func (c *C) M() { runar.Assert(true) }
`;
      const result = parseGoSource(go);
      expect(result.contract!.properties[0]!.name).toBe('pubKeyHash');
      expect(result.contract!.properties[1]!.name).toBe('maxCount');
    });

    it('maps Go types to Rúnar types', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct {
	runar.SmartContract
	A runar.Bigint  \`runar:"readonly"\`
	B runar.PubKey  \`runar:"readonly"\`
	D runar.Addr    \`runar:"readonly"\`
}

func (c *C) M() { runar.Assert(true) }
`;
      const result = parseGoSource(go);
      const props = result.contract!.properties;
      expect(props[0]!.type).toEqual({ kind: 'primitive_type', name: 'bigint' });
      expect(props[1]!.type).toEqual({ kind: 'primitive_type', name: 'PubKey' });
      expect(props[2]!.type).toEqual({ kind: 'primitive_type', name: 'Addr' });
    });
  });

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  describe('constructor', () => {
    it('auto-generates constructor from struct fields', () => {
      const result = parseGoSource(P2PKH_GO);
      const ctor = result.contract!.constructor;
      expect(ctor.kind).toBe('method');
      expect(ctor.name).toBe('constructor');
      expect(ctor.params).toHaveLength(1);
      expect(ctor.params[0]!.name).toBe('pubKeyHash');
    });

    it('auto-generated constructor body contains super() call', () => {
      const result = parseGoSource(P2PKH_GO);
      const ctor = result.contract!.constructor;
      const superCall = ctor.body[0] as ExpressionStatement;
      expect(superCall.kind).toBe('expression_statement');
      const callExpr = superCall.expression as CallExpr;
      expect(callExpr.kind).toBe('call_expr');
      expect((callExpr.callee as Identifier).name).toBe('super');
    });

    it('auto-generates constructor for multiple properties', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type Escrow struct {
	runar.SmartContract
	Seller runar.PubKey \`runar:"readonly"\`
	Buyer  runar.PubKey \`runar:"readonly"\`
	Amount runar.Bigint \`runar:"readonly"\`
}

func (c *Escrow) Release(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Seller))
}
`;
      const result = parseGoSource(go);
      const ctor = result.contract!.constructor;
      expect(ctor.params).toHaveLength(3);
      expect(ctor.params.map(p => p.name)).toEqual(['seller', 'buyer', 'amount']);
    });
  });

  // ---------------------------------------------------------------------------
  // Methods
  // ---------------------------------------------------------------------------

  describe('methods', () => {
    it('parses a public method (capitalized)', () => {
      const result = parseGoSource(P2PKH_GO);
      expect(result.contract!.methods).toHaveLength(1);
      const unlock = result.contract!.methods[0]!;
      expect(unlock.name).toBe('unlock'); // PascalCase -> camelCase
      expect(unlock.visibility).toBe('public');
    });

    it('parses a private method (lowercase)', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct {
	runar.SmartContract
	X runar.Bigint \`runar:"readonly"\`
}

func (c *C) helper(a runar.Bigint) runar.Bigint { return a + 1 }
func (c *C) Main() { runar.Assert(c.helper(c.X) > 0) }
`;
      const result = parseGoSource(go);
      const helper = result.contract!.methods.find(m => m.name === 'helper');
      expect(helper).toBeDefined();
      expect(helper!.visibility).toBe('private');
    });

    it('parses method parameters (receiver excluded)', () => {
      const result = parseGoSource(P2PKH_GO);
      const unlock = result.contract!.methods[0]!;
      expect(unlock.params).toHaveLength(2);
      expect(unlock.params[0]!.name).toBe('sig');
      expect(unlock.params[0]!.type).toEqual({ kind: 'primitive_type', name: 'Sig' });
      expect(unlock.params[1]!.name).toBe('pubKey');
      expect(unlock.params[1]!.type).toEqual({ kind: 'primitive_type', name: 'PubKey' });
    });

    it('converts PascalCase method names to camelCase', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) DoSomething() { runar.Assert(true) }
`;
      const result = parseGoSource(go);
      expect(result.contract!.methods[0]!.name).toBe('doSomething');
    });

    it('converts PascalCase parameter names to camelCase', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) M(MyParam runar.Bigint) { runar.Assert(MyParam > 0) }
`;
      const result = parseGoSource(go);
      expect(result.contract!.methods[0]!.params[0]!.name).toBe('myParam');
    });
  });

  // ---------------------------------------------------------------------------
  // Expressions
  // ---------------------------------------------------------------------------

  describe('expressions', () => {
    it('parses binary arithmetic', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct {
	runar.SmartContract
	X runar.Bigint \`runar:"readonly"\`
}

func (c *C) M(a runar.Bigint, b runar.Bigint) {
	sum := a + b
	runar.Assert(sum > 0)
}
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      expect(decl.kind).toBe('variable_decl');
      const init = decl.init as BinaryExpr;
      expect(init.kind).toBe('binary_expr');
      expect(init.op).toBe('+');
    });

    it('maps == to ===', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct {
	runar.SmartContract
	X runar.Bigint \`runar:"readonly"\`
}

func (c *C) M(a runar.Bigint) {
	runar.Assert(a == 42)
}
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const cmp = assertCall.args[0] as BinaryExpr;
      expect(cmp.op).toBe('===');
    });

    it('maps != to !==', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct {
	runar.SmartContract
	X runar.Bigint \`runar:"readonly"\`
}

func (c *C) M(a runar.Bigint) {
	runar.Assert(a != 0)
}
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const cmp = assertCall.args[0] as BinaryExpr;
      expect(cmp.op).toBe('!==');
    });

    it('parses runar.Assert as assert()', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) M() { runar.Assert(true) }
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      expect(assertCall.kind).toBe('call_expr');
      expect((assertCall.callee as Identifier).name).toBe('assert');
    });

    it('parses builtin function calls with PascalCase->camelCase mapping', () => {
      const result = parseGoSource(P2PKH_GO);
      const method = result.contract!.methods[0]!;
      // First assert: runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const cmp = assertCall.args[0] as BinaryExpr;
      // runar.Hash160 should map to hash160
      const hash160Call = cmp.left as CallExpr;
      expect(hash160Call.kind).toBe('call_expr');
      expect((hash160Call.callee as Identifier).name).toBe('hash160');
    });

    it('parses number literals as bigint', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) M() {
	a := 42
	runar.Assert(a > 0)
}
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      const lit = decl.init as BigIntLiteral;
      expect(lit.kind).toBe('bigint_literal');
      expect(lit.value).toBe(42n);
    });

    it('parses boolean literals', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) M() { runar.Assert(true) }
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const boolLit = assertCall.args[0] as BoolLiteral;
      expect(boolLit.kind).toBe('bool_literal');
      expect(boolLit.value).toBe(true);
    });

    it('parses hex string literals', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) M() {
	h := 0xabcd
	runar.Assert(true)
}
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      expect(decl.init.kind).toBe('bytestring_literal');
      if (decl.init.kind === 'bytestring_literal') {
        expect(decl.init.value).toBe('abcd');
      }
    });

    it('parses c.Field as property_access', () => {
      const result = parseGoSource(P2PKH_GO);
      const method = result.contract!.methods[0]!;
      // First assert: runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const cmp = assertCall.args[0] as BinaryExpr;
      expect(cmp.right.kind).toBe('property_access');
      if (cmp.right.kind === 'property_access') {
        expect(cmp.right.property).toBe('pubKeyHash');
      }
    });

    it('parses unary operators', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) M(flag bool) { runar.Assert(!flag) }
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const notExpr = assertCall.args[0] as UnaryExpr;
      expect(notExpr.kind).toBe('unary_expr');
      expect(notExpr.op).toBe('!');
    });

    it('handles operator precedence correctly', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) M(a runar.Bigint, b runar.Bigint) {
	result := a + b*2
	runar.Assert(result > 0)
}
`;
      const result = parseGoSource(go);
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
    it('parses if/else statements', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) M(a runar.Bigint) {
	if a > 0 {
		runar.Assert(true)
	} else {
		runar.Assert(false)
	}
}
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const ifStmt = method.body[0] as IfStatement;
      expect(ifStmt.kind).toBe('if_statement');
      expect(ifStmt.then.length).toBeGreaterThan(0);
      expect(ifStmt.else).toBeDefined();
    });

    it('parses for loops', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) M() {
	sum := 0
	for i := 0; i < 10; i++ {
		sum = sum + i
	}
	runar.Assert(sum > 0)
}
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const forStmt = method.body[1] as ForStatement;
      expect(forStmt.kind).toBe('for_statement');
      expect(forStmt.init.name).toBe('i');
    });

    it('parses return statements', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) helper(a runar.Bigint) runar.Bigint { return a + 1 }
func (c *C) M() { runar.Assert(true) }
`;
      const result = parseGoSource(go);
      const helper = result.contract!.methods.find(m => m.name === 'helper')!;
      const retStmt = helper.body[0] as ReturnStatement;
      expect(retStmt.kind).toBe('return_statement');
      expect(retStmt.value).toBeDefined();
    });

    it('parses := short variable declaration', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) M(a runar.Bigint, b runar.Bigint) {
	sum := a + b
	runar.Assert(sum > 0)
}
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      expect(decl.kind).toBe('variable_decl');
      expect(decl.name).toBe('sum');
    });

    it('parses compound assignment (+=)', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type C struct { runar.SmartContract }

func (c *C) M() {
	a := 1
	a += 2
	runar.Assert(a > 0)
}
`;
      const result = parseGoSource(go);
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

    it('parses increment (++)', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type Counter struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

func (c *Counter) Increment() {
	c.Count++
}
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      expect(stmt.expression.kind).toBe('increment_expr');
    });

    it('parses decrement (--)', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type Counter struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

func (c *Counter) Decrement() {
	c.Count--
}
`;
      const result = parseGoSource(go);
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      expect(stmt.expression.kind).toBe('decrement_expr');
    });
  });

  // ---------------------------------------------------------------------------
  // Full contract: Stateful Counter
  // ---------------------------------------------------------------------------

  describe('stateful counter contract', () => {
    it('parses the Counter contract correctly', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type Counter struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

func (c *Counter) Increment() {
	c.Count++
}

func (c *Counter) Decrement() {
	runar.Assert(c.Count > 0)
	c.Count--
}
`;
      const result = parseGoSource(go, 'Counter.runar.go');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const contract = result.contract!;
      expect(contract.name).toBe('Counter');
      expect(contract.parentClass).toBe('StatefulSmartContract');
      expect(contract.properties).toHaveLength(1);
      expect(contract.properties[0]!.name).toBe('count');
      expect(contract.properties[0]!.readonly).toBe(false);
      expect(contract.methods).toHaveLength(2);
      expect(contract.methods.map(m => m.name)).toEqual(['increment', 'decrement']);
    });
  });

  // ---------------------------------------------------------------------------
  // Full contract: Arithmetic conformance
  // ---------------------------------------------------------------------------

  describe('conformance: arithmetic', () => {
    it('parses the arithmetic Go contract', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type Arithmetic struct {
	runar.SmartContract
	Target runar.Bigint \`runar:"readonly"\`
}

func (c *Arithmetic) Verify(a runar.Bigint, b runar.Bigint) {
	sum := a + b
	diff := a - b
	prod := a * b
	quot := a / b
	result := sum + diff + prod + quot
	runar.Assert(result == c.Target)
}
`;
      const result = parseGoSource(go);
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const contract = result.contract!;
      expect(contract.name).toBe('Arithmetic');
      expect(contract.properties).toHaveLength(1);
      expect(contract.methods).toHaveLength(1);
      expect(contract.methods[0]!.params).toHaveLength(2);
      expect(contract.methods[0]!.body.length).toBeGreaterThanOrEqual(6);
    });
  });

  // ---------------------------------------------------------------------------
  // init() method: property initializers
  // ---------------------------------------------------------------------------

  describe('property initializers via init()', () => {
    it('extracts initializer from init() and excludes from constructor', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type BoundedCounter struct {
	runar.StatefulSmartContract
	Count   runar.Bigint
	MaxCount runar.Bigint \`runar:"readonly"\`
}

func (c *BoundedCounter) init() {
	c.MaxCount = 100
}

func (c *BoundedCounter) Increment() {
	runar.Assert(c.Count < c.MaxCount)
	c.Count++
}
`;
      const result = parseGoSource(go, 'BoundedCounter.runar.go');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const contract = result.contract!;
      // MaxCount has an initializer, so it should be excluded from constructor params
      const ctor = contract.constructor;
      expect(ctor.params.map(p => p.name)).not.toContain('maxCount');
      // The MaxCount property should have an initializer
      const maxProp = contract.properties.find(p => p.name === 'maxCount');
      expect(maxProp).toBeDefined();
      expect(maxProp!.initializer).toBeDefined();
      expect(maxProp!.initializer!.kind).toBe('bigint_literal');
    });
  });

  // -------------------------------------------------------------------------
  // BigintBig as a bigint alias
  // -------------------------------------------------------------------------

  describe('BigintBig alias', () => {
    it('maps runar.BigintBig to the bigint primitive (property + param)', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type BigMath struct {
\truntar.SmartContract
\tTarget runar.BigintBig \`runar:"readonly"\`
}

func (c *BigMath) Check(a runar.Bigint, b runar.BigintBig) {
\truntar.Assert(a + b == c.Target)
}
`.replace(/runtar\./g, 'runar.');
      const result = parseGoSource(go, 'BigMath.runar.go');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const c = result.contract!;
      const target = c.properties.find(p => p.name === 'target')!;
      expect(target.type.kind).toBe('primitive_type');
      expect((target.type as { name: string }).name).toBe('bigint');
      const b = c.methods[0]!.params[1]!;
      expect(b.type.kind).toBe('primitive_type');
      expect((b.type as { name: string }).name).toBe('bigint');
    });
  });

  // -------------------------------------------------------------------------
  // runar.ByteString("literal") -> ByteString literal (hex of raw bytes)
  // runar.ByteString(variable)  -> type-conversion no-op
  // -------------------------------------------------------------------------

  describe('ByteString conversion', () => {
    it('emits a ByteString literal (hex of raw bytes) for a string-literal arg', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type LitDemo struct {
\truntar.SmartContract
\tExpected runar.ByteString \`runar:"readonly"\`
}

func (c *LitDemo) Check() {
\truntar.Assert(runar.ByteString("\\x00\\x6a") == c.Expected)
}
`.replace(/runtar\./g, 'runar.');
      const result = parseGoSource(go, 'LitDemo.runar.go');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const body = result.contract!.methods[0]!.body;
      // Walk to find any bytestring_literal node; assert value is "006a".
      const found: string[] = [];
      function walk(node: unknown): void {
        if (!node || typeof node !== 'object') return;
        const n = node as { kind?: string; value?: unknown };
        if (n.kind === 'bytestring_literal' && typeof n.value === 'string') {
          found.push(n.value);
        }
        for (const v of Object.values(n)) walk(v);
      }
      walk(body);
      expect(found).toContain('006a');
    });

    it('unwraps runar.ByteString(variable) to the inner identifier', () => {
      const go = `
package contract
import runar "github.com/icellan/runar/packages/runar-go"

type VarDemo struct {
\truntar.SmartContract
\tExpected runar.ByteString \`runar:"readonly"\`
}

func (c *VarDemo) Check(data runar.ByteString) {
\truntar.Assert(runar.ByteString(data) == c.Expected)
}
`.replace(/runtar\./g, 'runar.');
      const result = parseGoSource(go, 'VarDemo.runar.go');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      // There must be a plain identifier 'data' somewhere, and NO call with
      // callee Identifier('byteString'). (A stray `byteString(data)` call
      // would indicate the unwrap didn't happen.)
      let sawDataIdent = false;
      let sawByteStringCall = false;
      function walk(node: unknown): void {
        if (!node || typeof node !== 'object') return;
        const n = node as { kind?: string; name?: string; callee?: { name?: string } };
        if (n.kind === 'identifier' && n.name === 'data') sawDataIdent = true;
        if (n.kind === 'call_expr' && n.callee && n.callee.name === 'byteString') {
          sawByteStringCall = true;
        }
        for (const v of Object.values(n)) walk(v);
      }
      walk(result.contract!.methods[0]!.body);
      expect(sawDataIdent).toBe(true);
      expect(sawByteStringCall).toBe(false);
    });
  });
});
