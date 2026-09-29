package frontend

import (
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// Test: Basic stateless contract (P2PKH)
// ---------------------------------------------------------------------------

func TestParseZig_P2PKH(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,

    pub fn init(self: P2PKH, pubKeyHash: runar.Addr) void {
        _ = self;
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.hash160(pubKey) == self.pubKeyHash);
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
`)
	result := ParseSource(source, "P2PKH.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}
	if result.Contract.Name != "P2PKH" {
		t.Errorf("expected P2PKH, got %s", result.Contract.Name)
	}
	if result.Contract.ParentClass != "SmartContract" {
		t.Errorf("expected SmartContract, got %s", result.Contract.ParentClass)
	}

	// Should have 1 property: pubKeyHash
	if len(result.Contract.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(result.Contract.Properties))
	}
	prop := result.Contract.Properties[0]
	if prop.Name != "pubKeyHash" {
		t.Errorf("expected property name 'pubKeyHash', got %s", prop.Name)
	}
	if !prop.Readonly {
		t.Errorf("expected pubKeyHash to be readonly (stateless contract)")
	}
	if pt, ok := prop.Type.(PrimitiveType); !ok || pt.Name != "Addr" {
		t.Errorf("expected property type Addr, got %v", prop.Type)
	}

	// Should have 1 method: unlock
	if len(result.Contract.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(result.Contract.Methods))
	}
	method := result.Contract.Methods[0]
	if method.Name != "unlock" {
		t.Errorf("expected method name 'unlock', got %s", method.Name)
	}
	if method.Visibility != "public" {
		t.Errorf("expected unlock to be public, got %s", method.Visibility)
	}
	// Params should not include self
	if len(method.Params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(method.Params))
	}
	if method.Params[0].Name != "sig" {
		t.Errorf("expected param 'sig', got %s", method.Params[0].Name)
	}
	if method.Params[1].Name != "pubKey" {
		t.Errorf("expected param 'pubKey', got %s", method.Params[1].Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Stateful contract (Counter)
// ---------------------------------------------------------------------------

func TestParseZig_StatefulCounter(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const Counter = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: runar.Bigint,

    pub fn init(self: Counter, count: runar.Bigint) void {
        _ = self;
        return .{ .count = count };
    }

    pub fn increment(self: *Counter) void {
        self.count += 1;
    }

    pub fn decrement(self: *Counter) void {
        runar.assert(self.count > 0);
        self.count -= 1;
    }
};
`)
	result := ParseSource(source, "Counter.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}
	if result.Contract.Name != "Counter" {
		t.Errorf("expected Counter, got %s", result.Contract.Name)
	}
	if result.Contract.ParentClass != "StatefulSmartContract" {
		t.Errorf("expected StatefulSmartContract, got %s", result.Contract.ParentClass)
	}
	if len(result.Contract.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(result.Contract.Properties))
	}

	// Should have 2 methods: increment, decrement
	if len(result.Contract.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(result.Contract.Methods))
	}
	if result.Contract.Methods[0].Name != "increment" {
		t.Errorf("expected 'increment', got %s", result.Contract.Methods[0].Name)
	}
	if result.Contract.Methods[1].Name != "decrement" {
		t.Errorf("expected 'decrement', got %s", result.Contract.Methods[1].Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Property with initializer
// ---------------------------------------------------------------------------

func TestParseZig_PropertyInitializer(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const MyContract = struct {
    pub const Contract = runar.SmartContract;

    value: runar.Bigint,
    limit: runar.Bigint = 100,

    pub fn check(self: MyContract) void {
        runar.assert(self.value < self.limit);
    }
};
`)
	result := ParseSource(source, "MyContract.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}
	if len(result.Contract.Properties) != 2 {
		t.Fatalf("expected 2 properties, got %d", len(result.Contract.Properties))
	}

	// First property: no initializer
	if result.Contract.Properties[0].Initializer != nil {
		t.Errorf("expected no initializer for 'value'")
	}

	// Second property: has initializer
	if result.Contract.Properties[1].Initializer == nil {
		t.Fatalf("expected initializer for 'limit'")
	}
	if lit, ok := result.Contract.Properties[1].Initializer.(BigIntLiteral); !ok || lit.Value.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("expected initializer BigIntLiteral(100), got %v", result.Contract.Properties[1].Initializer)
	}

	// Auto-generated constructor should only have 1 param (value), not limit
	if len(result.Contract.Constructor.Params) != 1 {
		t.Fatalf("expected 1 constructor param, got %d", len(result.Contract.Constructor.Params))
	}
	if result.Contract.Constructor.Params[0].Name != "value" {
		t.Errorf("expected constructor param 'value', got %s", result.Contract.Constructor.Params[0].Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Public and private methods
// ---------------------------------------------------------------------------

func TestParseZig_Visibility(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const Vis = struct {
    pub const Contract = runar.SmartContract;

    x: runar.Bigint,

    pub fn doPublic(self: Vis) void {
        runar.assert(self.x > 0);
    }

    fn doPrivate(self: Vis) runar.Bigint {
        return self.x + 1;
    }
};
`)
	result := ParseSource(source, "Vis.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}
	if len(result.Contract.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(result.Contract.Methods))
	}
	if result.Contract.Methods[0].Name != "doPublic" || result.Contract.Methods[0].Visibility != "public" {
		t.Errorf("expected doPublic to be public, got %s/%s", result.Contract.Methods[0].Name, result.Contract.Methods[0].Visibility)
	}
	if result.Contract.Methods[1].Name != "doPrivate" || result.Contract.Methods[1].Visibility != "private" {
		t.Errorf("expected doPrivate to be private, got %s/%s", result.Contract.Methods[1].Name, result.Contract.Methods[1].Visibility)
	}
}

// ---------------------------------------------------------------------------
// Test: Binary and unary operators
// ---------------------------------------------------------------------------

func TestParseZig_Operators(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const Ops = struct {
    pub const Contract = runar.SmartContract;

    x: runar.Bigint,

    pub fn check(self: Ops) void {
        const a = self.x + 1;
        const b = a * 2 - 3;
        const c = !true;
        const d = -a;
        runar.assert(b > 0);
        _ = c;
        _ = d;
    }
};
`)
	result := ParseSource(source, "Ops.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}
	// Should parse without errors
	if len(result.Contract.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(result.Contract.Methods))
	}

	// Method body should have statements
	body := result.Contract.Methods[0].Body
	if len(body) < 2 {
		t.Fatalf("expected at least 2 statements, got %d", len(body))
	}

	// First statement: const a = self.x + 1
	if decl, ok := body[0].(VariableDeclStmt); ok {
		if decl.Name != "a" {
			t.Errorf("expected variable 'a', got %s", decl.Name)
		}
		if decl.Mutable {
			t.Errorf("expected const (not mutable)")
		}
		if binExpr, ok := decl.Init.(BinaryExpr); ok {
			if binExpr.Op != "+" {
				t.Errorf("expected '+' op, got %s", binExpr.Op)
			}
		} else {
			t.Errorf("expected BinaryExpr for init of 'a'")
		}
	} else {
		t.Errorf("expected VariableDeclStmt, got %T", body[0])
	}
}

// ---------------------------------------------------------------------------
// Test: Self.property access
// ---------------------------------------------------------------------------

func TestParseZig_SelfAccess(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const Self = struct {
    pub const Contract = runar.SmartContract;

    value: runar.Bigint,

    pub fn check(self: Self) void {
        runar.assert(self.value > 0);
    }
};
`)
	result := ParseSource(source, "Self.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}

	body := result.Contract.Methods[0].Body
	// The body should contain assert(self.value > 0)
	// self.value should become PropertyAccessExpr
	if len(body) == 0 {
		t.Fatalf("expected at least 1 statement in body")
	}

	// The assert call should have an argument that is a binary expression
	// whose left side is a PropertyAccessExpr
	if exprStmt, ok := body[0].(ExpressionStmt); ok {
		if call, ok := exprStmt.Expr.(CallExpr); ok {
			if len(call.Args) > 0 {
				if binExpr, ok := call.Args[0].(BinaryExpr); ok {
					if _, ok := binExpr.Left.(PropertyAccessExpr); !ok {
						t.Errorf("expected PropertyAccessExpr for self.value, got %T", binExpr.Left)
					}
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test: runar.builtin() call stripping
// ---------------------------------------------------------------------------

func TestParseZig_RunarBuiltinStrip(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const B = struct {
    pub const Contract = runar.SmartContract;

    h: runar.Sha256,

    pub fn check(self: B, data: runar.ByteString) void {
        runar.assert(runar.sha256(data) == self.h);
    }
};
`)
	result := ParseSource(source, "B.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}

	// In the method body, runar.sha256(data) should become sha256(data)
	// and runar.assert(...) should become assert(...)
	body := result.Contract.Methods[0].Body
	if len(body) == 0 {
		t.Fatalf("expected at least 1 statement")
	}

	// The first statement should be an expression statement with a call to 'assert'
	if exprStmt, ok := body[0].(ExpressionStmt); ok {
		if call, ok := exprStmt.Expr.(CallExpr); ok {
			if ident, ok := call.Callee.(Identifier); ok {
				if ident.Name != "assert" {
					t.Errorf("expected 'assert' callee, got %s", ident.Name)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Constructor parsing
// ---------------------------------------------------------------------------

func TestParseZig_Constructor(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const Ctor = struct {
    pub const Contract = runar.SmartContract;

    x: runar.Bigint,
    y: runar.Bigint,

    pub fn init(self: Ctor, x: runar.Bigint, y: runar.Bigint) void {
        _ = self;
        return .{ .x = x, .y = y };
    }

    pub fn check(self: Ctor) void {
        runar.assert(self.x + self.y > 0);
    }
};
`)
	result := ParseSource(source, "Ctor.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}

	// Constructor should exist
	ctor := result.Contract.Constructor
	if ctor.Name != "constructor" {
		t.Errorf("expected constructor name 'constructor', got %s", ctor.Name)
	}
	if len(ctor.Params) != 2 {
		t.Fatalf("expected 2 constructor params, got %d", len(ctor.Params))
	}
	if ctor.Params[0].Name != "x" {
		t.Errorf("expected param 'x', got %s", ctor.Params[0].Name)
	}
	if ctor.Params[1].Name != "y" {
		t.Errorf("expected param 'y', got %s", ctor.Params[1].Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Compound assignment desugaring
// ---------------------------------------------------------------------------

func TestParseZig_CompoundAssignment(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const Comp = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: runar.Bigint,

    pub fn add(self: *Comp, n: runar.Bigint) void {
        self.count += n;
    }
};
`)
	result := ParseSource(source, "Comp.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}

	body := result.Contract.Methods[0].Body
	if len(body) == 0 {
		t.Fatalf("expected at least 1 statement")
	}

	// self.count += n should desugar to self.count = self.count + n
	if assign, ok := body[0].(AssignmentStmt); ok {
		if _, ok := assign.Target.(PropertyAccessExpr); !ok {
			t.Errorf("expected PropertyAccessExpr target, got %T", assign.Target)
		}
		if binExpr, ok := assign.Value.(BinaryExpr); ok {
			if binExpr.Op != "+" {
				t.Errorf("expected '+' op in desugared compound assignment, got %s", binExpr.Op)
			}
		} else {
			t.Errorf("expected BinaryExpr value, got %T", assign.Value)
		}
	} else {
		t.Errorf("expected AssignmentStmt, got %T", body[0])
	}
}

// ---------------------------------------------------------------------------
// Test: While loop parsing
// ---------------------------------------------------------------------------

func TestParseZig_WhileLoop(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const Loop = struct {
    pub const Contract = runar.SmartContract;

    n: runar.Bigint,

    pub fn check(self: Loop) void {
        var i: i64 = 0;
        while (i < self.n) : (i += 1) {
            runar.assert(i >= 0);
        }
    }
};
`)
	result := ParseSource(source, "Loop.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}

	body := result.Contract.Methods[0].Body
	// Should have 1 statement: a ForStmt (the var decl was merged)
	if len(body) != 1 {
		t.Fatalf("expected 1 statement (merged for loop), got %d", len(body))
	}

	forStmt, ok := body[0].(ForStmt)
	if !ok {
		t.Fatalf("expected ForStmt, got %T", body[0])
	}

	// Init should be the merged variable decl
	if forStmt.Init.Name != "i" {
		t.Errorf("expected init var name 'i', got %s", forStmt.Init.Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Zig @builtins
// ---------------------------------------------------------------------------

func TestParseZig_AtBuiltins(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const Builtins = struct {
    pub const Contract = runar.SmartContract;

    x: runar.Bigint,

    pub fn check(self: Builtins) void {
        const a = @divTrunc(self.x, 2);
        const b = @mod(self.x, 3);
        const c = @shlExact(self.x, 2);
        const d = @shrExact(self.x, 1);
        const e = @intCast(self.x);
        runar.assert(a + b + c + d + e > 0);
    }
};
`)
	result := ParseSource(source, "Builtins.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}

	body := result.Contract.Methods[0].Body
	// 5 const declarations + 1 assert
	if len(body) < 6 {
		t.Fatalf("expected at least 6 statements, got %d", len(body))
	}

	// @divTrunc -> /
	if decl, ok := body[0].(VariableDeclStmt); ok {
		if binExpr, ok := decl.Init.(BinaryExpr); ok {
			if binExpr.Op != "/" {
				t.Errorf("expected '/' for @divTrunc, got %s", binExpr.Op)
			}
		}
	}

	// @mod -> %
	if decl, ok := body[1].(VariableDeclStmt); ok {
		if binExpr, ok := decl.Init.(BinaryExpr); ok {
			if binExpr.Op != "%" {
				t.Errorf("expected '%%' for @mod, got %s", binExpr.Op)
			}
		}
	}

	// @shlExact -> <<
	if decl, ok := body[2].(VariableDeclStmt); ok {
		if binExpr, ok := decl.Init.(BinaryExpr); ok {
			if binExpr.Op != "<<" {
				t.Errorf("expected '<<' for @shlExact, got %s", binExpr.Op)
			}
		}
	}

	// @shrExact -> >>
	if decl, ok := body[3].(VariableDeclStmt); ok {
		if binExpr, ok := decl.Init.(BinaryExpr); ok {
			if binExpr.Op != ">>" {
				t.Errorf("expected '>>' for @shrExact, got %s", binExpr.Op)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Hex literal as ByteStringLiteral
// ---------------------------------------------------------------------------

func TestParseZig_HexLiteral(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const Hex = struct {
    pub const Contract = runar.SmartContract;

    h: runar.ByteString,

    pub fn check(self: Hex) void {
        runar.assert(self.h == 0xaabb);
    }
};
`)
	result := ParseSource(source, "Hex.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}

	// F-026: `0xaabb` is a Zig integer literal (0xaabb = 43707), as in Zig
	// and in the TS reference, not a ByteString.
	body := result.Contract.Methods[0].Body
	if len(body) == 0 {
		t.Fatalf("expected at least 1 statement")
	}
	// Look through the assert call to find the hex literal
	found := false
	if exprStmt, ok := body[0].(ExpressionStmt); ok {
		if call, ok := exprStmt.Expr.(CallExpr); ok {
			if len(call.Args) > 0 {
				if binExpr, ok := call.Args[0].(BinaryExpr); ok {
					if lit, ok := binExpr.Right.(BigIntLiteral); ok {
						if lit.Value.Int64() != 0xaabb {
							t.Errorf("expected 0xaabb = 43707, got %s", lit.Value)
						}
						found = true
					}
				}
			}
		}
	}
	if !found {
		t.Error("did not find BigIntLiteral for hex literal 0xaabb")
	}
}

// ---------------------------------------------------------------------------
// Test: Array type and literal
// ---------------------------------------------------------------------------

func TestParseZig_ArrayType(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const Arr = struct {
    pub const Contract = runar.SmartContract;

    items: [3]runar.Bigint,

    pub fn check(self: Arr) void {
        runar.assert(self.items[0] > 0);
    }
};
`)
	result := ParseSource(source, "Arr.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}
	if len(result.Contract.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(result.Contract.Properties))
	}

	// Property type should be FixedArrayType
	prop := result.Contract.Properties[0]
	if arrType, ok := prop.Type.(FixedArrayType); ok {
		if arrType.Length != 3 {
			t.Errorf("expected array length 3, got %d", arrType.Length)
		}
		if pt, ok := arrType.Element.(PrimitiveType); !ok || pt.Name != "bigint" {
			t.Errorf("expected element type bigint, got %v", arrType.Element)
		}
	} else {
		t.Errorf("expected FixedArrayType, got %T", prop.Type)
	}
}

// ---------------------------------------------------------------------------
// Test: Auto-generated fallback constructor
// ---------------------------------------------------------------------------

func TestParseZig_FallbackConstructor(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const NoInit = struct {
    pub const Contract = runar.SmartContract;

    a: runar.Bigint,
    b: runar.Bigint,

    pub fn check(self: NoInit) void {
        runar.assert(self.a + self.b > 0);
    }
};
`)
	result := ParseSource(source, "NoInit.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}

	ctor := result.Contract.Constructor
	if ctor.Name != "constructor" {
		t.Errorf("expected constructor, got %s", ctor.Name)
	}
	// Should auto-generate params for both properties
	if len(ctor.Params) != 2 {
		t.Fatalf("expected 2 constructor params, got %d", len(ctor.Params))
	}
	if ctor.Params[0].Name != "a" || ctor.Params[1].Name != "b" {
		t.Errorf("expected params a, b, got %s, %s", ctor.Params[0].Name, ctor.Params[1].Name)
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSource dispatch for .runar.zig
// ---------------------------------------------------------------------------

func TestParseZig_Dispatch(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const Dispatch = struct {
    pub const Contract = runar.SmartContract;

    x: runar.Bigint,

    pub fn check(self: Dispatch) void {
        runar.assert(self.x > 0);
    }
};
`)
	// Should work through ParseSource dispatch
	result := ParseSource(source, "Dispatch.runar.zig")
	if result.Contract == nil {
		t.Fatalf("expected contract via ParseSource, got nil (errors: %v)", result.ErrorStrings())
	}
	if result.Contract.Name != "Dispatch" {
		t.Errorf("expected Dispatch, got %s", result.Contract.Name)
	}
}

// ---------------------------------------------------------------------------
// Test: runar.Readonly type
// ---------------------------------------------------------------------------

func TestParseZig_ReadonlyType(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const RO = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: runar.Bigint,
    owner: runar.Readonly(runar.Addr),

    pub fn increment(self: *RO) void {
        self.count += 1;
    }
};
`)
	result := ParseSource(source, "RO.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}
	if len(result.Contract.Properties) != 2 {
		t.Fatalf("expected 2 properties, got %d", len(result.Contract.Properties))
	}

	// count should not be readonly (stateful contract, no Readonly wrapper)
	if result.Contract.Properties[0].Readonly {
		t.Errorf("expected count to NOT be readonly")
	}
	// owner should be readonly (wrapped in Readonly)
	if !result.Contract.Properties[1].Readonly {
		t.Errorf("expected owner to be readonly")
	}
}

// ---------------------------------------------------------------------------
// Test: Ternary-like if expression (as statement-level if)
// ---------------------------------------------------------------------------

func TestParseZig_IfElse(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const IfElse = struct {
    pub const Contract = runar.SmartContract;

    x: runar.Bigint,

    pub fn check(self: IfElse) void {
        if (self.x > 0) {
            runar.assert(true);
        } else {
            runar.assert(false);
        }
    }
};
`)
	result := ParseSource(source, "IfElse.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}

	body := result.Contract.Methods[0].Body
	if len(body) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(body))
	}
	ifStmt, ok := body[0].(IfStmt)
	if !ok {
		t.Fatalf("expected IfStmt, got %T", body[0])
	}
	if len(ifStmt.Then) != 1 {
		t.Errorf("expected 1 then statement, got %d", len(ifStmt.Then))
	}
	if len(ifStmt.Else) != 1 {
		t.Errorf("expected 1 else statement, got %d", len(ifStmt.Else))
	}
}

// ---------------------------------------------------------------------------
// Test: runar.bytesEq desugaring
// ---------------------------------------------------------------------------

func TestParseZig_BytesEq(t *testing.T) {
	source := []byte(`const runar = @import("runar");

pub const BytesEq = struct {
    pub const Contract = runar.SmartContract;

    a: runar.ByteString,

    pub fn check(self: BytesEq, b: runar.ByteString) void {
        runar.assert(runar.bytesEq(self.a, b));
    }
};
`)
	result := ParseSource(source, "BytesEq.runar.zig")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.ErrorStrings())
	}

	body := result.Contract.Methods[0].Body
	if len(body) == 0 {
		t.Fatalf("expected at least 1 statement")
	}

	// runar.bytesEq(a, b) should become BinaryExpr{===}
	if exprStmt, ok := body[0].(ExpressionStmt); ok {
		if call, ok := exprStmt.Expr.(CallExpr); ok {
			if len(call.Args) > 0 {
				if binExpr, ok := call.Args[0].(BinaryExpr); ok {
					if binExpr.Op != "===" {
						t.Errorf("expected '===' for bytesEq, got %s", binExpr.Op)
					}
				} else {
					t.Errorf("expected BinaryExpr for bytesEq, got %T", call.Args[0])
				}
			}
		}
	}
}
