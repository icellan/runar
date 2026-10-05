package frontend

import (
	"strings"
	"testing"
)

// N-052. parseExpression's default arm returned nil for every tree-sitter
// expression node it did not recognise, and parseBinaryExpression /
// parseUnaryExpression / parseUpdateExpression turned a nil operand into
// BigIntLiteral(0). So `assert((x, 0n) === this.t)` compiled as
// `assert(0 === this.t)`, an arrow function in an initializer became `0`, and
// `x + (() => 1n)` became `x + 0` — all while the TS reference refuses each
// shape. Operators were passed through verbatim too, so `**`, `??`, `>>>`,
// `in`, `instanceof`, unary `+`, `typeof`, `void` and `delete` were only caught
// in stack lowering (after every frontend-only CompileCheck had said yes).
//
// Proves: the Go .runar.ts surface refuses each expression kind and operator
// outside the TS reference's parseExpression / parseBinaryExpression /
// parsePrefixUnaryExpression tables, in the parser, with the TS reference's
// diagnostic text; and that the supported wrappers (as, !, <T>x, ?.,
// parentheses, comments) still parse clean. Does not prove: the other Go-tier
// surfaces (.runar.go/.sol/.move/...), which have their own dispatchers, nor
// byte-level codegen (covered by the conformance goldens).

func n052Wrap(body string) string {
	return `import { SmartContract, assert, min } from 'runar-lang';

class Probe extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  public unlock(x: bigint, y: bigint) {
    ` + body + `
  }
}
`
}

var n052Cases = []struct{ name, body, want string }{
	// sweep1 repros
	{"comma", "assert((x, 0n) === this.t);", "Unsupported binary operator: ','"},
	{"arrow-init", "const f = (y: bigint) => y; assert(x === this.t);", "Unsupported expression kind: ArrowFunction ('(y: bigint) => y')"},
	{"arrow-in-binary", "assert(x + ((y: bigint) => y) === this.t);", "Unsupported expression kind: ArrowFunction"},
	// remaining expression kinds the TS reference refuses
	{"comma-rhs", "assert(x === (this.t, x));", "Unsupported binary operator: ','"},
	{"assign-in-expr", "let z = 0n; assert((z = x) === this.t);", "Unsupported binary operator: '='"},
	{"compound-in-expr", "let z = 0n; assert((z += x) === this.t);", "Unsupported binary operator: '+='"},
	{"function-expr", "const f = function (y: bigint) { return y; }; assert(x === this.t);", "Unsupported expression kind: FunctionExpression"},
	{"class-expr", "const C = class {}; assert(x === this.t);", "Unsupported expression kind: ClassExpression"},
	{"new", "assert(new Probe(x) === this.t);", "Unsupported expression kind: NewExpression ('new Probe(x)')"},
	{"null", "assert(x === null);", "Unsupported expression kind: NullKeyword ('null')"},
	{"regex", "const r = /ab/; assert(x === this.t);", "Unsupported expression kind: RegularExpressionLiteral ('/ab/')"},
	{"satisfies", "assert((x satisfies bigint) === this.t);", "Unsupported expression kind: SatisfiesExpression ('x satisfies bigint')"},
	{"await", "assert((await x) === this.t);", "Unsupported expression kind: AwaitExpression ('await x')"},
	{"object", "const o = { a: 1n }; assert(x === this.t);", "Unsupported expression kind: ObjectLiteralExpression ('{ a: 1n }')"},
	{"spread", "assert(min(...[x, y]) === this.t);", "Unsupported expression kind: SpreadElement ('...[x, y]')"},
	{"template", "assert(`${x}` === this.t);", "Unsupported expression kind: TemplateExpression"},
	{"tagged-template", "assert(foo`ab` === this.t);", "Unsupported expression kind: TaggedTemplateExpression ('foo`ab`')"},
	{"typeof", "assert(typeof x === this.t);", "Unsupported expression kind: TypeOfExpression ('typeof x')"},
	{"void", "assert(void x === this.t);", "Unsupported expression kind: VoidExpression ('void x')"},
	{"delete", "assert(delete y);", "Unsupported expression kind: DeleteExpression ('delete y')"},
	// operators outside the TS reference's tables
	{"unary-plus", "assert(+x === this.t);", "Unsupported unary prefix operator"},
	{"pow", "assert(x ** 2n === this.t);", "Unsupported binary operator: '**'"},
	{"nullish", "assert((x ?? 0n) === this.t);", "Unsupported binary operator: '??'"},
	{"ushr", "assert((x >>> 1n) === this.t);", "Unsupported binary operator: '>>>'"},
	{"in", "assert(x in y);", "Unsupported binary operator: 'in'"},
	{"instanceof", "assert(x instanceof y);", "Unsupported binary operator: 'instanceof'"},
}

func TestN052_RefusesUnsupportedExpressions(t *testing.T) {
	for _, c := range n052Cases {
		t.Run(c.name, func(t *testing.T) {
			res := ParseSource([]byte(n052Wrap(c.body)), "Probe.runar.ts")
			for _, e := range res.Errors {
				if strings.Contains(e.Message, c.want) {
					return
				}
			}
			t.Fatalf("`%s` was not refused with %q; errors: %v", c.body, c.want, res.Errors)
		})
	}
}

// `undefined` is an Identifier in the TS reference, which the typechecker then
// refuses as "Undefined variable 'undefined'". tree-sitter gives it its own
// node type, which used to fall into the nil default and become 0.
func TestN052_UndefinedIsAnIdentifier(t *testing.T) {
	res := ParseSource([]byte(n052Wrap("assert(x === undefined);")), "Probe.runar.ts")
	if len(res.Errors) != 0 || res.Contract == nil {
		t.Fatalf("unexpected parse errors: %v", res.Errors)
	}
	tc := TypeCheck(res.Contract)
	for _, e := range tc.Errors {
		if strings.Contains(e.Message, "Undefined variable 'undefined'") {
			return
		}
	}
	t.Fatalf("`undefined` was not refused by the typechecker; errors: %v", tc.ErrorStrings())
}

// The wrappers the TS reference unwraps, and comments the tree-sitter walk sees
// as extra children, must still parse clean.
func TestN052_SupportedWrappersStillAccepted(t *testing.T) {
	for _, body := range []string{
		"assert((x as bigint) === this.t);",
		"assert(x! === this.t);",
		"assert((<bigint>x) === this.t);",
		"assert(this?.t === x);",
		"assert(((x)) === this.t);",
		"assert(min(x /* c */, y) === this.t);",
		"assert(min(\n      x, // c\n      y) === this.t);",
		"assert(-x === ~this.t && !(x === y));",
		"assert(`ab` === `ab`);",
		"const z: bigint = /* c */ x; assert(z === this.t);",
	} {
		res := ParseSource([]byte(n052Wrap(body)), "Probe.runar.ts")
		if len(res.Errors) != 0 {
			t.Errorf("`%s` rejected: %v", body, res.Errors)
		}
	}
}

// A comment as the first child of a parenthesized expression made
// parseParenExpression return nil, which the binary parser then read as 0:
// `(/* c */ x) === this.t` compiled as `0 === this.t` with no diagnostic.
func TestN052_CommentInParenthesesKeepsTheOperand(t *testing.T) {
	res := ParseSource([]byte(n052Wrap("assert((/* c */ x) === this.t);")), "Probe.runar.ts")
	if len(res.Errors) != 0 || res.Contract == nil {
		t.Fatalf("unexpected parse errors: %v", res.Errors)
	}
	for _, m := range res.Contract.Methods {
		if m.Name != "unlock" {
			continue
		}
		call := m.Body[0].(ExpressionStmt).Expr.(CallExpr)
		bin := call.Args[0].(BinaryExpr)
		if id, ok := bin.Left.(Identifier); !ok || id.Name != "x" {
			t.Fatalf("left operand of === is %#v, want Identifier x", bin.Left)
		}
		return
	}
	t.Fatal("method unlock not found")
}
