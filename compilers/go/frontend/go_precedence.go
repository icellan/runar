package frontend

import (
	"fmt"
	"go/ast"
	"go/token"
)

// N-056 — ambiguous operator precedence on .runar.go.
//
// go/parser builds Go precedence (`* / % << >> & &^` > `+ - | ^` >
// comparisons > `&&` > `||`); every other tier builds the C ladder (MulDiv >
// AddSub > Shift > Comparison > Equality > BitAnd > BitXor > BitOr > And >
// Or). For `x OP1 y OP2 z` a scheme groups left iff prec(OP1) >= prec(OP2).
// The ordered (OP1 class, OP2 class) pairs on which the schemes disagree are
// below: 23 class pairs, 72 operator pairs. `&^` is `&` over `~` in both.
// Mirrors GO_AMBIGUOUS_PRECEDENCE_PAIRS in 01-parse-go.ts.

var goPrecedenceClass = map[string]string{
	"*": "mul", "/": "mul", "%": "mul",
	"<<": "shift", ">>": "shift",
	"&": "and", "&^": "and",
	"+": "add", "-": "add",
	"|": "or", "^": "xor",
	"<": "rel", "<=": "rel", ">": "rel", ">=": "rel",
	"==": "eq", "!=": "eq",
	"&&": "land", "||": "lor",
}

var goAmbiguousPrecedencePairs = map[string]bool{
	"shift mul": true, "shift add": true,
	"and mul": true, "and shift": true, "and add": true, "and rel": true, "and eq": true,
	"add shift": true, "add and": true,
	"or add": true, "or xor": true, "or rel": true, "or eq": true,
	"xor add": true, "xor rel": true, "xor eq": true,
	"rel and": true, "rel or": true, "rel xor": true,
	"eq and": true, "eq or": true, "eq xor": true, "eq rel": true,
}

func goOpSpelling(op token.Token) string {
	if op == token.AND_NOT {
		return "&"
	}
	return op.String()
}

func isGoAmbiguousPrecedence(first, second token.Token) bool {
	a, okA := goPrecedenceClass[first.String()]
	b, okB := goPrecedenceClass[second.String()]
	return okA && okB && goAmbiguousPrecedencePairs[a+" "+b]
}

// goAmbiguousPrecedenceMessage returns the shared diagnostic when an
// unparenthesised direct operand of e groups differently under the two
// schemes (a *ast.ParenExpr operand is never a *ast.BinaryExpr here).
func goAmbiguousPrecedenceMessage(e *ast.BinaryExpr) (string, bool) {
	first, second := token.ILLEGAL, token.ILLEGAL
	if l, ok := e.X.(*ast.BinaryExpr); ok && isGoAmbiguousPrecedence(l.Op, e.Op) {
		first, second = l.Op, e.Op
	} else if r, ok := e.Y.(*ast.BinaryExpr); ok && isGoAmbiguousPrecedence(e.Op, r.Op) {
		first, second = e.Op, r.Op
	} else {
		return "", false
	}
	return fmt.Sprintf("ambiguous operator precedence in .runar.go: `a %s b %s c` "+
		"groups differently under Go precedence than in Rúnar's other surfaces; add parentheses",
		goOpSpelling(first), goOpSpelling(second)), true
}
