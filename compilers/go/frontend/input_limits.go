package frontend

import "fmt"

// MaxSourceBytes mirrors InputLimits.MAX_SOURCE_BYTES (4 MiB) from the TS
// schema package. Any Rúnar source file larger than this is rejected at
// the parser entry point (ParseSource / Parse / per-format parsers) BEFORE
// the tokenizer touches the input. BUG-008 follow-up.
//
// The byte cap does NOT bound nesting (2,000 nested parens is a 4 KB file);
// MaxSourceNesting below does (F-213).
const MaxSourceBytes = 4 * 1024 * 1024

// MaxSourceNesting mirrors InputLimits.MAX_SOURCE_NESTING (128) from
// packages/runar-ir-schema/src/input-limits.ts, which defines the two
// measures it bounds: (A) parse nesting, counted by every parser while it
// parses, and (B) AST nesting, checked on the finished Rúnar AST. A source
// exceeding either is refused with SourceNestingMessage (F-213).
const MaxSourceNesting = 128

// SourceNestingMessage is the one diagnostic every tier emits for an
// over-nested source (byte-identical across tiers).
const SourceNestingMessage = "source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)"

// SourceSizeExceededError is returned when a source payload exceeds
// MaxSourceBytes at a public parser entry point. Distinct typed error so
// callers can distinguish DoS-bound rejection from generic syntax errors.
type SourceSizeExceededError struct {
	Limit  int
	Actual int
}

func (e *SourceSizeExceededError) Error() string {
	return fmt.Sprintf(
		"source exceeds MAX_SOURCE_BYTES (limit=%d, actual=%d)",
		e.Limit, e.Actual,
	)
}

// assertSourceBytesUnderLimit returns SourceSizeExceededError if
// len(source) exceeds MaxSourceBytes. Returns nil otherwise.
func assertSourceBytesUnderLimit(source []byte) error {
	if len(source) > MaxSourceBytes {
		return &SourceSizeExceededError{Limit: MaxSourceBytes, Actual: len(source)}
	}
	return nil
}

// sourceSizeGuardResult returns a *ParseResult carrying a
// SourceSizeExceededError when source exceeds MaxSourceBytes, or nil when
// the source is within bounds. Every exported parser entry point (Parse,
// ParseSolidity, ParseMove, ParseGoContract, ParsePython, ParseRustMacro,
// ParseRuby, ParseZig, ParseJava — not just ParseSource) calls this first,
// so a caller that invokes a per-format parser directly still gets the same
// DoS-bound rejection ParseSource already guarantees (F-177).
func sourceSizeGuardResult(source []byte) *ParseResult {
	if err := assertSourceBytesUnderLimit(source); err != nil {
		sse := err.(*SourceSizeExceededError)
		return &ParseResult{
			Errors: []Diagnostic{{
				Message:  sse.Error(),
				Severity: SeverityError,
			}},
			SourceSizeErr: sse,
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// F-213: source nesting limit
// ---------------------------------------------------------------------------

// sourceNestingPanic unwinds a parser that went past MaxSourceNesting. It is
// raised only by nestingCounter / checkStmtNesting and recovered only by
// withNestingLimit, the Go analogue of the TS reference's SourceNestingError.
type sourceNestingPanic struct {
	loc *SourceLocation
}

// nestingCounter is measure (A): a parser calls enter on entry to each counted
// construct (a statement, a full-expression parse, a prefix-unary operand, a
// nested type argument, ...) and exit when it leaves. Going past
// MaxSourceNesting panics with sourceNestingPanic, so a parser's recursion is
// never deeper than MaxSourceNesting counted frames.
type nestingCounter struct {
	depth int
}

func (c *nestingCounter) enter(loc SourceLocation) {
	c.depth++
	if c.depth > MaxSourceNesting {
		l := loc
		panic(sourceNestingPanic{loc: &l})
	}
}

func (c *nestingCounter) exit() { c.depth-- }

// nested runs fn one counted level deeper.
func nested[T any](c *nestingCounter, loc SourceLocation, fn func() T) T {
	c.enter(loc)
	defer c.exit()
	return fn()
}

func nestingExprChildren(e Expression) []Expression {
	switch n := e.(type) {
	case BinaryExpr:
		return []Expression{n.Left, n.Right}
	case *BinaryExpr:
		return []Expression{n.Left, n.Right}
	case UnaryExpr:
		return []Expression{n.Operand}
	case *UnaryExpr:
		return []Expression{n.Operand}
	case CallExpr:
		return append([]Expression{n.Callee}, n.Args...)
	case *CallExpr:
		return append([]Expression{n.Callee}, n.Args...)
	case MemberExpr:
		return []Expression{n.Object}
	case *MemberExpr:
		return []Expression{n.Object}
	case TernaryExpr:
		return []Expression{n.Condition, n.Consequent, n.Alternate}
	case *TernaryExpr:
		return []Expression{n.Condition, n.Consequent, n.Alternate}
	case IndexAccessExpr:
		return []Expression{n.Object, n.Index}
	case *IndexAccessExpr:
		return []Expression{n.Object, n.Index}
	case IncrementExpr:
		return []Expression{n.Operand}
	case *IncrementExpr:
		return []Expression{n.Operand}
	case DecrementExpr:
		return []Expression{n.Operand}
	case *DecrementExpr:
		return []Expression{n.Operand}
	case ArrayLiteralExpr:
		return n.Elements
	case *ArrayLiteralExpr:
		return n.Elements
	}
	return nil
}

// exprTooDeep reports whether some node of e, sitting at nesting level, is
// deeper than MaxSourceNesting. It stops as soon as level passes the limit,
// so it never recurses more than MaxSourceNesting+1 frames.
func exprTooDeep(e Expression, level int) bool {
	if e == nil {
		return false
	}
	if level > MaxSourceNesting {
		return true
	}
	for _, c := range nestingExprChildren(e) {
		if exprTooDeep(c, level+1) {
			return true
		}
	}
	return false
}

// typeTooDeep: a fixed-array type is one deeper than its element. Iterative.
func typeTooDeep(t TypeNode) bool {
	depth := 0
	for cur := t; cur != nil; {
		depth++
		if depth > MaxSourceNesting {
			return true
		}
		switch fa := cur.(type) {
		case FixedArrayType:
			cur = fa.Element
		case *FixedArrayType:
			cur = fa.Element
		default:
			cur = nil
		}
	}
	return false
}

// stmtNestingParts returns the expression slots, the nested statement lists
// (each one level deeper) and the location of st.
func stmtNestingParts(st Statement) (slots []Expression, nested [][]Statement, typ TypeNode, loc *SourceLocation) {
	switch s := st.(type) {
	case VariableDeclStmt:
		return []Expression{s.Init}, nil, s.Type, &s.SourceLocation
	case *VariableDeclStmt:
		return []Expression{s.Init}, nil, s.Type, &s.SourceLocation
	case AssignmentStmt:
		return []Expression{s.Target, s.Value}, nil, nil, &s.SourceLocation
	case *AssignmentStmt:
		return []Expression{s.Target, s.Value}, nil, nil, &s.SourceLocation
	case ExpressionStmt:
		return []Expression{s.Expr}, nil, nil, &s.SourceLocation
	case *ExpressionStmt:
		return []Expression{s.Expr}, nil, nil, &s.SourceLocation
	case ReturnStmt:
		return []Expression{s.Value}, nil, nil, &s.SourceLocation
	case *ReturnStmt:
		return []Expression{s.Value}, nil, nil, &s.SourceLocation
	case IfStmt:
		nested = [][]Statement{s.Then}
		if s.Else != nil {
			nested = append(nested, s.Else)
		}
		return []Expression{s.Condition}, nested, nil, &s.SourceLocation
	case *IfStmt:
		nested = [][]Statement{s.Then}
		if s.Else != nil {
			nested = append(nested, s.Else)
		}
		return []Expression{s.Condition}, nested, nil, &s.SourceLocation
	case ForStmt:
		initUpdate := []Statement{s.Init}
		if s.Update != nil {
			initUpdate = append(initUpdate, s.Update)
		}
		return []Expression{s.Condition}, [][]Statement{initUpdate, s.Body}, nil, &s.SourceLocation
	case *ForStmt:
		initUpdate := []Statement{s.Init}
		if s.Update != nil {
			initUpdate = append(initUpdate, s.Update)
		}
		return []Expression{s.Condition}, [][]Statement{initUpdate, s.Body}, nil, &s.SourceLocation
	}
	return nil, nil, nil, nil
}

// stmtsTooDeep returns the first statement whose subtree breaks measure (B),
// or nil. Recursion over statement lists stops once level passes the limit.
func stmtsTooDeep(stmts []Statement, level int) Statement {
	for _, st := range stmts {
		if st == nil {
			continue
		}
		if level > MaxSourceNesting {
			return st
		}
		slots, nested, typ, _ := stmtNestingParts(st)
		if typeTooDeep(typ) {
			return st
		}
		for _, e := range slots {
			if exprTooDeep(e, level+1) {
				return st
			}
		}
		for _, list := range nested {
			if bad := stmtsTooDeep(list, level+1); bad != nil {
				return bad
			}
		}
	}
	return nil
}

func nestingStmtLoc(st Statement) *SourceLocation {
	_, _, _, loc := stmtNestingParts(st)
	if loc == nil || (loc.File == "" && loc.Line == 0) {
		return nil
	}
	l := *loc
	return &l
}

// astNestingViolation is measure (B) on the finished Rúnar AST: it returns
// (location-or-nil, true) when the contract breaks the limit.
func astNestingViolation(c *ContractNode) (*SourceLocation, bool) {
	for i := range c.Properties {
		p := &c.Properties[i]
		if typeTooDeep(p.Type) || exprTooDeep(p.Initializer, 1) {
			l := p.SourceLocation
			return &l, true
		}
	}
	methods := append([]MethodNode{c.Constructor}, c.Methods...)
	for i := range methods {
		m := &methods[i]
		for _, prm := range m.Params {
			if typeTooDeep(prm.Type) {
				l := m.SourceLocation
				return &l, true
			}
		}
		if bad := stmtsTooDeep(m.Body, 1); bad != nil {
			if loc := nestingStmtLoc(bad); loc != nil {
				return loc, true
			}
			l := m.SourceLocation
			return &l, true
		}
	}
	return nil, false
}

// checkStmtNesting is measure (B) evaluated early, by a parser, on one
// statement it has just built: the statement is at level >= 1, so if its
// subtree breaks the limit at level 1 the whole-AST check would refuse it too.
// It introduces no new refusals; it only refuses before any recursive pass
// inside the parser (renaming, rewriting) walks a tree the parser built in a
// loop (a 500,000-term `a + a + …` chain), which on Go's 1 GB stack ceiling
// is a fatal, unrecoverable overflow.
func checkStmtNesting(st Statement) {
	if st == nil {
		return
	}
	if bad := stmtsTooDeep([]Statement{st}, 1); bad != nil {
		panic(sourceNestingPanic{loc: nestingStmtLoc(bad)})
	}
}

// nestedStatement is a hand-written parser's statement production: one
// counted level deeper (measure A, rule A1), then measure (B) early on the
// statement it built (checkStmtNesting).
func nestedStatement(c *nestingCounter, loc SourceLocation, parse func() Statement) Statement {
	st := nested(c, loc, parse)
	checkStmtNesting(st)
	return st
}

func sourceNestingResult(loc *SourceLocation) *ParseResult {
	return &ParseResult{Errors: []Diagnostic{{Message: SourceNestingMessage, Severity: SeverityError, Loc: loc}}}
}

// withNestingLimit runs a parser and applies both F-213 measures to it: a
// sourceNestingPanic from measure (A) becomes the shared diagnostic, and on
// success measure (B) is checked before the AST is handed back. Every exported
// parser entry point that carries the MaxSourceBytes guard runs through it.
func withNestingLimit(run func() *ParseResult) (res *ParseResult) {
	defer func() {
		if r := recover(); r != nil {
			np, ok := r.(sourceNestingPanic)
			if !ok {
				panic(r)
			}
			res = sourceNestingResult(np.loc)
		}
	}()
	res = run()
	if res != nil && res.Contract != nil {
		if loc, bad := astNestingViolation(res.Contract); bad {
			errs := append(append([]Diagnostic{}, res.Errors...), Diagnostic{Message: SourceNestingMessage, Severity: SeverityError, Loc: loc})
			return &ParseResult{Errors: errs}
		}
	}
	return res
}
