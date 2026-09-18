package frontend

// N-019 (port of R-018, Rust): `this.arr[i]++` must be recognised as a state
// mutation.
//
// Two blind spots, both keyed on the operand of an increment/decrement being a
// bare PropertyAccessExpr:
//
//  1. Lowering — lowerIncrementExpr / lowerDecrementExpr in anf_lower.go emit
//     an `update_prop` ONLY when the operand is a PropertyAccessExpr. After
//     ExpandFixedArrays has run, `c.Board[i]` (runtime index) is a ternary read
//     chain over the expanded slots, so the new value is computed and
//     DISCARDED — the mutation vanishes.
//
//  2. Side-effect summary — collectExpr in side_effect_summary.go has the
//     identical guard, so MutatesState stays false, ContinuationShapeFor
//     returns IsTerminal = true, and NO continuation assertion is injected at
//     all: a method that mutates state emits nothing binding that mutation.
//
// The root cause is neither site: pass 3b rewrites only the increment's
// OPERAND, leaving a TernaryExpr where both sites expect a property access.
//
// The control below (`c.Total++`, a plain scalar property) is the shape that
// already works and must stay unchanged — it discriminates the two paths.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// Runtime index (`i` is a parameter), so ExpandFixedArrays cannot fold
// `c.Board[i]` to a single slot — it becomes a dispatch/ternary chain.
const n019IndexIncrementSrc = `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type BumpIncr struct {
	runar.StatefulSmartContract
	Board [3]runar.Bigint
}

func (c *BumpIncr) init() {
	c.Board = [3]runar.Bigint{0, 0, 0}
}

func (c *BumpIncr) Bump(i runar.Bigint) {
	c.Board[i]++
}
`

const n019IndexDecrementSrc = `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type BumpDecr struct {
	runar.StatefulSmartContract
	Board [3]runar.Bigint
}

func (c *BumpDecr) init() {
	c.Board = [3]runar.Bigint{0, 0, 0}
}

func (c *BumpDecr) Bump(i runar.Bigint) {
	c.Board[i]--
}
`

// The hand-written form `c.Board[i]++` must be equivalent to.
const n019IndexExplicitAddSrc = `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type BumpIncr struct {
	runar.StatefulSmartContract
	Board [3]runar.Bigint
}

func (c *BumpIncr) init() {
	c.Board = [3]runar.Bigint{0, 0, 0}
}

func (c *BumpIncr) Bump(i runar.Bigint) {
	c.Board[i] = c.Board[i] + 1
}
`

// Literal index — already folds to `c.Board__0`; must be byte-identical.
const n019LiteralIndexIncrementSrc = `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type BumpLit struct {
	runar.StatefulSmartContract
	Board [3]runar.Bigint
}

func (c *BumpLit) init() {
	c.Board = [3]runar.Bigint{0, 0, 0}
}

func (c *BumpLit) Bump(i runar.Bigint) {
	c.Board[0]++
}
`

const n019LiteralIndexExplicitSrc = `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type BumpLit struct {
	runar.StatefulSmartContract
	Board [3]runar.Bigint
}

func (c *BumpLit) init() {
	c.Board = [3]runar.Bigint{0, 0, 0}
}

func (c *BumpLit) Bump(i runar.Bigint) {
	c.Board[0] = c.Board[0] + 1
}
`

// The most plausible real-world shape: a histogram bump inside a loop.
const n019IndexIncrementInLoopSrc = `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type BumpLoop struct {
	runar.StatefulSmartContract
	Board [3]runar.Bigint
}

func (c *BumpLoop) init() {
	c.Board = [3]runar.Bigint{0, 0, 0}
}

func (c *BumpLoop) BumpAll() {
	for i := runar.Bigint(0); i < 3; i++ {
		c.Board[i]++
	}
}
`

// Control: the already-working shape. A plain mutable scalar property.
const n019PlainPropIncrementSrc = `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type BumpProp struct {
	runar.StatefulSmartContract
	Total runar.Bigint
}

func (c *BumpProp) init() {
	c.Total = 0
}

func (c *BumpProp) Bump(i runar.Bigint) {
	c.Total++
}
`

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// n019Expanded parses + runs pass 3b, exactly as the compiler driver does
// before ANF lowering. Any diagnostic is a fatal failure.
func n019Expanded(t *testing.T, source string) *ContractNode {
	t.Helper()
	pr := ParseGoContract([]byte(source), "Test.runar.go")
	if len(pr.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(pr.ErrorStrings(), "; "))
	}
	if pr.Contract == nil {
		t.Fatalf("no contract parsed")
	}
	res := ExpandFixedArrays(pr.Contract)
	if len(res.Errors) > 0 {
		t.Fatalf("expand-fixed-arrays errors: %v", res.Errors)
	}
	return res.Contract
}

// n019UpdatePropNames collects every update_prop name anywhere in the body,
// including inside `if` arms and loop bodies.
func n019UpdatePropNames(bindings []ir.ANFBinding, out *[]string) {
	for _, b := range bindings {
		switch b.Value.Kind {
		case "update_prop":
			*out = append(*out, b.Value.Name)
		case "if":
			n019UpdatePropNames(b.Value.Then, out)
			n019UpdatePropNames(b.Value.Else, out)
		case "loop":
			n019UpdatePropNames(b.Value.Body, out)
		}
	}
}

func n019UpdatedProps(t *testing.T, source, method string) []string {
	t.Helper()
	prog := LowerToANF(n019Expanded(t, source))
	for i := range prog.Methods {
		if prog.Methods[i].Name != method {
			continue
		}
		var out []string
		n019UpdatePropNames(prog.Methods[i].Body, &out)
		return out
	}
	t.Fatalf("method %s not found", method)
	return nil
}

func n019ParamNames(t *testing.T, source, method string) []string {
	t.Helper()
	prog := LowerToANF(n019Expanded(t, source))
	for i := range prog.Methods {
		if prog.Methods[i].Name != method {
			continue
		}
		out := make([]string, len(prog.Methods[i].Params))
		for j, p := range prog.Methods[i].Params {
			out[j] = p.Name
		}
		return out
	}
	t.Fatalf("method %s not found", method)
	return nil
}

func n019Shape(t *testing.T, source, method string) (bool, ContinuationShape) {
	t.Helper()
	summary := ComputeSideEffectSummary(n019Expanded(t, source))
	eff, ok := summary[method]
	if !ok {
		t.Fatalf("no side-effect entry for %s", method)
	}
	return eff.MutatesState, ContinuationShapeFor(eff)
}

func n019HasSlotUpdate(props []string, prefix string) bool {
	for _, p := range props {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func n019AnfJSON(t *testing.T, source string) string {
	t.Helper()
	b, err := json.Marshal(LowerToANF(n019Expanded(t, source)))
	if err != nil {
		t.Fatalf("marshal ANF: %v", err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Control — the shape that already works. Must pass before AND after the fix.
// ---------------------------------------------------------------------------

func TestN019_Control_PlainPropertyIncrementUpdatesState(t *testing.T) {
	props := n019UpdatedProps(t, n019PlainPropIncrementSrc, "bump")
	if !n019HasSlotUpdate(props, "total") {
		t.Fatalf("control regressed: `c.Total++` produced no update_prop for total; got %v", props)
	}
	mutates, shape := n019Shape(t, n019PlainPropIncrementSrc, "bump")
	if !mutates {
		t.Errorf("control regressed: `c.Total++` is not mutating")
	}
	if shape.IsTerminal {
		t.Errorf("control regressed: `c.Total++` method treated as terminal")
	}
}

// ---------------------------------------------------------------------------
// Half 1 — lowering: the increment through an index must produce update_prop.
// ---------------------------------------------------------------------------

func TestN019_IndexIncrementEmitsUpdateProp(t *testing.T) {
	props := n019UpdatedProps(t, n019IndexIncrementSrc, "bump")
	if len(props) == 0 {
		t.Fatalf("`c.Board[i]++` produced NO update_prop at all — the mutation was computed and discarded")
	}
	if !n019HasSlotUpdate(props, "board") {
		t.Errorf("`c.Board[i]++` produced no update_prop for a board slot; got %v", props)
	}
}

func TestN019_IndexDecrementEmitsUpdateProp(t *testing.T) {
	props := n019UpdatedProps(t, n019IndexDecrementSrc, "bump")
	if !n019HasSlotUpdate(props, "board") {
		t.Errorf("`c.Board[i]--` produced no update_prop for a board slot; got %v", props)
	}
}

// ---------------------------------------------------------------------------
// Half 2 — side-effect summary: the method is NOT terminal.
// ---------------------------------------------------------------------------

func TestN019_IndexIncrementIsAStateMutation(t *testing.T) {
	mutates, shape := n019Shape(t, n019IndexIncrementSrc, "bump")
	if !mutates {
		t.Errorf("`c.Board[i]++` did not set MutatesState — no continuation is injected")
	}
	if shape.IsTerminal {
		t.Errorf("`c.Board[i]++` method classified terminal: no continuation assertion binds the mutation")
	}
	if !shape.NeedsChange {
		t.Errorf("expected NeedsChange for a state mutation")
	}
	if !shape.NeedsNewAmount {
		t.Errorf("expected NeedsNewAmount for a single-output state mutation")
	}
}

func TestN019_IndexDecrementIsAStateMutation(t *testing.T) {
	mutates, shape := n019Shape(t, n019IndexDecrementSrc, "bump")
	if !mutates {
		t.Errorf("`c.Board[i]--` did not set MutatesState")
	}
	if shape.IsTerminal {
		t.Errorf("`c.Board[i]--` method classified terminal")
	}
}

func TestN019_IndexIncrementInsideALoopIsAStateMutation(t *testing.T) {
	props := n019UpdatedProps(t, n019IndexIncrementInLoopSrc, "bumpAll")
	if !n019HasSlotUpdate(props, "board") {
		t.Errorf("`c.Board[i]++` inside a for-loop produced no update_prop; got %v", props)
	}
	mutates, shape := n019Shape(t, n019IndexIncrementInLoopSrc, "bumpAll")
	if !mutates {
		t.Errorf("loop-bumped array element did not set MutatesState")
	}
	if shape.IsTerminal {
		t.Errorf("loop-bumping method classified terminal")
	}
}

// ---------------------------------------------------------------------------
// The desugar must be FAITHFUL, not merely present.
// ---------------------------------------------------------------------------

func TestN019_IndexIncrementLowersIdenticallyToTheExplicitAdd(t *testing.T) {
	sugar := n019AnfJSON(t, n019IndexIncrementSrc)
	explicit := n019AnfJSON(t, n019IndexExplicitAddSrc)
	if sugar != explicit {
		t.Errorf("`c.Board[i]++` must lower identically to `c.Board[i] = c.Board[i] + 1`\nsugar:    %s\nexplicit: %s", sugar, explicit)
	}
}

func TestN019_LiteralIndexIncrementIsUnchanged(t *testing.T) {
	sugar := n019AnfJSON(t, n019LiteralIndexIncrementSrc)
	explicit := n019AnfJSON(t, n019LiteralIndexExplicitSrc)
	if sugar != explicit {
		t.Errorf("literal-index `c.Board[0]++` must stay byte-identical to the explicit form\nsugar:    %s\nexplicit: %s", sugar, explicit)
	}
}

func TestN019_IndexIncrementMethodGetsContinuationParams(t *testing.T) {
	params := n019ParamNames(t, n019IndexIncrementSrc, "bump")
	control := n019ParamNames(t, n019PlainPropIncrementSrc, "bump")
	if strings.Join(params, ",") != strings.Join(control, ",") {
		t.Errorf("`c.Board[i]++` must receive the same continuation params as the equivalent `c.Total++`; got %v vs control %v", params, control)
	}
}

// ---------------------------------------------------------------------------
// Expression position cannot write back through the dispatch chain.
// ---------------------------------------------------------------------------

func TestN019_IndexIncrementInExpressionPositionIsRejected(t *testing.T) {
	// `c.Board[i]++` used for its VALUE. The Go DSL surface has no postfix
	// increment in expression position, so drive the AST directly: an
	// assignment whose value is an IncrementExpr over an IndexAccessExpr.
	contract := n019ParseOnly(t, n019IndexIncrementSrc)
	m := findMethod(contract, "bump")
	if m == nil {
		t.Fatalf("method bump not found")
	}
	incr, ok := m.Body[0].(ExpressionStmt).Expr.(IncrementExpr)
	if !ok {
		t.Fatalf("expected the body to start with an IncrementExpr, got %T", m.Body[0])
	}
	m.Body = []Statement{
		AssignmentStmt{
			Target: PropertyAccessExpr{Property: "board__0"},
			Value:  incr,
		},
	}
	res := ExpandFixedArrays(contract)
	if len(res.Errors) == 0 {
		t.Errorf("`x = c.Board[i]++` was accepted; the array write is silently dropped")
	}
}

// n019ParseOnly parses without running pass 3b.
func n019ParseOnly(t *testing.T, source string) *ContractNode {
	t.Helper()
	pr := ParseGoContract([]byte(source), "Test.runar.go")
	if len(pr.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(pr.ErrorStrings(), "; "))
	}
	return pr.Contract
}
