package frontend

import (
	"strings"
	"testing"
)

// parseAndExpand parses a Go-DSL contract source string and runs the
// expand-fixed-arrays pass on it, returning the resulting contract plus
// any diagnostics. Parser errors cause a fatal test failure. The Go DSL
// is used (rather than the TS parser) because the Go compiler's TS
// parser does not yet produce `ArrayLiteralExpr` initializers for
// FixedArray property defaults.
func parseAndExpand(t *testing.T, source string) (*ContractNode, []Diagnostic) {
	t.Helper()
	pr := ParseGoContract([]byte(source), "Test.runar.go")
	if len(pr.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(pr.ErrorStrings(), "; "))
	}
	if pr.Contract == nil {
		t.Fatalf("no contract parsed")
	}
	res := ExpandFixedArrays(pr.Contract)
	return res.Contract, res.Errors
}

func propertyNames(c *ContractNode) []string {
	out := make([]string, len(c.Properties))
	for i, p := range c.Properties {
		out[i] = p.Name
	}
	return out
}

func findMethod(c *ContractNode, name string) *MethodNode {
	for i := range c.Methods {
		if c.Methods[i].Name == name {
			return &c.Methods[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Property expansion
// ---------------------------------------------------------------------------

const basicArraySrc = `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Boardy struct {
	runar.StatefulSmartContract
	Board [3]runar.Bigint
}

func (c *Boardy) init() {
	c.Board = [3]runar.Bigint{0, 0, 0}
}

func (c *Boardy) SetZero(v runar.Bigint) {
	c.Board[0] = v
	runar.Assert(true)
}

func (c *Boardy) SetRuntime(idx runar.Bigint, v runar.Bigint) {
	c.Board[idx] = v
	runar.Assert(true)
}
`

func TestExpandFixedArrays_FlatPropertyExpansion(t *testing.T) {
	c, errs := parseAndExpand(t, basicArraySrc)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	names := propertyNames(c)
	want := []string{"board__0", "board__1", "board__2"}
	if len(names) != len(want) {
		t.Fatalf("expected properties %v, got %v", want, names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("property[%d] = %q, want %q", i, names[i], want[i])
		}
	}
	for _, p := range c.Properties {
		prim, ok := p.Type.(PrimitiveType)
		if !ok || prim.Name != "bigint" {
			t.Errorf("leaf %s has non-bigint type %T %v", p.Name, p.Type, p.Type)
		}
	}
}

func TestExpandFixedArrays_DistributesArrayLiteralInit(t *testing.T) {
	src := `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Init struct {
	runar.StatefulSmartContract
	Board [3]runar.Bigint
}

func (c *Init) init() {
	c.Board = [3]runar.Bigint{1, 2, 3}
}

func (c *Init) M() {
	runar.Assert(true)
}
`
	c, errs := parseAndExpand(t, src)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(c.Properties) != 3 {
		t.Fatalf("expected 3 properties, got %d", len(c.Properties))
	}
	wantVals := []int64{1, 2, 3}
	for i, p := range c.Properties {
		lit, ok := p.Initializer.(BigIntLiteral)
		if !ok {
			t.Errorf("property[%d] initializer is %T, want BigIntLiteral", i, p.Initializer)
			continue
		}
		if lit.Value.Int64() != wantVals[i] {
			t.Errorf("property[%d] init = %s, want %d", i, lit.Value.String(), wantVals[i])
		}
	}
}

func TestExpandFixedArrays_RejectsInitLengthMismatch(t *testing.T) {
	src := `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type BadInit struct {
	runar.StatefulSmartContract
	Board [3]runar.Bigint
}

func (c *BadInit) init() {
	c.Board = [2]runar.Bigint{0, 0}
}

func (c *BadInit) M() {
	runar.Assert(true)
}
`
	_, errs := parseAndExpand(t, src)
	if len(errs) == 0 {
		t.Fatalf("expected length-mismatch error, got none")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "does not match") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'does not match' error, got: %v", errs)
	}
}

func TestExpandFixedArrays_NestedRecursiveExpansion(t *testing.T) {
	src := `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Grid struct {
	runar.StatefulSmartContract
	G [2][2]runar.Bigint
}

func (c *Grid) init() {
	c.G = [2][2]runar.Bigint{{0, 0}, {0, 0}}
}

func (c *Grid) Tick() {
	c.G[0][1] = 7
	runar.Assert(true)
}
`
	c, errs := parseAndExpand(t, src)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	got := propertyNames(c)
	want := []string{"g__0__0", "g__0__1", "g__1__0", "g__1__1"}
	if len(got) != len(want) {
		t.Fatalf("want %v got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("leaf[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Literal index access
// ---------------------------------------------------------------------------

func TestExpandFixedArrays_LiteralIndexWrite(t *testing.T) {
	c, errs := parseAndExpand(t, basicArraySrc)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	m := findMethod(c, "setZero")
	if m == nil {
		t.Fatal("method setZero not found")
	}
	// Find an assignment statement; its target must be board__0.
	var assign *AssignmentStmt
	for i := range m.Body {
		if a, ok := m.Body[i].(AssignmentStmt); ok {
			assign = &a
			break
		}
	}
	if assign == nil {
		t.Fatal("no assignment found in setZero body")
	}
	pa, ok := assign.Target.(PropertyAccessExpr)
	if !ok {
		t.Fatalf("target %T is not PropertyAccessExpr", assign.Target)
	}
	if pa.Property != "board__0" {
		t.Errorf("target property %q, want board__0", pa.Property)
	}
}

func TestExpandFixedArrays_OutOfRangeLiteralIndex(t *testing.T) {
	src := `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Oor struct {
	runar.StatefulSmartContract
	Board [3]runar.Bigint
}

func (c *Oor) init() {
	c.Board = [3]runar.Bigint{0, 0, 0}
}

func (c *Oor) Bad() {
	c.Board[5] = 9
	runar.Assert(true)
}
`
	_, errs := parseAndExpand(t, src)
	if len(errs) == 0 {
		t.Fatal("expected out-of-range error")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "out of range") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'out of range' error, got: %v", errs)
	}
}

// ---------------------------------------------------------------------------
// Runtime index write
// ---------------------------------------------------------------------------

func TestExpandFixedArrays_RuntimeIndexWriteIfChain(t *testing.T) {
	c, errs := parseAndExpand(t, basicArraySrc)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	m := findMethod(c, "setRuntime")
	if m == nil {
		t.Fatal("method setRuntime not found")
	}
	if len(m.Body) == 0 {
		t.Fatal("empty body")
	}
	first := m.Body[0]
	ifStmt, ok := first.(IfStmt)
	if !ok {
		t.Fatalf("first statement is %T, want IfStmt", first)
	}
	branches := 0
	var node Statement = ifStmt
	for {
		ifs, ok := node.(IfStmt)
		if !ok {
			break
		}
		branches++
		if len(ifs.Else) == 0 {
			break
		}
		node = ifs.Else[0]
	}
	if branches != 3 {
		t.Errorf("expected 3 branches in if-chain, got %d", branches)
	}
}

func TestExpandFixedArrays_HoistsImpureIndexExpression(t *testing.T) {
	src := `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type SE struct {
	runar.StatefulSmartContract
	Board [3]runar.Bigint
}

func (c *SE) init() {
	c.Board = [3]runar.Bigint{0, 0, 0}
}

func (c *SE) DoStuff(base runar.Bigint) {
	c.Board[base + 1] = 5
	runar.Assert(true)
}
`
	c, errs := parseAndExpand(t, src)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	m := findMethod(c, "doStuff")
	if m == nil {
		t.Fatal("method doStuff not found")
	}
	if len(m.Body) == 0 {
		t.Fatal("empty body")
	}
	decl, ok := m.Body[0].(VariableDeclStmt)
	if !ok {
		t.Fatalf("first statement %T, want VariableDeclStmt", m.Body[0])
	}
	if !strings.HasPrefix(decl.Name, "__idx_") {
		t.Errorf("hoisted name = %q, want __idx_* prefix", decl.Name)
	}
}

// ---------------------------------------------------------------------------
// Runtime index read (statement-form vs ternary)
// ---------------------------------------------------------------------------

func TestExpandFixedArrays_StatementFormRuntimeRead(t *testing.T) {
	src := `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type R struct {
	runar.StatefulSmartContract
	Board [3]runar.Bigint
}

func (c *R) init() {
	c.Board = [3]runar.Bigint{0, 0, 0}
}

func (c *R) M(idx runar.Bigint) {
	v := c.Board[idx]
	runar.Assert(v == 0)
}
`
	c, errs := parseAndExpand(t, src)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	m := findMethod(c, "m")
	if m == nil {
		t.Fatal("method m not found")
	}
	decl, ok := m.Body[0].(VariableDeclStmt)
	if !ok {
		t.Fatalf("body[0] %T, want VariableDeclStmt", m.Body[0])
	}
	if decl.Name != "v" {
		t.Errorf("decl name %q, want v", decl.Name)
	}
	pa, ok := decl.Init.(PropertyAccessExpr)
	if !ok {
		t.Fatalf("decl.Init %T, want PropertyAccessExpr", decl.Init)
	}
	if pa.Property != "board__2" {
		t.Errorf("decl.Init.Property %q, want board__2", pa.Property)
	}
	ifStmt, ok := m.Body[1].(IfStmt)
	if !ok {
		t.Fatalf("body[1] %T, want IfStmt", m.Body[1])
	}
	branches := 0
	var node Statement = ifStmt
	for {
		ifs, ok := node.(IfStmt)
		if !ok {
			break
		}
		branches++
		if len(ifs.Then) == 0 {
			t.Errorf("branch has empty then")
		} else if a, ok := ifs.Then[0].(AssignmentStmt); !ok {
			t.Errorf("then[0] %T, want AssignmentStmt", ifs.Then[0])
		} else if id, ok := a.Target.(Identifier); !ok || id.Name != "v" {
			t.Errorf("then[0] target %T %v, want Identifier{v}", a.Target, a.Target)
		}
		if len(ifs.Else) == 0 {
			break
		}
		node = ifs.Else[0]
	}
	if branches != 2 {
		t.Errorf("expected 2 branches in read if-chain, got %d", branches)
	}
}

// ---------------------------------------------------------------------------
// SyntheticArrayChain markers
// ---------------------------------------------------------------------------

func TestExpandFixedArrays_FlatChain(t *testing.T) {
	c, errs := parseAndExpand(t, basicArraySrc)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(c.Properties) != 3 {
		t.Fatalf("got %d properties", len(c.Properties))
	}
	for i, p := range c.Properties {
		if len(p.SyntheticArrayChain) != 1 {
			t.Fatalf("property[%d] chain length %d, want 1", i, len(p.SyntheticArrayChain))
		}
		lvl := p.SyntheticArrayChain[0]
		if lvl.Base != "board" || lvl.Index != i || lvl.Length != 3 {
			t.Errorf("property[%d] chain[0] = %+v", i, lvl)
		}
	}
}

func TestExpandFixedArrays_NestedChain(t *testing.T) {
	src := `
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Grid struct {
	runar.StatefulSmartContract
	G [2][2]runar.Bigint
}

func (c *Grid) init() {
	c.G = [2][2]runar.Bigint{{0, 0}, {0, 0}}
}

func (c *Grid) Set01() {
	c.G[0][1] = 7
	runar.Assert(true)
}
`
	c, errs := parseAndExpand(t, src)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	expect := []struct {
		name  string
		chain [][3]interface{} // base, index, length
	}{
		{"g__0__0", [][3]interface{}{{"g", 0, 2}, {"g__0", 0, 2}}},
		{"g__0__1", [][3]interface{}{{"g", 0, 2}, {"g__0", 1, 2}}},
		{"g__1__0", [][3]interface{}{{"g", 1, 2}, {"g__1", 0, 2}}},
		{"g__1__1", [][3]interface{}{{"g", 1, 2}, {"g__1", 1, 2}}},
	}
	if len(c.Properties) != len(expect) {
		t.Fatalf("got %d properties, want %d", len(c.Properties), len(expect))
	}
	for i, e := range expect {
		p := c.Properties[i]
		if p.Name != e.name {
			t.Errorf("[%d] name = %q, want %q", i, p.Name, e.name)
		}
		if len(p.SyntheticArrayChain) != len(e.chain) {
			t.Errorf("[%d] chain len %d, want %d", i, len(p.SyntheticArrayChain), len(e.chain))
			continue
		}
		for j, lvl := range p.SyntheticArrayChain {
			want := e.chain[j]
			if lvl.Base != want[0] || lvl.Index != want[1] || lvl.Length != want[2] {
				t.Errorf("[%d].chain[%d] = %+v, want %+v", i, j, lvl, want)
			}
		}
	}
}

// R-229 (GK-GAP-008): the expansion pass must not drop a method's
// `@sighash` directive.
//
// The pass rebuilds method nodes while rewriting `this.arr[i]` reads, and a
// rebuild that lists fields explicitly loses whatever it forgets to list.
// SighashType is the field that costs money when it goes: validate has already
// ACCEPTED the directive by the time this pass runs, so losing it silently
// reverts the method to ALL|FORKID and commits a different signature hash than
// the author declared. R-025/R-026 fixed exactly that class of drop, and
// N-086 found four more fields going the same way in the Zig port.
//
// The TS, Python and Zig tiers assert this; go, rust, ruby and java did not.
// This is the Go half.
func TestExpandFixedArrays_PreservesSighashType(t *testing.T) {
	// The TS surface, not the Go DSL: the `@sighash` directive is a JSDoc
	// comment, which is where ParseSource reads it from (see
	// sighash_parse_test.go). A FixedArray property with no initializer is
	// enough to make the pass rewrite this method.
	src := `
        class Boardy extends StatefulSmartContract {
          board: FixedArray<bigint, 3>;
          n: bigint;
          constructor(n: bigint) { super(n); this.n = n; }
          /** @sighash SINGLE|FORKID */
          public bump(): void {
            this.addOutput(1000n, this.board[0], this.board[1], this.board[2], this.n);
          }
        }`
	pr := ParseSource([]byte(src), "Boardy.runar.ts")
	if len(pr.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(pr.ErrorStrings(), "; "))
	}
	if pr.Contract == nil {
		t.Fatal("no contract parsed")
	}

	before := findMethod(pr.Contract, "bump")
	if before == nil {
		t.Fatal("no bump method parsed")
	}
	if before.SighashType == nil {
		t.Fatal("the directive did not reach the AST — this test would be vacuous")
	}
	if *before.SighashType != 0x43 {
		t.Fatalf("before expansion: SighashType = %#x, want 0x43 (SINGLE|FORKID)", *before.SighashType)
	}

	res := ExpandFixedArrays(pr.Contract)
	if len(res.Errors) > 0 {
		t.Fatalf("expansion errors: %v", res.Errors)
	}
	// The pass must actually have done something, or the assertion below is
	// about a method nothing touched.
	if len(res.Contract.Properties) < 3 {
		t.Fatalf("expansion did not expand: properties = %v", propertyNames(res.Contract))
	}

	after := findMethod(res.Contract, "bump")
	if after == nil {
		t.Fatal("bump vanished during expansion")
	}
	if after.SighashType == nil {
		t.Fatal("expansion dropped SighashType — the method silently reverts to ALL|FORKID")
	}
	if *after.SighashType != 0x43 {
		t.Errorf("after expansion: SighashType = %#x, want 0x43", *after.SighashType)
	}
}
