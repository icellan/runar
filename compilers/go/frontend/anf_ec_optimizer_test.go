package frontend

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeTestProgram creates a minimal ANFProgram with a single method containing
// the given bindings.
func makeTestProgram(bindings []ir.ANFBinding) *ir.ANFProgram {
	return &ir.ANFProgram{
		ContractName: "Test",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:     "test",
				Params:   []ir.ANFParam{},
				Body:     bindings,
				IsPublic: true,
			},
		},
	}
}

// loadConstHex returns an ANFBinding with a load_const holding a hex string.
func loadConstHex(name, hexStr string) ir.ANFBinding {
	raw, _ := json.Marshal(hexStr)
	b := ir.ANFBinding{
		Name: name,
		Value: ir.ANFValue{
			Kind:     "load_const",
			RawValue: raw,
		},
	}
	b.Value.ConstString = &hexStr
	return b
}

// loadConstBigInt returns an ANFBinding with a load_const holding an integer.
func loadConstBigInt(name string, n int64) ir.ANFBinding {
	raw, _ := json.Marshal(n)
	bi := big.NewInt(n)
	b := ir.ANFBinding{
		Name: name,
		Value: ir.ANFValue{
			Kind:        "load_const",
			RawValue:    raw,
			ConstBigInt: bi,
		},
	}
	return b
}

// callBinding returns an ANFBinding representing a function call.
func callBinding(name, funcName string, args []string) ir.ANFBinding {
	return ir.ANFBinding{
		Name: name,
		Value: ir.ANFValue{
			Kind: "call",
			Func: funcName,
			Args: args,
		},
	}
}

// assertBinding returns an ANFBinding representing an assert with a value ref.
func assertBinding(name, valueRef string) ir.ANFBinding {
	raw, _ := json.Marshal(valueRef)
	return ir.ANFBinding{
		Name: name,
		Value: ir.ANFValue{
			Kind:     "assert",
			RawValue: raw,
			ValueRef: valueRef,
		},
	}
}

// findBinding returns the binding with the given name, or nil.
func findBinding(bindings []ir.ANFBinding, name string) *ir.ANFBinding {
	for i := range bindings {
		if bindings[i].Name == name {
			return &bindings[i]
		}
	}
	return nil
}

// getMethodBody returns the body of the first method.
func getMethodBody(program *ir.ANFProgram) []ir.ANFBinding {
	return program.Methods[0].Body
}

// bindingNames returns a slice of all binding names in order.
func bindingNames(bindings []ir.ANFBinding) []string {
	names := make([]string, len(bindings))
	for i, b := range bindings {
		names[i] = b.Name
	}
	return names
}

// callBuiltinBinding returns an ANFBinding representing a call_builtin invocation.
func callBuiltinBinding(name, funcName string, args []string) ir.ANFBinding {
	return ir.ANFBinding{
		Name: name,
		Value: ir.ANFValue{
			Kind: "call_builtin",
			Func: funcName,
			Args: args,
		},
	}
}

// ---------------------------------------------------------------------------
// Pass-through behavior (no EC ops)
// ---------------------------------------------------------------------------

// TestANFECOptimizer_PassThrough_NoECOps verifies that programs without EC
// calls pass through the optimizer unchanged.
func TestANFECOptimizer_PassThrough_NoECOps(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstBigInt("t0", 42),
		loadConstBigInt("t1", 10),
		{
			Name: "t2",
			Value: ir.ANFValue{
				Kind:  "bin_op",
				Op:    "+",
				Left:  "t0",
				Right: "t1",
			},
		},
		assertBinding("t3", "t2"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)

	body := getMethodBody(result)
	if len(body) != 4 {
		t.Fatalf("expected 4 bindings, got %d", len(body))
	}
	names := bindingNames(body)
	expected := []string{"t0", "t1", "t2", "t3"}
	for i, want := range expected {
		if names[i] != want {
			t.Errorf("binding[%d]: want %q, got %q", i, want, names[i])
		}
	}
}

// TestANFECOptimizer_NonECCallUnchanged verifies that a non-EC builtin call
// (e.g. hash160) passes through the optimizer completely unchanged.
func TestANFECOptimizer_NonECCallUnchanged(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstHex("t0", "abcd"),
		callBuiltinBinding("t1", "hash160", []string{"t0"}),
		assertBinding("t2", "t1"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	if len(body) != 3 {
		t.Fatalf("expected 3 bindings, got %d", len(body))
	}
	t1 := findBinding(body, "t1")
	if t1 == nil {
		t.Fatal("expected hash160 binding t1 to still be present after optimization")
	}
	if t1.Value.Kind != "call_builtin" {
		t.Errorf("expected t1.Kind == call_builtin, got %q", t1.Value.Kind)
	}
	if t1.Value.Func != "hash160" {
		t.Errorf("expected t1.Func == hash160, got %q", t1.Value.Func)
	}
}

// TestANFECOptimizer_SideEffectBindingsPreserved verifies that assert-type
// bindings are never eliminated by dead-binding removal, even after an EC
// simplification changes what they reference.
func TestANFECOptimizer_SideEffectBindingsPreserved(t *testing.T) {
	// ecAdd(t0, INFINITY) rewrites t2 to @ref:t0 — t2 is still referenced by t3.
	// The assert binding t3 must survive dead-binding elimination.
	bindings := []ir.ANFBinding{
		loadConstHex("t0", strings.Repeat("ab", 64)),
		loadConstHex("t1", infinityHex),
		callBinding("t2", "ecAdd", []string{"t0", "t1"}),
		assertBinding("t3", "t2"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	names := bindingNames(body)
	found := false
	for _, n := range names {
		if n == "t3" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected assert binding t3 to be preserved, but it was eliminated; bindings: %v", names)
	}
}

// TestANFECOptimizer_PassThrough_EmptyMethod verifies that an empty method body
// survives the optimizer unchanged.
func TestANFECOptimizer_PassThrough_EmptyMethod(t *testing.T) {
	program := makeTestProgram([]ir.ANFBinding{})
	result := OptimizeEC(program)
	body := getMethodBody(result)
	if len(body) != 0 {
		t.Fatalf("expected empty body, got %d bindings", len(body))
	}
}

// ---------------------------------------------------------------------------
// Rule 1: ecAdd(x, INFINITY) -> alias to x
// ---------------------------------------------------------------------------

func TestANFECOptimizer_Rule1_EcAddXInfinity(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstHex("t0", strings.Repeat("ab", 64)), // some point
		loadConstHex("t1", infinityHex),
		callBinding("t2", "ecAdd", []string{"t0", "t1"}),
		assertBinding("t3", "t2"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	t2 := findBinding(body, "t2")
	if t2 == nil {
		t.Fatal("expected binding t2 to exist")
	}
	if t2.Value.Kind != "load_const" {
		t.Errorf("expected t2.Kind == load_const, got %q", t2.Value.Kind)
	}
	if t2.Value.ConstString == nil || *t2.Value.ConstString != "@ref:t0" {
		t.Errorf("expected t2.ConstString == @ref:t0, got %v", t2.Value.ConstString)
	}
}

// ---------------------------------------------------------------------------
// Rule 2: ecAdd(INFINITY, x) -> alias to x
// ---------------------------------------------------------------------------

func TestANFECOptimizer_Rule2_EcAddInfinityX(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstHex("t0", infinityHex),
		loadConstHex("t1", strings.Repeat("cd", 64)), // some point
		callBinding("t2", "ecAdd", []string{"t0", "t1"}),
		assertBinding("t3", "t2"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	t2 := findBinding(body, "t2")
	if t2 == nil {
		t.Fatal("expected binding t2 to exist")
	}
	if t2.Value.Kind != "load_const" {
		t.Errorf("expected t2.Kind == load_const, got %q", t2.Value.Kind)
	}
	if t2.Value.ConstString == nil || *t2.Value.ConstString != "@ref:t1" {
		t.Errorf("expected t2.ConstString == @ref:t1, got %v", t2.Value.ConstString)
	}
}

// ---------------------------------------------------------------------------
// Rule 3: ecMul(x, 1) -> alias to x
// ---------------------------------------------------------------------------

func TestANFECOptimizer_Rule3_EcMulByOne(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstHex("t0", strings.Repeat("ab", 64)),
		loadConstBigInt("t1", 1),
		callBinding("t2", "ecMul", []string{"t0", "t1"}),
		assertBinding("t3", "t2"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	t2 := findBinding(body, "t2")
	if t2 == nil {
		t.Fatal("expected binding t2 to exist")
	}
	if t2.Value.Kind != "load_const" {
		t.Errorf("expected t2.Kind == load_const, got %q", t2.Value.Kind)
	}
	if t2.Value.ConstString == nil || *t2.Value.ConstString != "@ref:t0" {
		t.Errorf("expected t2.ConstString == @ref:t0, got %v", t2.Value.ConstString)
	}
}

// ---------------------------------------------------------------------------
// Rule 4: ecMul(x, 0) -> INFINITY
// ---------------------------------------------------------------------------

func TestANFECOptimizer_Rule4_EcMulByZero(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstHex("t0", strings.Repeat("ab", 64)),
		loadConstBigInt("t1", 0),
		callBinding("t2", "ecMul", []string{"t0", "t1"}),
		assertBinding("t3", "t2"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	t2 := findBinding(body, "t2")
	if t2 == nil {
		t.Fatal("expected binding t2 to exist")
	}
	if t2.Value.Kind != "load_const" {
		t.Errorf("expected t2.Kind == load_const, got %q", t2.Value.Kind)
	}
	if t2.Value.ConstString == nil || *t2.Value.ConstString != infinityHex {
		got := "<nil>"
		if t2.Value.ConstString != nil {
			got = *t2.Value.ConstString
		}
		t.Errorf("expected t2 to be INFINITY, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Rule 5: ecMulGen(0) -> INFINITY
// ---------------------------------------------------------------------------

func TestANFECOptimizer_Rule5_EcMulGenZero(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstBigInt("t0", 0),
		callBinding("t1", "ecMulGen", []string{"t0"}),
		assertBinding("t2", "t1"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	t1 := findBinding(body, "t1")
	if t1 == nil {
		t.Fatal("expected binding t1 to exist")
	}
	if t1.Value.Kind != "load_const" {
		t.Errorf("expected t1.Kind == load_const, got %q", t1.Value.Kind)
	}
	if t1.Value.ConstString == nil || *t1.Value.ConstString != infinityHex {
		got := "<nil>"
		if t1.Value.ConstString != nil {
			got = *t1.Value.ConstString
		}
		t.Errorf("expected t1 to be INFINITY, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Rule 6: ecMulGen(1) -> G
// ---------------------------------------------------------------------------

func TestANFECOptimizer_Rule6_EcMulGenOne(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstBigInt("t0", 1),
		callBinding("t1", "ecMulGen", []string{"t0"}),
		assertBinding("t2", "t1"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	t1 := findBinding(body, "t1")
	if t1 == nil {
		t.Fatal("expected binding t1 to exist")
	}
	if t1.Value.Kind != "load_const" {
		t.Errorf("expected t1.Kind == load_const, got %q", t1.Value.Kind)
	}
	if t1.Value.ConstString == nil || *t1.Value.ConstString != gHex {
		got := "<nil>"
		if t1.Value.ConstString != nil {
			got = *t1.Value.ConstString
		}
		t.Errorf("expected t1 to be G, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Rule 7: ecNegate(ecNegate(x)) -> alias to x
// ---------------------------------------------------------------------------

func TestANFECOptimizer_Rule7_DoubleNegate(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstHex("t0", strings.Repeat("ab", 64)),
		callBinding("t1", "ecNegate", []string{"t0"}),
		callBinding("t2", "ecNegate", []string{"t1"}),
		assertBinding("t3", "t2"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	t2 := findBinding(body, "t2")
	if t2 == nil {
		t.Fatal("expected binding t2 to exist")
	}
	if t2.Value.Kind != "load_const" {
		t.Errorf("expected t2.Kind == load_const, got %q", t2.Value.Kind)
	}
	if t2.Value.ConstString == nil || *t2.Value.ConstString != "@ref:t0" {
		t.Errorf("expected t2.ConstString == @ref:t0, got %v", t2.Value.ConstString)
	}
}

// ---------------------------------------------------------------------------
// Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY
// ---------------------------------------------------------------------------

func TestANFECOptimizer_Rule8_AddNegate(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstHex("t0", strings.Repeat("ab", 64)),
		callBinding("t1", "ecNegate", []string{"t0"}),
		callBinding("t2", "ecAdd", []string{"t0", "t1"}),
		assertBinding("t3", "t2"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	t2 := findBinding(body, "t2")
	if t2 == nil {
		t.Fatal("expected binding t2 to exist")
	}
	if t2.Value.Kind != "load_const" {
		t.Errorf("expected t2.Kind == load_const, got %q", t2.Value.Kind)
	}
	if t2.Value.ConstString == nil || *t2.Value.ConstString != infinityHex {
		got := "<nil>"
		if t2.Value.ConstString != nil {
			got = *t2.Value.ConstString
		}
		t.Errorf("expected t2 to be INFINITY, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Rule 12: ecMul(G, k) -> ecMulGen(k)
// ---------------------------------------------------------------------------

func TestANFECOptimizer_Rule12_MulGToMulGen(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstHex("t0", gHex),
		loadConstBigInt("t1", 42),
		callBinding("t2", "ecMul", []string{"t0", "t1"}),
		assertBinding("t3", "t2"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	t2 := findBinding(body, "t2")
	if t2 == nil {
		t.Fatal("expected binding t2 to exist")
	}
	if t2.Value.Kind != "call" {
		t.Errorf("expected t2.Kind == call, got %q", t2.Value.Kind)
	}
	if t2.Value.Func != "ecMulGen" {
		t.Errorf("expected t2.Func == ecMulGen, got %q", t2.Value.Func)
	}
	if len(t2.Value.Args) != 1 || t2.Value.Args[0] != "t1" {
		t.Errorf("expected t2.Args == [t1], got %v", t2.Value.Args)
	}
}

// ---------------------------------------------------------------------------
// Dead binding elimination
// ---------------------------------------------------------------------------

// TestANFECOptimizer_DeadBindingRemoved checks that a binding no longer
// referenced after optimization is eliminated.
func TestANFECOptimizer_DeadBindingRemoved(t *testing.T) {
	// ecAdd(t0, INFINITY) rewrites t2 to @ref:t0.
	// t1 (INFINITY) then has no users and should be removed.
	bindings := []ir.ANFBinding{
		loadConstHex("t0", strings.Repeat("ab", 64)),
		loadConstHex("t1", infinityHex),
		callBinding("t2", "ecAdd", []string{"t0", "t1"}),
		assertBinding("t3", "t2"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	names := bindingNames(body)
	for _, n := range names {
		if n == "t1" {
			t.Error("expected dead binding t1 (INFINITY) to be eliminated, but it is still present")
		}
	}
}

// ---------------------------------------------------------------------------
// Program structure preserved
// ---------------------------------------------------------------------------

// TestANFECOptimizer_ContractNamePreserved verifies that contract metadata
// (name, properties, method names) is retained after optimization.
func TestANFECOptimizer_ContractNamePreserved(t *testing.T) {
	program := &ir.ANFProgram{
		ContractName: "MyContract",
		Properties: []ir.ANFProperty{
			{Name: "x", Type: "bigint", Readonly: true},
		},
		Methods: []ir.ANFMethod{
			{
				Name: "doStuff",
				Params: []ir.ANFParam{
					{Name: "y", Type: "bigint"},
				},
				Body: []ir.ANFBinding{
					loadConstBigInt("t0", 1),
					assertBinding("t1", "t0"),
				},
				IsPublic: true,
			},
		},
	}

	result := OptimizeEC(program)

	if result.ContractName != "MyContract" {
		t.Errorf("expected ContractName == MyContract, got %q", result.ContractName)
	}
	if len(result.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(result.Properties))
	}
	if result.Properties[0].Name != "x" {
		t.Errorf("expected property name 'x', got %q", result.Properties[0].Name)
	}
	if len(result.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(result.Methods))
	}
	if result.Methods[0].Name != "doStuff" {
		t.Errorf("expected method name 'doStuff', got %q", result.Methods[0].Name)
	}
}

// ---------------------------------------------------------------------------
// Side effect: call binding without references is preserved
// ---------------------------------------------------------------------------

// TestANFECOptimizer_SideEffectCallPreserved verifies that a call binding
// (e.g., checkSig) that is not referenced by any other binding is NOT
// eliminated, because calls have side effects.
func TestANFECOptimizer_SideEffectCallPreserved(t *testing.T) {
	// Build an ANF program with a call binding that nothing else references.
	// checkSig is a side-effecting call; the result is unused but it must survive.
	bindings := []ir.ANFBinding{
		loadConstHex("t0", strings.Repeat("ab", 33)), // sig (33 bytes)
		loadConstHex("t1", strings.Repeat("cd", 33)), // pubKey (33 bytes)
		callBinding("t2", "checkSig", []string{"t0", "t1"}),
		// Nothing references t2 — but it's a call so it should be preserved.
		// We still need a terminal assert; use t0 directly as a stand-in.
		assertBinding("t3", "t0"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	// t2 (the checkSig call) must still be present
	t2 := findBinding(body, "t2")
	if t2 == nil {
		t.Error("expected call binding t2 (checkSig) to be preserved as a side-effecting call, but it was eliminated")
	}
}

// ---------------------------------------------------------------------------
// Chained rules: Rule 12 (ecMul(G,k) -> ecMulGen(k)) then Rule 5 (ecMulGen(0) -> INFINITY)
// ---------------------------------------------------------------------------

// TestANFECOptimizer_ChainedRules_Rule12ThenRule5 verifies that:
// 1. ecMul(G, 0) is first rewritten to ecMulGen(0) by Rule 12
// 2. ecMulGen(0) is then rewritten to INFINITY by Rule 5
func TestANFECOptimizer_ChainedRules_Rule12ThenRule5(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstHex("t0", gHex),       // G
		loadConstBigInt("t1", 0),       // k = 0
		callBinding("t2", "ecMul", []string{"t0", "t1"}),
		assertBinding("t3", "t2"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	t2 := findBinding(body, "t2")
	if t2 == nil {
		t.Fatal("expected binding t2 to exist after optimization")
	}

	// After both rules fire, t2 should be INFINITY (a load_const with infinityHex)
	if t2.Value.Kind != "load_const" {
		t.Errorf("expected t2.Kind == load_const (INFINITY), got %q", t2.Value.Kind)
	}
	if t2.Value.ConstString == nil || *t2.Value.ConstString != infinityHex {
		got := "<nil>"
		if t2.Value.ConstString != nil {
			got = *t2.Value.ConstString
		}
		t.Errorf("expected t2 to be INFINITY after Rule12+Rule5 chain, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen(k1+k2)
// NOTE: Rule 10 is not implemented in the Go optimizer (it returns false
// after reverting the transformation). This test documents expected behavior.
// Source bug: compilers/go/frontend/anf_optimize.go Rule 10 explicitly skips.
// ---------------------------------------------------------------------------

func TestANFECOptimizer_Rule10_EcAddMulGenMulGen(t *testing.T) {
	// Build ANF with:
	//   k1 = load_const 3
	//   k2 = load_const 5
	//   t2 = ecMulGen(k1)
	//   t3 = ecMulGen(k2)
	//   t4 = ecAdd(t2, t3)       <- should become ecMulGen(k1+k2) = ecMulGen(8)
	//   assert(t4)
	k1 := loadConstBigInt("k1", 3)
	k2 := loadConstBigInt("k2", 5)
	t2 := callBinding("t2", "ecMulGen", []string{"k1"})
	t3 := callBinding("t3", "ecMulGen", []string{"k2"})
	t4 := callBinding("t4", "ecAdd", []string{"t2", "t3"})
	t5 := assertBinding("t5", "t4")

	bindings := []ir.ANFBinding{k1, k2, t2, t3, t4, t5}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	t4Result := findBinding(body, "t4")
	if t4Result == nil {
		t.Fatal("expected binding t4 to exist after optimization")
	}

	// After Rule 10, t4 should be ecMulGen with k1+k2 = 8
	// Since Rule 10 is NOT implemented, this will still be ecAdd.
	// If it becomes ecMulGen, the rule was implemented and the test passes.
	if t4Result.Value.Kind == "call" && t4Result.Value.Func == "ecMulGen" {
		// Rule 10 fired — verify the result makes sense
		t.Logf("Rule 10 fired: t4 is now ecMulGen with args %v", t4Result.Value.Args)
	} else if t4Result.Value.Kind == "call" && t4Result.Value.Func == "ecAdd" {
		// Rule 10 was NOT implemented — fail with a descriptive message
		t.Errorf("Rule 10 not implemented: ecAdd(ecMulGen(k1), ecMulGen(k2)) was NOT rewritten to ecMulGen(k1+k2); t4 is still %s(%s)", t4Result.Value.Func, strings.Join(t4Result.Value.Args, ", "))
	} else {
		t.Errorf("unexpected t4 after optimization: kind=%s func=%s", t4Result.Value.Kind, t4Result.Value.Func)
	}
}

// TestANFECOptimizer_MultipleMethodsAllOptimized verifies that each method
// in a multi-method program is optimized independently.
func TestANFECOptimizer_MultipleMethodsAllOptimized(t *testing.T) {
	program := &ir.ANFProgram{
		ContractName: "Test",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{
				Name:   "method1",
				Params: []ir.ANFParam{},
				Body: []ir.ANFBinding{
					loadConstBigInt("t0", 0),
					callBinding("t1", "ecMulGen", []string{"t0"}),
					assertBinding("t2", "t1"),
				},
				IsPublic: true,
			},
			{
				Name:   "method2",
				Params: []ir.ANFParam{},
				Body: []ir.ANFBinding{
					loadConstBigInt("t0", 1),
					callBinding("t1", "ecMulGen", []string{"t0"}),
					assertBinding("t2", "t1"),
				},
				IsPublic: true,
			},
		},
	}

	result := OptimizeEC(program)

	if len(result.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(result.Methods))
	}

	// method1: ecMulGen(0) -> INFINITY
	body1 := result.Methods[0].Body
	t1m1 := findBinding(body1, "t1")
	if t1m1 == nil {
		t.Fatal("expected binding t1 in method1")
	}
	if t1m1.Value.Kind != "load_const" {
		t.Errorf("method1 t1: expected load_const, got %q", t1m1.Value.Kind)
	}
	if t1m1.Value.ConstString == nil || *t1m1.Value.ConstString != infinityHex {
		t.Errorf("method1 t1: expected INFINITY")
	}

	// method2: ecMulGen(1) -> G
	body2 := result.Methods[1].Body
	t1m2 := findBinding(body2, "t1")
	if t1m2 == nil {
		t.Fatal("expected binding t1 in method2")
	}
	if t1m2.Value.Kind != "load_const" {
		t.Errorf("method2 t1: expected load_const, got %q", t1m2.Value.Kind)
	}
	if t1m2.Value.ConstString == nil || *t1m2.Value.ConstString != gHex {
		t.Errorf("method2 t1: expected G")
	}
}
