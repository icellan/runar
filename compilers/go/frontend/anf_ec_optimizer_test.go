package frontend

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
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
	if t4Result.Value.Kind != "call" || t4Result.Value.Func != "ecMulGen" {
		t.Errorf("expected t4 to be ecMulGen after Rule 10, got %s(%s)", t4Result.Value.Func, strings.Join(t4Result.Value.Args, ", "))
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

// ---------------------------------------------------------------------------
// JSON-driven engine: rule-set parity, canonical file, and hot-reload tests
// ---------------------------------------------------------------------------

// TestECOptimizer_EmbeddedJSONMatchesCanonical verifies that the Go compiler's
// embedded copy of ec-rules.json is byte-identical to the canonical file at
// the project root (optimizer/ec-rules.json). This is what lets both
// compilers share a single source of truth — the copy exists only because
// go:embed can't reach above its source file's directory.
func TestECOptimizer_EmbeddedJSONMatchesCanonical(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile = <repo>/compilers/go/frontend/anf_ec_optimizer_test.go
	// canonical = <repo>/optimizer/ec-rules.json
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))))
	canonicalPath := filepath.Join(repoRoot, "optimizer", "ec-rules.json")
	canonical, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatalf("read canonical %s: %v", canonicalPath, err)
	}
	if string(canonical) != string(embeddedECRulesJSON) {
		t.Errorf("embedded ec-rules.json differs from %s — run: cp optimizer/ec-rules.json compilers/go/frontend/ec-rules.json", canonicalPath)
	}
}

// TestECOptimizer_AllJSONRulesTakeEffect exercises every rule tagged for Go
// (or untagged) by constructing a matching ANF program and asserting the
// rule fired. Guards against the "implemented in code but never called"
// regression where a rule name in JSON has no effect.
func TestECOptimizer_AllJSONRulesTakeEffect(t *testing.T) {
	// For each rule name, a program + post-optimization assertion.
	cases := map[string]struct {
		bindings []ir.ANFBinding
		target   string // binding expected to be rewritten
		assert   func(t *testing.T, b *ir.ANFBinding)
	}{
		"ec-add-identity-right": {
			bindings: []ir.ANFBinding{
				loadConstHex("t0", strings.Repeat("ab", 64)),
				loadConstHex("t1", infinityHex),
				callBinding("t2", "ecAdd", []string{"t0", "t1"}),
				assertBinding("t3", "t2"),
			},
			target: "t2",
			assert: func(t *testing.T, b *ir.ANFBinding) {
				if b.Value.Kind != "load_const" || b.Value.ConstString == nil || *b.Value.ConstString != "@ref:t0" {
					t.Errorf("ec-add-identity-right: expected alias @ref:t0, got %+v", b.Value)
				}
			},
		},
		"ec-add-identity-left": {
			bindings: []ir.ANFBinding{
				loadConstHex("t0", infinityHex),
				loadConstHex("t1", strings.Repeat("cd", 64)),
				callBinding("t2", "ecAdd", []string{"t0", "t1"}),
				assertBinding("t3", "t2"),
			},
			target: "t2",
			assert: func(t *testing.T, b *ir.ANFBinding) {
				if b.Value.Kind != "load_const" || b.Value.ConstString == nil || *b.Value.ConstString != "@ref:t1" {
					t.Errorf("ec-add-identity-left: expected alias @ref:t1, got %+v", b.Value)
				}
			},
		},
		"ec-mul-one": {
			bindings: []ir.ANFBinding{
				loadConstHex("t0", strings.Repeat("ab", 64)),
				loadConstBigInt("t1", 1),
				callBinding("t2", "ecMul", []string{"t0", "t1"}),
				assertBinding("t3", "t2"),
			},
			target: "t2",
			assert: func(t *testing.T, b *ir.ANFBinding) {
				if b.Value.Kind != "load_const" || b.Value.ConstString == nil || *b.Value.ConstString != "@ref:t0" {
					t.Errorf("ec-mul-one: expected alias @ref:t0")
				}
			},
		},
		"ec-mul-zero": {
			bindings: []ir.ANFBinding{
				loadConstHex("t0", strings.Repeat("ab", 64)),
				loadConstBigInt("t1", 0),
				callBinding("t2", "ecMul", []string{"t0", "t1"}),
				assertBinding("t3", "t2"),
			},
			target: "t2",
			assert: func(t *testing.T, b *ir.ANFBinding) {
				if b.Value.ConstString == nil || *b.Value.ConstString != infinityHex {
					t.Errorf("ec-mul-zero: expected INFINITY")
				}
			},
		},
		"ec-mulgen-zero": {
			bindings: []ir.ANFBinding{
				loadConstBigInt("t0", 0),
				callBinding("t1", "ecMulGen", []string{"t0"}),
				assertBinding("t2", "t1"),
			},
			target: "t1",
			assert: func(t *testing.T, b *ir.ANFBinding) {
				if b.Value.ConstString == nil || *b.Value.ConstString != infinityHex {
					t.Errorf("ec-mulgen-zero: expected INFINITY")
				}
			},
		},
		"ec-mulgen-one": {
			bindings: []ir.ANFBinding{
				loadConstBigInt("t0", 1),
				callBinding("t1", "ecMulGen", []string{"t0"}),
				assertBinding("t2", "t1"),
			},
			target: "t1",
			assert: func(t *testing.T, b *ir.ANFBinding) {
				if b.Value.ConstString == nil || *b.Value.ConstString != gHex {
					t.Errorf("ec-mulgen-one: expected G")
				}
			},
		},
		"ec-negate-negate": {
			bindings: []ir.ANFBinding{
				loadConstHex("t0", strings.Repeat("ab", 64)),
				callBinding("t1", "ecNegate", []string{"t0"}),
				callBinding("t2", "ecNegate", []string{"t1"}),
				assertBinding("t3", "t2"),
			},
			target: "t2",
			assert: func(t *testing.T, b *ir.ANFBinding) {
				if b.Value.ConstString == nil || *b.Value.ConstString != "@ref:t0" {
					t.Errorf("ec-negate-negate: expected alias @ref:t0")
				}
			},
		},
		"ec-add-negate-cancel": {
			bindings: []ir.ANFBinding{
				loadConstHex("t0", strings.Repeat("ab", 64)),
				callBinding("t1", "ecNegate", []string{"t0"}),
				callBinding("t2", "ecAdd", []string{"t0", "t1"}),
				assertBinding("t3", "t2"),
			},
			target: "t2",
			assert: func(t *testing.T, b *ir.ANFBinding) {
				if b.Value.ConstString == nil || *b.Value.ConstString != infinityHex {
					t.Errorf("ec-add-negate-cancel: expected INFINITY")
				}
			},
		},
		"ec-add-negate-cancel-reversed": {
			bindings: []ir.ANFBinding{
				loadConstHex("t0", strings.Repeat("ab", 64)),
				callBinding("t1", "ecNegate", []string{"t0"}),
				callBinding("t2", "ecAdd", []string{"t1", "t0"}),
				assertBinding("t3", "t2"),
			},
			target: "t2",
			assert: func(t *testing.T, b *ir.ANFBinding) {
				if b.Value.ConstString == nil || *b.Value.ConstString != infinityHex {
					t.Errorf("ec-add-negate-cancel-reversed: expected INFINITY")
				}
			},
		},
		"ec-mulgen-linear": {
			bindings: []ir.ANFBinding{
				loadConstBigInt("k1", 3),
				loadConstBigInt("k2", 5),
				callBinding("t2", "ecMulGen", []string{"k1"}),
				callBinding("t3", "ecMulGen", []string{"k2"}),
				callBinding("t4", "ecAdd", []string{"t2", "t3"}),
				assertBinding("t5", "t4"),
			},
			target: "t4",
			assert: func(t *testing.T, b *ir.ANFBinding) {
				if b.Value.Kind != "call" || b.Value.Func != "ecMulGen" {
					t.Errorf("ec-mulgen-linear: expected call ecMulGen, got kind=%s func=%s", b.Value.Kind, b.Value.Func)
				}
			},
		},
		"ec-mul-generator-specialize": {
			bindings: []ir.ANFBinding{
				loadConstHex("t0", gHex),
				loadConstBigInt("t1", 42),
				callBinding("t2", "ecMul", []string{"t0", "t1"}),
				assertBinding("t3", "t2"),
			},
			target: "t2",
			assert: func(t *testing.T, b *ir.ANFBinding) {
				if b.Value.Kind != "call" || b.Value.Func != "ecMulGen" {
					t.Errorf("ec-mul-generator-specialize: expected call ecMulGen, got kind=%s func=%s", b.Value.Kind, b.Value.Func)
				}
			},
		},
	}

	// Check that our cases cover every rule currently active for Go.
	// Any JSON rule tagged for Go (or untagged) that doesn't appear here is
	// a coverage gap — fail so we remember to add a case.
	active := ECRuleNames()
	covered := make(map[string]bool, len(cases))
	for k := range cases {
		covered[k] = true
	}
	for _, name := range active {
		if !covered[name] {
			t.Errorf("rule %q is active in Go but has no coverage case in this test", name)
		}
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			program := makeTestProgram(tc.bindings)
			result := OptimizeEC(program)
			body := getMethodBody(result)
			b := findBinding(body, tc.target)
			if b == nil {
				t.Fatalf("rule %q: target binding %q missing after optimization", name, tc.target)
			}
			tc.assert(t, b)
		})
	}
}

// TestECOptimizer_NewJSONRulePickedUp verifies that adding a rule to the
// JSON rule set (via the testing hook) makes it take effect without any Go
// code change. This is the acceptance criterion for GO-5: rules are data,
// not code.
func TestECOptimizer_NewJSONRulePickedUp(t *testing.T) {
	// A fake rule: ecOnCurve($x) -> $x. This rule is nonsense semantically,
	// but the EC optimizer doesn't care — it just pattern-matches. It's
	// useful as a pure-data test: ecOnCurve is a real EC builtin that the
	// baseline Go optimizer does NOT rewrite, so any observed rewrite must
	// have come from the JSON we injected.
	testJSON := []byte(`[
		{
			"name": "test-on-curve-alias",
			"match": { "func": "ecOnCurve", "args": ["$x"] },
			"replace": "$x"
		}
	]`)

	prev, err := SetECRulesForTesting(testJSON)
	if err != nil {
		t.Fatalf("SetECRulesForTesting: %v", err)
	}
	defer RestoreECRulesForTesting(prev)

	bindings := []ir.ANFBinding{
		loadConstHex("t0", strings.Repeat("ab", 64)),
		callBinding("t1", "ecOnCurve", []string{"t0"}),
		assertBinding("t2", "t1"),
	}
	program := makeTestProgram(bindings)
	result := OptimizeEC(program)
	body := getMethodBody(result)

	t1 := findBinding(body, "t1")
	if t1 == nil {
		t.Fatal("t1 missing after optimization")
	}
	if t1.Value.Kind != "load_const" || t1.Value.ConstString == nil || *t1.Value.ConstString != "@ref:t0" {
		t.Errorf("expected t1 rewritten to alias @ref:t0 by injected JSON rule, got %+v", t1.Value)
	}

	// Also verify the baseline (without the injection) does NOT rewrite:
	// put the ecOnCurve rule on the shelf and re-run with the normal rules.
	RestoreECRulesForTesting(prev)
	program2 := makeTestProgram([]ir.ANFBinding{
		loadConstHex("t0", strings.Repeat("ab", 64)),
		callBinding("t1", "ecOnCurve", []string{"t0"}),
		assertBinding("t2", "t1"),
	})
	result2 := OptimizeEC(program2)
	t1b := findBinding(getMethodBody(result2), "t1")
	if t1b == nil {
		t.Fatal("baseline t1 missing")
	}
	if t1b.Value.Kind != "call" || t1b.Value.Func != "ecOnCurve" {
		t.Errorf("baseline (no injected rule): expected ecOnCurve call to remain, got %+v", t1b.Value)
	}

	// Re-apply the injection for the deferred restore to be a no-op paired
	// correctly. (The defer above will restore to prev, which is what we
	// want.)
	if _, err := SetECRulesForTesting(testJSON); err != nil {
		t.Fatalf("re-inject for cleanup: %v", err)
	}
}

// TestECOptimizer_RulesSupportedFieldRespected verifies that rules tagged
// supported: ["ts"] are skipped by the Go engine. We rely on the two rules
// in ec-rules.json (ec-mul-associative, ec-mul-distributive) being so
// tagged; if someone removes the tag (implementing them in Go), this test
// will point out that the coverage case in TestECOptimizer_AllJSONRulesTakeEffect
// must be updated.
func TestECOptimizer_RulesSupportedFieldRespected(t *testing.T) {
	active := ECRuleNames()
	activeSet := make(map[string]bool, len(active))
	for _, n := range active {
		activeSet[n] = true
	}
	for _, unsupported := range []string{"ec-mul-associative", "ec-mul-distributive"} {
		if activeSet[unsupported] {
			t.Errorf("rule %q is tagged supported:[ts] in ec-rules.json but is active for Go — update the coverage case in TestECOptimizer_AllJSONRulesTakeEffect and remove this guard", unsupported)
		}
	}
}
