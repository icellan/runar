package frontend

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// ec-mul-associative (rule 9) and ec-mul-distributive (rule 11)
// ---------------------------------------------------------------------------
//
// Both rules carried `"supported": ["ts"]` in ec-rules.json long after TS
// stopped being the only tier that implemented them: Rust
// (frontend/anf_optimize.rs "Rule 9"/"Rule 11"), Python
// (frontend/anf_optimize.py), Ruby (frontend/anf_optimize.rb) and Java
// (passes/AnfOptimize.java) all ship the same two rewrites. The Go engine is
// the only tier that reads the tag, so it was the only tier declining them —
// a live 5-vs-1 hex divergence on any nested `ecMul(ecMul(p, k1), k2)` with
// constant scalars, which conformance invariant 2 forbids.
//
// The precondition these tests pin is the one commit 411d1985 (R-031)
// established for the sibling rule ec-mulgen-linear: a scalar-fusing rewrite
// is only in step with the hand-written tiers when BOTH scalars are
// compile-time constants, because only then can the compiler perform the
// mod-n reduction itself. Runtime scalars must be left alone.

// helperConst returns the load_const big.Int bound to name, or nil.
func helperConst(body []ir.ANFBinding, name string) *big.Int {
	b := findBinding(body, name)
	if b == nil || b.Value.Kind != "load_const" {
		return nil
	}
	return b.Value.ConstBigInt
}

// TestECOptimizer_MulAssociativeFiresForConstScalars pins the Go tier onto the
// five-tier majority for
//
//	ecMul(ecMul(p, 3), 5)  ->  ecMul(p, 15)
//
// Measured before the fix on `assert(ecOnCurve(ecMul(ecMul(ecMulGen(9n), 3n), 5n)))`:
// ts/rust/python/ruby/java all emitted 2548596 hex chars (sha256[:16]
// af73ba6aee64ebe4) while Go emitted 2548594 (e9afef173dcb8b94), the two
// scripts first differing at byte 424567 — inside the second scalar ladder,
// where Go still walks the bits of 5 over the result of the first ladder
// instead of the bits of the fused 15.
func TestECOptimizer_MulAssociativeFiresForConstScalars(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstBigInt("t0", 9),
		callBinding("t1", "ecMulGen", []string{"t0"}),
		loadConstBigInt("t2", 3),
		callBinding("t3", "ecMul", []string{"t1", "t2"}),
		loadConstBigInt("t4", 5),
		callBinding("t5", "ecMul", []string{"t3", "t4"}),
		assertBinding("t6", "t5"),
	}
	body := getMethodBody(OptimizeEC(makeTestProgram(bindings)))

	t5 := findBinding(body, "t5")
	if t5 == nil {
		t.Fatal("binding t5 missing after optimization")
	}
	if t5.Value.Kind != "call" || t5.Value.Func != "ecMul" || len(t5.Value.Args) != 2 {
		t.Fatalf("expected t5 to stay a 2-arg ecMul, got %+v", t5.Value)
	}
	// The point operand must be hoisted past the inner ecMul, exactly as the
	// other five tiers do (they return `ecMul(inner_point, <fused scalar>)`).
	if t5.Value.Args[0] != "t1" {
		t.Errorf("expected the inner point t1 to become t5's point operand, got %q", t5.Value.Args[0])
	}
	got := helperConst(body, t5.Value.Args[1])
	if got == nil {
		t.Fatalf("expected t5's scalar operand %q to be a folded load_const bigint", t5.Value.Args[1])
	}
	if got.Cmp(big.NewInt(15)) != 0 {
		t.Errorf("expected the fused scalar to be 3*5 = 15 (mod n), got %s", got)
	}
}

// TestECOptimizer_MulAssociativeFoldsModN pins the mod-n half of the fold: the
// five hand-written tiers reduce k1*k2 modulo the curve order at rewrite time
// (`(k1 * k2) % CURVE_N` in TS/Python/Ruby, `reduce_mod_n` in Rust). A Go
// engine that emitted the raw product would agree on small scalars and
// diverge on real secp256k1 ones.
func TestECOptimizer_MulAssociativeFoldsModN(t *testing.T) {
	// (n-1) * 2 = 2n-2 ≡ n-2 (mod n)
	nMinus1 := new(big.Int).Sub(curveN, big.NewInt(1))
	raw, _ := json.Marshal(nMinus1.String() + "n")
	bindings := []ir.ANFBinding{
		loadConstBigInt("t0", 9),
		callBinding("t1", "ecMulGen", []string{"t0"}),
		{Name: "t2", Value: ir.ANFValue{Kind: "load_const", RawValue: raw, ConstBigInt: nMinus1}},
		callBinding("t3", "ecMul", []string{"t1", "t2"}),
		loadConstBigInt("t4", 2),
		callBinding("t5", "ecMul", []string{"t3", "t4"}),
		assertBinding("t6", "t5"),
	}
	body := getMethodBody(OptimizeEC(makeTestProgram(bindings)))

	t5 := findBinding(body, "t5")
	if t5 == nil || t5.Value.Kind != "call" || len(t5.Value.Args) != 2 {
		t.Fatalf("expected t5 to be a rewritten 2-arg ecMul, got %+v", t5)
	}
	got := helperConst(body, t5.Value.Args[1])
	if got == nil {
		t.Fatalf("expected t5's scalar operand %q to be a folded load_const bigint", t5.Value.Args[1])
	}
	want := new(big.Int).Sub(curveN, big.NewInt(2))
	if got.Cmp(want) != 0 {
		t.Errorf("expected (n-1)*2 to fold to n-2 = %s, got %s", want, got)
	}
}

// TestECOptimizer_MulAssociativeSkipsRuntimeScalars is the R-031 soundness
// shape for rule 9: an unlock-argument scalar is attacker-chosen and cannot be
// reduced mod n at compile time, so no tier fuses it. Go must decline too, or
// it re-introduces exactly the CL-BUG-017 divergence R-031 closed for
// ec-mulgen-linear.
func TestECOptimizer_MulAssociativeSkipsRuntimeScalars(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstBigInt("t0", 9),
		callBinding("t1", "ecMulGen", []string{"t0"}),
		loadParamBinding("t2", "k1Arg"), // runtime scalar
		callBinding("t3", "ecMul", []string{"t1", "t2"}),
		loadConstBigInt("t4", 5),
		callBinding("t5", "ecMul", []string{"t3", "t4"}),
		assertBinding("t6", "t5"),
	}
	body := getMethodBody(OptimizeEC(makeTestProgram(bindings)))

	t5 := findBinding(body, "t5")
	if t5 == nil {
		t.Fatal("binding t5 missing after optimization")
	}
	if t5.Value.Kind != "call" || t5.Value.Func != "ecMul" {
		t.Fatalf("expected t5 to stay an ecMul, got %+v", t5.Value)
	}
	if len(t5.Value.Args) != 2 || t5.Value.Args[0] != "t3" || t5.Value.Args[1] != "t4" {
		t.Errorf("expected t5 to keep its original operands (t3, t4), got %v", t5.Value.Args)
	}
	// The inner multiplication must survive: two ecMul in, two ecMul out.
	muls := 0
	for _, b := range body {
		if b.Value.Kind == "call" && b.Value.Func == "ecMul" {
			muls++
		}
	}
	if muls != 2 {
		t.Errorf("expected both ecMul calls to survive, got %d", muls)
	}
	// And no synthesized runtime scalar arithmetic may be left behind.
	for _, b := range body {
		if b.Value.Kind == "bin_op" {
			t.Errorf("unexpected synthesized bin_op helper %q — the rule must not fire on runtime scalars", b.Name)
		}
	}
}

// TestECOptimizer_MulDistributiveFiresOnSharedPoint pins rule 11 against the
// five hand-written tiers:
//
//	ecAdd(ecMul(p, 3), ecMul(p, 5))  ->  ecMul(p, 8)
//
// This is also the test that catches the operand transposition in
// ec-rules.json. `ecMul` is `ecMul(point, scalar)`
// (packages/runar-lang/src/builtins.ts:510), but the rule was written
// `ecMul($k1, $p)` / `ecMul($k2, $p)` — binding the POINT to the scalar
// pattern variable and unifying `$p` on the SCALAR. Under that spelling this
// program does not match at all (the two scalar bindings t2 and t4 differ, so
// `$p` fails to unify), so the rewrite never happens.
func TestECOptimizer_MulDistributiveFiresOnSharedPoint(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadParamBinding("t0", "pointArg"),
		loadConstBigInt("t1", 3),
		callBinding("t2", "ecMul", []string{"t0", "t1"}),
		loadConstBigInt("t3", 5),
		callBinding("t4", "ecMul", []string{"t0", "t3"}),
		callBinding("t5", "ecAdd", []string{"t2", "t4"}),
		assertBinding("t6", "t5"),
	}
	body := getMethodBody(OptimizeEC(makeTestProgram(bindings)))

	t5 := findBinding(body, "t5")
	if t5 == nil {
		t.Fatal("binding t5 missing after optimization")
	}
	if t5.Value.Kind != "call" || t5.Value.Func != "ecMul" || len(t5.Value.Args) != 2 {
		t.Fatalf("expected t5 to become a 2-arg ecMul, got %+v", t5.Value)
	}
	if t5.Value.Args[0] != "t0" {
		t.Errorf("expected the shared point t0 to stay in the POINT slot, got %q", t5.Value.Args[0])
	}
	got := helperConst(body, t5.Value.Args[1])
	if got == nil {
		t.Fatalf("expected t5's scalar operand %q to be a folded load_const bigint", t5.Value.Args[1])
	}
	if got.Cmp(big.NewInt(8)) != 0 {
		t.Errorf("expected the fused scalar to be 3+5 = 8 (mod n), got %s", got)
	}
}

// TestECOptimizer_MulDistributiveRequiresTheSamePoint is the negative half of
// the transposition fix. Two DIFFERENT points multiplied by the SAME scalar
// binding is the shape the transposed spelling matched: `$p` unified on the
// shared scalar and `$k1`/`$k2` bound the two points, so the replace template
// summed two POINTS into the scalar slot. The point operands are spelled as
// load_const bigints here precisely so that `opOperandsAreConst` cannot mask
// the bug — under the transposed spelling this program rewrites to
// `ecMul(<p1+p2>, k)`, which is not a valid EC computation in any tier.
//
// ecAdd(k*P, k*Q) has no scalar-fusing form, so the correct behaviour is to
// leave the ecAdd alone.
func TestECOptimizer_MulDistributiveRequiresTheSamePoint(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadConstBigInt("p1", 11),
		loadConstBigInt("p2", 13),
		loadConstBigInt("k", 7),
		callBinding("t0", "ecMul", []string{"p1", "k"}),
		callBinding("t1", "ecMul", []string{"p2", "k"}),
		callBinding("t2", "ecAdd", []string{"t0", "t1"}),
		assertBinding("t3", "t2"),
	}
	body := getMethodBody(OptimizeEC(makeTestProgram(bindings)))

	t2 := findBinding(body, "t2")
	if t2 == nil {
		t.Fatal("binding t2 missing after optimization")
	}
	if t2.Value.Kind != "call" || t2.Value.Func != "ecAdd" {
		t.Fatalf("expected t2 to stay an ecAdd over two distinct points, got %+v", t2.Value)
	}
	if len(t2.Value.Args) != 2 || t2.Value.Args[0] != "t0" || t2.Value.Args[1] != "t1" {
		t.Errorf("expected t2 to keep its original operands (t0, t1), got %v", t2.Value.Args)
	}
}

// TestECOptimizer_MulDistributiveSkipsRuntimeScalars is the R-031 precondition
// for rule 11: the shared point is fine, but a runtime scalar cannot be
// reduced mod n at compile time, so the rule must decline.
func TestECOptimizer_MulDistributiveSkipsRuntimeScalars(t *testing.T) {
	bindings := []ir.ANFBinding{
		loadParamBinding("t0", "pointArg"),
		loadParamBinding("t1", "k1Arg"), // runtime scalar
		callBinding("t2", "ecMul", []string{"t0", "t1"}),
		loadConstBigInt("t3", 5),
		callBinding("t4", "ecMul", []string{"t0", "t3"}),
		callBinding("t5", "ecAdd", []string{"t2", "t4"}),
		assertBinding("t6", "t5"),
	}
	body := getMethodBody(OptimizeEC(makeTestProgram(bindings)))

	t5 := findBinding(body, "t5")
	if t5 == nil {
		t.Fatal("binding t5 missing after optimization")
	}
	if t5.Value.Kind != "call" || t5.Value.Func != "ecAdd" {
		t.Fatalf("expected t5 to stay an ecAdd for a runtime scalar, got %+v", t5.Value)
	}
	for _, b := range body {
		if b.Value.Kind == "bin_op" {
			t.Errorf("unexpected synthesized bin_op helper %q — the rule must not fire on runtime scalars", b.Name)
		}
	}
}
