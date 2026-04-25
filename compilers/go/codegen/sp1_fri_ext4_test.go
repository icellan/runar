package codegen

import (
	"fmt"
	"testing"

	sp1fri "github.com/icellan/runar/packages/runar-go/sp1fri"
)

// pushExt4Named pushes the four canonical coefficients of an Ext4 onto the
// stack, naming each as `<prefix>_<i>`.
func pushExt4Named(tracker *KBTracker, prefix string, e sp1fri.Ext4) {
	for i := 0; i < 4; i++ {
		tracker.pushInt(fmt.Sprintf("%s_%d", prefix, i), int64(e[i]))
	}
}

// assertExt4EqualsRef brings each component of `slotPrefix_i` to the top,
// pushes the reference value, and OP_NUMEQUALVERIFYs.
func assertExt4EqualsRef(t *testing.T, tracker *KBTracker, ops *[]StackOp, slotPrefix string, ref sp1fri.Ext4) {
	t.Helper()
	for i := 3; i >= 0; i-- {
		name := fmt.Sprintf("%s_%d", slotPrefix, i)
		tracker.toTop(name)
		*ops = append(*ops, pushInt64(int64(ref[i])))
		*ops = append(*ops, opcode("OP_NUMEQUALVERIFY"))
		tracker.rawBlock([]string{name}, "", func(e func(StackOp)) {})
	}
}

// drainAllStack drops every remaining tracked slot and closes with OP_1.
func drainAllStack(tracker *KBTracker, ops *[]StackOp) {
	for len(tracker.nm) > 0 {
		*ops = append(*ops, opcode("OP_DROP"))
		tracker.nm = tracker.nm[:len(tracker.nm)-1]
	}
	*ops = append(*ops, opcode("OP_1"))
}

func TestKbExt4Add_MatchesReference(t *testing.T) {
	a := sp1fri.Ext4{1, 2, 3, 4}
	b := sp1fri.Ext4{10, 20, 30, 40}
	want := sp1fri.Ext4Add(a, b)

	var ops []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
	pushExt4Named(tracker, "a", a)
	pushExt4Named(tracker, "b", b)

	kbExt4Add(tracker, "a", "b", "c")
	assertExt4EqualsRef(t, tracker, &ops, "c", want)
	drainAllStack(tracker, &ops)

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("ext4 add: %v (want=%v)", err, want)
	}
}

func TestKbExt4Sub_MatchesReference(t *testing.T) {
	a := sp1fri.Ext4{100, 50, 200, 7}
	b := sp1fri.Ext4{10, 99, 50, 9}
	want := sp1fri.Ext4Sub(a, b)

	var ops []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
	pushExt4Named(tracker, "a", a)
	pushExt4Named(tracker, "b", b)

	kbExt4Sub(tracker, "a", "b", "c")
	assertExt4EqualsRef(t, tracker, &ops, "c", want)
	drainAllStack(tracker, &ops)

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("ext4 sub: %v (want=%v)", err, want)
	}
}

func TestKbExt4Mul_MatchesReference(t *testing.T) {
	a := sp1fri.Ext4{1, 2, 3, 4}
	b := sp1fri.Ext4{5, 6, 7, 8}
	want := sp1fri.Ext4Mul(a, b)

	var ops []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
	pushExt4Named(tracker, "a", a)
	pushExt4Named(tracker, "b", b)

	kbExt4Mul(tracker, "a", "b", "c")
	assertExt4EqualsRef(t, tracker, &ops, "c", want)
	drainAllStack(tracker, &ops)

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("ext4 mul: %v (want=%v)", err, want)
	}
}

func TestKbExt4Inv_MatchesReference(t *testing.T) {
	a := sp1fri.Ext4{7, 11, 13, 17}
	want := sp1fri.Ext4Inv(a)

	var ops []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
	pushExt4Named(tracker, "a", a)

	kbExt4Inv(tracker, "a", "c")
	assertExt4EqualsRef(t, tracker, &ops, "c", want)
	drainAllStack(tracker, &ops)

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("ext4 inv: %v (want=%v)", err, want)
	}
}

func TestKbExt4ScalarMul_MatchesReference(t *testing.T) {
	a := sp1fri.Ext4{17, 23, 29, 31}
	s := uint32(42)
	want := sp1fri.Ext4ScalarMul(a, s)

	var ops []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
	pushExt4Named(tracker, "a", a)
	tracker.pushInt("s", int64(s))

	kbExt4ScalarMul(tracker, "a", "s", "c")
	assertExt4EqualsRef(t, tracker, &ops, "c", want)
	drainAllStack(tracker, &ops)

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("ext4 scalar mul: %v (want=%v)", err, want)
	}
}

// referenceColinearityFold computes the arity=2 colinearity fold on canonical
// Ext4 inputs. Mirrors the simplification of `foldRow` +
// `lagrangeInterpolateAt` for arity=2 (sp1fri/fri.go:344, 377). The two
// xs are [s, -s], so the lagrange interpolation reduces to:
//
//	folded = (e_low + e_high) / 2 + beta * (e_low - e_high) / (2*s)
func referenceColinearityFold(eLow, eHigh, beta sp1fri.Ext4, s uint32) sp1fri.Ext4 {
	// Build evals = [e_low, e_high]
	evals := []sp1fri.Ext4{eLow, eHigh}
	// xs = [s, -s] (since g_1 = -1 in any field)
	xs := []uint32{s, sp1fri.KbSub(0, s)}
	// foldRow does reverse_slice_index_bits(xs) which for n=2 is identity.
	return sp1fri_lagrange(xs, evals, beta)
}

// sp1fri_lagrange wraps the unexported lagrangeInterpolateAt by re-deriving
// the same algebra. We re-implement here because the function is unexported.
func sp1fri_lagrange(xs []uint32, ys []sp1fri.Ext4, z sp1fri.Ext4) sp1fri.Ext4 {
	n := len(xs)
	for i, x := range xs {
		if sp1fri.Ext4Equal(z, sp1fri.Ext4FromBase(x)) {
			return ys[i]
		}
	}
	logN := 0
	for (1 << logN) < n {
		logN++
	}
	cosetPower := sp1fri.KbPow(xs[0], uint64(1)<<uint(logN))
	weightScaleBase := sp1fri.KbInv(sp1fri.KbMul(sp1fri.KbFromU64(uint64(n)), cosetPower))
	diffs := make([]sp1fri.Ext4, n)
	for i, x := range xs {
		diffs[i] = sp1fri.Ext4Sub(z, sp1fri.Ext4FromBase(x))
	}
	diffInvs := make([]sp1fri.Ext4, n)
	for i, d := range diffs {
		diffInvs[i] = sp1fri.Ext4Inv(d)
	}
	lZ := sp1fri.Ext4One()
	for _, d := range diffs {
		lZ = sp1fri.Ext4Mul(lZ, d)
	}
	result := sp1fri.Ext4Zero()
	for i := range xs {
		w := sp1fri.KbMul(xs[i], weightScaleBase)
		term := sp1fri.Ext4Mul(sp1fri.Ext4ScalarMul(ys[i], w), diffInvs[i])
		result = sp1fri.Ext4Add(result, term)
	}
	return sp1fri.Ext4Mul(result, lZ)
}

// TestEmitFriColinearityFold_MatchesReference validates that the on-chain
// emission of one FRI fold step (arity=2) produces exactly the value the
// off-chain `lagrangeInterpolateAt`/`foldRow` reference produces for the
// same inputs. Mirrors `packages/runar-go/sp1fri/fri.go::foldRow`.
func TestEmitFriColinearityFold_MatchesReference(t *testing.T) {
	// Synthetic but representative inputs (canonical KoalaBear).
	eLow := sp1fri.Ext4{42, 17, 99, 1}
	eHigh := sp1fri.Ext4{77, 28, 5, 1234}
	beta := sp1fri.Ext4{555, 12345, 7, 88}
	s := sp1fri.KbPow(sp1fri.KbTwoAdicGenerator(5), 3) // arbitrary non-trivial s

	want := referenceColinearityFold(eLow, eHigh, beta, s)

	// Sanity: the formula derivation should match the reference.
	wantManual := func() sp1fri.Ext4 {
		sum := sp1fri.Ext4Add(eLow, eHigh)
		diff := sp1fri.Ext4Sub(eLow, eHigh)
		inv2 := uint32((sp1fri.KbPrime + 1) / 2)
		half := sp1fri.Ext4ScalarMul(sum, inv2)
		twoS := sp1fri.KbMul(s, 2)
		invTwoS := sp1fri.KbInv(twoS)
		dScaled := sp1fri.Ext4ScalarMul(diff, invTwoS)
		corr := sp1fri.Ext4Mul(beta, dScaled)
		return sp1fri.Ext4Add(half, corr)
	}()
	if !sp1fri.Ext4Equal(want, wantManual) {
		t.Fatalf("formula derivation disagrees with reference lagrangeInterpolateAt: "+
			"want=%v wantManual=%v", want, wantManual)
	}

	var ops []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
	pushExt4Named(tracker, "elo", eLow)
	pushExt4Named(tracker, "ehi", eHigh)
	pushExt4Named(tracker, "beta", beta)
	tracker.pushInt("s", int64(s))

	emitFriColinearityFold(tracker, "elo", "ehi", "beta", "s", "fold")

	assertExt4EqualsRef(t, tracker, &ops, "fold", want)
	drainAllStack(tracker, &ops)

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("on-chain colinearity fold disagrees with reference (want=%v): %v", want, err)
	}
	t.Logf("colinearity fold matches reference: e_low=%v e_high=%v beta=%v s=%d → folded=%v; |ops|=%d",
		eLow, eHigh, beta, s, want, len(ops))
}

// TestEmitMerkleVerify_AcceptsValidPath builds a synthetic Merkle path,
// computes the root off-chain via the validated sp1fri Poseidon2Compress,
// then verifies the on-chain emission accepts the same path.
//
// Mirrors the verifier-side step in `packages/runar-go/sp1fri/mmcs.go::VerifyBatch`
// for the simplest case: single matrix at the tallest height, one leaf,
// no injected mid-tree matrices.
func TestEmitMerkleVerify_AcceptsValidPath(t *testing.T) {
	const depth = 5
	// Synthetic 8-element leaf (canonical KB).
	leaf := [8]uint32{1, 2, 3, 4, 5, 6, 7, 8}
	// Synthetic siblings — one 8-element digest per depth.
	siblings := make([][8]uint32, depth)
	for i := 0; i < depth; i++ {
		for j := 0; j < 8; j++ {
			siblings[i][j] = uint32(100 + i*8 + j)
		}
	}
	// Choose an arbitrary index. The bits of `index` (LSB first) decide
	// sibling ordering at each depth: bit=0 → (current, sibling), bit=1 → (sibling, current).
	const index = uint64(0b10110)

	// Compute the expected root.
	current := leaf
	idx := index
	for i := 0; i < depth; i++ {
		bit := idx & 1
		var left, right [8]uint32
		if bit == 0 {
			left, right = current, siblings[i]
		} else {
			left, right = siblings[i], current
		}
		current = sp1fri.Poseidon2Compress(left, right)
		idx >>= 1
	}
	expectedRoot := current

	// Build the on-chain script.
	var ops []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })

	// Push expectedRoot (deepest), then leaf, then siblings, then index.
	for i := 0; i < 8; i++ {
		tracker.pushInt(fmt.Sprintf("er_%d", i), int64(expectedRoot[i]))
	}
	for i := 0; i < 8; i++ {
		tracker.pushInt(fmt.Sprintf("leaf_%d", i), int64(leaf[i]))
	}
	for s := 0; s < depth; s++ {
		for i := 0; i < 8; i++ {
			tracker.pushInt(fmt.Sprintf("sib_%d_%d", s, i), int64(siblings[s][i]))
		}
	}
	tracker.pushInt("index", int64(index))

	consume := []string{}
	for i := 0; i < 8; i++ {
		consume = append(consume, fmt.Sprintf("er_%d", i))
	}
	for i := 0; i < 8; i++ {
		consume = append(consume, fmt.Sprintf("leaf_%d", i))
	}
	for s := 0; s < depth; s++ {
		for i := 0; i < 8; i++ {
			consume = append(consume, fmt.Sprintf("sib_%d_%d", s, i))
		}
	}
	consume = append(consume, "index")

	emitMerkleVerify(tracker, depth, consume)

	drainAllStack(tracker, &ops)
	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("emitMerkleVerify rejected a valid path: %v", err)
	}
	t.Logf("emitMerkleVerify accepted depth=%d path; expectedRoot=%v |ops|=%d",
		depth, expectedRoot, len(ops))
}

// TestEmitFinalPolyEqualityCheck_FixesPreExistingBug validates the fix to
// the pre-existing emitFinalPolyEqualityCheck stub which used OP_EQUALVERIFY
// (byte-string equality) instead of OP_NUMEQUALVERIFY (numeric equality)
// for KB element comparison. Confirms equal Ext4 values pass and unequal
// ones fail.
func TestEmitFinalPolyEqualityCheck_FixesPreExistingBug(t *testing.T) {
	a := sp1fri.Ext4{42, 17, 99, 1234567}
	// Equal case: emission must accept.
	{
		var ops []StackOp
		tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
		pushExt4Named(tracker, "lhs", a)
		pushExt4Named(tracker, "rhs", a)
		emitFinalPolyEqualityCheck(tracker, "lhs", "rhs")
		drainAllStack(tracker, &ops)
		if err := buildAndExecute(t, ops); err != nil {
			t.Fatalf("emitFinalPolyEqualityCheck rejected equal Ext4 values: %v", err)
		}
	}
	// Unequal case: emission must reject.
	{
		b := a
		b[2] = sp1fri.KbAdd(b[2], 1)
		var ops []StackOp
		tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
		pushExt4Named(tracker, "lhs", a)
		pushExt4Named(tracker, "rhs", b)
		emitFinalPolyEqualityCheck(tracker, "lhs", "rhs")
		drainAllStack(tracker, &ops)
		if err := buildAndExecute(t, ops); err == nil {
			t.Fatal("emitFinalPolyEqualityCheck accepted unequal Ext4 values")
		}
	}
}

// TestEmitMerkleVerify_RejectsTamperedPath confirms the helper fails when
// the expected root is wrong.
func TestEmitMerkleVerify_RejectsTamperedPath(t *testing.T) {
	const depth = 3
	leaf := [8]uint32{1, 2, 3, 4, 5, 6, 7, 8}
	siblings := make([][8]uint32, depth)
	for i := 0; i < depth; i++ {
		for j := 0; j < 8; j++ {
			siblings[i][j] = uint32(100 + i*8 + j)
		}
	}
	const index = uint64(0b101)

	// Compute correct root then tamper with one element.
	current := leaf
	idx := index
	for i := 0; i < depth; i++ {
		bit := idx & 1
		var left, right [8]uint32
		if bit == 0 {
			left, right = current, siblings[i]
		} else {
			left, right = siblings[i], current
		}
		current = sp1fri.Poseidon2Compress(left, right)
		idx >>= 1
	}
	tamperedRoot := current
	tamperedRoot[3] = sp1fri.KbAdd(tamperedRoot[3], 1) // flip one element

	var ops []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })

	for i := 0; i < 8; i++ {
		tracker.pushInt(fmt.Sprintf("er_%d", i), int64(tamperedRoot[i]))
	}
	for i := 0; i < 8; i++ {
		tracker.pushInt(fmt.Sprintf("leaf_%d", i), int64(leaf[i]))
	}
	for s := 0; s < depth; s++ {
		for i := 0; i < 8; i++ {
			tracker.pushInt(fmt.Sprintf("sib_%d_%d", s, i), int64(siblings[s][i]))
		}
	}
	tracker.pushInt("index", int64(index))

	consume := []string{}
	for i := 0; i < 8; i++ {
		consume = append(consume, fmt.Sprintf("er_%d", i))
	}
	for i := 0; i < 8; i++ {
		consume = append(consume, fmt.Sprintf("leaf_%d", i))
	}
	for s := 0; s < depth; s++ {
		for i := 0; i < 8; i++ {
			consume = append(consume, fmt.Sprintf("sib_%d_%d", s, i))
		}
	}
	consume = append(consume, "index")

	emitMerkleVerify(tracker, depth, consume)

	drainAllStack(tracker, &ops)
	err := buildAndExecute(t, ops)
	if err == nil {
		t.Fatal("emitMerkleVerify accepted a tampered root; expected OP_NUMEQUALVERIFY failure")
	}
	t.Logf("emitMerkleVerify correctly rejected tampered root: %v", err)
}

// TestEmitFinalPolyHorner_MatchesReference validates the on-chain Horner
// evaluation matches the off-chain reference at sp1fri/fri.go:124-127.
func TestEmitFinalPolyHorner_MatchesReference(t *testing.T) {
	// 4 Ext4 coefficients (matches PoC fixture LogFinalPolyLen=2).
	coefs := []sp1fri.Ext4{
		{1, 2, 3, 4},
		{5, 6, 7, 8},
		{9, 10, 11, 12},
		{13, 14, 15, 16},
	}
	x := sp1fri.Ext4{100, 200, 300, 400}

	// Reference: eval = ((coef[3] * x + coef[2]) * x + coef[1]) * x + coef[0]
	want := sp1fri.Ext4Zero()
	for i := len(coefs) - 1; i >= 0; i-- {
		want = sp1fri.Ext4Add(sp1fri.Ext4Mul(want, x), coefs[i])
	}

	var ops []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) { ops = append(ops, op) })
	for i, c := range coefs {
		pushExt4Named(tracker, fmt.Sprintf("coef_%d", i), c)
	}
	pushExt4Named(tracker, "x", x)

	emitFinalPolyHorner(tracker, "coef", "x", "out", len(coefs))

	assertExt4EqualsRef(t, tracker, &ops, "out", want)
	drainAllStack(tracker, &ops)

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("on-chain Horner disagrees with reference (want=%v): %v", want, err)
	}
	t.Logf("Horner matches reference: |coefs|=%d → eval=%v; |ops|=%d", len(coefs), want, len(ops))
}
