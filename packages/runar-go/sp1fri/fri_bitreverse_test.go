package sp1fri

import (
	"testing"
)

// R-220 (CL-GAP-070) — cover the arity-2 blind spot in the FRI fold.
//
// docs/audit/2026-08-go-only-crypto-oracles.md records that the folding RULE is
// anchored upstream: minimal-guest/proof.postcard is real Plonky3 output and
// Verify accepts it end to end, so a fold that diverged from Plonky3 could not
// verify a Plonky3 proof. Measured — perturbing foldRow's generator order makes
// TestVerifyMinimalGuest fail.
//
// That anchor has one hole. The pinned PoC config sets max_log_arity: 1, so
// every fold the fixtures reach is arity-2, and reverseSliceIndexBits is the
// identity on two elements. Deleting the call outright leaves BOTH the sp1fri
// suite and the Go codegen FRI tests fully green — nothing in the corpus can
// tell the difference.
//
// These tests grade the permutation against its own definition
// (p3_util::reverse_slice_index_bits: element i moves to reverseBitsLen(i,
// log2(n))) at the widths no fixture reaches, and pin the fact that arity 2 is
// blind while arity 4 is not. They are not a substitute for a max_log_arity > 1
// proof fixture; they stop the utility from silently rotting until one lands.

func TestReverseSliceIndexBits_MatchesDefinition(t *testing.T) {
	cases := []struct {
		name string
		in   []uint32
		want []uint32
	}{
		// n=1 and n=2: the permutation is the identity. This is precisely why
		// the arity-2 fixtures cannot grade it.
		{"n=1", []uint32{10}, []uint32{10}},
		{"n=2", []uint32{10, 20}, []uint32{10, 20}},
		// n=4, logN=2: 0->00->00=0, 1->01->10=2, 2->10->01=1, 3->11->11=3.
		{"n=4", []uint32{0, 1, 2, 3}, []uint32{0, 2, 1, 3}},
		// n=8, logN=3: 0,4,2,6,1,5,3,7.
		{"n=8", []uint32{0, 1, 2, 3, 4, 5, 6, 7}, []uint32{0, 4, 2, 6, 1, 5, 3, 7}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := append([]uint32(nil), tc.in...)
			reverseSliceIndexBits(got)
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("reverseSliceIndexBits(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestReverseSliceIndexBits_IsItsOwnInverse(t *testing.T) {
	// Bit reversal is an involution, so applying it twice must restore the
	// input at every width. A permutation table that was merely self-consistent
	// but wrong would still satisfy this, which is why the explicit expectations
	// above carry the real weight — this catches the asymmetric mistakes.
	for _, n := range []int{1, 2, 4, 8, 16, 32} {
		xs := make([]uint32, n)
		for i := range xs {
			xs[i] = uint32(i) * 7
		}
		original := append([]uint32(nil), xs...)
		reverseSliceIndexBits(xs)
		reverseSliceIndexBits(xs)
		for i := range original {
			if xs[i] != original[i] {
				t.Fatalf("n=%d: double reversal changed element %d (%d != %d)",
					n, i, xs[i], original[i])
			}
		}
	}
}

// TestFoldRow_AppliesTheBitReversal recomputes foldRow's xs by hand and checks
// that the fold uses the BIT-REVERSED ordering, not the natural one.
//
// An earlier version of this test compared foldRow against itself with permuted
// evals, which differ as inputs whether or not the permutation is applied — it
// stayed green with the reverseSliceIndexBits call deleted outright. Comparing
// against lagrangeInterpolateAt with each candidate ordering is what actually
// discriminates.
func TestFoldRow_AppliesTheBitReversal(t *testing.T) {
	const index, logHeight, logArity = 3, 4, 2
	beta := Ext4FromBase(KbFromU64(12345))
	evals := []Ext4{
		Ext4FromBase(KbFromU64(11)), Ext4FromBase(KbFromU64(22)),
		Ext4FromBase(KbFromU64(33)), Ext4FromBase(KbFromU64(44)),
	}

	// The coset, in natural order, exactly as foldRow builds it before permuting.
	arity := 1 << logArity
	subgroupStart := KbPow(KbTwoAdicGenerator(logHeight+logArity),
		reverseBitsLen(index, logHeight))
	g := KbTwoAdicGenerator(logArity)
	natural := make([]uint32, arity)
	natural[0] = subgroupStart
	for i := 1; i < arity; i++ {
		natural[i] = KbMul(natural[i-1], g)
	}
	// n=4 bit reversal: 0->0, 1->2, 2->1, 3->3.
	reversed := []uint32{natural[0], natural[2], natural[1], natural[3]}

	withReversed := lagrangeInterpolateAt(reversed, evals, beta)
	withNatural := lagrangeInterpolateAt(natural, evals, beta)

	// Anti-vacuity: if the two orderings agreed, the assertion below would hold
	// no matter what foldRow did, and reverseSliceIndexBits would be dead code.
	if Ext4Equal(withReversed, withNatural) {
		t.Fatalf("the two coset orderings interpolate alike at arity %d — "+
			"this test cannot observe the permutation", arity)
	}

	got := foldRow(index, logHeight, logArity, beta, evals)
	if !Ext4Equal(got, withReversed) {
		if Ext4Equal(got, withNatural) {
			t.Fatalf("foldRow used the natural coset ordering; the bit reversal is not applied")
		}
		t.Fatalf("foldRow matched neither candidate ordering")
	}
}

// TestFoldRow_BitReversalIsBlindAtArity2 pins the coverage hole itself: at
// log_arity 1 the permutation is the identity, so every fixture in the corpus
// folds identically with the call present or absent. If a parameter change ever
// makes arity-2 folds sensitive to it, this says so rather than leaving the
// audit note's claim stale.
func TestFoldRow_BitReversalIsBlindAtArity2(t *testing.T) {
	const index, logHeight = 3, 4
	beta := Ext4FromBase(KbFromU64(12345))
	evals := []Ext4{Ext4FromBase(KbFromU64(11)), Ext4FromBase(KbFromU64(22))}

	subgroupStart := KbPow(KbTwoAdicGenerator(logHeight+1), reverseBitsLen(index, logHeight))
	natural := []uint32{subgroupStart, KbMul(subgroupStart, KbTwoAdicGenerator(1))}

	if !Ext4Equal(foldRow(index, logHeight, 1, beta, evals),
		lagrangeInterpolateAt(natural, evals, beta)) {
		t.Fatalf("arity-2 fold no longer matches the unpermuted coset — the audit " +
			"note's claim that max_log_arity 1 cannot observe the bit reversal is stale")
	}
}
