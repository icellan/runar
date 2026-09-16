package conformance

import (
	"fmt"
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// R-119 -- executed coverage for the BabyBear canonicity gate, on the babybear
// FIXTURE's own compiled bytes.
//
// The fixture existed and its golden was byte-stable, but nothing in this
// repository ever SPENT it: conformance/witnesses has no entry, and
// coverage-ledger.json routes it to a regtest integration job that only spends
// the happy path. So the hole -- every operand of every BabyBear builtin going
// straight into OP_ADD / OP_MUL / OP_MOD with no range check at all -- was
// unreachable by any gate here.
//
// What was actually broken is the NEGATIVE half. `bbFieldAdd` and `bbFieldMul`
// reduce with a BARE OP_MOD, documented as safe because both operands are
// assumed to be in [0, p-1]; OP_MOD takes the sign of the dividend, so a
// negative witness walks out of the field:
//
//	bbFieldAdd(-1, 0) -> -1        bbFieldAdd(p-1, 0) -> 2013265920
//
// Two script numbers for one residue, out of a builtin whose codomain is
// declared to be the field. `v + p` was NOT broken in the same way -- the
// result is reduced either way -- but it is gated too, because two accepted
// spellings of one element is the aliasing the finding names.
//
// These tests compile the fixture through the TYPESCRIPT compiler and execute
// the result on the go-sdk consensus interpreter: two independent
// implementations on the two sides of every assertion.
// ---------------------------------------------------------------------------

// bbP is the BabyBear prime the fixture's builtins work over.
var bbP = big.NewInt(2013265921)

// babybearMethod indexes BabyBearDemo's public methods in declaration order:
// checkAdd, checkSub, checkMul, checkInv, checkAddSubRoundtrip, checkDistributive.
const (
	bbCheckAdd = 0
	bbCheckSub = 1
	bbCheckMul = 2
	bbCheckInv = 3
)

// spendBabyBear compiles the babybear fixture (no constructor args) and spends
// `method` with the given bigint arguments. Returns whether the consensus
// interpreter ACCEPTED.
func spendBabyBear(t *testing.T, method int, args ...*big.Int) bool {
	t.Helper()
	lockingHex, err := compileRúnar("babybear", `{}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	unlocking := ""
	for _, a := range args {
		unlocking += encodePushBigInt(a)
	}
	unlocking += encodePushInt(int64(method))
	return executeScript(lockingHex, unlocking) == nil
}

func bbi(n int64) *big.Int { return big.NewInt(n) }

// TestR119_BabyBearFixture_NonCanonicalOperandRejected is the finding, executed
// on the fixture's real locking script.
func TestR119_BabyBearFixture_NonCanonicalOperandRejected(t *testing.T) {
	p := bbP
	pm1 := new(big.Int).Sub(p, bbi(1))
	alias := new(big.Int).Add(bbi(5), p) // 5 + p — same element, different spelling

	// CONTROL WITH TEETH: the honest spends still work, against results
	// computed off-chain.
	for _, c := range []struct {
		method int
		args   []*big.Int
		name   string
	}{
		{bbCheckAdd, []*big.Int{bbi(5), bbi(7), bbi(12)}, "checkAdd(5,7,12)"},
		{bbCheckAdd, []*big.Int{pm1, bbi(1), bbi(0)}, "checkAdd(p-1,1,0)"},
		{bbCheckSub, []*big.Int{bbi(0), bbi(1), pm1}, "checkSub(0,1,p-1)"},
		{bbCheckMul, []*big.Int{pm1, bbi(2), new(big.Int).Sub(p, bbi(2))}, "checkMul(p-1,2,p-2)"},
		{bbCheckInv, []*big.Int{bbi(3)}, "checkInv(3)"},
		{bbCheckInv, []*big.Int{pm1}, "checkInv(p-1)"},
	} {
		if !spendBabyBear(t, c.method, c.args...) {
			t.Fatalf("control %s must still spend", c.name)
		}
	}

	// The >= p half: before the gate, `checkAdd(5+p, 0, 5)` SPENT, because the
	// emitter reduced the result and the contract compared the reduced value.
	if spendBabyBear(t, bbCheckAdd, alias, bbi(0), bbi(5)) {
		t.Errorf("checkAdd(5+p, 0, 5) spent — a non-canonical operand was accepted")
	}
	if spendBabyBear(t, bbCheckMul, alias, bbi(1), bbi(5)) {
		t.Errorf("checkMul(5+p, 1, 5) spent")
	}
	if spendBabyBear(t, bbCheckInv, alias) {
		t.Errorf("checkInv(5+p) spent")
	}
	if spendBabyBear(t, bbCheckAdd, p, bbi(0), bbi(0)) {
		t.Errorf("checkAdd(p, 0, 0) spent — the bound must exclude p itself")
	}

	// The NEGATIVE half — the one that returned a value outside the field.
	// Before the gate, `checkAdd(-1, 1, 0)` spent: -1 + 1 = 0, 0 mod p = 0.
	if spendBabyBear(t, bbCheckAdd, bbi(-1), bbi(1), bbi(0)) {
		t.Errorf("checkAdd(-1, 1, 0) spent — a negative operand was accepted")
	}
	// And `checkAdd(-1, 0, -1)` spent while `checkAdd(p-1, 0, -1)` did not,
	// which is the two-spellings-of-one-residue defect in one line.
	if spendBabyBear(t, bbCheckAdd, bbi(-1), bbi(0), bbi(-1)) {
		t.Errorf("checkAdd(-1, 0, -1) spent — the builtin returned -1, not p-1")
	}
	if spendBabyBear(t, bbCheckMul, bbi(-1), bbi(1), bbi(-1)) {
		t.Errorf("checkMul(-1, 1, -1) spent")
	}
	if spendBabyBear(t, bbCheckInv, bbi(-1)) {
		t.Errorf("checkInv(-1) spent")
	}
}

// TestR119_BabyBearFixture_BoundIsExact pins the domain at [0, p) on both
// sides, so an over-strict gate reddens on the accept half.
func TestR119_BabyBearFixture_BoundIsExact(t *testing.T) {
	p := bbP
	pm1 := new(big.Int).Sub(p, bbi(1))

	// 0 and p-1 are both legal; p and -1 are not. Exercised through checkMul,
	// whose expected value is computed here and not by the compiler.
	for _, a := range []*big.Int{bbi(0), bbi(1), pm1} {
		want := new(big.Int).Mod(new(big.Int).Mul(a, bbi(3)), p)
		if !spendBabyBear(t, bbCheckMul, a, bbi(3), want) {
			t.Errorf("in-domain operand %s rejected", a)
		}
	}
	for _, a := range []*big.Int{p, new(big.Int).Add(p, bbi(1)), bbi(-1)} {
		want := new(big.Int).Mod(new(big.Int).Mul(a, bbi(3)), p)
		if spendBabyBear(t, bbCheckMul, a, bbi(3), want) {
			t.Errorf("out-of-domain operand %s accepted", a)
		}
	}
}

// TestR119_BabyBearFixture_CompositionStillSpends is why the gate sits on the
// INPUT rather than fixing up the output: a gated builtin RETURNS a canonical
// element, so feeding one into the next passes the next gate for free. The
// fixture's own checkAddSubRoundtrip and checkDistributive compose two and
// three builtins; if the output ever escaped the field they would abort.
func TestR119_BabyBearFixture_CompositionStillSpends(t *testing.T) {
	p := bbP
	pm1 := new(big.Int).Sub(p, bbi(1))
	const checkAddSubRoundtrip = 4
	const checkDistributive = 5

	for _, ab := range [][2]*big.Int{{pm1, pm1}, {bbi(0), pm1}, {bbi(5), bbi(7)}} {
		if !spendBabyBear(t, checkAddSubRoundtrip, ab[0], ab[1]) {
			t.Errorf("checkAddSubRoundtrip(%s, %s) rejected", ab[0], ab[1])
		}
	}
	for _, abc := range [][3]*big.Int{{pm1, pm1, pm1}, {bbi(3), bbi(5), bbi(7)}} {
		if !spendBabyBear(t, checkDistributive, abc[0], abc[1], abc[2]) {
			t.Errorf("checkDistributive(%s, %s, %s) rejected", abc[0], abc[1], abc[2])
		}
	}
	_ = fmt.Sprint(p)
}
