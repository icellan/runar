package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

const (
	ownerKey  = "0000000000000000000000000000000000000000000000000000000000000001"
	backupKey = "0000000000000000000000000000000000000000000000000000000000000002"
)

func newMultiMethod() *MultiMethod {
	return &MultiMethod{
		Owner:  runar.PubKeyFromPrivKey(ownerKey),
		Backup: runar.PubKeyFromPrivKey(backupKey),
	}
}

func TestMultiMethod_Compile(t *testing.T) {
	if err := runar.CompileCheck("MultiMethod.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// The two public methods are separate spending paths bound to DIFFERENT keys.
// Crossing them is the failure that costs money, so each key is tried against
// both paths.
func TestMultiMethod_PathsAreBoundToTheirOwnKey(t *testing.T) {
	c := newMultiMethod()
	ownerSig := runar.SignTestMessage(ownerKey)
	backupSig := runar.SignTestMessage(backupKey)

	mustAccept(t, "owner signs the owner path", func() { c.SpendWithOwner(ownerSig, 6) })
	mustAccept(t, "backup signs the backup path", func() { c.SpendWithBackup(backupSig) })
	mustRefuse(t, "backup key on the owner path", func() { c.SpendWithOwner(backupSig, 6) })
	mustRefuse(t, "owner key on the backup path", func() { c.SpendWithBackup(ownerSig) })
}

// SpendWithOwner inlines the private helper `computeThreshold(a,b) = a*b+1`
// and asserts the result exceeds 10. amount=6 gives 13 (accept) and amount=4
// gives 9 (refuse); amount=5 gives exactly 11, and 4 is the largest amount
// that refuses -- so the pair pins both the formula and the strict `>`.
func TestMultiMethod_InlinedHelperGatesTheAmount(t *testing.T) {
	c := newMultiMethod()
	sig := runar.SignTestMessage(ownerKey)

	for _, amount := range []runar.Int{5, 6, 100} {
		amount := amount
		mustAccept(t, "amount above the inlined threshold", func() {
			c.SpendWithOwner(sig, amount)
		})
	}
	for _, amount := range []runar.Int{0, 1, 4} {
		amount := amount
		mustRefuse(t, "amount below the inlined threshold", func() {
			c.SpendWithOwner(sig, amount)
		})
	}
	// a*b+1 with b=2: the boundary sits between 4 (9) and 5 (11), and 10 is
	// unreachable -- which is what makes `> 10` and `>= 10` indistinguishable
	// here and why the formula itself is pinned directly.
	if got := (&MultiMethod{}).computeThreshold(6, 2); got != 13 {
		t.Fatalf("computeThreshold(6,2) = %d, want 13 (a*b+1)", got)
	}
}

func mustAccept(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: the contract REFUSED (%v)", what, r)
		}
	}()
	fn()
}

func mustRefuse(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: the contract ACCEPTED where it must refuse", what)
		}
	}()
	fn()
}
