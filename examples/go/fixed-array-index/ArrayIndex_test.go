package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestArrayIndex_Compile(t *testing.T) {
	if err := runar.CompileCheck("ArrayIndex.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// init() is the Go-DSL spelling of a property initializer; the Rúnar compiler
// bakes the same four values into the locking script. The compiler expands
// Table into four scalar siblings (Table__0..Table__3) and rewrites each
// indexed read, so an off-by-one in that expansion reads the WRONG slot --
// which a test that only checked Lookup(0) would never see. Every index is
// covered, and each is also checked against its neighbours' values.
func TestArrayIndex_LooksUpEverySlot(t *testing.T) {
	c := &ArrayIndex{}
	c.init()

	want := [4]runar.Int{10, 20, 30, 40}
	for i := runar.Int(0); i < 4; i++ {
		i := i
		mustAccept(t, "Lookup at the right slot", func() { c.Lookup(i, want[i]) })

		for j := runar.Int(0); j < 4; j++ {
			if i == j {
				continue
			}
			j := j
			mustRefuse(t, "Lookup returned a neighbouring slot", func() { c.Lookup(i, want[j]) })
		}
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
