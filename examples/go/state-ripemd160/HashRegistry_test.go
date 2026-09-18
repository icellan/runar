package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// HashRegistry.runar.go used to carry `//go:build ignore`, so this suite could
// only run the Rúnar frontend and the contract type was not constructible from
// the test binary. The blocker was the missing `Ripemd160Hash` arm in the seven
// `.runar.go` type tables; with it in place the port is Go as well as Rúnar,
// and the state transition below is actually executed.

func TestHashRegistry_Update(t *testing.T) {
	start := runar.Ripemd160(runar.ByteString("first"))
	next := runar.Ripemd160(runar.ByteString("second"))

	// A test whose two digests were equal would pass on an Update that did
	// nothing at all.
	if start == next {
		t.Fatalf("the two fixtures hash the same (%x) -- this test would be vacuous", start)
	}

	c := &HashRegistry{CurrentHash: start}
	c.Update(next)
	if c.CurrentHash != next {
		t.Fatalf("CurrentHash = %x, want %x", c.CurrentHash, next)
	}
}

// TestHashRegistry_DigestTypeIsNotTheHashFunction pins the distinction the
// exclusion was about. `runar.Ripemd160Hash` is the digest TYPE and
// `runar.Ripemd160` is the hash FUNCTION; an SDK that resolved the call as a
// conversion would return its input unchanged, and a contract comparing a
// stored digest against `Ripemd160(preimage)` would accept the digest itself.
func TestHashRegistry_DigestTypeIsNotTheHashFunction(t *testing.T) {
	preimage := runar.ByteString("preimage")
	var digest runar.Ripemd160Hash = runar.Ripemd160(preimage)

	if runar.ByteString(digest) == preimage {
		t.Fatal("runar.Ripemd160 returned its input -- it is resolving as an " +
			"identity conversion, not a hash")
	}
	if len(digest) != 20 {
		t.Fatalf("RIPEMD-160 digest is %d bytes, want 20", len(digest))
	}
}

func TestHashRegistry_Compile(t *testing.T) {
	if err := runar.CompileCheck("HashRegistry.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
