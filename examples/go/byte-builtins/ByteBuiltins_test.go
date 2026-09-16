package contract

import (
	"encoding/hex"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ByteBuiltins.runar.go carried `//go:build ignore` from the day it was written
// until `Ripemd160Hash` reached the seven `.runar.go` type tables, so nothing
// here ever ran: the contract type was not constructible from a test binary and
// the port got only the Rúnar half of what a `.runar.go` file is for.
//
// The two digests below are FIPS/RIPEMD known-answer vectors, not values this
// repo computed. That is deliberate: the SDK mock is the thing under test on
// this side of the fence, so an "expected" value it produced itself would agree
// with any bug it has. `conformance/byte_builtins_execution_test.go` spends the
// compiled script for the same two builtins on the go-sdk consensus
// interpreter, against digests from crypto/sha256 and golang.org/x/crypto —
// three independent implementations, none grading its own output.

// sha256OfABC is SHA-256("abc"), FIPS 180-4 appendix B.1.
const sha256OfABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

// ripemd160OfABC is RIPEMD-160("abc") from the algorithm's published test
// vectors.
const ripemd160OfABC = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"

// ripemd160OfEmpty is RIPEMD-160(""), the other published vector. An
// implementation that returned its input would return the empty string here,
// so this row is what makes the identity-conversion failure visible.
const ripemd160OfEmpty = "9c1185a5c5e9fc54612808977ee8f548b2258d31"

func mustHex(t *testing.T, s string) runar.ByteString {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return runar.ByteString(b)
}

// newByteBuiltins bakes the two digests of `preimage` into the contract the way
// the locking script would.
func newByteBuiltins(preimage runar.ByteString) *ByteBuiltins {
	return &ByteBuiltins{
		ExpectedDigest: runar.Sha256(preimage),
		ExpectedRipemd: runar.Ripemd160(preimage),
	}
}

// mustAccept runs fn and fails if the contract refuses. runar.Assert panics on
// a false condition, mirroring OP_VERIFY aborting the script, so "the contract
// refuses" and "fn panics" are the same event.
func mustAccept(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: the contract REFUSED (%v)", what, r)
		}
	}()
	fn()
}

// mustRefuse is the other half: without it every acceptance above would pass on
// a contract whose assertion had been deleted.
func mustRefuse(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: the contract ACCEPTED where it must refuse", what)
		}
	}()
	fn()
}

func TestByteBuiltins_Split(t *testing.T) {
	c := newByteBuiltins(runar.ByteString("x"))
	data := mustHex(t, "aabbccdd")

	// `split` binds the RIGHT half. 0 and len are the ends of the legal range
	// and the only places an off-by-one shows.
	for _, row := range []struct {
		name string
		idx  int64
		tail string
	}{
		{"index 0 binds the whole string", 0, "aabbccdd"},
		{"a mid split", 2, "ccdd"},
		{"index == len binds the empty string", 4, ""},
	} {
		mustAccept(t, row.name, func() {
			c.CheckSplit(data, row.idx, mustHex(t, row.tail))
		})
	}

	mustRefuse(t, "split at 2 is not the whole string", func() {
		c.CheckSplit(data, 2, data)
	})
}

func TestByteBuiltins_Int2Str(t *testing.T) {
	c := newByteBuiltins(runar.ByteString("x"))

	// Fixed-width little-endian sign-magnitude, which is Script's number
	// encoding and not Go's.
	mustAccept(t, "1 in 4 bytes", func() {
		c.CheckInt2Str(1, 4, mustHex(t, "01000000"))
	})
	mustAccept(t, "-1 in 4 bytes sets the sign bit of the last byte", func() {
		c.CheckInt2Str(-1, 4, mustHex(t, "01000080"))
	})
	mustRefuse(t, "-1 is not encoded as +1", func() {
		c.CheckInt2Str(-1, 4, mustHex(t, "01000000"))
	})
}

func TestByteBuiltins_Reverse(t *testing.T) {
	c := newByteBuiltins(runar.ByteString("x"))

	mustAccept(t, "odd length", func() {
		c.CheckReverse(mustHex(t, "aabbcc"), mustHex(t, "ccbbaa"))
	})
	mustAccept(t, "empty", func() {
		c.CheckReverse(runar.ByteString(""), runar.ByteString(""))
	})
	mustRefuse(t, "a non-palindrome is not its own reverse", func() {
		c.CheckReverse(mustHex(t, "aabbcc"), mustHex(t, "aabbcc"))
	})
}

// TestByteBuiltins_Sha256 uses the `Sha256Hash` alias spelling, which is what
// CheckSha256 calls and which only the Go surface parser maps.
func TestByteBuiltins_Sha256(t *testing.T) {
	c := &ByteBuiltins{ExpectedDigest: mustHex(t, sha256OfABC)}

	mustAccept(t, "the FIPS 180-4 vector for \"abc\"", func() {
		c.CheckSha256(runar.ByteString("abc"))
	})
	mustRefuse(t, "a different preimage", func() {
		c.CheckSha256(runar.ByteString("abd"))
	})
	// The identity-conversion failure: if Sha256Hash returned its input, a
	// contract whose baked digest IS the digest would accept the digest as the
	// preimage, and the publicly readable locking script would be the key.
	mustRefuse(t, "the baked digest pushed as the preimage", func() {
		c.CheckSha256(runar.ByteString(c.ExpectedDigest))
	})
}

// TestByteBuiltins_Ripemd is the half this port exists for. `runar.Ripemd160`
// is a FUNCTION and `runar.Ripemd160Hash` is the digest TYPE; the field above
// could not be spelled at all until the type name reached the parsers.
func TestByteBuiltins_Ripemd(t *testing.T) {
	c := &ByteBuiltins{ExpectedRipemd: mustHex(t, ripemd160OfABC)}

	mustAccept(t, "the published vector for \"abc\"", func() {
		c.CheckRipemd(runar.ByteString("abc"))
	})
	mustRefuse(t, "a different preimage", func() {
		c.CheckRipemd(runar.ByteString("abd"))
	})
	mustRefuse(t, "the baked digest pushed as the preimage", func() {
		c.CheckRipemd(runar.ByteString(c.ExpectedRipemd))
	})

	// The empty-string vector, where an identity conversion is unmistakable.
	empty := &ByteBuiltins{ExpectedRipemd: mustHex(t, ripemd160OfEmpty)}
	mustAccept(t, "the published vector for the empty string", func() {
		empty.CheckRipemd(runar.ByteString(""))
	})
}

func TestByteBuiltins_Compile(t *testing.T) {
	if err := runar.CompileCheck("ByteBuiltins.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
