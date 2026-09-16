package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // RIPEMD-160 is a consensus opcode; this is the reference implementation of it.
)

// ---------------------------------------------------------------------------
// Executed coverage for the byte-level builtins, on the byte-builtins FIXTURE's
// own compiled bytes.
//
// WHY THIS FILE EXISTS. Of the 105 `export function`s in
// packages/runar-lang/src/builtins.ts, `split`, `int2str`, `reverseBytes` and
// `ripemd160` appeared in ZERO fixtures' expected-ir.json and the fuzzer could
// generate none of them. Seven compilers shipped codegen for all four with
// nothing on either side of it: no cross-tier byte comparison, and no
// execution.
//
// `ripemd160` was the last of them to land, and it is the one that shows why
// the gap mattered. The `.runar.go` surface's only spelling for it is
// `runar.Ripemd160`, a name that is BOTH a Rúnar type and a Rúnar builtin; two
// of the seven tiers resolved the call as a type cast and dropped OP_RIPEMD160
// altogether. No fixture called it, so nothing noticed. See
// conformance/go_surface_hash_spelling_execution_test.go for the fund-loss
// proof and the fix.
//
// A fixture alone would not have been enough. `pow` DID have a fixture callsite
// -- math-demo.exponentiate -- and still returned base^min(exp,32) for every
// exponent above 32, through three review rounds, because the callsite was only
// ever COMPILED. Nothing spent it past the bound. So these tests spend the
// fixture's real locking script at each builtin's boundaries, against results
// computed independently in Go.
//
// The compiler under test is TypeScript; the interpreter is the go-sdk
// consensus engine. Two independent implementations on the two sides of every
// assertion.
// ---------------------------------------------------------------------------

// byteBuiltinsMethod indexes ByteBuiltins' public methods in DECLARATION order.
// Changing the order in examples/*/byte-builtins/ changes these.
const (
	bbCheckSplit   = 0
	bbCheckInt2Str = 1
	bbCheckReverse = 2
	bbCheckSha256  = 3
	bbCheckRipemd  = 4
)

// bbPreimage is the message whose two digests are baked into the locking
// script as the contract's constructor args.
var bbPreimage = []byte("runar byte-builtins fixture")

// bbDigest is the SHA-256 digest baked into the locking script.
var bbDigest = sha256.Sum256(bbPreimage)

// bbRipemd is the RIPEMD-160 digest baked into the locking script. Computed by
// golang.org/x/crypto, which is not the implementation under test.
var bbRipemd = ripemd160Of(bbPreimage)

func ripemd160Of(b []byte) []byte {
	h := ripemd160.New()
	h.Write(b)
	return h.Sum(nil)
}

// spendByteBuiltins compiles the byte-builtins fixture with `expectedDigest`
// baked in and spends `method` with the given pushes. Returns whether the
// consensus interpreter ACCEPTED.
func spendByteBuiltins(t *testing.T, method int, pushes ...string) bool {
	t.Helper()
	args := `{"expectedDigest":"` + hex.EncodeToString(bbDigest[:]) +
		`","expectedRipemd":"` + hex.EncodeToString(bbRipemd) + `"}`
	lockingHex, err := compileRúnar("byte-builtins", args)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	unlocking := ""
	for _, p := range pushes {
		unlocking += p
	}
	unlocking += encodePushInt(int64(method))
	return executeScript(lockingHex, unlocking) == nil
}

// pushHexBytes encodes a hex string as a single minimal push.
func pushHexBytes(t *testing.T, h string) string {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("bad hex %q: %v", h, err)
	}
	return encodePushBytes(b)
}

// ---------------------------------------------------------------------------
// split -- OP_SPLIT. The builtin binds the RIGHT half.
// ---------------------------------------------------------------------------

func TestByteBuiltins_Split_Boundaries(t *testing.T) {
	const data = "aabbccdd" // 4 bytes

	for _, c := range []struct {
		name string
		data string
		idx  int64
		tail string
		want bool
	}{
		// The two ends of the legal range are the point of this test: an
		// off-by-one in the OP_SPLIT lowering shows up at 0 or at len, never
		// in the middle.
		{"idx 0 binds the whole string", data, 0, "aabbccdd", true},
		{"idx == len binds the empty string", data, 4, "", true},
		{"idx mid", data, 2, "ccdd", true},
		{"empty data at idx 0", "", 0, "", true},

		// Teeth: the same split with the wrong expectation must be refused,
		// or every row above passes on a script that ignores its arguments.
		{"mid split, wrong tail", data, 2, "ccde", false},
		{"idx 0, tail of a different length", data, 0, "aabbcc", false},

		// Out of range is consensus' own abort, not the contract's.
		{"idx past end", data, 5, "", false},
		{"idx negative", data, -1, "aabbccdd", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := spendByteBuiltins(t, bbCheckSplit,
				pushHexBytes(t, c.data),
				encodePushInt(c.idx),
				pushHexBytes(t, c.tail),
			)
			if got != c.want {
				t.Fatalf("split(%q, %d) == %q: accepted=%v, want %v", c.data, c.idx, c.tail, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// int2str -- OP_NUM2BIN. Fixed-width little-endian sign-magnitude.
// ---------------------------------------------------------------------------

func TestByteBuiltins_Int2Str_Boundaries(t *testing.T) {
	for _, c := range []struct {
		name     string
		value    int64
		width    int64
		expected string
		want     bool
	}{
		// Zero and the negatives are the encodings a hand-rolled NUM2BIN gets
		// wrong: the sign lives in the TOP byte, not as a two's complement.
		{"zero into 4 bytes", 0, 4, "00000000", true},
		{"one into 4 bytes", 1, 4, "01000000", true},
		{"minus one into 4 bytes", -1, 4, "01000080", true},
		{"minus five into 4 bytes", -5, 4, "05000080", true},
		{"255 needs its sign byte", 255, 2, "ff00", true},
		{"zero into zero width", 0, 0, "", true},
		{"2^31-1 into 4 bytes", 2147483647, 4, "ffffff7f", true},
		{"2^32-1 into 5 bytes", 4294967295, 5, "ffffffff00", true},

		// Teeth: two's complement instead of sign-magnitude, and a byte-order
		// flip. Both are the plausible regressions.
		{"minus one as two's complement", -1, 4, "ffffffff", false},
		{"one big-endian", 1, 4, "00000001", false},

		// Widths consensus refuses.
		{"255 will not fit in 1 byte", 255, 1, "ff", false},
		{"nonzero will not fit in 0 bytes", 1, 0, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := spendByteBuiltins(t, bbCheckInt2Str,
				encodePushBigInt(big.NewInt(c.value)),
				encodePushInt(c.width),
				pushHexBytes(t, c.expected),
			)
			if got != c.want {
				t.Fatalf("int2str(%d, %d) == %q: accepted=%v, want %v", c.value, c.width, c.expected, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// reverseBytes -- 520 unrolled OP_SPLIT / OP_CAT iterations, one per possible
// byte of a maximum-size BSV stack element.
// ---------------------------------------------------------------------------

func TestByteBuiltins_ReverseBytes_Boundaries(t *testing.T) {
	rev := func(b []byte) []byte {
		out := make([]byte, len(b))
		for i := range b {
			out[len(b)-1-i] = b[i]
		}
		return out
	}
	seq := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i % 256)
		}
		return b
	}

	// The unroll is a fixed 520 iterations whatever the input length, so the
	// interesting lengths are the two ends: nothing to reverse, and the
	// maximum element where the LAST of the 520 iterations does real work.
	for _, n := range []int{0, 1, 2, 3, 17, 64, 255, 519, 520} {
		in := seq(n)
		t.Run(lenName(n), func(t *testing.T) {
			if !spendByteBuiltins(t, bbCheckReverse,
				encodePushBytes(in), encodePushBytes(rev(in))) {
				t.Fatalf("reverseBytes of %d bytes was rejected on its own correct result", n)
			}
		})
	}

	// Teeth. A reverse that is a no-op passes for a palindrome and for the
	// empty string, so the negatives have to use inputs that are neither.
	t.Run("identity is not a reverse", func(t *testing.T) {
		in := []byte{0xaa, 0xbb, 0xcc}
		if spendByteBuiltins(t, bbCheckReverse, encodePushBytes(in), encodePushBytes(in)) {
			t.Fatal("reverseBytes accepted its own input as the reversed result")
		}
	})
	t.Run("word-swapped is not byte-reversed", func(t *testing.T) {
		in := []byte{0x01, 0x02, 0x03, 0x04}
		if spendByteBuiltins(t, bbCheckReverse, encodePushBytes(in),
			encodePushBytes([]byte{0x03, 0x04, 0x01, 0x02})) {
			t.Fatal("reverseBytes accepted a 16-bit word swap as a byte reversal")
		}
	})
	t.Run("truncated result", func(t *testing.T) {
		in := seq(8)
		if spendByteBuiltins(t, bbCheckReverse, encodePushBytes(in),
			encodePushBytes(rev(in)[:7])) {
			t.Fatal("reverseBytes accepted a result one byte short")
		}
	})
}

func lenName(n int) string {
	return "len " + big.NewInt(int64(n)).String()
}

// ---------------------------------------------------------------------------
// sha256 -- OP_SHA256. In the `.runar.go` surface this call is spelled
// `Sha256Hash`, the alias whose only resolving parser is Go's.
// ---------------------------------------------------------------------------

func TestByteBuiltins_Sha256_AgainstBakedDigest(t *testing.T) {
	// The honest spend: the preimage whose digest was baked in.
	if !spendByteBuiltins(t, bbCheckSha256, encodePushBytes(bbPreimage)) {
		t.Fatal("the preimage of the baked digest was rejected")
	}

	// Teeth: the digest itself must NOT unlock. This is the exact shape of the
	// Go-surface `runar.Sha256` defect -- when the hash call is lowered to an
	// identity binding the script degenerates to `preimage == storedDigest`,
	// and the publicly known digest becomes the spending key. This row goes
	// red the moment OP_SHA256 stops being emitted.
	if spendByteBuiltins(t, bbCheckSha256, encodePushBytes(bbDigest[:])) {
		t.Fatal("the DIGEST unlocked the contract -- OP_SHA256 is not being applied")
	}

	// And an unrelated preimage stays rejected.
	other := sha256.Sum256([]byte("not the preimage"))
	if spendByteBuiltins(t, bbCheckSha256, encodePushBytes(other[:])) {
		t.Fatal("an unrelated preimage unlocked the contract")
	}
}

// ---------------------------------------------------------------------------
// ripemd160 -- OP_RIPEMD160. In the `.runar.go` surface this call is spelled
// `runar.Ripemd160`, which is also a Rúnar TYPE name. That collision is why
// this builtin had zero fixtures until now: two of the seven tiers lowered the
// call to an identity binding, so any fixture calling it would have wedged
// cross-tier parity rather than reported the bug.
// ---------------------------------------------------------------------------

func TestByteBuiltins_Ripemd160_AgainstBakedDigest(t *testing.T) {
	// The teeth first. Under the identity-cast miscompile the method
	// degenerates to `pushed == storedRipemd`, and storedRipemd is IN the
	// locking script — the contract is spendable by anyone who can read the
	// chain. This row is the whole reason the method exists.
	if spendByteBuiltins(t, bbCheckRipemd, encodePushBytes(bbRipemd)) {
		t.Fatal("the DIGEST unlocked the contract -- OP_RIPEMD160 is not being applied")
	}

	// The honest spend.
	if !spendByteBuiltins(t, bbCheckRipemd, encodePushBytes(bbPreimage)) {
		t.Fatal("the preimage of the baked RIPEMD-160 digest was rejected")
	}

	// An unrelated preimage stays rejected, so the row above cannot pass on a
	// script that refuses everything.
	if spendByteBuiltins(t, bbCheckRipemd, encodePushBytes([]byte("not the preimage"))) {
		t.Fatal("an unrelated preimage unlocked the contract")
	}

	// RIPEMD-160 is 20 bytes and SHA-256 is 32. Pushing the SHA-256 digest of
	// the same preimage must not unlock it — that is the check a length-only
	// comparison would fail.
	if spendByteBuiltins(t, bbCheckRipemd, encodePushBytes(bbDigest[:])) {
		t.Fatal("the SHA-256 digest of the preimage unlocked the RIPEMD-160 method")
	}
}

// The two hash methods must not be interchangeable: each has its own baked
// digest, and a lowering that crossed the wires would still pass every row
// above if both methods hashed the same way.
func TestByteBuiltins_HashMethodsAreNotInterchangeable(t *testing.T) {
	if spendByteBuiltins(t, bbCheckSha256, encodePushBytes(bbRipemd)) {
		t.Fatal("checkSha256 accepted the RIPEMD-160 digest as its preimage")
	}
	if len(bbRipemd) != 20 {
		t.Fatalf("RIPEMD-160 digest is %d bytes, want 20", len(bbRipemd))
	}
	if len(bbDigest) != 32 {
		t.Fatalf("SHA-256 digest is %d bytes, want 32", len(bbDigest))
	}
}
