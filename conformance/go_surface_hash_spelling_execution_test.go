package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // RIPEMD-160 is a consensus opcode; this is the reference implementation of it.
)

// ---------------------------------------------------------------------------
// F1 -- the `.runar.go` surface's `Sha256` / `Ripemd160` name collision.
//
// `Sha256` and `Ripemd160` are BOTH Rúnar type names and Rúnar builtin names.
// The TypeScript and Ruby Go-surface parsers listed them in their type-cast
// table, and the cast branch was tried BEFORE the builtin table, so
// `runar.Sha256(preimage)` in *call* position resolved to an identity cast:
// the ANF binding became `h = load_const @ref:t0` and the hash opcode was
// never emitted. `assert(sha256(preimage) == storedDigest)` compiled to
// `assert(preimage == storedDigest)`.
//
// That is a fund bug, not a style bug, and a hex diff cannot say so: the
// absence of `a8` in a byte string is not an unlock. These tests spend the
// miscompiled script on the go-sdk consensus interpreter and assert the thing
// that actually costs money -- that the PUBLICLY KNOWN DIGEST is accepted as
// the preimage. Pre-fix both DIGEST rows below accept (the script is
// `x == storedDigest`, and the attacker simply pushes storedDigest). Post-fix
// both reject and only the real preimage spends.
//
// The compiler under test is TypeScript (one of the two defective tiers); the
// interpreter is the go-sdk consensus engine; the expected digests are
// computed by Go's crypto/sha256 and golang.org/x/crypto/ripemd160. Three
// independent implementations, none of them grading its own output.
//
// The cross-tier half of the same defect (5 tiers emitted the opcode, 2 did
// not, on byte-identical source) is gated by
// conformance/subtype-parity/GoHashSpelling.runar.go, which every tier must
// accept AND compile to byte-identical hex.
// ---------------------------------------------------------------------------

// goHashSpellingSource builds a stateless Go-surface contract whose single
// public method asserts `<call>(preimage) == c.Expected`, with the digest
// baked into the locking script as the one constructor arg.
//
// `call` is passed as the literal Go-surface spelling so each row of the table
// below is exactly the text a contract author would write.
func goHashSpellingSource(structName, call string) string {
	return fmt.Sprintf(`package contract

import runar "github.com/icellan/runar/packages/runar-go"

type %[1]s struct {
	runar.SmartContract
	Expected runar.ByteString `+"`runar:\"readonly\"`"+`
}

func (c *%[1]s) Check(preimage runar.ByteString) {
	h := runar.%[2]s(preimage)
	runar.Assert(h == c.Expected)
}
`, structName, call)
}

// spendGoHashSpelling compiles the Go-surface contract with `digest` baked in
// and spends it with `push`. Reports whether the consensus interpreter
// ACCEPTED.
func spendGoHashSpelling(t *testing.T, structName, call string, digest, push []byte) bool {
	t.Helper()
	src := goHashSpellingSource(structName, call)
	args := `{"expected":"` + hex.EncodeToString(digest) + `"}`
	lockingHex, err := compileRúnarInline(src, args, structName+".runar.go")
	if err != nil {
		t.Fatalf("compiling runar.%s: %v", call, err)
	}
	// One public method, so there is no method selector to push.
	return executeScript(lockingHex, encodePushBytes(push)) == nil
}

// assertHashSpellingIsRealHash is the whole point of the file: for a Go-surface
// hash spelling, the preimage spends and the digest does not.
func assertHashSpellingIsRealHash(t *testing.T, structName, call string, digestOf func([]byte) []byte) {
	t.Helper()
	preimage := []byte("runar go-surface hash spelling")
	digest := digestOf(preimage)

	// The teeth first, so a regression reports the fund bug rather than the
	// symptom. Under the identity-cast miscompile the locking script is
	// `<pushed> == storedDigest`, and storedDigest is in the locking script
	// itself: anyone who can read the chain can spend it.
	if spendGoHashSpelling(t, structName, call, digest, digest) {
		t.Fatalf("runar.%s: the DIGEST unlocked the contract — the hash opcode "+
			"is not being applied, so the public digest is the spending key", call)
	}

	if !spendGoHashSpelling(t, structName, call, digest, preimage) {
		t.Fatalf("runar.%s: the preimage of the baked digest was REJECTED — "+
			"the contract cannot be spent by its rightful owner", call)
	}

	// A near miss, so the row above cannot pass on a script that refuses
	// everything.
	other := digestOf([]byte("not the preimage"))
	if spendGoHashSpelling(t, structName, call, digest, other) {
		t.Fatalf("runar.%s: an unrelated digest unlocked the contract", call)
	}
}

func TestGoSurface_Sha256Spelling_IsAHashNotACast(t *testing.T) {
	assertHashSpellingIsRealHash(t, "GoSha256Spelling", "Sha256", func(b []byte) []byte {
		d := sha256.Sum256(b)
		return d[:]
	})
}

func TestGoSurface_Ripemd160Spelling_IsAHashNotACast(t *testing.T) {
	assertHashSpellingIsRealHash(t, "GoRipemd160Spelling", "Ripemd160", func(b []byte) []byte {
		h := ripemd160.New()
		h.Write(b)
		return h.Sum(nil)
	})
}

// The unambiguous spellings must keep working, or the fix could "pass" by
// breaking hashing altogether.
func TestGoSurface_UnambiguousHashSpellings_StillHash(t *testing.T) {
	assertHashSpellingIsRealHash(t, "GoSha256HashSpelling", "Sha256Hash", func(b []byte) []byte {
		d := sha256.Sum256(b)
		return d[:]
	})
	assertHashSpellingIsRealHash(t, "GoHash160Spelling", "Hash160", func(b []byte) []byte {
		d := sha256.Sum256(b)
		h := ripemd160.New()
		h.Write(d[:])
		return h.Sum(nil)
	})
}

// The opcode has to actually be in the bytes. This is the cheap direct read of
// the same defect, kept beside the execution rows so a future regression names
// itself instead of only showing up as "the digest spends".
func TestGoSurface_HashSpellings_EmitTheirOpcode(t *testing.T) {
	for _, c := range []struct {
		call   string
		opcode string // OP_SHA256 = a8, OP_RIPEMD160 = a6, OP_HASH160 = a9
	}{
		{"Sha256", "a8"},
		{"Sha256Hash", "a8"},
		{"Ripemd160", "a6"},
		{"Hash160", "a9"},
	} {
		t.Run(c.call, func(t *testing.T) {
			src := goHashSpellingSource("GoOpcode"+c.call, c.call)
			lockingHex, err := compileRúnarInline(src, `{"expected":"`+strings.Repeat("00", 32)+`"}`, "GoOpcode"+c.call+".runar.go")
			if err != nil {
				t.Fatalf("compiling runar.%s: %v", c.call, err)
			}
			// The hash is the script's first act on the one unlocking push, so
			// its opcode is the script's first byte. A `Contains` check would
			// also match the baked digest's own bytes.
			if !strings.HasPrefix(lockingHex, c.opcode) {
				t.Fatalf("runar.%s did not emit %s as the script's first opcode — "+
					"the call was lowered to an identity binding.\nhex: %s",
					c.call, c.opcode, lockingHex)
			}
		})
	}
}
