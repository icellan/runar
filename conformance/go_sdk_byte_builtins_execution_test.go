package conformance

import (
	"encoding/hex"
	"fmt"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// The five builtins `packages/runar-go` grew: Split, Left, Right, Int2Str and
// Ripemd160.
//
// WHY THIS FILE EXISTS. The `.runar.go` surface parser accepted all five long
// before the SDK declared any of them: `Split`, `Left` and `Right` resolve
// through mapGoBuiltin's default leading-character rule, `Int2Str` through an
// explicit entry, `Ripemd160` through both the type table and the builtin
// table. A contract that called them compiled to Bitcoin Script and did NOT
// build as Go, so 32 of the 84 ports in examples/go carried `//go:build
// ignore` and the dual-compilation check the package exists to provide ran on
// half of them.
//
// Declaring the functions closes that. It does not prove them. A Go `Split`
// that returns the right half because that is what its author typed agrees
// with nothing; `pow` returned base^min(exp,32) for three review rounds while
// every tier agreed with every other tier. So each row below computes the
// result with the SDK mock and then SPENDS the compiled locking script with
// that exact value on the go-sdk consensus interpreter. A disagreement between
// the mock and the opcodes is a rejected spend, not a diff.
//
// Two independent implementations on the two sides of every assertion: the
// compiler under test is TypeScript (compileRúnarInline drives
// packages/runar-compiler), the value under test comes from the Go SDK, and
// the judge is the go-sdk interpreter. None of the three grades its own
// output.
//
// The opcodes these lower to, read off `--asm`, are what makes the four
// byte-slicing builtins distinguishable at all:
//
//	Split(d, n)   OP_SPLIT OP_NIP                       right half at index n
//	Left(d, n)    OP_SPLIT OP_DROP                      leftmost n bytes
//	Right(d, n)   OP_SIZE OP_ROT OP_SUB OP_SPLIT OP_NIP rightmost n bytes
//	Int2Str(v, w) OP_NUM2BIN                            w-byte LE sign-magnitude
//
// Split and Left are the two sides of one cut; Right measures its offset from
// the END. An SDK that confused any pair of them would pass a test that only
// checked "returns a ByteString of a plausible length", which is why every
// case below also spends a NEIGHBOURING value and requires a refusal.
// ---------------------------------------------------------------------------

// goSdkBuiltinSource builds a property-less stateless Go-surface contract
// whose single public method asserts `<call>(a, b) == expected`. One public
// method means there is no method selector to push.
//
// `call` is the literal Go-surface spelling, so each row below is exactly the
// text a contract author would write.
func goSdkBuiltinSource(structName, call, aType string) string {
	return fmt.Sprintf(`package contract

import runar "github.com/icellan/runar/packages/runar-go"

type %[1]s struct {
	runar.SmartContract
}

func (c *%[1]s) Check(a runar.%[3]s, b runar.Int, expected runar.ByteString) {
	runar.Assert(runar.%[2]s(a, b) == expected)
}
`, structName, call, aType)
}

// goSdkUnaryBuiltinSource is the single-argument shape, for Ripemd160.
func goSdkUnaryBuiltinSource(structName, call string) string {
	return fmt.Sprintf(`package contract

import runar "github.com/icellan/runar/packages/runar-go"

type %[1]s struct {
	runar.SmartContract
}

func (c *%[1]s) Check(a runar.ByteString, expected runar.ByteString) {
	runar.Assert(runar.%[2]s(a) == expected)
}
`, structName, call)
}

// compileGoSdkBuiltin compiles one of the sources above once per test.
func compileGoSdkBuiltin(t *testing.T, src, structName string) string {
	t.Helper()
	lockingHex, err := compileRúnarInline(src, `{}`, structName+".runar.go")
	if err != nil {
		t.Fatalf("compiling %s: %v", structName, err)
	}
	return lockingHex
}

// perturb returns a ByteString that is guaranteed to differ from `b`, for the
// near-miss row. Appending a zero byte works for the empty string too, which
// several boundary cases produce -- a perturbation that returned `b` unchanged
// would turn the teeth into a second copy of the positive row.
func perturb(b runar.ByteString) runar.ByteString {
	return b + "\x00"
}

// ---------------------------------------------------------------------------
// Split / Left / Right -- the three byte-slicing builtins.
// ---------------------------------------------------------------------------

func TestGoSdk_ByteSlicingBuiltins_AgreeWithCompiledScript(t *testing.T) {
	data := runar.ByteString("\xaa\xbb\xcc\xdd") // 4 bytes

	for _, b := range []struct {
		name string
		call string
		fn   func(runar.ByteString, int64) runar.ByteString
	}{
		{"Split", "Split", runar.Split},
		{"Left", "Left", runar.Left},
		{"Right", "Right", runar.Right},
	} {
		t.Run(b.name, func(t *testing.T) {
			structName := "GoSdk" + b.name + "Probe"
			lockingHex := compileGoSdkBuiltin(t,
				goSdkBuiltinSource(structName, b.call, "ByteString"), structName)

			// 0 and len are where an off-by-one in the lowering shows up; a
			// middle index is where confusing Split with Left or Right shows
			// up. All three are covered for all three builtins, so no pair of
			// them can swap places and still pass.
			for _, n := range []int64{0, 1, 2, 3, 4} {
				want := b.fn(data, n)

				spend := func(expected runar.ByteString) bool {
					unlocking := encodePushBytes([]byte(data)) +
						encodePushInt(n) +
						encodePushBytes([]byte(expected))
					return executeScript(lockingHex, unlocking) == nil
				}

				if !spend(want) {
					t.Fatalf("%s(%x, %d): the SDK returned %x, which the "+
						"compiled script REFUSED -- the Go mock and the "+
						"opcodes disagree", b.call, data, n, want)
				}
				if spend(perturb(want)) {
					t.Fatalf("%s(%x, %d): the script also accepted %x, so it "+
						"is not checking its argument and the row above "+
						"proves nothing", b.call, data, n, perturb(want))
				}
			}
		})
	}
}

// Split and Left are the two halves of one cut, and Right is measured from the
// other end. Asserting that the three are DISTINCT is what stops the table
// above from passing on an SDK where all three are the same function.
func TestGoSdk_ByteSlicingBuiltins_AreNotEachOther(t *testing.T) {
	data := runar.ByteString("\xaa\xbb\xcc\xdd")
	const n = 1

	split, left, right := runar.Split(data, n), runar.Left(data, n), runar.Right(data, n)
	if split == left || split == right || left == right {
		t.Fatalf("Split=%x Left=%x Right=%x: at index %d these must be three "+
			"different values", split, left, right, n)
	}
	if got, want := split, runar.ByteString("\xbb\xcc\xdd"); got != want {
		t.Fatalf("Split binds the RIGHT half: got %x, want %x", got, want)
	}
	if got, want := left, runar.ByteString("\xaa"); got != want {
		t.Fatalf("Left binds the leftmost n bytes: got %x, want %x", got, want)
	}
	if got, want := right, runar.ByteString("\xdd"); got != want {
		t.Fatalf("Right binds the rightmost n bytes: got %x, want %x", got, want)
	}
}

// ---------------------------------------------------------------------------
// Int2Str -- OP_NUM2BIN, fixed-width little-endian sign-magnitude.
// ---------------------------------------------------------------------------

func TestGoSdk_Int2Str_AgreesWithCompiledScript(t *testing.T) {
	const structName = "GoSdkInt2StrProbe"
	lockingHex := compileGoSdkBuiltin(t,
		goSdkBuiltinSource(structName, "Int2Str", "Int"), structName)

	for _, c := range []struct {
		value int64
		width int64
	}{
		{0, 1}, {0, 4},
		{1, 1}, {1, 4},
		{127, 1}, {128, 2},
		{-1, 1}, {-1, 4}, // the sign bit lives in the LAST byte, not the first
		{-128, 2},
		{65535, 4},
	} {
		t.Run(fmt.Sprintf("v=%d,w=%d", c.value, c.width), func(t *testing.T) {
			want := runar.Int2Str(c.value, c.width)

			spend := func(expected runar.ByteString) bool {
				unlocking := encodePushInt(c.value) +
					encodePushInt(c.width) +
					encodePushBytes([]byte(expected))
				return executeScript(lockingHex, unlocking) == nil
			}

			if !spend(want) {
				t.Fatalf("Int2Str(%d, %d): the SDK returned %s, which the "+
					"compiled OP_NUM2BIN REFUSED", c.value, c.width,
					hex.EncodeToString([]byte(want)))
			}
			if spend(perturb(want)) {
				t.Fatalf("Int2Str(%d, %d): the script accepted a different "+
					"encoding too", c.value, c.width)
			}
			if int64(len(want)) != c.width {
				t.Fatalf("Int2Str(%d, %d) returned %d bytes; OP_NUM2BIN is "+
					"fixed-width", c.value, c.width, len(want))
			}
		})
	}
}

// Int2str (lower-cased `s`) is the spelling examples/go/byte-builtins uses and
// the Go surface parser resolves it through the default rule. It must be the
// same function as Int2Str or one of the two spellings is a silent trap.
func TestGoSdk_Int2StrSpellings_Agree(t *testing.T) {
	for _, c := range []struct{ v, w int64 }{{0, 1}, {1, 4}, {-1, 4}, {65535, 4}} {
		if a, b := runar.Int2Str(c.v, c.w), runar.Int2str(c.v, c.w); a != b {
			t.Fatalf("Int2Str(%d,%d)=%x but Int2str(%d,%d)=%x", c.v, c.w, a, c.v, c.w, b)
		}
	}
}

// ---------------------------------------------------------------------------
// Ripemd160 -- OP_RIPEMD160, and the fail-loud half of the name collision.
// ---------------------------------------------------------------------------

func TestGoSdk_Ripemd160_AgreesWithCompiledScript(t *testing.T) {
	const structName = "GoSdkRipemd160Probe"
	lockingHex := compileGoSdkBuiltin(t,
		goSdkUnaryBuiltinSource(structName, "Ripemd160"), structName)

	preimage := runar.ByteString("runar go-sdk ripemd160 builtin")
	want := runar.Ripemd160(preimage)

	spend := func(expected runar.ByteString) bool {
		unlocking := encodePushBytes([]byte(preimage)) + encodePushBytes([]byte(expected))
		return executeScript(lockingHex, unlocking) == nil
	}

	if !spend(runar.ByteString(want)) {
		t.Fatalf("Ripemd160: the SDK returned %x, which OP_RIPEMD160 REFUSED", want)
	}
	// The teeth that matter for this particular builtin. `Ripemd160` is both a
	// Rúnar type name and a Rúnar builtin name; an SDK that declared it as a
	// TYPE would make runar.Ripemd160(x) a conversion returning x unchanged,
	// and the publicly readable digest would become the spending key. That is
	// the defect two of the seven tiers shipped -- see
	// conformance/go_surface_hash_spelling_execution_test.go. Here the mock is
	// the thing under test, so the check is that it does not return its input.
	if runar.ByteString(want) == preimage {
		t.Fatal("Ripemd160 returned its input -- the SDK is resolving it as an " +
			"identity conversion, not a hash")
	}
	if spend(preimage) {
		t.Fatal("Ripemd160: the PREIMAGE was accepted where the digest belongs")
	}
	if spend(perturb(runar.ByteString(want))) {
		t.Fatal("Ripemd160: a near-miss digest was accepted too")
	}

	// Ripemd160 and Ripemd160Func are one implementation, not two.
	if a, b := runar.Ripemd160(preimage), runar.Ripemd160Func(preimage); a != b {
		t.Fatalf("Ripemd160=%x but Ripemd160Func=%x", a, b)
	}
}

// ---------------------------------------------------------------------------
// Out-of-range arguments.
// ---------------------------------------------------------------------------
//
// At script level OP_SPLIT aborts the entire evaluation when the index is
// negative or past the end, so there is no value the mock could return that
// would be faithful. Substr, which shipped first, panics through Go's own
// slice-bounds check; the three new builtins panic explicitly for the same
// reason. The script side of this boundary is already spent by
// conformance/byte_builtins_execution_test.go ("idx past end", "idx
// negative"); this test pins the mock to the same answer -- refuse -- rather
// than silently clamping.

func TestGoSdk_ByteSlicingBuiltins_RefuseOutOfRange(t *testing.T) {
	data := runar.ByteString("\xaa\xbb\xcc\xdd")

	for _, c := range []struct {
		name string
		fn   func()
	}{
		{"Split negative", func() { runar.Split(data, -1) }},
		{"Split past end", func() { runar.Split(data, 5) }},
		{"Left negative", func() { runar.Left(data, -1) }},
		{"Left past end", func() { runar.Left(data, 5) }},
		{"Right negative", func() { runar.Right(data, -1) }},
		{"Right past end", func() { runar.Right(data, 5) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s: returned a value where consensus aborts", c.name)
				}
			}()
			c.fn()
		})
	}
}
