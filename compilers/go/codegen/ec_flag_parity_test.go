package codegen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Cross-tier parity for the EXPERIMENTAL EC size flags.
//
// The flags default off, so the ordinary conformance suite — which compiles
// with defaults — cannot see them at all. Seven tiers could each ship a
// DIFFERENT --ec-constant-pool and the suite would stay green.
//
// That matters because the flags are not cosmetic: they change which reduction
// form is emitted and which addition formula each ladder round uses. A tier
// that ports the constant pool but not the sign lattice's `Reduced`
// precondition produces a script that is smaller, passes its own tests, and is
// wrong on ecAdd((0,1), (2^256-1,1)). Byte-identical output against a single
// reference is the only cheap check that catches that.
//
// conformance/ec-flag-parity/expected.json is derived from the TypeScript
// reference compiler and re-derived by its own vitest, so it cannot go stale.

type parityEntry struct {
	Bytes  int    `json:"bytes"`
	Sha256 string `json:"sha256"`
}

type parityFixture struct {
	Variants map[string]struct {
		ConstantPool     bool `json:"constantPool"`
		ReductionSinking bool `json:"reductionSinking"`
		FixedBaseComb    bool `json:"fixedBaseComb"`
	} `json:"variants"`
	Emitters map[string]map[string]parityEntry `json:"emitters"`
}

func loadParityFixture(t *testing.T) *parityFixture {
	t.Helper()
	// codegen -> compilers/go -> compilers -> repo root
	path := filepath.Join("..", "..", "..", "conformance", "ec-flag-parity", "expected.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var f parityFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return &f
}

// ecEmittersUnderTest maps the fixture's emitter names to this tier's
// functions. Emitters whose output the flags cannot reach (EcModReduce,
// EcPointX, ...) are deliberately included: a tier that accidentally made them
// flag-sensitive would be diverging just as badly as one that ignored a flag.
func ecEmittersUnderTest() map[string]func(func(StackOp), *EcCodegenOptions) {
	ignore := func(f func(func(StackOp))) func(func(StackOp), *EcCodegenOptions) {
		return func(e func(StackOp), _ *EcCodegenOptions) { f(e) }
	}
	return map[string]func(func(StackOp), *EcCodegenOptions){
		"EcAdd":              EmitEcAdd,
		"EcMul":              EmitEcMul,
		"EcMulGen":           EmitEcMulGen,
		"EcNegate":           EmitEcNegate,
		"EcOnCurve":          EmitEcOnCurve,
		"EcModReduce":        ignore(EmitEcModReduce),
		"EcEncodeCompressed": ignore(EmitEcEncodeCompressed),
		"EcMakePoint":        ignore(EmitEcMakePoint),
		"EcPointX":           ignore(EmitEcPointX),
		"EcPointY":           ignore(EmitEcPointY),

		"P256Add":              EmitP256Add,
		"P256Mul":              EmitP256Mul,
		"P256MulGen":           EmitP256MulGen,
		"P256Negate":           EmitP256Negate,
		"P256OnCurve":          EmitP256OnCurve,
		"P256EncodeCompressed": ignore(EmitP256EncodeCompressed),
		"VerifyECDSA_P256":     EmitVerifyECDSA_P256,

		"P384Add":              EmitP384Add,
		"P384Mul":              EmitP384Mul,
		"P384MulGen":           EmitP384MulGen,
		"P384Negate":           EmitP384Negate,
		"P384OnCurve":          EmitP384OnCurve,
		"P384EncodeCompressed": ignore(EmitP384EncodeCompressed),
		"VerifyECDSA_P384":     EmitVerifyECDSA_P384,
	}
}

func emitAndHash(t *testing.T, emit func(func(StackOp), *EcCodegenOptions), opts *EcCodegenOptions) (int, string) {
	t.Helper()
	var ops []StackOp
	emit(func(op StackOp) { ops = append(ops, op) }, opts)
	res, err := EmitMethod(&StackMethod{Name: "t", Ops: ops})
	if err != nil {
		t.Fatalf("emit failed: %v", err)
	}
	raw, err := hex.DecodeString(res.ScriptHex)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	sum := sha256.Sum256(raw)
	return len(raw), hex.EncodeToString(sum[:])
}

func TestEcFlagParityAgainstTypeScriptReference(t *testing.T) {
	f := loadParityFixture(t)
	emitters := ecEmittersUnderTest()

	for name, emit := range emitters {
		want, ok := f.Emitters[name]
		if !ok {
			t.Fatalf("%s: no entry in the parity fixture", name)
		}
		for variant, spec := range f.Variants {
			expect, ok := want[variant]
			if !ok {
				t.Fatalf("%s/%s: no entry in the parity fixture", name, variant)
			}
			t.Run(fmt.Sprintf("%s/%s", name, variant), func(t *testing.T) {
				opts := &EcCodegenOptions{
					ConstantPool:     spec.ConstantPool,
					ReductionSinking: spec.ReductionSinking,
					FixedBaseComb:    spec.FixedBaseComb,
				}
				gotBytes, gotHash := emitAndHash(t, emit, opts)
				if gotBytes != expect.Bytes || gotHash != expect.Sha256 {
					t.Fatalf("%s under %s: Go emits %d bytes (%s), TS reference emits %d bytes (%s)",
						name, variant, gotBytes, gotHash[:16], expect.Bytes, expect.Sha256[:16])
				}
			})
		}
	}
}

// A nil options pointer must be byte-identical to the shipping output. This is
// what keeps the existing goldens, the size baseline and every cross-tier hex
// comparison from moving while the flags are experimental.
func TestEcFlagsDefaultOffIsByteIdentical(t *testing.T) {
	f := loadParityFixture(t)
	for name, emit := range ecEmittersUnderTest() {
		t.Run(name, func(t *testing.T) {
			var nilOps, offOps []StackOp
			emit(func(op StackOp) { nilOps = append(nilOps, op) }, nil)
			emit(func(op StackOp) { offOps = append(offOps, op) }, &EcCodegenOptions{})
			nilRes, _ := EmitMethod(&StackMethod{Name: "t", Ops: nilOps})
			offRes, _ := EmitMethod(&StackMethod{Name: "t", Ops: offOps})
			if nilRes.ScriptHex != offRes.ScriptHex {
				t.Fatalf("%s: nil options and all-false options disagree", name)
			}
			raw, _ := hex.DecodeString(nilRes.ScriptHex)
			sum := sha256.Sum256(raw)
			if hex.EncodeToString(sum[:]) != f.Emitters[name]["off"].Sha256 {
				t.Fatalf("%s: default output moved", name)
			}
		})
	}
}
