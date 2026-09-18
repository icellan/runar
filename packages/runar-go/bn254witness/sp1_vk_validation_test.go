package bn254witness_test

// Tests for the verifying-key curve-membership guards in
// LoadSP1VKFromFile (R-159).
//
// The loader used to check only that the JSON parsed, that curve=="bn254",
// that numPubInputs>0 and that len(ic)==numPubInputs+1. Nothing established
// that the key's own points were on their curve, in the prime-order
// subgroup, or non-degenerate — while the SAME repository already applies
// on-curve checks to every prover-supplied point
// (compilers/go/codegen/bn254_groth16.go: emitWAG1OnCurveCheck /
// emitWAG2OnCurveCheck / emitWAG2SubgroupCheck). These tests pin the
// asymmetry closed.

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"

	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// vkFieldModulus is the BN254 base field modulus p.
func vkFieldModulus() *big.Int {
	return fp.Modulus()
}

// readVKJSON loads the real SP1 v6.0.0 fixture as a generic JSON map so
// individual fields can be corrupted one at a time.
func readVKJSON(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(sp1FixtureDir(t), "vk.json"))
	if err != nil {
		t.Fatalf("read fixture vk.json: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal fixture vk.json: %v", err)
	}
	return m
}

// writeVK serialises a (possibly corrupted) VK map to a temp file and
// returns its path.
func writeVK(t *testing.T, m map[string]any) string {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal mutated vk: %v", err)
	}
	path := filepath.Join(t.TempDir(), "vk.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write mutated vk: %v", err)
	}
	return path
}

// setPoint replaces a whole named point object in the VK map.
func setPoint(m map[string]any, field string, coords map[string]any) {
	m[field] = coords
}

// bumpCoord adds delta to one decimal-string coordinate of a named point.
func bumpCoord(t *testing.T, m map[string]any, field, coord string, delta *big.Int) {
	t.Helper()
	pt, ok := m[field].(map[string]any)
	if !ok {
		t.Fatalf("field %q is not an object", field)
	}
	s, ok := pt[coord].(string)
	if !ok {
		t.Fatalf("%s.%s is not a string", field, coord)
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("%s.%s is not decimal: %q", field, coord, s)
	}
	pt[coord] = new(big.Int).Add(v, delta).String()
}

func mustReject(t *testing.T, path, what string) {
	t.Helper()
	_, err := bn254witness.LoadSP1VKFromFile(path)
	if err == nil {
		t.Fatalf("LoadSP1VKFromFile accepted %s — expected rejection", what)
	}
	t.Logf("rejected %s: %v", what, err)
}

// mustRejectBecause additionally pins WHICH guard did the rejecting, via a
// substring of the error. This matters where two guards overlap: an off-curve
// G2 point is also refused by the subgroup test, so without pinning the
// diagnosis the on-curve G2 guard would be unfalsifiable — deleting it would
// leave every test green while off-curve garbage got handed to
// G2Affine.IsInSubGroup, a routine whose contract only covers on-curve input.
func mustRejectBecause(t *testing.T, path, what, wantSubstr string) {
	t.Helper()
	_, err := bn254witness.LoadSP1VKFromFile(path)
	if err == nil {
		t.Fatalf("LoadSP1VKFromFile accepted %s — expected rejection", what)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("rejected %s, but not by the expected guard: want error containing %q, got: %v",
			what, wantSubstr, err)
	}
	t.Logf("rejected %s: %v", what, err)
}

// --- control: the real production keys must still load -------------------

// TestLoadSP1VK_RealKeysStillLoad is the over-strictness control. Both real
// SP1 v6.0.0 verifying keys checked into the repo must load, and every point
// in them must independently satisfy the properties the loader now enforces.
func TestLoadSP1VK_RealKeysStillLoad(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	repoRoot := filepath.Join(wd, "..", "..", "..")
	paths := []string{
		filepath.Join(repoRoot, "tests", "vectors", "sp1", "v6.0.0", "vk.json"),
		filepath.Join(repoRoot, "examples", "go", "SP1Verifier.groth16.vk.json"),
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("real VK fixture %s missing: %v", p, err)
		}
		vk, err := bn254witness.LoadSP1VKFromFile(p)
		if err != nil {
			t.Fatalf("real production VK %s was REJECTED by the loader: %v", p, err)
		}

		// Independent restatement of the invariants, so this control has
		// teeth even if the loader's own helpers were wrong.
		var alpha bn254.G1Affine
		alpha.X.SetBigInt(vk.AlphaG1[0])
		alpha.Y.SetBigInt(vk.AlphaG1[1])
		if alpha.IsInfinity() || !alpha.IsOnCurve() {
			t.Fatalf("%s: alphaG1 is not a valid non-zero G1 point", p)
		}
		for name, g2 := range map[string][4]*big.Int{
			"betaNegG2":  vk.BetaNegG2,
			"gammaNegG2": vk.GammaNegG2,
			"deltaNegG2": vk.DeltaNegG2,
		} {
			var q bn254.G2Affine
			q.X.A0.SetBigInt(g2[0])
			q.X.A1.SetBigInt(g2[1])
			q.Y.A0.SetBigInt(g2[2])
			q.Y.A1.SetBigInt(g2[3])
			if q.IsInfinity() || !q.IsOnCurve() || !q.IsInSubGroup() {
				t.Fatalf("%s: %s is not a valid non-zero subgroup G2 point", p, name)
			}
		}
		for i, ic := range vk.IC {
			var g bn254.G1Affine
			g.X.SetBigInt(ic[0])
			g.Y.SetBigInt(ic[1])
			if !g.IsOnCurve() {
				t.Fatalf("%s: ic[%d] is not on G1", p, i)
			}
		}
	}
}

// --- zero / point-at-infinity -------------------------------------------

func TestLoadSP1VK_RejectsZeroGamma(t *testing.T) {
	m := readVKJSON(t)
	setPoint(m, "gammaNegG2", map[string]any{"x0": "0", "x1": "0", "y0": "0", "y1": "0"})
	mustReject(t, writeVK(t, m), "gammaNegG2 = (0,0,0,0)")
}

func TestLoadSP1VK_RejectsZeroDelta(t *testing.T) {
	m := readVKJSON(t)
	setPoint(m, "deltaNegG2", map[string]any{"x0": "0", "x1": "0", "y0": "0", "y1": "0"})
	mustReject(t, writeVK(t, m), "deltaNegG2 = (0,0,0,0)")
}

func TestLoadSP1VK_RejectsZeroBeta(t *testing.T) {
	m := readVKJSON(t)
	setPoint(m, "betaNegG2", map[string]any{"x0": "0", "x1": "0", "y0": "0", "y1": "0"})
	mustReject(t, writeVK(t, m), "betaNegG2 = (0,0,0,0)")
}

func TestLoadSP1VK_RejectsZeroAlpha(t *testing.T) {
	m := readVKJSON(t)
	setPoint(m, "alphaG1", map[string]any{"x": "0", "y": "0"})
	mustReject(t, writeVK(t, m), "alphaG1 = (0,0)")
}

// --- off-curve -----------------------------------------------------------

func TestLoadSP1VK_RejectsOffCurveG1(t *testing.T) {
	m := readVKJSON(t)
	bumpCoord(t, m, "alphaG1", "y", big.NewInt(1)) // y+1 is off the curve
	mustReject(t, writeVK(t, m), "alphaG1 off the G1 curve")
}

func TestLoadSP1VK_RejectsOffCurveG2(t *testing.T) {
	m := readVKJSON(t)
	bumpCoord(t, m, "gammaNegG2", "y0", big.NewInt(1))
	mustRejectBecause(t, writeVK(t, m),
		"gammaNegG2 off the G2 twist curve", "is not on the BN254 G2 twist curve")
}

func TestLoadSP1VK_RejectsOffCurveIC(t *testing.T) {
	m := readVKJSON(t)
	ic, ok := m["ic"].([]any)
	if !ok || len(ic) == 0 {
		t.Fatalf("fixture ic is not a non-empty array")
	}
	pt := ic[2].(map[string]any)
	y, _ := new(big.Int).SetString(pt["y"].(string), 10)
	pt["y"] = new(big.Int).Add(y, big.NewInt(1)).String()
	mustReject(t, writeVK(t, m), "ic[2] off the G1 curve")
}

// --- subgroup ------------------------------------------------------------

// nonSubgroupG2 returns a point that IS on the BN254 G2 twist curve but is
// NOT in the prime-order r subgroup. The twist has a large cofactor, so a
// point found by solving the curve equation for a small x almost never lands
// in the subgroup — the search below asserts that it did not.
func nonSubgroupG2(t *testing.T) (x0, x1, y0, y1 *big.Int) {
	t.Helper()
	var one, b bn254.E2
	one.SetOne()
	b.MulBybTwistCurveCoeff(&one)

	for c := uint64(1); c < 200; c++ {
		var x bn254.E2
		x.A0.SetUint64(c)
		x.A1.SetZero()

		var rhs bn254.E2
		rhs.Square(&x).Mul(&rhs, &x).Add(&rhs, &b)
		if rhs.Legendre() != 1 {
			continue
		}
		var y bn254.E2
		y.Sqrt(&rhs)

		var q bn254.G2Affine
		q.X.Set(&x)
		q.Y.Set(&y)
		if !q.IsOnCurve() || q.IsInfinity() {
			continue
		}
		if q.IsInSubGroup() {
			continue
		}
		var a0, a1, b0, b1 big.Int
		q.X.A0.BigInt(&a0)
		q.X.A1.BigInt(&a1)
		q.Y.A0.BigInt(&b0)
		q.Y.A1.BigInt(&b1)
		return &a0, &a1, &b0, &b1
	}
	t.Fatalf("could not construct an on-curve, non-subgroup G2 point")
	return nil, nil, nil, nil
}

func TestLoadSP1VK_RejectsNonSubgroupG2(t *testing.T) {
	x0, x1, y0, y1 := nonSubgroupG2(t)
	m := readVKJSON(t)
	setPoint(m, "gammaNegG2", map[string]any{
		"x0": x0.String(), "x1": x1.String(),
		"y0": y0.String(), "y1": y1.String(),
	})
	mustRejectBecause(t, writeVK(t, m),
		"gammaNegG2 on-curve but outside the r-order subgroup",
		"outside the prime-order (r) subgroup")
}

// --- coordinate range ----------------------------------------------------

// A coordinate >= p is silently reduced mod p by fp.Element.SetBigInt, so the
// key gnark validates is not the key the compiler pushes into the script
// (VerifyingKey stores the raw big.Int). Adding p to a valid coordinate keeps
// the point on-curve and in-subgroup after reduction, so ONLY the range guard
// can reject this input.
func TestLoadSP1VK_RejectsOutOfRangeG1Coordinate(t *testing.T) {
	m := readVKJSON(t)
	bumpCoord(t, m, "alphaG1", "x", vkFieldModulus())
	mustReject(t, writeVK(t, m), "alphaG1.x >= p (congruent but non-canonical)")
}

func TestLoadSP1VK_RejectsOutOfRangeG2Coordinate(t *testing.T) {
	m := readVKJSON(t)
	bumpCoord(t, m, "deltaNegG2", "x1", vkFieldModulus())
	mustReject(t, writeVK(t, m), "deltaNegG2.x1 >= p (congruent but non-canonical)")
}

// Guard against a lazy "reject everything" fix: the error messages must name
// the offending field.
func TestLoadSP1VK_ErrorNamesTheField(t *testing.T) {
	m := readVKJSON(t)
	setPoint(m, "deltaNegG2", map[string]any{"x0": "0", "x1": "0", "y0": "0", "y1": "0"})
	_, err := bn254witness.LoadSP1VKFromFile(writeVK(t, m))
	if err == nil {
		t.Fatalf("expected rejection")
	}
	if !strings.Contains(err.Error(), "deltaNegG2") {
		t.Fatalf("error does not name deltaNegG2: %v", err)
	}
}
