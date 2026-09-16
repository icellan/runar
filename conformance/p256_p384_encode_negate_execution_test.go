package conformance

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// Executed coverage for pNNNNegate and pNNNEncodeCompressed, on the
// p256-encode-negate / p384-encode-negate FIXTURES' own compiled bytes.
//
// WHY THIS FILE EXISTS. All four builtins were among the 30 of runar-lang's
// 105 `export function`s that appeared in ZERO fixtures' expected-ir.json and
// that the fuzzer cannot generate. The pre-existing `pNNN-primitives` fixtures
// cover Add / Mul / MulGen / OnCurve and stop there, so seven compilers
// shipped negate and compress with no cross-tier byte comparison and nothing
// that ever ran them.
//
// The compression half is where the money is. CL-BUG-095 lived exactly here:
// the parity byte used to be read from the blob's LAST byte instead of a fixed
// offset, so appending ONE byte flipped the sign of the compressed encoding --
// the same point compressing to 02||x or 03||x at the caller's choice, and
// anything that hashes a compressed pubkey (a P2PKH address, a commitment)
// became forgeable between the two spellings. The fix verifies the width and
// reads parity from a fixed offset; until this file, no test stood on it.
//
// Curve arithmetic here is written from the NIST parameters in plain
// math/big -- an implementation independent of the one under test.
// ---------------------------------------------------------------------------

// nistCurve is a short-Weierstrass curve y^2 = x^3 - 3x + b over F_p.
type nistCurve struct {
	p          *big.Int
	b          *big.Int
	gx, gy     *big.Int
	coordBytes int
}

func hexInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex int: " + s)
	}
	return n
}

var p256Curve = &nistCurve{
	p:          hexInt("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
	b:          hexInt("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
	gx:         hexInt("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
	gy:         hexInt("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
	coordBytes: 32,
}

var p384Curve = &nistCurve{
	p: hexInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe" +
		"ffffffff0000000000000000ffffffff"),
	b: hexInt("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a" +
		"c656398d8a2ed19d2a85c8edd3ec2aef"),
	gx: hexInt("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38" +
		"5502f25dbf55296c3a545e3872760ab7"),
	gy: hexInt("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0" +
		"0a60b1ce1d7e819d7a431d7c90ea0e5f"),
	coordBytes: 48,
}

type ecPoint struct{ x, y *big.Int }

func (c *nistCurve) mod(v *big.Int) *big.Int { return new(big.Int).Mod(v, c.p) }

func (c *nistCurve) add(a, b *ecPoint) *ecPoint {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if a.x.Cmp(b.x) == 0 && c.mod(new(big.Int).Add(a.y, b.y)).Sign() == 0 {
		return nil
	}
	var lam *big.Int
	if a.x.Cmp(b.x) == 0 {
		num := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(a.x, a.x))
		num.Sub(num, big.NewInt(3))
		den := new(big.Int).Mul(big.NewInt(2), a.y)
		lam = c.mod(new(big.Int).Mul(num, new(big.Int).ModInverse(c.mod(den), c.p)))
	} else {
		num := new(big.Int).Sub(b.y, a.y)
		den := new(big.Int).Sub(b.x, a.x)
		lam = c.mod(new(big.Int).Mul(num, new(big.Int).ModInverse(c.mod(den), c.p)))
	}
	x3 := c.mod(new(big.Int).Sub(new(big.Int).Mul(lam, lam), new(big.Int).Add(a.x, b.x)))
	y3 := c.mod(new(big.Int).Sub(new(big.Int).Mul(lam, new(big.Int).Sub(a.x, x3)), a.y))
	return &ecPoint{x3, y3}
}

func (c *nistCurve) mul(k *big.Int, p *ecPoint) *ecPoint {
	var r *ecPoint
	acc := p
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			r = c.add(r, acc)
		}
		acc = c.add(acc, acc)
	}
	return r
}

func (c *nistCurve) g() *ecPoint { return &ecPoint{new(big.Int).Set(c.gx), new(big.Int).Set(c.gy)} }

func (c *nistCurve) negate(p *ecPoint) *ecPoint {
	return &ecPoint{new(big.Int).Set(p.x), c.mod(new(big.Int).Sub(c.p, p.y))}
}

// coord renders one coordinate as fixed-width big-endian, the Point wire form.
func (c *nistCurve) coord(v *big.Int) string {
	b := make([]byte, c.coordBytes)
	v.FillBytes(b)
	return hex.EncodeToString(b)
}

// blob renders a point as the x||y wire form the builtins consume.
func (c *nistCurve) blob(p *ecPoint) string { return c.coord(p.x) + c.coord(p.y) }

// compress renders the 02/03||x form pNNNEncodeCompressed must produce.
func (c *nistCurve) compress(p *ecPoint) string {
	prefix := "02"
	if p.y.Bit(0) == 1 {
		prefix = "03"
	}
	return prefix + c.coord(p.x)
}

// encodeNegateMethod indexes the fixtures' public methods in declaration order.
const (
	enCheckNegate           = 0
	enCheckEncode           = 1
	enCheckNegateThenEncode = 2
)

// spendEncodeNegate compiles the named fixture with `expectedCompressed` baked
// in and spends `method`. Returns whether the consensus interpreter ACCEPTED.
func spendEncodeNegate(t *testing.T, fixture string, expectedCompressed string, method int, pushes ...string) bool {
	t.Helper()
	lockingHex, err := compileRúnar(fixture, `{"expectedCompressed":"`+expectedCompressed+`"}`)
	if err != nil {
		t.Fatalf("compile %s: %v", fixture, err)
	}
	unlocking := ""
	for _, p := range pushes {
		unlocking += p
	}
	unlocking += encodePushInt(int64(method))
	return executeScript(lockingHex, unlocking) == nil
}

func pushHex(t *testing.T, h string) string {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("bad hex %q: %v", h, err)
	}
	return encodePushBytes(b)
}

// runEncodeNegateSuite is the whole battery, parameterised by curve. P-256 and
// P-384 share one codegen path with different widths, so the interesting
// question is whether the WIDTHS are right -- which means running both.
func runEncodeNegateSuite(t *testing.T, fixture string, c *nistCurve) {
	g := c.g()
	q := c.mul(big.NewInt(0x1234567890abcdef), g)
	negG := c.negate(g)
	negQ := c.negate(q)
	zero := c.coord(big.NewInt(0))

	// The baked constructor arg: compress(negate(G)).
	baked := c.compress(negG)

	t.Run("negate/G", func(t *testing.T) {
		if !spendEncodeNegate(t, fixture, baked, enCheckNegate,
			pushHex(t, c.blob(g)), pushHex(t, c.blob(negG))) {
			t.Fatal("negate(G) was rejected on its own correct result")
		}
	})

	t.Run("negate/derived point", func(t *testing.T) {
		if !spendEncodeNegate(t, fixture, baked, enCheckNegate,
			pushHex(t, c.blob(q)), pushHex(t, c.blob(negQ))) {
			t.Fatal("negate(Q) was rejected on its own correct result")
		}
	})

	t.Run("negate/is an involution", func(t *testing.T) {
		if !spendEncodeNegate(t, fixture, baked, enCheckNegate,
			pushHex(t, c.blob(negG)), pushHex(t, c.blob(g))) {
			t.Fatal("negate(negate(G)) != G")
		}
	})

	// y == 0 is the reduction boundary: p - 0 is p, which is NOT a field
	// element. A negate that forgot to reduce would return (x, p) here and
	// hand every downstream canonicity check a value outside the field.
	t.Run("negate/y=0 reduces to 0, not to p", func(t *testing.T) {
		in := c.coord(c.gx) + zero
		if !spendEncodeNegate(t, fixture, baked, enCheckNegate,
			pushHex(t, in), pushHex(t, in)) {
			t.Fatal("negate((x,0)) did not return (x,0)")
		}
		if spendEncodeNegate(t, fixture, baked, enCheckNegate,
			pushHex(t, in), pushHex(t, c.coord(c.gx)+c.coord(c.p))) {
			t.Fatal("negate((x,0)) returned (x,p) -- the subtraction is not reduced")
		}
	})

	// Non-canonical coordinates. cEmitCoordCanonVerify must abort; if it ever
	// stops doing so, two spellings of one residue both become acceptable.
	t.Run("negate/refuses x >= p", func(t *testing.T) {
		in := c.coord(c.p) + c.coord(c.gy)
		out := c.coord(c.p) + c.coord(c.mod(new(big.Int).Sub(c.p, c.gy)))
		if spendEncodeNegate(t, fixture, baked, enCheckNegate, pushHex(t, in), pushHex(t, out)) {
			t.Fatal("negate accepted a non-canonical x (x == p)")
		}
	})
	t.Run("negate/refuses y >= p", func(t *testing.T) {
		in := c.coord(c.gx) + c.coord(c.p)
		if spendEncodeNegate(t, fixture, baked, enCheckNegate,
			pushHex(t, in), pushHex(t, c.coord(c.gx)+zero)) {
			t.Fatal("negate accepted a non-canonical y (y == p)")
		}
	})

	// Width. CL-BUG-095's other half: an over-length blob used to have its
	// surplus silently discarded.
	t.Run("negate/refuses an over-length blob", func(t *testing.T) {
		if spendEncodeNegate(t, fixture, baked, enCheckNegate,
			pushHex(t, c.blob(g)+"ff"), pushHex(t, c.blob(negG))) {
			t.Fatal("negate accepted a point with one byte appended")
		}
	})
	t.Run("negate/refuses an under-length blob", func(t *testing.T) {
		if spendEncodeNegate(t, fixture, baked, enCheckNegate,
			pushHex(t, c.blob(g)[2:]), pushHex(t, c.blob(negG))) {
			t.Fatal("negate accepted a point one byte short")
		}
	})

	// --- compression ---

	// Both parities, so a flipped prefix cannot pass either row: G and -G have
	// opposite y parity by construction.
	t.Run("encode/G", func(t *testing.T) {
		if !spendEncodeNegate(t, fixture, baked, enCheckEncode,
			pushHex(t, c.blob(g)), pushHex(t, c.compress(g))) {
			t.Fatal("compress(G) was rejected on its own correct result")
		}
	})
	t.Run("encode/-G has the other prefix", func(t *testing.T) {
		if c.compress(g)[:2] == c.compress(negG)[:2] {
			t.Fatal("test setup: G and -G must have opposite parity")
		}
		if !spendEncodeNegate(t, fixture, baked, enCheckEncode,
			pushHex(t, c.blob(negG)), pushHex(t, c.compress(negG))) {
			t.Fatal("compress(-G) was rejected on its own correct result")
		}
	})
	t.Run("encode/derived point", func(t *testing.T) {
		if !spendEncodeNegate(t, fixture, baked, enCheckEncode,
			pushHex(t, c.blob(q)), pushHex(t, c.compress(q))) {
			t.Fatal("compress(Q) was rejected on its own correct result")
		}
	})

	// Teeth: the flipped prefix must be refused for both parities.
	t.Run("encode/refuses a flipped prefix", func(t *testing.T) {
		flip := func(s string) string {
			if s[:2] == "02" {
				return "03" + s[2:]
			}
			return "02" + s[2:]
		}
		for name, p := range map[string]*ecPoint{"G": g, "-G": negG} {
			if spendEncodeNegate(t, fixture, baked, enCheckEncode,
				pushHex(t, c.blob(p)), pushHex(t, flip(c.compress(p)))) {
				t.Fatalf("compress(%s) accepted the opposite parity prefix", name)
			}
		}
	})

	// CL-BUG-095 ITSELF. Appending one byte used to move the parity source and
	// flip the sign of the encoding. Today the width gate aborts first, so the
	// spend must be refused whichever prefix is claimed.
	t.Run("encode/CL-BUG-095: one appended byte", func(t *testing.T) {
		for _, suffix := range []string{"00", "ff", "01"} {
			for _, want := range []string{"02", "03"} {
				if spendEncodeNegate(t, fixture, baked, enCheckEncode,
					pushHex(t, c.blob(g)+suffix), pushHex(t, want+c.coord(c.gx))) {
					t.Fatalf("compress accepted a point with %q appended, claiming prefix %s", suffix, want)
				}
			}
		}
	})

	t.Run("encode/refuses an under-length blob", func(t *testing.T) {
		if spendEncodeNegate(t, fixture, baked, enCheckEncode,
			pushHex(t, c.blob(g)[2:]), pushHex(t, c.compress(g))) {
			t.Fatal("compress accepted a point one byte short")
		}
	})

	// --- composed, against the baked constructor arg ---

	t.Run("negate-then-encode/matches the baked value", func(t *testing.T) {
		if !spendEncodeNegate(t, fixture, baked, enCheckNegateThenEncode, pushHex(t, c.blob(g))) {
			t.Fatal("compress(negate(G)) did not match the baked compress(-G)")
		}
	})
	t.Run("negate-then-encode/G itself does not match", func(t *testing.T) {
		// compress(negate(G)) != compress(G): the composition must actually
		// negate, not pass the point through.
		if spendEncodeNegate(t, fixture, c.compress(g), enCheckNegateThenEncode, pushHex(t, c.blob(g))) {
			t.Fatal("compress(negate(G)) equalled compress(G) -- the negation is a no-op")
		}
	})
}

func TestP256_EncodeNegate_Boundaries(t *testing.T) {
	runEncodeNegateSuite(t, "p256-encode-negate", p256Curve)
}

func TestP384_EncodeNegate_Boundaries(t *testing.T) {
	runEncodeNegateSuite(t, "p384-encode-negate", p384Curve)
}
