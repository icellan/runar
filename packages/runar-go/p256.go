// P-256 (NIST P-256 / secp256r1) off-chain helpers for testing Rúnar contracts.
//
// These functions use Go's standard library crypto/ecdsa and crypto/elliptic
// with no external dependencies. They are not compiled into Bitcoin Script —
// they exist so Go contract tests can generate keys, sign messages, and
// perform EC arithmetic using the P-256 curve.
//
// P256Point is a 64-byte ByteString: x[32] || y[32], big-endian, zero-padded.
// This matches the Point convention used for secp256k1 in runar.go / ec.go.
package runar

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// P256Point is a 64-byte ByteString encoding a P-256 point as x[32] || y[32].
// Coordinates are big-endian and zero-padded to 32 bytes each.
type P256Point = ByteString

// P256KeyPair holds a P-256 key pair.
type P256KeyPair struct {
	SK           *ecdsa.PrivateKey
	PK           P256Point // 64-byte uncompressed encoding (x[32] || y[32])
	PKCompressed []byte    // 33-byte compressed encoding (02/03 prefix + x[32])
}

// p256PointFromXY serializes a P-256 (x, y) pair into a 64-byte P256Point.
func p256PointFromXY(x, y *big.Int) P256Point {
	buf := make([]byte, 64)
	xb := x.Bytes()
	yb := y.Bytes()
	copy(buf[32-len(xb):32], xb)
	copy(buf[64-len(yb):64], yb)
	return P256Point(buf)
}

// p256XYFromPoint extracts (x, y) *big.Int from a 64-byte P256Point.
func p256XYFromPoint(p P256Point) (*big.Int, *big.Int) {
	b := []byte(p)
	if len(b) != 64 {
		panic("runar: P256Point must be exactly 64 bytes")
	}
	x := new(big.Int).SetBytes(b[:32])
	y := new(big.Int).SetBytes(b[32:])
	return x, y
}

// P256Keygen generates a random P-256 key pair.
func P256Keygen() P256KeyPair {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("runar: P256Keygen: " + err.Error())
	}
	pk := p256PointFromXY(sk.PublicKey.X, sk.PublicKey.Y)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), sk.PublicKey.X, sk.PublicKey.Y)
	return P256KeyPair{
		SK:           sk,
		PK:           pk,
		PKCompressed: compressed,
	}
}

// P256Sign signs msg with sk using ECDSA on P-256.
// The message is SHA-256 hashed internally before signing.
// Returns a 64-byte raw signature: r[32] || s[32] (big-endian, zero-padded).
func P256Sign(msg []byte, sk *ecdsa.PrivateKey) []byte {
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, sk, digest[:])
	if err != nil {
		panic("runar: P256Sign: " + err.Error())
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

// P256Add adds two P-256 points.
// If either point is the zero point (all-zero bytes), the other is returned.
func P256Add(a, b P256Point) P256Point {
	ax, ay := p256XYFromPoint(a)
	bx, by := p256XYFromPoint(b)
	curve := elliptic.P256()
	rx, ry := curve.Add(ax, ay, bx, by)
	return p256PointFromXY(rx, ry)
}

// P256Mul performs scalar multiplication k * p on the P-256 curve.
func P256Mul(p P256Point, k *big.Int) P256Point {
	px, py := p256XYFromPoint(p)
	curve := elliptic.P256()
	kBytes := k.Bytes()
	rx, ry := curve.ScalarMult(px, py, kBytes)
	return p256PointFromXY(rx, ry)
}

// P256MulGen performs scalar multiplication k * G where G is the P-256 generator.
func P256MulGen(k *big.Int) P256Point {
	curve := elliptic.P256()
	kBytes := k.Bytes()
	rx, ry := curve.ScalarBaseMult(kBytes)
	return p256PointFromXY(rx, ry)
}

// P256Negate returns the negation of a P-256 point: (x, p - y).
func P256Negate(p P256Point) P256Point {
	px, py := p256XYFromPoint(p)
	fieldP := elliptic.P256().Params().P
	negY := new(big.Int).Sub(fieldP, py)
	negY.Mod(negY, fieldP)
	return p256PointFromXY(px, negY)
}

// P256OnCurve reports whether the given point lies on the P-256 curve.
func P256OnCurve(p P256Point) bool {
	px, py := p256XYFromPoint(p)
	// Reject the point at infinity (0, 0) — not a valid curve point.
	if px.Sign() == 0 && py.Sign() == 0 {
		return false
	}
	return elliptic.P256().IsOnCurve(px, py)
}

// P256EncodeCompressed returns the 33-byte compressed encoding of a P-256 point
// (02/03 prefix byte followed by the 32-byte x coordinate, big-endian).
func P256EncodeCompressed(p P256Point) ByteString {
	px, py := p256XYFromPoint(p)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), px, py)
	return ByteString(compressed)
}

// VerifyECDSAP256 verifies a raw ECDSA signature on P-256.
// msg is the raw message — it is SHA-256 hashed internally before verification.
// sig is the 64-byte raw signature (r[32] || s[32]) produced by P256Sign.
// pubkey is the 33-byte compressed public key (02/03 + x[32]).
func VerifyECDSAP256(msg, sig, pubkey ByteString) bool {
	if len(sig) != 64 {
		return false
	}
	digest := sha256.Sum256([]byte(msg))

	// Decode compressed public key.
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), []byte(pubkey))
	if x == nil {
		return false
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	r := new(big.Int).SetBytes([]byte(sig)[:32])
	s := new(big.Int).SetBytes([]byte(sig)[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}
