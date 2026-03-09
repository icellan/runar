package runar

import "math/big"

// secp256k1 curve parameters
var (
	ecP, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	ecN, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	ecGX, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	ecGY, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)

// pointToCoords extracts (x, y) big.Ints from a 64-byte Point.
func pointToCoords(p Point) (*big.Int, *big.Int) {
	b := []byte(p)
	if len(b) != 64 {
		panic("runar: Point must be exactly 64 bytes")
	}
	x := new(big.Int).SetBytes(b[:32])
	y := new(big.Int).SetBytes(b[32:])
	return x, y
}

// coordsToPoint serializes (x, y) into a 64-byte Point.
func coordsToPoint(x, y *big.Int) Point {
	buf := make([]byte, 64)
	xb := x.Bytes()
	yb := y.Bytes()
	copy(buf[32-len(xb):32], xb)
	copy(buf[64-len(yb):64], yb)
	return Point(buf)
}

// fieldInv computes modular inverse mod p using Fermat's little theorem.
func fieldInv(a *big.Int) *big.Int {
	// a^(p-2) mod p
	exp := new(big.Int).Sub(ecP, big.NewInt(2))
	return new(big.Int).Exp(a, exp, ecP)
}

// ecAddCoords performs point addition on secp256k1.
func ecAddCoords(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	// Point at infinity checks (represented by (0, 0))
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}

	// Check for point + (-point) = infinity
	ySum := new(big.Int).Add(y1, y2)
	ySum.Mod(ySum, ecP)
	if x1.Cmp(x2) == 0 && ySum.Sign() == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	var slope *big.Int
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		// Point doubling: slope = (3*x1^2) / (2*y1)
		num := new(big.Int).Mul(x1, x1)
		num.Mul(num, big.NewInt(3))
		num.Mod(num, ecP)
		den := new(big.Int).Mul(big.NewInt(2), y1)
		den.Mod(den, ecP)
		slope = new(big.Int).Mul(num, fieldInv(den))
		slope.Mod(slope, ecP)
	} else {
		// Point addition: slope = (y2-y1) / (x2-x1)
		num := new(big.Int).Sub(y2, y1)
		num.Mod(num, ecP)
		den := new(big.Int).Sub(x2, x1)
		den.Mod(den, ecP)
		slope = new(big.Int).Mul(num, fieldInv(den))
		slope.Mod(slope, ecP)
	}

	// rx = slope^2 - x1 - x2
	rx := new(big.Int).Mul(slope, slope)
	rx.Sub(rx, x1)
	rx.Sub(rx, x2)
	rx.Mod(rx, ecP)

	// ry = slope * (x1 - rx) - y1
	ry := new(big.Int).Sub(x1, rx)
	ry.Mul(ry, slope)
	ry.Sub(ry, y1)
	ry.Mod(ry, ecP)

	return rx, ry
}

// scalarMulCoords performs scalar multiplication using double-and-add.
func scalarMulCoords(bx, by *big.Int, k *big.Int) (*big.Int, *big.Int) {
	// Reduce k mod n
	k = new(big.Int).Mod(k, ecN)
	if k.Sign() < 0 {
		k.Add(k, ecN)
	}
	if k.Sign() == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	rx, ry := big.NewInt(0), big.NewInt(0) // point at infinity
	started := false

	for i := k.BitLen() - 1; i >= 0; i-- {
		if started {
			rx, ry = ecAddCoords(rx, ry, rx, ry) // double
		}
		if k.Bit(i) == 1 {
			if !started {
				rx = new(big.Int).Set(bx)
				ry = new(big.Int).Set(by)
				started = true
			} else {
				rx, ry = ecAddCoords(rx, ry, bx, by) // add
			}
		}
	}
	return rx, ry
}

// EcAdd performs point addition on secp256k1.
func EcAdd(a, b Point) Point {
	ax, ay := pointToCoords(a)
	bx, by := pointToCoords(b)
	rx, ry := ecAddCoords(ax, ay, bx, by)
	return coordsToPoint(rx, ry)
}

// EcMul performs scalar multiplication: k * P.
func EcMul(p Point, k Bigint) Point {
	px, py := pointToCoords(p)
	rx, ry := scalarMulCoords(px, py, big.NewInt(k))
	return coordsToPoint(rx, ry)
}

// EcMulGen performs scalar multiplication with the generator: k * G.
func EcMulGen(k Bigint) Point {
	rx, ry := scalarMulCoords(ecGX, ecGY, big.NewInt(k))
	return coordsToPoint(rx, ry)
}

// EcNegate returns the negated point (x, p - y).
func EcNegate(p Point) Point {
	px, py := pointToCoords(p)
	negY := new(big.Int).Sub(ecP, py)
	negY.Mod(negY, ecP)
	return coordsToPoint(px, negY)
}

// EcOnCurve checks if a point is on the secp256k1 curve: y^2 = x^3 + 7 (mod p).
func EcOnCurve(p Point) bool {
	x, y := pointToCoords(p)
	// y^2 mod p
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, ecP)
	// x^3 + 7 mod p
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, big.NewInt(7))
	rhs.Mod(rhs, ecP)
	return lhs.Cmp(rhs) == 0
}

// EcModReduce computes non-negative modular reduction: ((value % m) + m) % m.
func EcModReduce(value, m Bigint) Bigint {
	r := value % m
	if r < 0 {
		r += m
	}
	return r
}

// EcEncodeCompressed encodes a point as a 33-byte compressed public key.
func EcEncodeCompressed(p Point) ByteString {
	x, y := pointToCoords(p)
	buf := make([]byte, 33)
	if new(big.Int).And(y, big.NewInt(1)).Sign() == 0 {
		buf[0] = 0x02
	} else {
		buf[0] = 0x03
	}
	xb := x.Bytes()
	copy(buf[33-len(xb):33], xb)
	return ByteString(buf)
}

// EcMakePoint constructs a Point from two coordinate integers.
func EcMakePoint(x, y Bigint) Point {
	bx := big.NewInt(x)
	by := big.NewInt(y)
	return coordsToPoint(bx, by)
}

// EcPointX extracts the x-coordinate from a Point.
func EcPointX(p Point) Bigint {
	x, _ := pointToCoords(p)
	return x.Int64()
}

// EcPointY extracts the y-coordinate from a Point.
func EcPointY(p Point) Bigint {
	_, y := pointToCoords(p)
	return y.Int64()
}
