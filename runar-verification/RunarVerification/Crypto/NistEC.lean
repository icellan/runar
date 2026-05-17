/-!
# Crypto.NistEC — concrete NIST P-256 / P-384 EC specs

Concrete `def`s for the twelve NIST P-256 / P-384 primitive symbols
that previously appeared as bare `axiom`s in
`RunarVerification.ANF.Eval` (`Crypto` namespace).

This module **does not** depend on the ANF interpreter, the Stack
layer, or the Pipeline. It is a leaf module of pure
`ByteArray → ByteArray` / `Int` algorithms parameterised by the
curve. `ANF/Eval.lean` imports this module and rebinds the named
primitives in its own `Crypto` namespace so the client surface
(`Crypto.p256Add`, ..., `Crypto.verifyECDSA_P384`) is unchanged.

## What ships here

For `c ∈ {p256, p384}`:

* `cAdd : ByteArray → ByteArray → ByteArray`
  Affine point addition on `y² ≡ x³ − 3x + b (mod p)`.
* `cMul : ByteArray → Int → ByteArray`
  Affine scalar multiplication via square-and-multiply.
* `cMulGen : Int → ByteArray`
  Multiply the curve generator `G_c` by an integer scalar.
* `cOnCurve : ByteArray → Bool`
  Test whether the encoded point satisfies the curve equation.
* `cEncodeCompressed : ByteArray → ByteArray`
  Encode the (parity || x) compressed point form per SEC 1 §2.3.3.
* `verifyECDSA_c (sha256 sig pubkey preimage) : Bool`
  Standard ECDSA verification per FIPS 186-5 §6.4, parameterised by
  the SHA-256 backend (the codegen uses SHA-256 for both curves).

## Encoding convention (matches the codegen)

* **Uncompressed point**: 2·coordBytes-byte payload
  `x_be(coordBytes) || y_be(coordBytes)`, big-endian unsigned, no
  prefix byte. (P-256: 64 bytes; P-384: 96 bytes.)
* **Signature**: 2·coordBytes-byte payload
  `r_be(coordBytes) || s_be(coordBytes)`.
* **Compressed pubkey**: 1 + coordBytes-byte payload
  `parity || x_be(coordBytes)` with parity = `0x02` if y is even,
  `0x03` if y is odd.

## Point-at-infinity convention

The codegen uses 2·coordBytes-byte affine points exclusively;
there is no canonical "point at infinity" wire representation.
This spec represents the infinity point with the all-zero payload
(`ByteArray.mk (Array.replicate (2*coordBytes) 0)`). Callers that
need a real exception-safe affine group must add a separate flag;
the codegen does not, and neither does this spec.

## Reference

FIPS 186-5 ("Digital Signature Standard (DSS)"), §6.4 (ECDSA
verification), Appendix D.1.2.3 (P-256) and Appendix D.1.2.4
(P-384). Curve constants taken directly from the codegen reference
`packages/runar-compiler/src/passes/p256-p384-codegen.ts:21-43`
(cross-checked against `compilers/go/codegen/p256_p384.go`).
-/

namespace RunarVerification.Crypto.NistEC

/-! ## Curve parameters -/

/-- Curve parameters for short-Weierstraß curves with `a = -3`:
`y² ≡ x³ − 3x + b (mod p)`, with generator `(gx, gy)` of order `n`. -/
structure Params where
  /-- Field modulus. -/
  p          : Int
  /-- Curve constant `b` (the constant `a = -3` is hardcoded). -/
  b          : Int
  /-- Order of the generator. -/
  n          : Int
  /-- Generator x-coordinate. -/
  gx         : Int
  /-- Generator y-coordinate. -/
  gy         : Int
  /-- Coordinate length in bytes (32 for P-256, 48 for P-384). -/
  coordBytes : Nat
  deriving Inhabited

/-! ### P-256 parameters (FIPS 186-5 Appendix D.1.2.3) -/

def p256Params : Params :=
  { p :=
      0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
  , b :=
      0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
  , n :=
      0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
  , gx :=
      0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
  , gy :=
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
  , coordBytes := 32 }

/-! ### P-384 parameters (FIPS 186-5 Appendix D.1.2.4) -/

def p384Params : Params :=
  { p :=
      0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
  , b :=
      0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
  , n :=
      0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
  , gx :=
      0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
  , gy :=
      0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
  , coordBytes := 48 }

/-! ## Byte ⇆ Int conversion (big-endian, unsigned) -/

/-- Read the byte at offset `i` of `b`, returning 0 if out of bounds. -/
def readByte (b : ByteArray) (i : Nat) : Nat :=
  if h : i < b.size then (b.get i h).toNat else 0

/-- Decode `len` big-endian unsigned bytes starting at `off` into an
`Int`. Out-of-range bytes are read as 0. -/
def beToInt (b : ByteArray) (off : Nat) (len : Nat) : Int := Id.run do
  let mut acc : Int := 0
  let mut i : Nat := 0
  while i < len do
    acc := acc * 256 + Int.ofNat (readByte b (off + i))
    i := i + 1
  pure acc

/-- Encode `n` as `len` big-endian unsigned bytes (truncating high bytes
that don't fit). Negative inputs are treated as 0. -/
def intToBE (n : Int) (len : Nat) : ByteArray := Id.run do
  let mut bytes : Array UInt8 := Array.replicate len 0
  let mut v : Int := if n < 0 then 0 else n
  let mut i : Nat := len
  while i > 0 do
    i := i - 1
    let lowByte : Nat := (v % 256).toNat
    bytes := bytes.set! i (UInt8.ofNat lowByte)
    v := v / 256
  pure (ByteArray.mk bytes)

/-! ## Field arithmetic mod a generic prime

`a = -3` is hardcoded into the curve equation, so we only need a
prime-modulus reduction here. Inversion uses Fermat's little
theorem: `a^(p−2) ≡ a⁻¹ (mod p)` when `gcd(a, p) = 1`.

These helpers take the modulus as a raw `Int` so that ECDSA can
reuse them mod `n` (the group order) as well as mod `p` (the field
prime). -/

/-- `(a mod m + m) mod m` — Euclidean mod with non-negative result. -/
def modP (m : Int) (a : Int) : Int :=
  ((a % m) + m) % m

def addP (m : Int) (a b : Int) : Int := modP m (a + b)
def subP (m : Int) (a b : Int) : Int := modP m (a - b)
def mulP (m : Int) (a b : Int) : Int := modP m (a * b)
def negP (m : Int) (a : Int) : Int   := modP m (-a)

/-- `a^e mod m`, recursive on the `Nat` exponent. -/
def powNatP (m : Int) (a : Int) : Nat → Int
  | 0     => 1
  | n + 1 => mulP m a (powNatP m a n)

/-- `a^(m−2) mod m` via Fermat's little theorem. Note that this also
yields `0` for `a = 0`, which matches the codegen behaviour
(`Stack/P256P384.lean#cFieldInv` does not special-case `a = 0`). -/
def invP (m : Int) (a : Int) : Int :=
  powNatP m (modP m a) (m - 2).toNat

/-- Field arithmetic specialised to the curve's field prime. -/
@[inline] def fMod (c : Params) (a : Int) : Int := modP c.p a
@[inline] def fAdd (c : Params) (a b : Int) : Int := addP c.p a b
@[inline] def fSub (c : Params) (a b : Int) : Int := subP c.p a b
@[inline] def fMul (c : Params) (a b : Int) : Int := mulP c.p a b
@[inline] def fNeg (c : Params) (a : Int) : Int   := negP c.p a
@[inline] def fInv (c : Params) (a : Int) : Int   := invP c.p a

/-! ## Affine point arithmetic

Points are represented as `Option (Int × Int)`: `none` is the point
at infinity, `some (x, y)` is an affine point with coordinates
reduced mod `p`. The wire encoding (`encodePoint` / `decodePoint`)
uses `2·coordBytes` bytes for affine points and an all-zero payload
for the point at infinity. -/

abbrev AffinePoint : Type := Option (Int × Int)

/-- Decode `2·coordBytes` bytes as `(x, y)`. Wire format:
`x_be(coordBytes) || y_be(coordBytes)`.

If `b` is the all-zero `2·coordBytes`-byte payload, returns `none`
(point at infinity convention).

Out-of-range sizes (other than zero or `2·coordBytes`) are treated
as the all-zero / infinity case to keep the function total. -/
def decodePoint (c : Params) (b : ByteArray) : AffinePoint :=
  let x : Int := beToInt b 0 c.coordBytes
  let y : Int := beToInt b c.coordBytes c.coordBytes
  if x = 0 ∧ y = 0 then none
  else some (x, y)

/-- Encode `(x, y)` as `2·coordBytes` bytes: `x_be || y_be`.
`none` encodes as the all-zero payload. -/
def encodePoint (c : Params) (p : AffinePoint) : ByteArray :=
  match p with
  | none        => intToBE 0 (2 * c.coordBytes)
  | some (x, y) => intToBE x c.coordBytes ++ intToBE y c.coordBytes

/-- Affine point doubling on `y² = x³ − 3x + b`:
`s = (3x² − 3) / (2y) mod p`, `xr = s² − 2x mod p`, `yr = s(x − xr) − y mod p`.
Doubling a point with `y = 0` (a 2-torsion point) is `infinity`. -/
def affineDouble (c : Params) : AffinePoint → AffinePoint
  | none           => none
  | some (x, y)    =>
      if fMod c y = 0 then none
      else
        let num := fSub c (fMul c (fMul c 3 x) x) 3
        let den := fMul c 2 y
        let s   := fMul c num (fInv c den)
        let xr  := fSub c (fMul c s s) (fMul c 2 x)
        let yr  := fSub c (fMul c s (fSub c x xr)) y
        some (fMod c xr, fMod c yr)

/-- Affine point addition. Handles all standard exceptional cases:
`P + O = P`, `O + Q = Q`, `P + (−P) = O`, and the doubling fall-through. -/
def affineAdd (c : Params) : AffinePoint → AffinePoint → AffinePoint
  | none,           q              => q
  | p,              none           => p
  | some (x1, y1),  some (x2, y2)  =>
      let x1m := fMod c x1
      let y1m := fMod c y1
      let x2m := fMod c x2
      let y2m := fMod c y2
      if x1m = x2m then
        if fMod c (y1m + y2m) = 0 then none
        else affineDouble c (some (x1m, y1m))
      else
        let s   := fMul c (fSub c y2 y1) (fInv c (fSub c x2 x1))
        let xr  := fSub c (fMul c s s) (fAdd c x1 x2)
        let yr  := fSub c (fMul c s (fSub c x1 xr)) y1
        some (fMod c xr, fMod c yr)

/-! ## Scalar multiplication (square-and-multiply, low bit first) -/

/-- Affine point negation: `−(x, y) = (x, −y)`. -/
def affineNeg (c : Params) : AffinePoint → AffinePoint
  | none        => none
  | some (x, y) => some (fMod c x, fNeg c y)

/-- Low-bit-first double-and-add. Walks `bits` iterations, treating
`k` as a non-negative integer and adding the running `base` when the
current low bit is set. The point `base` is doubled at every step.
Mirrors `cEmitMulOps` in `Stack/P256P384.lean` (low-bit-first
double-and-add). -/
def affineMulLoop (c : Params) (bits : Nat) (base acc : AffinePoint)
    (k : Int) : AffinePoint :=
  match bits with
  | 0     => acc
  | b + 1 =>
      let acc'  := if k % 2 = 1 then affineAdd c acc base else acc
      let base' := affineDouble c base
      affineMulLoop c b base' acc' (k / 2)

/-- Affine scalar multiplication via low-bit-first square-and-multiply.
Negative scalars negate `P` and reuse `|k|`. Iterates 384 bits
(enough for both P-256 and P-384); extra iterations on a zero
remainder are no-ops, so the function is total. -/
def affineMul (c : Params) (k : Int) (P : AffinePoint) : AffinePoint :=
  let absK : Nat := k.natAbs
  let base : AffinePoint := if k < 0 then affineNeg c P else P
  affineMulLoop c 384 base none (Int.ofNat absK)

/-- Curve generator. -/
def gen (c : Params) : AffinePoint := some (c.gx, c.gy)

/-! ## Public API (matching the bare axioms' signatures) -/

/-- Point addition on the affine wire form. -/
def cAdd (c : Params) (a b : ByteArray) : ByteArray :=
  encodePoint c (affineAdd c (decodePoint c a) (decodePoint c b))

/-- Affine scalar multiplication on the wire form. -/
def cMul (c : Params) (a : ByteArray) (k : Int) : ByteArray :=
  encodePoint c (affineMul c k (decodePoint c a))

/-- Generator scalar multiplication. -/
def cMulGen (c : Params) (k : Int) : ByteArray :=
  encodePoint c (affineMul c k (gen c))

/-- Curve membership test: `y² ≡ x³ − 3x + b (mod p)`. The all-zero
payload (point-at-infinity convention) returns `false` — the codegen
does not produce that encoding, and `emitPXOnCurve` would also
report `false` for the zero point. -/
def cOnCurve (c : Params) (a : ByteArray) : Bool :=
  match decodePoint c a with
  | none        => false
  | some (x, y) =>
      let lhs := fMul c (fMod c y) (fMod c y)
      let x2  := fMul c (fMod c x) (fMod c x)
      let x3  := fMul c x2 x
      let rhs := fAdd c (fSub c x3 (fMul c 3 x)) c.b
      decide (lhs = rhs)

/-- SEC 1 §2.3.3 compressed encoding:
`parity || x_be(coordBytes)` where parity is `0x02` if `y` is even,
`0x03` otherwise. The point at infinity encodes as a single `0x00`
byte — the codegen does not emit infinity points, but the function
is total. -/
def cEncodeCompressed (c : Params) (a : ByteArray) : ByteArray :=
  match decodePoint c a with
  | none        => ByteArray.mk #[0x00]
  | some (x, y) =>
      let parity : UInt8 := if (fMod c y) % 2 = 0 then 0x02 else 0x03
      (ByteArray.mk #[parity]) ++ intToBE x c.coordBytes

/-! ## ECDSA verification (FIPS 186-5 §6.4)

Sig is the concatenation `r_be(coordBytes) || s_be(coordBytes)`.
Pubkey is the uncompressed affine point `x_be || y_be`. `preimage` is
the message bytes that get hashed via the supplied SHA-256 backend
(the codegen uses SHA-256 for both P-256 and P-384). -/

/-- Decompose the signature into `(r, s)` ∈ `Int × Int`. Both are read
as big-endian unsigned integers of length `coordBytes`. -/
def parseSig (c : Params) (sig : ByteArray) : Int × Int :=
  ( beToInt sig 0 c.coordBytes
  , beToInt sig c.coordBytes c.coordBytes )

/-- ECDSA verification.

Returns `true` iff:
1. `r, s ∈ [1, n − 1]`
2. `Q := decodePubkey pubkey` is a valid (non-infinity) affine point
3. with `e := int(sha256(preimage))`, `w := s⁻¹ mod n`,
   `u₁ := e * w mod n`, `u₂ := r * w mod n`,
   `R := u₁·G + u₂·Q` is not the point at infinity, and
   `R.x mod n == r`. -/
def cVerifyECDSA (c : Params) (sha256 : ByteArray → ByteArray)
    (sig pubkey preimage : ByteArray) : Bool :=
  let (r, s) := parseSig c sig
  let Q      := decodePoint c pubkey
  match Q with
  | none => false
  | some _ =>
      if r ≤ 0 ∨ r ≥ c.n then false
      else if s ≤ 0 ∨ s ≥ c.n then false
      else
        let h    := sha256 preimage
        let e    := beToInt h 0 (min h.size 32)
        let w    := invP c.n s
        let u1   := mulP c.n e w
        let u2   := mulP c.n r w
        let R1   := affineMul c u1 (gen c)
        let R2   := affineMul c u2 Q
        let R    := affineAdd c R1 R2
        match R with
        | none           => false
        | some (xr, _)   => decide (modP c.n xr = r)

end RunarVerification.Crypto.NistEC
