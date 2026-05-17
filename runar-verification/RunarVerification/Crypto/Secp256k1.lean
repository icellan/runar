/-!
# Crypto.Secp256k1 — concrete secp256k1 primitive specs

Concrete `def`s for the 10 secp256k1 EC primitives that previously
appeared as bare `axiom`s in `RunarVerification.ANF.Eval` (`Crypto`
namespace).

This module **does not** depend on the ANF interpreter, the Stack
layer, or the Pipeline. It is a leaf module of pure
`ByteArray` / `Int` algorithms. `ANF/Eval.lean` imports this module
and rebinds the named primitives in its own `Crypto` namespace so the
client surface (`Crypto.ecAdd`, `Crypto.ecMul`, etc.) is unchanged.

## What ships here

* `ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`,
  `ecModReduce`, `ecEncodeCompressed`, `ecMakePoint`, `ecPointX`,
  `ecPointY` — concrete implementations of the 10 secp256k1 primitives.

## Reference

* SEC 2 v2 secp256k1 parameters: field modulus
  `p = 2^256 − 2^32 − 977`, group order `n`, generator `G`.
* Rúnar `Point` byte convention: 64 bytes `= x[32] || y[32]`, each
  coordinate big-endian unsigned, no SEC prefix byte
  (see `packages/runar-lang/src/ec.ts`).
* TypeScript codegen the spec must agree with at the byte level
  (proved by `Stack.Ec.runOps_emitEc*_eq` at the codegen-to-spec
  tier): `packages/runar-compiler/src/passes/ec-codegen.ts`.

## Totality note

`ecMul` is a 256-iteration square-and-multiply loop with an explicit
`termination_by 256 - iter` measure. Field inversion in `ecAdd`
uses Fermat's little theorem (`a^(p-2) mod p`); this is total but
intentionally inefficient to evaluate — soundness over speed.
Degenerate group-law cases (point at infinity, equal-x with
opposite y) are mapped to a sentinel zero point so every def is a
total `ByteArray → ByteArray` function.

## Scope (B4-a)

This file lands the concrete spec defs only. The codegen-to-spec
linking theorems (`runOps_emitEcAdd_eq`, ...) live in `Stack/Ec.lean`
(currently axioms in `Crypto/Spec.lean §6`). Phase B4 (Tier 3)
discharges those against the spec defs landed here. The result is
−10 axioms in `ANF/Eval.lean` (the ten bare `axiom ec*` lines are
replaced with `def`s that delegate here).
-/

namespace RunarVerification.Crypto.Secp256k1

/-! ## SEC 2 v2 secp256k1 parameters -/

/-- secp256k1 field modulus `p = 2^256 − 2^32 − 977`. -/
def FIELD_P : Int :=
  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

/-- secp256k1 group order `n`. -/
def CURVE_N : Int :=
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

/-- Generator x-coordinate. -/
def GEN_X : Int :=
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

/-- Generator y-coordinate. -/
def GEN_Y : Int :=
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

/-! ## Field arithmetic mod `FIELD_P` -/

/-- Canonical mod: `((a % p) + p) % p`, kept in the range `[0, p)`. -/
def fieldMod (a : Int) : Int :=
  ((a % FIELD_P) + FIELD_P) % FIELD_P

def fieldAdd (a b : Int) : Int := fieldMod (a + b)
def fieldSub (a b : Int) : Int := fieldMod (a - b)
def fieldMul (a b : Int) : Int := fieldMod (a * b)

/-- Modular exponentiation by a non-negative `Nat`. Recursive on the
exponent. Used by `fieldInv` (Fermat's little theorem). -/
def fieldPowNat (a : Int) : Nat → Int
  | 0     => 1
  | n + 1 => fieldMul a (fieldPowNat a n)

/-- Modular inverse via Fermat's little theorem: `a^(p-2) mod p`.
Totality is the priority; we do not attempt fast modular
exponentiation in the spec layer. -/
def fieldInv (a : Int) : Int :=
  fieldPowNat (fieldMod a) (FIELD_P - 2).toNat

/-! ## Byte / coordinate conversion (32-byte big-endian, unsigned) -/

/-- Encode a non-negative `Int` as 32 big-endian bytes, taking
`fieldMod` first so the result is in `[0, p)`. -/
def intToBE32 (a : Int) : ByteArray :=
  let v := fieldMod a
  let byteAt (i : Nat) : UInt8 :=
    -- High byte is at index 0 (big-endian).
    let shift : Nat := 8 * (31 - i)
    ((v / (2 ^ shift)) % 256).toNat.toUInt8
  ByteArray.mk #[
    byteAt 0,  byteAt 1,  byteAt 2,  byteAt 3,
    byteAt 4,  byteAt 5,  byteAt 6,  byteAt 7,
    byteAt 8,  byteAt 9,  byteAt 10, byteAt 11,
    byteAt 12, byteAt 13, byteAt 14, byteAt 15,
    byteAt 16, byteAt 17, byteAt 18, byteAt 19,
    byteAt 20, byteAt 21, byteAt 22, byteAt 23,
    byteAt 24, byteAt 25, byteAt 26, byteAt 27,
    byteAt 28, byteAt 29, byteAt 30, byteAt 31
  ]

/-- Decode a big-endian byte run `b[start..start+32)` as a non-negative
`Int`. Out-of-range indices read as zero (callers in this module always
pass valid offsets for the 64-byte point payloads). -/
def be32At (b : ByteArray) (start : Nat) : Int :=
  let byte (i : Nat) : Int :=
    if start + i < b.size then (b.get! (start + i)).toNat else 0
  let step (acc : Int) (i : Nat) : Int := acc * 256 + byte i
  let acc := byte 0
  let acc := step acc 1
  let acc := step acc 2
  let acc := step acc 3
  let acc := step acc 4
  let acc := step acc 5
  let acc := step acc 6
  let acc := step acc 7
  let acc := step acc 8
  let acc := step acc 9
  let acc := step acc 10
  let acc := step acc 11
  let acc := step acc 12
  let acc := step acc 13
  let acc := step acc 14
  let acc := step acc 15
  let acc := step acc 16
  let acc := step acc 17
  let acc := step acc 18
  let acc := step acc 19
  let acc := step acc 20
  let acc := step acc 21
  let acc := step acc 22
  let acc := step acc 23
  let acc := step acc 24
  let acc := step acc 25
  let acc := step acc 26
  let acc := step acc 27
  let acc := step acc 28
  let acc := step acc 29
  let acc := step acc 30
  step acc 31

/-! ## Point representation

A `Point` is a 64-byte `ByteArray` `x[32] || y[32]` with both
coordinates big-endian unsigned. The "point at infinity" is represented
as the all-zero 64-byte payload, used as a sentinel for degenerate
group-law cases (the spec does not need to faithfully model O — every
client invariant requires `ecOnCurve` to hold before further EC
operations).
-/

/-- Build a `Point` from `(x, y)` integers. -/
def makePoint (x y : Int) : ByteArray :=
  intToBE32 x ++ intToBE32 y

/-- Sentinel "point at infinity" — 64 zero bytes. Used as a total-
function fallback for degenerate group-law cases. -/
def zeroPoint : ByteArray := makePoint 0 0

/-- Extract the x-coordinate from a 64-byte point. -/
def pointX (p : ByteArray) : Int := be32At p 0

/-- Extract the y-coordinate from a 64-byte point. -/
def pointY (p : ByteArray) : Int := be32At p 32

/-! ## 10 secp256k1 primitives -/

/-- `ecMakePoint x y` — pack `(x, y)` as 64-byte big-endian point.
Mirrors `emitEcMakePoint` (`packages/runar-compiler/src/passes/
ec-codegen.ts`). -/
def ecMakePoint (x y : Int) : ByteArray := makePoint x y

/-- `ecPointX p` — extract the x-coordinate of `p` as an `Int`.
Mirrors `emitEcPointX`. -/
def ecPointX (p : ByteArray) : Int := pointX p

/-- `ecPointY p` — extract the y-coordinate of `p` as an `Int`.
Mirrors `emitEcPointY`. -/
def ecPointY (p : ByteArray) : Int := pointY p

/-- `ecModReduce a m` — `((a mod m) + m) mod m`. Standard signed-aware
modular reduction. Mirrors `emitEcModReduce`. Returns `0` when
`m = 0` (the modulus stays a user input — codegen does not check). -/
def ecModReduce (a m : Int) : Int :=
  if m = 0 then 0 else ((a % m) + m) % m

/-- `ecOnCurve p` — true iff `y² ≡ x³ + 7 (mod p)`. Mirrors
`emitEcOnCurve`. -/
def ecOnCurve (p : ByteArray) : Bool :=
  let x := pointX p
  let y := pointY p
  let lhs := fieldMul y y
  let rhs := fieldAdd (fieldMul (fieldMul x x) x) 7
  decide (lhs = rhs)

/-- `ecNegate p` — `(x, p − y mod p)`. Mirrors `emitEcNegate`. -/
def ecNegate (p : ByteArray) : ByteArray :=
  let x := pointX p
  let y := pointY p
  makePoint x (fieldSub 0 y)

/-- `ecEncodeCompressed p` — 33-byte SEC compressed encoding:
parity byte (`0x02` if y even, `0x03` if odd) followed by the
32-byte big-endian x-coordinate. Mirrors `emitEcEncodeCompressed`. -/
def ecEncodeCompressed (p : ByteArray) : ByteArray :=
  let x := pointX p
  let y := pointY p
  let parity : UInt8 := if y % 2 = 0 then 0x02 else 0x03
  ByteArray.mk #[parity] ++ intToBE32 x

/-! ### Affine group law -/

/-- Affine point doubling on secp256k1 (`a = 0`, so the standard
formula reduces to `slope = (3 x²) / (2 y)`). Returns the sentinel
`zeroPoint` when the input lies "at infinity" (y = 0). -/
def affineDouble (px py : Int) : Int × Int :=
  if py = 0 then (0, 0)
  else
    let num := fieldMul (fieldMul px px) 3
    let den := fieldMul py 2
    let s := fieldMul num (fieldInv den)
    let rx := fieldSub (fieldMul s s) (fieldMul px 2)
    let ry := fieldSub (fieldMul s (fieldSub px rx)) py
    (rx, ry)

/-- Affine point addition on secp256k1. Falls back to `affineDouble`
when both inputs are the same point; returns `(0, 0)` for the
sentinel-zero / opposite-y cases (point at infinity). -/
def affineAdd (px py qx qy : Int) : Int × Int :=
  -- Identity cases: input "zero point" (both coords 0) means the
  -- sentinel "point at infinity". Return the other operand.
  if px = 0 ∧ py = 0 then (qx, qy)
  else if qx = 0 ∧ qy = 0 then (px, py)
  else
    let pxm := fieldMod px
    let qxm := fieldMod qx
    if pxm = qxm then
      let pym := fieldMod py
      let qym := fieldMod qy
      if pym = qym then affineDouble px py
      else (0, 0)  -- p + (−p) = point at infinity
    else
      let num := fieldSub qy py
      let den := fieldSub qx px
      let s := fieldMul num (fieldInv den)
      let rx := fieldSub (fieldSub (fieldMul s s) px) qx
      let ry := fieldSub (fieldMul s (fieldSub px rx)) py
      (rx, ry)

/-- `ecAdd p q` — affine point addition over secp256k1.
Mirrors `emitEcAdd`. -/
def ecAdd (p q : ByteArray) : ByteArray :=
  let (rx, ry) := affineAdd (pointX p) (pointY p) (pointX q) (pointY q)
  makePoint rx ry

/-! ### Scalar multiplication -/

/-- Single iteration of square-and-multiply. Reads the
`(255 − iter)`-th bit of `k.natAbs` (MSB-first). If the bit is set,
`acc := acc + base`. Always doubles `base` at the end of the
iteration.

Returns the updated `(acc_x, acc_y, base_x, base_y)`. -/
def ecMulStep (iter : Nat) (k : Int)
    (ax ay bx by_ : Int) : Int × Int × Int × Int :=
  let bitPos : Nat := 255 - iter
  let bit : Nat := (k.natAbs / (2 ^ bitPos)) % 2
  let (ax', ay') :=
    if bit = 1 then affineAdd ax ay bx by_
    else (ax, ay)
  let (bx', by') := affineDouble bx by_
  (ax', ay', bx', by')

/-- Inner loop of `ecMul`: process bits from MSB (`iter = 0`) down to
LSB (`iter = 255`). Terminates because `256 − iter` strictly decreases
each call. -/
def ecMulLoop (iter : Nat) (k : Int)
    (ax ay bx by_ : Int) : Int × Int :=
  if h : iter ≥ 256 then (ax, ay)
  else
    let (ax', ay', bx', by') := ecMulStep iter k ax ay bx by_
    ecMulLoop (iter + 1) k ax' ay' bx' by'
termination_by 256 - iter
decreasing_by
  simp_wf
  omega

/-- `ecMul p k` — scalar multiplication `k · p` via 256-iteration
square-and-multiply over affine coordinates. Mirrors `emitEcMul`. -/
def ecMul (p : ByteArray) (k : Int) : ByteArray :=
  let (rx, ry) := ecMulLoop 0 k 0 0 (pointX p) (pointY p)
  makePoint rx ry

/-- `ecMulGen k` — scalar multiplication of the generator point `G`
by `k`. Mirrors `emitEcMulGen`. -/
def ecMulGen (k : Int) : ByteArray := ecMul (makePoint GEN_X GEN_Y) k

end RunarVerification.Crypto.Secp256k1
