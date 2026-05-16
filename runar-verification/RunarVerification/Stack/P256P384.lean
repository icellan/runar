import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Ec
import RunarVerification.Stack.Eval
import RunarVerification.Crypto.Spec

/-!
# NIST P-256 / P-384 EC codegen — Phase 4 (port of
`packages/runar-compiler/src/passes/p256-p384-codegen.ts`).

Mirrors the TypeScript reference one-to-one. Reuses `Stack.Ec.Tracker`
(the per-named-stack-slot tracker) since the TS reference imports the
same `ECTracker` class. Only field/group constants and coordinate sizes
differ between this module and `Stack.Ec`:

* P-256: 64-byte point (`x[32] || y[32]`), `p`/`n` are 256-bit,
  generator `(GX, GY)` per FIPS 186-4.
* P-384: 96-byte point (`x[48] || y[48]`), `p`/`n` are 384-bit.

Both curves use `a = -3`, which enables the optimized Jacobian doubling
formula `A = 3*(X - Z²)*(X + Z²)`.

Top-level entry points (mirroring `emit*` in TS):

* `emitP256Add`, `emitP256Mul`, `emitP256MulGen`, `emitP256Negate`,
  `emitP256OnCurve`, `emitP256EncodeCompressed`, `emitVerifyECDSA_P256`.
* `emitP384Add`, `emitP384Mul`, `emitP384MulGen`, `emitP384Negate`,
  `emitP384OnCurve`, `emitP384EncodeCompressed`, `emitVerifyECDSA_P384`.

Each is a static `List StackOp` (or, for verifyECDSA, a function from a
fresh tracker — same calling convention as `Stack.Ec`'s `emitEcAdd`
constants).

Source of truth: `p256-p384-codegen.ts` (1229 LoC). Cross-checked
against `compilers/go/codegen/p256_p384.go` (1176 LoC) and
`compilers/rust/src/codegen/p256_p384.rs` (1263 LoC).
-/

namespace RunarVerification.Stack
namespace P256P384

open RunarVerification.Stack
open RunarVerification.Stack.Ec
open RunarVerification.Stack.Ec.Tracker

/-! ## Constants (mirroring `p256-p384-codegen.ts:21-43`). -/

/-- P-256 field prime. -/
def p256P : Int :=
  0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
def p256PMinus2 : Int := p256P - 2
def p256B : Int :=
  0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
def p256N : Int :=
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
def p256NMinus2 : Int := p256N - 2
def p256GX : Int :=
  0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
def p256GY : Int :=
  0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
def p256SqrtExp : Int := (p256P + 1) / 4

/-- P-384 field prime. -/
def p384P : Int :=
  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
def p384PMinus2 : Int := p384P - 2
def p384B : Int :=
  0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
def p384N : Int :=
  0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
def p384NMinus2 : Int := p384N - 2
def p384GX : Int :=
  0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
def p384GY : Int :=
  0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
def p384SqrtExp : Int := (p384P + 1) / 4

/-! ## Helpers -/

/-- Encode a non-negative `Int` as `len` big-endian bytes (low byte at end).
Mirrors TS `bigintToBytes`. -/
def bigintToBytes (n : Int) (len : Nat) : ByteArray := Id.run do
  let mut bytes : Array UInt8 := Array.replicate len 0
  let mut v : Int := n
  let mut i : Nat := len
  while i > 0 do
    i := i - 1
    let lowByte : Nat := (v % 256).toNat
    bytes := bytes.set! i (UInt8.ofNat lowByte)
    v := v / 256
  pure (ByteArray.mk bytes)

/-- Bit-length of a non-negative integer (position of highest set bit + 1).
Mirrors TS `bitLength`. -/
def bitLengthInt (n : Int) : Nat := Id.run do
  let mut bits : Nat := 0
  let mut v : Int := n
  -- Bound the loop generously (P-384 max bits is 386).
  for _ in [0:1024] do
    if v ≤ 0 then break
    bits := bits + 1
    v := v / 2
  pure bits

/-- Test whether bit `i` of `exp` is set. Mirrors TS `((exp >> BigInt(i)) & 1n) !== 0n`. -/
def bitAt (exp : Int) (i : Nat) : Bool :=
  ((exp / (2 ^ i)) % 2) = 1

/-! ## Byte reversal helpers (mirror `p256-p384-codegen.ts:75-104`). -/

/-- One step of inline byte reversal (7 ops). -/
def reverseStep : List StackOp :=
  [ .push (.bigint 1)
  , .opcode "OP_SPLIT"
  , .rot
  , .rot
  , .swap
  , .opcode "OP_CAT"
  , .swap ]

/-- Loop body of inline byte reversal: `n × reverseStep`. -/
def reverseLoop : Nat → List StackOp
  | 0     => []
  | n + 1 => reverseStep ++ reverseLoop n

/-- 32-byte reversal (P-256). -/
def emitReverse32Ops : List StackOp :=
  [ .opcode "OP_0", .swap ] ++ reverseLoop 32 ++ [ .drop ]

/-- 48-byte reversal (P-384). -/
def emitReverse48Ops : List StackOp :=
  [ .opcode "OP_0", .swap ] ++ reverseLoop 48 ++ [ .drop ]

/-! ## Curve parameter record (mirroring `CurveParams` in TS).

The `reverseBytes` field is captured as a list-of-ops so the `Tracker`
can splice it via `rawBlock`. -/

structure CurveParams where
  fieldP        : Int
  fieldPMinus2  : Int
  coordBytes    : Nat              -- 32 (P-256) or 48 (P-384)
  reverseBytes  : List StackOp     -- inline byte-reverse ops
  deriving Inhabited

def p256Params : CurveParams :=
  { fieldP := p256P
  , fieldPMinus2 := p256PMinus2
  , coordBytes := 32
  , reverseBytes := emitReverse32Ops }

def p384Params : CurveParams :=
  { fieldP := p384P
  , fieldPMinus2 := p384PMinus2
  , coordBytes := 48
  , reverseBytes := emitReverse48Ops }

structure GroupParams where
  n        : Int
  nMinus2  : Int
  deriving Inhabited

def p256Group : GroupParams := { n := p256N, nMinus2 := p256NMinus2 }
def p384Group : GroupParams := { n := p384N, nMinus2 := p384NMinus2 }

/-! ## Generic field arithmetic (parameterized by `CurveParams`). -/

@[inline] def cPushFieldP (t : Tracker) (name : String) (c : CurveParams) :
    Tracker :=
  t.pushInt name c.fieldP

@[inline] def cPushGroupN (t : Tracker) (name : String) (g : GroupParams) :
    Tracker :=
  t.pushInt name g.n

/-- `(a % p + p) % p` raw block (same shape as `Ec.fieldModOps`). -/
def fieldModOpsP : List StackOp :=
  [ .opcode "OP_2DUP"
  , .opcode "OP_MOD"
  , .rot
  , .drop
  , .over
  , .opcode "OP_ADD"
  , .swap
  , .opcode "OP_MOD" ]

/-- `cFieldMod`: reduce TOS mod `c.fieldP`. -/
def cFieldMod (t : Tracker) (aName resultName : String) (c : CurveParams) :
    Tracker :=
  let t := t.toTop aName
  let t := cPushFieldP t "_fmod_p" c
  t.rawBlock 2 (some resultName) fieldModOpsP

def cFieldAdd (t : Tracker) (aName bName resultName : String) (c : CurveParams) :
    Tracker :=
  let t := t.toTop aName
  let t := t.toTop bName
  let t := t.rawBlock 2 (some "_fadd_sum") [.opcode "OP_ADD"]
  cFieldMod t "_fadd_sum" resultName c

def cFieldSub (t : Tracker) (aName bName resultName : String) (c : CurveParams) :
    Tracker :=
  let t := t.toTop aName
  let t := t.toTop bName
  let t := t.rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]
  cFieldMod t "_fsub_diff" resultName c

def cFieldMul (t : Tracker) (aName bName resultName : String) (c : CurveParams) :
    Tracker :=
  let t := t.toTop aName
  let t := t.toTop bName
  let t := t.rawBlock 2 (some "_fmul_prod") [.opcode "OP_MUL"]
  cFieldMod t "_fmul_prod" resultName c

def cFieldMulConst (t : Tracker) (aName : String) (cv : Int) (resultName : String)
    (c : CurveParams) : Tracker :=
  let t := t.toTop aName
  let extras : List StackOp :=
    if cv = 2 then
      [.opcode "OP_2MUL"]
    else
      [.push (.bigint cv), .opcode "OP_MUL"]
  let t := t.rawBlock 1 (some "_fmc_prod") extras
  cFieldMod t "_fmc_prod" resultName c

def cFieldSqr (t : Tracker) (aName resultName : String) (c : CurveParams) :
    Tracker :=
  let t := t.copyToTop aName "_fsqr_copy"
  cFieldMul t aName "_fsqr_copy" resultName c

/-- Generic square-and-multiply over bits (bits-2 .. 0) of `exp`.
Mirrors TS `cFieldInv` (`p256-p384-codegen.ts:199-218`).

Recursion variant: `step` counts the bit index downward from `bits-2` to `0`.
The TS loop body is:
  for i = bits-2 .. 0:
    cFieldSqr -> _inv_r2; rename _inv_r
    if (exp >> i) & 1: copyToTop aName -> _inv_a; cFieldMul; rename _inv_r
-/
def cFieldInvLoop : Nat → Int → Tracker → String → CurveParams → Tracker
  | 0,     _exp, t, _aName, _c  => t
  | k + 1, exp,  t, aName, c   =>
    let t := cFieldSqr t "_inv_r" "_inv_r2" c
    let t := t.rename "_inv_r"
    let t :=
      if bitAt exp k then
        let t := t.copyToTop aName "_inv_a"
        let t := cFieldMul t "_inv_r" "_inv_a" "_inv_m" c
        t.rename "_inv_r"
      else
        t
    cFieldInvLoop k exp t aName c

def cFieldInv (t : Tracker) (aName resultName : String) (c : CurveParams) :
    Tracker :=
  let exp := c.fieldPMinus2
  let bits := bitLengthInt exp
  -- Start: result = a (highest bit always 1)
  let t := t.copyToTop aName "_inv_r"
  -- Iterate bit `bits-2` down to `0`. The `cFieldInvLoop k exp ...`
  -- processes bits `k-1`, `k-2`, ..., `0` (k iterations total).
  let iterCount : Nat := if bits ≥ 2 then bits - 1 else 0
  let t := cFieldInvLoop iterCount exp t aName c
  -- Cleanup
  let t := t.toTop aName |>.drop
  let t := t.toTop "_inv_r"
  t.rename resultName

/-! ## Group-order arithmetic (mod n). -/

def groupModOpsP : List StackOp :=
  [ .opcode "OP_2DUP"
  , .opcode "OP_MOD"
  , .rot
  , .drop
  , .over
  , .opcode "OP_ADD"
  , .swap
  , .opcode "OP_MOD" ]

def cGroupMod (t : Tracker) (aName resultName : String) (g : GroupParams) :
    Tracker :=
  let t := t.toTop aName
  let t := cPushGroupN t "_gmod_n" g
  t.rawBlock 2 (some resultName) groupModOpsP

def cGroupMul (t : Tracker) (aName bName resultName : String) (g : GroupParams) :
    Tracker :=
  let t := t.toTop aName
  let t := t.toTop bName
  let t := t.rawBlock 2 (some "_gmul_prod") [.opcode "OP_MUL"]
  cGroupMod t "_gmul_prod" resultName g

/-- Generic group-order square-and-multiply. Mirrors TS `cGroupInv`
(`p256-p384-codegen.ts:263-283`). The body squares via copy-and-mul
(no `cFieldSqr` — `cGroupMul` is mod-n). -/
def cGroupInvLoop : Nat → Int → Tracker → String → GroupParams → Tracker
  | 0,     _exp, t, _aName, _g  => t
  | k + 1, exp,  t, aName, g    =>
    -- Square: copyToTop _ginv_r -> _ginv_sq_copy; cGroupMul -> _ginv_sq; rename _ginv_r
    let t := t.copyToTop "_ginv_r" "_ginv_sq_copy"
    let t := cGroupMul t "_ginv_r" "_ginv_sq_copy" "_ginv_sq" g
    let t := t.rename "_ginv_r"
    let t :=
      if bitAt exp k then
        let t := t.copyToTop aName "_ginv_a"
        let t := cGroupMul t "_ginv_r" "_ginv_a" "_ginv_m" g
        t.rename "_ginv_r"
      else
        t
    cGroupInvLoop k exp t aName g

def cGroupInv (t : Tracker) (aName resultName : String) (g : GroupParams) :
    Tracker :=
  let exp := g.nMinus2
  let bits := bitLengthInt exp
  let t := t.copyToTop aName "_ginv_r"
  let iterCount : Nat := if bits ≥ 2 then bits - 1 else 0
  let t := cGroupInvLoop iterCount exp t aName g
  let t := t.toTop aName |>.drop
  let t := t.toTop "_ginv_r"
  t.rename resultName

/-! ## Point decompose / compose (parameterized). -/

/-- Decompose `coordBytes*2`-byte point → `(x_num, y_num)` on tracker.
Mirrors TS `cDecomposePoint` (`p256-p384-codegen.ts:293-321`). -/
def cDecomposePoint (t : Tracker) (pointName xName yName : String)
    (c : CurveParams) : Tracker :=
  let t := t.toTop pointName
  -- OP_SPLIT at coordBytes produces x_bytes (bottom) and y_bytes (top).
  let t := t.rawBlock 1 none
              [.push (.bigint (Int.ofNat c.coordBytes)), .opcode "OP_SPLIT"]
  -- Manually push two new slots.
  let t : Tracker :=
    { t with nm := (t.nm.push (some "_dp_xb")).push (some "_dp_yb") }
  -- Convert y_bytes (TOS) → num.
  let yConvOps : List StackOp :=
    c.reverseBytes
    ++ [ .push (.bytes (ByteArray.mk #[0x00]))
       , .opcode "OP_CAT"
       , .opcode "OP_BIN2NUM" ]
  let t := t.rawBlock 1 (some yName) yConvOps
  -- Convert x_bytes → num.
  let t := t.toTop "_dp_xb"
  let xConvOps : List StackOp :=
    c.reverseBytes
    ++ [ .push (.bytes (ByteArray.mk #[0x00]))
       , .opcode "OP_CAT"
       , .opcode "OP_BIN2NUM" ]
  let t := t.rawBlock 1 (some xName) xConvOps
  -- Stack now [yName, xName]; swap to standard order.
  t.swap

/-- Compose `(x_num, y_num)` → `coordBytes*2` bytes. Mirrors TS
`cComposePoint` (`p256-p384-codegen.ts:327-358`). -/
def cComposePoint (t : Tracker) (xName yName resultName : String)
    (c : CurveParams) : Tracker :=
  let numBinSize : Int := Int.ofNat (c.coordBytes + 1)
  -- x → coordBytes BE.
  let xConvOps : List StackOp :=
    [ .push (.bigint numBinSize)
    , .opcode "OP_NUM2BIN"
    , .push (.bigint (Int.ofNat c.coordBytes))
    , .opcode "OP_SPLIT"
    , .drop ]
    ++ c.reverseBytes
  let t := t.toTop xName
  let t := t.rawBlock 1 (some "_cp_xb") xConvOps
  -- y → coordBytes BE.
  let yConvOps : List StackOp :=
    [ .push (.bigint numBinSize)
    , .opcode "OP_NUM2BIN"
    , .push (.bigint (Int.ofNat c.coordBytes))
    , .opcode "OP_SPLIT"
    , .drop ]
    ++ c.reverseBytes
  let t := t.toTop yName
  let t := t.rawBlock 1 (some "_cp_yb") yConvOps
  -- x_be || y_be.
  let t := t.toTop "_cp_xb"
  let t := t.toTop "_cp_yb"
  t.rawBlock 2 (some resultName) [.opcode "OP_CAT"]

/-! ## Affine point addition. Mirrors TS `cAffineAdd`
(`p256-p384-codegen.ts:364-400`). -/

def cAffineAdd (t : Tracker) (c : CurveParams) : Tracker :=
  -- s_num = qy - py
  let t := t.copyToTop "qy" "_qy1"
  let t := t.copyToTop "py" "_py1"
  let t := cFieldSub t "_qy1" "_py1" "_s_num" c
  -- s_den = qx - px
  let t := t.copyToTop "qx" "_qx1"
  let t := t.copyToTop "px" "_px1"
  let t := cFieldSub t "_qx1" "_px1" "_s_den" c
  -- s = s_num / s_den mod p
  let t := cFieldInv t "_s_den" "_s_den_inv" c
  let t := cFieldMul t "_s_num" "_s_den_inv" "_s" c
  -- rx = s² - px - qx mod p
  let t := t.copyToTop "_s" "_s_keep"
  let t := cFieldSqr t "_s" "_s2" c
  let t := t.copyToTop "px" "_px2"
  let t := cFieldSub t "_s2" "_px2" "_rx1" c
  let t := t.copyToTop "qx" "_qx2"
  let t := cFieldSub t "_rx1" "_qx2" "rx" c
  -- ry = s * (px - rx) - py mod p
  let t := t.copyToTop "px" "_px3"
  let t := t.copyToTop "rx" "_rx2"
  let t := cFieldSub t "_px3" "_rx2" "_px_rx" c
  let t := cFieldMul t "_s_keep" "_px_rx" "_s_px_rx" c
  let t := t.copyToTop "py" "_py2"
  let t := cFieldSub t "_s_px_rx" "_py2" "ry" c
  -- Cleanup
  let t := t.toTop "px" |>.drop
  let t := t.toTop "py" |>.drop
  let t := t.toTop "qx" |>.drop
  let t := t.toTop "qy" |>.drop
  t

/-! ## Jacobian doubling (a = -3 optimization). Mirrors TS
`cJacobianDouble` (`p256-p384-codegen.ts:414-473`). -/

def cJacobianDouble (t : Tracker) (c : CurveParams) : Tracker :=
  -- Z²
  let t := t.copyToTop "jz" "_jz_sq_tmp"
  let t := cFieldSqr t "_jz_sq_tmp" "_Z2" c
  -- X - Z² and X + Z²
  let t := t.copyToTop "jx" "_jx_c1"
  let t := t.copyToTop "_Z2" "_Z2_c1"
  let t := cFieldSub t "_jx_c1" "_Z2_c1" "_X_minus_Z2" c
  let t := t.copyToTop "jx" "_jx_c2"
  let t := cFieldAdd t "_jx_c2" "_Z2" "_X_plus_Z2" c
  -- A = 3*(X-Z²)*(X+Z²)
  let t := cFieldMul t "_X_minus_Z2" "_X_plus_Z2" "_prod" c
  let t := t.pushInt "_three" 3
  let t := cFieldMul t "_prod" "_three" "_A" c
  -- B = 4 * X * Y²
  let t := t.copyToTop "jy" "_jy_sq_tmp"
  let t := cFieldSqr t "_jy_sq_tmp" "_Y2" c
  let t := t.copyToTop "_Y2" "_Y2_c1"
  let t := t.copyToTop "jx" "_jx_c3"
  let t := cFieldMul t "_jx_c3" "_Y2" "_xY2" c
  let t := t.pushInt "_four" 4
  let t := cFieldMul t "_xY2" "_four" "_B" c
  -- C = 8 * Y⁴
  let t := cFieldSqr t "_Y2_c1" "_Y4" c
  let t := t.pushInt "_eight" 8
  let t := cFieldMul t "_Y4" "_eight" "_C" c
  -- X3 = A² - 2B
  let t := t.copyToTop "_A" "_A_save"
  let t := t.copyToTop "_B" "_B_save"
  let t := cFieldSqr t "_A" "_A2" c
  let t := t.copyToTop "_B" "_B_c1"
  let t := cFieldMulConst t "_B_c1" 2 "_2B" c
  let t := cFieldSub t "_A2" "_2B" "_X3" c
  -- Y3 = A*(B - X3) - C
  let t := t.copyToTop "_X3" "_X3_c"
  let t := cFieldSub t "_B_save" "_X3_c" "_B_minus_X3" c
  let t := cFieldMul t "_A_save" "_B_minus_X3" "_A_tmp" c
  let t := cFieldSub t "_A_tmp" "_C" "_Y3" c
  -- Z3 = 2*Y*Z
  let t := t.copyToTop "jy" "_jy_c"
  let t := t.copyToTop "jz" "_jz_c"
  let t := cFieldMul t "_jy_c" "_jz_c" "_yz" c
  let t := cFieldMulConst t "_yz" 2 "_Z3" c
  -- Cleanup + rename
  let t := t.toTop "_B" |>.drop
  let t := t.toTop "jz" |>.drop
  let t := t.toTop "jx" |>.drop
  let t := t.toTop "jy" |>.drop
  let t := t.toTop "_X3" |>.rename "jx"
  let t := t.toTop "_Y3" |>.rename "jy"
  let t := t.toTop "_Z3" |>.rename "jz"
  t

/-! ## Jacobian → Affine. Mirrors TS `cJacobianToAffine`
(`p256-p384-codegen.ts:479-487`). -/

def cJacobianToAffine (t : Tracker) (rxName ryName : String) (c : CurveParams) :
    Tracker :=
  let t := cFieldInv t "jz" "_zinv" c
  let t := t.copyToTop "_zinv" "_zinv_keep"
  let t := cFieldSqr t "_zinv" "_zinv2" c
  let t := t.copyToTop "_zinv2" "_zinv2_keep"
  let t := cFieldMul t "_zinv_keep" "_zinv2" "_zinv3" c
  let t := cFieldMul t "jx" "_zinv2_keep" rxName c
  cFieldMul t "jy" "_zinv3" ryName c

/-! ## Jacobian mixed addition body (for inside `OP_IF`). Mirrors TS
`buildJacobianAddAffineInline` (`p256-p384-codegen.ts:498-564`). -/

def buildJacobianAddAffineBody (initNm : Array (Option String))
    (c : CurveParams) : List StackOp :=
  let it : Tracker := { nm := initNm, ops := #[] }
  let it := it.copyToTop "jz" "_jz_for_z1cu"
  let it := it.copyToTop "jz" "_jz_for_z3"
  let it := it.copyToTop "jy" "_jy_for_y3"
  let it := it.copyToTop "jx" "_jx_for_u1h2"
  -- Z1sq = jz²
  let it := cFieldSqr it "jz" "_Z1sq" c
  -- Z1cu = _jz_for_z1cu * Z1sq
  let it := it.copyToTop "_Z1sq" "_Z1sq_for_u2"
  let it := cFieldMul it "_jz_for_z1cu" "_Z1sq" "_Z1cu" c
  -- U2 = ax * Z1sq_for_u2
  let it := it.copyToTop "ax" "_ax_c"
  let it := cFieldMul it "_ax_c" "_Z1sq_for_u2" "_U2" c
  -- S2 = ay * Z1cu
  let it := it.copyToTop "ay" "_ay_c"
  let it := cFieldMul it "_ay_c" "_Z1cu" "_S2" c
  -- H = U2 - jx
  let it := cFieldSub it "_U2" "jx" "_H" c
  -- R = S2 - jy
  let it := cFieldSub it "_S2" "jy" "_R" c
  let it := it.copyToTop "_H" "_H_for_h3"
  let it := it.copyToTop "_H" "_H_for_z3"
  -- H2 = H²
  let it := cFieldSqr it "_H" "_H2" c
  let it := it.copyToTop "_H2" "_H2_for_u1h2"
  -- H3 = H_for_h3 * H2
  let it := cFieldMul it "_H_for_h3" "_H2" "_H3" c
  -- U1H2 = _jx_for_u1h2 * H2_for_u1h2
  let it := cFieldMul it "_jx_for_u1h2" "_H2_for_u1h2" "_U1H2" c
  let it := it.copyToTop "_R" "_R_for_y3"
  let it := it.copyToTop "_U1H2" "_U1H2_for_y3"
  let it := it.copyToTop "_H3" "_H3_for_y3"
  -- X3 = R² - H3 - 2*U1H2
  let it := cFieldSqr it "_R" "_R2" c
  let it := cFieldSub it "_R2" "_H3" "_x3_tmp" c
  let it := cFieldMulConst it "_U1H2" 2 "_2U1H2" c
  let it := cFieldSub it "_x3_tmp" "_2U1H2" "_X3" c
  -- Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
  let it := it.copyToTop "_X3" "_X3_c"
  let it := cFieldSub it "_U1H2_for_y3" "_X3_c" "_u_minus_x" c
  let it := cFieldMul it "_R_for_y3" "_u_minus_x" "_r_tmp" c
  let it := cFieldMul it "_jy_for_y3" "_H3_for_y3" "_jy_h3" c
  let it := cFieldSub it "_r_tmp" "_jy_h3" "_Y3" c
  -- Z3 = _jz_for_z3 * _H_for_z3
  let it := cFieldMul it "_jz_for_z3" "_H_for_z3" "_Z3" c
  -- Rename
  let it := it.toTop "_X3" |>.rename "jx"
  let it := it.toTop "_Y3" |>.rename "jy"
  let it := it.toTop "_Z3" |>.rename "jz"
  it.ops.toList

/-! ## Scalar multiplication.

Mirrors TS `cEmitMul` (`p256-p384-codegen.ts:579-657`). The TS reference
runs `topBit - 2` where `topBit = bitLength(4n - 1)`. For P-256 this is
`startBit = 256` (i.e. iterate bit 256 down to 0 = 257 iterations);
for P-384 `startBit = 384` (385 iterations).

Note: the TS comment claims 258 / 386 iterations, but the actual loop
runs `startBit + 1` iterations because `for (let bit = startBit; bit >= 0)`.
Re-deriving: `4n - 1` for P-256 is just under `2^258`, so `bitLength` is
258, `topBit = 258`, `startBit = 256`. Loop iterations = 257.
-/

/-- Per-iteration body of scalar-mul (mirrors TS `for (let bit = …)` body
`p256-p384-codegen.ts:618-647`). -/
def cMulIter (t : Tracker) (bit : Nat) (c : CurveParams) : Tracker :=
  let t := cJacobianDouble t c
  -- Extract bit: (k >> bit) & 1
  let t := t.copyToTop "_k" "_k_copy"
  let t :=
    if bit = 1 then
      t.rawBlock 1 (some "_shifted") [.opcode "OP_2DIV"]
    else if bit > 1 then
      let t := t.pushInt "_shift" (Int.ofNat bit)
      t.rawBlock 2 (some "_shifted") [.opcode "OP_RSHIFTNUM"]
    else
      t.rename "_shifted"
  let t := t.pushInt "_two" 2
  let t := t.rawBlock 2 (some "_bit") [.opcode "OP_MOD"]
  -- Move _bit to TOS and pop from tracker; build `addOps` against the
  -- post-pop nm so the IF body sees the same names as the surrounding
  -- tracker.
  let t := t.toTop "_bit"
  let nmAfterPop := t.nm.pop
  let addOps := buildJacobianAddAffineBody nmAfterPop c
  let ifOp : StackOp := .ifOp addOps (some [])
  { nm := nmAfterPop, ops := t.ops.push ifOp }

/-- Iterate `cMulIter` from `startBit` down to `0`. -/
def cMulIterLoop : Nat → Tracker → CurveParams → Tracker
  | 0,     t, c => cMulIter t 0 c
  | n + 1, t, c => cMulIterLoop n (cMulIter t (n + 1) c) c

/-- Compute `startBit` per the TS reference: `topBit = bitLength(4n - 1)`,
`startBit = topBit - 2`. -/
def computeStartBit (g : GroupParams) : Nat :=
  let topBit := bitLengthInt (4 * g.n - 1)
  if topBit ≥ 2 then topBit - 2 else 0

/-- Scalar mul body: stack in `[..., point, scalar]` → `[..., result_point]`.
Mirrors TS `cEmitMul` (`p256-p384-codegen.ts:579-657`). -/
def cEmitMulOps (c : CurveParams) (g : GroupParams) : List StackOp :=
  let t : Tracker := Tracker.init [some "_pt", some "_k"]
  let t := cDecomposePoint t "_pt" "ax" "ay" c
  -- k' = k + 3n
  let t := t.toTop "_k"
  let t := t.pushInt "_n" g.n
  let t := t.rawBlock 2 (some "_kn") [.opcode "OP_ADD"]
  let t := t.pushInt "_n2" g.n
  let t := t.rawBlock 2 (some "_kn2") [.opcode "OP_ADD"]
  let t := t.pushInt "_n3" g.n
  let t := t.rawBlock 2 (some "_kn3") [.opcode "OP_ADD"]
  let t := t.rename "_k"
  -- Init accumulator = P
  let t := t.copyToTop "ax" "jx"
  let t := t.copyToTop "ay" "jy"
  let t := t.pushInt "jz" 1
  -- Iterate startBit down to 0
  let startBit := computeStartBit g
  let t := cMulIterLoop startBit t c
  -- Final affine conversion
  let t := cJacobianToAffine t "_rx" "_ry" c
  -- Cleanup
  let t := t.toTop "ax" |>.drop
  let t := t.toTop "ay" |>.drop
  let t := t.toTop "_k" |>.drop
  -- Compose
  let t := cComposePoint t "_rx" "_ry" "_result" c
  t.ops.toList

/-! ## Pubkey decompression. Mirrors TS `decompressPubKey`
(`p256-p384-codegen.ts:695-808`). -/

/-- Replace the rightmost slot named `from` with `to`. Mirrors TS
`nm[idx] = to` after `nm.lastIndexOf(from)`. -/
def renameRight (nm : Array (Option String)) (fromN toN : String) :
    Array (Option String) := Id.run do
  let n := nm.size
  let mut i : Nat := n
  while i > 0 do
    i := i - 1
    if nm[i]! == some fromN then
      return nm.set! i (some toN)
  return nm

/-- Erase the rightmost slot named `from`. Mirrors TS
`nm.splice(idx, 1)`. -/
def eraseRight (nm : Array (Option String)) (fromN : String) :
    Array (Option String) := Id.run do
  let n := nm.size
  let mut i : Nat := n
  while i > 0 do
    i := i - 1
    if nm[i]! == some fromN then
      return nm.eraseIdxIfInBounds i
  return nm

/-- Square-and-multiply for the field exponentiation used in sqrt.
Mirrors TS `cFieldPow` (`p256-p384-codegen.ts:667-685`). -/
def cFieldPowLoop : Nat → Int → Tracker → String → CurveParams → Tracker
  | 0,     _exp, t, _baseN, _c  => t
  | k + 1, exp,  t, baseN, c   =>
    let t := cFieldSqr t "_pow_r" "_pow_sq" c
    let t := t.rename "_pow_r"
    let t :=
      if bitAt exp k then
        let t := t.copyToTop baseN "_pow_b"
        let t := cFieldMul t "_pow_r" "_pow_b" "_pow_m" c
        t.rename "_pow_r"
      else
        t
    cFieldPowLoop k exp t baseN c

def cFieldPow (t : Tracker) (baseName : String) (exp : Int) (resultName : String)
    (c : CurveParams) : Tracker :=
  let bits := bitLengthInt exp
  let t := t.copyToTop baseName "_pow_r"
  let iterCount : Nat := if bits ≥ 2 then bits - 1 else 0
  let t := cFieldPowLoop iterCount exp t baseName c
  let t := t.toTop baseName |>.drop
  let t := t.toTop "_pow_r"
  t.rename resultName

/-- Decompress a compressed pubkey on tracker. Consumes `pkName`,
produces `qxName` and `qyName`. Mirrors TS `decompressPubKey`. -/
def decompressPubKey (t : Tracker) (pkName qxName qyName : String)
    (c : CurveParams) (curveB sqrtExp : Int) : Tracker :=
  let t := t.toTop pkName
  -- Split: [prefix, x_bytes]
  let t := t.rawBlock 1 none [.push (.bigint 1), .opcode "OP_SPLIT"]
  let t : Tracker :=
    { t with nm := (t.nm.push (some "_dk_prefix")).push (some "_dk_xbytes") }
  -- Convert prefix → parity (0/1)
  let t := t.toTop "_dk_prefix"
  let t := t.rawBlock 1 (some "_dk_parity")
              [ .opcode "OP_BIN2NUM"
              , .push (.bigint 2)
              , .opcode "OP_MOD" ]
  -- Stash parity on alt
  let t := t.toTop "_dk_parity"
  let t := t.toAlt
  -- Convert x_bytes → num
  let t := t.toTop "_dk_xbytes"
  let xConvOps : List StackOp :=
    c.reverseBytes
    ++ [ .push (.bytes (ByteArray.mk #[0x00]))
       , .opcode "OP_CAT"
       , .opcode "OP_BIN2NUM" ]
  let t := t.rawBlock 1 (some "_dk_x") xConvOps
  -- Save x for later as qx
  let t := t.copyToTop "_dk_x" "_dk_x_save"
  -- y² = x³ - 3x + b mod p
  let t := t.copyToTop "_dk_x" "_dk_x_c1"
  let t := cFieldSqr t "_dk_x" "_dk_x2" c
  let t := cFieldMul t "_dk_x2" "_dk_x_c1" "_dk_x3" c
  let t := t.copyToTop "_dk_x_save" "_dk_x_for_3"
  let t := cFieldMulConst t "_dk_x_for_3" 3 "_dk_3x" c
  let t := cFieldSub t "_dk_x3" "_dk_3x" "_dk_x3m3x" c
  let t := t.pushInt "_dk_b" curveB
  let t := cFieldAdd t "_dk_x3m3x" "_dk_b" "_dk_y2" c
  -- y = (y²)^sqrtExp mod p
  let t := cFieldPow t "_dk_y2" sqrtExp "_dk_y_cand" c
  -- Check parity match
  let t := t.copyToTop "_dk_y_cand" "_dk_y_check"
  let t := t.rawBlock 1 (some "_dk_y_par")
              [ .push (.bigint 2)
              , .opcode "OP_MOD" ]
  -- Retrieve parity from alt
  let t := t.fromAlt "_dk_parity"
  -- Compare
  let t := t.toTop "_dk_y_par"
  let t := t.toTop "_dk_parity"
  let t := t.rawBlock 2 (some "_dk_match") [.opcode "OP_EQUAL"]
  -- Compute p - y_cand
  let t := t.copyToTop "_dk_y_cand" "_dk_y_for_neg"
  let t := cPushFieldP t "_dk_pfn" c
  let t := t.toTop "_dk_y_for_neg"
  let t := t.rawBlock 2 (some "_dk_neg_y") [.opcode "OP_SUB"]
  -- Bring match to TOS for IF; tracker pops it (consumed by IF).
  let t := t.toTop "_dk_match"
  let nmAfterMatch := t.nm.pop
  -- IF body: drop neg_y; ELSE body: nip y_cand.
  let thenOps : List StackOp := [.drop]
  let elseOps : List StackOp := [.nip]
  let ifOp : StackOp := .ifOp thenOps (some elseOps)
  -- Emit IF directly via tracker.emit (no name push).
  let t : Tracker := { nm := nmAfterMatch, ops := t.ops.push ifOp }
  -- Tracker still names both _dk_y_cand and _dk_neg_y; one is gone.
  -- Erase `_dk_neg_y`, rename `_dk_y_cand` → qyName, `_dk_x_save` → qxName.
  let nm1 := eraseRight t.nm "_dk_neg_y"
  let nm2 := renameRight nm1 "_dk_y_cand" qyName
  let nm3 := renameRight nm2 "_dk_x_save" qxName
  { t with nm := nm3 }

/-! ## ECDSA verification. Mirrors TS `cEmitVerifyECDSA`
(`p256-p384-codegen.ts:830-983`). -/

def cEmitVerifyECDSAOps (c : CurveParams) (g : GroupParams)
    (curveB sqrtExp gx gy : Int) : List StackOp :=
  let t : Tracker := Tracker.init [some "_msg", some "_sig", some "_pk"]
  -- Step 1: e = SHA-256(msg) as integer
  let t := t.toTop "_msg"
  let eOps : List StackOp :=
    [ .opcode "OP_SHA256" ]
    ++ emitReverse32Ops
    ++ [ .push (.bytes (ByteArray.mk #[0x00]))
       , .opcode "OP_CAT"
       , .opcode "OP_BIN2NUM" ]
  let t := t.rawBlock 1 (some "_e") eOps
  -- Step 2: parse sig into (r, s)
  let t := t.toTop "_sig"
  let t := t.rawBlock 1 none
              [.push (.bigint (Int.ofNat c.coordBytes)), .opcode "OP_SPLIT"]
  let t : Tracker :=
    { t with nm := (t.nm.push (some "_r_bytes")).push (some "_s_bytes") }
  let t := t.toTop "_r_bytes"
  let convOps : List StackOp :=
    c.reverseBytes
    ++ [ .push (.bytes (ByteArray.mk #[0x00]))
       , .opcode "OP_CAT"
       , .opcode "OP_BIN2NUM" ]
  let t := t.rawBlock 1 (some "_r") convOps
  let t := t.toTop "_s_bytes"
  let t := t.rawBlock 1 (some "_s") convOps
  -- Step 3: decompress pubkey
  let t := decompressPubKey t "_pk" "_qx" "_qy" c curveB sqrtExp
  -- Step 4: w = s^{-1} mod n
  let t := cGroupInv t "_s" "_w" g
  -- Step 5: u1 = e * w mod n
  let t := t.copyToTop "_w" "_w_c1"
  let t := cGroupMul t "_e" "_w_c1" "_u1" g
  -- Step 6: u2 = r * w mod n
  let t := t.copyToTop "_r" "_r_save"
  let t := cGroupMul t "_r" "_w" "_u2" g
  -- Step 7: R = u1*G + u2*Q
  let pointBytes : Nat := c.coordBytes * 2
  let _ := pointBytes
  let gPoint : ByteArray :=
    bigintToBytes gx c.coordBytes ++ bigintToBytes gy c.coordBytes
  let t := t.pushBytes "_G" gPoint
  let t := t.toTop "_u1"
  -- Stash _r_save, _u2, _qy, _qx on alt (in that order so cEmitMul sees [_G, _u1])
  let t := t.toTop "_r_save" |>.toAlt
  let t := t.toTop "_u2" |>.toAlt
  let t := t.toTop "_qy" |>.toAlt
  let t := t.toTop "_qx" |>.toAlt
  -- Pop _G and _u1 from tracker — cEmitMul manages its own internal tracker.
  let t : Tracker := { t with nm := t.nm.pop }    -- _u1
  let t : Tracker := { t with nm := t.nm.pop }    -- _G
  -- Splice mul1 ops
  let mul1Ops := cEmitMulOps c g
  let t : Tracker :=
    { nm := t.nm.push (some "_R1_point")
    , ops := t.ops ++ mul1Ops.toArray }
  -- Restore qx, qy, u2 (LIFO)
  let t := t.fromAlt "_qx"
  let t := t.fromAlt "_qy"
  let t := t.fromAlt "_u2"
  -- Stash R1 on alt (alt now: only _r_save)
  let t := t.toTop "_R1_point" |>.toAlt
  -- Compose Q = (qx, qy)
  let t := cComposePoint t "_qx" "_qy" "_Q_point" c
  let t := t.toTop "_u2"
  -- Pop _u2 and _Q_point, splice mul2 ops, push _R2_point.
  let t : Tracker := { t with nm := t.nm.pop }    -- _u2
  let t : Tracker := { t with nm := t.nm.pop }    -- _Q_point
  let mul2Ops := cEmitMulOps c g
  let t : Tracker :=
    { nm := t.nm.push (some "_R2_point")
    , ops := t.ops ++ mul2Ops.toArray }
  -- Restore R1
  let t := t.fromAlt "_R1_point"
  -- Stack: [..., _R2_point, _R1_point] — swap.
  let t := t.swap
  -- Decompose both, rename to (px, py, qx, qy) for cAffineAdd.
  let t := cDecomposePoint t "_R1_point" "_rpx" "_rpy" c
  let t := cDecomposePoint t "_R2_point" "_rqx" "_rqy" c
  let nm := t.nm
  let nm := renameRight nm "_rpx" "px"
  let nm := renameRight nm "_rpy" "py"
  let nm := renameRight nm "_rqx" "qx"
  let nm := renameRight nm "_rqy" "qy"
  let t : Tracker := { t with nm := nm }
  let t := cAffineAdd t c
  -- Drop ry; reduce rx mod n; restore _r_save; compare.
  let t := t.toTop "ry" |>.drop
  let t := cGroupMod t "rx" "_rx_mod_n" g
  let t := t.fromAlt "_r_save"
  let t := t.toTop "_rx_mod_n"
  let t := t.toTop "_r_save"
  let t := t.rawBlock 2 (some "_result") [.opcode "OP_EQUAL"]
  t.ops.toList

/-! ## P-256 public API (mirroring `p256-p384-codegen.ts:986-1106`). -/

/-- P-256 point addition: stack `[Point, Point]` → `[Point]`. -/
def emitP256Add : List StackOp :=
  let t : Tracker := Tracker.init [some "_pa", some "_pb"]
  let t := cDecomposePoint t "_pa" "px" "py" p256Params
  let t := cDecomposePoint t "_pb" "qx" "qy" p256Params
  let t := cAffineAdd t p256Params
  let t := cComposePoint t "rx" "ry" "_result" p256Params
  t.ops.toList

/-- P-256 scalar multiplication: stack `[Point, scalar]` → `[Point]`. -/
def emitP256Mul : List StackOp :=
  cEmitMulOps p256Params p256Group

/-- P-256 generator multiplication: stack `[scalar]` → `[Point]`. Pushes
G as 64-byte blob, swaps, delegates to `emitP256Mul`. -/
def emitP256MulGen : List StackOp :=
  let gPoint : ByteArray := bigintToBytes p256GX 32 ++ bigintToBytes p256GY 32
  [ .push (.bytes gPoint)
  , .swap ]
  ++ emitP256Mul

/-- P-256 negation: `(x, y) → (x, p - y)`. -/
def emitP256Negate : List StackOp :=
  let t : Tracker := Tracker.init [some "_pt"]
  let t := cDecomposePoint t "_pt" "_nx" "_ny" p256Params
  let t := cPushFieldP t "_fp" p256Params
  let t := cFieldSub t "_fp" "_ny" "_neg_y" p256Params
  let t := cComposePoint t "_nx" "_neg_y" "_result" p256Params
  t.ops.toList

/-- P-256 on-curve check: `y² == x³ - 3x + b mod p`. -/
def emitP256OnCurve : List StackOp :=
  let t : Tracker := Tracker.init [some "_pt"]
  let t := cDecomposePoint t "_pt" "_x" "_y" p256Params
  let t := cFieldSqr t "_y" "_y2" p256Params
  let t := t.copyToTop "_x" "_x_copy"
  let t := t.copyToTop "_x" "_x_copy2"
  let t := cFieldSqr t "_x" "_x2" p256Params
  let t := cFieldMul t "_x2" "_x_copy" "_x3" p256Params
  let t := cFieldMulConst t "_x_copy2" 3 "_3x" p256Params
  let t := cFieldSub t "_x3" "_3x" "_x3m3x" p256Params
  let t := t.pushInt "_b" p256B
  let t := cFieldAdd t "_x3m3x" "_b" "_rhs" p256Params
  let t := t.toTop "_y2"
  let t := t.toTop "_rhs"
  let t := t.rawBlock 2 (some "_result") [.opcode "OP_EQUAL"]
  t.ops.toList

/-- P-256 compressed encoding: 64-byte point → 33-byte compressed pubkey. -/
def emitP256EncodeCompressed : List StackOp :=
  [ .push (.bigint 32)
  , .opcode "OP_SPLIT"
  , .opcode "OP_SIZE"
  , .push (.bigint 1)
  , .opcode "OP_SUB"
  , .opcode "OP_SPLIT"
  , .opcode "OP_BIN2NUM"
  , .push (.bigint 2)
  , .opcode "OP_MOD"
  , .swap
  , .drop
  , .ifOp [.push (.bytes (ByteArray.mk #[0x03]))]
          (some [.push (.bytes (ByteArray.mk #[0x02]))])
  , .swap
  , .opcode "OP_CAT" ]

/-- P-256 ECDSA verification. -/
def emitVerifyECDSA_P256 : List StackOp :=
  cEmitVerifyECDSAOps p256Params p256Group p256B p256SqrtExp p256GX p256GY

/-! ## P-384 public API (mirroring `p256-p384-codegen.ts:1112-1229`). -/

/-- P-384 point addition. -/
def emitP384Add : List StackOp :=
  let t : Tracker := Tracker.init [some "_pa", some "_pb"]
  let t := cDecomposePoint t "_pa" "px" "py" p384Params
  let t := cDecomposePoint t "_pb" "qx" "qy" p384Params
  let t := cAffineAdd t p384Params
  let t := cComposePoint t "rx" "ry" "_result" p384Params
  t.ops.toList

/-- P-384 scalar multiplication. -/
def emitP384Mul : List StackOp :=
  cEmitMulOps p384Params p384Group

/-- P-384 generator multiplication. -/
def emitP384MulGen : List StackOp :=
  let gPoint : ByteArray := bigintToBytes p384GX 48 ++ bigintToBytes p384GY 48
  [ .push (.bytes gPoint)
  , .swap ]
  ++ emitP384Mul

/-- P-384 negation. -/
def emitP384Negate : List StackOp :=
  let t : Tracker := Tracker.init [some "_pt"]
  let t := cDecomposePoint t "_pt" "_nx" "_ny" p384Params
  let t := cPushFieldP t "_fp" p384Params
  let t := cFieldSub t "_fp" "_ny" "_neg_y" p384Params
  let t := cComposePoint t "_nx" "_neg_y" "_result" p384Params
  t.ops.toList

/-- P-384 on-curve check. -/
def emitP384OnCurve : List StackOp :=
  let t : Tracker := Tracker.init [some "_pt"]
  let t := cDecomposePoint t "_pt" "_x" "_y" p384Params
  let t := cFieldSqr t "_y" "_y2" p384Params
  let t := t.copyToTop "_x" "_x_copy"
  let t := t.copyToTop "_x" "_x_copy2"
  let t := cFieldSqr t "_x" "_x2" p384Params
  let t := cFieldMul t "_x2" "_x_copy" "_x3" p384Params
  let t := cFieldMulConst t "_x_copy2" 3 "_3x" p384Params
  let t := cFieldSub t "_x3" "_3x" "_x3m3x" p384Params
  let t := t.pushInt "_b" p384B
  let t := cFieldAdd t "_x3m3x" "_b" "_rhs" p384Params
  let t := t.toTop "_y2"
  let t := t.toTop "_rhs"
  let t := t.rawBlock 2 (some "_result") [.opcode "OP_EQUAL"]
  t.ops.toList

/-- P-384 compressed encoding: 96-byte point → 49-byte compressed pubkey. -/
def emitP384EncodeCompressed : List StackOp :=
  [ .push (.bigint 48)
  , .opcode "OP_SPLIT"
  , .opcode "OP_SIZE"
  , .push (.bigint 1)
  , .opcode "OP_SUB"
  , .opcode "OP_SPLIT"
  , .opcode "OP_BIN2NUM"
  , .push (.bigint 2)
  , .opcode "OP_MOD"
  , .swap
  , .drop
  , .ifOp [.push (.bytes (ByteArray.mk #[0x03]))]
          (some [.push (.bytes (ByteArray.mk #[0x02]))])
  , .swap
  , .opcode "OP_CAT" ]

/-- P-384 ECDSA verification. -/
def emitVerifyECDSA_P384 : List StackOp :=
  cEmitVerifyECDSAOps p384Params p384Group p384B p384SqrtExp p384GX p384GY

/-! ## Codegen-to-spec axioms (Phase B5)

Each emit function above is large (`cEmitMulOps` alone is ~250+ ops),
and proving operational equivalence against the abstract `Crypto.pX*`
primitives by direct unfolding of `runOps` is out of scope for the
current verification phase: it requires modelling BSV Script's
field-arithmetic opcodes (`OP_MOD`, `OP_LSHIFTNUM`, etc.) over the
relevant `Int` semantics, plus the byte-reversal / `OP_BIN2NUM`
glue.

We commit to that equivalence here as a narrow `axiom` family per
emit function, mirroring the secp256k1 pattern in §2 of
`Crypto/Spec.lean`. Each axiom asserts: when the runtime stack
matches the expected ABI shape (operands as 64-byte / 96-byte
`vBytes` blobs, scalars as `vBigint`, etc.), executing the emitted
ops leaves a single `vBytes`/`vBool` result on top of the stack
holding the value of the corresponding `Crypto.pX*` primitive.

These axioms are listed in the trust manifest under the FIPS 186-4
heading; a future iteration may discharge them by formalising BSV
field-arithmetic opcodes against `ZMod p256P` / `ZMod p384P` and
re-running each emit function.

Reference: FIPS 186-4 ("Digital Signature Standard (DSS)"),
§D.1.2.3 (P-256) and §D.1.2.4 (P-384). Source-of-truth for the
emit functions: `packages/runar-compiler/src/passes/p256-p384-codegen.ts`.
-/

open RunarVerification.Stack.Eval (StackState runOps)
open RunarVerification.ANF.Eval

/-! ### P-256 codegen-to-spec axioms -/

/-- `emitP256Add`: stack `[p1, p2, …]` (top = p2) reduces to
`[p256Add p1 p2, …]`. -/
axiom emitP256Add_runOps_eq (stkSt : StackState) (p1 p2 : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes p2 :: .vBytes p1 :: rest) :
    runOps emitP256Add stkSt
    = .ok { stkSt with stack := .vBytes (Crypto.p256Add p1 p2) :: rest }

/-- `emitP256Mul`: stack `[point, scalar, …]` (top = scalar) reduces to
`[p256Mul point scalar, …]`. -/
axiom emitP256Mul_runOps_eq (stkSt : StackState) (p : ByteArray) (k : Int)
    (rest : List Value)
    (hStk : stkSt.stack = .vBigint k :: .vBytes p :: rest) :
    runOps emitP256Mul stkSt
    = .ok { stkSt with stack := .vBytes (Crypto.p256Mul p k) :: rest }

/-- `emitP256MulGen`: stack `[scalar, …]` reduces to
`[p256MulGen scalar, …]` (`G` is pushed inline by the emit code). -/
axiom emitP256MulGen_runOps_eq (stkSt : StackState) (k : Int)
    (rest : List Value)
    (hStk : stkSt.stack = .vBigint k :: rest) :
    runOps emitP256MulGen stkSt
    = .ok { stkSt with stack := .vBytes (Crypto.p256MulGen k) :: rest }

/-- `emitP256Negate`: stack `[point, …]` reduces to
`[p256Negate point, …]` (computed inline as `(x, p − y)`). -/
axiom emitP256Negate_runOps_eq (stkSt : StackState) (p : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes p :: rest) :
    runOps emitP256Negate stkSt
    = .ok { stkSt with stack := .vBytes (RunarVerification.Crypto.Spec.p256Negate p) :: rest }

/-- `emitP256OnCurve`: stack `[point, …]` reduces to `[p256OnCurve point, …]`. -/
axiom emitP256OnCurve_runOps_eq (stkSt : StackState) (p : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes p :: rest) :
    runOps emitP256OnCurve stkSt
    = .ok { stkSt with stack := .vBool (Crypto.p256OnCurve p) :: rest }

/-- `emitP256EncodeCompressed`: stack `[point, …]` reduces to
`[p256EncodeCompressed point, …]`. -/
axiom emitP256EncodeCompressed_runOps_eq (stkSt : StackState) (p : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes p :: rest) :
    runOps emitP256EncodeCompressed stkSt
    = .ok { stkSt with stack := .vBytes (Crypto.p256EncodeCompressed p) :: rest }

/-- `emitVerifyECDSA_P256`: stack `[msg, sig, pk, …]` (top = pk) reduces to
`[verifyECDSA_P256 sig pk msg, …]`. The argument order on the runtime stack
matches `cEmitVerifyECDSAOps`'s `Tracker.init` order: `_msg`, `_sig`, `_pk`. -/
axiom emitVerifyECDSA_P256_runOps_eq (stkSt : StackState)
    (msg sig pk : ByteArray) (rest : List Value)
    (hStk : stkSt.stack = .vBytes pk :: .vBytes sig :: .vBytes msg :: rest) :
    runOps emitVerifyECDSA_P256 stkSt
    = .ok { stkSt with stack := .vBool (Crypto.verifyECDSA_P256 sig pk msg) :: rest }

/-! ### P-384 codegen-to-spec axioms (mirror P-256) -/

/-- `emitP384Add`: stack `[p1, p2, …]` reduces to `[p384Add p1 p2, …]`. -/
axiom emitP384Add_runOps_eq (stkSt : StackState) (p1 p2 : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes p2 :: .vBytes p1 :: rest) :
    runOps emitP384Add stkSt
    = .ok { stkSt with stack := .vBytes (Crypto.p384Add p1 p2) :: rest }

/-- `emitP384Mul`: stack `[point, scalar, …]` reduces to
`[p384Mul point scalar, …]`. -/
axiom emitP384Mul_runOps_eq (stkSt : StackState) (p : ByteArray) (k : Int)
    (rest : List Value)
    (hStk : stkSt.stack = .vBigint k :: .vBytes p :: rest) :
    runOps emitP384Mul stkSt
    = .ok { stkSt with stack := .vBytes (Crypto.p384Mul p k) :: rest }

/-- `emitP384MulGen`: stack `[scalar, …]` reduces to `[p384MulGen scalar, …]`. -/
axiom emitP384MulGen_runOps_eq (stkSt : StackState) (k : Int)
    (rest : List Value)
    (hStk : stkSt.stack = .vBigint k :: rest) :
    runOps emitP384MulGen stkSt
    = .ok { stkSt with stack := .vBytes (Crypto.p384MulGen k) :: rest }

/-- `emitP384Negate`: stack `[point, …]` reduces to `[p384Negate point, …]`. -/
axiom emitP384Negate_runOps_eq (stkSt : StackState) (p : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes p :: rest) :
    runOps emitP384Negate stkSt
    = .ok { stkSt with stack := .vBytes (RunarVerification.Crypto.Spec.p384Negate p) :: rest }

/-- `emitP384OnCurve`: stack `[point, …]` reduces to `[p384OnCurve point, …]`. -/
axiom emitP384OnCurve_runOps_eq (stkSt : StackState) (p : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes p :: rest) :
    runOps emitP384OnCurve stkSt
    = .ok { stkSt with stack := .vBool (Crypto.p384OnCurve p) :: rest }

/-- `emitP384EncodeCompressed`: stack `[point, …]` reduces to
`[p384EncodeCompressed point, …]`. -/
axiom emitP384EncodeCompressed_runOps_eq (stkSt : StackState) (p : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes p :: rest) :
    runOps emitP384EncodeCompressed stkSt
    = .ok { stkSt with stack := .vBytes (Crypto.p384EncodeCompressed p) :: rest }

/-- `emitVerifyECDSA_P384`: stack `[msg, sig, pk, …]` reduces to
`[verifyECDSA_P384 sig pk msg, …]`. -/
axiom emitVerifyECDSA_P384_runOps_eq (stkSt : StackState)
    (msg sig pk : ByteArray) (rest : List Value)
    (hStk : stkSt.stack = .vBytes pk :: .vBytes sig :: .vBytes msg :: rest) :
    runOps emitVerifyECDSA_P384 stkSt
    = .ok { stkSt with stack := .vBool (Crypto.verifyECDSA_P384 sig pk msg) :: rest }

end P256P384
end RunarVerification.Stack
