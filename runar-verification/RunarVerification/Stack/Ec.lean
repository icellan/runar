import RunarVerification.Stack.Syntax

/-!
# secp256k1 EC codegen — Phase 4 (port of `packages/runar-compiler/src/passes/ec-codegen.ts`)

Mirrors the TypeScript reference one-to-one. Each public entry point
mirrors a top-level `emitEc*` function in TS:

* `emitEcAdd`, `emitEcMul`, `emitEcMulGen`, `emitEcNegate`,
  `emitEcOnCurve`, `emitEcModReduce`, `emitEcEncodeCompressed`,
  `emitEcMakePoint`, `emitEcPointX`, `emitEcPointY`.

The TS reference uses an `ECTracker` class that mutates an internal
`nm : (string | null)[]` (per-stack-slot name) and emits ops via a
callback. The Lean port models this purely:

* `Tracker` is a structure with `nm : Array (Option String)` and
  `ops : Array StackOp`. Every `Tracker.*` function returns the
  updated tracker (no mutation).
* The tracker is wrapped in `Id.run do` blocks where convenient.

Point representation: 64 bytes (`x[32] || y[32]`, big-endian unsigned).
Internal scalar multiplication uses Jacobian coordinates per TS reference.

Source of truth: `packages/runar-compiler/src/passes/ec-codegen.ts` (835 LoC).
-/

namespace RunarVerification.Stack
namespace Ec

open RunarVerification.Stack

/-! ## Constants (mirroring `ec-codegen.ts:18-27`) -/

/-- secp256k1 field prime `p = 2^256 - 2^32 - 977`. -/
def fieldP : Int :=
  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

/-- `p - 2`, used for Fermat's little theorem modular inverse. -/
def fieldPMinus2 : Int := fieldP - 2

/-- secp256k1 curve order. -/
def curveN : Int :=
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

/-- secp256k1 generator x-coordinate. -/
def genX : Int :=
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

/-- secp256k1 generator y-coordinate. -/
def genY : Int :=
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

/-- Encode a non-negative `Int` as 32 big-endian bytes. -/
def bigintToBytes32 (n : Int) : ByteArray := Id.run do
  let mut bytes : Array UInt8 := Array.replicate 32 0
  let mut v : Int := n
  let mut i : Nat := 31
  for _ in [0:32] do
    let lowByte : Nat := (v % 256).toNat
    bytes := bytes.set! i (UInt8.ofNat lowByte)
    v := v / 256
    if i > 0 then i := i - 1
  pure (ByteArray.mk bytes)

/-! ## Tracker (mirroring TS `ECTracker`)

Pure record — every operation returns an updated `Tracker`. `nm` mirrors
the TS `nm: (string | null)[]` (bottom→top). `ops` is the accumulated
StackOp output (we avoid the TS callback by simply appending). -/

structure Tracker where
  nm  : Array (Option String)
  ops : Array StackOp
  deriving Inhabited

namespace Tracker

@[inline] def init (nms : List (Option String)) : Tracker :=
  { nm := nms.toArray, ops := #[] }

@[inline] def emit (t : Tracker) (op : StackOp) : Tracker :=
  { t with ops := t.ops.push op }

@[inline] def depth (t : Tracker) : Nat := t.nm.size

/-- Find depth-from-TOS of `name` (rightmost match, mirrors TS `findDepth`).
Returns `0` if absent (TS would throw, but we keep total). -/
def findDepth (t : Tracker) (name : String) : Nat := Id.run do
  let n := t.nm.size
  let mut i : Nat := n
  while i > 0 do
    i := i - 1
    if t.nm[i]! == some name then
      return n - 1 - i
  return 0

@[inline] def pushBytes (t : Tracker) (n : String) (v : ByteArray) : Tracker :=
  let t := t.emit (.push (.bytes v))
  { t with nm := t.nm.push (some n) }

@[inline] def pushInt (t : Tracker) (n : String) (v : Int) : Tracker :=
  let t := t.emit (.push (.bigint v))
  { t with nm := t.nm.push (some n) }

@[inline] def dup (t : Tracker) (n : String) : Tracker :=
  let t := t.emit .dup
  { t with nm := t.nm.push (some n) }

@[inline] def drop (t : Tracker) : Tracker :=
  let t := t.emit .drop
  { t with nm := t.nm.pop }

@[inline] def nip (t : Tracker) : Tracker :=
  let t := t.emit .nip
  let L := t.nm.size
  if L ≥ 2 then
    { t with nm := (t.nm.eraseIdxIfInBounds (L - 2)) }
  else t

@[inline] def over (t : Tracker) (n : String) : Tracker :=
  let t := t.emit .over
  { t with nm := t.nm.push (some n) }

@[inline] def swap (t : Tracker) : Tracker :=
  let t := t.emit .swap
  let L := t.nm.size
  if L ≥ 2 then
    let topI := L - 1
    let secondI := L - 2
    let topV := t.nm[topI]!
    let secondV := t.nm[secondI]!
    { t with nm := (t.nm.set! topI secondV).set! secondI topV }
  else t

@[inline] def rot (t : Tracker) : Tracker :=
  let t := t.emit .rot
  let L := t.nm.size
  if L ≥ 3 then
    -- Take element at index L-3 and move it to top
    let r := t.nm[L - 3]!
    let nm' := t.nm.eraseIdxIfInBounds (L - 3)
    { t with nm := nm'.push r }
  else t

@[inline] def op (t : Tracker) (code : String) : Tracker :=
  t.emit (.opcode code)

/-- `roll(d)`: 0 → nop, 1 → swap, 2 → rot, else `.roll d`.
The single Lean `.roll d` op encodes as TS's `push d + roll d` pair. -/
def roll (t : Tracker) (d : Nat) : Tracker :=
  match d with
  | 0     => t
  | 1     => t.swap
  | 2     => t.rot
  | n + 3 =>
    let t := t.emit (.roll (n + 3))
    -- Take element at depth d (index L-1-d) and move to top
    let L := t.nm.size
    if L ≥ d + 1 then
      let r := t.nm[L - 1 - d]!
      let nm' := t.nm.eraseIdxIfInBounds (L - 1 - d)
      { t with nm := nm'.push r }
    else t

/-- `pick(d, n)`: 0 → dup(n), 1 → over(n), else `.pickStruct d` then push name.
The single Lean `.pickStruct d` op encodes byte-identically to the TS
reference's `push d + pick d` pair (Emit synthesises the depth push),
but with no-pop runtime semantics matching the copy-only TS lowering. -/
def pick (t : Tracker) (d : Nat) (n : String) : Tracker :=
  match d with
  | 0     => t.dup n
  | 1     => t.over n
  | k + 2 =>
    let t := t.emit (.pickStruct (k + 2))
    { t with nm := t.nm.push (some n) }

@[inline] def toTop (t : Tracker) (name : String) : Tracker :=
  t.roll (t.findDepth name)

@[inline] def copyToTop (t : Tracker) (name : String) (newName : String) : Tracker :=
  t.pick (t.findDepth name) newName

@[inline] def copyToTopSelf (t : Tracker) (name : String) : Tracker :=
  t.pick (t.findDepth name) name

@[inline] def toAlt (t : Tracker) : Tracker :=
  let t := t.emit (.opcode "OP_TOALTSTACK")
  { t with nm := t.nm.pop }

@[inline] def fromAlt (t : Tracker) (n : String) : Tracker :=
  let t := t.emit (.opcode "OP_FROMALTSTACK")
  { t with nm := t.nm.push (some n) }

@[inline] def rename (t : Tracker) (n : String) : Tracker :=
  let L := t.nm.size
  if L > 0 then
    { t with nm := t.nm.set! (L - 1) (some n) }
  else t

/-- Pop `consume.length` slots from `nm`, append `extraOps`, then push
`produce` slot if `some _`. Mirrors TS `rawBlock(consume, produce, fn)`. -/
def rawBlock (t : Tracker) (consumeCnt : Nat) (produce : Option String)
    (extraOps : List StackOp) : Tracker := Id.run do
  let mut nm' := t.nm
  -- Pop |consume| slots
  for _ in [0:consumeCnt] do
    nm' := nm'.pop
  -- Append the raw ops
  let mut ops' := t.ops
  for op in extraOps do
    ops' := ops'.push op
  match produce with
  | some n => return { nm := nm'.push (some n), ops := ops' }
  | none   => return { nm := nm', ops := ops' }

/-- Pop one slot, run inner-tracker on cloned state, capture its ops as
the body of an `ifOp`, append the ifOp, optionally push result. -/
def emitIfTracker (t : Tracker) (condName : String)
    (thenBody elseBody : Tracker → Tracker)
    (resultName : Option String) : Tracker :=
  let t := t.toTop condName
  let nmAfterCond := t.nm.pop
  let innerInit : Tracker := { nm := nmAfterCond, ops := #[] }
  let tThen := thenBody innerInit
  let tElse := elseBody innerInit
  let ifOp : StackOp := .ifOp tThen.ops.toList (some tElse.ops.toList)
  let t' : Tracker := { nm := nmAfterCond, ops := t.ops.push ifOp }
  match resultName with
  | some n => { t' with nm := t'.nm.push (some n) }
  | none   => t'

end Tracker

open Tracker

/-! ## Field arithmetic helpers (mirror `ec-codegen.ts:142-261`) -/

/-- Push the field prime `p` onto the stack as a script-number. -/
@[inline] def pushFieldP (t : Tracker) (name : String) : Tracker :=
  t.pushInt name fieldP

/-- `(a % p + p) % p` raw-block ops list (mirrors TS `fieldMod`). -/
def fieldModOps : List StackOp :=
  [ .opcode "OP_2DUP"   -- a p a p
  , .opcode "OP_MOD"    -- a p (a%p)
  , .rot                -- p (a%p) a
  , .drop               -- p (a%p)
  , .over               -- p (a%p) p
  , .opcode "OP_ADD"    -- p ((a%p)+p)
  , .swap               -- ((a%p)+p) p
  , .opcode "OP_MOD"    -- ((a%p+p)%p)
  ]

/-- `fieldMod`: reduce TOS mod p, ensure non-negative.
Expects `aName` on tracker stack; produces `resultName`. -/
def fieldMod (t : Tracker) (aName resultName : String) : Tracker :=
  let t := t.toTop aName
  let t := pushFieldP t "_fmod_p"
  t.rawBlock 2 (some resultName) fieldModOps

/-- `fieldAdd`: `(a + b) mod p`. -/
def fieldAdd (t : Tracker) (aName bName resultName : String) : Tracker :=
  let t := t.toTop aName
  let t := t.toTop bName
  let t := t.rawBlock 2 (some "_fadd_sum") [.opcode "OP_ADD"]
  fieldMod t "_fadd_sum" resultName

/-- `fieldSub`: `(a - b) mod p` (non-negative). -/
def fieldSub (t : Tracker) (aName bName resultName : String) : Tracker :=
  let t := t.toTop aName
  let t := t.toTop bName
  let t := t.rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]
  fieldMod t "_fsub_diff" resultName

/-- `fieldMul`: `(a * b) mod p`. -/
def fieldMul (t : Tracker) (aName bName resultName : String) : Tracker :=
  let t := t.toTop aName
  let t := t.toTop bName
  let t := t.rawBlock 2 (some "_fmul_prod") [.opcode "OP_MUL"]
  fieldMod t "_fmul_prod" resultName

/-- `fieldMulConst`: `(a * c) mod p` with small constant `c`.
`c = 2` uses `OP_2MUL`; otherwise `push c; OP_MUL`. -/
def fieldMulConst (t : Tracker) (aName : String) (c : Int) (resultName : String) :
    Tracker :=
  let t := t.toTop aName
  let extras : List StackOp :=
    if c = 2 then
      [.opcode "OP_2MUL"]
    else
      [.push (.bigint c), .opcode "OP_MUL"]
  let t := t.rawBlock 1 (some "_fmc_prod") extras
  fieldMod t "_fmc_prod" resultName

/-- `fieldSqr`: `(a * a) mod p`. -/
def fieldSqr (t : Tracker) (aName resultName : String) : Tracker :=
  let t := t.copyToTop aName "_fsqr_copy"
  fieldMul t aName "_fsqr_copy" resultName

/-- `fieldInv`: `a^(p-2) mod p` via square-and-multiply. Consumes `aName`.

Mirrors TS `fieldInv` (`ec-codegen.ts:227-261`):

* p-2 in hex: bits 255..32 are all 1 except bit 32 = 0; bits 31..0 = 0xFFFFFC2D.
* Start: result = a (bit 255 = 1).
* For 222 iterations (bits 254..33): square + multiply.
* Bit 32: square only.
* For bits 31..0 of 0xFFFFFC2D: square + (multiply if bit set).
* Cleanup: drop original `aName`, rename `_inv_r` to `resultName`.
-/
def fieldInvHighLoop : Nat → Tracker → String → Tracker
  | 0,     t, _aName  => t
  | n + 1, t, aName   =>
    let t := fieldSqr t "_inv_r" "_inv_r2"
    let t := t.rename "_inv_r"
    let t := t.copyToTop aName "_inv_a"
    let t := fieldMul t "_inv_r" "_inv_a" "_inv_m"
    let t := t.rename "_inv_r"
    fieldInvHighLoop n t aName

/-- Process bits 31..0 of `lowBits`, MSB-first. `i` counts down from 31 to 0
(decoded by recursion `step`); we square always and multiply when bit i is set. -/
def fieldInvLowLoop (steps : Nat) (lowBits : Int) (t : Tracker) (aName : String) :
    Tracker :=
  match steps with
  | 0     => t
  | k + 1 =>
    -- Bit position is `k`, MSB-first means the very first call processes bit 31
    -- when k = 31. The recursion decrements k each step.
    let t := fieldSqr t "_inv_r" "_inv_r2"
    let t := t.rename "_inv_r"
    let bitSet : Bool := ((lowBits / (2 ^ k)) % 2) = 1
    let t :=
      if bitSet then
        let t := t.copyToTop aName "_inv_a"
        let t := fieldMul t "_inv_r" "_inv_a" "_inv_m"
        t.rename "_inv_r"
      else
        t
    fieldInvLowLoop k lowBits t aName

def fieldInv (t : Tracker) (aName resultName : String) : Tracker :=
  -- Start: result = a (bit 255 = 1)
  let t := t.copyToTop aName "_inv_r"
  -- 222 iterations for bits 254..33
  let t := fieldInvHighLoop 222 t aName
  -- Bit 32 is 0: square only
  let t := fieldSqr t "_inv_r" "_inv_r2"
  let t := t.rename "_inv_r"
  -- Low 32 bits of p-2 = 0xFFFFFC2D
  let lowBits : Int := 0xFFFFFC2D
  let t := fieldInvLowLoop 32 lowBits t aName
  -- Cleanup: drop original input, rename result
  let t := t.toTop aName
  let t := t.drop
  let t := t.toTop "_inv_r"
  t.rename resultName

/-! ## Point decompose / compose (mirror `ec-codegen.ts:267-339`) -/

/-- Inline 32-byte reversal on TOS. 6 setup ops + 32 × 9 ops + 1 drop = 295 ops.
Mirrors TS `emitReverse32`. -/
def emitReverse32Step : List StackOp :=
  [ .push (.bigint 1)
  , .opcode "OP_SPLIT"
  , .rot
  , .rot
  , .swap
  , .opcode "OP_CAT"
  , .swap ]

def emitReverse32Loop : Nat → List StackOp
  | 0     => []
  | n + 1 => emitReverse32Step ++ emitReverse32Loop n

def emitReverse32Ops : List StackOp :=
  [ .opcode "OP_0"
  , .swap ]
  ++ emitReverse32Loop 32
  ++ [ .drop ]

/-- Decompose 64-byte Point → (x_num, y_num).
Consumes `pointName`, produces `xName` and `yName`. -/
def decomposePoint (t : Tracker) (pointName xName yName : String) : Tracker :=
  let t := t.toTop pointName
  -- OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top)
  let t := t.rawBlock 1 none [.push (.bigint 32), .opcode "OP_SPLIT"]
  -- Manually push the two new items
  let t : Tracker := { t with nm := (t.nm.push (some "_dp_xb")).push (some "_dp_yb") }
  -- Convert y_bytes (TOS) → num
  let yConvertOps : List StackOp :=
    emitReverse32Ops
    ++ [ .push (.bytes (ByteArray.mk #[0x00]))
       , .opcode "OP_CAT"
       , .opcode "OP_BIN2NUM" ]
  let t := t.rawBlock 1 (some yName) yConvertOps
  -- Convert x_bytes → num
  let t := t.toTop "_dp_xb"
  let xConvertOps : List StackOp :=
    emitReverse32Ops
    ++ [ .push (.bytes (ByteArray.mk #[0x00]))
       , .opcode "OP_CAT"
       , .opcode "OP_BIN2NUM" ]
  let t := t.rawBlock 1 (some xName) xConvertOps
  -- Stack: [yName, xName] — swap to [xName, yName]
  t.swap

/-- Compose (x_num, y_num) → 64-byte Point.
Consumes `xName` and `yName`, produces `resultName`. -/
def composePoint (t : Tracker) (xName yName resultName : String) : Tracker :=
  -- Convert x to 32-byte big-endian
  let xConvOps : List StackOp :=
    [ .push (.bigint 33)
    , .opcode "OP_NUM2BIN"
    , .push (.bigint 32)
    , .opcode "OP_SPLIT"
    , .drop ]
    ++ emitReverse32Ops
  let t := t.toTop xName
  let t := t.rawBlock 1 (some "_cp_xb") xConvOps
  -- Convert y similarly
  let yConvOps : List StackOp :=
    [ .push (.bigint 33)
    , .opcode "OP_NUM2BIN"
    , .push (.bigint 32)
    , .opcode "OP_SPLIT"
    , .drop ]
    ++ emitReverse32Ops
  let t := t.toTop yName
  let t := t.rawBlock 1 (some "_cp_yb") yConvOps
  -- Cat: x_be || y_be (x is below y after the two toTops)
  let t := t.toTop "_cp_xb"
  let t := t.toTop "_cp_yb"
  t.rawBlock 2 (some resultName) [.opcode "OP_CAT"]

/-! ## Affine point addition (mirror `ec-codegen.ts:378-414`) -/

/-- Affine addition: expects `px, py, qx, qy` on tracker (qy=TOS).
Produces `rx, ry`; consumes all four inputs. -/
def affineAdd (t : Tracker) : Tracker :=
  -- s_num = qy - py
  let t := t.copyToTop "qy" "_qy1"
  let t := t.copyToTop "py" "_py1"
  let t := fieldSub t "_qy1" "_py1" "_s_num"
  -- s_den = qx - px
  let t := t.copyToTop "qx" "_qx1"
  let t := t.copyToTop "px" "_px1"
  let t := fieldSub t "_qx1" "_px1" "_s_den"
  -- s = s_num / s_den mod p
  let t := fieldInv t "_s_den" "_s_den_inv"
  let t := fieldMul t "_s_num" "_s_den_inv" "_s"
  -- rx = s² - px - qx mod p
  let t := t.copyToTop "_s" "_s_keep"
  let t := fieldSqr t "_s" "_s2"
  let t := t.copyToTop "px" "_px2"
  let t := fieldSub t "_s2" "_px2" "_rx1"
  let t := t.copyToTop "qx" "_qx2"
  let t := fieldSub t "_rx1" "_qx2" "rx"
  -- ry = s * (px - rx) - py mod p
  let t := t.copyToTop "px" "_px3"
  let t := t.copyToTop "rx" "_rx2"
  let t := fieldSub t "_px3" "_rx2" "_px_rx"
  let t := fieldMul t "_s_keep" "_px_rx" "_s_px_rx"
  let t := t.copyToTop "py" "_py2"
  let t := fieldSub t "_s_px_rx" "_py2" "ry"
  -- Clean up original points
  let t := t.toTop "px" |>.drop
  let t := t.toTop "py" |>.drop
  let t := t.toTop "qx" |>.drop
  let t := t.toTop "qy" |>.drop
  t

/-! ## Jacobian point doubling (mirror `ec-codegen.ts:424-473`) -/

def jacobianDouble (t : Tracker) : Tracker :=
  -- Save copies of jx, jy, jz
  let t := t.copyToTop "jy" "_jy_save"
  let t := t.copyToTop "jx" "_jx_save"
  let t := t.copyToTop "jz" "_jz_save"
  -- A = jy²
  let t := fieldSqr t "jy" "_A"
  -- B = 4 * jx * A
  let t := t.copyToTop "_A" "_A_save"
  let t := fieldMul t "jx" "_A" "_xA"
  let t := t.pushInt "_four" 4
  let t := fieldMul t "_xA" "_four" "_B"
  -- C = 8 * A²
  let t := fieldSqr t "_A_save" "_A2"
  let t := t.pushInt "_eight" 8
  let t := fieldMul t "_A2" "_eight" "_C"
  -- D = 3 * X²
  let t := fieldSqr t "_jx_save" "_x2"
  let t := t.pushInt "_three" 3
  let t := fieldMul t "_x2" "_three" "_D"
  -- nx = D² - 2*B
  let t := t.copyToTop "_D" "_D_save"
  let t := t.copyToTop "_B" "_B_save"
  let t := fieldSqr t "_D" "_D2"
  let t := t.copyToTop "_B" "_B1"
  let t := fieldMulConst t "_B1" 2 "_2B"
  let t := fieldSub t "_D2" "_2B" "_nx"
  -- ny = D*(B - nx) - C
  let t := t.copyToTop "_nx" "_nx_copy"
  let t := fieldSub t "_B_save" "_nx_copy" "_B_nx"
  let t := fieldMul t "_D_save" "_B_nx" "_D_B_nx"
  let t := fieldSub t "_D_B_nx" "_C" "_ny"
  -- nz = 2 * Y * Z
  let t := fieldMul t "_jy_save" "_jz_save" "_yz"
  let t := fieldMulConst t "_yz" 2 "_nz"
  -- Cleanup
  let t := t.toTop "_B" |>.drop
  let t := t.toTop "jz" |>.drop
  let t := t.toTop "_nx" |>.rename "jx"
  let t := t.toTop "_ny" |>.rename "jy"
  let t := t.toTop "_nz" |>.rename "jz"
  t

/-! ## Jacobian → Affine (mirror `ec-codegen.ts:479-487`) -/

def jacobianToAffine (t : Tracker) (rxName ryName : String) : Tracker :=
  let t := fieldInv t "jz" "_zinv"
  let t := t.copyToTop "_zinv" "_zinv_keep"
  let t := fieldSqr t "_zinv" "_zinv2"
  let t := t.copyToTop "_zinv2" "_zinv2_keep"
  let t := fieldMul t "_zinv_keep" "_zinv2" "_zinv3"
  let t := fieldMul t "jx" "_zinv2_keep" rxName
  fieldMul t "jy" "_zinv3" ryName

/-! ## Jacobian mixed addition body (mirror `ec-codegen.ts:500-572`) -/

/-- Build the body of `IF` block for Jacobian mixed-add. Operates on a
fresh `Tracker` whose `nm` is cloned from the surrounding tracker (only
ops are returned; the surrounding tracker tracks its own state). -/
def buildJacobianAddAffineBody (initNm : Array (Option String)) :
    List StackOp :=
  let it : Tracker := { nm := initNm, ops := #[] }
  -- Save copies of values that get consumed but are needed later
  let it := it.copyToTop "jz" "_jz_for_z1cu"
  let it := it.copyToTop "jz" "_jz_for_z3"
  let it := it.copyToTop "jy" "_jy_for_y3"
  let it := it.copyToTop "jx" "_jx_for_u1h2"
  -- Z1sq = jz²
  let it := fieldSqr it "jz" "_Z1sq"
  -- Z1cu = _jz_for_z1cu * Z1sq
  let it := it.copyToTop "_Z1sq" "_Z1sq_for_u2"
  let it := fieldMul it "_jz_for_z1cu" "_Z1sq" "_Z1cu"
  -- U2 = ax * Z1sq_for_u2
  let it := it.copyToTop "ax" "_ax_c"
  let it := fieldMul it "_ax_c" "_Z1sq_for_u2" "_U2"
  -- S2 = ay * Z1cu
  let it := it.copyToTop "ay" "_ay_c"
  let it := fieldMul it "_ay_c" "_Z1cu" "_S2"
  -- H = U2 - jx
  let it := fieldSub it "_U2" "jx" "_H"
  -- R = S2 - jy
  let it := fieldSub it "_S2" "jy" "_R"
  -- Save copies of H
  let it := it.copyToTop "_H" "_H_for_h3"
  let it := it.copyToTop "_H" "_H_for_z3"
  -- H2 = H²
  let it := fieldSqr it "_H" "_H2"
  let it := it.copyToTop "_H2" "_H2_for_u1h2"
  -- H3 = H_for_h3 * H2
  let it := fieldMul it "_H_for_h3" "_H2" "_H3"
  -- U1H2 = _jx_for_u1h2 * H2_for_u1h2
  let it := fieldMul it "_jx_for_u1h2" "_H2_for_u1h2" "_U1H2"
  -- Save R, U1H2, H3 for Y3 computation
  let it := it.copyToTop "_R" "_R_for_y3"
  let it := it.copyToTop "_U1H2" "_U1H2_for_y3"
  let it := it.copyToTop "_H3" "_H3_for_y3"
  -- X3 = R² - H3 - 2*U1H2
  let it := fieldSqr it "_R" "_R2"
  let it := fieldSub it "_R2" "_H3" "_x3_tmp"
  let it := fieldMulConst it "_U1H2" 2 "_2U1H2"
  let it := fieldSub it "_x3_tmp" "_2U1H2" "_X3"
  -- Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
  let it := it.copyToTop "_X3" "_X3_c"
  let it := fieldSub it "_U1H2_for_y3" "_X3_c" "_u_minus_x"
  let it := fieldMul it "_R_for_y3" "_u_minus_x" "_r_tmp"
  let it := fieldMul it "_jy_for_y3" "_H3_for_y3" "_jy_h3"
  let it := fieldSub it "_r_tmp" "_jy_h3" "_Y3"
  -- Z3 = _jz_for_z3 * _H_for_z3
  let it := fieldMul it "_jz_for_z3" "_H_for_z3" "_Z3"
  -- Rename
  let it := it.toTop "_X3" |>.rename "jx"
  let it := it.toTop "_Y3" |>.rename "jy"
  let it := it.toTop "_Z3" |>.rename "jz"
  it.ops.toList

/-! ## Public entry points (mirror `ec-codegen.ts:583-835`) -/

/-- `ecAdd`: stack in `[point_a, point_b]` → out `[result_point]`. -/
def emitEcAdd : List StackOp :=
  let t : Tracker := Tracker.init [some "_pa", some "_pb"]
  let t := decomposePoint t "_pa" "px" "py"
  let t := decomposePoint t "_pb" "qx" "qy"
  let t := affineAdd t
  let t := composePoint t "rx" "ry" "_result"
  t.ops.toList

/-- One iteration of the scalar-mul loop. Mirrors the loop body
`ec-codegen.ts:630-662`. -/
def ecMulIter (t : Tracker) (bit : Nat) : Tracker :=
  let t := jacobianDouble t
  -- Extract bit: (k >> bit) & 1
  let t := t.copyToTop "_k" "_k_copy"
  let t :=
    if bit = 1 then
      t.rawBlock 1 (some "_shifted") [.opcode "OP_2DIV"]
    else if bit > 1 then
      let t := t.pushInt "_shift" (Int.ofNat bit)
      t.rawBlock 2 (some "_shifted") [.opcode "OP_RSHIFTNUM"]
    else
      -- bit = 0: rename _k_copy to _shifted (no shift op)
      t.rename "_shifted"
  let t := t.pushInt "_two" 2
  let t := t.rawBlock 2 (some "_bit") [.opcode "OP_MOD"]
  -- Move _bit to TOS and remove from tracker BEFORE generating add ops
  let t := t.toTop "_bit"
  let nmAfterPop := t.nm.pop
  -- Build add body with the post-pop nm
  let addOps := buildJacobianAddAffineBody nmAfterPop
  let ifOp : StackOp := .ifOp addOps (some [])
  -- Emit the ifOp; nm is consumed (popped) but no result pushed
  { nm := nmAfterPop, ops := t.ops.push ifOp }

/-- Iterate `ecMulIter` for bits 256, 255, …, 0. -/
def ecMulIterLoop : Nat → Tracker → Tracker
  | 0,     t => ecMulIter t 0  -- bit = 0 (final iteration)
  | n + 1, t => ecMulIterLoop n (ecMulIter t (n + 1))

/-- 257-iteration MSB-first double-and-add. -/
def ecMulAllBits (t : Tracker) : Tracker :=
  ecMulIterLoop 256 t

/-- `ecMul`: stack in `[point, scalar]` → out `[result_point]`.
Uses 257-iter MSB-first double-and-add with k+3n adjustment. -/
def emitEcMul : List StackOp :=
  let t : Tracker := Tracker.init [some "_pt", some "_k"]
  let t := decomposePoint t "_pt" "ax" "ay"
  -- k' = k + 3n
  let t := t.toTop "_k"
  let t := t.pushInt "_n" curveN
  let t := t.rawBlock 2 (some "_kn") [.opcode "OP_ADD"]
  let t := t.pushInt "_n2" curveN
  let t := t.rawBlock 2 (some "_kn2") [.opcode "OP_ADD"]
  let t := t.pushInt "_n3" curveN
  let t := t.rawBlock 2 (some "_kn3") [.opcode "OP_ADD"]
  let t := t.rename "_k"
  -- Init accumulator = P (bit 257 of k+3n is always 1)
  let t := t.copyToTop "ax" "jx"
  let t := t.copyToTop "ay" "jy"
  let t := t.pushInt "jz" 1
  -- 257 iterations
  let t := ecMulAllBits t
  -- Final affine conversion
  let t := jacobianToAffine t "_rx" "_ry"
  -- Cleanup
  let t := t.toTop "ax" |>.drop
  let t := t.toTop "ay" |>.drop
  let t := t.toTop "_k" |>.drop
  -- Compose result
  let t := composePoint t "_rx" "_ry" "_result"
  t.ops.toList

/-- Generator point as 64 bytes: `bigintToBytes32(GEN_X) || bigintToBytes32(GEN_Y)`. -/
def genPointBytes : ByteArray :=
  bigintToBytes32 genX ++ bigintToBytes32 genY

/-- `ecMulGen`: stack in `[scalar]` → out `[result_point]`.
Push G as 64-byte blob, swap, delegate to `ecMul`. -/
def emitEcMulGen : List StackOp :=
  [ .push (.bytes genPointBytes)
  , .swap ]
  ++ emitEcMul

/-- `ecNegate`: negate a point `(x, y) → (x, p - y)`. -/
def emitEcNegate : List StackOp :=
  let t : Tracker := Tracker.init [some "_pt"]
  let t := decomposePoint t "_pt" "_nx" "_ny"
  let t := pushFieldP t "_fp"
  let t := fieldSub t "_fp" "_ny" "_neg_y"
  let t := composePoint t "_nx" "_neg_y" "_result"
  t.ops.toList

/-- `ecOnCurve`: check `y² ≡ x³ + 7 mod p`. -/
def emitEcOnCurve : List StackOp :=
  let t : Tracker := Tracker.init [some "_pt"]
  let t := decomposePoint t "_pt" "_x" "_y"
  -- lhs = y²
  let t := fieldSqr t "_y" "_y2"
  -- rhs = x³ + 7
  let t := t.copyToTop "_x" "_x_copy"
  let t := fieldSqr t "_x" "_x2"
  let t := fieldMul t "_x2" "_x_copy" "_x3"
  let t := t.pushInt "_seven" 7
  let t := fieldAdd t "_x3" "_seven" "_rhs"
  -- Compare
  let t := t.toTop "_y2"
  let t := t.toTop "_rhs"
  let t := t.rawBlock 2 (some "_result") [.opcode "OP_EQUAL"]
  t.ops.toList

/-- `ecModReduce`: `((value % mod) + mod) % mod`. Stack `[value, mod]` → `[result]`.
Identical sequence to `fieldModOps`. -/
def emitEcModReduce : List StackOp :=
  [ .opcode "OP_2DUP"
  , .opcode "OP_MOD"
  , .rot
  , .drop
  , .over
  , .opcode "OP_ADD"
  , .swap
  , .opcode "OP_MOD" ]

/-- `ecEncodeCompressed`: 64-byte point → 33-byte compressed pubkey. -/
def emitEcEncodeCompressed : List StackOp :=
  [ .push (.bigint 32)
  , .opcode "OP_SPLIT"
  -- Stack: [x_bytes, y_bytes]
  , .opcode "OP_SIZE"
  , .push (.bigint 1)
  , .opcode "OP_SUB"
  , .opcode "OP_SPLIT"
  -- Stack: [x_bytes, y_prefix, last_byte]
  , .opcode "OP_BIN2NUM"
  , .push (.bigint 2)
  , .opcode "OP_MOD"
  -- Stack: [x_bytes, y_prefix, parity]
  , .swap
  , .drop
  -- Stack: [x_bytes, parity]
  , .ifOp [.push (.bytes (ByteArray.mk #[0x03]))]
          (some [.push (.bytes (ByteArray.mk #[0x02]))])
  -- Stack: [x_bytes, prefix_byte]
  , .swap
  , .opcode "OP_CAT" ]

/-- `ecMakePoint`: `(x: Int, y: Int) → Point`. Stack `[x, y]` → `[point_bytes]`. -/
def emitEcMakePoint : List StackOp :=
  -- Convert y → 32-byte BE
  [ .push (.bigint 33)
  , .opcode "OP_NUM2BIN"
  , .push (.bigint 32)
  , .opcode "OP_SPLIT"
  , .drop ]
  ++ emitReverse32Ops
  -- Stack: [x_num, y_be]
  ++ [ .swap
  -- Stack: [y_be, x_num]
     , .push (.bigint 33)
     , .opcode "OP_NUM2BIN"
     , .push (.bigint 32)
     , .opcode "OP_SPLIT"
     , .drop ]
  ++ emitReverse32Ops
  -- Stack: [y_be, x_be]
  ++ [ .swap
     , .opcode "OP_CAT" ]

/-- `ecPointX`: extract x-coordinate (Int) from Point. -/
def emitEcPointX : List StackOp :=
  [ .push (.bigint 32)
  , .opcode "OP_SPLIT"
  , .drop ]
  ++ emitReverse32Ops
  ++ [ .push (.bytes (ByteArray.mk #[0x00]))
     , .opcode "OP_CAT"
     , .opcode "OP_BIN2NUM" ]

/-- `ecPointY`: extract y-coordinate (Int) from Point. -/
def emitEcPointY : List StackOp :=
  [ .push (.bigint 32)
  , .opcode "OP_SPLIT"
  , .swap
  , .drop ]
  ++ emitReverse32Ops
  ++ [ .push (.bytes (ByteArray.mk #[0x00]))
     , .opcode "OP_CAT"
     , .opcode "OP_BIN2NUM" ]

end Ec
end RunarVerification.Stack
