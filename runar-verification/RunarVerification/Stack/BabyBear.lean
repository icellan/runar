import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Ec

/-!
# Baby Bear field codegen — Phase 4-J (port of `packages/runar-compiler/src/passes/babybear-codegen.ts`)

Mirrors the TypeScript reference one-to-one. Each public entry point
mirrors a top-level `emitBB*` function in TS:

* `emitBBFieldAdd`, `emitBBFieldSub`, `emitBBFieldMul`, `emitBBFieldInv`
  — base BabyBear prime-field operations modulo
  `p = 2^31 - 2^27 + 1 = 2013265921`.
* `emitBBExt4Mul0..3`, `emitBBExt4Inv0..3` — degree-4 extension field
  operations using the irreducible `X^4 - W` with `W = 11`.

Source of truth: `packages/runar-compiler/src/passes/babybear-codegen.ts`.
Cross-reference: `compilers/go/codegen/babybear.go` (byte-exact peer).

The module reuses the `Tracker` structure from `RunarVerification.Stack.Ec`
(an opaque, read-only stack-state tracker that mirrors the TS `BBTracker`
identically — `nm : Array (Option String)` + `ops : Array StackOp`, with
`copyToTop`, `toTop`, `pick`, `roll`, `swap`, `rot`, `dup`, `drop`,
`pushInt`, `rename`, `rawBlock`). No new opaque definitions are
introduced; BabyBear codegen is pure data movement over StackOp.

**Trust surface.** This file adds zero new axioms and zero new opaque
defs. It produces concrete `List StackOp` values whose byte-exactness
to the TS reference is verified by the conformance suite (the
`pipelineGolden` test in `tests/PipelineGolden.lean`).
-/

namespace RunarVerification.Stack
namespace BabyBear

open RunarVerification.Stack
open RunarVerification.Stack.Ec (Tracker)
open RunarVerification.Stack.Ec.Tracker

/-! ## Constants (mirror `babybear-codegen.ts:18-23`) -/

/-- BabyBear field prime `p = 2^31 - 2^27 + 1 = 2013265921`. -/
def fieldP : Int := 2013265921

/-- Quadratic non-residue `W = 11` for the `X^4 - W` extension. -/
def fieldW : Int := 11

/-! ## Field arithmetic helpers (mirror `babybear-codegen.ts:131-232`) -/

/-- `fieldMod`: reduce a (possibly negative) value mod `p` using
`(a % p + p) % p`. Mirrors TS `fieldMod` (`babybear-codegen.ts:136-147`). -/
def fieldMod (t : Tracker) (aName resultName : String) : Tracker :=
  let t := t.toTop aName
  let extras : List StackOp :=
    [ .push (.bigint fieldP), .opcode "OP_MOD"
    , .push (.bigint fieldP), .opcode "OP_ADD"
    , .push (.bigint fieldP), .opcode "OP_MOD" ]
  t.rawBlock 1 (some resultName) extras

/-- `fieldAdd`: `(a + b) mod p`. Sum of two values in `[0, p-1]` is
non-negative, so a single `OP_MOD` suffices. Mirrors TS `fieldAdd`
(`babybear-codegen.ts:150-162`). -/
def fieldAdd (t : Tracker) (aName bName resultName : String) : Tracker :=
  let t := t.toTop aName
  let t := t.toTop bName
  let t := t.rawBlock 2 (some "_bb_add") [.opcode "OP_ADD"]
  let t := t.toTop "_bb_add"
  t.rawBlock 1 (some resultName)
    [.push (.bigint fieldP), .opcode "OP_MOD"]

/-- `fieldSub`: `(a - b) mod p` (non-negative — uses `fieldMod`).
Mirrors TS `fieldSub` (`babybear-codegen.ts:165-173`). -/
def fieldSub (t : Tracker) (aName bName resultName : String) : Tracker :=
  let t := t.toTop aName
  let t := t.toTop bName
  let t := t.rawBlock 2 (some "_bb_diff") [.opcode "OP_SUB"]
  fieldMod t "_bb_diff" resultName

/-- `fieldMul`: `(a * b) mod p`. Product is non-negative; single mod.
Mirrors TS `fieldMul` (`babybear-codegen.ts:176-188`). -/
def fieldMul (t : Tracker) (aName bName resultName : String) : Tracker :=
  let t := t.toTop aName
  let t := t.toTop bName
  let t := t.rawBlock 2 (some "_bb_prod") [.opcode "OP_MUL"]
  let t := t.toTop "_bb_prod"
  t.rawBlock 1 (some resultName)
    [.push (.bigint fieldP), .opcode "OP_MOD"]

/-- `fieldSqr`: `(a * a) mod p` via `copyToTop` + `fieldMul`.
Mirrors TS `fieldSqr` (`babybear-codegen.ts:191-194`). -/
def fieldSqr (t : Tracker) (aName resultName : String) : Tracker :=
  let t := t.copyToTop aName "_bb_sqr_copy"
  fieldMul t aName "_bb_sqr_copy" resultName

/-- `fieldMulConst`: `(a * c) mod p` for a constant `c`. Unlike the
secp256k1 variant in `Stack.Ec`, BabyBear's `fieldMulConst` does NOT
special-case `c = 2` to `OP_2MUL` — both TS and Go reference always
emit `[push c, OP_MUL]`. Diverging here would break byte-parity.
Mirrors TS `fieldMulConst` (`babybear-codegen.ts:293-304`). -/
def fieldMulConst (t : Tracker) (aName : String) (c : Int) (resultName : String) :
    Tracker :=
  let t := t.toTop aName
  let t := t.rawBlock 1 (some "_bb_mc")
    [.push (.bigint c), .opcode "OP_MUL"]
  let t := t.toTop "_bb_mc"
  t.rawBlock 1 (some resultName)
    [.push (.bigint fieldP), .opcode "OP_MOD"]

/-! ## Field inverse via Fermat's little theorem

`p - 2 = 2013265919 = 0b111_0111_1111_1111_1111_1111_1111_1111` — a
31-bit number with the bit at position 27 cleared and all other low
bits set. The TS reference processes bits 30..0 MSB-first: bit 30 is
handled by initialising the accumulator with `a` (no square), then
bits 29..0 are processed via square-and-multiply.

Bits 29..28 are 1, bit 27 is 0, bits 26..0 are all 1.
-/

/-- `p - 2` as an `Int` constant. -/
def fieldPMinus2 : Int := 2013265919

/-- Process bit `k` (where `k` counts down from 29 to 0): always square,
multiply by `a` if the bit is set in `p - 2`. -/
def fieldInvLoop (steps : Nat) (t : Tracker) (aName : String) : Tracker :=
  match steps with
  | 0     => t
  | k + 1 =>
    -- Square always
    let t := fieldSqr t "_inv_r" "_inv_r2"
    let t := t.rename "_inv_r"
    -- Multiply if bit `k` is set in `p - 2`
    let bitSet : Bool := ((fieldPMinus2 / (2 ^ k)) % 2) = 1
    let t :=
      if bitSet then
        let t := t.copyToTop aName "_inv_a"
        let t := fieldMul t "_inv_r" "_inv_a" "_inv_m"
        t.rename "_inv_r"
      else
        t
    fieldInvLoop k t aName

/-- `fieldInv`: `a^(p-2) mod p` via square-and-multiply. Consumes
`aName` and produces `resultName`. Mirrors TS `fieldInv`
(`babybear-codegen.ts:202-232`). -/
def fieldInv (t : Tracker) (aName resultName : String) : Tracker :=
  -- Bit 30 (MSB) = 1: start accumulator with a copy of `a`
  let t := t.copyToTop aName "_inv_r"
  -- Process bits 29..0 (30 iterations, MSB-first)
  let t := fieldInvLoop 30 t aName
  -- Cleanup: drop original `a`, rename result
  let t := t.toTop aName
  let t := t.drop
  let t := t.toTop "_inv_r"
  t.rename resultName

/-! ## Public entry points (mirror `babybear-codegen.ts:243-277`) -/

/-- `bbFieldAdd`: stack in `[..., a, b]` → out `[..., (a+b) mod p]`. -/
def emitBBFieldAdd : List StackOp :=
  let t : Tracker := Tracker.init [some "a", some "b"]
  let t := fieldAdd t "a" "b" "result"
  t.ops.toList

/-- `bbFieldSub`: stack in `[..., a, b]` → out `[..., (a-b) mod p]`. -/
def emitBBFieldSub : List StackOp :=
  let t : Tracker := Tracker.init [some "a", some "b"]
  let t := fieldSub t "a" "b" "result"
  t.ops.toList

/-- `bbFieldMul`: stack in `[..., a, b]` → out `[..., (a*b) mod p]`. -/
def emitBBFieldMul : List StackOp :=
  let t : Tracker := Tracker.init [some "a", some "b"]
  let t := fieldMul t "a" "b" "result"
  t.ops.toList

/-- `bbFieldInv`: stack in `[..., a]` → out `[..., a^(p-2) mod p]`. -/
def emitBBFieldInv : List StackOp :=
  let t : Tracker := Tracker.init [some "a"]
  let t := fieldInv t "a" "result"
  t.ops.toList

/-! ## Quartic extension F[X]/(X⁴ - 11) — multiplication

For elements `a = (a0, a1, a2, a3)` and `b = (b0, b1, b2, b3)`:
  r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
  r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
  r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
  r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0

Each `bbExt4MulN` builtin computes a single component; the high-level
contract chains them. Stack in for every component:
`[a0, a1, a2, a3, b0, b1, b2, b3]` (b3 on top); stack out: `[result]`.
Mirrors TS `emitExt4MulComponent` (`babybear-codegen.ts:311-389`).
-/

/-- Drop every `nm` slot whose name is in `names` (consume order
matches the TS reference's `for ... t.toTop(name); t.drop()` loop). -/
def dropNames (t : Tracker) (names : List String) : Tracker :=
  names.foldl (init := t) fun t n =>
    let t := t.toTop n
    t.drop

/-- Common epilogue for ext4 mul: drop the 8 input names, then promote
`_r` to `result` at TOS. -/
def ext4MulEpilogue (t : Tracker) : Tracker :=
  let t := dropNames t ["a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3"]
  let t := t.toTop "_r"
  t.rename "result"

/-- Component 0: `r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)`. -/
def emitBBExt4Mul0 : List StackOp :=
  let t : Tracker := Tracker.init
    [some "a0", some "a1", some "a2", some "a3",
     some "b0", some "b1", some "b2", some "b3"]
  let t := t.copyToTop "a0" "_a0" |>.copyToTop "b0" "_b0"
  let t := fieldMul t "_a0" "_b0" "_t0"
  let t := t.copyToTop "a1" "_a1" |>.copyToTop "b3" "_b3"
  let t := fieldMul t "_a1" "_b3" "_t1"
  let t := t.copyToTop "a2" "_a2" |>.copyToTop "b2" "_b2"
  let t := fieldMul t "_a2" "_b2" "_t2"
  let t := fieldAdd t "_t1" "_t2" "_t12"
  let t := t.copyToTop "a3" "_a3" |>.copyToTop "b1" "_b1"
  let t := fieldMul t "_a3" "_b1" "_t3"
  let t := fieldAdd t "_t12" "_t3" "_cross"
  let t := fieldMulConst t "_cross" fieldW "_wcross"
  let t := fieldAdd t "_t0" "_wcross" "_r"
  let t := ext4MulEpilogue t
  t.ops.toList

/-- Component 1: `r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)`. -/
def emitBBExt4Mul1 : List StackOp :=
  let t : Tracker := Tracker.init
    [some "a0", some "a1", some "a2", some "a3",
     some "b0", some "b1", some "b2", some "b3"]
  let t := t.copyToTop "a0" "_a0" |>.copyToTop "b1" "_b1"
  let t := fieldMul t "_a0" "_b1" "_t0"
  let t := t.copyToTop "a1" "_a1" |>.copyToTop "b0" "_b0"
  let t := fieldMul t "_a1" "_b0" "_t1"
  let t := fieldAdd t "_t0" "_t1" "_direct"
  let t := t.copyToTop "a2" "_a2" |>.copyToTop "b3" "_b3"
  let t := fieldMul t "_a2" "_b3" "_t2"
  let t := t.copyToTop "a3" "_a3" |>.copyToTop "b2" "_b2"
  let t := fieldMul t "_a3" "_b2" "_t3"
  let t := fieldAdd t "_t2" "_t3" "_cross"
  let t := fieldMulConst t "_cross" fieldW "_wcross"
  let t := fieldAdd t "_direct" "_wcross" "_r"
  let t := ext4MulEpilogue t
  t.ops.toList

/-- Component 2: `r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)`. -/
def emitBBExt4Mul2 : List StackOp :=
  let t : Tracker := Tracker.init
    [some "a0", some "a1", some "a2", some "a3",
     some "b0", some "b1", some "b2", some "b3"]
  let t := t.copyToTop "a0" "_a0" |>.copyToTop "b2" "_b2"
  let t := fieldMul t "_a0" "_b2" "_t0"
  let t := t.copyToTop "a1" "_a1" |>.copyToTop "b1" "_b1"
  let t := fieldMul t "_a1" "_b1" "_t1"
  let t := fieldAdd t "_t0" "_t1" "_sum01"
  let t := t.copyToTop "a2" "_a2" |>.copyToTop "b0" "_b0"
  let t := fieldMul t "_a2" "_b0" "_t2"
  let t := fieldAdd t "_sum01" "_t2" "_direct"
  let t := t.copyToTop "a3" "_a3" |>.copyToTop "b3" "_b3"
  let t := fieldMul t "_a3" "_b3" "_t3"
  let t := fieldMulConst t "_t3" fieldW "_wcross"
  let t := fieldAdd t "_direct" "_wcross" "_r"
  let t := ext4MulEpilogue t
  t.ops.toList

/-- Component 3: `r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0`. -/
def emitBBExt4Mul3 : List StackOp :=
  let t : Tracker := Tracker.init
    [some "a0", some "a1", some "a2", some "a3",
     some "b0", some "b1", some "b2", some "b3"]
  let t := t.copyToTop "a0" "_a0" |>.copyToTop "b3" "_b3"
  let t := fieldMul t "_a0" "_b3" "_t0"
  let t := t.copyToTop "a1" "_a1" |>.copyToTop "b2" "_b2"
  let t := fieldMul t "_a1" "_b2" "_t1"
  let t := fieldAdd t "_t0" "_t1" "_sum01"
  let t := t.copyToTop "a2" "_a2" |>.copyToTop "b1" "_b1"
  let t := fieldMul t "_a2" "_b1" "_t2"
  let t := fieldAdd t "_sum01" "_t2" "_sum012"
  let t := t.copyToTop "a3" "_a3" |>.copyToTop "b0" "_b0"
  let t := fieldMul t "_a3" "_b0" "_t3"
  let t := fieldAdd t "_sum012" "_t3" "_r"
  let t := ext4MulEpilogue t
  t.ops.toList

/-! ## Quartic extension — inverse (tower of quadratics, W = 11)

View `a = (a0, a1, a2, a3)` as `(even, odd)` where
`even = (a0, a2)` and `odd = (a1, a3)` in `F[X²]/(X⁴ - W) = F'[Y]/(Y² - W)`.

  norm0 = a0² + W*a2² - 2*W*a1*a3
  norm1 = 2*a0*a2 - a1² - W*a3²
  det   = norm0² - W*norm1²
  scalar = inv(det)
  inv_n0 = norm0 * scalar
  inv_n1 = -norm1 * scalar  (= (p - norm1) * scalar)

Then the inverse components are:
  r0 = a0*inv_n0 + W*a2*inv_n1
  r1 = -(a1*inv_n0 + W*a3*inv_n1)
  r2 = a0*inv_n1 + a2*inv_n0
  r3 = -(a1*inv_n1 + a3*inv_n0)

Mirrors TS `emitExt4InvComponent` (`babybear-codegen.ts:417-542`).
-/

/-- Shared prologue: leaves `_inv_n0` and `_inv_n1` on the tracker. -/
def ext4InvPrologue (t : Tracker) : Tracker :=
  -- Step 1: norm0 = a0² + W*a2² - 2*W*a1*a3
  let t := t.copyToTop "a0" "_a0c"
  let t := fieldSqr t "_a0c" "_a0sq"
  let t := t.copyToTop "a2" "_a2c"
  let t := fieldSqr t "_a2c" "_a2sq"
  let t := fieldMulConst t "_a2sq" fieldW "_wa2sq"
  let t := fieldAdd t "_a0sq" "_wa2sq" "_n0a"
  let t := t.copyToTop "a1" "_a1c"
  let t := t.copyToTop "a3" "_a3c"
  let t := fieldMul t "_a1c" "_a3c" "_a1a3"
  -- 2*W mod p — but W=11, so 2*W = 22 < p. The TS reference passes the
  -- value `(BB_W * 2n) % BB_P` literally; for W=11 that is just 22.
  let twoW : Int := (fieldW * 2) % fieldP
  let t := fieldMulConst t "_a1a3" twoW "_2wa1a3"
  let t := fieldSub t "_n0a" "_2wa1a3" "_norm0"
  -- Step 2: norm1 = 2*a0*a2 - a1² - W*a3²
  let t := t.copyToTop "a0" "_a0d"
  let t := t.copyToTop "a2" "_a2d"
  let t := fieldMul t "_a0d" "_a2d" "_a0a2"
  let t := fieldMulConst t "_a0a2" 2 "_2a0a2"
  let t := t.copyToTop "a1" "_a1d"
  let t := fieldSqr t "_a1d" "_a1sq"
  let t := fieldSub t "_2a0a2" "_a1sq" "_n1a"
  let t := t.copyToTop "a3" "_a3d"
  let t := fieldSqr t "_a3d" "_a3sq"
  let t := fieldMulConst t "_a3sq" fieldW "_wa3sq"
  let t := fieldSub t "_n1a" "_wa3sq" "_norm1"
  -- Step 3: scalar = (norm0² - W*norm1²)^(-1)
  let t := t.copyToTop "_norm0" "_n0copy"
  let t := fieldSqr t "_n0copy" "_n0sq"
  let t := t.copyToTop "_norm1" "_n1copy"
  let t := fieldSqr t "_n1copy" "_n1sq"
  let t := fieldMulConst t "_n1sq" fieldW "_wn1sq"
  let t := fieldSub t "_n0sq" "_wn1sq" "_det"
  let t := fieldInv t "_det" "_scalar"
  -- Step 4: inv_n0 = norm0 * scalar
  let t := t.copyToTop "_scalar" "_sc0"
  let t := fieldMul t "_norm0" "_sc0" "_inv_n0"
  -- inv_n1 = -norm1 * scalar = ((p - norm1) mod p) * scalar
  let t := t.copyToTop "_norm1" "_neg_n1_pre"
  let t := t.pushInt "_pval" fieldP
  let t := t.toTop "_neg_n1_pre"
  let t := t.rawBlock 2 (some "_neg_n1_sub") [.opcode "OP_SUB"]
  let t := fieldMod t "_neg_n1_sub" "_neg_norm1"
  let t := fieldMul t "_neg_norm1" "_scalar" "_inv_n1"
  t

/-- Drop every named slot in `t` except `_r`, then move `_r` to TOS and
rename it to `result`. Used as the cleanup epilogue for ext4 inverse.

The TS reference walks the live `nm` array and drops every named entry
that is not `_r`. We mirror that order — TOS-down — by reversing the
filtered name list before consuming, since `t.toTop name; t.drop` over
a list pops names left-to-right but the actual stack ordering doesn't
affect byte parity (each `toTop` finds the named slot wherever it is).
The TS reference iterates the `nm` array bottom→top and calls
`toTop`/`drop` for each — Lean does the same via `t.nm.foldl`. -/
def ext4InvEpilogue (t : Tracker) : Tracker :=
  let names : List String :=
    t.nm.foldl (init := ([] : List String)) fun acc o =>
      match o with
      | some n => if n = "_r" then acc else acc ++ [n]
      | none   => acc
  let t := dropNames t names
  let t := t.toTop "_r"
  t.rename "result"

/-- Component 0: `r0 = a0*inv_n0 + W*a2*inv_n1`. -/
def emitBBExt4Inv0 : List StackOp :=
  let t : Tracker := Tracker.init
    [some "a0", some "a1", some "a2", some "a3"]
  let t := ext4InvPrologue t
  -- r0 = a0*inv_n0 + W*a2*inv_n1
  let t := t.copyToTop "a0" "_ea0"
  let t := t.copyToTop "_inv_n0" "_ein0"
  let t := fieldMul t "_ea0" "_ein0" "_ep0"
  let t := t.copyToTop "a2" "_ea2"
  let t := t.copyToTop "_inv_n1" "_ein1"
  let t := fieldMul t "_ea2" "_ein1" "_ep1"
  let t := fieldMulConst t "_ep1" fieldW "_wep1"
  let t := fieldAdd t "_ep0" "_wep1" "_r"
  let t := ext4InvEpilogue t
  t.ops.toList

/-- Component 1: `r1 = -(a1*inv_n0 + W*a3*inv_n1)`. -/
def emitBBExt4Inv1 : List StackOp :=
  let t : Tracker := Tracker.init
    [some "a0", some "a1", some "a2", some "a3"]
  let t := ext4InvPrologue t
  -- odd0 = a1*inv_n0 + W*a3*inv_n1; r1 = (0 - odd0) mod p
  let t := t.copyToTop "a1" "_oa1"
  let t := t.copyToTop "_inv_n0" "_oin0"
  let t := fieldMul t "_oa1" "_oin0" "_op0"
  let t := t.copyToTop "a3" "_oa3"
  let t := t.copyToTop "_inv_n1" "_oin1"
  let t := fieldMul t "_oa3" "_oin1" "_op1"
  let t := fieldMulConst t "_op1" fieldW "_wop1"
  let t := fieldAdd t "_op0" "_wop1" "_odd0"
  let t := t.pushInt "_zero1" 0
  let t := fieldSub t "_zero1" "_odd0" "_r"
  let t := ext4InvEpilogue t
  t.ops.toList

/-- Component 2: `r2 = a0*inv_n1 + a2*inv_n0`. -/
def emitBBExt4Inv2 : List StackOp :=
  let t : Tracker := Tracker.init
    [some "a0", some "a1", some "a2", some "a3"]
  let t := ext4InvPrologue t
  -- r2 = a0*inv_n1 + a2*inv_n0
  let t := t.copyToTop "a0" "_ea0"
  let t := t.copyToTop "_inv_n1" "_ein1"
  let t := fieldMul t "_ea0" "_ein1" "_ep0"
  let t := t.copyToTop "a2" "_ea2"
  let t := t.copyToTop "_inv_n0" "_ein0"
  let t := fieldMul t "_ea2" "_ein0" "_ep1"
  let t := fieldAdd t "_ep0" "_ep1" "_r"
  let t := ext4InvEpilogue t
  t.ops.toList

/-- Component 3: `r3 = -(a1*inv_n1 + a3*inv_n0)`. -/
def emitBBExt4Inv3 : List StackOp :=
  let t : Tracker := Tracker.init
    [some "a0", some "a1", some "a2", some "a3"]
  let t := ext4InvPrologue t
  -- odd1 = a1*inv_n1 + a3*inv_n0; r3 = (0 - odd1) mod p
  let t := t.copyToTop "a1" "_oa1"
  let t := t.copyToTop "_inv_n1" "_oin1"
  let t := fieldMul t "_oa1" "_oin1" "_op0"
  let t := t.copyToTop "a3" "_oa3"
  let t := t.copyToTop "_inv_n0" "_oin0"
  let t := fieldMul t "_oa3" "_oin0" "_op1"
  let t := fieldAdd t "_op0" "_op1" "_odd1"
  let t := t.pushInt "_zero3" 0
  let t := fieldSub t "_zero3" "_odd1" "_r"
  let t := ext4InvEpilogue t
  t.ops.toList

end BabyBear
end RunarVerification.Stack
