import RunarVerification.Stack.Syntax

/-!
# SLH-DSA (FIPS 205) codegen — Phase 4 (port of
`packages/runar-compiler/src/passes/slh-dsa-codegen.ts`)

Mirrors the TypeScript reference one-to-one. The TS reference uses a
stateful `SLHTracker` class; the Lean port models that purely as a
`Tracker` record (`nm : Array (Option String)`, `ops : Array StackOp`).
Every `Tracker.*` returns the updated tracker.

## Layout

* §1  — Parameter sets (`SHA2_128s/f`, `SHA2_192s/f`, `SHA2_256s/f`).
* §1b — Generic byte-reversal `emitReverseN`.
* §2  — Compressed ADRS literal builders (`slhADRS`, `slhADRS18`).
* §2b — Runtime ADRS builders (`emitBuildADRS18`, `emitBuildADRS`)
        producing raw `StackOp` lists with depth-parameterised `pick`s.
* §3  — `Tracker` (purely-functional analogue of TS `SLHTracker`).
* §4  — Tweakable hash `T` (raw-form `emitSLHT_raw` and tracked form).
* §5  — One WOTS+ chain (`slhChainStepThen`, `emitSLHOneChain`).
* §6  — Full WOTS+ over `len` chains (`emitSLHWotsAll`).
* §7  — Merkle authentication path (`emitSLHMerkle`).
* §8  — FORS verification (`emitSLHFors`).
* §9  — `Hmsg` SHA-256-MGF1 message digest (`emitSLHHmsg`).
* §10 — Top-level `emitVerifySLHDSA`.

The SLH-DSA fixtures (`post-quantum-slhdsa`, `sphincs-wallet`) only
exercise `verifySLHDSA_SHA2_128s`. Other parameter sets are still
reachable through `slhParams` for completeness, but the public entry
points are switched on the parameter-set string.

Source of truth: `packages/runar-compiler/src/passes/slh-dsa-codegen.ts`
(1357 LoC). Cross-validated against `compilers/go/codegen/slh_dsa.go`.
-/

namespace RunarVerification.Stack
namespace SlhDsa

open RunarVerification.Stack

/-! ## §1 — Parameter sets -/

/-- FIPS 205 SHA-2 parameter set (compile-time constants used by codegen). -/
structure Params where
  n    : Nat   -- security parameter / hash output bytes (16, 24, 32)
  h    : Nat   -- total tree height
  d    : Nat   -- hypertree layers
  hp   : Nat   -- subtree height (h / d)
  a    : Nat   -- FORS tree height
  k    : Nat   -- FORS tree count
  w    : Nat := 16
  len1 : Nat   -- = 2 * n
  len2 : Nat   -- always 3 for SHA-2 sets
  len  : Nat   -- = len1 + len2
  deriving Inhabited

/-- Build a `Params` from the FIPS-205 vector. Mirrors TS `slhMk`. -/
@[inline] def mkParams (n h d a k : Nat) : Params :=
  let len1 := 2 * n
  let len2 := 3   -- for all SHA-2 SLH-DSA sets, ⌊log₂(len1·15)/log₂16⌋ + 1 = 3
  { n, h, d, hp := h / d, a, k, len1, len2, len := len1 + len2 }

/-- The six FIPS-205 SHA-2 parameter sets. -/
def paramsSHA2_128s : Params := mkParams 16 63 7  12 14
def paramsSHA2_128f : Params := mkParams 16 66 22 6  33
def paramsSHA2_192s : Params := mkParams 24 63 7  14 17
def paramsSHA2_192f : Params := mkParams 24 66 22 8  33
def paramsSHA2_256s : Params := mkParams 32 64 8  14 22
def paramsSHA2_256f : Params := mkParams 32 68 17 8  35

/-- Look up params by parameter-set key. -/
def paramsByKey : String → Option Params
  | "SHA2_128s" => some paramsSHA2_128s
  | "SHA2_128f" => some paramsSHA2_128f
  | "SHA2_192s" => some paramsSHA2_192s
  | "SHA2_192f" => some paramsSHA2_192f
  | "SHA2_256s" => some paramsSHA2_256s
  | "SHA2_256f" => some paramsSHA2_256f
  | _           => none

/-! ## §1b — Generic byte reversal helper

Unrolled fixed-length byte reversal for `n` bytes:
  * (n-1) split-into-individual-bytes ops
  * (n-1) swap-and-cat ops to reconstitute in reverse order.
Mirrors TS `emitReverseN`. -/

private def reverseSplitPhase : Nat → List StackOp
  | 0     => []
  | k + 1 => reverseSplitPhase k ++ [.push (.bigint 1), .opcode "OP_SPLIT"]

private def reverseConcatPhase : Nat → List StackOp
  | 0     => []
  | k + 1 => reverseConcatPhase k ++ [.swap, .opcode "OP_CAT"]

def emitReverseN (n : Nat) : List StackOp :=
  if n ≤ 1 then [] else
    reverseSplitPhase (n - 1) ++ reverseConcatPhase (n - 1)

/-! ## §2 — Compressed ADRS (22 bytes, FIPS-205 §11.2)

Layout:
  byte  0    : layer
  bytes 1-8  : tree (8 BE)
  byte  9    : type
  bytes 10-13: keypair (4 BE)
  bytes 14-17: chain / treeHeight (4 BE)
  bytes 18-21: hash / treeIndex (4 BE)
-/

def SLH_WOTS_HASH  : Nat := 0
def SLH_WOTS_PK    : Nat := 1
def SLH_TREE       : Nat := 2
def SLH_FORS_TREE  : Nat := 3
def SLH_FORS_ROOTS : Nat := 4

/-- Encode a non-negative `Int` as `n` big-endian bytes (truncated mod 256
per byte; matches the TS bit-shift composition for non-negatives). -/
def intToBytesBE (v : Int) (n : Nat) : ByteArray := Id.run do
  let mut bytes : Array UInt8 := Array.replicate n 0
  let mut x : Int := v
  let mut i : Nat := n
  for _ in [0:n] do
    if i = 0 then
      break
    i := i - 1
    let lo : Nat := (x % 256).toNat
    bytes := bytes.set! i (UInt8.ofNat lo)
    x := x / 256
  pure (ByteArray.mk bytes)

/-- 4-byte big-endian (TS `int4BE`). -/
@[inline] def int4BE (v : Nat) : ByteArray := intToBytesBE (Int.ofNat v) 4

/-- 8-byte big-endian. -/
@[inline] def int8BE (v : Nat) : ByteArray := intToBytesBE (Int.ofNat v) 8

/-- Single zero byte. -/
@[inline] def zero1 : ByteArray := ByteArray.mk #[0]

/-- `n`-byte zero pad. -/
@[inline] def zerosN (n : Nat) : ByteArray :=
  ByteArray.mk (Array.replicate n 0)

/-! ## §2b — Runtime ADRS builders

`treeAddr8` (8-byte BE tree address) and `keypair4` (4-byte BE keypair)
sit on the main stack and are picked at known depth. Layer / type / chain
are compile-time constants and pushed inline.
-/

/-- Selector for keypair source: either "PICK from `kp4Depth` from TOS" or
"push 4 zero bytes". -/
inductive Kp4Source where
  | depth (d : Nat) : Kp4Source
  | zero            : Kp4Source

/-- Selector for hash byte source. -/
inductive HashSource where
  | zero  : HashSource   -- append 4 zero bytes
  | stack : HashSource   -- TOS holds 4-byte BE hash, consumed and appended

/--
Emit runtime 18-byte ADRS prefix:
  layer(1B) || PICK(treeAddr8)(8B) || type(1B) || keypair4(4B) || chain(4B).

Net stack effect: +1 (the 18-byte result on TOS).
`ta8Depth` and `kp4Depth` are measured from TOS *before* this emits.
Mirrors TS `emitBuildADRS18`. -/
def emitBuildADRS18 (layer type chain ta8Depth : Nat) (kp4 : Kp4Source) :
    List StackOp :=
  let layerOps : List StackOp := [.push (.bytes (ByteArray.mk #[UInt8.ofNat (layer % 256)]))]
  -- After push: ta8 at ta8Depth+1
  let pickTa : List StackOp := [.pickStruct (ta8Depth + 1), .opcode "OP_CAT"]
  -- After CAT: (layer || ta8) net +1
  let typeOps : List StackOp := [.push (.bytes (ByteArray.mk #[UInt8.ofNat (type % 256)])), .opcode "OP_CAT"]
  -- Keypair: PICK or push 4 zeros
  let kpOps : List StackOp :=
    match kp4 with
    | .zero    => [.push (.bytes (zerosN 4)), .opcode "OP_CAT"]
    | .depth d => [.pickStruct (d + 1), .opcode "OP_CAT"]
  let chainOps : List StackOp := [.push (.bytes (int4BE chain)), .opcode "OP_CAT"]
  layerOps ++ pickTa ++ typeOps ++ kpOps ++ chainOps

/--
Emit runtime 22-byte ADRS.

`hash` mode:
  * `.zero`  — append 4 zero bytes (net +1)
  * `.stack` — TOS holds 4-byte BE hash; consumed and appended (net 0)

Mirrors TS `emitBuildADRS`.
-/
def emitBuildADRS (layer type chain ta8Depth : Nat) (kp4 : Kp4Source)
    (hash : HashSource) : List StackOp :=
  match hash with
  | .stack =>
    -- Save hash4 from TOS to alt
    let saveOps : List StackOp := [.opcode "OP_TOALTSTACK"]
    -- Depths shift by -1
    let kp4Adj : Kp4Source :=
      match kp4 with
      | .zero    => .zero
      | .depth d => .depth (d - 1)
    let prefixOps := emitBuildADRS18 layer type chain (ta8Depth - 1) kp4Adj
    saveOps ++ prefixOps ++ [.opcode "OP_FROMALTSTACK", .opcode "OP_CAT"]
  | .zero  =>
    let prefixOps := emitBuildADRS18 layer type chain ta8Depth kp4
    prefixOps ++ [.push (.bytes (zerosN 4)), .opcode "OP_CAT"]

/-! ## §3 — Tracker

Pure analogue of TS `SLHTracker`. Every operation returns an updated
tracker. -/

structure Tracker where
  nm  : Array (Option String)
  ops : Array StackOp
  deriving Inhabited

namespace Tracker

@[inline] def init (nms : List (Option String)) : Tracker :=
  { nm := nms.toArray, ops := #[] }

@[inline] def emit (t : Tracker) (op : StackOp) : Tracker :=
  { t with ops := t.ops.push op }

@[inline] def emitMany (t : Tracker) (ops : List StackOp) : Tracker :=
  ops.foldl (fun t op => t.emit op) t

@[inline] def depth (t : Tracker) : Nat := t.nm.size

/-- Find depth-from-TOS of `name` (rightmost match). Returns 0 if absent. -/
def findDepth (t : Tracker) (name : String) : Nat := Id.run do
  let n := t.nm.size
  let mut i : Nat := n
  while i > 0 do
    i := i - 1
    if t.nm[i]! == some name then
      return n - 1 - i
  return 0

/-- Predicate: is `name` somewhere on the tracker stack? -/
def has (t : Tracker) (name : String) : Bool := Id.run do
  let n := t.nm.size
  let mut i : Nat := 0
  while i < n do
    if t.nm[i]! == some name then return true
    i := i + 1
  return false

@[inline] def pushBytes (t : Tracker) (n : Option String) (v : ByteArray) : Tracker :=
  let t := t.emit (.push (.bytes v))
  { t with nm := t.nm.push n }

@[inline] def pushInt (t : Tracker) (n : Option String) (v : Int) : Tracker :=
  let t := t.emit (.push (.bigint v))
  { t with nm := t.nm.push n }

@[inline] def pushEmpty (t : Tracker) (n : Option String) : Tracker :=
  let t := t.emit (.opcode "OP_0")
  { t with nm := t.nm.push n }

@[inline] def dup (t : Tracker) (n : Option String) : Tracker :=
  let t := t.emit .dup
  { t with nm := t.nm.push n }

@[inline] def drop (t : Tracker) : Tracker :=
  let t := t.emit .drop
  { t with nm := t.nm.pop }

@[inline] def nip (t : Tracker) : Tracker :=
  let t := t.emit .nip
  let L := t.nm.size
  if L ≥ 2 then
    { t with nm := t.nm.eraseIdxIfInBounds (L - 2) }
  else t

@[inline] def over (t : Tracker) (n : Option String) : Tracker :=
  let t := t.emit .over
  { t with nm := t.nm.push n }

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
    let r := t.nm[L - 3]!
    let nm' := t.nm.eraseIdxIfInBounds (L - 3)
    { t with nm := nm'.push r }
  else t

@[inline] def opc (t : Tracker) (code : String) : Tracker :=
  t.emit (.opcode code)

/-- `roll(d)`: 0 → nop, 1 → swap, 2 → rot, else `.roll d`. -/
def roll (t : Tracker) (d : Nat) : Tracker :=
  match d with
  | 0     => t
  | 1     => t.swap
  | 2     => t.rot
  | n + 3 =>
    let t := t.emit (.roll (n + 3))
    let L := t.nm.size
    if L ≥ d + 1 then
      let r := t.nm[L - 1 - d]!
      let nm' := t.nm.eraseIdxIfInBounds (L - 1 - d)
      { t with nm := nm'.push r }
    else t

/-- `pick(d, n)`: 0 → dup(n), 1 → over(n), else `.pickStruct d` then push name.
The TS reference emits a single `pick` opcode at the StackOp layer (the
depth becomes a byte-level push inside `Emit`); we use `pickStruct`
(no-pop) for byte parity. -/
def pick (t : Tracker) (d : Nat) (n : Option String) : Tracker :=
  match d with
  | 0     => t.dup n
  | 1     => t.over n
  | k + 2 =>
    let t := t.emit (.pickStruct (k + 2))
    { t with nm := t.nm.push n }

@[inline] def toTop (t : Tracker) (name : String) : Tracker :=
  t.roll (t.findDepth name)

@[inline] def copyToTop (t : Tracker) (name : String) (newName : Option String) : Tracker :=
  t.pick (t.findDepth name) newName

@[inline] def toAlt (t : Tracker) : Tracker :=
  let t := t.emit (.opcode "OP_TOALTSTACK")
  { t with nm := t.nm.pop }

@[inline] def fromAlt (t : Tracker) (n : Option String) : Tracker :=
  let t := t.emit (.opcode "OP_FROMALTSTACK")
  { t with nm := t.nm.push n }

@[inline] def split (t : Tracker) (left right : Option String) : Tracker :=
  let t := t.emit (.opcode "OP_SPLIT")
  -- TS pops 2 (size + bytes) and pushes 2 (left, right). Tracker mirror:
  -- pop 2 names, push left then right.
  let nm0 := t.nm.pop |>.pop
  { t with nm := (nm0.push left).push right }

@[inline] def cat (t : Tracker) (n : Option String) : Tracker :=
  let t := t.emit (.opcode "OP_CAT")
  let nm0 := t.nm.pop |>.pop
  { t with nm := nm0.push n }

@[inline] def sha256 (t : Tracker) (n : Option String) : Tracker :=
  let t := t.emit (.opcode "OP_SHA256")
  let nm0 := t.nm.pop
  { t with nm := nm0.push n }

@[inline] def equal (t : Tracker) (n : Option String) : Tracker :=
  let t := t.emit (.opcode "OP_EQUAL")
  let nm0 := t.nm.pop |>.pop
  { t with nm := nm0.push n }

@[inline] def rename (t : Tracker) (n : Option String) : Tracker :=
  let L := t.nm.size
  if L > 0 then
    { t with nm := t.nm.set! (L - 1) n }
  else t

/-- `rawBlock`: emit raw opcodes; tracker only records net stack effect.
  * `consumeCnt` names popped (top is last).
  * `produce`    name for the single result, or `none`.
Mirrors TS `SLHTracker.rawBlock`. -/
def rawBlock (t : Tracker) (consumeCnt : Nat) (produce : Option String)
    (extra : List StackOp) : Tracker := Id.run do
  let mut nm' := t.nm
  for _ in [0:consumeCnt] do
    nm' := nm'.pop
  let mut ops' := t.ops
  for op in extra do
    ops' := ops'.push op
  match produce with
  | some n => return { nm := nm'.push (some n), ops := ops' }
  | none   => return { nm := nm', ops := ops' }

end Tracker

open Tracker

/-! ## §4 — Tweakable hash T(pkSeed, ADRS, M)

`trunc_n(SHA-256(pkSeedPad(64) || ADRS(22) || M))`. `pkSeedPad` is on
the main stack and accessed via PICK. -/

/-- Raw `T` body. Stack on entry: `... ADRS msg`, with `pkSeedPad` at
`pkSeedPadDepth` from TOS. Stack on exit: `... result`. Net: -1.
Mirrors TS `emitSLHT_raw`. -/
def emitSLHT_raw (n pkSeedPadDepth : Nat) : List StackOp :=
  let cat1 : List StackOp := [.opcode "OP_CAT"]
  -- After CAT: 2 consumed, 1 produced. pspDepth = pkSeedPadDepth - 1.
  let pickD := pkSeedPadDepth - 1
  let pickOps : List StackOp := [.pickStruct pickD]
  let combine : List StackOp :=
    [ .swap, .opcode "OP_CAT", .opcode "OP_SHA256" ]
  let truncate : List StackOp :=
    if n < 32 then
      [.push (.bigint (Int.ofNat n)), .opcode "OP_SPLIT", .drop]
    else []
  cat1 ++ pickOps ++ combine ++ truncate

/-! ## §5 — One WOTS+ chain

Conditional hash step body (the if-then payload).
Entry: `... sigElem(2) steps(1) hashAddr(0)` with prefix18 on alt.
Exit:  `... newSigElem(2) (steps-1)(1) (hashAddr+1)(0)`. Net 0.
Mirrors TS `slhChainStepThen`. -/
def slhChainStepThen (n pkSeedPadDepth : Nat) : List StackOp :=
  let dupHashAddr : List StackOp := [.dup]
  -- Convert copy to 4-byte big-endian
  let toBE4 : List StackOp :=
    [.push (.bigint 4), .opcode "OP_NUM2BIN"] ++ emitReverseN 4
  -- Pull prefix18 from alt: FROMALT; DUP; TOALT
  let pullPrefix : List StackOp :=
    [.opcode "OP_FROMALTSTACK", .opcode "OP_DUP", .opcode "OP_TOALTSTACK"]
  let buildAdrs : List StackOp :=
    [.swap, .opcode "OP_CAT"]
  -- Move sigElem to top: ROLL 3
  let rollSig : List StackOp :=
    [.roll 3, .opcode "OP_CAT"]
  -- pkSeedPad via PICK
  let pickPsp : List StackOp :=
    [.pickStruct pkSeedPadDepth, .swap, .opcode "OP_CAT", .opcode "OP_SHA256"]
  let truncate : List StackOp :=
    if n < 32 then
      [.push (.bigint (Int.ofNat n)), .opcode "OP_SPLIT", .drop]
    else []
  -- Rearrange to (newSigElem, steps-1, hashAddr+1)
  let rearrange : List StackOp :=
    [.rot, .opcode "OP_1SUB", .rot, .opcode "OP_1ADD"]
  dupHashAddr ++ toBE4 ++ pullPrefix ++ buildAdrs
    ++ rollSig ++ pickPsp ++ truncate ++ rearrange

/-- Unrolled 15-iteration if-then chain loop (one WOTS+ chain step). -/
def slhChainLoop (n pkSeedPadDepth : Nat) : List StackOp :=
  let body := slhChainStepThen n pkSeedPadDepth
  let oneStep : List StackOp :=
    [.over, .opcode "OP_0NOTEQUAL", .ifOp body none]
  let rec go (i : Nat) (acc : List StackOp) : List StackOp :=
    if i ≥ 15 then acc
    else go (i + 1) (acc ++ oneStep)
  termination_by 15 - i
  go 0 []

/--
One WOTS+ chain (raw form). Mirrors TS `emitSLHOneChainClean`.

Stack on entry:  `... sig(3) csum(2) endptAcc(1) digit(0)` with `pkSeedPad`
at `pkSeedPadDepth`, `treeAddr8` at `ta8Depth`, `keypair4` at `kp4Depth`
from TOS.

Stack on exit:   `... sigRest(2) newCsum(1) newEndptAcc(0)`. Net: -1
(replaces 4 with 3).
-/
def emitSLHOneChain (n layer chainIdx pkSeedPadDepth ta8Depth kp4Depth : Nat) :
    List StackOp :=
  -- Stage 1: steps = 15 - digit
  let stepsCalc : List StackOp :=
    [.push (.bigint 15), .swap, .opcode "OP_SUB"]
  -- Stage 2: save steps_copy, endptAcc, csum to alt
  let saveAlt : List StackOp :=
    [ .opcode "OP_DUP", .opcode "OP_TOALTSTACK"
    , .swap, .opcode "OP_TOALTSTACK"
    , .swap, .opcode "OP_TOALTSTACK" ]
  -- Stage 3: split n-byte sig element off sig
  let splitSig : List StackOp :=
    [ .swap
    , .push (.bigint (Int.ofNat n)), .opcode "OP_SPLIT"
    , .opcode "OP_TOALTSTACK"
    , .swap ]
  -- Stage 4: hashAddr = 15 - steps
  let hashAddrCalc : List StackOp :=
    [.opcode "OP_DUP", .push (.bigint 15), .swap, .opcode "OP_SUB"]
  -- After Stage 4: 3 items on main; pspD/ta8D/kp4D each -1.
  let pspD := pkSeedPadDepth - 1
  let ta8D := ta8Depth - 1
  let kp4D := kp4Depth - 1
  -- Stage 5: build 18-byte ADRS prefix, save to alt
  let buildPrefix : List StackOp :=
    emitBuildADRS18 layer SLH_WOTS_HASH chainIdx ta8D (.depth kp4D)
    ++ [.opcode "OP_TOALTSTACK"]
  -- Stage 6: 15-step hash loop
  let loop := slhChainLoop n pspD
  -- Stage 7: drop unused (endpoint, 0, finalHashAddr) → endpoint
  let cleanupMain : List StackOp := [.drop, .drop]
  let dropPrefix : List StackOp := [.opcode "OP_FROMALTSTACK", .drop]
  -- Stage 8: restore from alt (LIFO): sigRest, csum, endptAcc, steps_copy
  let restoreAlt : List StackOp :=
    [ .opcode "OP_FROMALTSTACK"   -- sigRest
    , .opcode "OP_FROMALTSTACK"   -- csum
    , .opcode "OP_FROMALTSTACK"   -- endptAcc
    , .opcode "OP_FROMALTSTACK"   -- steps_copy
    ]
  -- Stage 9: csum += steps_copy via ROT/ADD
  let csumAdd : List StackOp := [.rot, .opcode "OP_ADD"]
  -- Stage 10: cat endpoint to endptAcc
  let endptCat : List StackOp :=
    [ .swap, .roll 3, .opcode "OP_CAT" ]
  stepsCalc ++ saveAlt ++ splitSig ++ hashAddrCalc
    ++ buildPrefix ++ loop ++ cleanupMain ++ dropPrefix
    ++ restoreAlt ++ csumAdd ++ endptCat

/-! ## §6 — Full WOTS+ over `len` chains -/

/-- Emit per-byte processing in WOTS+ message phase: split a byte off the
remaining message (or not, on the last byte), convert to nibbles, and
chain them. Mirrors TS `emitSLHWotsAll` per-byte block. -/
def emitWotsByteBlock (n layer byteIdx : Nat) : List StackOp :=
  let isNotLast : Bool := byteIdx + 1 < n
  let splitPart : List StackOp :=
    if isNotLast then
      [.push (.bigint 1), .opcode "OP_SPLIT", .swap]
    else []
  -- Unsigned byte conversion + nibble decomposition
  let nibbleDecomp : List StackOp :=
    [ .push (.bigint 0)
    , .push (.bigint 1), .opcode "OP_NUM2BIN"
    , .opcode "OP_CAT"
    , .opcode "OP_BIN2NUM"
    , .opcode "OP_DUP"
    , .push (.bigint 16), .opcode "OP_DIV"  -- high
    , .swap
    , .push (.bigint 16), .opcode "OP_MOD"  -- low
    ]
  let preFirstChain : List StackOp :=
    if isNotLast then
      [ .opcode "OP_TOALTSTACK"   -- low → alt
      , .swap                      -- msgRest hi → hi msgRest
      , .opcode "OP_TOALTSTACK" ]  -- msgRest → alt
    else
      [ .opcode "OP_TOALTSTACK" ]  -- low → alt
  let firstChain := emitSLHOneChain n layer (byteIdx * 2) 6 5 4
  let preSecondChain : List StackOp :=
    if isNotLast then
      [ .opcode "OP_FROMALTSTACK"   -- msgRest
      , .opcode "OP_FROMALTSTACK"   -- low
      , .swap
      , .opcode "OP_TOALTSTACK" ]   -- msgRest → alt
    else
      [ .opcode "OP_FROMALTSTACK" ] -- low
  let secondChain := emitSLHOneChain n layer (byteIdx * 2 + 1) 6 5 4
  let postBlock : List StackOp :=
    if isNotLast then
      [.opcode "OP_FROMALTSTACK"]  -- msgRest back
    else []
  splitPart ++ nibbleDecomp ++ preFirstChain ++ firstChain
    ++ preSecondChain ++ secondChain ++ postBlock

/-- Emit all `n` byte blocks. -/
def emitWotsAllBytes (n layer : Nat) : List StackOp :=
  let rec go (i : Nat) (acc : List StackOp) : List StackOp :=
    if i ≥ n then acc
    else go (i + 1) (acc ++ emitWotsByteBlock n layer i)
  termination_by n - i
  go 0 []

/-- Emit checksum chains (`len2` of them, always 3 for SHA-2 SLH-DSA). -/
def emitWotsChecksumChains (n layer len1 len2 : Nat) : List StackOp :=
  let rec go (ci : Nat) (acc : List StackOp) : List StackOp :=
    if ci ≥ len2 then acc
    else
      let block : List StackOp :=
        [ .opcode "OP_TOALTSTACK"          -- endptAcc → alt
        , .push (.bigint 0)
        , .opcode "OP_FROMALTSTACK"        -- endptAcc back
        , .opcode "OP_FROMALTSTACK"        -- digit
        ]
        ++ emitSLHOneChain n layer (len1 + ci) 6 5 4
        ++ [ .swap, .drop ]                 -- drop newCsum
      go (ci + 1) (acc ++ block)
  termination_by len2 - ci
  go 0 []

/--
Full WOTS+ verification.

Stack in:  `psp(4) ta8(3) kp4(2) wotsSig(1) msg(0)`
Stack out: `psp(3) ta8(2) kp4(1) wotsPk(0)`.

Mirrors TS `emitSLHWotsAll`. -/
def emitSLHWotsAll (p : Params) (layer : Nat) : List StackOp :=
  let { n, len1, len2, .. } := p
  -- Rearrange: psp(6) ta8(5) kp4(4) sigRem(3) csum=0(2) endptAcc=empty(1) msgRem(0)
  let setup : List StackOp :=
    [ .swap
    , .push (.bigint 0)
    , .opcode "OP_0"
    , .roll 3 ]
  let messagePhase := emitWotsAllBytes n layer
  -- After all bytes: psp(5) ta8(4) kp4(3) sigRest(2) totalCsum(1) endptAcc(0)
  -- Emit: SWAP → psp(5) ta8(4) kp4(3) sigRest(2) endptAcc(1) totalCsum(0)
  -- Then compute 3 checksum digits onto alt.
  let checksumDigits : List StackOp :=
    [ .swap
    , .opcode "OP_DUP"
    , .push (.bigint 16), .opcode "OP_MOD"
    , .opcode "OP_TOALTSTACK"
    , .opcode "OP_DUP"
    , .push (.bigint 16), .opcode "OP_DIV"
    , .push (.bigint 16), .opcode "OP_MOD"
    , .opcode "OP_TOALTSTACK"
    , .push (.bigint 256), .opcode "OP_DIV"
    , .push (.bigint 16), .opcode "OP_MOD"
    , .opcode "OP_TOALTSTACK"
    ]
  let csChains := emitWotsChecksumChains n layer len1 len2
  -- After checksum: psp(4) ta8(3) kp4(2) empty(1) endptAcc(0)
  let afterCs : List StackOp := [.swap, .drop]
  -- Compress → wotsPk via T(pkSeed, ADRS_WOTS_PK, endptAcc).
  -- Build ADRS: ta8 at depth 2, keypair = zero, hash = zero.
  let buildAdrs := emitBuildADRS layer SLH_WOTS_PK 0 2 .zero .zero
  -- After buildAdrs: psp(4) ta8(3) kp4(2) endptAcc(1) adrs22(0)
  -- SWAP → adrs22(1) endptAcc(0), then T_raw with pspDepth=4.
  let swapAdrs : List StackOp := [.swap]
  let tHash := emitSLHT_raw n 4
  setup ++ messagePhase ++ checksumDigits ++ csChains
    ++ afterCs ++ buildAdrs ++ swapAdrs ++ tHash

/-! ## §7 — Merkle authentication path verification

Stack in:  `psp(5) ta8(4) kp4(3) leafIdx(2) authPath(hp*n)(1) node(n)(0)`
Stack out: `psp(3) ta8(2) kp4(1) root(0)`.

Mirrors TS `emitSLHMerkle`. -/

private def merkleAuthHashOps (n layer j : Nat) : List StackOp :=
  -- Stack in: `authPathRest(1) children(0)` with pspD=4, ta8D=3, kp4D=2.
  -- Get leafIdx from alt to compute hash.
  let pullIdx : List StackOp :=
    [.opcode "OP_FROMALTSTACK", .opcode "OP_DUP", .opcode "OP_TOALTSTACK"]
  -- After pull: authPathRest(2) children(1) leafIdx(0); pspD=5, ta8D=4, kp4D=3.
  let shiftIdx : List StackOp :=
    if j + 1 > 0 then
      [.push (.bigint (1 <<< (j + 1))), .opcode "OP_DIV"]
    else []
  let toBE4 : List StackOp :=
    [.push (.bigint 4), .opcode "OP_NUM2BIN"] ++ emitReverseN 4
  -- Build ADRS, hash=stack, kp4=zero (FIPS-205 setType clears keypair).
  let buildAdrs := emitBuildADRS layer SLH_TREE (j + 1) 4 .zero .stack
  -- After buildAdrs: authPathRest(2) children(1) adrs22(0); pspD=5.
  -- SWAP → authPathRest(2) adrs22(1) children(0). Tweakable hash with pspD=5.
  let swapAndHash : List StackOp := [.swap] ++ emitSLHT_raw n 5
  pullIdx ++ shiftIdx ++ toBE4 ++ buildAdrs ++ swapAndHash

private def merkleStep (n layer j : Nat) : List StackOp :=
  -- psp(4) ta8(3) kp4(2) authPath(1) node(0)
  let saveNode : List StackOp := [.opcode "OP_TOALTSTACK"]
  -- psp(4) ta8(3) kp4(2) authPath(1) → split off authJ from authPath
  let splitAuth : List StackOp :=
    [.push (.bigint (Int.ofNat n)), .opcode "OP_SPLIT", .swap]
  -- authPathRest(1) authJ(0) → restore node from alt
  let restoreNode : List StackOp := [.opcode "OP_FROMALTSTACK"]
  -- authPathRest(2) authJ(1) node(0) — get leafIdx, dup, push back
  let pullIdx : List StackOp :=
    [.opcode "OP_FROMALTSTACK", .opcode "OP_DUP", .opcode "OP_TOALTSTACK"]
  -- bit = (leafIdx >> j) % 2
  let bitCalc : List StackOp :=
    (if j > 0 then [.push (.bigint (1 <<< j)), .opcode "OP_DIV"] else [])
    ++ [.push (.bigint 2), .opcode "OP_MOD"]
  -- IF/ELSE branches: bit==1 → CAT; bit==0 → SWAP, CAT. Both then run hash.
  let hashOps := merkleAuthHashOps n layer j
  let thenBranch : List StackOp := [.opcode "OP_CAT"] ++ hashOps
  let elseBranch : List StackOp := [.swap, .opcode "OP_CAT"] ++ hashOps
  let ifOps : List StackOp := [.ifOp thenBranch (some elseBranch)]
  saveNode ++ splitAuth ++ restoreNode ++ pullIdx ++ bitCalc ++ ifOps

def emitSLHMerkle (p : Params) (layer : Nat) : List StackOp :=
  let { n, hp, .. } := p
  -- Move leafIdx to alt
  let saveLeaf : List StackOp := [.roll 2, .opcode "OP_TOALTSTACK"]
  -- hp Merkle steps
  let rec mergeSteps (j : Nat) (acc : List StackOp) : List StackOp :=
    if j ≥ hp then acc
    else mergeSteps (j + 1) (acc ++ merkleStep n layer j)
  termination_by hp - j
  let stepsOps := mergeSteps 0 []
  -- Drop leafIdx from alt
  let dropLeaf : List StackOp := [.opcode "OP_FROMALTSTACK", .drop]
  -- Drop empty authPathRest, leaving root
  let cleanup : List StackOp := [.swap, .drop]
  saveLeaf ++ stepsOps ++ dropLeaf ++ cleanup

/-! ## §8 — FORS verification

Stack in:  `psp(4) ta8(3) kp4(2) forsSig(1) md(0)`
Stack out: `psp(3) ta8(2) kp4(1) forsPk(0)`.
Mirrors TS `emitSLHFors`. -/

/-- Bit-extraction parameters from `bitStart` and `a` (FORS index extraction). -/
private def forsExtractIdx (a i : Nat) : List StackOp :=
  let bitStart  := i * a
  let byteStart := bitStart / 8
  let bitOffset := bitStart % 8
  let bitsInFirst := if 8 - bitOffset < a then 8 - bitOffset else a
  let take : Nat := if a > bitsInFirst then 2 else 1
  let stripPrefix : List StackOp :=
    if byteStart > 0 then
      [.push (.bigint (Int.ofNat byteStart)), .opcode "OP_SPLIT", .opcode "OP_NIP"]
    else []
  let takeBytes : List StackOp :=
    [.push (.bigint (Int.ofNat take)), .opcode "OP_SPLIT", .drop]
  let reverseTake : List StackOp :=
    if take > 1 then emitReverseN take else []
  let unsignedConv : List StackOp :=
    [ .push (.bigint 0)
    , .push (.bigint 1), .opcode "OP_NUM2BIN"
    , .opcode "OP_CAT"
    , .opcode "OP_BIN2NUM" ]
  let totalBits := take * 8
  let rightShift : Int := Int.ofNat totalBits - Int.ofNat bitOffset - Int.ofNat a
  let shiftOps : List StackOp :=
    if rightShift > 0 then
      [.push (.bigint (1 <<< rightShift.toNat)), .opcode "OP_DIV"]
    else []
  let modOps : List StackOp :=
    [.push (.bigint (1 <<< a)), .opcode "OP_MOD"]
  stripPrefix ++ takeBytes ++ reverseTake ++ unsignedConv ++ shiftOps ++ modOps

private def forsLeafHashOps (n a i : Nat) : List StackOp :=
  -- Stack: psp(4) ta8(3) kp4(2) sigRest(1) sk(0)
  -- Get idx from alt, dup, push back: psp(5) ta8(4) kp4(3) sigRest(2) sk(1) idx(0).
  let pullIdx : List StackOp :=
    [.opcode "OP_FROMALTSTACK", .opcode "OP_DUP", .opcode "OP_TOALTSTACK"]
  -- hash = i*(1<<a) + idx; convert to 4B BE.
  let addBase : List StackOp :=
    if i > 0 then
      [.push (.bigint (Int.ofNat (i * (1 <<< a)))), .opcode "OP_ADD"]
    else []
  let toBE4 : List StackOp :=
    [.push (.bigint 4), .opcode "OP_NUM2BIN"] ++ emitReverseN 4
  -- Build ADRS hash=stack, ta8D=4, kp4D=3
  let buildAdrs := emitBuildADRS 0 SLH_FORS_TREE 0 4 (.depth 3) .stack
  -- After buildAdrs: psp(5) ta8(4) kp4(3) sigRest(2) sk(1) adrs22(0). SWAP, T_raw.
  let swapAndHash : List StackOp := [.swap] ++ emitSLHT_raw n 5
  pullIdx ++ addBase ++ toBE4 ++ buildAdrs ++ swapAndHash

private def forsAuthHashOps (n a i j : Nat) : List StackOp :=
  -- Stack: sigRest(1) children(0); pspD=4, ta8D=3, kp4D=2.
  let pullIdx : List StackOp :=
    [.opcode "OP_FROMALTSTACK", .opcode "OP_DUP", .opcode "OP_TOALTSTACK"]
  let shiftIdx : List StackOp :=
    if j + 1 > 0 then
      [.push (.bigint (1 <<< (j + 1))), .opcode "OP_DIV"]
    else []
  let base := i * (1 <<< (a - j - 1))
  let addBase : List StackOp :=
    if base > 0 then
      [.push (.bigint (Int.ofNat base)), .opcode "OP_ADD"]
    else []
  let toBE4 : List StackOp :=
    [.push (.bigint 4), .opcode "OP_NUM2BIN"] ++ emitReverseN 4
  let buildAdrs := emitBuildADRS 0 SLH_FORS_TREE (j + 1) 4 (.depth 3) .stack
  let swapAndHash : List StackOp := [.swap] ++ emitSLHT_raw n 5
  pullIdx ++ shiftIdx ++ addBase ++ toBE4 ++ buildAdrs ++ swapAndHash

private def forsAuthStep (n a i j : Nat) : List StackOp :=
  -- psp(4) ta8(3) kp4(2) sigRest(1) node(0)
  let saveNode : List StackOp := [.opcode "OP_TOALTSTACK"]
  let splitAuth : List StackOp :=
    [.push (.bigint (Int.ofNat n)), .opcode "OP_SPLIT", .swap]
  let restoreNode : List StackOp := [.opcode "OP_FROMALTSTACK"]
  let pullIdx : List StackOp :=
    [.opcode "OP_FROMALTSTACK", .opcode "OP_DUP", .opcode "OP_TOALTSTACK"]
  let bitCalc : List StackOp :=
    (if j > 0 then [.push (.bigint (1 <<< j)), .opcode "OP_DIV"] else [])
    ++ [.push (.bigint 2), .opcode "OP_MOD"]
  let hashOps := forsAuthHashOps n a i j
  let thenBranch : List StackOp := [.opcode "OP_CAT"] ++ hashOps
  let elseBranch : List StackOp := [.swap, .opcode "OP_CAT"] ++ hashOps
  let ifOps : List StackOp := [.ifOp thenBranch (some elseBranch)]
  saveNode ++ splitAuth ++ restoreNode ++ pullIdx ++ bitCalc ++ ifOps

private def forsTree (n a i : Nat) : List StackOp :=
  -- Per i ∈ [0, k):
  -- 1. Get md from alt, dup, push back as md_copy (above rootAcc).
  let getMd : List StackOp :=
    [ .opcode "OP_FROMALTSTACK"   -- rootAcc
    , .opcode "OP_FROMALTSTACK"   -- md
    , .opcode "OP_DUP"
    , .opcode "OP_TOALTSTACK"     -- md back
    , .swap
    , .opcode "OP_TOALTSTACK"     -- rootAcc back
    ]
  -- 2. Extract `a` bits at offset i*a.
  let idxExtract := forsExtractIdx a i
  -- Save idx → alt (above rootAcc).
  let saveIdx : List StackOp := [.opcode "OP_TOALTSTACK"]
  -- 3. Split sk(n) from sigRem.
  let splitSk : List StackOp :=
    [.push (.bigint (Int.ofNat n)), .opcode "OP_SPLIT", .swap]
  -- 4. Leaf hash.
  let leafHash := forsLeafHashOps n a i
  -- 5. `a` levels of auth-path walking.
  let rec authSteps (j : Nat) (acc : List StackOp) : List StackOp :=
    if j ≥ a then acc
    else authSteps (j + 1) (acc ++ forsAuthStep n a i j)
  termination_by a - j
  let walk := authSteps 0 []
  -- 6. Drop idx from alt; append treeRoot to rootAcc; save back to alt.
  let drainAndAppend : List StackOp :=
    [ .opcode "OP_FROMALTSTACK", .drop
    , .opcode "OP_FROMALTSTACK"   -- rootAcc
    , .swap, .opcode "OP_CAT"
    , .opcode "OP_TOALTSTACK"     -- rootAcc back
    ]
  getMd ++ idxExtract ++ saveIdx ++ splitSk ++ leafHash ++ walk ++ drainAndAppend

def emitSLHFors (p : Params) : List StackOp :=
  let { n, a, k, .. } := p
  -- Save md to alt; push empty rootAcc to alt.
  let setup : List StackOp :=
    [ .opcode "OP_TOALTSTACK"      -- md → alt
    , .opcode "OP_0"
    , .opcode "OP_TOALTSTACK"      -- rootAcc(empty) → alt
    ]
  -- k FORS trees
  let rec trees (i : Nat) (acc : List StackOp) : List StackOp :=
    if i ≥ k then acc
    else trees (i + 1) (acc ++ forsTree n a i)
  termination_by k - i
  let allTrees := trees 0 []
  -- Drop empty sigRest; pop rootAcc, then md, drop md.
  let cleanup : List StackOp :=
    [ .drop
    , .opcode "OP_FROMALTSTACK"    -- rootAcc
    , .opcode "OP_FROMALTSTACK"    -- md
    , .drop
    ]
  -- Compress: T(pkSeed, ADRS_FORS_ROOTS, rootAcc). ta8D=2, kp4D=1.
  let buildAdrs := emitBuildADRS 0 SLH_FORS_ROOTS 0 2 (.depth 1) .zero
  let swapAndHash : List StackOp := [.swap] ++ emitSLHT_raw n 4
  setup ++ allTrees ++ cleanup ++ buildAdrs ++ swapAndHash

/-! ## §9 — Hmsg (SHA-256-MGF1 message digest)

Stack in:  `R(3) pkSeed(2) pkRoot(1) msg(0)`
Stack out: `digest(outLen bytes)`.
Mirrors TS `emitSLHHmsg`. -/

private def hmsgMultiBlock (outLen : Nat) : List StackOp :=
  let blocks := (outLen + 31) / 32   -- ceil(outLen / 32)
  -- Setup: OP_0 SWAP — `seed → resultAcc seed`.
  let setup : List StackOp := [.opcode "OP_0", .swap]
  let rec go (ctr : Nat) (acc : List StackOp) : List StackOp :=
    if ctr ≥ blocks then acc
    else
      let isLast : Bool := ctr + 1 = blocks
      let dupSeed : List StackOp :=
        if !isLast then [.opcode "OP_DUP"] else []
      let pushCtr : List StackOp :=
        [.push (.bytes (int4BE ctr)), .opcode "OP_CAT", .opcode "OP_SHA256"]
      let truncate : List StackOp :=
        if isLast then
          let rem := outLen - ctr * 32
          if rem < 32 then
            [.push (.bigint (Int.ofNat rem)), .opcode "OP_SPLIT", .drop]
          else []
        else []
      let mergeAcc : List StackOp :=
        if !isLast then
          [.rot, .swap, .opcode "OP_CAT", .swap]
        else
          [.swap, .opcode "OP_CAT"]
      go (ctr + 1) (acc ++ dupSeed ++ pushCtr ++ truncate ++ mergeAcc)
  termination_by blocks - ctr
  setup ++ go 0 []

def emitSLHHmsg (outLen : Nat) : List StackOp :=
  -- CAT: R || pkSeed || pkRoot || msg → seed via SHA256.
  let combine : List StackOp :=
    [ .opcode "OP_CAT", .opcode "OP_CAT", .opcode "OP_CAT", .opcode "OP_SHA256" ]
  let blocks := (outLen + 31) / 32
  let body : List StackOp :=
    if blocks = 1 then
      let trunc : List StackOp :=
        if outLen < 32 then
          [.push (.bigint (Int.ofNat outLen)), .opcode "OP_SPLIT", .drop]
        else []
      [ .push (.bytes (zerosN 4)), .opcode "OP_CAT", .opcode "OP_SHA256" ] ++ trunc
    else
      hmsgMultiBlock outLen
  combine ++ body

/-! ## §10 — Top-level entry

Mirrors TS `emitVerifySLHDSA`. Stack in: `msg sig pubkey`. Stack out: bool.

The body is built using the `Tracker`. -/

private def applyHmsg (t : Tracker) (n outLen : Nat) : Tracker :=
  -- Bring R, pkSeed, pkRoot, msg copies to top in order.
  let t := t.copyToTop "R" (some "_R")
  let t := t.copyToTop "pkSeed" (some "_pks")
  let t := t.copyToTop "pkRoot" (some "_pkr")
  let t := t.copyToTop "msg" (some "_msg")
  -- 4 args consumed, 1 produced (digest).
  t.rawBlock 4 (some "digest") (emitSLHHmsg outLen)

private def parseTreeIdx (t : Tracker) (treeIdxLen heightDelta : Nat) : Tracker :=
  let t := t.toTop "_treeBytes"
  let modulus : Int := 1 <<< heightDelta
  let body : List StackOp :=
    (if treeIdxLen > 1 then emitReverseN treeIdxLen else [])
    ++ [ .push (.bigint 0)
       , .push (.bigint 1), .opcode "OP_NUM2BIN"
       , .opcode "OP_CAT"
       , .opcode "OP_BIN2NUM"
       , .push (.bigint modulus), .opcode "OP_MOD" ]
  t.rawBlock 1 (some "treeIdx") body

private def parseLeafIdx (t : Tracker) (leafIdxLen hp : Nat) : Tracker :=
  let t := t.toTop "_leafBytes"
  let body : List StackOp :=
    (if leafIdxLen > 1 then emitReverseN leafIdxLen else [])
    ++ [ .push (.bigint 0)
       , .push (.bigint 1), .opcode "OP_NUM2BIN"
       , .opcode "OP_CAT"
       , .opcode "OP_BIN2NUM"
       , .push (.bigint (1 <<< hp)), .opcode "OP_MOD" ]
  t.rawBlock 1 (some "leafIdx") body

private def computeTreeAddr8 (t : Tracker) : Tracker :=
  let t := t.copyToTop "treeIdx" (some "_ti8")
  let body : List StackOp :=
    [.push (.bigint 8), .opcode "OP_NUM2BIN"] ++ emitReverseN 8
  t.rawBlock 1 (some "treeAddr8") body

private def computeKeypair4 (t : Tracker) : Tracker :=
  let t := t.copyToTop "leafIdx" (some "_li4")
  let body : List StackOp :=
    [.push (.bigint 4), .opcode "OP_NUM2BIN"] ++ emitReverseN 4
  t.rawBlock 1 (some "keypair4") body

private def applyForsBlock (t : Tracker) (p : Params) : Tracker :=
  let t := t.copyToTop "_pkSeedPad" (some "_psp")
  let t := t.copyToTop "treeAddr8"  (some "_ta")
  let t := t.copyToTop "keypair4"   (some "_kp")
  let t := t.toTop "forsSig"
  let t := t.toTop "md"
  -- Inline body: emitSLHFors + cleanup of psp/ta8/kp4.
  let inner : List StackOp :=
    emitSLHFors p
    ++ [ .opcode "OP_TOALTSTACK"  -- forsPk → alt
       , .drop, .drop, .drop      -- kp4, ta8, psp
       , .opcode "OP_FROMALTSTACK" ]
  t.rawBlock 5 (some "forsPk") inner

private def applyHypertreeLayer (t : Tracker) (p : Params) (layer : Nat)
    (curMsg : String) : Tracker :=
  let { n, len, hp, .. } := p
  let xmssSigLen := (len + hp) * n
  let wotsBytes := len * n
  -- Split xmssSig from htSigRest.
  let xsigName  := s!"xsig{layer}"
  let wsigName  := s!"wsig{layer}"
  let authName  := s!"auth{layer}"
  let wpkName   := s!"wpk{layer}"
  let rootName  := s!"root{layer}"
  let t := t.toTop "htSigRest"
  let t := t.pushInt none (Int.ofNat xmssSigLen)
  let t := t.split (some xsigName) (some "htSigRest")
  -- Split wotsSig and authPath.
  let t := t.toTop xsigName
  let t := t.pushInt none (Int.ofNat wotsBytes)
  let t := t.split (some wsigName) (some authName)
  -- WOTS+: copy psp/ta8/kp4 + wotsSig + currentMsg → wotsPk.
  let t := t.copyToTop "_pkSeedPad" (some "_psp")
  let t := t.copyToTop "treeAddr8"  (some "_ta")
  let t := t.copyToTop "keypair4"   (some "_kp")
  let t := t.toTop wsigName
  let t := t.toTop curMsg
  let wotsBody : List StackOp :=
    emitSLHWotsAll p layer
    ++ [ .opcode "OP_TOALTSTACK"
       , .drop, .drop, .drop
       , .opcode "OP_FROMALTSTACK" ]
  let t := t.rawBlock 5 (some wpkName) wotsBody
  -- Merkle: copy psp/ta8/kp4 + leafIdx + authPath + wotsPk → root.
  let t := t.copyToTop "_pkSeedPad" (some "_psp")
  let t := t.copyToTop "treeAddr8"  (some "_ta")
  let t := t.copyToTop "keypair4"   (some "_kp")
  let t := t.toTop "leafIdx"
  let t := t.toTop authName
  let t := t.toTop wpkName
  let merkleBody : List StackOp :=
    emitSLHMerkle p layer
    ++ [ .opcode "OP_TOALTSTACK"
       , .drop, .drop, .drop
       , .opcode "OP_FROMALTSTACK" ]
  let t := t.rawBlock 6 (some rootName) merkleBody
  t

private def updateForNextLayer (t : Tracker) (hp : Nat) : Tracker :=
  -- leafIdx = treeIdx % (1 << hp); treeIdx = treeIdx >> hp; refresh treeAddr8 + keypair4.
  let t := t.toTop "treeIdx"
  let t := t.dup (some "_tic")
  let t := t.rawBlock 1 (some "leafIdx")
              [.push (.bigint (1 <<< hp)), .opcode "OP_MOD"]
  let t := t.swap
  let t := t.rawBlock 1 (some "treeIdx")
              [.push (.bigint (1 <<< hp)), .opcode "OP_DIV"]
  -- Drop the old treeAddr8 and keypair4.
  let t := t.toTop "treeAddr8" |>.drop
  let t := computeTreeAddr8 t
  let t := t.toTop "keypair4" |>.drop
  let t := computeKeypair4 t
  t

private def cleanupRemainingNames (t : Tracker) : Tracker := Id.run do
  let leftover : List String :=
    ["msg", "R", "pkSeed", "htSigRest", "treeIdx", "leafIdx",
     "_pkSeedPad", "treeAddr8", "keypair4"]
  let mut t := t
  for nm in leftover do
    if t.has nm then
      t := t.toTop nm
      t := t.drop
  while t.depth > 0 do
    t := t.drop
  pure t

/-- The top-level body emitted *after* `msg`, `sig`, `pubkey` are loaded
to the top of the stack (in that order, with `pubkey` on TOS). After
the body: `[..., bool]`. Mirrors TS `emitVerifySLHDSA`. -/
def emitVerifySLHDSABody (paramKey : String) : List StackOp :=
  match paramsByKey paramKey with
  | none   => [.opcode "OP_RUNAR_UNKNOWN_SLHDSA_PARAMS"]
  | some p =>
    let { n, h, hp, k, a, len, d, .. } := p
    let forsSigLen := k * (1 + a) * n
    let mdLen      := (k * a + 7) / 8
    let treeIdxLen := (h - hp + 7) / 8
    let leafIdxLen := (hp + 7) / 8
    let digestLen  := mdLen + treeIdxLen + leafIdxLen
    let t : Tracker := Tracker.init [some "msg", some "sig", some "pubkey"]
    -- §1. Parse pubkey → pkSeed, pkRoot.
    let t := t.toTop "pubkey"
    let t := t.pushInt none (Int.ofNat n)
    let t := t.split (some "pkSeed") (some "pkRoot")
    -- Build pkSeedPad = pkSeed || zeros(64-n) on main.
    let t := t.copyToTop "pkSeed" (some "_psp")
    let t :=
      if 64 - n > 0 then
        let t := t.pushBytes none (zerosN (64 - n))
        t.cat (some "_pkSeedPad")
      else
        t.rename (some "_pkSeedPad")
    -- §2. Parse R from sig.
    let t := t.toTop "sig"
    let t := t.pushInt none (Int.ofNat n)
    let t := t.split (some "R") (some "sigRest")
    -- §3. Hmsg(R, pkSeed, pkRoot, msg) → digest.
    let t := applyHmsg t n digestLen
    -- §4. Extract md, treeIdx, leafIdx.
    let t := t.toTop "digest"
    let t := t.pushInt none (Int.ofNat mdLen)
    let t := t.split (some "md") (some "_drest")
    let t := t.toTop "_drest"
    let t := t.pushInt none (Int.ofNat treeIdxLen)
    let t := t.split (some "_treeBytes") (some "_leafBytes")
    -- Convert _treeBytes → treeIdx, _leafBytes → leafIdx.
    let t := parseTreeIdx t treeIdxLen (h - hp)
    let t := parseLeafIdx t leafIdxLen hp
    -- §4b. treeAddr8 (8B BE) + keypair4 (4B BE).
    let t := computeTreeAddr8 t
    let t := computeKeypair4 t
    -- §5. Parse FORS sig.
    let t := t.toTop "sigRest"
    let t := t.pushInt none (Int.ofNat forsSigLen)
    let t := t.split (some "forsSig") (some "htSigRest")
    -- §6. FORS → forsPk.
    let t := applyForsBlock t p
    -- §7. Hypertree: d layers.
    let rec hyper (layer : Nat) (t : Tracker) : Tracker :=
      if layer ≥ d then t
      else
        let curMsg := if layer = 0 then "forsPk" else s!"root{layer - 1}"
        let t := applyHypertreeLayer t p layer curMsg
        let t := if layer < d - 1 then updateForNextLayer t hp else t
        hyper (layer + 1) t
    termination_by d - layer
    let t := hyper 0 t
    -- §8. Compare last root to pkRoot.
    let lastRoot := s!"root{d - 1}"
    let t := t.toTop lastRoot
    let t := t.toTop "pkRoot"
    let t := t.equal (some "_result")
    -- §9. Cleanup: save _result to alt, drop everything else, restore.
    let t := t.toTop "_result"
    let t := t.toAlt
    let t := cleanupRemainingNames t
    let t := t.fromAlt (some "_result")
    t.ops.toList

end SlhDsa
end RunarVerification.Stack
