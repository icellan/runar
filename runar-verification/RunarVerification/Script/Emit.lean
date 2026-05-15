import RunarVerification.Stack.Syntax
import RunarVerification.Script.Syntax

/-!
# Bitcoin Script — Emit (Phase 3a, byte-exact for simple programs)

A Lean implementation of `packages/runar-compiler/src/passes/06-emit.ts`
covering exactly the encoding paths exercised by the simplest
conformance fixtures:

* `OP_0` (zero), `OP_1NEGATE`, `OP_1`–`OP_16` for small integer pushes,
* direct-prefix push (1–75-byte data),
* `OP_PUSHDATA1` (76–255-byte data),
* every concrete opcode from `Script/Syntax.lean`'s named table,
* `dup` / `swap` / `nip` / `over` / `rot` / `tuck` / `drop` short-form
  stack ops,
* `placeholder` and legacy `pushCodesepIndex` (both emit `OP_0`),
* the `pick d` / `roll d` form which lowers to a script-number push of
  the depth followed by `OP_PICK` / `OP_ROLL`.

The legacy `emit` / `emitFast` entrypoints intentionally keep
`pushCodesepIndex` as a one-byte placeholder for backwards-compatible
golden checks. `emitWithCodeSepPatches` is the proof-facing deployment
shape: it records constructor slots, tracks byte offsets of emitted
`OP_CODESEPARATOR`s, and emits each `pushCodesepIndex` as the script
number for the latest separator byte offset. That path is branch-aware:
if control-flow joins make the latest executed separator ambiguous, it
returns a `CodeSepPatchError` instead of guessing a patch value.

**Out of scope (Phase 3b).** Source-map construction.
-/

namespace RunarVerification.Script
namespace Emit

open RunarVerification.Stack
open RunarVerification.Script

/-! ## Hex utilities -/

private def nibbleToHex (n : UInt8) : Char :=
  let v := n.toNat &&& 0xf
  if v < 10 then Char.ofNat (v + 48) else Char.ofNat (v + 87)

def byteToHex (b : UInt8) : String :=
  let hi := nibbleToHex (b >>> 4)
  let lo := nibbleToHex b
  String.ofList [hi, lo]

def bytesToHex (b : ByteArray) : String :=
  b.toList.foldl (fun acc x => acc ++ byteToHex x) ""

/-! ## Script-number encoding (sign-magnitude little-endian)

Mirrors `encodeScriptNumber` in `06-emit.ts:189-213`.

* `0`           → empty byte string
* positive `n`  → little-endian bytes; if the MSB's high bit is set,
                  append a `0x00` byte for sign clarity
* negative `n`  → little-endian bytes of `|n|`; if the MSB's high bit
                  is set, append `0x80`; otherwise OR `0x80` into the MSB.
-/

private def absNat (n : Int) : Nat := n.natAbs

set_option linter.unusedVariables false in
private def absToBytesLE (n : Nat) : List UInt8 :=
  if h : n = 0 then []
  else (UInt8.ofNat (n &&& 0xff)) :: absToBytesLE (n >>> 8)
termination_by n
decreasing_by
  -- n >>> 8 = n / 2^8 < n when n > 0
  simp_wf
  rw [Nat.shiftRight_eq_div_pow]
  exact Nat.div_lt_self (Nat.pos_of_ne_zero h) (by decide)

def encodeScriptNumber (n : Int) : ByteArray :=
  if n = 0 then ByteArray.empty
  else
    let negative := n < 0
    let absN := absNat n
    let bytes := absToBytesLE absN
    -- bytes is non-empty (n ≠ 0)
    let last := bytes.getLast!
    let body := bytes.dropLast
    if last &&& 0x80 ≠ 0 then
      -- need an extra sign byte
      let sign : UInt8 := if negative then 0x80 else 0x00
      ByteArray.mk (body ++ [last, sign]).toArray
    else if negative then
      ByteArray.mk (body ++ [last ||| 0x80]).toArray
    else
      ByteArray.mk bytes.toArray

/-! ## Push-data encoding (length prefix or PUSHDATA1)

Mirrors `encodePushData` in `06-emit.ts:228-269`. Phase 3a covers
`len = 0`, `len ∈ [1, 75]`, and `len ∈ [76, 255]`. Lengths ≥ 256 fall
through to `OP_PUSHDATA2` / `OP_PUSHDATA4`, deferred to Phase 3b.
-/

def encodePushData (data : ByteArray) : ByteArray :=
  let len := data.size
  if len = 0 then
    ByteArray.mk #[0x00]
  else if len ≤ 75 then
    let lenPrefix : ByteArray := ByteArray.mk #[UInt8.ofNat len]
    lenPrefix ++ data
  else if len ≤ 255 then
    let lenPrefix : ByteArray := ByteArray.mk #[0x4c, UInt8.ofNat len]
    lenPrefix ++ data
  else if len ≤ 65535 then
    let lo : UInt8 := UInt8.ofNat (len &&& 0xff)
    let hi : UInt8 := UInt8.ofNat ((len >>> 8) &&& 0xff)
    let lenPrefix : ByteArray := ByteArray.mk #[0x4d, lo, hi]
    lenPrefix ++ data
  else
    -- OP_PUSHDATA4 (Phase 3b extends with full guarantees)
    let b0 : UInt8 := UInt8.ofNat (len &&& 0xff)
    let b1 : UInt8 := UInt8.ofNat ((len >>> 8) &&& 0xff)
    let b2 : UInt8 := UInt8.ofNat ((len >>> 16) &&& 0xff)
    let b3 : UInt8 := UInt8.ofNat ((len >>> 24) &&& 0xff)
    let lenPrefix : ByteArray := ByteArray.mk #[0x4e, b0, b1, b2, b3]
    lenPrefix ++ data

/-! ## Push-value encoding (small-integer fast path + general)

Mirrors `encodePushValue` and `encodePushBigInt` in `06-emit.ts:274-326`.

* `bool true`        → `OP_TRUE` (0x51)
* `bool false`       → `OP_FALSE` (0x00)
* `bigint 0`         → `OP_0` (0x00)
* `bigint -1`        → `OP_1NEGATE` (0x4f)
* `bigint 1..16`     → `OP_1`..`OP_16`
* otherwise          → `encodePushData (encodeScriptNumber n)`
* `bytes []`         → `OP_0`
* `bytes [b]` with `b ∈ [1,16]`   → `OP_1`..`OP_16`
* `bytes [0x81]`     → `OP_1NEGATE`
* otherwise          → `encodePushData bs`
-/

def encodePushBigInt (n : Int) : ByteArray :=
  if n = 0 then ByteArray.mk #[0x00]                       -- OP_0
  else if n = -1 then ByteArray.mk #[0x4f]                 -- OP_1NEGATE
  else if 1 ≤ n ∧ n ≤ 16 then
    ByteArray.mk #[UInt8.ofNat (0x50 + n.natAbs)]
  else
    encodePushData (encodeScriptNumber n)

def encodePushBool (b : Bool) : ByteArray :=
  if b then ByteArray.mk #[0x51] else ByteArray.mk #[0x00]

def encodePushBytes (data : ByteArray) : ByteArray :=
  if data.size = 0 then ByteArray.mk #[0x00]
  else if data.size = 1 then
    let b := data.get! 0
    if 1 ≤ b.toNat ∧ b.toNat ≤ 16 then
      ByteArray.mk #[UInt8.ofNat (0x50 + b.toNat)]
    else if b = 0x81 then
      ByteArray.mk #[0x4f]
    else
      encodePushData data
  else
    encodePushData data

def encodePushVal : PushVal → ByteArray
  | .bigint i => encodePushBigInt i
  | .bool b   => encodePushBool b
  | .bytes b  => encodePushBytes b

/-! ## Single StackOp → bytes

Each `StackOp` translates to the byte sequence expected by
`emitStackOp` in `06-emit.ts:447-513`.
-/

mutual

def emitStackOp : StackOp → ByteArray
  | .push v          => encodePushVal v
  | .dup             => ByteArray.mk #[0x76]   -- OP_DUP
  | .swap            => ByteArray.mk #[0x7c]   -- OP_SWAP
  | .nip             => ByteArray.mk #[0x77]   -- OP_NIP
  | .over            => ByteArray.mk #[0x78]   -- OP_OVER
  | .rot             => ByteArray.mk #[0x7b]   -- OP_ROT
  | .tuck            => ByteArray.mk #[0x7d]   -- OP_TUCK
  | .drop            => ByteArray.mk #[0x75]   -- OP_DROP
  | .roll d          => encodePushBigInt d ++ ByteArray.mk #[0x7a]  -- depth then OP_ROLL
  | .pick d          => encodePushBigInt d ++ ByteArray.mk #[0x79]  -- depth then OP_PICK
  | .pickStruct d    => encodePushBigInt d ++ ByteArray.mk #[0x79]  -- byte-identical to `.pick d`
  | .opcode name     =>
      match opcodeByName? name with
      | some b => ByteArray.mk #[b]
      | none   => ByteArray.empty   -- legacy total path; `compileSafe` rejects this first
  | .ifOp thn els    =>
      -- OP_IF (0x63) <thn> [OP_ELSE (0x67) <els>] OP_ENDIF (0x68)
      -- Mirrors `06-emit.ts:533`: emit OP_ELSE only when the else branch
      -- is non-empty. `some []` (explicit-but-empty else) and `none`
      -- (no else at all) produce identical bytes.
      let thnBytes := emitOps thn
      let elseSection :=
        match els with
        | none      => ByteArray.empty
        | some []   => ByteArray.empty
        | some elsB => ByteArray.mk #[0x67] ++ emitOps elsB
      ByteArray.mk #[0x63] ++ thnBytes ++ elseSection ++ ByteArray.mk #[0x68]
  | .placeholder _ _ => ByteArray.mk #[0x00]   -- OP_0 placeholder
  | .pushCodesepIndex => ByteArray.mk #[0x00]  -- OP_0 placeholder

/-- Emit a flat op list as a concatenated byte array. -/
def emitOps : List StackOp → ByteArray
  | [] => ByteArray.empty
  | op :: rest => emitStackOp op ++ emitOps rest

end

/-! ## Builder-style fast emit (perf path)

`emit` / `emitOps` above use repeated `ByteArray.++`, which is O(n²) in
total byte count. For EC / SLH-DSA fixtures generating ~10⁵+ opcodes
this becomes prohibitive (tens of minutes).

The fast variants below produce byte-identical output via tail-recursive
accumulators that use `ByteArray.push` (amortised O(1)). They are
defined in a separate mutual block so that the structural `emitStackOp`
/ `emitOps` keep their definitional `rfl` reductions for the proofs in
`Script/EmitCorrect.lean`.

Critically, `emitStackOpFast` recurses into `emitOpsFast` for `.ifOp`
bodies — without this, deeply-nested ifOp programs (e.g. ecMul's 257
ifOp wrappers each holding ~1000 inner ops) would still hit the O(n²)
wall via the slow `emitOps` invocation inside `.ifOp`. -/

mutual

def emitStackOpFast : StackOp → ByteArray
  | .push v          => encodePushVal v
  | .dup             => ByteArray.mk #[0x76]
  | .swap            => ByteArray.mk #[0x7c]
  | .nip             => ByteArray.mk #[0x77]
  | .over            => ByteArray.mk #[0x78]
  | .rot             => ByteArray.mk #[0x7b]
  | .tuck            => ByteArray.mk #[0x7d]
  | .drop            => ByteArray.mk #[0x75]
  | .roll d          => encodePushBigInt d ++ ByteArray.mk #[0x7a]
  | .pick d          => encodePushBigInt d ++ ByteArray.mk #[0x79]
  | .pickStruct d    => encodePushBigInt d ++ ByteArray.mk #[0x79]
  | .opcode name     =>
      match opcodeByName? name with
      | some b => ByteArray.mk #[b]
      | none   => ByteArray.empty
  | .ifOp thn els    =>
      -- Use the fast emit recursively for the body. Mirrors TS
      -- `06-emit.ts:533`: skip OP_ELSE when the else branch is empty
      -- (whether absent or `some []`).
      let thnBytes := emitOpsFast thn
      let elseSection :=
        match els with
        | none      => ByteArray.empty
        | some []   => ByteArray.empty
        | some elsB => ByteArray.mk #[0x67] ++ emitOpsFast elsB
      ByteArray.mk #[0x63] ++ thnBytes ++ elseSection ++ ByteArray.mk #[0x68]
  | .placeholder _ _ => ByteArray.mk #[0x00]
  | .pushCodesepIndex => ByteArray.mk #[0x00]

def emitOpsFastAux : ByteArray → List StackOp → ByteArray
  | acc, [] => acc
  | acc, op :: rest =>
    emitOpsFastAux ((emitStackOpFast op).foldl (init := acc) fun a b => a.push b) rest

def emitOpsFast (ops : List StackOp) : ByteArray :=
  emitOpsFastAux ByteArray.empty ops

end

/-! ## Method emission (Phase 3w-d)

Mirrors `06-emit.ts:555-637`:

* The auto-generated `constructor` is filtered out — its body is the
  property-initialisation prologue that the SDK splices in at deploy
  time, never part of the spend script.
* If only one public method remains, its body is emitted directly.
* If two or more public methods remain, an `OP_DUP <i> OP_NUMEQUAL
  OP_IF OP_DROP <body> OP_ELSE …` dispatch chain is emitted, with the
  *last* method using `<n-1> OP_NUMEQUALVERIFY` so an out-of-range
  selector aborts the script. The whole chain is closed with
  `(n-1)` `OP_ENDIF` opcodes.

The bytes emitted by this dispatch chain match `06-emit.ts`'s
`emitMethodDispatch` exactly: the only opcodes used (`OP_DUP=0x76`,
`OP_NUMEQUAL=0x9c`, `OP_NUMEQUALVERIFY=0x9d`, `OP_IF=0x63`,
`OP_DROP=0x75`, `OP_ELSE=0x67`, `OP_ENDIF=0x68`) are pinned to the
TS encoder's opcode table.
-/

/-- A method is "public" (in the spend-script sense) iff its name is
not the magic `"constructor"`. The `is_public` field of the source
ANF method is *not* consulted here, mirroring `06-emit.ts:558`
which filters solely on the name. -/
def isPublicStackMethod (m : StackMethod) : Bool :=
  m.name != "constructor"

/-- Drop the auto-generated `constructor` from a method list. -/
def publicMethodsOf (p : StackProgram) : List StackMethod :=
  p.methods.filter isPublicStackMethod

/-- Body bytes for a single method (no dispatch wrapper). -/
def emitMethod (m : StackMethod) : ByteArray :=
  emitOps m.ops

/-! ### Multi-method dispatch chain bytes

The chain emitted for `n ≥ 2` public methods looks like:
```
[OP_DUP <0> OP_NUMEQUAL OP_IF OP_DROP <body0> OP_ELSE]
[OP_DUP <1> OP_NUMEQUAL OP_IF OP_DROP <body1> OP_ELSE]
…
[OP_DUP <n-2> OP_NUMEQUAL OP_IF OP_DROP <body_{n-2}> OP_ELSE]
[<n-1> OP_NUMEQUALVERIFY <body_{n-1}>]
[OP_ENDIF * (n-1)]
```
Each `<i>` is `encodePushBigInt (Int.ofNat i)`.
-/

/-- Dispatch head for a non-last method at index `i`:
`OP_DUP push(i) OP_NUMEQUAL OP_IF OP_DROP`. -/
def emitDispatchHeadNonLast (i : Nat) : ByteArray :=
  ByteArray.mk #[0x76]                        -- OP_DUP
    ++ encodePushBigInt (Int.ofNat i)
    ++ ByteArray.mk #[0x9c, 0x63, 0x75]       -- OP_NUMEQUAL OP_IF OP_DROP

/-- Dispatch head for the last method at index `i`:
`push(i) OP_NUMEQUALVERIFY`. -/
def emitDispatchHeadLast (i : Nat) : ByteArray :=
  encodePushBigInt (Int.ofNat i) ++ ByteArray.mk #[0x9d]   -- OP_NUMEQUALVERIFY

/-- Single `OP_ELSE` byte. -/
def emitElse : ByteArray := ByteArray.mk #[0x67]

/-- `n` repeated `OP_ENDIF` bytes (closes the nested IF stack). -/
def emitEndifs : Nat → ByteArray
  | 0     => ByteArray.empty
  | n + 1 => ByteArray.mk #[0x68] ++ emitEndifs n

/-- Walk the method list emitting the dispatch chain (head + body +
`OP_ELSE` for non-last; head + body for last). The closing
`OP_ENDIF`s are appended once by `emitDispatch`. -/
def emitDispatchChain : Nat → List StackMethod → ByteArray
  | _, []         => ByteArray.empty
  | i, [m]        => emitDispatchHeadLast i ++ emitOps m.ops
  | i, m :: rest  =>
      emitDispatchHeadNonLast i ++ emitOps m.ops ++ emitElse
        ++ emitDispatchChain (i + 1) rest

/-- Full dispatch bytes for `≥ 2` public methods. -/
def emitDispatch (methods : List StackMethod) : ByteArray :=
  emitDispatchChain 0 methods ++ emitEndifs (methods.length - 1)

/-- Top-level emit. Filters out the constructor, then either emits the
sole remaining method directly or builds the multi-method dispatch
chain. Mirrors `06-emit.ts:555-593` byte-for-byte. -/
def emit (p : StackProgram) : ByteArray :=
  match publicMethodsOf p with
  | []      => ByteArray.empty
  | [m]     => emitMethod m
  | ms      => emitDispatch ms

/-- Emit + hex-encode in one shot, matching `expected-script.hex` format. -/
def emitHex (p : StackProgram) : String :=
  bytesToHex (emit p)

/-! ## Builder-style fast emit (perf path for large fixtures)

`emit` above uses repeated `++` on `ByteArray`, which is O(n²) in the
total byte count. For most fixtures this is negligible (< 50 KB scripts
finish in milliseconds). For EC / SLH-DSA fixtures generating
hundreds of thousands of opcodes (~1+ MB scripts), the O(n²) factor
becomes prohibitive (tens of minutes).

`emitFast` produces byte-identical output via a tail-recursive
accumulator that uses `ByteArray.push` (amortised O(1)) instead.
Used by `Pipeline.compile`. The structural `emit` / `emitOps` remain
for proof-friendly definitional unfolding (e.g. `emitOps_nil := rfl`).
-/

def appendBA (acc : ByteArray) (bs : ByteArray) : ByteArray :=
  bs.foldl (init := acc) fun a b => a.push b

def emitDispatchChainFast : ByteArray → Nat → List StackMethod → ByteArray
  | acc, _, []         => acc
  | acc, i, [m]        =>
    let acc1 := appendBA acc (emitDispatchHeadLast i)
    emitOpsFastAux acc1 m.ops
  | acc, i, m :: rest  =>
    let acc1 := appendBA acc (emitDispatchHeadNonLast i)
    let acc2 := emitOpsFastAux acc1 m.ops
    let acc3 := acc2.push 0x67  -- OP_ELSE
    emitDispatchChainFast acc3 (i + 1) rest

def emitEndifsFastAux : ByteArray → Nat → ByteArray
  | acc, 0     => acc
  | acc, n + 1 => emitEndifsFastAux (acc.push 0x68) n

def emitFast (p : StackProgram) : ByteArray :=
  match publicMethodsOf p with
  | []      => ByteArray.empty
  | [m]     => emitOpsFast m.ops
  | ms      =>
    let chainAcc := emitDispatchChainFast ByteArray.empty 0 ms
    emitEndifsFastAux chainAcc (ms.length - 1)

/-! ## Slot-aware code-separator emission

The deployment SDK needs two pieces of byte-level metadata that the
plain `ByteArray` emit path cannot carry:

* constructor placeholders: where an `OP_0` byte stands in for a
  constructor argument; and
* code-separator index pushes: where the state-method body needs the
  byte offset of the latest emitted `OP_CODESEPARATOR`.

This section provides a second emit path that computes both from the
same byte stream it emits. It deliberately does not change `emit` or
`emitFast`; existing golden checks continue to exercise the historical
placeholder bytes, while `emitWithCodeSepPatches` gives the proof-facing
path a concrete byte-offset model. The patching path treats IF branches
as runtime alternatives: both branches start with the same incoming
separator state, and the join is accepted only when every later
`pushCodesepIndex` has a unique candidate offset.
-/

/-- Constructor placeholder byte-offset metadata. -/
structure ConstructorSlot where
  offset : Nat
  paramIndex : Nat
  paramName : String
  deriving Repr, BEq, DecidableEq, Inhabited

/--
Code-separator patch metadata.

`offset` is the byte offset where the script-number push begins.
`codeSeparatorOffset` is the byte offset of the most recent emitted
`OP_CODESEPARATOR`, or zero when no separator has appeared yet. The
emitted byte sequence at `offset` is `encodePushBigInt codeSeparatorOffset`;
`encodedSize` records its length so callers can map back into the byte
stream without re-encoding.
-/
structure CodeSepIndexSlot where
  offset : Nat
  codeSeparatorOffset : Nat
  encodedSize : Nat
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Slot-aware emit result. -/
structure EmitResult where
  bytes : ByteArray
  constructorSlots : List ConstructorSlot := []
  codeSepIndexSlots : List CodeSepIndexSlot := []
  deriving BEq, DecidableEq, Inhabited

/-- Fail-closed errors for code-separator patch emission. -/
inductive CodeSepPatchError where
  /--
  A `pushCodesepIndex` was reached after a control-flow join where
  different execution paths had different latest `OP_CODESEPARATOR`
  offsets, so no single static patch value is sound.
  -/
  | ambiguousCodeSepIndex (offset : Nat) (candidates : List Nat)
  deriving Repr, BEq, DecidableEq

private def natListContains (xs : List Nat) (n : Nat) : Bool :=
  xs.any (· == n)

private def natListInsert (xs : List Nat) (n : Nat) : List Nat :=
  if natListContains xs n then xs else xs ++ [n]

private def natListUnion (xs ys : List Nat) : List Nat :=
  ys.foldl natListInsert xs

private def singletonNat? : List Nat → Option Nat
  | [n] => some n
  | _ => none

private structure PatchState where
  bytes : ByteArray := ByteArray.empty
  constructorSlotsRev : List ConstructorSlot := []
  codeSepIndexSlotsRev : List CodeSepIndexSlot := []
  possibleCodeSeparatorOffsets : List Nat := [0]
  deriving Inhabited

private def PatchState.offset (st : PatchState) : Nat :=
  st.bytes.size

private def PatchState.append (st : PatchState) (bs : ByteArray) : PatchState :=
  { st with bytes := appendBA st.bytes bs }

private def PatchState.appendByte (st : PatchState) (b : UInt8) : PatchState :=
  { st with bytes := st.bytes.push b }

private def PatchState.finish (st : PatchState) : EmitResult :=
  { bytes := st.bytes,
    constructorSlots := st.constructorSlotsRev.reverse,
    codeSepIndexSlots := st.codeSepIndexSlotsRev.reverse }

mutual

/--
True when an op tree contains no byte positions whose deployed bytes
can differ from the legacy emitter: constructor placeholders,
`pushCodesepIndex`, or `OP_CODESEPARATOR`.
-/
def stackOpHasNoPatchSites : StackOp → Bool
  | .placeholder _ _ => false
  | .pushCodesepIndex => false
  | .opcode "OP_CODESEPARATOR" => false
  | .ifOp thn none => opsHaveNoPatchSites thn
  | .ifOp thn (some els) =>
      opsHaveNoPatchSites thn && opsHaveNoPatchSites els
  | _ => true

def opsHaveNoPatchSites : List StackOp → Bool
  | [] => true
  | op :: rest => stackOpHasNoPatchSites op && opsHaveNoPatchSites rest

end

mutual

private def emitStackOpPatchedChecked : StackOp → PatchState →
    Except CodeSepPatchError PatchState
  | .placeholder paramIndex paramName, st =>
      let slot : ConstructorSlot :=
        { offset := st.offset, paramIndex := paramIndex, paramName := paramName }
      .ok { st with
        bytes := st.bytes.push 0x00,
        constructorSlotsRev := slot :: st.constructorSlotsRev }
  | .pushCodesepIndex, st =>
      match singletonNat? st.possibleCodeSeparatorOffsets with
      | some value =>
          let encoded := encodePushBigInt (Int.ofNat value)
          let slot : CodeSepIndexSlot :=
            { offset := st.offset,
              codeSeparatorOffset := value,
              encodedSize := encoded.size }
          .ok { (st.append encoded) with
            codeSepIndexSlotsRev := slot :: st.codeSepIndexSlotsRev }
      | none =>
          .error (.ambiguousCodeSepIndex st.offset st.possibleCodeSeparatorOffsets)
  | .opcode "OP_CODESEPARATOR", st =>
      let offset := st.offset
      .ok { (st.appendByte 0xab) with possibleCodeSeparatorOffsets := [offset] }
  | .ifOp thn els, st => do
      let stIf := st.appendByte 0x63
      let stThen ← emitOpsPatchedAuxChecked thn stIf
      let stAfterBranches ←
        match els with
        | none =>
            .ok { stThen with
              possibleCodeSeparatorOffsets :=
                natListUnion stThen.possibleCodeSeparatorOffsets
                  stIf.possibleCodeSeparatorOffsets }
        | some [] =>
            .ok { stThen with
              possibleCodeSeparatorOffsets :=
                natListUnion stThen.possibleCodeSeparatorOffsets
                  stIf.possibleCodeSeparatorOffsets }
        | some elsB =>
            let stElseBase := stThen.appendByte 0x67
            let stElseStart :=
              { stElseBase with
                possibleCodeSeparatorOffsets := stIf.possibleCodeSeparatorOffsets }
            let stElse ← emitOpsPatchedAuxChecked elsB stElseStart
            .ok { stElse with
              possibleCodeSeparatorOffsets :=
                natListUnion stThen.possibleCodeSeparatorOffsets
                  stElse.possibleCodeSeparatorOffsets }
      .ok (stAfterBranches.appendByte 0x68)
  | op, st =>
      .ok (st.append (emitStackOp op))

private def emitOpsPatchedAuxChecked : List StackOp → PatchState →
    Except CodeSepPatchError PatchState
  | [], st => .ok st
  | op :: rest, st => do
      let st' ← emitStackOpPatchedChecked op st
      emitOpsPatchedAuxChecked rest st'

end

/--
Emit one op list, replacing each `pushCodesepIndex` with the script
number for the latest emitted `OP_CODESEPARATOR` byte offset.
-/
def emitOpsWithCodeSepPatches (ops : List StackOp) :
    Except CodeSepPatchError EmitResult := do
  let st ← emitOpsPatchedAuxChecked ops {}
  .ok st.finish

private def emitDispatchChainPatched : Nat → List StackMethod → PatchState →
    Except CodeSepPatchError PatchState
  | _, [], st => .ok st
  | i, [m], st =>
      emitOpsPatchedAuxChecked m.ops (st.append (emitDispatchHeadLast i))
  | i, m :: rest, st => do
      let stHead := st.append (emitDispatchHeadNonLast i)
      let stBody ← emitOpsPatchedAuxChecked m.ops stHead
      let stElseBase := stBody.appendByte 0x67
      let stElseStart :=
        { stElseBase with
          possibleCodeSeparatorOffsets := stHead.possibleCodeSeparatorOffsets }
      let stRest ← emitDispatchChainPatched (i + 1) rest stElseStart
      .ok { stRest with
        possibleCodeSeparatorOffsets :=
          natListUnion stBody.possibleCodeSeparatorOffsets
            stRest.possibleCodeSeparatorOffsets }

private def emitEndifsPatched : Nat → PatchState → PatchState
  | 0, st => st
  | n + 1, st => emitEndifsPatched n (st.appendByte 0x68)

/--
Top-level slot-aware emit. Public-method dispatch bytes are included in
the offset accounting, so code-separator slot values match the final
deployed script layout rather than a method-local body layout.
-/
def emitWithCodeSepPatches (p : StackProgram) :
    Except CodeSepPatchError EmitResult :=
  match publicMethodsOf p with
  | [] => .ok ({} : PatchState).finish
  | [m] => do
      let st ← emitOpsPatchedAuxChecked m.ops {}
      .ok st.finish
  | ms => do
      let stChain ← emitDispatchChainPatched 0 ms {}
      .ok (emitEndifsPatched (ms.length - 1) stChain).finish

namespace PatchProof

private def noPatchState (bytes : ByteArray) : PatchState :=
  { bytes := bytes,
    constructorSlotsRev := [],
    codeSepIndexSlotsRev := [],
    possibleCodeSeparatorOffsets := [0] }

private theorem loop_eq_append_extract
    (bs acc : ByteArray) (i j : Nat) (hij : j + i = bs.size) :
    ByteArray.foldlM.loop (m := Id)
        (fun a b => pure (a.push b)) bs bs.size (Nat.le_refl _) i j acc
      = acc ++ bs.extract j bs.size := by
  induction i generalizing j acc with
  | zero =>
    have hj_eq : j = bs.size := by omega
    unfold ByteArray.foldlM.loop
    by_cases hjlt : j < bs.size
    · omega
    · simp only [hjlt, ↓reduceDIte]
      have hempty : bs.extract j bs.size = ByteArray.empty := by
        apply ByteArray.ext
        simp [hj_eq]
      rw [hempty]
      show acc = acc ++ ByteArray.empty
      rw [ByteArray.append_empty]
  | succ i ih =>
    have hjlt : j < bs.size := by omega
    unfold ByteArray.foldlM.loop
    simp only [hjlt, ↓reduceDIte]
    show (Id.run do
      let b ← (pure (acc.push bs[j]) : Id ByteArray)
      ByteArray.foldlM.loop (m := Id)
        (fun a b' => pure (a.push b')) bs bs.size (Nat.le_refl _) i (j+1) b
      ) = acc ++ bs.extract j bs.size
    simp only [Id.run, pure_bind]
    rw [ih (acc.push bs[j]) (j+1) (by omega)]
    have hsplit :
        bs.extract j bs.size
          = bs.extract j (j+1) ++ bs.extract (j+1) bs.size :=
      ByteArray.extract_eq_extract_append_extract (j+1)
        (Nat.le_succ j) (by omega)
    rw [hsplit, ← ByteArray.append_assoc,
        ByteArray.extract_add_one (by omega),
        ByteArray.append_toByteArray_singleton]
    rfl

theorem foldl_push_eq_append (acc bs : ByteArray) :
    bs.foldl (init := acc) (fun a b => a.push b) = acc ++ bs := by
  show (Id.run <| ByteArray.foldlM (m := Id)
        (fun a b => pure (a.push b)) acc bs 0 bs.size) = acc ++ bs
  unfold ByteArray.foldlM
  simp only [Nat.le_refl, ↓reduceDIte, Id.run]
  have h := loop_eq_append_extract bs acc bs.size 0 (by omega)
  show ByteArray.foldlM.loop (m := Id)
        (fun a b => pure (a.push b)) bs bs.size (Nat.le_refl _) (bs.size - 0) 0 acc
      = acc ++ bs
  rw [Nat.sub_zero, h]
  rw [ByteArray.extract_zero_size]

theorem appendBA_eq_append (acc bs : ByteArray) :
    appendBA acc bs = acc ++ bs := by
  unfold appendBA
  exact foldl_push_eq_append acc bs

def flatStackOpHasNoPatchSites : StackOp → Bool
  | .placeholder _ _ => false
  | .pushCodesepIndex => false
  | .opcode _ => false
  | .ifOp _ _ => false
  | _ => true

def flatOpsHaveNoPatchSites : List StackOp → Bool
  | [] => true
  | op :: rest => flatStackOpHasNoPatchSites op && flatOpsHaveNoPatchSites rest

private theorem emitStackOpPatchedChecked_flat_no_patch_sites_eq_emitStackOp
    (op : StackOp) (acc : ByteArray)
    (hNoPatch : flatStackOpHasNoPatchSites op = true) :
    emitStackOpPatchedChecked op (noPatchState acc)
      = .ok (noPatchState (acc ++ emitStackOp op)) := by
  cases op with
  | push v =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState,
        PatchState.append, appendBA_eq_append]
  | dup =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState,
        PatchState.append, appendBA_eq_append]
  | swap =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState,
        PatchState.append, appendBA_eq_append]
  | roll d =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState,
        PatchState.append, appendBA_eq_append]
  | pick d =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState,
        PatchState.append, appendBA_eq_append]
  | pickStruct d =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState,
        PatchState.append, appendBA_eq_append]
  | drop =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState,
        PatchState.append, appendBA_eq_append]
  | nip =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState,
        PatchState.append, appendBA_eq_append]
  | over =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState,
        PatchState.append, appendBA_eq_append]
  | rot =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState,
        PatchState.append, appendBA_eq_append]
  | tuck =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState,
        PatchState.append, appendBA_eq_append]
  | opcode name =>
      simp [flatStackOpHasNoPatchSites] at hNoPatch
  | ifOp thn els =>
      simp [flatStackOpHasNoPatchSites] at hNoPatch
  | placeholder i n =>
      simp [flatStackOpHasNoPatchSites] at hNoPatch
  | pushCodesepIndex =>
      simp [flatStackOpHasNoPatchSites] at hNoPatch

private theorem emitOpsPatchedAuxChecked_flat_no_patch_sites_eq_emitOps :
    ∀ (ops : List StackOp) (acc : ByteArray),
      flatOpsHaveNoPatchSites ops = true →
      emitOpsPatchedAuxChecked ops (noPatchState acc)
        = .ok (noPatchState (acc ++ emitOps ops))
  | [], acc, _ => by
      simp [emitOpsPatchedAuxChecked, emitOps, noPatchState]
  | op :: rest, acc, hNoPatch => by
      have hOp : flatStackOpHasNoPatchSites op = true := by
        cases h : flatStackOpHasNoPatchSites op <;>
          simp [flatOpsHaveNoPatchSites, h] at hNoPatch ⊢
      have hRest : flatOpsHaveNoPatchSites rest = true := by
        cases h : flatOpsHaveNoPatchSites rest <;>
          simp [flatOpsHaveNoPatchSites, h] at hNoPatch ⊢
      unfold emitOpsPatchedAuxChecked
      rw [emitStackOpPatchedChecked_flat_no_patch_sites_eq_emitStackOp
        op acc hOp]
      change
        emitOpsPatchedAuxChecked rest (noPatchState (acc ++ emitStackOp op))
          = Except.ok (noPatchState (acc ++ emitOps (op :: rest)))
      rw [emitOpsPatchedAuxChecked_flat_no_patch_sites_eq_emitOps
        rest (acc ++ emitStackOp op) hRest]
      simp [emitOps, noPatchState, ByteArray.append_assoc]

theorem emitOpsWithCodeSepPatches_flat_no_patch_sites_bytes_eq_emitOps
    (ops : List StackOp) (r : EmitResult)
    (hNoPatch : flatOpsHaveNoPatchSites ops = true)
    (hPatch : emitOpsWithCodeSepPatches ops = .ok r) :
    r.bytes = emitOps ops := by
  unfold emitOpsWithCodeSepPatches at hPatch
  change
    (do
      let st ← emitOpsPatchedAuxChecked ops (noPatchState ByteArray.empty)
      Except.ok st.finish) = Except.ok r at hPatch
  rw [emitOpsPatchedAuxChecked_flat_no_patch_sites_eq_emitOps ops ByteArray.empty
    hNoPatch] at hPatch
  simp [noPatchState, PatchState.finish] at hPatch
  cases hPatch
  rfl

theorem emitWithCodeSepPatches_single_public_flat_no_patch_sites_bytes_eq_emit
    (p : StackProgram) (m : StackMethod) (r : EmitResult)
    (hPublic : publicMethodsOf p = [m])
    (hNoPatch : flatOpsHaveNoPatchSites m.ops = true)
    (hPatch : emitWithCodeSepPatches p = .ok r) :
    r.bytes = emit p := by
  unfold emitWithCodeSepPatches at hPatch
  rw [hPublic] at hPatch
  simp at hPatch
  unfold emit
  rw [hPublic]
  simp only
  exact emitOpsWithCodeSepPatches_flat_no_patch_sites_bytes_eq_emitOps
    m.ops r hNoPatch hPatch

/-! ### Generalised: nested IFs

The flat predicate `flatOpsHaveNoPatchSites` rejects `.ifOp` outright,
which is too restrictive for the public-method bodies emitted by the
production compiler (the peephole pipeline routinely produces nested
IFs even when no code-separator / placeholder sites exist).

The mutual predicate `opsHaveNoPatchSites` (defined in `Emit`) allows
`.ifOp` provided every branch is itself patch-site-free. The lemmas
below extend the no-patch-sites byte-equality bridge to that wider
subset by mutual recursion on `stackOpHasNoPatchSites` /
`opsHaveNoPatchSites`.

The state-preservation invariant we ride on is that whenever
`opsHaveNoPatchSites ops = true`, processing `ops` through the patched
emitter does not modify `possibleCodeSeparatorOffsets`. Because the
top-level entry begins with `possibleCodeSeparatorOffsets := [0]`
(`noPatchState ByteArray.empty`), every recursive call stays at
`[0]` and `natListUnion [0] [0] = [0]` discharges the IF-join
bookkeeping. -/

private theorem natListUnion_singleton_zero_self :
    natListUnion [0] [0] = [0] := by
  decide

private theorem noPatchState_appendByte (acc : ByteArray) (b : UInt8) :
    (noPatchState acc).appendByte b
      = noPatchState (acc ++ ByteArray.mk #[b]) := by
  have hpush : ∀ (a : ByteArray) (x : UInt8),
      a.push x = a ++ ByteArray.mk #[x] := by
    intro a x; apply ByteArray.ext; simp
  simp [noPatchState, PatchState.appendByte, hpush]

private theorem noPatchState_append_bytes (acc bs : ByteArray) :
    (noPatchState acc).append bs = noPatchState (acc ++ bs) := by
  simp [noPatchState, PatchState.append, appendBA_eq_append]

mutual

private theorem emitStackOpPatchedChecked_no_patch_sites_eq_emitStackOp
    (op : StackOp) (acc : ByteArray)
    (hNoPatch : stackOpHasNoPatchSites op = true) :
    emitStackOpPatchedChecked op (noPatchState acc)
      = .ok (noPatchState (acc ++ emitStackOp op)) := by
  cases op with
  | push v =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState_append_bytes]
  | dup =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState_append_bytes]
  | swap =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState_append_bytes]
  | roll d =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState_append_bytes]
  | pick d =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState_append_bytes]
  | pickStruct d =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState_append_bytes]
  | drop =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState_append_bytes]
  | nip =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState_append_bytes]
  | over =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState_append_bytes]
  | rot =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState_append_bytes]
  | tuck =>
      simp [emitStackOpPatchedChecked, emitStackOp, noPatchState_append_bytes]
  | opcode name =>
      by_cases hCs : name = "OP_CODESEPARATOR"
      · subst hCs
        simp [stackOpHasNoPatchSites] at hNoPatch
      · -- The `.opcode name` case for non-`OP_CODESEPARATOR` reduces to
        -- the catch-all `op, st => .ok (st.append (emitStackOp op))` branch.
        have hUnfold :
            emitStackOpPatchedChecked (.opcode name) (noPatchState acc)
              = .ok ((noPatchState acc).append (emitStackOp (.opcode name))) := by
          unfold emitStackOpPatchedChecked
          split <;> first
            | rfl
            | (rename_i hname; injection hname with hname'; exact absurd hname' hCs)
            | (rename_i hname; cases hname)
        rw [hUnfold, noPatchState_append_bytes]
  | placeholder i n =>
      simp [stackOpHasNoPatchSites] at hNoPatch
  | pushCodesepIndex =>
      simp [stackOpHasNoPatchSites] at hNoPatch
  | ifOp thn els =>
      -- Common preparation for every IF case: extract `thn` no-patch-sites
      -- and run the inductive step on `thn`.
      have hThn : opsHaveNoPatchSites thn = true := by
        cases els with
        | none =>
            simp [stackOpHasNoPatchSites] at hNoPatch; exact hNoPatch
        | some elsB =>
            cases elsB with
            | nil =>
                simp [stackOpHasNoPatchSites, opsHaveNoPatchSites] at hNoPatch
                exact hNoPatch
            | cons elsHead elsTail =>
                have h := hNoPatch
                simp [stackOpHasNoPatchSites] at h
                exact h.1
      have hIH1 := emitOpsPatchedAuxChecked_no_patch_sites_eq_emitOps thn
        (acc ++ ByteArray.mk #[0x63]) hThn
      -- Unfold the .ifOp branch of emitStackOpPatchedChecked.
      unfold emitStackOpPatchedChecked
      -- Use `simp only` to rewrite the inner bind chain via hIH1.
      rw [noPatchState_appendByte]
      -- Reduce: `emitOpsPatchedAuxChecked thn (noPatchState (acc ++ #[0x63])) = .ok ...`
      simp only [hIH1, Bind.bind, Except.bind]
      -- Goal now has substituted `stThen := noPatchState (acc ++ #[0x63] ++ emitOps thn)`.
      -- Split into the three sub-cases of `els`.
      cases els with
      | none =>
          -- Reduces to a single `.ok (... appendByte 0x68)`.
          show Except.ok _ = _
          simp [noPatchState, natListUnion_singleton_zero_self,
            PatchState.appendByte, emitStackOp]
          apply ByteArray.ext
          simp
      | some elsB =>
          cases elsB with
          | nil =>
              show Except.ok _ = _
              simp [noPatchState, natListUnion_singleton_zero_self,
                PatchState.appendByte, emitStackOp]
              apply ByteArray.ext
              simp
          | cons elsHead elsTail =>
              have hEls : opsHaveNoPatchSites (elsHead :: elsTail) = true := by
                have h := hNoPatch
                simp [stackOpHasNoPatchSites] at h
                exact h.2
              -- After the outer bind has substituted `stThen := noPatchState ...`,
              -- the residual state-record on which `elsB` runs equals
              -- `noPatchState (acc ++ #[0x63] ++ emitOps thn ++ #[0x67])`.
              have hStart :
                  ({ (noPatchState
                        (acc ++ ByteArray.mk #[0x63] ++ emitOps thn)).appendByte 0x67 with
                      possibleCodeSeparatorOffsets :=
                        (noPatchState (acc ++ ByteArray.mk #[0x63])).possibleCodeSeparatorOffsets }
                    : PatchState)
                    = noPatchState
                        (acc ++ ByteArray.mk #[0x63] ++ emitOps thn
                          ++ ByteArray.mk #[0x67]) := by
                rw [noPatchState_appendByte]
                simp [noPatchState]
              simp only [hStart]
              have hIH2 := emitOpsPatchedAuxChecked_no_patch_sites_eq_emitOps
                (elsHead :: elsTail)
                (acc ++ ByteArray.mk #[0x63] ++ emitOps thn ++ ByteArray.mk #[0x67]) hEls
              rw [hIH2]
              show Except.ok _ = _
              simp [noPatchState, natListUnion_singleton_zero_self,
                PatchState.appendByte, emitStackOp]
              apply ByteArray.ext
              simp [ByteArray.append_assoc]

private theorem emitOpsPatchedAuxChecked_no_patch_sites_eq_emitOps
    (ops : List StackOp) (acc : ByteArray)
    (hNoPatch : opsHaveNoPatchSites ops = true) :
    emitOpsPatchedAuxChecked ops (noPatchState acc)
      = .ok (noPatchState (acc ++ emitOps ops)) := by
  cases ops with
  | nil =>
      simp [emitOpsPatchedAuxChecked, emitOps, noPatchState]
  | cons op rest =>
      have hOp : stackOpHasNoPatchSites op = true := by
        cases h : stackOpHasNoPatchSites op <;>
          simp [opsHaveNoPatchSites, h] at hNoPatch ⊢
      have hRest : opsHaveNoPatchSites rest = true := by
        cases h : opsHaveNoPatchSites rest <;>
          simp [opsHaveNoPatchSites, h] at hNoPatch ⊢
      unfold emitOpsPatchedAuxChecked
      rw [emitStackOpPatchedChecked_no_patch_sites_eq_emitStackOp op acc hOp]
      change
        emitOpsPatchedAuxChecked rest (noPatchState (acc ++ emitStackOp op))
          = Except.ok (noPatchState (acc ++ emitOps (op :: rest)))
      rw [emitOpsPatchedAuxChecked_no_patch_sites_eq_emitOps rest (acc ++ emitStackOp op) hRest]
      simp [emitOps, noPatchState, ByteArray.append_assoc]

end

theorem emitOpsWithCodeSepPatches_no_patch_sites_bytes_eq_emitOps
    (ops : List StackOp) (r : EmitResult)
    (hNoPatch : opsHaveNoPatchSites ops = true)
    (hPatch : emitOpsWithCodeSepPatches ops = .ok r) :
    r.bytes = emitOps ops := by
  unfold emitOpsWithCodeSepPatches at hPatch
  change
    (do
      let st ← emitOpsPatchedAuxChecked ops (noPatchState ByteArray.empty)
      Except.ok st.finish) = Except.ok r at hPatch
  rw [emitOpsPatchedAuxChecked_no_patch_sites_eq_emitOps ops ByteArray.empty
    hNoPatch] at hPatch
  simp [noPatchState, PatchState.finish] at hPatch
  cases hPatch
  rfl

theorem emitWithCodeSepPatches_single_public_no_patch_sites_bytes_eq_emit
    (p : StackProgram) (m : StackMethod) (r : EmitResult)
    (hPublic : publicMethodsOf p = [m])
    (hNoPatch : opsHaveNoPatchSites m.ops = true)
    (hPatch : emitWithCodeSepPatches p = .ok r) :
    r.bytes = emit p := by
  unfold emitWithCodeSepPatches at hPatch
  rw [hPublic] at hPatch
  simp at hPatch
  unfold emit
  rw [hPublic]
  simp only
  exact emitOpsWithCodeSepPatches_no_patch_sites_bytes_eq_emitOps
    m.ops r hNoPatch hPatch

end PatchProof

theorem emitWithCodeSepPatches_single_public_empty_ops_bytes_eq_emitFast
    (p : StackProgram) (m : StackMethod) (r : EmitResult)
    (hPublic : publicMethodsOf p = [m])
    (hOps : m.ops = [])
    (hPatch : emitWithCodeSepPatches p = .ok r) :
    r.bytes = emitFast p := by
  unfold emitWithCodeSepPatches at hPatch
  rw [hPublic] at hPatch
  simp at hPatch
  rw [hOps] at hPatch
  cases hPatch
  unfold emitFast
  rw [hPublic]
  simp [hOps, emitOpsFast, emitOpsFastAux, PatchState.finish]

theorem emitOpsWithCodeSepPatches_sample :
    (match emitOpsWithCodeSepPatches
        [.push (.bigint 7), .opcode "OP_CODESEPARATOR", .pushCodesepIndex] with
     | .ok r =>
         r.bytes.toList == [0x57, 0xab, 0x51]
           && r.constructorSlots == []
           && r.codeSepIndexSlots ==
                [{ offset := 2, codeSeparatorOffset := 1, encodedSize := 1 }]
     | .error _ => false) = true := by
  native_decide

theorem emitOpsWithCodeSepPatches_constructorSlot_sample :
    (match emitOpsWithCodeSepPatches
        [.placeholder 3 "owner", .opcode "OP_CODESEPARATOR", .pushCodesepIndex] with
     | .ok r =>
         r.bytes.toList == [0x00, 0xab, 0x51]
           && r.constructorSlots ==
                [{ offset := 0, paramIndex := 3, paramName := "owner" }]
           && r.codeSepIndexSlots ==
                [{ offset := 2, codeSeparatorOffset := 1, encodedSize := 1 }]
     | .error _ => false) = true := by
  native_decide

theorem emitWithCodeSepPatches_dispatchOffset_sample :
    (let p : StackProgram :=
      { contractName := "C",
        methods :=
          [{ name := "a",
             ops := [.opcode "OP_CODESEPARATOR", .pushCodesepIndex],
             maxStackDepth := 0 },
           { name := "b", ops := [], maxStackDepth := 0 }] }
    match emitWithCodeSepPatches p with
    | .ok r =>
        r.bytes.toList ==
            [0x76, 0x00, 0x9c, 0x63, 0x75, 0xab, 0x55,
             0x67, 0x51, 0x9d, 0x68]
          && r.codeSepIndexSlots ==
              [{ offset := 6, codeSeparatorOffset := 5, encodedSize := 1 }]
     | .error _ => false) = true := by
  native_decide

theorem emitWithCodeSepPatches_dispatchBranchReset_sample :
    (let p : StackProgram :=
      { contractName := "C",
        methods :=
          [{ name := "a",
             ops := [.opcode "OP_CODESEPARATOR"],
             maxStackDepth := 0 },
           { name := "b",
             ops := [.pushCodesepIndex],
             maxStackDepth := 0 }] }
    match emitWithCodeSepPatches p with
    | .ok r =>
        r.bytes.toList ==
            [0x76, 0x00, 0x9c, 0x63, 0x75, 0xab,
             0x67, 0x51, 0x9d, 0x00, 0x68]
          && r.codeSepIndexSlots ==
              [{ offset := 9, codeSeparatorOffset := 0, encodedSize := 1 }]
    | .error _ => false) = true := by
  native_decide

theorem emitOpsWithCodeSepPatches_branchLocalElse_sample :
    (match emitOpsWithCodeSepPatches
        [.ifOp [.opcode "OP_CODESEPARATOR"] (some [.pushCodesepIndex])] with
     | .ok r =>
         r.bytes.toList == [0x63, 0xab, 0x67, 0x00, 0x68]
           && r.codeSepIndexSlots ==
                [{ offset := 3, codeSeparatorOffset := 0, encodedSize := 1 }]
     | .error _ => false) = true := by
  native_decide

theorem emitOpsWithCodeSepPatches_ambiguousJoin_sample :
    (match emitOpsWithCodeSepPatches
        [.ifOp [.opcode "OP_CODESEPARATOR"] none, .pushCodesepIndex] with
     | .error (.ambiguousCodeSepIndex 3 [1, 0]) => true
     | _ => false) = true := by
  native_decide

end Emit
end RunarVerification.Script
