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
* `placeholder` and `pushCodesepIndex` (both emit `OP_0`),
* the `pick d` / `roll d` form which lowers to a script-number push of
  the depth followed by `OP_PICK` / `OP_ROLL`.

**Out of scope (Phase 3b).** `OP_PUSHDATA2` (≥256-byte data),
`OP_PUSHDATA4` (≥65 536-byte data), method-dispatch chain emission
(public-method index threading via `OP_NUMEQUALVERIFY`), source-map
construction, and the `constructorSlots` / `codeSepIndexSlots` byte
tables (the records are still produced by the SDK at deploy time).
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
  String.mk [hi, lo]

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

private partial def absToBytesLE (n : Nat) : List UInt8 :=
  if n = 0 then []
  else (UInt8.ofNat (n &&& 0xff)) :: absToBytesLE (n >>> 8)

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
  | .opcode name     =>
      match opcodeByName? name with
      | some b => ByteArray.mk #[b]
      | none   => ByteArray.empty   -- TODO opcodes are stripped silently in Phase 3a
  | .ifOp thn els    =>
      -- OP_IF (0x63) <thn> [OP_ELSE (0x67) <els>] OP_ENDIF (0x68)
      let thnBytes := emitOps thn
      let elseSection :=
        match els with
        | none      => ByteArray.empty
        | some elsB => ByteArray.mk #[0x67] ++ emitOps elsB
      ByteArray.mk #[0x63] ++ thnBytes ++ elseSection ++ ByteArray.mk #[0x68]
  | .placeholder _ _ => ByteArray.mk #[0x00]   -- OP_0 placeholder
  | .pushCodesepIndex => ByteArray.mk #[0x00]  -- OP_0 placeholder

/-- Emit a flat op list as a concatenated byte array. -/
def emitOps : List StackOp → ByteArray
  | [] => ByteArray.empty
  | op :: rest => emitStackOp op ++ emitOps rest

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

end Emit
end RunarVerification.Script
