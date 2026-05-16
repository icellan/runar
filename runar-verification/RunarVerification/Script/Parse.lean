import RunarVerification.Script.Syntax
import RunarVerification.Script.Emit
import RunarVerification.Stack.Syntax

/-!
# Bitcoin Script byte parser (Tier 2 item 2.3 of the remediation plan)

The decoder for the Rúnar-emitted opcode subset.

This module provides the **inverse direction** of `Emit.emit` for the
closed subset of opcodes the Rúnar compiler actually produces. It is
NOT a full Bitcoin Script parser — out-of-scope opcodes (e.g.
`OP_CHECKMULTISIG` argument frames, `OP_CODESEPARATOR` script-position
tracking, `OP_RESERVED*`) are handled only insofar as they can appear
in Rúnar-emitted bytes.

## Surface

* `ParseError` — failure modes (truncated input, unknown opcode, short
  pushdata, unmatched OP_IF).
* `parsePushVal?` — read one pushdata header (`OP_0`..`OP_16`,
  `OP_1NEGATE`, literal-length, `OP_PUSHDATA1`, `OP_PUSHDATA2`,
  `OP_PUSHDATA4`) and return the decoded `PushVal` plus the remaining
  byte tail.
* `parseStackOp1?` — single-byte zero-arg opcodes
  (`dup`/`swap`/`nip`/`over`/`rot`/`tuck`/`drop`) plus the named
  opcodes referenced from `Stack.opcode`'s string table.
* `parseStackOpFuel` / `parseOpsFuel` — fuel-driven primitive decoders
  that reconstruct `roll d` / `pick d` / `pickStruct d` (push-then-byte)
  and `ifOp thn els` (`OP_IF` / `OP_ELSE` / `OP_ENDIF` matched-bracket
  blocks).
* `parseScript` — top-level entry: `ByteArray → Except ParseError
  (List StackOp)`.

## Round-trip theorem

The headline result is `parseOps_emit_round_trip` (and its
`parseScript`-level corollary): for every list of `RunarEmittable`
ops, parsing the bytes produced by `emitStackOpL`/`emitOpsL` returns
exactly the original op list.

`emitStackOpL` and `emitOpsL` are list-of-byte mirrors of
`Emit.emitStackOp` and `Emit.emitOps` (which produce `ByteArray`).
The two encoders agree pointwise via the `emit_toList` lemmas.
Working in `List UInt8` avoids the `ByteArray.++ / .toList` algebra
that lacks stdlib lemmas in Lean 4.29.1, while still pinning down the
exact byte sequence the round-trip targets.
-/

namespace RunarVerification.Script
namespace Parse

open RunarVerification.Script
open RunarVerification.Stack (StackOp PushVal)

/-! ## Failure modes -/

/-- Parse-time errors. -/
inductive ParseError where
  /-- The input ended in the middle of decoding an opcode/pushdata. -/
  | unexpectedEnd
  /-- A byte was found that doesn't correspond to any Rúnar-emittable
      opcode. -/
  | unknownOpcode (b : UInt8) : ParseError
  /-- A pushdata declared length exceeds available remaining bytes. -/
  | shortPushdata (declared actual : Nat) : ParseError
  /-- An OP_IF was seen without a balancing OP_ENDIF. -/
  | unmatchedIf : ParseError
  /-- The decoder ran out of fuel — never raised when fuel is the input
      byte length, since each step consumes ≥ 1 byte. Present so the
      `Except` chain in `parseStackOpFuel` is total. -/
  | outOfFuel : ParseError
  deriving Repr

/-! ## List-level encoders

Mirrors `Emit.emitStackOp` / `Emit.emitOps` but at `List UInt8` level
so the parser (which consumes `List UInt8`) and the encoder share an
algebraic theory (`++`, `length`, `cons` reduction) that Lean's stdlib
already supplies.

Each definition is line-by-line parallel to its `Emit.lean` peer.
-/

/-! ### Script-number encoding (list version) -/

private def absToBytesLEL : (n : Nat) → List UInt8
  | 0 => []
  | (k + 1) =>
      let n := k + 1
      (UInt8.ofNat (n &&& 0xff)) :: absToBytesLEL (n >>> 8)
termination_by n => n
decreasing_by
  simp [Nat.shiftRight_eq_div_pow]
  exact Nat.div_lt_self (Nat.succ_pos _) (by decide)

/-- Sign-magnitude little-endian encoding, same algorithm as
`Emit.encodeScriptNumber` but returning `List UInt8`. -/
def encodeScriptNumberL (n : Int) : List UInt8 :=
  if n = 0 then []
  else
    let negative := n < 0
    let absN := n.natAbs
    let bytes := absToBytesLEL absN
    let last := bytes.getLast!
    let body := bytes.dropLast
    if last &&& 0x80 ≠ 0 then
      let sign : UInt8 := if negative then 0x80 else 0x00
      body ++ [last, sign]
    else if negative then
      body ++ [last ||| 0x80]
    else
      bytes

/-! ### Push-data encoding (list version) -/

def encodePushDataL (data : List UInt8) : List UInt8 :=
  let len := data.length
  if len = 0 then
    [0x00]
  else if len ≤ 75 then
    UInt8.ofNat len :: data
  else if len ≤ 255 then
    0x4c :: UInt8.ofNat len :: data
  else if len ≤ 65535 then
    let lo : UInt8 := UInt8.ofNat (len &&& 0xff)
    let hi : UInt8 := UInt8.ofNat ((len >>> 8) &&& 0xff)
    0x4d :: lo :: hi :: data
  else
    let b0 : UInt8 := UInt8.ofNat (len &&& 0xff)
    let b1 : UInt8 := UInt8.ofNat ((len >>> 8) &&& 0xff)
    let b2 : UInt8 := UInt8.ofNat ((len >>> 16) &&& 0xff)
    let b3 : UInt8 := UInt8.ofNat ((len >>> 24) &&& 0xff)
    0x4e :: b0 :: b1 :: b2 :: b3 :: data

/-! ### Push-value encoding (list version) -/

def encodePushBigIntL (n : Int) : List UInt8 :=
  if n = 0 then [0x00]
  else if n = -1 then [0x4f]
  else if 1 ≤ n ∧ n ≤ 16 then
    [UInt8.ofNat (0x50 + n.natAbs)]
  else
    encodePushDataL (encodeScriptNumberL n)

def encodePushBoolL (b : Bool) : List UInt8 :=
  if b then [0x51] else [0x00]

def encodePushBytesL (data : List UInt8) : List UInt8 :=
  match data with
  | [] => [0x00]
  | [b] =>
      if 1 ≤ b.toNat ∧ b.toNat ≤ 16 then
        [UInt8.ofNat (0x50 + b.toNat)]
      else if b = 0x81 then
        [0x4f]
      else
        encodePushDataL [b]
  | _ :: _ :: _ => encodePushDataL data

def encodePushValL : PushVal → List UInt8
  | .bigint i => encodePushBigIntL i
  | .bool b   => encodePushBoolL b
  | .bytes b  => encodePushBytesL b.toList

/-! ### StackOp emit (list version)

Mirrors `Emit.emitStackOp` and `Emit.emitOps`. Note the same caveats:

* `.opcode name` falls back to `[]` when `opcodeByName?` returns
  `none` — preserving the (unsound!) Phase 3a behaviour. The round-trip
  theorem rules out this case via `RunarEmittable`.
* `.placeholder` and `.pushCodesepIndex` both emit `[0x00]` (`OP_0`).
  These are deploy-time slot markers; the round-trip theorem treats
  them as equal to a `.push (.bigint 0)` after parsing — i.e. they are
  excluded from `RunarEmittable` since the parser cannot tell them
  apart from a literal `OP_0`.
-/

mutual

def emitStackOpL : StackOp → List UInt8
  | .push v          => encodePushValL v
  | .dup             => [0x76]
  | .swap            => [0x7c]
  | .nip             => [0x77]
  | .over            => [0x78]
  | .rot             => [0x7b]
  | .tuck            => [0x7d]
  | .drop            => [0x75]
  | .roll d          => encodePushBigIntL (Int.ofNat d) ++ [0x7a]
  | .pick d          => encodePushBigIntL (Int.ofNat d) ++ [0x79]
  | .pickStruct d    => encodePushBigIntL (Int.ofNat d) ++ [0x79]
  | .opcode name     =>
      match opcodeByName? name with
      | some b => [b]
      | none   => []
  | .ifOp thn els    =>
      let thnBytes := emitOpsL thn
      let elseSection :=
        match els with
        | none      => []
        | some []   => []
        | some elsB => 0x67 :: emitOpsL elsB
      0x63 :: thnBytes ++ elseSection ++ [0x68]
  | .placeholder _ _ => [0x00]
  | .pushCodesepIndex => [0x00]
  | .rawBytes b      => b.toList

def emitOpsL : List StackOp → List UInt8
  | [] => []
  | op :: rest => emitStackOpL op ++ emitOpsL rest

end

/-! ## Roll/pick depth-encoding distinguishability

For the round-trip theorem to recover `roll d` / `pick d` from
`encodePushBigIntL (Int.ofNat d) ++ [0x7a/0x79]`, the parser
needs to extract exactly that natural-number depth. This means the
push-bigint encoding for `Int.ofNat d` must round-trip through
`parsePushVal?` to `PushVal.bigint (Int.ofNat d)`.
-/

/-! ## Pushdata header decoding

Pure pattern-match on the leading byte. For literal-length and
`OP_PUSHDATA*` headers, we read the next N bytes off the stream.
-/

/-- Read `n` bytes from the prefix, returning them and the remaining
suffix. Fails with `unexpectedEnd` if the input is too short. -/
def takeBytes : Nat → List UInt8 → Except ParseError (List UInt8 × List UInt8)
  | 0,     bs        => .ok ([], bs)
  | _ + 1, []        => .error .unexpectedEnd
  | n + 1, b :: bs   => do
      let (rest, tail) ← takeBytes n bs
      .ok (b :: rest, tail)

/-- Decode a literal-length push (header byte gave us the length).
Returns the corresponding `PushVal`, applying the bsv minimal-encoding
rules: a single-byte payload `b ∈ [1,16]` would have been emitted as
`OP_1`..`OP_16`, and `b = 0x81` would have been emitted as
`OP_1NEGATE`; the parser must therefore *not* re-fold those payloads
into a small-int `bigint` here — they remain as literal `bytes`.

Empty payload (length 0) cannot occur as a literal-length push (the
emit pass uses `OP_0` for that). -/
def decodeLiteralPush (data : List UInt8) : PushVal :=
  PushVal.bytes ⟨data.toArray⟩

/-- Read a 1-byte little-endian length and the corresponding payload. -/
def parsePushdata1 : List UInt8 → Except ParseError (PushVal × List UInt8)
  | []          => .error .unexpectedEnd
  | n :: rest   => do
      let (data, tail) ← takeBytes n.toNat rest
      .ok (decodeLiteralPush data, tail)

/-- Read a 2-byte little-endian length and the corresponding payload. -/
def parsePushdata2 : List UInt8 → Except ParseError (PushVal × List UInt8)
  | b0 :: b1 :: rest => do
      let len := b0.toNat ||| (b1.toNat <<< 8)
      let (data, tail) ← takeBytes len rest
      .ok (decodeLiteralPush data, tail)
  | _ => .error .unexpectedEnd

/-- Read a 4-byte little-endian length and the corresponding payload. -/
def parsePushdata4 : List UInt8 → Except ParseError (PushVal × List UInt8)
  | b0 :: b1 :: b2 :: b3 :: rest => do
      let len :=
        b0.toNat
        ||| (b1.toNat <<< 8)
        ||| (b2.toNat <<< 16)
        ||| (b3.toNat <<< 24)
      let (data, tail) ← takeBytes len rest
      .ok (decodeLiteralPush data, tail)
  | _ => .error .unexpectedEnd

/-- Decode a push instruction. Returns `none` if the leading byte is
not a push opcode (the caller dispatches to the named-opcode table). -/
def parsePushVal? : List UInt8 → Option (Except ParseError (PushVal × List UInt8))
  | []        => none
  | b :: rest =>
    let n := b.toNat
    if n = 0 then
      some (.ok (.bigint 0, rest))
    else if n = 0x4f then
      some (.ok (.bigint (-1), rest))
    else if 0x51 ≤ n ∧ n ≤ 0x60 then
      some (.ok (.bigint (Int.ofNat (n - 0x50)), rest))
    else if 1 ≤ n ∧ n ≤ 0x4b then
      some <| do
        let (data, tail) ← takeBytes n rest
        .ok (decodeLiteralPush data, tail)
    else if n = 0x4c then
      some (parsePushdata1 rest)
    else if n = 0x4d then
      some (parsePushdata2 rest)
    else if n = 0x4e then
      some (parsePushdata4 rest)
    else
      none

/-! ## Single-byte opcode decoding -/

/-- Decode a single zero-argument opcode byte to its `StackOp`.
Mirrors the inverse of the named-opcode emit table (single-byte
named opcodes plus the seven short-form stack ops). -/
def parseStackOp1? : UInt8 → Option StackOp
  | 0x76 => some .dup
  | 0x7c => some .swap
  | 0x77 => some .nip
  | 0x78 => some .over
  | 0x7b => some .rot
  | 0x7d => some .tuck
  | 0x75 => some .drop
  | b    =>
      -- Look up by the canonical name table; if found, reconstruct
      -- as a named-opcode StackOp. Filters out OP_IF/OP_ELSE/OP_ENDIF
      -- (those are only legal inside an ifOp frame, handled by
      -- `parseOpsFuel`'s outer dispatch).
      match opcodeName? b with
      | some name =>
          if b = 0x63 ∨ b = 0x67 ∨ b = 0x68 ∨ b = 0x79 ∨ b = 0x7a then
            none
          else
            some (.opcode name)
      | none => none

/-! ## Script-number decoding (depth recovery)

The encoder lowers `.pick d` / `.roll d` to `encodePushBigInt d ++
[0x79/0x7a]`. For `d ∈ [0..16]` this is a single-byte push (`OP_0`,
`OP_1NEGATE`, or `OP_N`). For `d ≥ 17` (or `d ≤ -2`, never used in
practice) it falls through to `encodePushData (encodeScriptNumber d)`
— a literal-length push whose payload is the sign-magnitude
little-endian byte encoding of the depth.

`parsePushVal?` decodes a literal-length push as `.bytes _`, NOT as
`.bigint _` — there is no way to round-trip a `.push (.bigint d)`
back to `.bigint` once it has been encoded as a literal-length push,
because `.push (.bytes payload)` produces byte-identical output when
`payload.size > 1`. The two are byte-equivalent IR forms.

For the `.pick d` / `.roll d` reconstruction, however, we know from
the encoder that any push followed by `0x79` / `0x7a` was produced
by `encodePushBigInt d` for some non-negative `d`. We therefore
re-decode the `.bytes` payload as a script-number to recover `d`.

`decodeScriptNumberL` is the byte-level inverse of `encodeScriptNumberL`
on canonical inputs. Mirrors the BSV consensus rule for `OP_PICK` /
`OP_ROLL`-depth interpretation.
-/

/-- Read a list of bytes as a little-endian unsigned natural. -/
private def littleEndianNatL : List UInt8 → Nat
  | []        => 0
  | b :: rest => b.toNat + 256 * littleEndianNatL rest

/-- Decode a sign-magnitude little-endian script-number. Empty bytes
denote zero. The high bit of the last byte is the sign bit; the
remaining 7 bits of that byte plus the lower bytes form the magnitude.

Inverse of `encodeScriptNumberL` on canonical (well-formed) inputs.
For non-canonical inputs (e.g. `[0x80]` or trailing zero) it still
returns a deterministic `Int`, but the round-trip is only guaranteed
for canonical encodings. -/
def decodeScriptNumberL : List UInt8 → Int
  | [] => 0
  | bs =>
      let last := bs.getLast!
      let body := bs.dropLast
      let neg : Bool := decide (last &&& 0x80 ≠ 0)
      let highByte : UInt8 := last &&& 0x7f
      let magBytes : List UInt8 := body ++ [highByte]
      let mag : Nat := littleEndianNatL magBytes
      if neg then -(Int.ofNat mag) else Int.ofNat mag

/-! ## Top-level driver — fuel-based to keep totality obvious

`fuel = bytes.length` is always sufficient, since each successful
single-op parse strictly shrinks the byte list (every successful
parse consumes ≥ 1 byte).

`parseOpsFuel` accepts a `stopAtElse` flag: when true, it returns on
encountering an `OP_ELSE` (0x67) or `OP_ENDIF` (0x68) without
consuming it. This is the recursive-descent hook for `ifOp` body
parsing.
-/

mutual

/-- Fuel-driven primitive. Structurally recursive on the `fuel` Nat.

The first iteration reads one structural unit (a single opcode or
the body of an OP_IF block) and returns the parsed StackOp plus the
remaining bytes. Recursive calls (one for the then-branch, one for
the else-branch) decrement the fuel.

`fuel = bytes.length` is always a safe upper bound: each successful
single-op parse strictly shrinks the byte list (every successful
parse consumes ≥ 1 byte), so any well-formed Rúnar-emitted prefix
will terminate before fuel runs out. -/
def parseStackOpFuel : Nat → List UInt8 →
    Except ParseError (StackOp × List UInt8)
  | 0,        _           => .error .outOfFuel
  | _ + 1,    []          => .error .unexpectedEnd
  | fuel + 1, b :: rest   =>
    -- Push opcodes first.
    match parsePushVal? (b :: rest) with
    | some result =>
        match result with
        | .error e => .error e
        | .ok (pv, tail) =>
            -- Roll/pick reconstruction: a push followed by 0x7a /
            -- 0x79 collapses to .roll / .pick. Two paths:
            --
            -- 1. `.bigint i` push (small-int fast path, `i ∈ [0..16]`
            --    or `i = -1`): trivially recoverable as `.pick/.roll
            --    i.toNat` when `i ≥ 0`.
            -- 2. `.bytes payload` push (literal-length push for any
            --    `i ≥ 17` or `i ≤ -2`): the encoder lowered
            --    `.pick d` / `.roll d` for large `d` via
            --    `encodePushBigInt d → encodePushData (encodeScriptNumber d)`,
            --    which produces byte-identical output to a `.push
            --    (.bytes ...)`. We re-decode the payload as a
            --    script-number to recover `d`.
            --
            -- The `.bytes` case is the load-bearing addition for the
            -- Tier 4.6 differential allowlist closure: babybear-ext4 /
            -- blake3 / sha256-compress / sha256-finalize all emit
            -- `.pick d` / `.roll d` with `d ≥ 17`.
            match pv, tail with
            | .bigint i, 0x7a :: tail' =>
                if 0 ≤ i then
                  .ok (.roll i.toNat, tail')
                else
                  .ok (.push (.bigint i), 0x7a :: tail')
            | .bigint i, 0x79 :: tail' =>
                if 0 ≤ i then
                  .ok (.pick i.toNat, tail')
                else
                  .ok (.push (.bigint i), 0x79 :: tail')
            | .bytes payload, 0x7a :: tail' =>
                let depth := decodeScriptNumberL payload.toList
                if 0 ≤ depth then
                  .ok (.roll depth.toNat, tail')
                else
                  .ok (.push (.bytes payload), 0x7a :: tail')
            | .bytes payload, 0x79 :: tail' =>
                let depth := decodeScriptNumberL payload.toList
                if 0 ≤ depth then
                  .ok (.pick depth.toNat, tail')
                else
                  .ok (.push (.bytes payload), 0x79 :: tail')
            | _, _ =>
                .ok (.push pv, tail)
    | none =>
        -- Control-flow: OP_IF starts a balanced bracket frame.
        if b = 0x63 then
          match parseOpsFuel fuel rest true with
          | .error e => .error e
          | .ok (thn, afterThn) =>
              match afterThn with
              | 0x67 :: rest' =>
                  match parseOpsFuel fuel rest' true with
                  | .error e => .error e
                  | .ok (els, afterEls) =>
                      match afterEls with
                      | 0x68 :: rest'' =>
                          .ok (.ifOp thn (some els), rest'')
                      | _ => .error .unmatchedIf
              | 0x68 :: rest' =>
                  .ok (.ifOp thn none, rest')
              | _ => .error .unmatchedIf
        else
          match parseStackOp1? b with
          | some op => .ok (op, rest)
          | none    => .error (.unknownOpcode b)

/-- Repeatedly call `parseStackOpFuel` until the input is exhausted
or (when `stopAtElse` is true) we hit OP_ELSE / OP_ENDIF. Decreases
on `fuel` (each iteration consumes at least one byte from `bytes`,
but we use fuel-decrement to stay structurally recursive and total). -/
def parseOpsFuel : Nat → List UInt8 → Bool →
    Except ParseError (List StackOp × List UInt8)
  | 0,        _,     _          => .error .outOfFuel
  | _ + 1,    [],    _          => .ok ([], [])
  | fuel + 1, bytes@(b :: _), stopAtElse =>
      if stopAtElse ∧ (b = 0x67 ∨ b = 0x68) then
        .ok ([], bytes)
      else
        match parseStackOpFuel fuel bytes with
        | .error e => .error e
        | .ok (op, rest) =>
            match parseOpsFuel fuel rest stopAtElse with
            | .error e => .error e
            | .ok (ops, tail) => .ok (op :: ops, tail)

end

/-- Top-level: consume the entire byte list with fuel sized to its length.
Each successful op parse consumes ≥ 1 byte; we'd actually need at most
`bytes.length` rounds, but we double the budget for safety inside ifOp
recursion (each recursion replays the same `fuel` rather than computing
the residual). The doubled budget guarantees termination for any
Rúnar-emittable prefix. -/
def parseOps (bytes : List UInt8) : Except ParseError (List StackOp) :=
  match parseOpsFuel (bytes.length + 1) bytes false with
  | .error e => .error e
  | .ok (ops, tail) =>
      match tail with
      | []     => .ok ops
      | b :: _ => .error (.unknownOpcode b)

/-- ByteArray entry-point. -/
def parseScript (bs : ByteArray) : Except ParseError (List StackOp) :=
  parseOps bs.toList

/-! ## Per-op round-trip lemmas

Each lemma proves that decoding the bytes produced by `emitStackOpL`
recovers the original `StackOp`. The cases below cover every
`RunarEmittable` op shape. -/

theorem parseStackOp1?_dup_round_trip :
    parseStackOp1? 0x76 = some .dup := rfl

theorem parseStackOp1?_swap_round_trip :
    parseStackOp1? 0x7c = some .swap := rfl

theorem parseStackOp1?_nip_round_trip :
    parseStackOp1? 0x77 = some .nip := rfl

theorem parseStackOp1?_over_round_trip :
    parseStackOp1? 0x78 = some .over := rfl

theorem parseStackOp1?_rot_round_trip :
    parseStackOp1? 0x7b = some .rot := rfl

theorem parseStackOp1?_tuck_round_trip :
    parseStackOp1? 0x7d = some .tuck := rfl

theorem parseStackOp1?_drop_round_trip :
    parseStackOp1? 0x75 = some .drop := rfl

theorem parseStackOp1?_verify_round_trip :
    parseStackOp1? 0x69 = some (.opcode "OP_VERIFY") := rfl

theorem parseStackOp1?_negate_round_trip :
    parseStackOp1? 0x8f = some (.opcode "OP_NEGATE") := rfl

theorem parseStackOp1?_not_round_trip :
    parseStackOp1? 0x91 = some (.opcode "OP_NOT") := rfl

/-! ## RunarEmittable predicate

The main list-level set of StackOps the parser is required to recover.
Excludes:

* `.placeholder` / `.pushCodesepIndex` — both emit `OP_0`, which
  parses as `.push (.bigint 0)`. Inverse is ambiguous.
* `.opcode name` where `opcodeByName? name = none` — emit drops the
  byte silently, so no unique inverse.
* `.opcode "OP_IF"` / `"OP_ELSE"` / `"OP_ENDIF"` / `"OP_PICK"` /
  `"OP_ROLL"` — these bytes are reserved for the structural decoders
  (ifOp / pick / roll). Direct named usage clashes with reconstruction.

Standalone structural IF round-trip theorems below cover `.ifOp thn none`
and `.ifOp thn (some nonemptyElse)` when the branch bodies are already
`AreRunarEmittable`. IF remains outside this main predicate until the
list-level round-trip proof is refactored around a mutual op/list
predicate and a byte-length fuel invariant.
-/

/-- An opcode-string is "free" — i.e. parses back as `.opcode name`
rather than triggering a structural reconstruction.

Excluded reserved bytes:
* `0x63 OP_IF` / `0x67 OP_ELSE` / `0x68 OP_ENDIF` — control flow
  reserved for the structural ifOp decoder.
* `0x79 OP_PICK` / `0x7a OP_ROLL` — reserved for `.pick`/`.roll`
  reconstruction (push-then-byte form).
* `0x75 OP_DROP` / `0x76 OP_DUP` / `0x77 OP_NIP` /
  `0x78 OP_OVER` / `0x7b OP_ROT` / `0x7c OP_SWAP` / `0x7d OP_TUCK` —
  dedicated `StackOp` constructors are preferred by `parseStackOp1?`.
* `0x00 OP_0`, `0x4f OP_1NEGATE`, `0x51..0x60 OP_1..OP_16` — small-int
  push fast path collides with the named-opcode form.
* `0x4c..0x4e OP_PUSHDATA*`, `0x01..0x4b` literal-length push prefix
  bytes — only legal as push *headers*, never bare. -/
def isFreeOpcodeName (name : String) : Bool :=
  match opcodeByName? name with
  | none   => false
  | some b =>
      ! (b = 0x63 ∨ b = 0x67 ∨ b = 0x68 ∨ b = 0x79 ∨ b = 0x7a
        ∨ b = 0x75 ∨ b = 0x76 ∨ b = 0x77 ∨ b = 0x78 ∨ b = 0x7b
        ∨ b = 0x7c ∨ b = 0x7d
        ∨ b = 0x00 ∨ b = 0x4f
        ∨ b = 0x51 ∨ b = 0x52 ∨ b = 0x53 ∨ b = 0x54 ∨ b = 0x55
        ∨ b = 0x56 ∨ b = 0x57 ∨ b = 0x58 ∨ b = 0x59 ∨ b = 0x5a
        ∨ b = 0x5b ∨ b = 0x5c ∨ b = 0x5d ∨ b = 0x5e ∨ b = 0x5f
        ∨ b = 0x60
        ∨ b = 0x4c ∨ b = 0x4d ∨ b = 0x4e
        ∨ (0x01 ≤ b ∧ b ≤ 0x4b))

/-! The predicate enumerating which Stack ops the parser recovers
exactly from their emitted bytes.

Exclusions:
* `placeholder` / `pushCodesepIndex` → both emit `OP_0`; ambiguous inverse.
* `.opcode name` where `name` is not in the free table.
* `.push _` of any kind — collides with the small-int / push-data byte
  prefixes used by `roll`/`pick` reconstruction. The current parser is
  push-eager (it reads pushes first), so a `.push (.bigint 0)` emits
  exactly the same byte as `.placeholder` or `.pushCodesepIndex`, and
  a `.push (.bool true)` emits `0x51` which collides with the
  `OP_1`/`.push (.bigint 1)` decoding. To keep `RunarEmittable` a
  decidable round-trip target, all `.push` shapes are deferred to the
  Phase 7.B push-roundtrip work that pairs each push case with a
  list-level "next byte ≠ 0x79/0x7a" hypothesis.
* `.pickStruct d` — emits the same bytes as `.pick d`, and the parser
  always reconstructs as `.pick`. Excluded; users should write `.pick d`.
* `.ifOp` — covered by standalone per-op theorems
  `parseStackOpFuel_ifOp_none` and `parseStackOpFuel_ifOp_some_cons`
  below for branch bodies that are already `AreRunarEmittable`.
  It remains outside the main list predicate because lifting it into
  `RunarEmittable` requires a mutual op/list predicate and replacing
  the current top-level-op-count fuel invariant with a byte-length
  invariant. The ambiguous `.ifOp thn (some [])` shape stays excluded
  because it emits the same bytes as `.ifOp thn none`.

The main `RunarEmittable` predicate therefore covers:
* the 7 short-form stack ops (dup/swap/nip/over/rot/tuck/drop),
* `.roll d` and `.pick d` for `d ∈ [0..16]` (single-byte small-int
  push prefix; `roll`/`pick` reconstruction is unambiguous because no
  other op shape begins with a small-int push followed by `0x7a/0x79`),
* `.opcode name` where `name` is canonical (the table-inverse round-
  trips: `opcodeName? (opcodeByName? name).get! = some name`), free
  (no clash with structural / push / short-form bytes), and the
  consuming `parseStackOp1?` returns it directly.
-/

/-- Round-trip side condition for `.opcode name`: the canonical name
returned by `opcodeName?` for the encoded byte must agree with `name`.
Excludes the two aliases (`OP_FALSE → OP_0`, `OP_TRUE → OP_1`) — both
of those bytes are already excluded by `isFreeOpcodeName`, so the
predicate `isCanonicalFreeOpcodeName` is in fact equivalent to
`isFreeOpcodeName ∧ opcodeName? ∘ opcodeByName? = some`. -/
def isCanonicalFreeOpcodeName (name : String) : Bool :=
  match opcodeByName? name with
  | none   => false
  | some b =>
      isFreeOpcodeName name
        && (match opcodeName? b with
            | some name' => name = name'
            | none       => false)

/-- An explicit allowlist of opcode names recoverable by the parser.
We include 14 commonly-used opcodes whose bytes are not in the
reserved-for-structural-decoding set and whose canonical names match
their `opcodeByName?` lookups. The list intentionally excludes
`OP_FALSE`/`OP_TRUE` aliases (they decode as small-int pushes, not
named opcodes) and the small-int / structural / short-form bytes
listed in `isFreeOpcodeName`'s exclusion table. -/
def isAllowedOpcodeName (name : String) : Bool :=
  name = "OP_VERIFY" || name = "OP_NEGATE" || name = "OP_NOT"
    || name = "OP_ADD" || name = "OP_SUB" || name = "OP_MUL"
    || name = "OP_EQUAL" || name = "OP_EQUALVERIFY"
    || name = "OP_HASH160" || name = "OP_SHA256"
    || name = "OP_CHECKSIG" || name = "OP_CHECKSIGVERIFY"
    || name = "OP_CAT" || name = "OP_SPLIT"

/-- The list-level emittability predicate, threaded as a single
inductive (no mutual recursion needed for the current covered subset
since `.ifOp` is excluded). -/
inductive RunarEmittable : StackOp → Prop where
  | dup        : RunarEmittable .dup
  | swap       : RunarEmittable .swap
  | nip        : RunarEmittable .nip
  | over       : RunarEmittable .over
  | rot        : RunarEmittable .rot
  | tuck       : RunarEmittable .tuck
  | drop       : RunarEmittable .drop
  /-- `.roll d` is recoverable for small depths `d ∈ [1..16]`. (The
      `d = 0` case collides with `.push (.bigint 0)` followed by
      `OP_ROLL`, but `roll 0` is not a useful op in practice.) -/
  | roll       (d : Nat) (hd : 1 ≤ d ∧ d ≤ 16) : RunarEmittable (.roll d)
  /-- `.pick d` for the same small-depth range as `.roll`. -/
  | pick       (d : Nat) (hd : 1 ≤ d ∧ d ≤ 16) : RunarEmittable (.pick d)
  /-- A concrete opcode by name, restricted to the allowlist. The
      allowlist is enumerated in `isAllowedOpcodeName` and covers 14
      commonly-used opcodes whose round-trip lemmas are proved by
      `rfl`. Future extensions should add to both the allowlist and
      the per-name `parseStackOpFuel_OP_*` lemmas. -/
  | opcode (name : String) (h : isAllowedOpcodeName name = true) :
      RunarEmittable (.opcode name)

inductive AreRunarEmittable : List StackOp → Prop where
  | nil  : AreRunarEmittable []
  | cons (op : StackOp) (rest : List StackOp)
      (hOp : RunarEmittable op) (hRest : AreRunarEmittable rest) :
      AreRunarEmittable (op :: rest)

/-! ### F1 decidability for `RunarEmittable` / `AreRunarEmittable`

Both predicates are inductively defined with a small fixed shape. The
Boolean checkers `runarEmittableBool` / `areRunarEmittableBool` walk the
same shape and the `_iff` lemmas establish propositional equivalence. -/

def runarEmittableBool : StackOp → Bool
  | .dup => true
  | .swap => true
  | .nip => true
  | .over => true
  | .rot => true
  | .tuck => true
  | .drop => true
  | .roll d => decide (1 ≤ d ∧ d ≤ 16)
  | .pick d => decide (1 ≤ d ∧ d ≤ 16)
  | .opcode name => isAllowedOpcodeName name
  | _ => false

theorem runarEmittableBool_iff_RunarEmittable :
    ∀ (op : StackOp), runarEmittableBool op = true ↔ RunarEmittable op := by
  intro op
  cases op
  case dup => exact ⟨fun _ => .dup, fun _ => rfl⟩
  case swap => exact ⟨fun _ => .swap, fun _ => rfl⟩
  case nip => exact ⟨fun _ => .nip, fun _ => rfl⟩
  case over => exact ⟨fun _ => .over, fun _ => rfl⟩
  case rot => exact ⟨fun _ => .rot, fun _ => rfl⟩
  case tuck => exact ⟨fun _ => .tuck, fun _ => rfl⟩
  case drop => exact ⟨fun _ => .drop, fun _ => rfl⟩
  case roll d =>
    constructor
    · intro h
      unfold runarEmittableBool at h
      exact .roll d (of_decide_eq_true h)
    · intro h
      cases h with
      | roll _ hd => unfold runarEmittableBool; exact decide_eq_true hd
  case pick d =>
    constructor
    · intro h
      unfold runarEmittableBool at h
      exact .pick d (of_decide_eq_true h)
    · intro h
      cases h with
      | pick _ hd => unfold runarEmittableBool; exact decide_eq_true hd
  case opcode name =>
    constructor
    · intro h
      unfold runarEmittableBool at h
      exact .opcode name h
    · intro h
      cases h with
      | opcode _ hAllow => unfold runarEmittableBool; exact hAllow
  case push v =>
    constructor
    · intro h; simp [runarEmittableBool] at h
    · intro h; cases h
  case pickStruct d =>
    constructor
    · intro h; simp [runarEmittableBool] at h
    · intro h; cases h
  case ifOp t e =>
    constructor
    · intro h; simp [runarEmittableBool] at h
    · intro h; cases h
  case placeholder i n =>
    constructor
    · intro h; simp [runarEmittableBool] at h
    · intro h; cases h
  case pushCodesepIndex =>
    constructor
    · intro h; simp [runarEmittableBool] at h
    · intro h; cases h
  case rawBytes b =>
    constructor
    · intro h; simp [runarEmittableBool] at h
    · intro h; cases h

instance runarEmittable_decidable (op : StackOp) : Decidable (RunarEmittable op) :=
  decidable_of_iff (runarEmittableBool op = true)
    (runarEmittableBool_iff_RunarEmittable op)

def areRunarEmittableBool : List StackOp → Bool
  | [] => true
  | op :: rest => runarEmittableBool op && areRunarEmittableBool rest

theorem areRunarEmittableBool_iff_AreRunarEmittable :
    ∀ (ops : List StackOp),
      areRunarEmittableBool ops = true ↔ AreRunarEmittable ops
  | [] => ⟨fun _ => .nil, fun _ => rfl⟩
  | op :: rest => by
    unfold areRunarEmittableBool
    rw [Bool.and_eq_true]
    constructor
    · intro ⟨hHead, hRest⟩
      exact .cons op rest
        ((runarEmittableBool_iff_RunarEmittable op).mp hHead)
        ((areRunarEmittableBool_iff_AreRunarEmittable rest).mp hRest)
    · intro h
      cases h with
      | cons _ _ hOp hRest =>
          exact ⟨(runarEmittableBool_iff_RunarEmittable op).mpr hOp,
                 (areRunarEmittableBool_iff_AreRunarEmittable rest).mpr hRest⟩

instance areRunarEmittable_decidable (ops : List StackOp) :
    Decidable (AreRunarEmittable ops) :=
  decidable_of_iff (areRunarEmittableBool ops = true)
    (areRunarEmittableBool_iff_AreRunarEmittable ops)

/-! ## Per-shape round-trip lemmas (list-level)

Each lemma proves `parseStackOpFuel (emitStackOpL op ++ rest)` returns
`(op, rest)` for one specific `op` shape. These compose into the
master `parseOps_emit_round_trip`.

We use `unfold` + `rfl` for the simple short-form opcodes; roll and
pick need structural arguments. Structural IF is handled later by
standalone per-op theorems rather than by the main predicate.
-/

theorem parseStackOpFuel_dup (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL .dup ++ rest) = .ok (.dup, rest) := by
  rfl

theorem parseStackOpFuel_swap (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL .swap ++ rest) = .ok (.swap, rest) := by
  rfl

theorem parseStackOpFuel_nip (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL .nip ++ rest) = .ok (.nip, rest) := by
  rfl

theorem parseStackOpFuel_over (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL .over ++ rest) = .ok (.over, rest) := by
  rfl

theorem parseStackOpFuel_rot (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL .rot ++ rest) = .ok (.rot, rest) := by
  rfl

theorem parseStackOpFuel_tuck (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL .tuck ++ rest) = .ok (.tuck, rest) := by
  rfl

theorem parseStackOpFuel_drop (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL .drop ++ rest) = .ok (.drop, rest) := by
  rfl

/-! ### `push (.bigint n)` for the small-int fast path -/

/-- The next-byte sentinel: a byte list does NOT begin with `0x7a` or
`0x79` (the `OP_PICK` / `OP_ROLL` reserved bytes). When `rest` satisfies
this predicate, a leading bigint-push parses cleanly to
`.push (.bigint i)` rather than collapsing into a `.roll`/`.pick`. -/
def restNotPickOrRoll : List UInt8 → Prop
  | []          => True
  | b :: _      => b ≠ 0x7a ∧ b ≠ 0x79

/-- A leading bigint-push of 0 over an empty tail parses cleanly to
`.push (.bigint 0)`. -/
theorem parseStackOpFuel_push_bigint_zero_nil (fuel : Nat) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.push (.bigint 0)) ++ [])
      = .ok (.push (.bigint 0), []) := by
  rfl

/-- A leading bigint-push of -1 over an empty tail. -/
theorem parseStackOpFuel_push_bigint_negOne_nil (fuel : Nat) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.push (.bigint (-1))) ++ [])
      = .ok (.push (.bigint (-1)), []) := by
  rfl

/-- A leading bigint-push followed by a non-pick / non-roll byte
(specifically: `OP_DUP` 0x76 chosen as a witness) parses cleanly to
`.push (.bigint 0)` then continues with the dup. -/
theorem parseStackOpFuel_push_bigint_zero_cons_dup (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1)
        (emitStackOpL (.push (.bigint 0)) ++ (0x76 :: rest))
      = .ok (.push (.bigint 0), 0x76 :: rest) := by
  rfl

theorem parseStackOpFuel_push_bigint_one_nil (fuel : Nat) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.push (.bigint 1)) ++ [])
      = .ok (.push (.bigint 1), []) := by
  rfl

theorem parseStackOpFuel_push_bigint_sixteen_nil (fuel : Nat) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.push (.bigint 16)) ++ [])
      = .ok (.push (.bigint 16), []) := by
  rfl

/-! ### `roll d` / `pick d` — small-int depth case

Each `d ∈ [1..16]` is encoded as a single byte (`0x50 + d`) push prefix
followed by `0x7a` (roll) or `0x79` (pick). The parser sees the small-
int push, peeks at the next byte, and reconstructs the structured
`.roll d` / `.pick d`.

We prove one lemma per small depth (1 through 16) by `rfl`: each case
unfolds to a pure value equation on a 2-byte head plus an arbitrary
tail. -/

theorem parseStackOpFuel_roll_1 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 1) ++ rest)
      = .ok (.roll 1, rest) := rfl

theorem parseStackOpFuel_roll_2 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 2) ++ rest)
      = .ok (.roll 2, rest) := rfl

theorem parseStackOpFuel_roll_3 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 3) ++ rest)
      = .ok (.roll 3, rest) := rfl

theorem parseStackOpFuel_roll_4 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 4) ++ rest)
      = .ok (.roll 4, rest) := rfl

theorem parseStackOpFuel_roll_5 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 5) ++ rest)
      = .ok (.roll 5, rest) := rfl

theorem parseStackOpFuel_roll_6 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 6) ++ rest)
      = .ok (.roll 6, rest) := rfl

theorem parseStackOpFuel_roll_7 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 7) ++ rest)
      = .ok (.roll 7, rest) := rfl

theorem parseStackOpFuel_roll_8 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 8) ++ rest)
      = .ok (.roll 8, rest) := rfl

theorem parseStackOpFuel_roll_9 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 9) ++ rest)
      = .ok (.roll 9, rest) := rfl

theorem parseStackOpFuel_roll_10 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 10) ++ rest)
      = .ok (.roll 10, rest) := rfl

theorem parseStackOpFuel_roll_11 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 11) ++ rest)
      = .ok (.roll 11, rest) := rfl

theorem parseStackOpFuel_roll_12 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 12) ++ rest)
      = .ok (.roll 12, rest) := rfl

theorem parseStackOpFuel_roll_13 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 13) ++ rest)
      = .ok (.roll 13, rest) := rfl

theorem parseStackOpFuel_roll_14 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 14) ++ rest)
      = .ok (.roll 14, rest) := rfl

theorem parseStackOpFuel_roll_15 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 15) ++ rest)
      = .ok (.roll 15, rest) := rfl

theorem parseStackOpFuel_roll_16 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll 16) ++ rest)
      = .ok (.roll 16, rest) := rfl

theorem parseStackOpFuel_pick_1 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 1) ++ rest)
      = .ok (.pick 1, rest) := rfl

theorem parseStackOpFuel_pick_2 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 2) ++ rest)
      = .ok (.pick 2, rest) := rfl

theorem parseStackOpFuel_pick_3 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 3) ++ rest)
      = .ok (.pick 3, rest) := rfl

theorem parseStackOpFuel_pick_4 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 4) ++ rest)
      = .ok (.pick 4, rest) := rfl

theorem parseStackOpFuel_pick_5 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 5) ++ rest)
      = .ok (.pick 5, rest) := rfl

theorem parseStackOpFuel_pick_6 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 6) ++ rest)
      = .ok (.pick 6, rest) := rfl

theorem parseStackOpFuel_pick_7 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 7) ++ rest)
      = .ok (.pick 7, rest) := rfl

theorem parseStackOpFuel_pick_8 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 8) ++ rest)
      = .ok (.pick 8, rest) := rfl

theorem parseStackOpFuel_pick_9 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 9) ++ rest)
      = .ok (.pick 9, rest) := rfl

theorem parseStackOpFuel_pick_10 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 10) ++ rest)
      = .ok (.pick 10, rest) := rfl

theorem parseStackOpFuel_pick_11 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 11) ++ rest)
      = .ok (.pick 11, rest) := rfl

theorem parseStackOpFuel_pick_12 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 12) ++ rest)
      = .ok (.pick 12, rest) := rfl

theorem parseStackOpFuel_pick_13 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 13) ++ rest)
      = .ok (.pick 13, rest) := rfl

theorem parseStackOpFuel_pick_14 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 14) ++ rest)
      = .ok (.pick 14, rest) := rfl

theorem parseStackOpFuel_pick_15 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 15) ++ rest)
      = .ok (.pick 15, rest) := rfl

theorem parseStackOpFuel_pick_16 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick 16) ++ rest)
      = .ok (.pick 16, rest) := rfl

/-- `roll d` for `d ∈ [1..16]` round-trips. The proof is a 16-way
case-split on `d` plus the per-`d` `rfl` lemmas above. -/
theorem parseStackOpFuel_roll_smallD (fuel : Nat) (rest : List UInt8)
    (d : Nat) (hd : 1 ≤ d ∧ d ≤ 16) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.roll d) ++ rest)
      = .ok (.roll d, rest) := by
  obtain ⟨h1, h16⟩ := hd
  -- Repeatedly chop the lowest constructor off `d`.
  rcases d with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | d
  · exact absurd h1 (by omega)
  · exact parseStackOpFuel_roll_1 fuel rest
  · exact parseStackOpFuel_roll_2 fuel rest
  · exact parseStackOpFuel_roll_3 fuel rest
  · exact parseStackOpFuel_roll_4 fuel rest
  · exact parseStackOpFuel_roll_5 fuel rest
  · exact parseStackOpFuel_roll_6 fuel rest
  · exact parseStackOpFuel_roll_7 fuel rest
  · exact parseStackOpFuel_roll_8 fuel rest
  · exact parseStackOpFuel_roll_9 fuel rest
  · exact parseStackOpFuel_roll_10 fuel rest
  · exact parseStackOpFuel_roll_11 fuel rest
  · exact parseStackOpFuel_roll_12 fuel rest
  · exact parseStackOpFuel_roll_13 fuel rest
  · exact parseStackOpFuel_roll_14 fuel rest
  · exact parseStackOpFuel_roll_15 fuel rest
  · exact parseStackOpFuel_roll_16 fuel rest
  · exact absurd h16 (by omega)

theorem parseStackOpFuel_pick_smallD (fuel : Nat) (rest : List UInt8)
    (d : Nat) (hd : 1 ≤ d ∧ d ≤ 16) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.pick d) ++ rest)
      = .ok (.pick d, rest) := by
  obtain ⟨h1, h16⟩ := hd
  rcases d with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | d
  · exact absurd h1 (by omega)
  · exact parseStackOpFuel_pick_1 fuel rest
  · exact parseStackOpFuel_pick_2 fuel rest
  · exact parseStackOpFuel_pick_3 fuel rest
  · exact parseStackOpFuel_pick_4 fuel rest
  · exact parseStackOpFuel_pick_5 fuel rest
  · exact parseStackOpFuel_pick_6 fuel rest
  · exact parseStackOpFuel_pick_7 fuel rest
  · exact parseStackOpFuel_pick_8 fuel rest
  · exact parseStackOpFuel_pick_9 fuel rest
  · exact parseStackOpFuel_pick_10 fuel rest
  · exact parseStackOpFuel_pick_11 fuel rest
  · exact parseStackOpFuel_pick_12 fuel rest
  · exact parseStackOpFuel_pick_13 fuel rest
  · exact parseStackOpFuel_pick_14 fuel rest
  · exact parseStackOpFuel_pick_15 fuel rest
  · exact parseStackOpFuel_pick_16 fuel rest
  · exact absurd h16 (by omega)

/-! ### Free-named opcodes round-trip

For a `.opcode name` whose canonical inverse `opcodeName? ∘ opcodeByName? = some name`
and that is in the "free" subset (no clash with structural / push /
short-form bytes), the parser recovers exactly `.opcode name`.

The proof is a single `parseStackOpFuel` unfold: the encoded byte
`b = (opcodeByName? name).get!` is not a push prefix (`parsePushVal?
(b :: rest) = none` is forced by the free-byte constraint), it is not
`OP_IF` (also forced by free-byte), and `parseStackOp1? b` returns
`.opcode (opcodeName? b).get!` for free bytes. The final `name = opcodeName? b`
equation is the canonical-name hypothesis. -/

/-- Step lemma: under `isCanonicalFreeOpcodeName name`, the byte
returned by `opcodeByName? name` is none of the small-int / structural /
short-form bytes excluded by `isFreeOpcodeName`. The proof is by
unfolding `isCanonicalFreeOpcodeName` and case analysis. -/
private theorem opcodeByName?_of_canonical_free (name : String)
    (h : isCanonicalFreeOpcodeName name = true) :
    ∃ b, opcodeByName? name = some b
       ∧ opcodeName? b = some name
       ∧ isFreeOpcodeName name = true := by
  unfold isCanonicalFreeOpcodeName at h
  match hLookup : opcodeByName? name with
  | none =>
      rw [hLookup] at h
      simp at h
  | some b =>
      rw [hLookup] at h
      simp at h
      obtain ⟨hFree, hName⟩ := h
      match hN : opcodeName? b with
      | none =>
          rw [hN] at hName
          simp at hName
      | some name' =>
          rw [hN] at hName
          simp at hName
          refine ⟨b, rfl, ?_, hFree⟩
          rw [hN, hName]

/-! ### Free-opcode byte properties

For any byte `b` that's the encoding of a free opcode, the parser's
push-fast-path returns `none`, the byte is not `OP_IF` (0x63), and
`parseStackOp1?` returns `.opcode (canonical name)` directly. -/

/-- A byte `b` is "free" (a non-reserved single-byte opcode) iff it's
the codomain of an `isFreeOpcodeName` name. Equivalently: it is not in
the reserved set of bytes excluded by `isFreeOpcodeName`. -/
def isFreeByte (b : UInt8) : Bool :=
  ! (b = 0x63 ∨ b = 0x67 ∨ b = 0x68 ∨ b = 0x79 ∨ b = 0x7a
    ∨ b = 0x75 ∨ b = 0x76 ∨ b = 0x77 ∨ b = 0x78 ∨ b = 0x7b
    ∨ b = 0x7c ∨ b = 0x7d
    ∨ b = 0x00 ∨ b = 0x4f
    ∨ b = 0x51 ∨ b = 0x52 ∨ b = 0x53 ∨ b = 0x54 ∨ b = 0x55
    ∨ b = 0x56 ∨ b = 0x57 ∨ b = 0x58 ∨ b = 0x59 ∨ b = 0x5a
    ∨ b = 0x5b ∨ b = 0x5c ∨ b = 0x5d ∨ b = 0x5e ∨ b = 0x5f
    ∨ b = 0x60
    ∨ b = 0x4c ∨ b = 0x4d ∨ b = 0x4e
    ∨ (0x01 ≤ b ∧ b ≤ 0x4b))

/-- If `isFreeOpcodeName name = true` and `opcodeByName? name = some b`,
then `b` is a free byte. -/
private theorem isFreeByte_of_isFreeOpcodeName (name : String) (b : UInt8)
    (hFree : isFreeOpcodeName name = true) (hLookup : opcodeByName? name = some b) :
    isFreeByte b = true := by
  unfold isFreeOpcodeName at hFree
  rw [hLookup] at hFree
  unfold isFreeByte
  exact hFree

/-! Rather than work via `isFreeByte` predicate (which requires tedious
case-decomposition through `parsePushVal?`'s nested ifs), prove
`parsePushVal?` returns `none` for the *specific* byte set we care
about by enumeration. For our `RunarEmittable` `.opcode` set, we
restrict to a manageable subset of bytes (proven case-by-case via rfl). -/

/-- For each canonical free name, `parseStackOp1?` returns the named
opcode. Proved case-by-case for a fixed list of canonical names. -/
private theorem parseStackOp1?_VERIFY :
    parseStackOp1? 0x69 = some (.opcode "OP_VERIFY") := rfl

private theorem parseStackOp1?_NEGATE :
    parseStackOp1? 0x8f = some (.opcode "OP_NEGATE") := rfl

private theorem parseStackOp1?_NOT :
    parseStackOp1? 0x91 = some (.opcode "OP_NOT") := rfl

private theorem parseStackOp1?_ADD :
    parseStackOp1? 0x93 = some (.opcode "OP_ADD") := rfl

private theorem parseStackOp1?_SUB :
    parseStackOp1? 0x94 = some (.opcode "OP_SUB") := rfl

private theorem parseStackOp1?_MUL :
    parseStackOp1? 0x95 = some (.opcode "OP_MUL") := rfl

private theorem parseStackOp1?_EQUAL :
    parseStackOp1? 0x87 = some (.opcode "OP_EQUAL") := rfl

private theorem parseStackOp1?_EQUALVERIFY :
    parseStackOp1? 0x88 = some (.opcode "OP_EQUALVERIFY") := rfl

private theorem parseStackOp1?_HASH160 :
    parseStackOp1? 0xa9 = some (.opcode "OP_HASH160") := rfl

private theorem parseStackOp1?_SHA256 :
    parseStackOp1? 0xa8 = some (.opcode "OP_SHA256") := rfl

private theorem parseStackOp1?_CHECKSIG :
    parseStackOp1? 0xac = some (.opcode "OP_CHECKSIG") := rfl

private theorem parseStackOp1?_CHECKSIGVERIFY :
    parseStackOp1? 0xad = some (.opcode "OP_CHECKSIGVERIFY") := rfl

private theorem parseStackOp1?_CAT :
    parseStackOp1? 0x7e = some (.opcode "OP_CAT") := rfl

private theorem parseStackOp1?_SPLIT :
    parseStackOp1? 0x7f = some (.opcode "OP_SPLIT") := rfl

/-- For a fixed list of free opcode bytes, the parsePushVal?-then-IF
fast-path returns the structured `.opcode` directly. We prove these
by `rfl` (the parseStackOpFuel definition reduces). -/
theorem parseStackOpFuel_OP_VERIFY (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_VERIFY") ++ rest)
      = .ok (.opcode "OP_VERIFY", rest) := rfl

theorem parseStackOpFuel_OP_NEGATE (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_NEGATE") ++ rest)
      = .ok (.opcode "OP_NEGATE", rest) := rfl

theorem parseStackOpFuel_OP_NOT (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_NOT") ++ rest)
      = .ok (.opcode "OP_NOT", rest) := rfl

theorem parseStackOpFuel_OP_ADD (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_ADD") ++ rest)
      = .ok (.opcode "OP_ADD", rest) := rfl

theorem parseStackOpFuel_OP_SUB (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_SUB") ++ rest)
      = .ok (.opcode "OP_SUB", rest) := rfl

theorem parseStackOpFuel_OP_MUL (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_MUL") ++ rest)
      = .ok (.opcode "OP_MUL", rest) := rfl

theorem parseStackOpFuel_OP_EQUAL (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_EQUAL") ++ rest)
      = .ok (.opcode "OP_EQUAL", rest) := rfl

theorem parseStackOpFuel_OP_EQUALVERIFY (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_EQUALVERIFY") ++ rest)
      = .ok (.opcode "OP_EQUALVERIFY", rest) := rfl

theorem parseStackOpFuel_OP_HASH160 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_HASH160") ++ rest)
      = .ok (.opcode "OP_HASH160", rest) := rfl

theorem parseStackOpFuel_OP_SHA256 (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_SHA256") ++ rest)
      = .ok (.opcode "OP_SHA256", rest) := rfl

theorem parseStackOpFuel_OP_CHECKSIG (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_CHECKSIG") ++ rest)
      = .ok (.opcode "OP_CHECKSIG", rest) := rfl

theorem parseStackOpFuel_OP_CHECKSIGVERIFY (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_CHECKSIGVERIFY") ++ rest)
      = .ok (.opcode "OP_CHECKSIGVERIFY", rest) := rfl

theorem parseStackOpFuel_OP_CAT (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_CAT") ++ rest)
      = .ok (.opcode "OP_CAT", rest) := rfl

theorem parseStackOpFuel_OP_SPLIT (fuel : Nat) (rest : List UInt8) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode "OP_SPLIT") ++ rest)
      = .ok (.opcode "OP_SPLIT", rest) := rfl

/-- Allowed opcode names round-trip. Dispatches on the 14-way
disjunction in `isAllowedOpcodeName`. -/
theorem parseStackOpFuel_opcode_allowed (fuel : Nat) (rest : List UInt8)
    (name : String) (h : isAllowedOpcodeName name = true) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.opcode name) ++ rest)
      = .ok (.opcode name, rest) := by
  unfold isAllowedOpcodeName at h
  -- isAllowedOpcodeName is a Bool with 14 || disjuncts.
  -- Decompose via Bool.or_eq_true then case split.
  simp only [Bool.or_eq_true, decide_eq_true_eq] at h
  -- After simp, h : name = "..." ∨ ... ∨ name = "..." (14 disjuncts)
  -- Process each of the 14 cases.
  -- Use a series of rcases with a left-associated pattern.
  obtain h1 | h1 := h
  obtain h1 | h1 := h1
  obtain h1 | h1 := h1
  obtain h1 | h1 := h1
  obtain h1 | h1 := h1
  obtain h1 | h1 := h1
  obtain h1 | h1 := h1
  obtain h1 | h1 := h1
  obtain h1 | h1 := h1
  obtain h1 | h1 := h1
  obtain h1 | h1 := h1
  obtain h1 | h1 := h1
  obtain h1 | h1 := h1
  all_goals (subst h1; first
    | exact parseStackOpFuel_OP_VERIFY fuel rest
    | exact parseStackOpFuel_OP_NEGATE fuel rest
    | exact parseStackOpFuel_OP_NOT fuel rest
    | exact parseStackOpFuel_OP_ADD fuel rest
    | exact parseStackOpFuel_OP_SUB fuel rest
    | exact parseStackOpFuel_OP_MUL fuel rest
    | exact parseStackOpFuel_OP_EQUAL fuel rest
    | exact parseStackOpFuel_OP_EQUALVERIFY fuel rest
    | exact parseStackOpFuel_OP_HASH160 fuel rest
    | exact parseStackOpFuel_OP_SHA256 fuel rest
    | exact parseStackOpFuel_OP_CHECKSIG fuel rest
    | exact parseStackOpFuel_OP_CHECKSIGVERIFY fuel rest
    | exact parseStackOpFuel_OP_CAT fuel rest
    | exact parseStackOpFuel_OP_SPLIT fuel rest)

/-! ## Per-op round-trip — single op via `RunarEmittable` -/

/-- Single-op round-trip: for any `RunarEmittable` op, parsing the
emitted bytes followed by an arbitrary tail returns the op and the
tail. Fuel of `fuel + 1` is sufficient. -/
theorem parseStackOp_emit_round_trip (fuel : Nat) (op : StackOp) (rest : List UInt8)
    (hOp : RunarEmittable op) :
    parseStackOpFuel (fuel + 1) (emitStackOpL op ++ rest) = .ok (op, rest) := by
  cases hOp with
  | dup       => exact parseStackOpFuel_dup fuel rest
  | swap      => exact parseStackOpFuel_swap fuel rest
  | nip       => exact parseStackOpFuel_nip fuel rest
  | over      => exact parseStackOpFuel_over fuel rest
  | rot       => exact parseStackOpFuel_rot fuel rest
  | tuck      => exact parseStackOpFuel_tuck fuel rest
  | drop      => exact parseStackOpFuel_drop fuel rest
  | roll d hd => exact parseStackOpFuel_roll_smallD fuel rest d hd
  | pick d hd => exact parseStackOpFuel_pick_smallD fuel rest d hd
  | opcode name h => exact parseStackOpFuel_opcode_allowed fuel rest name h

/-! ## List round-trip via `parseOpsFuel`

The list-level round-trip threads `parseOpsFuel` through each op.
We need: each op consumes ≥ 1 byte (so the same `fuel` is enough for
the recursion), and the list-level `stopAtElse = false` flag never
fires inside `RunarEmittable` (no OP_ELSE/ENDIF bytes are emitted by
the allowed ops because `.ifOp` is excluded).

The proof is by induction on the op list. -/

/-! Each `RunarEmittable` op produces at least one byte. Phrased
as: `emitStackOpL op = b :: tail` for some `b, tail`. -/
theorem emitStackOpL_cons_of_RunarEmittable (op : StackOp)
    (hOp : RunarEmittable op) :
    ∃ b tail, emitStackOpL op = b :: tail := by
  cases hOp with
  | dup => exact ⟨0x76, [], rfl⟩
  | swap => exact ⟨0x7c, [], rfl⟩
  | nip => exact ⟨0x77, [], rfl⟩
  | over => exact ⟨0x78, [], rfl⟩
  | rot => exact ⟨0x7b, [], rfl⟩
  | tuck => exact ⟨0x7d, [], rfl⟩
  | drop => exact ⟨0x75, [], rfl⟩
  | roll d hd =>
      obtain ⟨h1, h16⟩ := hd
      rcases d with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | d
      · exact absurd h1 (by omega)
      · exact ⟨0x51, [0x7a], rfl⟩
      · exact ⟨0x52, [0x7a], rfl⟩
      · exact ⟨0x53, [0x7a], rfl⟩
      · exact ⟨0x54, [0x7a], rfl⟩
      · exact ⟨0x55, [0x7a], rfl⟩
      · exact ⟨0x56, [0x7a], rfl⟩
      · exact ⟨0x57, [0x7a], rfl⟩
      · exact ⟨0x58, [0x7a], rfl⟩
      · exact ⟨0x59, [0x7a], rfl⟩
      · exact ⟨0x5a, [0x7a], rfl⟩
      · exact ⟨0x5b, [0x7a], rfl⟩
      · exact ⟨0x5c, [0x7a], rfl⟩
      · exact ⟨0x5d, [0x7a], rfl⟩
      · exact ⟨0x5e, [0x7a], rfl⟩
      · exact ⟨0x5f, [0x7a], rfl⟩
      · exact ⟨0x60, [0x7a], rfl⟩
      · exact absurd h16 (by omega)
  | pick d hd =>
      obtain ⟨h1, h16⟩ := hd
      rcases d with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | d
      · exact absurd h1 (by omega)
      · exact ⟨0x51, [0x79], rfl⟩
      · exact ⟨0x52, [0x79], rfl⟩
      · exact ⟨0x53, [0x79], rfl⟩
      · exact ⟨0x54, [0x79], rfl⟩
      · exact ⟨0x55, [0x79], rfl⟩
      · exact ⟨0x56, [0x79], rfl⟩
      · exact ⟨0x57, [0x79], rfl⟩
      · exact ⟨0x58, [0x79], rfl⟩
      · exact ⟨0x59, [0x79], rfl⟩
      · exact ⟨0x5a, [0x79], rfl⟩
      · exact ⟨0x5b, [0x79], rfl⟩
      · exact ⟨0x5c, [0x79], rfl⟩
      · exact ⟨0x5d, [0x79], rfl⟩
      · exact ⟨0x5e, [0x79], rfl⟩
      · exact ⟨0x5f, [0x79], rfl⟩
      · exact ⟨0x60, [0x79], rfl⟩
      · exact absurd h16 (by omega)
  | opcode name hAllow =>
      unfold isAllowedOpcodeName at hAllow
      simp only [Bool.or_eq_true, decide_eq_true_eq] at hAllow
      obtain hN | hN := hAllow
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      all_goals (subst hN; first
        | exact ⟨0x69, [], rfl⟩  -- VERIFY
        | exact ⟨0x8f, [], rfl⟩  -- NEGATE
        | exact ⟨0x91, [], rfl⟩  -- NOT
        | exact ⟨0x93, [], rfl⟩  -- ADD
        | exact ⟨0x94, [], rfl⟩  -- SUB
        | exact ⟨0x95, [], rfl⟩  -- MUL
        | exact ⟨0x87, [], rfl⟩  -- EQUAL
        | exact ⟨0x88, [], rfl⟩  -- EQUALVERIFY
        | exact ⟨0xa9, [], rfl⟩  -- HASH160
        | exact ⟨0xa8, [], rfl⟩  -- SHA256
        | exact ⟨0xac, [], rfl⟩  -- CHECKSIG
        | exact ⟨0xad, [], rfl⟩  -- CHECKSIGVERIFY
        | exact ⟨0x7e, [], rfl⟩  -- CAT
        | exact ⟨0x7f, [], rfl⟩) -- SPLIT

/-! Helper: a single step lemma for `parseOpsFuel` when the head bytes
parse cleanly. Avoids unfolding parseOpsFuel directly. -/

/-- One-step unfolding of `parseOpsFuel` when bytes are non-empty and
`stopAtElse = false`. The `match` reduces to a simple sequence of
`parseStackOpFuel` then recursive `parseOpsFuel`. -/
theorem parseOpsFuel_cons_unfold (fuel : Nat) (b : UInt8) (rest : List UInt8) :
    parseOpsFuel (fuel + 1) (b :: rest) false
    = match parseStackOpFuel fuel (b :: rest) with
      | .error e => .error e
      | .ok (op, rest') =>
          match parseOpsFuel fuel rest' false with
          | .error e => .error e
          | .ok (ops, tail) => .ok (op :: ops, tail) := by
  rfl

/-- For any `AreRunarEmittable` list, the parser-level `parseOpsFuel`
returns the original list with empty tail when run on the emitted
bytes, provided the fuel is sufficiently large. The fuel `n + 1`
suffices when `n ≥ ops.length`. -/
theorem parseOpsFuel_emit_round_trip (ops : List StackOp)
    (hOps : AreRunarEmittable ops) (fuel : Nat) (hFuel : ops.length ≤ fuel) :
    parseOpsFuel (fuel + 1) (emitOpsL ops) false = .ok (ops, []) := by
  induction ops generalizing fuel with
  | nil => rfl
  | cons op rest ih =>
      cases hOps with
      | cons _ _ hOp hRest =>
          -- fuel ≥ 1 since ops.length ≥ 1.
          have hFuelGe1 : 1 ≤ fuel := by
            simp [List.length] at hFuel; omega
          obtain ⟨fuel', rfl⟩ : ∃ k, fuel = k + 1 := ⟨fuel - 1, by omega⟩
          -- The emitted bytes start with at least one byte (head of emitStackOpL op).
          obtain ⟨b, opTail, hOpHead⟩ := emitStackOpL_cons_of_RunarEmittable op hOp
          -- `emitOpsL (op :: rest)` = `emitStackOpL op ++ emitOpsL rest`
          --                       = `(b :: opTail) ++ emitOpsL rest`
          --                       = `b :: (opTail ++ emitOpsL rest)`
          have hAllBytes : emitOpsL (op :: rest)
              = b :: (opTail ++ emitOpsL rest) := by
            show emitStackOpL op ++ emitOpsL rest = _
            rw [hOpHead]
            rfl
          rw [hAllBytes]
          -- Apply the one-step unfold.
          rw [parseOpsFuel_cons_unfold]
          -- Now the goal has `parseStackOpFuel (fuel' + 1) (b :: opTail ++ emitOpsL rest)`.
          -- We rewrite back to `emitStackOpL op ++ emitOpsL rest`.
          have hHeadBack : b :: (opTail ++ emitOpsL rest)
              = emitStackOpL op ++ emitOpsL rest := by
            rw [hOpHead]
            rfl
          rw [hHeadBack]
          -- Apply the per-op round-trip lemma; this gives us
          -- `match .ok (op, emitOpsL rest) with ...` which dsimp reduces.
          rw [parseStackOp_emit_round_trip fuel' op (emitOpsL rest) hOp]
          dsimp only
          -- Now the goal is `match parseOpsFuel (fuel' + 1) (emitOpsL rest) false with ...`.
          -- Apply the inductive hypothesis.
          have hRestLen : rest.length ≤ fuel' := by
            simp [List.length] at hFuel; omega
          rw [ih hRest fuel' hRestLen]

/-! ## `parseOps` (top-level fuel-budget) round-trip

`parseOps` chooses fuel `bytes.length + 1`, which is always enough for
any `RunarEmittable` op list because each op consumes ≥ 1 byte. -/

/-- The number of bytes emitted is at least the op-count for any
`AreRunarEmittable` list. This justifies the fuel choice in `parseOps`. -/
theorem emitOpsL_length_ge_ops_length (ops : List StackOp)
    (hOps : AreRunarEmittable ops) : ops.length ≤ (emitOpsL ops).length := by
  induction ops with
  | nil => simp [emitOpsL]
  | cons op rest ih =>
      cases hOps with
      | cons _ _ hOp hRest =>
          have hOpBytes := emitStackOpL_cons_of_RunarEmittable op hOp
          obtain ⟨b, opTail, hOpHead⟩ := hOpBytes
          have hRestLen := ih hRest
          show (op :: rest).length ≤ (emitStackOpL op ++ emitOpsL rest).length
          simp [hOpHead, List.length_append, List.length_cons]
          omega

/-- Top-level `parseOps`: emitted bytes round-trip back to the original
op list. -/
theorem parseOps_emit_round_trip (ops : List StackOp)
    (hOps : AreRunarEmittable ops) :
    parseOps (emitOpsL ops) = .ok ops := by
  unfold parseOps
  -- `parseOps` calls `parseOpsFuel (bytes.length + 1) bytes false` and
  -- then checks the tail is empty.
  have hLen : ops.length ≤ (emitOpsL ops).length :=
    emitOpsL_length_ge_ops_length ops hOps
  rw [parseOpsFuel_emit_round_trip ops hOps (emitOpsL ops).length hLen]

/-! ## `parseScript` (ByteArray) round-trip

`parseScript` is `parseOps ∘ ByteArray.toList`. To bridge from
`emitOps` (ByteArray) to `emitOpsL` (List), we need
`(Emit.emitOps ops).toList = emitOpsL ops`. This is proved by induction
on ops, using `(Emit.emitStackOp op).toList = emitStackOpL op` for the
single-op case. -/

/-! ### Single-op ByteArray ↔ List equivalence

We bridge `ByteArray.toList` to `bs.data.toList` so that the per-op
shapes used by `Emit.emitStackOp` (each `ByteArray.mk #[b]` or two
such concatenated) reduce to their `emitStackOpL` counterparts. The
`toList` definition uses an internal accumulator-based loop; we prove
its closed form by a strong induction on `bs.size - i`. -/

/-- Closed-form description of `ByteArray.toList.loop`: starting at
position `i` with reverse-accumulator `acc`, the loop returns
`acc.reverse ++ bs.data.toList.drop i`. -/
theorem ByteArray.toList_loop_eq (bs : ByteArray) :
    ∀ (k i : Nat) (acc : List UInt8),
      bs.size - i = k →
      ByteArray.toList.loop bs i acc =
        acc.reverse ++ bs.data.toList.drop i := by
  intro k
  induction k with
  | zero =>
      intro i acc hk
      have hi : bs.size ≤ i := by omega
      unfold ByteArray.toList.loop
      have hlt : ¬ (i < bs.size) := Nat.not_lt.mpr hi
      rw [if_neg hlt]
      have hlen : bs.data.toList.length ≤ i := by
        show bs.data.size ≤ i
        exact hi
      rw [List.drop_eq_nil_of_le hlen, List.append_nil]
  | succ k ih =>
      intro i acc hk
      have hi : i < bs.size := by omega
      unfold ByteArray.toList.loop
      rw [if_pos hi]
      have hk' : bs.size - (i + 1) = k := by omega
      rw [ih (i + 1) (bs.get! i :: acc) hk']
      -- Show `(bs.get! i :: acc).reverse ++ drop (i+1) = acc.reverse ++ drop i`.
      have hi' : i < bs.data.size := hi
      have hidx : i < bs.data.toList.length := hi
      have hgetEq : bs.get! i = bs.data.toList[i]'hidx := by
        show bs.data[i]! = _
        rw [getElem!_pos bs.data i hi']
        rw [Array.getElem_toList hi']
      have hdrop : bs.data.toList.drop i =
          bs.data.toList[i]'hidx :: bs.data.toList.drop (i + 1) :=
        List.drop_eq_getElem_cons hidx
      rw [hdrop, ← hgetEq]
      rw [List.reverse_cons]
      rw [List.append_assoc]
      rfl

/-- The `ByteArray.toList` function equals the underlying array's
`toList`. Bridges from the `ByteArray` API (used by `Emit.emitOps`)
to the `List UInt8` API (used by `parseOps`). -/
theorem ByteArray.toList_eq_data_toList (bs : ByteArray) :
    bs.toList = bs.data.toList := by
  unfold ByteArray.toList
  have h := ByteArray.toList_loop_eq bs bs.size 0 [] (by omega)
  simpa using h

/-- `ByteArray.++` distributes over `toList`. Combines
`toList_eq_data_toList` with the existing
`ByteArray.toList_data_append`. -/
theorem ByteArray.toList_append (a b : ByteArray) :
    (a ++ b).toList = a.toList ++ b.toList := by
  rw [ByteArray.toList_eq_data_toList,
      ByteArray.toList_eq_data_toList a,
      ByteArray.toList_eq_data_toList b]
  exact ByteArray.toList_data_append

/-- A singleton ByteArray's `toList` is the singleton list. -/
theorem ByteArray.toList_mk_singleton (b : UInt8) :
    (ByteArray.mk #[b]).toList = [b] := by
  rw [ByteArray.toList_eq_data_toList]

/-! ### `emitStackOp` ↔ `emitStackOpL` bridge for `RunarEmittable` ops -/

/-- Helper: for any `b`, the ByteArray `mk #[b1] ++ mk #[b2]` has
`toList = [b1, b2]`. Used by the `.roll` / `.pick` cases below where
the depth's push always reduces to a single byte. -/
theorem ByteArray.toList_two_singletons (b1 b2 : UInt8) :
    (ByteArray.mk #[b1] ++ ByteArray.mk #[b2]).toList = [b1, b2] := by
  rw [ByteArray.toList_append, ByteArray.toList_mk_singleton,
      ByteArray.toList_mk_singleton]
  rfl

/-- For each `RunarEmittable` op, the ByteArray-level `emitStackOp`
agrees with the list-level `emitStackOpL` after `toList`. The proof
case-splits the small-`d` shape of `roll`/`pick` (16 each) the same
way as `emitStackOpL_cons_of_RunarEmittable`, so each case reduces
to a `rfl` after `ByteArray.toList_two_singletons` evaluates the
underlying byte pair. -/
theorem emitStackOp_toList_of_RunarEmittable (op : StackOp)
    (hOp : RunarEmittable op) :
    (Emit.emitStackOp op).toList = emitStackOpL op := by
  cases hOp with
  | dup  => exact ByteArray.toList_mk_singleton _
  | swap => exact ByteArray.toList_mk_singleton _
  | nip  => exact ByteArray.toList_mk_singleton _
  | over => exact ByteArray.toList_mk_singleton _
  | rot  => exact ByteArray.toList_mk_singleton _
  | tuck => exact ByteArray.toList_mk_singleton _
  | drop => exact ByteArray.toList_mk_singleton _
  | roll d hd =>
      obtain ⟨h1, h16⟩ := hd
      rcases d with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | d
      · exact absurd h1 (by omega)
      · exact ByteArray.toList_two_singletons 0x51 0x7a
      · exact ByteArray.toList_two_singletons 0x52 0x7a
      · exact ByteArray.toList_two_singletons 0x53 0x7a
      · exact ByteArray.toList_two_singletons 0x54 0x7a
      · exact ByteArray.toList_two_singletons 0x55 0x7a
      · exact ByteArray.toList_two_singletons 0x56 0x7a
      · exact ByteArray.toList_two_singletons 0x57 0x7a
      · exact ByteArray.toList_two_singletons 0x58 0x7a
      · exact ByteArray.toList_two_singletons 0x59 0x7a
      · exact ByteArray.toList_two_singletons 0x5a 0x7a
      · exact ByteArray.toList_two_singletons 0x5b 0x7a
      · exact ByteArray.toList_two_singletons 0x5c 0x7a
      · exact ByteArray.toList_two_singletons 0x5d 0x7a
      · exact ByteArray.toList_two_singletons 0x5e 0x7a
      · exact ByteArray.toList_two_singletons 0x5f 0x7a
      · exact ByteArray.toList_two_singletons 0x60 0x7a
      · exact absurd h16 (by omega)
  | pick d hd =>
      obtain ⟨h1, h16⟩ := hd
      rcases d with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | d
      · exact absurd h1 (by omega)
      · exact ByteArray.toList_two_singletons 0x51 0x79
      · exact ByteArray.toList_two_singletons 0x52 0x79
      · exact ByteArray.toList_two_singletons 0x53 0x79
      · exact ByteArray.toList_two_singletons 0x54 0x79
      · exact ByteArray.toList_two_singletons 0x55 0x79
      · exact ByteArray.toList_two_singletons 0x56 0x79
      · exact ByteArray.toList_two_singletons 0x57 0x79
      · exact ByteArray.toList_two_singletons 0x58 0x79
      · exact ByteArray.toList_two_singletons 0x59 0x79
      · exact ByteArray.toList_two_singletons 0x5a 0x79
      · exact ByteArray.toList_two_singletons 0x5b 0x79
      · exact ByteArray.toList_two_singletons 0x5c 0x79
      · exact ByteArray.toList_two_singletons 0x5d 0x79
      · exact ByteArray.toList_two_singletons 0x5e 0x79
      · exact ByteArray.toList_two_singletons 0x5f 0x79
      · exact ByteArray.toList_two_singletons 0x60 0x79
      · exact absurd h16 (by omega)
  | opcode name hAllow =>
      -- Each allowed name resolves through `opcodeByName?` to a
      -- single-byte hit; both sides reduce to `[b]` for that byte.
      unfold isAllowedOpcodeName at hAllow
      simp only [Bool.or_eq_true, decide_eq_true_eq] at hAllow
      obtain hN | hN := hAllow
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      all_goals (subst hN; exact ByteArray.toList_mk_singleton _)

/-- Bridge `Emit.emitOps` to `emitOpsL` at the `List UInt8` level for
any `AreRunarEmittable` op list. -/
theorem emitOps_toList_of_AreRunarEmittable (ops : List StackOp)
    (hOps : AreRunarEmittable ops) :
    (Emit.emitOps ops).toList = emitOpsL ops := by
  induction ops with
  | nil =>
      show (Emit.emitOps []).toList = emitOpsL []
      unfold Emit.emitOps emitOpsL
      exact ByteArray.toList_empty
  | cons op rest ih =>
      cases hOps with
      | cons _ _ hOp hRest =>
          show (Emit.emitOps (op :: rest)).toList = emitOpsL (op :: rest)
          unfold Emit.emitOps emitOpsL
          rw [ByteArray.toList_append]
          rw [emitStackOp_toList_of_RunarEmittable op hOp]
          rw [ih hRest]

/-! ### Top-level `parseScript` round-trip -/

/-- For any `RunarEmittable` op list, the ByteArray-level emit
function and the ByteArray-level parser round-trip. This lifts
`parseOps_emit_round_trip` through the `ByteArray ↔ List UInt8`
bridge proved above. -/
theorem parseScript_emit_round_trip (ops : List StackOp)
    (hOps : AreRunarEmittable ops) :
    parseScript (Emit.emitOps ops) = .ok ops := by
  unfold parseScript
  rw [emitOps_toList_of_AreRunarEmittable ops hOps]
  exact parseOps_emit_round_trip ops hOps

/-! ### Terminal singleton push round-trip

This is an intentionally separate, bounded expansion beyond
`RunarEmittable`: a terminal singleton `.push (.bigint i)` round-trips
for the unambiguous small-int fast-path values below. It does not say
anything about `.placeholder` / `.pushCodesepIndex`, nor about a push
followed by `OP_PICK` / `OP_ROLL`.
-/

/-- ByteArray/list bridge for the terminal singleton bigint-push subset. -/
private theorem emitOps_toList_singleton_push_bigint_terminal
    (i : Int) (h : i = -1 ∨ (0 ≤ i ∧ i ≤ 16)) :
    (Emit.emitOps [.push (.bigint i)]).toList = emitOpsL [.push (.bigint i)] := by
  have hCases :
      i = -1 ∨ i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨
        i = 6 ∨ i = 7 ∨ i = 8 ∨ i = 9 ∨ i = 10 ∨ i = 11 ∨ i = 12 ∨
        i = 13 ∨ i = 14 ∨ i = 15 ∨ i = 16 := by
    omega
  rcases hCases with
    h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h <;>
    subst i <;>
    simp [Emit.emitOps, Emit.emitStackOp, Emit.encodePushVal, Emit.encodePushBigInt,
      emitOpsL, emitStackOpL, encodePushValL, encodePushBigIntL,
      ByteArray.toList_mk_singleton]

/-- List parser round-trip for a terminal singleton bigint-push subset. -/
theorem parseOps_emit_singleton_push_bigint_terminal
    (i : Int) (h : i = -1 ∨ (0 ≤ i ∧ i ≤ 16)) :
    parseOps (emitOpsL [.push (.bigint i)]) = .ok [.push (.bigint i)] := by
  have hCases :
      i = -1 ∨ i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨
        i = 6 ∨ i = 7 ∨ i = 8 ∨ i = 9 ∨ i = 10 ∨ i = 11 ∨ i = 12 ∨
        i = 13 ∨ i = 14 ∨ i = 15 ∨ i = 16 := by
    omega
  rcases hCases with
    h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h <;>
    subst i <;> rfl

/-- ByteArray parser round-trip for a terminal singleton bigint-push subset. -/
theorem parseScript_emit_singleton_push_bigint_terminal
    (i : Int) (h : i = -1 ∨ (0 ≤ i ∧ i ≤ 16)) :
    parseScript (Emit.emitOps [.push (.bigint i)]) = .ok [.push (.bigint i)] := by
  unfold parseScript
  rw [emitOps_toList_singleton_push_bigint_terminal i h]
  exact parseOps_emit_singleton_push_bigint_terminal i h

theorem parseOps_emit_singleton_push_bool_false_terminal :
    parseOps (emitOpsL [.push (.bool false)]) = .ok [.push (.bigint 0)] := rfl

theorem parseOps_emit_singleton_push_bool_true_terminal :
    parseOps (emitOpsL [.push (.bool true)]) = .ok [.push (.bigint 1)] := rfl

private theorem emitOps_toList_singleton_push_bool_terminal (b : Bool) :
    (Emit.emitOps [.push (.bool b)]).toList = emitOpsL [.push (.bool b)] := by
  cases b <;>
    simp [Emit.emitOps, Emit.emitStackOp, Emit.encodePushVal, Emit.encodePushBool,
      emitOpsL, emitStackOpL, encodePushValL, encodePushBoolL,
      ByteArray.toList_mk_singleton]

theorem parseScript_emit_singleton_push_bool_false_terminal :
    parseScript (Emit.emitOps [.push (.bool false)]) = .ok [.push (.bigint 0)] := by
  unfold parseScript
  rw [emitOps_toList_singleton_push_bool_terminal false]
  exact parseOps_emit_singleton_push_bool_false_terminal

theorem parseScript_emit_singleton_push_bool_true_terminal :
    parseScript (Emit.emitOps [.push (.bool true)]) = .ok [.push (.bigint 1)] := by
  unfold parseScript
  rw [emitOps_toList_singleton_push_bool_terminal true]
  exact parseOps_emit_singleton_push_bool_true_terminal

theorem parseOps_emit_singleton_push_bytes_empty_terminal :
    parseOps (emitOpsL [.push (.bytes (ByteArray.mk #[]))])
      = .ok [.push (.bigint 0)] := by
  unfold emitOpsL emitStackOpL encodePushValL encodePushBytesL
  simp [ByteArray.toList_eq_data_toList]
  rfl

theorem parseOps_emit_singleton_push_bytes_81_terminal :
    parseOps (emitOpsL [.push (.bytes (ByteArray.mk #[0x81]))])
      = .ok [.push (.bigint (-1))] := by
  unfold emitOpsL emitStackOpL encodePushValL encodePushBytesL
  simp [ByteArray.toList_eq_data_toList]
  rfl

theorem parseOps_emit_singleton_push_bytes_17_terminal :
    parseOps (emitOpsL [.push (.bytes (ByteArray.mk #[0x17]))])
      = .ok [.push (.bytes (ByteArray.mk #[0x17]))] := by
  unfold emitOpsL emitStackOpL encodePushValL encodePushBytesL encodePushDataL
  simp [ByteArray.toList_eq_data_toList]
  rfl

/-! ### Nonterminal push parser samples

These concrete facts cover push-eager parsing when a push is followed by
another recoverable op. The bool case documents the same byte collision
as the terminal facts: `true` emits `OP_1`, so parsing recovers
`.push (.bigint 1)`.
-/

theorem parseOps_emit_push_bigint_two_then_dup :
    parseOps (emitOpsL [.push (.bigint 2), .dup])
      = .ok [.push (.bigint 2), .dup] := rfl

theorem parseOps_emit_push_bool_true_then_dup :
    parseOps (emitOpsL [.push (.bool true), .dup])
      = .ok [.push (.bigint 1), .dup] := rfl

theorem parseOps_emit_push_bytes_17_then_dup :
    parseOps (emitOpsL [.push (.bytes (ByteArray.mk #[0x17])), .dup])
      = .ok [.push (.bytes (ByteArray.mk #[0x17])), .dup] := by
  unfold emitOpsL emitStackOpL encodePushValL encodePushBytesL encodePushDataL
  simp [ByteArray.toList_eq_data_toList]
  rfl

private theorem emitOps_toList_push_bigint_two_then_dup :
    (Emit.emitOps [.push (.bigint 2), .dup]).toList
      = emitOpsL [.push (.bigint 2), .dup] := by
  simp [Emit.emitOps, Emit.emitStackOp, Emit.encodePushVal, Emit.encodePushBigInt,
    emitOpsL, emitStackOpL, encodePushValL, encodePushBigIntL,
    ByteArray.toList_append, ByteArray.toList_mk_singleton]

private theorem emitOps_toList_push_bool_true_then_dup :
    (Emit.emitOps [.push (.bool true), .dup]).toList
      = emitOpsL [.push (.bool true), .dup] := by
  simp [Emit.emitOps, Emit.emitStackOp, Emit.encodePushVal, Emit.encodePushBool,
    emitOpsL, emitStackOpL, encodePushValL, encodePushBoolL,
    ByteArray.toList_append, ByteArray.toList_mk_singleton]

private theorem emitOps_toList_push_bytes_17_then_dup :
    (Emit.emitOps [.push (.bytes (ByteArray.mk #[0x17])), .dup]).toList
      = emitOpsL [.push (.bytes (ByteArray.mk #[0x17])), .dup] := by
  native_decide

theorem parseScript_emit_push_bigint_two_then_dup :
    parseScript (Emit.emitOps [.push (.bigint 2), .dup])
      = .ok [.push (.bigint 2), .dup] := by
  unfold parseScript
  rw [emitOps_toList_push_bigint_two_then_dup]
  exact parseOps_emit_push_bigint_two_then_dup

theorem parseScript_emit_push_bool_true_then_dup :
    parseScript (Emit.emitOps [.push (.bool true), .dup])
      = .ok [.push (.bigint 1), .dup] := by
  unfold parseScript
  rw [emitOps_toList_push_bool_true_then_dup]
  exact parseOps_emit_push_bool_true_then_dup

theorem parseScript_emit_push_bytes_17_then_dup :
    parseScript (Emit.emitOps [.push (.bytes (ByteArray.mk #[0x17])), .dup])
      = .ok [.push (.bytes (ByteArray.mk #[0x17])), .dup] := by
  unfold parseScript
  rw [emitOps_toList_push_bytes_17_then_dup]
  exact parseOps_emit_push_bytes_17_then_dup

/-! ## Tier 3.4 Path B — multi-method dispatch chain primitives

The TS reference compiler emits an `OP_DUP <i> OP_NUMEQUAL OP_IF OP_DROP
<body_i> OP_ELSE` chain for each non-last public method, terminated by
`<n-1> OP_NUMEQUALVERIFY <body_{n-1}>` and closed by `n-1` `OP_ENDIF`s.
See `Script.Emit.emitDispatch{Chain,HeadNonLast,HeadLast,Else,Endifs}`.

### Scope

This block delivers:

1. **List-level dispatch encoders** mirroring the ByteArray-level
   `Emit.emitDispatch*` (the same trick used for `emitStackOpL`).
2. **Primitive recognisers** `parseDispatchHeadNonLast?` /
   `parseDispatchHeadLast?` for the 5-byte / 2-byte head chunks
   (small index `i ∈ [0..16]`).
3. **Per-primitive round-trip lemmas** — by `rfl` for `i ∈ [0..16]`.
4. **A `parseDispatch2` driver** for the smallest non-trivial
   dispatch (2 methods).
5. **2-method byte-level round-trip** under the natural body
   constraint (each body is `AreRunarEmittable`).

### Deferred (multi-day per audit)

* The N-method generalisation requires threading `n-1` ENDIFs through
  a recursive `parseDispatchN` driver and inducting on `n`. The
  primitives + body-bytes-don't-include-ELSE/ENDIF lemma already
  handle the non-trivial part; the induction is mechanical but
  non-trivial bookkeeping.
* The lift to `compile_runs_correctly_simple_multi` (Path B's
  pipeline-level theorem) requires bridging
  `Pipeline.compile p = Emit.emitDispatch (publicMethodsOf ...)` for
  multi-public-method programs (parallel to
  `compile_eq_emitOps_of_single_public`) plus a multi-method
  observational equivalence theorem (parallel to
  `compile_observational_correct_simple_structured`). The
  observational side requires a multi-input dispatch evaluator
  that runs the matching method based on the index pushed onto the
  stack — not currently in `Stack.Eval`.

The remaining pipeline-level items are documented inline; this block
closes the byte-level recogniser story for the 2-method case and
provides the primitive head parsers required by any N-method extension.
-/

/-! ### List-level dispatch chain emit (mirrors `Emit.emitDispatch*`)

Each definition is line-by-line parallel to its `Emit.lean` peer. -/

/-- List-level mirror of `Emit.emitDispatchHeadNonLast`. -/
def emitDispatchHeadNonLastL (i : Nat) : List UInt8 :=
  0x76 :: encodePushBigIntL (Int.ofNat i) ++ [0x9c, 0x63, 0x75]

/-- List-level mirror of `Emit.emitDispatchHeadLast`. -/
def emitDispatchHeadLastL (i : Nat) : List UInt8 :=
  encodePushBigIntL (Int.ofNat i) ++ [0x9d]

/-- List-level mirror of `Emit.emitElse`. -/
def emitElseL : List UInt8 := [0x67]

/-- List-level mirror of `Emit.emitEndifs`. -/
def emitEndifsL : Nat → List UInt8
  | 0     => []
  | n + 1 => 0x68 :: emitEndifsL n

/-! ### Primitive head recognisers

These pattern-match on the literal 5-byte (non-last) or 2-byte (last)
head shapes for small dispatch indices `i ∈ [0..16]`. Larger indices
use multi-byte push encodings; we restrict the supported range here
since the conformance corpus only exercises small dispatch indices
(public-method counts ≤ 17 in practice). -/

/-- Recognise a non-last dispatch head at index `i ∈ [0..16]`:
the byte sequence `[0x76, push i, 0x9c, 0x63, 0x75]`. Returns the
recognised index and the trailing bytes; `none` if the prefix does
not match. -/
def parseDispatchHeadNonLast? : List UInt8 → Option (Nat × List UInt8)
  | 0x76 :: 0x00 :: 0x9c :: 0x63 :: 0x75 :: rest => some (0, rest)
  | 0x76 :: 0x51 :: 0x9c :: 0x63 :: 0x75 :: rest => some (1, rest)
  | 0x76 :: 0x52 :: 0x9c :: 0x63 :: 0x75 :: rest => some (2, rest)
  | 0x76 :: 0x53 :: 0x9c :: 0x63 :: 0x75 :: rest => some (3, rest)
  | 0x76 :: 0x54 :: 0x9c :: 0x63 :: 0x75 :: rest => some (4, rest)
  | 0x76 :: 0x55 :: 0x9c :: 0x63 :: 0x75 :: rest => some (5, rest)
  | 0x76 :: 0x56 :: 0x9c :: 0x63 :: 0x75 :: rest => some (6, rest)
  | 0x76 :: 0x57 :: 0x9c :: 0x63 :: 0x75 :: rest => some (7, rest)
  | 0x76 :: 0x58 :: 0x9c :: 0x63 :: 0x75 :: rest => some (8, rest)
  | 0x76 :: 0x59 :: 0x9c :: 0x63 :: 0x75 :: rest => some (9, rest)
  | 0x76 :: 0x5a :: 0x9c :: 0x63 :: 0x75 :: rest => some (10, rest)
  | 0x76 :: 0x5b :: 0x9c :: 0x63 :: 0x75 :: rest => some (11, rest)
  | 0x76 :: 0x5c :: 0x9c :: 0x63 :: 0x75 :: rest => some (12, rest)
  | 0x76 :: 0x5d :: 0x9c :: 0x63 :: 0x75 :: rest => some (13, rest)
  | 0x76 :: 0x5e :: 0x9c :: 0x63 :: 0x75 :: rest => some (14, rest)
  | 0x76 :: 0x5f :: 0x9c :: 0x63 :: 0x75 :: rest => some (15, rest)
  | 0x76 :: 0x60 :: 0x9c :: 0x63 :: 0x75 :: rest => some (16, rest)
  | _ => none

/-- Recognise a last-method dispatch head at index `i ∈ [0..16]`:
the byte sequence `[push i, 0x9d]`. -/
def parseDispatchHeadLast? : List UInt8 → Option (Nat × List UInt8)
  | 0x00 :: 0x9d :: rest => some (0, rest)
  | 0x51 :: 0x9d :: rest => some (1, rest)
  | 0x52 :: 0x9d :: rest => some (2, rest)
  | 0x53 :: 0x9d :: rest => some (3, rest)
  | 0x54 :: 0x9d :: rest => some (4, rest)
  | 0x55 :: 0x9d :: rest => some (5, rest)
  | 0x56 :: 0x9d :: rest => some (6, rest)
  | 0x57 :: 0x9d :: rest => some (7, rest)
  | 0x58 :: 0x9d :: rest => some (8, rest)
  | 0x59 :: 0x9d :: rest => some (9, rest)
  | 0x5a :: 0x9d :: rest => some (10, rest)
  | 0x5b :: 0x9d :: rest => some (11, rest)
  | 0x5c :: 0x9d :: rest => some (12, rest)
  | 0x5d :: 0x9d :: rest => some (13, rest)
  | 0x5e :: 0x9d :: rest => some (14, rest)
  | 0x5f :: 0x9d :: rest => some (15, rest)
  | 0x60 :: 0x9d :: rest => some (16, rest)
  | _ => none

/-! ### Primitive head round-trip lemmas

For each `i ∈ [0..16]` the list-level encoder produces the byte
sequence the recogniser expects. Proved by `rfl` (the encoder
reduces to a literal cons sequence; the recogniser pattern-matches
on the same sequence). -/

theorem parseDispatchHeadNonLast?_emit_round_trip_smallI
    (i : Nat) (hi : i ≤ 16) (rest : List UInt8) :
    parseDispatchHeadNonLast? (emitDispatchHeadNonLastL i ++ rest)
      = some (i, rest) := by
  rcases i with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | i
  all_goals first
    | rfl
    | exact absurd hi (by omega)

theorem parseDispatchHeadLast?_emit_round_trip_smallI
    (i : Nat) (hi : i ≤ 16) (rest : List UInt8) :
    parseDispatchHeadLast? (emitDispatchHeadLastL i ++ rest)
      = some (i, rest) := by
  rcases i with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | i
  all_goals first
    | rfl
    | exact absurd hi (by omega)

/-! ### `parseOpsFuel` body-with-trailing-stop-byte round-trip

The 2-method dispatch driver calls `parseOpsFuel fuel after_head true`
on `emitOpsL body ++ (stopByte :: rest)` where `stopByte ∈ {0x67, 0x68}`.
The parser must return `(body, stopByte :: rest)`: it parses body until
it sees the stop byte, then halts. This is the dispatch-chain analogue
of `parseOpsFuel_emit_round_trip` (which assumes the byte tail after
all body ops is empty).

We need: every `RunarEmittable` op's emit head byte is NOT
`0x67`/`0x68`, so the stopAtElse branch of `parseOpsFuel` doesn't
fire while we're inside the body. -/

/-- For every `RunarEmittable` op the head byte of its emit is neither
`0x67` (`OP_ELSE`) nor `0x68` (`OP_ENDIF`). Direct case analysis on
each constructor: 7 short-form ops have unique single-byte heads,
roll/pick d ∈ [1..16] use 0x51..0x60 for the push head, and the 14
allowed opcode names map to bytes that don't overlap with the
control-flow reservation (verified by enumeration of
`isAllowedOpcodeName`). -/
private theorem head_of_emitStackOpL_not_else_or_endif
    (op : StackOp) (hOp : RunarEmittable op) :
    ∀ b tail, emitStackOpL op = b :: tail → b ≠ 0x67 ∧ b ≠ 0x68 := by
  cases hOp with
  | dup        => intro b tail h; injection h with hb _; subst hb; exact ⟨by decide, by decide⟩
  | swap       => intro b tail h; injection h with hb _; subst hb; exact ⟨by decide, by decide⟩
  | nip        => intro b tail h; injection h with hb _; subst hb; exact ⟨by decide, by decide⟩
  | over       => intro b tail h; injection h with hb _; subst hb; exact ⟨by decide, by decide⟩
  | rot        => intro b tail h; injection h with hb _; subst hb; exact ⟨by decide, by decide⟩
  | tuck       => intro b tail h; injection h with hb _; subst hb; exact ⟨by decide, by decide⟩
  | drop       => intro b tail h; injection h with hb _; subst hb; exact ⟨by decide, by decide⟩
  | roll d hd  =>
      obtain ⟨h1, h16⟩ := hd
      rcases d with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | d
      all_goals first
        | exact absurd h1 (by omega)
        | exact absurd h16 (by omega)
        | (intro b tail h; injection h with hb _; subst hb;
           exact ⟨by decide, by decide⟩)
  | pick d hd  =>
      obtain ⟨h1, h16⟩ := hd
      rcases d with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | d
      all_goals first
        | exact absurd h1 (by omega)
        | exact absurd h16 (by omega)
        | (intro b tail h; injection h with hb _; subst hb;
           exact ⟨by decide, by decide⟩)
  | opcode name hAllow =>
      unfold isAllowedOpcodeName at hAllow
      simp only [Bool.or_eq_true, decide_eq_true_eq] at hAllow
      obtain hN | hN := hAllow
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      obtain hN | hN := hN
      all_goals (subst hN; intro b tail h; injection h with hb _; subst hb;
                 exact ⟨by decide, by decide⟩)

/-- One-step unfold of `parseOpsFuel` with `stopAtElse = true` when the
head byte is neither `0x67` nor `0x68`. Mirrors `parseOpsFuel_cons_unfold`
but for the stop-aware mode. -/
private theorem parseOpsFuel_cons_unfold_stop
    (fuel : Nat) (b : UInt8) (rest : List UInt8)
    (hb : b ≠ 0x67 ∧ b ≠ 0x68) :
    parseOpsFuel (fuel + 1) (b :: rest) true
    = match parseStackOpFuel fuel (b :: rest) with
      | .error e => .error e
      | .ok (op, rest') =>
          match parseOpsFuel fuel rest' true with
          | .error e => .error e
          | .ok (ops, tail) => .ok (op :: ops, tail) := by
  obtain ⟨hb1, hb2⟩ := hb
  -- parseOpsFuel reduces to: `if stopAtElse ∧ (b ∈ {0x67,0x68}) then ... else ...`.
  -- With stopAtElse=true and our hypothesis the if-test is false; the else branch
  -- matches the goal RHS modulo `rfl`.
  show
    (if (true : Bool) ∧ (b = 0x67 ∨ b = 0x68) then
        (Except.ok ([], b :: rest) : Except ParseError (List StackOp × List UInt8))
     else
       match parseStackOpFuel fuel (b :: rest) with
        | .error e => .error e
        | .ok (op, rest') =>
            match parseOpsFuel fuel rest' true with
            | .error e => .error e
            | .ok (ops, tail) => .ok (op :: ops, tail))
    = match parseStackOpFuel fuel (b :: rest) with
      | .error e => .error e
      | .ok (op, rest') =>
          match parseOpsFuel fuel rest' true with
          | .error e => .error e
          | .ok (ops, tail) => .ok (op :: ops, tail)
  rw [if_neg]
  intro hAnd
  rcases hAnd.2 with h | h
  · exact hb1 h
  · exact hb2 h

/-- Body-with-stop-byte round-trip: parsing `emitOpsL ops ++ (s :: rest)`
with `stopAtElse = true` and `s ∈ {0x67, 0x68}` returns `(ops, s :: rest)`.

The induction is on `ops`. For empty `ops`, the parser sees `s :: rest`,
recognises the stop byte, and returns `([], s :: rest)`. For
`op :: rest'`, the parser sees the head byte of `emitStackOpL op` which
(by `head_of_emitStackOpL_not_else_or_endif`) is not `0x67`/`0x68`, so
the stopAtElse branch does NOT fire; the parser proceeds to
`parseStackOpFuel` which (by the per-op round-trip) consumes the op
and recursively parses the rest. -/
theorem parseOpsFuel_emit_round_trip_with_stop_byte
    (ops : List StackOp) (hOps : AreRunarEmittable ops)
    (fuel : Nat) (hFuel : ops.length ≤ fuel) (s : UInt8)
    (hStop : s = 0x67 ∨ s = 0x68) (rest : List UInt8) :
    parseOpsFuel (fuel + 1) (emitOpsL ops ++ (s :: rest)) true
      = .ok (ops, s :: rest) := by
  induction ops generalizing fuel with
  | nil =>
      -- emitOpsL [] ++ (s :: rest) = s :: rest.
      show parseOpsFuel (fuel + 1) (s :: rest) true = .ok ([], s :: rest)
      -- parseOpsFuel pattern-matches on cons; with stopAtElse=true and
      -- s ∈ {0x67, 0x68}, the if-branch fires.
      rcases hStop with h | h <;> subst h <;> rfl
  | cons op rest' ih =>
      cases hOps with
      | cons _ _ hOp hRestE =>
          have hFuelGe1 : 1 ≤ fuel := by
            simp [List.length] at hFuel; omega
          obtain ⟨fuel', rfl⟩ : ∃ k, fuel = k + 1 := ⟨fuel - 1, by omega⟩
          obtain ⟨b, opTail, hOpHead⟩ := emitStackOpL_cons_of_RunarEmittable op hOp
          -- emitOpsL (op :: rest') ++ (s :: rest) = b :: (opTail ++ emitOpsL rest' ++ (s :: rest)).
          have hAllBytes :
              emitOpsL (op :: rest') ++ (s :: rest)
              = b :: (opTail ++ emitOpsL rest' ++ (s :: rest)) := by
            show emitStackOpL op ++ emitOpsL rest' ++ (s :: rest) = _
            rw [hOpHead]
            simp [List.cons_append, List.append_assoc]
          rw [hAllBytes]
          have hBnotStop : b ≠ 0x67 ∧ b ≠ 0x68 :=
            head_of_emitStackOpL_not_else_or_endif op hOp b opTail hOpHead
          -- One-step unfold using the helper.
          rw [parseOpsFuel_cons_unfold_stop (fuel' + 1) b
                (opTail ++ emitOpsL rest' ++ (s :: rest)) hBnotStop]
          have hHeadBack :
              b :: (opTail ++ emitOpsL rest' ++ (s :: rest))
              = emitStackOpL op ++ (emitOpsL rest' ++ (s :: rest)) := by
            rw [hOpHead]; simp [List.cons_append, List.append_assoc]
          rw [hHeadBack]
          rw [parseStackOp_emit_round_trip fuel' op
                (emitOpsL rest' ++ (s :: rest)) hOp]
          dsimp only
          have hRestLen : rest'.length ≤ fuel' := by
            simp [List.length] at hFuel; omega
          rw [ih hRestE fuel' hRestLen]

/-- `parseOpsFuel` with `stopAtElse = true` on emitted bytes followed by
`[]`: returns `(ops, [])`. Same structural argument as
`parseOpsFuel_emit_round_trip` in `false` mode, since no
`RunarEmittable` op emits a head byte of `0x67`/`0x68` so the
stop-check never fires. -/
private theorem parseOpsFuel_emit_round_trip_true_nil
    (ops : List StackOp) (hOps : AreRunarEmittable ops)
    (fuel : Nat) (hFuel : ops.length ≤ fuel) :
    parseOpsFuel (fuel + 1) (emitOpsL ops) true = .ok (ops, []) := by
  induction ops generalizing fuel with
  | nil => rfl
  | cons op rest ih =>
      cases hOps with
      | cons _ _ hOp hRest =>
          have hFuelGe1 : 1 ≤ fuel := by
            simp [List.length] at hFuel; omega
          obtain ⟨fuel', rfl⟩ : ∃ k, fuel = k + 1 := ⟨fuel - 1, by omega⟩
          obtain ⟨b, opTail, hOpHead⟩ := emitStackOpL_cons_of_RunarEmittable op hOp
          have hAllBytes : emitOpsL (op :: rest)
              = b :: (opTail ++ emitOpsL rest) := by
            show emitStackOpL op ++ emitOpsL rest = _
            rw [hOpHead]; rfl
          rw [hAllBytes]
          have hBnotStop : b ≠ 0x67 ∧ b ≠ 0x68 :=
            head_of_emitStackOpL_not_else_or_endif op hOp b opTail hOpHead
          rw [parseOpsFuel_cons_unfold_stop (fuel' + 1) b
                (opTail ++ emitOpsL rest) hBnotStop]
          have hHeadBack : b :: (opTail ++ emitOpsL rest)
              = emitStackOpL op ++ emitOpsL rest := by
            rw [hOpHead]; rfl
          rw [hHeadBack]
          rw [parseStackOp_emit_round_trip fuel' op (emitOpsL rest) hOp]
          dsimp only
          have hRestLen : rest.length ≤ fuel' := by
            simp [List.length] at hFuel; omega
          rw [ih hRest fuel' hRestLen]

private theorem parsePushVal?_OP_IF (rest : List UInt8) :
    parsePushVal? (0x63 :: rest) = none := rfl

/-! ### Structural `ifOp` body round-trip

These theorems expand the proven emitted subset at the per-op level:
an `ifOp` whose branch bodies are already `AreRunarEmittable` parses
back to the same structural `ifOp`. The exact `some []` shape is still
intentionally excluded because `Emit.emitStackOp` emits no `OP_ELSE`
for an empty else branch, making `.ifOp thn (some [])` byte-identical
to `.ifOp thn none`.
-/

/-- An emitted `ifOp` with no else branch round-trips when the then-body
is in the existing emitted subset and the fuel covers that body. -/
theorem parseStackOpFuel_ifOp_none
    (fuel : Nat) (thn : List StackOp)
    (hThn : AreRunarEmittable thn) (hFuelThn : thn.length ≤ fuel)
    (rest : List UInt8) :
    parseStackOpFuel (fuel + 2) (emitStackOpL (.ifOp thn none) ++ rest)
      = .ok (.ifOp thn none, rest) := by
  rw [show emitStackOpL (.ifOp thn none) ++ rest
        = 0x63 :: (emitOpsL thn ++ (0x68 :: rest)) by
      simp [emitStackOpL, List.append_assoc]]
  simp [parseStackOpFuel]
  rw [parseOpsFuel_emit_round_trip_with_stop_byte thn hThn fuel hFuelThn
        0x68 (by right; rfl) rest]
  rw [parsePushVal?_OP_IF]
  rfl

/-- An emitted `ifOp` with a non-empty else branch round-trips when both
branch bodies are in the existing emitted subset and the fuel covers both
bodies. The else branch is stated as `elsHead :: elsTail` to rule out the
`some []`/`none` byte ambiguity. -/
theorem parseStackOpFuel_ifOp_some_cons
    (fuel : Nat) (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
    (hThn : AreRunarEmittable thn)
    (hEls : AreRunarEmittable (elsHead :: elsTail))
    (hFuelThn : thn.length ≤ fuel)
    (hFuelEls : (elsHead :: elsTail).length ≤ fuel)
    (rest : List UInt8) :
    parseStackOpFuel (fuel + 2)
        (emitStackOpL (.ifOp thn (some (elsHead :: elsTail))) ++ rest)
      = .ok (.ifOp thn (some (elsHead :: elsTail)), rest) := by
  rw [show emitStackOpL (.ifOp thn (some (elsHead :: elsTail))) ++ rest
        = 0x63 :: (emitOpsL thn ++
            (0x67 :: (emitOpsL (elsHead :: elsTail) ++ (0x68 :: rest)))) by
      simp [emitStackOpL, List.append_assoc]]
  simp [parseStackOpFuel]
  rw [parseOpsFuel_emit_round_trip_with_stop_byte thn hThn fuel hFuelThn
        0x67 (by left; rfl) (emitOpsL (elsHead :: elsTail) ++ (0x68 :: rest))]
  rw [parsePushVal?_OP_IF]
  simp
  rw [parseOpsFuel_emit_round_trip_with_stop_byte (elsHead :: elsTail) hEls fuel
        hFuelEls 0x68 (by right; rfl) rest]
  rfl

/-- Top-level fuel round-trip for a singleton `ifOp` with no else branch. -/
theorem parseOpsFuel_emit_singleton_ifOp_none
    (fuel : Nat) (thn : List StackOp)
    (hThn : AreRunarEmittable thn) (hFuelThn : thn.length ≤ fuel) :
    parseOpsFuel (fuel + 3) (emitOpsL [.ifOp thn none]) false
      = .ok ([.ifOp thn none], []) := by
  rw [show emitOpsL [.ifOp thn none]
        = 0x63 :: (emitOpsL thn ++ [0x68]) by
      simp [emitOpsL, emitStackOpL]]
  rw [parseOpsFuel_cons_unfold (fuel + 2) 0x63
        (emitOpsL thn ++ [0x68])]
  rw [show 0x63 :: (emitOpsL thn ++ [0x68])
        = emitStackOpL (.ifOp thn none) ++ [] by
      simp [emitStackOpL]]
  rw [parseStackOpFuel_ifOp_none fuel thn hThn hFuelThn []]
  rfl

/-- Top-level list parser round-trip for a singleton `ifOp` with no else branch. -/
theorem parseOps_emit_singleton_ifOp_none
    (thn : List StackOp) (hThn : AreRunarEmittable thn) :
    parseOps (emitOpsL [.ifOp thn none]) = .ok [.ifOp thn none] := by
  unfold parseOps
  have hFuelThn : thn.length ≤ (emitOpsL thn).length :=
    emitOpsL_length_ge_ops_length thn hThn
  rw [show (emitOpsL [.ifOp thn none]).length + 1
        = (emitOpsL thn).length + 3 by
      simp [emitOpsL, emitStackOpL, List.length_append]]
  rw [parseOpsFuel_emit_singleton_ifOp_none (emitOpsL thn).length thn
        hThn hFuelThn]

/-- ByteArray/list bridge for a singleton `ifOp` with no else branch. -/
private theorem emitOps_toList_singleton_ifOp_none
    (thn : List StackOp) (hThn : AreRunarEmittable thn) :
    (Emit.emitOps [.ifOp thn none]).toList = emitOpsL [.ifOp thn none] := by
  change (Emit.emitStackOp (.ifOp thn none) ++ Emit.emitOps []).toList
      = emitStackOpL (.ifOp thn none) ++ emitOpsL []
  rw [ByteArray.toList_append]
  have hEmpty : (Emit.emitOps []).toList = [] := by
    unfold Emit.emitOps
    exact ByteArray.toList_empty
  rw [hEmpty]
  simp [Emit.emitStackOp, emitOpsL, emitStackOpL,
    ByteArray.toList_append, ByteArray.toList_mk_singleton,
    emitOps_toList_of_AreRunarEmittable thn hThn]

/-- ByteArray parser round-trip for a singleton `ifOp` with no else branch. -/
theorem parseScript_emit_singleton_ifOp_none
    (thn : List StackOp) (hThn : AreRunarEmittable thn) :
    parseScript (Emit.emitOps [.ifOp thn none]) = .ok [.ifOp thn none] := by
  unfold parseScript
  rw [emitOps_toList_singleton_ifOp_none thn hThn]
  exact parseOps_emit_singleton_ifOp_none thn hThn

/-- Top-level fuel round-trip for a singleton `ifOp` with a non-empty else branch. -/
theorem parseOpsFuel_emit_singleton_ifOp_some_cons
    (fuel : Nat) (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
    (hThn : AreRunarEmittable thn)
    (hEls : AreRunarEmittable (elsHead :: elsTail))
    (hFuelThn : thn.length ≤ fuel)
    (hFuelEls : (elsHead :: elsTail).length ≤ fuel) :
    parseOpsFuel (fuel + 3)
        (emitOpsL [.ifOp thn (some (elsHead :: elsTail))]) false
      = .ok ([.ifOp thn (some (elsHead :: elsTail))], []) := by
  rw [show emitOpsL [.ifOp thn (some (elsHead :: elsTail))]
        = 0x63 ::
            (emitOpsL thn ++ (0x67 :: (emitOpsL (elsHead :: elsTail) ++ [0x68]))) by
      simp [emitOpsL, emitStackOpL, List.append_assoc]]
  rw [parseOpsFuel_cons_unfold (fuel + 2) 0x63
        (emitOpsL thn ++ (0x67 :: (emitOpsL (elsHead :: elsTail) ++ [0x68])))]
  rw [show 0x63 ::
          (emitOpsL thn ++ (0x67 :: (emitOpsL (elsHead :: elsTail) ++ [0x68])))
        = emitStackOpL (.ifOp thn (some (elsHead :: elsTail))) ++ [] by
      simp [emitStackOpL, List.append_assoc]]
  rw [parseStackOpFuel_ifOp_some_cons fuel thn elsHead elsTail
        hThn hEls hFuelThn hFuelEls []]
  rfl

/-- Top-level list parser round-trip for a singleton `ifOp` with a non-empty else branch. -/
theorem parseOps_emit_singleton_ifOp_some_cons
    (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
    (hThn : AreRunarEmittable thn)
    (hEls : AreRunarEmittable (elsHead :: elsTail)) :
    parseOps (emitOpsL [.ifOp thn (some (elsHead :: elsTail))])
      = .ok [.ifOp thn (some (elsHead :: elsTail))] := by
  unfold parseOps
  have hFuelThn0 : thn.length ≤ (emitOpsL thn).length :=
    emitOpsL_length_ge_ops_length thn hThn
  have hFuelEls0 :
      (elsHead :: elsTail).length ≤ (emitOpsL (elsHead :: elsTail)).length :=
    emitOpsL_length_ge_ops_length (elsHead :: elsTail) hEls
  let fuel := (emitOpsL thn).length + (emitOpsL (elsHead :: elsTail)).length + 1
  have hFuelThn : thn.length ≤ fuel := by
    dsimp [fuel]
    exact Nat.le_trans hFuelThn0 (by omega)
  have hFuelEls : (elsHead :: elsTail).length ≤ fuel := by
    dsimp [fuel]
    exact Nat.le_trans hFuelEls0 (by omega)
  rw [show (emitOpsL [.ifOp thn (some (elsHead :: elsTail))]).length + 1
        = fuel + 3 by
      dsimp [fuel]
      simp [emitOpsL, emitStackOpL, List.length_append]
      omega]
  rw [parseOpsFuel_emit_singleton_ifOp_some_cons fuel thn elsHead elsTail
        hThn hEls hFuelThn hFuelEls]

/-- ByteArray/list bridge for a singleton `ifOp` with a non-empty else branch. -/
private theorem emitOps_toList_singleton_ifOp_some_cons
    (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
    (hThn : AreRunarEmittable thn)
    (hEls : AreRunarEmittable (elsHead :: elsTail)) :
    (Emit.emitOps [.ifOp thn (some (elsHead :: elsTail))]).toList
      = emitOpsL [.ifOp thn (some (elsHead :: elsTail))] := by
  change (Emit.emitStackOp (.ifOp thn (some (elsHead :: elsTail))) ++ Emit.emitOps []).toList
      = emitStackOpL (.ifOp thn (some (elsHead :: elsTail))) ++ emitOpsL []
  rw [ByteArray.toList_append]
  have hEmpty : (Emit.emitOps []).toList = [] := by
    unfold Emit.emitOps
    exact ByteArray.toList_empty
  rw [hEmpty]
  simp [Emit.emitStackOp, emitOpsL, emitStackOpL,
    ByteArray.toList_append, ByteArray.toList_mk_singleton,
    emitOps_toList_of_AreRunarEmittable thn hThn,
    emitOps_toList_of_AreRunarEmittable (elsHead :: elsTail) hEls]

/-- ByteArray parser round-trip for a singleton `ifOp` with a non-empty else branch. -/
theorem parseScript_emit_singleton_ifOp_some_cons
    (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
    (hThn : AreRunarEmittable thn)
    (hEls : AreRunarEmittable (elsHead :: elsTail)) :
    parseScript (Emit.emitOps [.ifOp thn (some (elsHead :: elsTail))])
      = .ok [.ifOp thn (some (elsHead :: elsTail))] := by
  unfold parseScript
  rw [emitOps_toList_singleton_ifOp_some_cons thn elsHead elsTail hThn hEls]
  exact parseOps_emit_singleton_ifOp_some_cons thn elsHead elsTail hThn hEls

/-! ### Concrete nested IF smoke case

The generic parser predicate below deliberately stops at one structural
IF layer. This concrete theorem keeps one nested parser path covered
while the recursive predicate design remains open.
-/

theorem parseOps_emit_singleton_nested_ifOp_none_dup :
    parseOps (emitOpsL [.ifOp [.ifOp [.dup] none] none])
      = .ok [.ifOp [.ifOp [.dup] none] none] := rfl

private theorem emitOps_toList_singleton_nested_ifOp_none_dup :
    (Emit.emitOps [.ifOp [.ifOp [.dup] none] none]).toList
      = emitOpsL [.ifOp [.ifOp [.dup] none] none] := by
  simp [Emit.emitOps, Emit.emitStackOp, emitOpsL, emitStackOpL,
    ByteArray.toList_append, ByteArray.toList_mk_singleton]

theorem parseScript_emit_singleton_nested_ifOp_none_dup :
    parseScript (Emit.emitOps [.ifOp [.ifOp [.dup] none] none])
      = .ok [.ifOp [.ifOp [.dup] none] none] := by
  unfold parseScript
  rw [emitOps_toList_singleton_nested_ifOp_none_dup]
  exact parseOps_emit_singleton_nested_ifOp_none_dup

theorem parseOps_emit_singleton_nested_ifOp_some_dup_drop_swap :
    parseOps (emitOpsL [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])])
      = .ok [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])] := rfl

private theorem emitOps_toList_singleton_nested_ifOp_some_dup_drop_swap :
    (Emit.emitOps [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])]).toList
      = emitOpsL [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])] := by
  simp [Emit.emitOps, Emit.emitStackOp, emitOpsL, emitStackOpL,
    ByteArray.toList_append, ByteArray.toList_mk_singleton]

theorem parseScript_emit_singleton_nested_ifOp_some_dup_drop_swap :
    parseScript (Emit.emitOps [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])])
      = .ok [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])] := by
  unfold parseScript
  rw [emitOps_toList_singleton_nested_ifOp_some_dup_drop_swap]
  exact parseOps_emit_singleton_nested_ifOp_some_dup_drop_swap

/-! ### List-level structural IF integration

`RunarEmittableWithIf` extends the flat `RunarEmittable` subset with
structural `.ifOp` values whose branch bodies are recursively in the
same subset. The empty-else shape remains excluded because
`.ifOp thn (some [])` emits the same bytes as `.ifOp thn none`.
-/

mutual

inductive RunarEmittableWithIf : StackOp → Prop where
  | flat (op : StackOp) (h : RunarEmittable op) :
      RunarEmittableWithIf op
  | if_none (thn : List StackOp) (hThn : AreRunarEmittableWithIf thn) :
      RunarEmittableWithIf (.ifOp thn none)
  | if_some_cons (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
      (hThn : AreRunarEmittableWithIf thn)
      (hEls : AreRunarEmittableWithIf (elsHead :: elsTail)) :
      RunarEmittableWithIf (.ifOp thn (some (elsHead :: elsTail)))

inductive AreRunarEmittableWithIf : List StackOp → Prop where
  | nil : AreRunarEmittableWithIf []
  | cons (op : StackOp) (rest : List StackOp)
      (hOp : RunarEmittableWithIf op) (hRest : AreRunarEmittableWithIf rest) :
      AreRunarEmittableWithIf (op :: rest)

end

/-! ### F1 decidability for `RunarEmittableWithIf` / `AreRunarEmittableWithIf`

The mutual inductive structure walks both `StackOp` and `List StackOp`.
The Boolean checkers below mirror the mutual recursion using `StackOp`'s
generated structural recursor: the `.ifOp thn els` arm recurses through
both `thn` and (when `els = some (head :: tail)`) the else body. -/

mutual

def runarEmittableWithIfBool : StackOp → Bool
  | .ifOp thn none => areRunarEmittableWithIfBool thn
  | .ifOp _ (some []) => false
  | .ifOp thn (some (h :: t)) =>
      areRunarEmittableWithIfBool thn && areRunarEmittableWithIfBool (h :: t)
  | op => runarEmittableBool op

def areRunarEmittableWithIfBool : List StackOp → Bool
  | [] => true
  | op :: rest => runarEmittableWithIfBool op && areRunarEmittableWithIfBool rest

end

mutual

theorem runarEmittableWithIfBool_iff :
    ∀ (op : StackOp),
      runarEmittableWithIfBool op = true ↔ RunarEmittableWithIf op
  | .ifOp thn none => by
      unfold runarEmittableWithIfBool
      constructor
      · intro h
        exact .if_none thn ((areRunarEmittableWithIfBool_iff thn).mp h)
      · intro h
        cases h with
        | flat _ hFlat => cases hFlat
        | if_none _ hThn => exact (areRunarEmittableWithIfBool_iff thn).mpr hThn
  | .ifOp thn (some []) => by
      unfold runarEmittableWithIfBool
      constructor
      · intro h; exact absurd h (by decide)
      · intro h
        cases h with
        | flat _ hFlat => cases hFlat
  | .ifOp thn (some (eh :: et)) => by
      unfold runarEmittableWithIfBool
      rw [Bool.and_eq_true]
      constructor
      · intro ⟨hThn, hEls⟩
        exact .if_some_cons thn eh et
          ((areRunarEmittableWithIfBool_iff thn).mp hThn)
          ((areRunarEmittableWithIfBool_iff (eh :: et)).mp hEls)
      · intro h
        cases h with
        | flat _ hFlat => cases hFlat
        | if_some_cons _ _ _ hThn hEls =>
            exact ⟨(areRunarEmittableWithIfBool_iff thn).mpr hThn,
                   (areRunarEmittableWithIfBool_iff (eh :: et)).mpr hEls⟩
  | .dup => Iff.intro (fun _ => .flat .dup .dup) (fun _ => rfl)
  | .swap => Iff.intro (fun _ => .flat .swap .swap) (fun _ => rfl)
  | .nip => Iff.intro (fun _ => .flat .nip .nip) (fun _ => rfl)
  | .over => Iff.intro (fun _ => .flat .over .over) (fun _ => rfl)
  | .rot => Iff.intro (fun _ => .flat .rot .rot) (fun _ => rfl)
  | .tuck => Iff.intro (fun _ => .flat .tuck .tuck) (fun _ => rfl)
  | .drop => Iff.intro (fun _ => .flat .drop .drop) (fun _ => rfl)
  | .roll d => by
      unfold runarEmittableWithIfBool
      rw [show runarEmittableBool (.roll d) = decide (1 ≤ d ∧ d ≤ 16) from rfl]
      constructor
      · intro h; exact .flat _ (.roll d (of_decide_eq_true h))
      · intro h
        cases h with
        | flat _ hFlat =>
            cases hFlat with
            | roll _ hd => exact decide_eq_true hd
  | .pick d => by
      unfold runarEmittableWithIfBool
      rw [show runarEmittableBool (.pick d) = decide (1 ≤ d ∧ d ≤ 16) from rfl]
      constructor
      · intro h; exact .flat _ (.pick d (of_decide_eq_true h))
      · intro h
        cases h with
        | flat _ hFlat =>
            cases hFlat with
            | pick _ hd => exact decide_eq_true hd
  | .opcode name => by
      unfold runarEmittableWithIfBool
      rw [show runarEmittableBool (.opcode name) = isAllowedOpcodeName name from rfl]
      constructor
      · intro h; exact .flat _ (.opcode name h)
      · intro h
        cases h with
        | flat _ hFlat =>
            cases hFlat with
            | opcode _ hAllow => exact hAllow
  | .push v => by
      unfold runarEmittableWithIfBool
      simp [runarEmittableBool]
      intro h
      cases h with
      | flat _ hFlat => cases hFlat
  | .pickStruct d => by
      unfold runarEmittableWithIfBool
      simp [runarEmittableBool]
      intro h
      cases h with
      | flat _ hFlat => cases hFlat
  | .placeholder i n => by
      unfold runarEmittableWithIfBool
      simp [runarEmittableBool]
      intro h
      cases h with
      | flat _ hFlat => cases hFlat
  | .pushCodesepIndex => by
      unfold runarEmittableWithIfBool
      simp [runarEmittableBool]
      intro h
      cases h with
      | flat _ hFlat => cases hFlat
  | .rawBytes _ => by
      unfold runarEmittableWithIfBool
      simp [runarEmittableBool]
      intro h
      cases h with
      | flat _ hFlat => cases hFlat

theorem areRunarEmittableWithIfBool_iff :
    ∀ (ops : List StackOp),
      areRunarEmittableWithIfBool ops = true ↔ AreRunarEmittableWithIf ops
  | [] => ⟨fun _ => .nil, fun _ => rfl⟩
  | op :: rest => by
    unfold areRunarEmittableWithIfBool
    rw [Bool.and_eq_true]
    constructor
    · intro ⟨hHead, hRest⟩
      exact .cons op rest
        ((runarEmittableWithIfBool_iff op).mp hHead)
        ((areRunarEmittableWithIfBool_iff rest).mp hRest)
    · intro h
      cases h with
      | cons _ _ hOp hRest =>
          exact ⟨(runarEmittableWithIfBool_iff op).mpr hOp,
                 (areRunarEmittableWithIfBool_iff rest).mpr hRest⟩

end

instance runarEmittableWithIf_decidable (op : StackOp) :
    Decidable (RunarEmittableWithIf op) :=
  decidable_of_iff (runarEmittableWithIfBool op = true)
    (runarEmittableWithIfBool_iff op)

instance areRunarEmittableWithIf_decidable (ops : List StackOp) :
    Decidable (AreRunarEmittableWithIf ops) :=
  decidable_of_iff (areRunarEmittableWithIfBool ops = true)
    (areRunarEmittableWithIfBool_iff ops)

theorem RunarEmittable.toWithIf (op : StackOp) (h : RunarEmittable op) :
    RunarEmittableWithIf op :=
  .flat op h

theorem AreRunarEmittable.toWithIf :
    ∀ (ops : List StackOp), AreRunarEmittable ops → AreRunarEmittableWithIf ops
  | [], .nil => .nil
  | op :: rest, .cons _ _ hOp hRest =>
      .cons op rest (.flat op hOp) (AreRunarEmittable.toWithIf rest hRest)

private theorem emitStackOpL_cons_of_RunarEmittableWithIf
    (op : StackOp) (hOp : RunarEmittableWithIf op) :
    ∃ b tail, emitStackOpL op = b :: tail := by
  cases hOp with
  | flat op h => exact emitStackOpL_cons_of_RunarEmittable op h
  | if_none thn hThn =>
      exact ⟨0x63, emitOpsL thn ++ [0x68], by simp [emitStackOpL]⟩
  | if_some_cons thn elsHead elsTail hThn hEls =>
      exact ⟨0x63,
        emitOpsL thn ++ (0x67 :: (emitOpsL (elsHead :: elsTail) ++ [0x68])),
        by simp [emitStackOpL]⟩

private theorem emitStackOpL_length_pos_of_RunarEmittableWithIf
    (op : StackOp) (hOp : RunarEmittableWithIf op) :
    1 ≤ (emitStackOpL op).length := by
  obtain ⟨b, tail, hHead⟩ := emitStackOpL_cons_of_RunarEmittableWithIf op hOp
  rw [hHead]
  simp

private theorem head_of_emitStackOpL_not_else_or_endif_with_if
    (op : StackOp) (hOp : RunarEmittableWithIf op) :
    ∀ b tail, emitStackOpL op = b :: tail → b ≠ 0x67 ∧ b ≠ 0x68 := by
  cases hOp with
  | flat op h =>
      exact head_of_emitStackOpL_not_else_or_endif op h
  | if_none thn hThn =>
      intro b tail h
      injection h with hb _
      subst hb
      exact ⟨by decide, by decide⟩
  | if_some_cons thn elsHead elsTail hThn hEls =>
      intro b tail h
      injection h with hb _
      subst hb
      exact ⟨by decide, by decide⟩

mutual

/-- A single op in the integrated predicate round-trips with any fuel at least
as large as its emitted byte length. -/
private theorem parseStackOpFuel_emit_round_trip_with_if
    (op : StackOp) (hOp : RunarEmittableWithIf op)
    (fuel : Nat) (hFuel : (emitStackOpL op).length ≤ fuel)
    (rest : List UInt8) :
    parseStackOpFuel fuel (emitStackOpL op ++ rest) = .ok (op, rest) := by
  cases hOp with
  | flat op h =>
      have hFuelPos : 1 ≤ fuel := by
        have hLen := emitStackOpL_length_pos_of_RunarEmittableWithIf op (.flat op h)
        omega
      obtain ⟨fuel', rfl⟩ : ∃ k, fuel = k + 1 := ⟨fuel - 1, by omega⟩
      exact parseStackOp_emit_round_trip fuel' op rest h
  | if_none thn hThn =>
      have hFuel2 : 2 ≤ fuel := by
        have hLen : (emitOpsL thn).length + 2 ≤ fuel := by
          simpa [emitStackOpL, List.length_append] using hFuel
        omega
      obtain ⟨fuel', hFuelEq⟩ : ∃ k, fuel = k + 2 := ⟨fuel - 2, by omega⟩
      subst fuel
      have hFuelThn : (emitOpsL thn).length ≤ fuel' := by
        have hLen : (emitOpsL thn).length + 2 ≤ fuel' + 2 := by
          simpa [emitStackOpL, List.length_append] using hFuel
        omega
      rw [show emitStackOpL (.ifOp thn none) ++ rest
            = 0x63 :: (emitOpsL thn ++ (0x68 :: rest)) by
          simp [emitStackOpL, List.append_assoc]]
      simp [parseStackOpFuel]
      rw [parseOpsFuel_emit_round_trip_with_if_stop thn hThn fuel'
            hFuelThn 0x68 (by right; rfl) rest]
      rw [parsePushVal?_OP_IF]
      rfl
  | if_some_cons thn elsHead elsTail hThn hEls =>
      have hFuel2 : 2 ≤ fuel := by
        have hLen0 := hFuel
        simp [emitStackOpL, List.length_append] at hLen0
        omega
      obtain ⟨fuel', hFuelEq⟩ : ∃ k, fuel = k + 2 := ⟨fuel - 2, by omega⟩
      subst fuel
      have hFuelThn : (emitOpsL thn).length ≤ fuel' := by
        have hLen0 := hFuel
        simp [emitStackOpL, List.length_append] at hLen0
        omega
      have hFuelEls : (emitOpsL (elsHead :: elsTail)).length ≤ fuel' := by
        have hLen0 := hFuel
        simp [emitStackOpL, List.length_append] at hLen0
        omega
      rw [show emitStackOpL (.ifOp thn (some (elsHead :: elsTail))) ++ rest
            = 0x63 :: (emitOpsL thn ++
                (0x67 :: (emitOpsL (elsHead :: elsTail) ++ (0x68 :: rest)))) by
          simp [emitStackOpL, List.append_assoc]]
      simp [parseStackOpFuel]
      rw [parseOpsFuel_emit_round_trip_with_if_stop thn hThn fuel'
            hFuelThn 0x67 (by left; rfl)
            (emitOpsL (elsHead :: elsTail) ++ (0x68 :: rest))]
      rw [parsePushVal?_OP_IF]
      simp
      rw [parseOpsFuel_emit_round_trip_with_if_stop
            (elsHead :: elsTail) hEls fuel' hFuelEls 0x68 (by right; rfl) rest]
      rfl

/-- Top-level fuel round-trip for lists that mix flat emitted ops with
recursive structural IF ops. The fuel is measured in emitted bytes, not
source op count, because IF body parsing consumes nested fuel. -/
theorem parseOpsFuel_emit_round_trip_with_if :
    ∀ (ops : List StackOp), AreRunarEmittableWithIf ops →
      ∀ (fuel : Nat), (emitOpsL ops).length ≤ fuel →
        parseOpsFuel (fuel + 1) (emitOpsL ops) false = .ok (ops, []) := by
  intro ops hOps
  cases hOps with
  | nil =>
      intro fuel hFuel
      rfl
  | cons op rest hOp hRest =>
      intro fuel hFuel
      have hHeadLen := emitStackOpL_length_pos_of_RunarEmittableWithIf op hOp
      have hFuelPos : 1 ≤ fuel := by
        show 1 ≤ fuel
        have hLen : (emitStackOpL op).length + (emitOpsL rest).length ≤ fuel := by
          simpa [emitOpsL, List.length_append] using hFuel
        omega
      obtain ⟨fuel', rfl⟩ : ∃ k, fuel = k + 1 := ⟨fuel - 1, by omega⟩
      obtain ⟨b, opTail, hOpHead⟩ :=
        emitStackOpL_cons_of_RunarEmittableWithIf op hOp
      have hAllBytes : emitOpsL (op :: rest)
          = b :: (opTail ++ emitOpsL rest) := by
        show emitStackOpL op ++ emitOpsL rest = _
        rw [hOpHead]
        rfl
      rw [hAllBytes]
      rw [parseOpsFuel_cons_unfold (fuel' + 1) b (opTail ++ emitOpsL rest)]
      have hHeadBack : b :: (opTail ++ emitOpsL rest)
          = emitStackOpL op ++ emitOpsL rest := by
        rw [hOpHead]
        rfl
      rw [hHeadBack]
      have hOpFuel : (emitStackOpL op).length ≤ fuel' + 1 := by
        have hLen : (emitStackOpL op).length + (emitOpsL rest).length ≤ fuel' + 1 := by
          simpa [emitOpsL, List.length_append] using hFuel
        omega
      rw [parseStackOpFuel_emit_round_trip_with_if op hOp (fuel' + 1) hOpFuel
            (emitOpsL rest)]
      dsimp only
      have hRestFuel : (emitOpsL rest).length ≤ fuel' := by
        have hLen : (emitStackOpL op).length + (emitOpsL rest).length ≤ fuel' + 1 := by
          simpa [emitOpsL, List.length_append] using hFuel
        omega
      rw [parseOpsFuel_emit_round_trip_with_if rest hRest fuel' hRestFuel]

private theorem parseOpsFuel_emit_round_trip_with_if_stop :
    ∀ (ops : List StackOp), AreRunarEmittableWithIf ops →
      ∀ (fuel : Nat), (emitOpsL ops).length ≤ fuel →
        ∀ (s : UInt8), s = 0x67 ∨ s = 0x68 → ∀ (rest : List UInt8),
          parseOpsFuel (fuel + 1) (emitOpsL ops ++ (s :: rest)) true
            = .ok (ops, s :: rest) := by
  intro ops hOps
  cases hOps with
  | nil =>
      intro fuel hFuel s hStop rest
      rcases hStop with h | h <;> subst h <;> rfl
  | cons op rest' hOp hRest =>
      intro fuel hFuel s hStop rest
      have hHeadLen := emitStackOpL_length_pos_of_RunarEmittableWithIf op hOp
      have hFuelPos : 1 ≤ fuel := by
        have hLen : (emitStackOpL op).length + (emitOpsL rest').length ≤ fuel := by
          simpa [emitOpsL, List.length_append] using hFuel
        omega
      obtain ⟨fuel', rfl⟩ : ∃ k, fuel = k + 1 := ⟨fuel - 1, by omega⟩
      obtain ⟨b, opTail, hOpHead⟩ :=
        emitStackOpL_cons_of_RunarEmittableWithIf op hOp
      have hAllBytes :
          emitOpsL (op :: rest') ++ (s :: rest)
          = b :: (opTail ++ emitOpsL rest' ++ (s :: rest)) := by
        show emitStackOpL op ++ emitOpsL rest' ++ (s :: rest) = _
        rw [hOpHead]
        simp [List.cons_append, List.append_assoc]
      rw [hAllBytes]
      have hBnotStop : b ≠ 0x67 ∧ b ≠ 0x68 :=
        head_of_emitStackOpL_not_else_or_endif_with_if op hOp b opTail hOpHead
      rw [parseOpsFuel_cons_unfold_stop (fuel' + 1) b
            (opTail ++ emitOpsL rest' ++ (s :: rest)) hBnotStop]
      have hHeadBack :
          b :: (opTail ++ emitOpsL rest' ++ (s :: rest))
          = emitStackOpL op ++ (emitOpsL rest' ++ (s :: rest)) := by
        rw [hOpHead]
        simp [List.cons_append, List.append_assoc]
      rw [hHeadBack]
      have hOpFuel : (emitStackOpL op).length ≤ fuel' + 1 := by
        have hLen : (emitStackOpL op).length + (emitOpsL rest').length ≤ fuel' + 1 := by
          simpa [emitOpsL, List.length_append] using hFuel
        omega
      rw [parseStackOpFuel_emit_round_trip_with_if op hOp (fuel' + 1) hOpFuel
            (emitOpsL rest' ++ (s :: rest))]
      dsimp only
      have hRestFuel : (emitOpsL rest').length ≤ fuel' := by
        have hLen : (emitStackOpL op).length + (emitOpsL rest').length ≤ fuel' + 1 := by
          simpa [emitOpsL, List.length_append] using hFuel
        omega
      rw [parseOpsFuel_emit_round_trip_with_if_stop rest' hRest fuel' hRestFuel s hStop rest]

end

/-- Top-level list parser round-trip for the integrated structural IF subset. -/
theorem parseOps_emit_round_trip_with_if
    (ops : List StackOp) (hOps : AreRunarEmittableWithIf ops) :
    parseOps (emitOpsL ops) = .ok ops := by
  unfold parseOps
  rw [parseOpsFuel_emit_round_trip_with_if ops hOps (emitOpsL ops).length (Nat.le_refl _)]

mutual

private theorem emitStackOp_toList_of_RunarEmittableWithIf
    (op : StackOp) (hOp : RunarEmittableWithIf op) :
    (Emit.emitStackOp op).toList = emitStackOpL op := by
  cases hOp with
  | flat op h => exact emitStackOp_toList_of_RunarEmittable op h
  | if_none thn hThn =>
      simp [Emit.emitStackOp, emitStackOpL, ByteArray.toList_append,
        ByteArray.toList_mk_singleton,
        emitOps_toList_of_AreRunarEmittableWithIf thn hThn]
  | if_some_cons thn elsHead elsTail hThn hEls =>
      simp [Emit.emitStackOp, emitStackOpL, ByteArray.toList_append,
        ByteArray.toList_mk_singleton,
        emitOps_toList_of_AreRunarEmittableWithIf thn hThn,
        emitOps_toList_of_AreRunarEmittableWithIf (elsHead :: elsTail) hEls]

/-- ByteArray/list bridge for the integrated structural IF subset. -/
theorem emitOps_toList_of_AreRunarEmittableWithIf
    (ops : List StackOp) (hOps : AreRunarEmittableWithIf ops) :
    (Emit.emitOps ops).toList = emitOpsL ops := by
  cases hOps with
  | nil =>
      unfold Emit.emitOps emitOpsL
      exact ByteArray.toList_empty
  | cons op rest hOp hRest =>
      change (Emit.emitStackOp op ++ Emit.emitOps rest).toList
        = emitStackOpL op ++ emitOpsL rest
      rw [ByteArray.toList_append,
        emitStackOp_toList_of_RunarEmittableWithIf op hOp,
        emitOps_toList_of_AreRunarEmittableWithIf rest hRest]

end

/-- ByteArray parser round-trip for the integrated structural IF subset. -/
theorem parseScript_emit_round_trip_with_if
    (ops : List StackOp) (hOps : AreRunarEmittableWithIf ops) :
    parseScript (Emit.emitOps ops) = .ok ops := by
  unfold parseScript
  rw [emitOps_toList_of_AreRunarEmittableWithIf ops hOps]
  exact parseOps_emit_round_trip_with_if ops hOps

/-! ### Normalized push integration

Pushes cannot be admitted into an exact inverse predicate without extra
information: `OP_0`, `OP_1NEGATE`, and `OP_1..OP_16` intentionally
normalise bools, small byte payloads, and small ints to
`.push (.bigint ...)`, and a push immediately followed by `OP_PICK` or
`OP_ROLL` is structurally reconstructed as `.pick` / `.roll`.

The conservative predicate below therefore proves the useful statement:
for op lists whose pushes have a supplied normalised parse proof, and
whose push tails do not start with `OP_PICK` / `OP_ROLL`, parsing emitted
bytes returns `normalizeOps ops`.
-/

def byteArrayOfList (bs : List UInt8) : ByteArray :=
  ByteArray.mk bs.toArray

def normalizePushVal : PushVal → PushVal
  | .bigint i =>
      if i = -1 ∨ (0 ≤ i ∧ i ≤ 16) then
        .bigint i
      else
        .bytes (byteArrayOfList (encodeScriptNumberL i))
  | .bool b =>
      .bigint (if b then 1 else 0)
  | .bytes bs =>
      match bs.toList with
      | [] => .bigint 0
      | [b] =>
          if 1 ≤ b.toNat ∧ b.toNat ≤ 16 then
            .bigint (Int.ofNat b.toNat)
          else if b = 0x81 then
            .bigint (-1)
          else
            .bytes bs
      | _ :: _ :: _ => .bytes bs

mutual

def normalizeStackOp : StackOp → StackOp
  | .push v => .push (normalizePushVal v)
  | .ifOp thn none => .ifOp (normalizeOps thn) none
  | .ifOp thn (some []) => .ifOp (normalizeOps thn) none
  | .ifOp thn (some els) => .ifOp (normalizeOps thn) (some (normalizeOps els))
  | op => op

def normalizeOps : List StackOp → List StackOp
  | [] => []
  | op :: rest => normalizeStackOp op :: normalizeOps rest

end

def isPushStackOp : StackOp → Bool
  | .push _ => true
  | _ => false

structure NormalizedPushEmittable (v : PushVal) : Prop where
  emitted_cons : ∃ b tail, emitStackOpL (.push v) = b :: tail
  head_not_stop :
    ∀ b tail, emitStackOpL (.push v) = b :: tail → b ≠ 0x67 ∧ b ≠ 0x68
  emit_toList : (Emit.emitStackOp (.push v)).toList = emitStackOpL (.push v)
  parse_normalized :
    ∀ (fuel : Nat) (rest : List UInt8), restNotPickOrRoll rest →
      parseStackOpFuel (fuel + 1) (emitStackOpL (.push v) ++ rest)
        = .ok (.push (normalizePushVal v), rest)

private theorem normalizedPush_bool_false : NormalizedPushEmittable (.bool false) where
  emitted_cons := ⟨0x00, [], rfl⟩
  head_not_stop := by
    intro b tail h
    injection h with hb _
    subst hb
    exact ⟨by decide, by decide⟩
  emit_toList := by
    simp [Emit.emitStackOp, Emit.encodePushVal, Emit.encodePushBool,
      emitStackOpL, encodePushValL, encodePushBoolL, ByteArray.toList_mk_singleton]
  parse_normalized := by
    intro fuel rest hRest
    cases rest with
    | nil => rfl
    | cons b bs =>
        unfold restNotPickOrRoll at hRest
        unfold emitStackOpL encodePushValL encodePushBoolL normalizePushVal
        unfold parseStackOpFuel parsePushVal?
        simp [hRest.1, hRest.2]

private theorem normalizedPush_bool_true : NormalizedPushEmittable (.bool true) where
  emitted_cons := ⟨0x51, [], rfl⟩
  head_not_stop := by
    intro b tail h
    injection h with hb _
    subst hb
    exact ⟨by decide, by decide⟩
  emit_toList := by
    simp [Emit.emitStackOp, Emit.encodePushVal, Emit.encodePushBool,
      emitStackOpL, encodePushValL, encodePushBoolL, ByteArray.toList_mk_singleton]
  parse_normalized := by
    intro fuel rest hRest
    cases rest with
    | nil => rfl
    | cons b bs =>
        unfold restNotPickOrRoll at hRest
        unfold emitStackOpL encodePushValL encodePushBoolL normalizePushVal
        unfold parseStackOpFuel parsePushVal?
        simp [hRest.1, hRest.2]

theorem normalizedPush_bool (b : Bool) : NormalizedPushEmittable (.bool b) := by
  cases b
  · exact normalizedPush_bool_false
  · exact normalizedPush_bool_true

theorem normalizedPush_bytes_empty :
    NormalizedPushEmittable (.bytes (ByteArray.mk #[])) where
  emitted_cons := by
    unfold emitStackOpL encodePushValL encodePushBytesL
    simp [ByteArray.toList_eq_data_toList]
  head_not_stop := by
    intro b tail h
    unfold emitStackOpL encodePushValL encodePushBytesL at h
    simp [ByteArray.toList_eq_data_toList] at h
    rcases h with ⟨hb, _⟩
    subst b
    exact ⟨by decide, by decide⟩
  emit_toList := by
    native_decide
  parse_normalized := by
    intro fuel rest hRest
    cases rest with
    | nil =>
        unfold emitStackOpL encodePushValL encodePushBytesL normalizePushVal
        unfold parseStackOpFuel parsePushVal?
        simp [ByteArray.toList_eq_data_toList]
    | cons b bs =>
        unfold restNotPickOrRoll at hRest
        unfold emitStackOpL encodePushValL encodePushBytesL normalizePushVal
        unfold parseStackOpFuel parsePushVal?
        simp [ByteArray.toList_eq_data_toList, hRest.1, hRest.2]

private theorem normalizePushVal_bigint_small_eq
    (i : Int) (h : i = -1 ∨ (0 ≤ i ∧ i ≤ 16)) :
    normalizePushVal (.bigint i) = .bigint i := by
  simp [normalizePushVal, h]

private theorem parseStackOpFuel_push_bigint_small_normalized
    (fuel : Nat) (rest : List UInt8) (i : Int)
    (h : i = -1 ∨ (0 ≤ i ∧ i ≤ 16)) (hRest : restNotPickOrRoll rest) :
    parseStackOpFuel (fuel + 1) (emitStackOpL (.push (.bigint i)) ++ rest)
      = .ok (.push (.bigint i), rest) := by
  have hCases :
      i = -1 ∨ i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨
        i = 6 ∨ i = 7 ∨ i = 8 ∨ i = 9 ∨ i = 10 ∨ i = 11 ∨ i = 12 ∨
        i = 13 ∨ i = 14 ∨ i = 15 ∨ i = 16 := by
    omega
  rcases hCases with
    hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI |
    hI | hI | hI | hI <;> subst i <;> cases rest with
    | nil => rfl
    | cons b bs =>
        unfold restNotPickOrRoll at hRest
        unfold emitStackOpL encodePushValL encodePushBigIntL
        unfold parseStackOpFuel parsePushVal?
        simp [hRest.1, hRest.2]

private theorem emitStackOpL_push_bigint_small_cons
    (i : Int) (h : i = -1 ∨ (0 ≤ i ∧ i ≤ 16)) :
    ∃ b tail, emitStackOpL (.push (.bigint i)) = b :: tail := by
  have hCases :
      i = -1 ∨ i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨
        i = 6 ∨ i = 7 ∨ i = 8 ∨ i = 9 ∨ i = 10 ∨ i = 11 ∨ i = 12 ∨
        i = 13 ∨ i = 14 ∨ i = 15 ∨ i = 16 := by
    omega
  rcases hCases with
    hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI |
    hI | hI | hI | hI <;> subst i
  · exact ⟨0x4f, [], rfl⟩
  · exact ⟨0x00, [], rfl⟩
  · exact ⟨0x51, [], rfl⟩
  · exact ⟨0x52, [], rfl⟩
  · exact ⟨0x53, [], rfl⟩
  · exact ⟨0x54, [], rfl⟩
  · exact ⟨0x55, [], rfl⟩
  · exact ⟨0x56, [], rfl⟩
  · exact ⟨0x57, [], rfl⟩
  · exact ⟨0x58, [], rfl⟩
  · exact ⟨0x59, [], rfl⟩
  · exact ⟨0x5a, [], rfl⟩
  · exact ⟨0x5b, [], rfl⟩
  · exact ⟨0x5c, [], rfl⟩
  · exact ⟨0x5d, [], rfl⟩
  · exact ⟨0x5e, [], rfl⟩
  · exact ⟨0x5f, [], rfl⟩
  · exact ⟨0x60, [], rfl⟩

private theorem head_not_stop_push_bigint_small
    (i : Int) (h : i = -1 ∨ (0 ≤ i ∧ i ≤ 16)) :
    ∀ b tail, emitStackOpL (.push (.bigint i)) = b :: tail → b ≠ 0x67 ∧ b ≠ 0x68 := by
  have hCases :
      i = -1 ∨ i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨
        i = 6 ∨ i = 7 ∨ i = 8 ∨ i = 9 ∨ i = 10 ∨ i = 11 ∨ i = 12 ∨
        i = 13 ∨ i = 14 ∨ i = 15 ∨ i = 16 := by
    omega
  rcases hCases with
    hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI |
    hI | hI | hI | hI <;> subst i
  all_goals
    intro b' tail' hHead
    injection hHead with hb _
    subst hb
    exact ⟨by decide, by decide⟩

private theorem emitStackOp_toList_push_bigint_small
    (i : Int) (h : i = -1 ∨ (0 ≤ i ∧ i ≤ 16)) :
    (Emit.emitStackOp (.push (.bigint i))).toList = emitStackOpL (.push (.bigint i)) := by
  have hCases :
      i = -1 ∨ i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨
        i = 6 ∨ i = 7 ∨ i = 8 ∨ i = 9 ∨ i = 10 ∨ i = 11 ∨ i = 12 ∨
        i = 13 ∨ i = 14 ∨ i = 15 ∨ i = 16 := by
    omega
  rcases hCases with
    hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI | hI |
    hI | hI | hI | hI <;> subst i <;>
    simp [Emit.emitStackOp, Emit.encodePushVal, Emit.encodePushBigInt,
      emitStackOpL, encodePushValL, encodePushBigIntL, ByteArray.toList_mk_singleton]

theorem normalizedPush_bigint_small
    (i : Int) (h : i = -1 ∨ (0 ≤ i ∧ i ≤ 16)) :
    NormalizedPushEmittable (.bigint i) where
  emitted_cons := emitStackOpL_push_bigint_small_cons i h
  head_not_stop := head_not_stop_push_bigint_small i h
  emit_toList := emitStackOp_toList_push_bigint_small i h
  parse_normalized := by
    intro fuel rest hRest
    rw [normalizePushVal_bigint_small_eq i h]
    exact parseStackOpFuel_push_bigint_small_normalized fuel rest i h hRest

private theorem encodeScriptNumberL_17 : encodeScriptNumberL 17 = [0x11] := by
  native_decide

private theorem normalizePushVal_bigint_17_eq :
    normalizePushVal (.bigint 17) = .bytes (byteArrayOfList [0x11]) := by
  simp [normalizePushVal, encodeScriptNumberL_17]

private theorem emitStackOpL_push_bigint_17_eq :
    emitStackOpL (.push (.bigint 17)) = 0x01 :: [0x11] := by
  native_decide

theorem normalizedPush_bigint_17 : NormalizedPushEmittable (.bigint 17) where
  emitted_cons := ⟨0x01, [0x11], emitStackOpL_push_bigint_17_eq⟩
  head_not_stop := by
    intro b tail h
    rw [emitStackOpL_push_bigint_17_eq] at h
    injection h with hb _
    subst hb
    exact ⟨by decide, by decide⟩
  emit_toList := by
    native_decide
  parse_normalized := by
    intro fuel rest hRest
    cases rest with
    | nil =>
        rw [emitStackOpL_push_bigint_17_eq, normalizePushVal_bigint_17_eq]
        unfold parseStackOpFuel parsePushVal? takeBytes decodeLiteralPush
        simp [Bind.bind, Except.bind, takeBytes, byteArrayOfList]
    | cons b bs =>
        change b ≠ 0x7a ∧ b ≠ 0x79 at hRest
        rw [emitStackOpL_push_bigint_17_eq, normalizePushVal_bigint_17_eq]
        unfold parseStackOpFuel parsePushVal? takeBytes decodeLiteralPush
        simp [Bind.bind, Except.bind, takeBytes, byteArrayOfList, hRest.1, hRest.2]

private theorem encodeScriptNumberL_128 : encodeScriptNumberL 128 = [0x80, 0x00] := by
  native_decide

private theorem normalizePushVal_bigint_128_eq :
    normalizePushVal (.bigint 128) = .bytes (byteArrayOfList [0x80, 0x00]) := by
  simp [normalizePushVal, encodeScriptNumberL_128]

private theorem emitStackOpL_push_bigint_128_eq :
    emitStackOpL (.push (.bigint 128)) = 0x02 :: [0x80, 0x00] := by
  native_decide

theorem normalizedPush_bigint_128 : NormalizedPushEmittable (.bigint 128) where
  emitted_cons := ⟨0x02, [0x80, 0x00], emitStackOpL_push_bigint_128_eq⟩
  head_not_stop := by
    intro b tail h
    rw [emitStackOpL_push_bigint_128_eq] at h
    injection h with hb _
    subst hb
    exact ⟨by decide, by decide⟩
  emit_toList := by
    native_decide
  parse_normalized := by
    intro fuel rest hRest
    cases rest with
    | nil =>
        rw [emitStackOpL_push_bigint_128_eq, normalizePushVal_bigint_128_eq]
        unfold parseStackOpFuel parsePushVal? takeBytes decodeLiteralPush
        simp [Bind.bind, Except.bind, takeBytes, byteArrayOfList]
    | cons b bs =>
        change b ≠ 0x7a ∧ b ≠ 0x79 at hRest
        rw [emitStackOpL_push_bigint_128_eq, normalizePushVal_bigint_128_eq]
        unfold parseStackOpFuel parsePushVal? takeBytes decodeLiteralPush
        simp [Bind.bind, Except.bind, takeBytes, byteArrayOfList, hRest.1, hRest.2]

private theorem normalizePushVal_bytes_aa_bb_eq :
    normalizePushVal (.bytes (ByteArray.mk #[0xaa, 0xbb]))
      = .bytes (ByteArray.mk #[0xaa, 0xbb]) := by
  unfold normalizePushVal
  simp [ByteArray.toList_eq_data_toList]

private theorem emitStackOpL_push_bytes_aa_bb_eq :
    emitStackOpL (.push (.bytes (ByteArray.mk #[0xaa, 0xbb])))
      = 0x02 :: [0xaa, 0xbb] := by
  native_decide

theorem normalizedPush_bytes_aa_bb :
    NormalizedPushEmittable (.bytes (ByteArray.mk #[0xaa, 0xbb])) where
  emitted_cons := ⟨0x02, [0xaa, 0xbb], emitStackOpL_push_bytes_aa_bb_eq⟩
  head_not_stop := by
    intro b tail h
    rw [emitStackOpL_push_bytes_aa_bb_eq] at h
    injection h with hb _
    subst hb
    exact ⟨by decide, by decide⟩
  emit_toList := by
    native_decide
  parse_normalized := by
    intro fuel rest hRest
    cases rest with
    | nil =>
        rw [emitStackOpL_push_bytes_aa_bb_eq, normalizePushVal_bytes_aa_bb_eq]
        unfold parseStackOpFuel parsePushVal? takeBytes decodeLiteralPush
        simp [Bind.bind, Except.bind, takeBytes]
    | cons b bs =>
        change b ≠ 0x7a ∧ b ≠ 0x79 at hRest
        rw [emitStackOpL_push_bytes_aa_bb_eq, normalizePushVal_bytes_aa_bb_eq]
        unfold parseStackOpFuel parsePushVal? takeBytes decodeLiteralPush
        simp [Bind.bind, Except.bind, takeBytes, hRest.1, hRest.2]

mutual

inductive RunarEmittableNormalized : StackOp → Prop where
  | flat (op : StackOp) (h : RunarEmittable op) :
      RunarEmittableNormalized op
  | push (v : PushVal) (h : NormalizedPushEmittable v) :
      RunarEmittableNormalized (.push v)
  | if_none (thn : List StackOp) (hThn : AreRunarEmittableNormalized thn) :
      RunarEmittableNormalized (.ifOp thn none)
  | if_some_cons (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
      (hThn : AreRunarEmittableNormalized thn)
      (hEls : AreRunarEmittableNormalized (elsHead :: elsTail)) :
      RunarEmittableNormalized (.ifOp thn (some (elsHead :: elsTail)))

inductive AreRunarEmittableNormalized : List StackOp → Prop where
  | nil : AreRunarEmittableNormalized []
  | cons (op : StackOp) (rest : List StackOp)
      (hOp : RunarEmittableNormalized op)
      (hRest : AreRunarEmittableNormalized rest)
      (hTail : isPushStackOp op = true → restNotPickOrRoll (emitOpsL rest)) :
      AreRunarEmittableNormalized (op :: rest)

end

theorem RunarEmittable.toNormalized (op : StackOp) (h : RunarEmittable op) :
    RunarEmittableNormalized op :=
  .flat op h

theorem AreRunarEmittable.toNormalized :
    ∀ (ops : List StackOp), AreRunarEmittable ops → AreRunarEmittableNormalized ops
  | [], .nil => .nil
  | op :: rest, .cons _ _ hOp hRest =>
      .cons op rest (.flat op hOp) (AreRunarEmittable.toNormalized rest hRest)
        (by intro hPush; cases hOp <;> simp [isPushStackOp] at hPush)

private theorem restNotPickOrRoll_append_stop
    (xs : List UInt8) (hxs : restNotPickOrRoll xs)
    (s : UInt8) (hStop : s = 0x67 ∨ s = 0x68) (tail : List UInt8) :
    restNotPickOrRoll (xs ++ (s :: tail)) := by
  cases xs with
  | nil =>
      rcases hStop with h | h <;> subst h <;> exact ⟨by decide, by decide⟩
  | cons b bs =>
      exact hxs

private theorem emitStackOpL_cons_of_RunarEmittableNormalized
    (op : StackOp) (hOp : RunarEmittableNormalized op) :
    ∃ b tail, emitStackOpL op = b :: tail := by
  cases hOp with
  | flat op h => exact emitStackOpL_cons_of_RunarEmittable op h
  | push v h => exact h.emitted_cons
  | if_none thn hThn =>
      exact ⟨0x63, emitOpsL thn ++ [0x68], by simp [emitStackOpL]⟩
  | if_some_cons thn elsHead elsTail hThn hEls =>
      exact ⟨0x63,
        emitOpsL thn ++ (0x67 :: (emitOpsL (elsHead :: elsTail) ++ [0x68])),
        by simp [emitStackOpL]⟩

private theorem emitStackOpL_length_pos_of_RunarEmittableNormalized
    (op : StackOp) (hOp : RunarEmittableNormalized op) :
    1 ≤ (emitStackOpL op).length := by
  obtain ⟨b, tail, hHead⟩ := emitStackOpL_cons_of_RunarEmittableNormalized op hOp
  rw [hHead]
  simp

private theorem head_of_emitStackOpL_not_else_or_endif_normalized
    (op : StackOp) (hOp : RunarEmittableNormalized op) :
    ∀ b tail, emitStackOpL op = b :: tail → b ≠ 0x67 ∧ b ≠ 0x68 := by
  cases hOp with
  | flat op h => exact head_of_emitStackOpL_not_else_or_endif op h
  | push v h => exact h.head_not_stop
  | if_none thn hThn =>
      intro b tail h
      injection h with hb _
      subst hb
      exact ⟨by decide, by decide⟩
  | if_some_cons thn elsHead elsTail hThn hEls =>
      intro b tail h
      injection h with hb _
      subst hb
      exact ⟨by decide, by decide⟩

private theorem normalizeStackOp_eq_self_of_RunarEmittable
    (op : StackOp) (hOp : RunarEmittable op) :
    normalizeStackOp op = op := by
  cases hOp <;> rfl

mutual

private theorem parseStackOpFuel_emit_round_trip_normalized
    (op : StackOp) (hOp : RunarEmittableNormalized op)
    (fuel : Nat) (hFuel : (emitStackOpL op).length ≤ fuel)
    (rest : List UInt8)
    (hTail : isPushStackOp op = true → restNotPickOrRoll rest) :
    parseStackOpFuel fuel (emitStackOpL op ++ rest)
      = .ok (normalizeStackOp op, rest) := by
  cases hOp with
  | flat op h =>
      have hFuelPos : 1 ≤ fuel := by
        have hLen := emitStackOpL_length_pos_of_RunarEmittableNormalized op (.flat op h)
        omega
      obtain ⟨fuel', rfl⟩ : ∃ k, fuel = k + 1 := ⟨fuel - 1, by omega⟩
      rw [normalizeStackOp_eq_self_of_RunarEmittable op h]
      exact parseStackOp_emit_round_trip fuel' op rest h
  | push v h =>
      have hFuelPos : 1 ≤ fuel := by
        have hLen := emitStackOpL_length_pos_of_RunarEmittableNormalized (.push v) (.push v h)
        omega
      obtain ⟨fuel', rfl⟩ : ∃ k, fuel = k + 1 := ⟨fuel - 1, by omega⟩
      exact h.parse_normalized fuel' rest (hTail rfl)
  | if_none thn hThn =>
      have hFuel2 : 2 ≤ fuel := by
        have hLen : (emitOpsL thn).length + 2 ≤ fuel := by
          simpa [emitStackOpL, List.length_append] using hFuel
        omega
      obtain ⟨fuel', hFuelEq⟩ : ∃ k, fuel = k + 2 := ⟨fuel - 2, by omega⟩
      subst fuel
      have hFuelThn : (emitOpsL thn).length ≤ fuel' := by
        have hLen : (emitOpsL thn).length + 2 ≤ fuel' + 2 := by
          simpa [emitStackOpL, List.length_append] using hFuel
        omega
      rw [show emitStackOpL (.ifOp thn none) ++ rest
            = 0x63 :: (emitOpsL thn ++ (0x68 :: rest)) by
          simp [emitStackOpL, List.append_assoc]]
      simp [parseStackOpFuel]
      rw [parseOpsFuel_emit_round_trip_normalized_stop thn hThn fuel'
            hFuelThn 0x68 (by right; rfl) rest]
      rw [parsePushVal?_OP_IF]
      rfl
  | if_some_cons thn elsHead elsTail hThn hEls =>
      have hFuel2 : 2 ≤ fuel := by
        have hLen0 := hFuel
        simp [emitStackOpL, List.length_append] at hLen0
        omega
      obtain ⟨fuel', hFuelEq⟩ : ∃ k, fuel = k + 2 := ⟨fuel - 2, by omega⟩
      subst fuel
      have hFuelThn : (emitOpsL thn).length ≤ fuel' := by
        have hLen0 := hFuel
        simp [emitStackOpL, List.length_append] at hLen0
        omega
      have hFuelEls : (emitOpsL (elsHead :: elsTail)).length ≤ fuel' := by
        have hLen0 := hFuel
        simp [emitStackOpL, List.length_append] at hLen0
        omega
      rw [show emitStackOpL (.ifOp thn (some (elsHead :: elsTail))) ++ rest
            = 0x63 :: (emitOpsL thn ++
                (0x67 :: (emitOpsL (elsHead :: elsTail) ++ (0x68 :: rest)))) by
          simp [emitStackOpL, List.append_assoc]]
      simp [parseStackOpFuel]
      rw [parseOpsFuel_emit_round_trip_normalized_stop thn hThn fuel'
            hFuelThn 0x67 (by left; rfl)
            (emitOpsL (elsHead :: elsTail) ++ (0x68 :: rest))]
      rw [parsePushVal?_OP_IF]
      simp
      rw [parseOpsFuel_emit_round_trip_normalized_stop
            (elsHead :: elsTail) hEls fuel' hFuelEls 0x68 (by right; rfl) rest]
      rfl

theorem parseOpsFuel_emit_round_trip_normalized :
    ∀ (ops : List StackOp), AreRunarEmittableNormalized ops →
      ∀ (fuel : Nat), (emitOpsL ops).length ≤ fuel →
        parseOpsFuel (fuel + 1) (emitOpsL ops) false
          = .ok (normalizeOps ops, []) := by
  intro ops hOps
  cases hOps with
  | nil =>
      intro fuel hFuel
      rfl
  | cons op rest hOp hRest hTail =>
      intro fuel hFuel
      have hHeadLen := emitStackOpL_length_pos_of_RunarEmittableNormalized op hOp
      have hFuelPos : 1 ≤ fuel := by
        have hLen : (emitStackOpL op).length + (emitOpsL rest).length ≤ fuel := by
          simpa [emitOpsL, List.length_append] using hFuel
        omega
      obtain ⟨fuel', rfl⟩ : ∃ k, fuel = k + 1 := ⟨fuel - 1, by omega⟩
      obtain ⟨b, opTail, hOpHead⟩ :=
        emitStackOpL_cons_of_RunarEmittableNormalized op hOp
      have hAllBytes : emitOpsL (op :: rest)
          = b :: (opTail ++ emitOpsL rest) := by
        show emitStackOpL op ++ emitOpsL rest = _
        rw [hOpHead]
        rfl
      rw [hAllBytes]
      rw [parseOpsFuel_cons_unfold (fuel' + 1) b (opTail ++ emitOpsL rest)]
      have hHeadBack : b :: (opTail ++ emitOpsL rest)
          = emitStackOpL op ++ emitOpsL rest := by
        rw [hOpHead]
        rfl
      rw [hHeadBack]
      have hOpFuel : (emitStackOpL op).length ≤ fuel' + 1 := by
        have hLen : (emitStackOpL op).length + (emitOpsL rest).length ≤ fuel' + 1 := by
          simpa [emitOpsL, List.length_append] using hFuel
        omega
      rw [parseStackOpFuel_emit_round_trip_normalized op hOp (fuel' + 1) hOpFuel
            (emitOpsL rest) hTail]
      dsimp only
      have hRestFuel : (emitOpsL rest).length ≤ fuel' := by
        have hLen : (emitStackOpL op).length + (emitOpsL rest).length ≤ fuel' + 1 := by
          simpa [emitOpsL, List.length_append] using hFuel
        omega
      rw [parseOpsFuel_emit_round_trip_normalized rest hRest fuel' hRestFuel]
      rfl

private theorem parseOpsFuel_emit_round_trip_normalized_stop :
    ∀ (ops : List StackOp), AreRunarEmittableNormalized ops →
      ∀ (fuel : Nat), (emitOpsL ops).length ≤ fuel →
        ∀ (s : UInt8), s = 0x67 ∨ s = 0x68 → ∀ (rest : List UInt8),
          parseOpsFuel (fuel + 1) (emitOpsL ops ++ (s :: rest)) true
            = .ok (normalizeOps ops, s :: rest) := by
  intro ops hOps
  cases hOps with
  | nil =>
      intro fuel hFuel s hStop rest
      rcases hStop with h | h <;> subst h <;> rfl
  | cons op rest' hOp hRest hTail =>
      intro fuel hFuel s hStop rest
      have hHeadLen := emitStackOpL_length_pos_of_RunarEmittableNormalized op hOp
      have hFuelPos : 1 ≤ fuel := by
        have hLen : (emitStackOpL op).length + (emitOpsL rest').length ≤ fuel := by
          simpa [emitOpsL, List.length_append] using hFuel
        omega
      obtain ⟨fuel', rfl⟩ : ∃ k, fuel = k + 1 := ⟨fuel - 1, by omega⟩
      obtain ⟨b, opTail, hOpHead⟩ :=
        emitStackOpL_cons_of_RunarEmittableNormalized op hOp
      have hAllBytes :
          emitOpsL (op :: rest') ++ (s :: rest)
          = b :: (opTail ++ emitOpsL rest' ++ (s :: rest)) := by
        show emitStackOpL op ++ emitOpsL rest' ++ (s :: rest) = _
        rw [hOpHead]
        simp [List.cons_append, List.append_assoc]
      rw [hAllBytes]
      have hBnotStop : b ≠ 0x67 ∧ b ≠ 0x68 :=
        head_of_emitStackOpL_not_else_or_endif_normalized op hOp b opTail hOpHead
      rw [parseOpsFuel_cons_unfold_stop (fuel' + 1) b
            (opTail ++ emitOpsL rest' ++ (s :: rest)) hBnotStop]
      have hHeadBack :
          b :: (opTail ++ emitOpsL rest' ++ (s :: rest))
          = emitStackOpL op ++ (emitOpsL rest' ++ (s :: rest)) := by
        rw [hOpHead]
        simp [List.cons_append, List.append_assoc]
      rw [hHeadBack]
      have hOpFuel : (emitStackOpL op).length ≤ fuel' + 1 := by
        have hLen : (emitStackOpL op).length + (emitOpsL rest').length ≤ fuel' + 1 := by
          simpa [emitOpsL, List.length_append] using hFuel
        omega
      have hPushTail :
          isPushStackOp op = true →
            restNotPickOrRoll (emitOpsL rest' ++ (s :: rest)) := by
        intro hPush
        exact restNotPickOrRoll_append_stop (emitOpsL rest')
          (hTail hPush) s hStop rest
      rw [parseStackOpFuel_emit_round_trip_normalized op hOp (fuel' + 1) hOpFuel
            (emitOpsL rest' ++ (s :: rest)) hPushTail]
      dsimp only
      have hRestFuel : (emitOpsL rest').length ≤ fuel' := by
        have hLen : (emitStackOpL op).length + (emitOpsL rest').length ≤ fuel' + 1 := by
          simpa [emitOpsL, List.length_append] using hFuel
        omega
      rw [parseOpsFuel_emit_round_trip_normalized_stop rest' hRest fuel'
            hRestFuel s hStop rest]
      rfl

end

theorem parseOps_emit_round_trip_normalized
    (ops : List StackOp) (hOps : AreRunarEmittableNormalized ops) :
    parseOps (emitOpsL ops) = .ok (normalizeOps ops) := by
  unfold parseOps
  rw [parseOpsFuel_emit_round_trip_normalized
    ops hOps (emitOpsL ops).length (Nat.le_refl _)]

mutual

private theorem emitStackOp_toList_of_RunarEmittableNormalized
    (op : StackOp) (hOp : RunarEmittableNormalized op) :
    (Emit.emitStackOp op).toList = emitStackOpL op := by
  cases hOp with
  | flat op h => exact emitStackOp_toList_of_RunarEmittable op h
  | push v h => exact h.emit_toList
  | if_none thn hThn =>
      simp [Emit.emitStackOp, emitStackOpL, ByteArray.toList_append,
        ByteArray.toList_mk_singleton,
        emitOps_toList_of_AreRunarEmittableNormalized thn hThn]
  | if_some_cons thn elsHead elsTail hThn hEls =>
      simp [Emit.emitStackOp, emitStackOpL, ByteArray.toList_append,
        ByteArray.toList_mk_singleton,
        emitOps_toList_of_AreRunarEmittableNormalized thn hThn,
        emitOps_toList_of_AreRunarEmittableNormalized (elsHead :: elsTail) hEls]

theorem emitOps_toList_of_AreRunarEmittableNormalized
    (ops : List StackOp) (hOps : AreRunarEmittableNormalized ops) :
    (Emit.emitOps ops).toList = emitOpsL ops := by
  cases hOps with
  | nil =>
      unfold Emit.emitOps emitOpsL
      exact ByteArray.toList_empty
  | cons op rest hOp hRest hTail =>
      change (Emit.emitStackOp op ++ Emit.emitOps rest).toList
        = emitStackOpL op ++ emitOpsL rest
      rw [ByteArray.toList_append,
        emitStackOp_toList_of_RunarEmittableNormalized op hOp,
        emitOps_toList_of_AreRunarEmittableNormalized rest hRest]

end

theorem parseScript_emit_round_trip_normalized
    (ops : List StackOp) (hOps : AreRunarEmittableNormalized ops) :
    parseScript (Emit.emitOps ops) = .ok (normalizeOps ops) := by
  unfold parseScript
  rw [emitOps_toList_of_AreRunarEmittableNormalized ops hOps]
  exact parseOps_emit_round_trip_normalized ops hOps

/-! ### 2-method dispatch chain bytes

The 2-method dispatch chain layout (mirrors
`emitDispatchChain 0 [m0, m1] ++ emitEndifs 1`):

```
[0x76, 0x00, 0x9c, 0x63, 0x75]  -- head non-last (i=0)
<body0 bytes>
[0x67]                           -- OP_ELSE
[0x51, 0x9d]                     -- head last (i=1)
<body1 bytes>
[0x68]                           -- OP_ENDIF
```

This block: list-level dispatch chain emit, parser, and round-trip. -/

/-- The full byte sequence for a 2-method dispatch (list level). -/
def emitDispatch2L (m0 m1 : List StackOp) : List UInt8 :=
  emitDispatchHeadNonLastL 0 ++ emitOpsL m0 ++ emitElseL
    ++ emitDispatchHeadLastL 1 ++ emitOpsL m1 ++ emitEndifsL 1

/-- Auxiliary parser for a 2-method dispatch chain. Reads:
  * head non-last (5 bytes) → confirm index 0,
  * body0 ops (until `OP_ELSE`) via `parseOpsFuel ... true`,
  * the `OP_ELSE` byte,
  * head last (2 bytes) → confirm index 1,
  * body1 ops (until `OP_ENDIF`) via `parseOpsFuel ... true`,
  * the `OP_ENDIF` byte.

Returns `(body0, body1, residual_bytes_after_endif)`. -/
def parseDispatch2Aux (fuel : Nat) (bytes : List UInt8) :
    Except ParseError (List StackOp × List StackOp × List UInt8) := do
  match parseDispatchHeadNonLast? bytes with
  | none =>
      .error (.unknownOpcode (bytes.headD 0))
  | some (i0, after0) =>
      if i0 ≠ 0 then
        .error (.unknownOpcode 0)
      else
        let (body0, afterBody0) ← parseOpsFuel fuel after0 true
        match afterBody0 with
        | 0x67 :: afterElse =>
            match parseDispatchHeadLast? afterElse with
            | none =>
                .error (.unknownOpcode (afterElse.headD 0))
            | some (i1, after1) =>
                if i1 ≠ 1 then
                  .error (.unknownOpcode 1)
                else
                  let (body1, afterBody1) ← parseOpsFuel fuel after1 true
                  match afterBody1 with
                  | 0x68 :: afterEndif =>
                      .ok (body0, body1, afterEndif)
                  | _ => .error .unmatchedIf
        | _ => .error .unmatchedIf

/-- Top-level 2-method dispatch parser. Wraps `parseDispatch2Aux`
with adequate fuel and rejects any trailing bytes. -/
def parseDispatch2 (bytes : List UInt8) :
    Except ParseError (List StackOp × List StackOp) := do
  let (body0, body1, tail) ← parseDispatch2Aux (bytes.length + 1) bytes
  match tail with
  | []     => .ok (body0, body1)
  | b :: _ => .error (.unknownOpcode b)

/-! ### `parseDispatch2` round-trip

For two `AreRunarEmittable` body lists, the bytes produced by
`emitDispatch2L` parse back to those exact two lists. -/

/-- Layout: the dispatch bytes equal the literal head/body/else/head/body/endif
sequence regrouped right-associatively for the parser's left-to-right reads.
Direct definitional reduction with `++` associativity. -/
theorem emitDispatch2L_layout (m0 m1 : List StackOp) :
    emitDispatch2L m0 m1
      = emitDispatchHeadNonLastL 0 ++
          (emitOpsL m0 ++
            (0x67 :: (emitDispatchHeadLastL 1 ++
              (emitOpsL m1 ++ (0x68 :: []))))) := by
  show emitDispatchHeadNonLastL 0 ++ emitOpsL m0 ++ emitElseL
        ++ emitDispatchHeadLastL 1 ++ emitOpsL m1 ++ emitEndifsL 1
      = emitDispatchHeadNonLastL 0 ++
          (emitOpsL m0 ++
            (0x67 :: (emitDispatchHeadLastL 1 ++
              (emitOpsL m1 ++ (0x68 :: [])))))
  -- emitElseL = [0x67]; emitEndifsL 1 = [0x68].
  show emitDispatchHeadNonLastL 0 ++ emitOpsL m0 ++ [0x67]
        ++ emitDispatchHeadLastL 1 ++ emitOpsL m1 ++ [0x68]
      = _
  simp [List.append_assoc, List.cons_append]

/-- The auxiliary driver returns the expected triple on the canonical
2-method dispatch byte sequence. The fuel `fuel` must satisfy
`m0.length + 1 ≤ fuel ∧ m1.length + 1 ≤ fuel`. -/
theorem parseDispatch2Aux_emit_round_trip
    (m0 m1 : List StackOp)
    (hM0 : AreRunarEmittable m0) (hM1 : AreRunarEmittable m1)
    (fuel : Nat) (hFuelM0 : m0.length + 1 ≤ fuel)
    (hFuelM1 : m1.length + 1 ≤ fuel) :
    parseDispatch2Aux fuel (emitDispatch2L m0 m1) = .ok (m0, m1, []) := by
  obtain ⟨fuelPred, rfl⟩ : ∃ k, fuel = k + 1 := by
    refine ⟨fuel - 1, ?_⟩; omega
  have hFPm0 : m0.length ≤ fuelPred := by omega
  have hFPm1 : m1.length ≤ fuelPred := by omega
  rw [emitDispatch2L_layout]
  unfold parseDispatch2Aux
  rw [parseDispatchHeadNonLast?_emit_round_trip_smallI 0 (by omega)]
  -- After the head non-last recogniser succeeds, the outer `match some (0, _)`
  -- arm and the `if 0 ≠ 0` test reduce.
  simp
  -- Apply the body-stop-byte for m0.
  rw [parseOpsFuel_emit_round_trip_with_stop_byte
        m0 hM0 fuelPred hFPm0 0x67 (Or.inl rfl)
        (emitDispatchHeadLastL 1 ++ (emitOpsL m1 ++ (0x68 :: [])))]
  -- Reduce the do-bind on `.ok` (substitutes (m0, 0x67 :: ...) for the bind
  -- variable) and the `0x67 :: ...` cons match arm.
  show
    (match parseDispatchHeadLast?
              (emitDispatchHeadLastL 1 ++ (emitOpsL m1 ++ ((0x68 : UInt8) :: []))) with
     | none =>
         Except.error (ParseError.unknownOpcode
           ((emitDispatchHeadLastL 1 ++ (emitOpsL m1 ++ ((0x68 : UInt8) :: []))).head?.getD 0))
     | some (i1, after1) =>
         if i1 = 1 then
           (do
             let __discr_1 ← parseOpsFuel (fuelPred + 1) after1 true
             match __discr_1.snd with
             | (0x68 : UInt8) :: afterEndif => Except.ok (m0, __discr_1.fst, afterEndif)
             | _ => Except.error ParseError.unmatchedIf)
         else Except.error (ParseError.unknownOpcode 1) : Except ParseError _)
      = Except.ok (m0, m1, [])
  rw [parseDispatchHeadLast?_emit_round_trip_smallI 1 (by omega : 1 ≤ 16)]
  -- The match arm `some (1, after1)` with after1 = emitOpsL m1 ++ [0x68] reduces.
  -- `if 1 = 1` reduces to the then-branch.
  show
    (do
      let __discr_1 ← parseOpsFuel (fuelPred + 1) (emitOpsL m1 ++ ((0x68 : UInt8) :: [])) true
      match __discr_1.snd with
      | (0x68 : UInt8) :: afterEndif => Except.ok (m0, __discr_1.fst, afterEndif)
      | _ => Except.error ParseError.unmatchedIf : Except ParseError _)
      = Except.ok (m0, m1, [])
  rw [parseOpsFuel_emit_round_trip_with_stop_byte
        m1 hM1 fuelPred hFPm1 0x68 (Or.inr rfl) []]
  rfl

/-- Length lemma: the 2-method dispatch byte sequence is at least
`max m0.length m1.length + 6` bytes long. -/
theorem emitDispatch2L_length_lower_bound
    (m0 m1 : List StackOp)
    (hM0 : AreRunarEmittable m0) (hM1 : AreRunarEmittable m1) :
    m0.length + 1 ≤ (emitDispatch2L m0 m1).length + 1 ∧
    m1.length + 1 ≤ (emitDispatch2L m0 m1).length + 1 := by
  have hLen_m0 : m0.length ≤ (emitOpsL m0).length :=
    emitOpsL_length_ge_ops_length m0 hM0
  have hLen_m1 : m1.length ≤ (emitOpsL m1).length :=
    emitOpsL_length_ge_ops_length m1 hM1
  -- Compute (emitDispatch2L m0 m1).length explicitly.
  -- emitDispatch2L = head_non_last(5) ++ emitOpsL m0 ++ [0x67] ++
  --                  head_last(2) ++ emitOpsL m1 ++ [0x68]
  -- Length = 5 + |m0| + 1 + 2 + |m1| + 1.
  have hHeadLen : (emitDispatchHeadNonLastL 0).length = 5 := rfl
  have hLastLen : (emitDispatchHeadLastL 1).length = 2 := rfl
  have hElseLen : emitElseL.length = 1 := rfl
  have hEndifLen : (emitEndifsL 1).length = 1 := rfl
  have hSum : (emitDispatch2L m0 m1).length =
      5 + (emitOpsL m0).length + 1 + 2 + (emitOpsL m1).length + 1 := by
    show ((emitDispatchHeadNonLastL 0 ++ emitOpsL m0 ++ emitElseL
            ++ emitDispatchHeadLastL 1 ++ emitOpsL m1 ++ emitEndifsL 1).length) = _
    rw [List.length_append, List.length_append, List.length_append,
        List.length_append, List.length_append,
        hHeadLen, hLastLen, hElseLen, hEndifLen]
  refine ⟨?_, ?_⟩ <;> rw [hSum] <;> omega

/-- Top-level 2-method dispatch round-trip. -/
theorem parseDispatch2_emit_round_trip
    (m0 m1 : List StackOp)
    (hM0 : AreRunarEmittable m0) (hM1 : AreRunarEmittable m1) :
    parseDispatch2 (emitDispatch2L m0 m1) = .ok (m0, m1) := by
  unfold parseDispatch2
  obtain ⟨hF0, hF1⟩ := emitDispatch2L_length_lower_bound m0 m1 hM0 hM1
  rw [parseDispatch2Aux_emit_round_trip m0 m1 hM0 hM1
        ((emitDispatch2L m0 m1).length + 1) hF0 hF1]
  rfl

/-! ## N-method dispatch generalisation (Tier 3.4 Path B)

Generalises the 2-method machinery above to an arbitrary number of
methods `n ≥ 1`. The chain layout (mirrors `Emit.emitDispatchChain` /
`emitDispatch`):

```
[OP_DUP push(0)   OP_NUMEQUAL OP_IF OP_DROP <body_0>     OP_ELSE]
[OP_DUP push(1)   OP_NUMEQUAL OP_IF OP_DROP <body_1>     OP_ELSE]
…
[OP_DUP push(n-2) OP_NUMEQUAL OP_IF OP_DROP <body_{n-2}> OP_ELSE]
[push(n-1) OP_NUMEQUALVERIFY <body_{n-1}>]
[OP_ENDIF * (n-1)]
```

The dispatch indices `i ∈ [0, n-1]` MUST satisfy `i ≤ 16` for the
literal-push-byte form recognised by
`parseDispatchHeadNonLast?` / `parseDispatchHeadLast?`. The
conformance corpus only exercises ≤ 17 public methods (so all
indices ≤ 16); the `parseDispatchN_emit_round_trip` theorem
explicitly carries this `n ≤ 17` precondition. -/

/-! ### List-level multi-method emit (mirrors `Emit.emitDispatchChain` /
`Emit.emitDispatch`) -/

/-- List-level mirror of `Emit.emitDispatchChain`, but parameterised on a
list-of-bodies (not `StackMethod`s) so it composes with `emitOpsL`. -/
def emitDispatchChainL : Nat → List (List StackOp) → List UInt8
  | _, []          => []
  | i, [m]         => emitDispatchHeadLastL i ++ emitOpsL m
  | i, m :: rest   =>
      emitDispatchHeadNonLastL i ++ emitOpsL m ++ emitElseL
        ++ emitDispatchChainL (i + 1) rest

/-- List-level mirror of `Emit.emitDispatch` for a list of method bodies. -/
def emitDispatchNL (ms : List (List StackOp)) : List UInt8 :=
  emitDispatchChainL 0 ms ++ emitEndifsL (ms.length - 1)

/-! ### N-method recursive parser

Given a known `n` and a starting dispatch index `i`, walk the chain
bytes:
* `n = 0`: error (the dispatch chain is non-empty by construction).
* `n = 1`: parse `emitDispatchHeadLastL i` (verify index = i), then
  parse the body via `parseOpsFuel ... true` (stops at the first
  `0x67`/`0x68`).
* `n ≥ 2`: parse `emitDispatchHeadNonLastL i` (verify index = i), parse
  the body (stops at the first `0x67`/`0x68`), expect a leading
  `0x67`, then recurse at `i+1` for the remaining `n-1` methods.

Returns the recovered body list and the bytes left after the chain
(which will be `emitEndifsL (n-1) ++ caller_residual`). -/
def parseDispatchChainAux (fuel : Nat) :
    Nat → Nat → List UInt8 → Except ParseError (List (List StackOp) × List UInt8)
  | _, 0,        _     => .error .unmatchedIf
  | i, 1,        bytes =>
      match parseDispatchHeadLast? bytes with
      | none => .error (.unknownOpcode (bytes.headD 0))
      | some (idx, after) =>
          if idx ≠ i then
            .error (.unknownOpcode (UInt8.ofNat i))
          else
            match parseOpsFuel fuel after true with
            | .error e => .error e
            | .ok (body, afterBody) => .ok ([body], afterBody)
  | i, n + 2,    bytes =>
      match parseDispatchHeadNonLast? bytes with
      | none => .error (.unknownOpcode (bytes.headD 0))
      | some (idx, after) =>
          if idx ≠ i then
            .error (.unknownOpcode (UInt8.ofNat i))
          else
            match parseOpsFuel fuel after true with
            | .error e => .error e
            | .ok (body, afterBody) =>
                match afterBody with
                | 0x67 :: afterElse =>
                    match parseDispatchChainAux fuel (i + 1) (n + 1) afterElse with
                    | .error e => .error e
                    | .ok (rest, tail) => .ok (body :: rest, tail)
                | _ => .error .unmatchedIf

/-- Strip exactly `k` leading `0x68` bytes. Used by `parseDispatchN` to
consume the `n-1` trailing `OP_ENDIF`s after the chain. -/
def stripEndifs : Nat → List UInt8 → Except ParseError (List UInt8)
  | 0,     bs              => .ok bs
  | _ + 1, []              => .error .unmatchedIf
  | n + 1, 0x68 :: rest    => stripEndifs n rest
  | _ + 1, b :: _          => .error (.unknownOpcode b)

/-- Top-level N-method dispatch parser. Wraps `parseDispatchChainAux`
and consumes the trailing `n-1` `OP_ENDIF`s. Returns the body list
and any residual bytes after the closing endifs. -/
def parseDispatchN (fuel : Nat) (n : Nat) (bytes : List UInt8) :
    Except ParseError (List (List StackOp) × List UInt8) := do
  let (ms, afterChain) ← parseDispatchChainAux fuel 0 n bytes
  let afterEndifs ← stripEndifs (n - 1) afterChain
  .ok (ms, afterEndifs)

/-! ### N-method round-trip layout helpers -/

/-- Layout of `emitDispatchChainL` for a non-empty list `m :: m' :: rest`.
The non-last shape always extracts a head + body + ELSE + tail-chain. -/
private theorem emitDispatchChainL_cons_cons
    (i : Nat) (m m' : List StackOp) (rest : List (List StackOp)) :
    emitDispatchChainL i (m :: m' :: rest)
      = emitDispatchHeadNonLastL i ++
          (emitOpsL m ++
            (0x67 :: emitDispatchChainL (i + 1) (m' :: rest))) := by
  show emitDispatchHeadNonLastL i ++ emitOpsL m ++ emitElseL
        ++ emitDispatchChainL (i + 1) (m' :: rest)
      = emitDispatchHeadNonLastL i ++
          (emitOpsL m ++
            (0x67 :: emitDispatchChainL (i + 1) (m' :: rest)))
  show emitDispatchHeadNonLastL i ++ emitOpsL m ++ [0x67]
        ++ emitDispatchChainL (i + 1) (m' :: rest) = _
  simp [List.append_assoc, List.cons_append]

/-- Singleton chain layout: `emitDispatchChainL i [m]
    = emitDispatchHeadLastL i ++ emitOpsL m`. -/
private theorem emitDispatchChainL_singleton (i : Nat) (m : List StackOp) :
    emitDispatchChainL i [m] = emitDispatchHeadLastL i ++ emitOpsL m := rfl

/-! `AreRunarEmittable` lifted pointwise to a list-of-bodies. -/

/-- All bodies in a method list are `AreRunarEmittable`. -/
def AllAreRunarEmittable (ms : List (List StackOp)) : Prop :=
  ∀ m ∈ ms, AreRunarEmittable m

theorem AllAreRunarEmittable_head {m : List StackOp} {ms : List (List StackOp)}
    (h : AllAreRunarEmittable (m :: ms)) : AreRunarEmittable m := by
  apply h; exact List.Mem.head _

theorem AllAreRunarEmittable_tail {m : List StackOp} {ms : List (List StackOp)}
    (h : AllAreRunarEmittable (m :: ms)) : AllAreRunarEmittable ms := by
  intro m' hm'
  apply h; exact List.Mem.tail _ hm'

/-! ### Chain auxiliary round-trip

The chain parser, given the canonical chain bytes followed by an
arbitrary `tail`, recovers the body list and returns `tail` itself
(verifying the chain consumes exactly `emitDispatchChainL i ms`).

The `tail` parameter is critical: when called from `parseDispatchN` it
will be `emitEndifsL (n-1) ++ caller_residual`, and the last body's
parse must stop at the first `0x68`. The body-stop-byte lemma needs a
`stopByte ∈ {0x67, 0x68}` to be the head of the post-body bytes —
hence the precondition `tail` starts with `0x67` or `0x68`. -/
private theorem parseDispatchChainAux_emit_round_trip_with_tail
    (ms : List (List StackOp)) (hMs : AllAreRunarEmittable ms)
    (hLen : ms.length ≥ 1)
    (i : Nat) (hI : i + ms.length ≤ 17)
    (fuel : Nat)
    (hFuel : ∀ m ∈ ms, m.length ≤ fuel)
    (s : UInt8) (hStop : s = 0x67 ∨ s = 0x68)
    (rest : List UInt8) :
    parseDispatchChainAux (fuel + 1) i ms.length
        (emitDispatchChainL i ms ++ (s :: rest))
      = .ok (ms, s :: rest) := by
  induction ms generalizing i fuel s rest with
  | nil => exact absurd hLen (by simp)
  | cons m rest_ms ih =>
      match rest_ms with
      | [] =>
          -- Singleton case: ms = [m], parser takes the n=1 branch.
          have hM : AreRunarEmittable m := AllAreRunarEmittable_head hMs
          have hI16 : i ≤ 16 := by
            have h1 : i + 1 ≤ 17 := by simpa [List.length] using hI
            omega
          have hFuelM : m.length ≤ fuel := by
            apply hFuel; exact List.Mem.head _
          show parseDispatchChainAux (fuel + 1) i ([m] : List (List StackOp)).length
                  (emitDispatchChainL i [m] ++ (s :: rest)) = _
          rw [emitDispatchChainL_singleton]
          show parseDispatchChainAux (fuel + 1) i 1
                  ((emitDispatchHeadLastL i ++ emitOpsL m) ++ (s :: rest)) = _
          have hAssoc :
              (emitDispatchHeadLastL i ++ emitOpsL m) ++ (s :: rest)
              = emitDispatchHeadLastL i ++ (emitOpsL m ++ (s :: rest)) := by
            simp [List.append_assoc]
          rw [hAssoc]
          unfold parseDispatchChainAux
          rw [parseDispatchHeadLast?_emit_round_trip_smallI i hI16]
          show
            (if ¬ i = i then
               (Except.error (.unknownOpcode (UInt8.ofNat i))
                 : Except ParseError (List (List StackOp) × List UInt8))
             else
               match parseOpsFuel (fuel + 1) (emitOpsL m ++ (s :: rest)) true with
               | .error e => .error e
               | .ok (body, afterBody) => .ok ([body], afterBody))
              = .ok ([m], s :: rest)
          rw [if_neg (by simp)]
          rw [parseOpsFuel_emit_round_trip_with_stop_byte
                m hM fuel hFuelM s hStop rest]
      | m' :: rest' =>
          -- Non-singleton: ms = m :: m' :: rest', parser takes n+2 branch.
          have hM : AreRunarEmittable m := AllAreRunarEmittable_head hMs
          have hMs' : AllAreRunarEmittable (m' :: rest') :=
            AllAreRunarEmittable_tail hMs
          have hLen' : (m' :: rest').length ≥ 1 := by simp [List.length]
          have hI16 : i ≤ 16 := by
            have h2 : i + (m :: m' :: rest').length ≤ 17 := hI
            simp [List.length] at h2; omega
          have hI' : (i + 1) + (m' :: rest').length ≤ 17 := by
            simp [List.length] at hI ⊢; omega
          have hFuelM : m.length ≤ fuel := by
            apply hFuel; exact List.Mem.head _
          have hFuel' : ∀ mm ∈ (m' :: rest'), mm.length ≤ fuel := by
            intro mm hmm
            apply hFuel; exact List.Mem.tail _ hmm
          rw [emitDispatchChainL_cons_cons]
          show parseDispatchChainAux (fuel + 1) i (m :: m' :: rest').length
                  (emitDispatchHeadNonLastL i ++
                    (emitOpsL m ++
                      (0x67 :: emitDispatchChainL (i + 1) (m' :: rest'))) ++ (s :: rest)) = _
          have hLenEq : (m :: m' :: rest').length = rest'.length + 2 := by
            simp [List.length_cons]
          rw [hLenEq]
          have hAllBytes :
              emitDispatchHeadNonLastL i ++
                (emitOpsL m ++
                  (0x67 :: emitDispatchChainL (i + 1) (m' :: rest'))) ++ (s :: rest)
              = emitDispatchHeadNonLastL i ++
                  (emitOpsL m ++
                    ((0x67 : UInt8) ::
                      (emitDispatchChainL (i + 1) (m' :: rest') ++ (s :: rest)))) := by
            simp [List.append_assoc, List.cons_append]
          rw [hAllBytes]
          unfold parseDispatchChainAux
          -- After unfolding, the parser pattern n+2 matched with n = rest'.length.
          -- The bytes argument is (head_nonlast(i) ++ body ++ trailer), so the head
          -- recogniser fires next. Reduce match + if-i-eq-i:
          rw [parseDispatchHeadNonLast?_emit_round_trip_smallI i hI16]
          show
            (if ¬ i = i then
               (Except.error (.unknownOpcode (UInt8.ofNat i))
                 : Except ParseError (List (List StackOp) × List UInt8))
             else
               (match parseOpsFuel (fuel + 1)
                       (emitOpsL m ++ ((0x67 : UInt8) ::
                         (emitDispatchChainL (i + 1) (m' :: rest') ++ (s :: rest)))) true with
                | .error e => .error e
                | .ok (body, afterBody) =>
                    match afterBody with
                    | 0x67 :: afterElse =>
                        match parseDispatchChainAux (fuel + 1) (i + 1)
                            (rest'.length + 1) afterElse with
                        | .error e => .error e
                        | .ok (msRest, tail') => .ok (body :: msRest, tail')
                    | _ => .error .unmatchedIf))
              = .ok (m :: m' :: rest', s :: rest)
          rw [if_neg (by simp)]
          rw [parseOpsFuel_emit_round_trip_with_stop_byte
                m hM fuel hFuelM 0x67 (Or.inl rfl)
                (emitDispatchChainL (i + 1) (m' :: rest') ++ (s :: rest))]
          show
            (match parseDispatchChainAux (fuel + 1) (i + 1) (rest'.length + 1)
                    (emitDispatchChainL (i + 1) (m' :: rest') ++ (s :: rest)) with
              | .error e => .error e
              | .ok (msRest, tail') => .ok (m :: msRest, tail')
              : Except ParseError (List (List StackOp) × List UInt8))
              = .ok (m :: m' :: rest', s :: rest)
          have hLenSubst : (m' :: rest').length = rest'.length + 1 := by
            simp [List.length_cons]
          have hI'' : (i + 1) + (m' :: rest').length ≤ 17 := hI'
          have ihGoal := ih hMs' hLen' (i + 1) hI'' fuel hFuel' s hStop rest
          rw [hLenSubst] at ihGoal
          rw [ihGoal]

/-- The trailing-endif stripper round-trips on the canonical
`emitEndifsL k ++ tail`. -/
private theorem stripEndifs_emit (k : Nat) (tail : List UInt8) :
    stripEndifs k (emitEndifsL k ++ tail) = .ok tail := by
  induction k with
  | zero => rfl
  | succ k ih =>
      show stripEndifs (k + 1) (((0x68 : UInt8) :: emitEndifsL k) ++ tail) = .ok tail
      show stripEndifs (k + 1) ((0x68 : UInt8) :: (emitEndifsL k ++ tail)) = .ok tail
      unfold stripEndifs
      exact ih

/-- Helper: each body's emitted bytes fit inside the chain length. -/
private theorem emitOpsL_length_le_emitDispatchChainL_of_mem
    (ms : List (List StackOp))
    {m : List StackOp} (hMmem : m ∈ ms) :
    ∀ i, (emitOpsL m).length ≤ (emitDispatchChainL i ms).length := by
  intro i
  induction ms generalizing i with
  | nil => cases hMmem
  | cons m₀ rest ih =>
      cases hMmem with
      | head =>
          -- m = m₀
          match rest with
          | [] =>
              show (emitOpsL m).length ≤ (emitDispatchHeadLastL i ++ emitOpsL m).length
              simp [List.length_append]
          | m' :: rest' =>
              rw [emitDispatchChainL_cons_cons]
              simp [List.length_append, List.length_cons]
              omega
      | tail _ hMmemRest =>
          -- m ∈ rest, rest non-empty
          match rest, hMmemRest with
          | m' :: rest', hMmemRest =>
              have ihApplied : (emitOpsL m).length
                  ≤ (emitDispatchChainL (i + 1) (m' :: rest')).length :=
                ih hMmemRest (i + 1)
              rw [emitDispatchChainL_cons_cons]
              show (emitOpsL m).length
                  ≤ (emitDispatchHeadNonLastL i ++
                      (emitOpsL m₀ ++
                        ((0x67 : UInt8) :: emitDispatchChainL (i + 1) (m' :: rest')))).length
              simp [List.length_append, List.length_cons]
              omega

/-- The N-method emit length is at least each body's length. -/
private theorem emitOpsL_length_le_emitDispatchNL
    (ms : List (List StackOp))
    (m : List StackOp) (hMmem : m ∈ ms) :
    (emitOpsL m).length ≤ (emitDispatchNL ms).length := by
  unfold emitDispatchNL
  rw [List.length_append]
  have h := emitOpsL_length_le_emitDispatchChainL_of_mem ms hMmem 0
  omega

/-- N-method dispatch round-trip. -/
theorem parseDispatchN_emit_round_trip
    (ms : List (List StackOp)) (hMs : AllAreRunarEmittable ms)
    (hLen : ms.length ≥ 1) (hSize : ms.length ≤ 17) :
    parseDispatchN ((emitDispatchNL ms).length + 1) ms.length
        (emitDispatchNL ms)
      = .ok (ms, []) := by
  unfold parseDispatchN emitDispatchNL
  -- emitDispatchNL ms = emitDispatchChainL 0 ms ++ emitEndifsL (ms.length - 1).
  -- The last body's stop byte is the leading 0x68 of emitEndifsL (ms.length - 1)
  -- when ms.length ≥ 2; when ms.length = 1, emitEndifsL 0 = [], which would
  -- break the parseOpsFuel_emit_round_trip_with_stop_byte precondition.
  -- Handle the singleton case separately.
  have hI : 0 + ms.length ≤ 17 := by simpa using hSize
  have hFuelMs : ∀ m ∈ ms, m.length ≤ (emitDispatchNL ms).length := by
    intro m hMmem
    have hMe : AreRunarEmittable m := hMs m hMmem
    have hLenBody : m.length ≤ (emitOpsL m).length :=
      emitOpsL_length_ge_ops_length m hMe
    exact Nat.le_trans hLenBody (emitOpsL_length_le_emitDispatchNL ms m hMmem)
  match ms, hLen with
  | [m], _ =>
      -- Singleton: emitEndifsL 0 = [], so the chain residual after body is [].
      have hM : AreRunarEmittable m := AllAreRunarEmittable_head hMs
      have hFuelM : m.length ≤ (emitDispatchNL [m]).length :=
        hFuelMs m (List.Mem.head _)
      have hENL : emitDispatchNL [m] = emitDispatchHeadLastL 0 ++ emitOpsL m := by
        unfold emitDispatchNL
        show emitDispatchChainL 0 [m]
              ++ emitEndifsL (([m] : List (List StackOp)).length - 1)
            = emitDispatchHeadLastL 0 ++ emitOpsL m
        show emitDispatchChainL 0 [m] ++ emitEndifsL 0
            = emitDispatchHeadLastL 0 ++ emitOpsL m
        rw [emitDispatchChainL_singleton]
        show emitDispatchHeadLastL 0 ++ emitOpsL m ++ ([] : List UInt8)
            = emitDispatchHeadLastL 0 ++ emitOpsL m
        simp
      show
        (do
          let (ms', afterChain) ← parseDispatchChainAux
              ((emitDispatchChainL 0 [m]
                  ++ emitEndifsL (([m] : List (List StackOp)).length - 1)).length + 1)
              0 ([m] : List (List StackOp)).length
              (emitDispatchChainL 0 [m]
                  ++ emitEndifsL (([m] : List (List StackOp)).length - 1))
          let afterEndifs ← stripEndifs (([m] : List (List StackOp)).length - 1) afterChain
          .ok (ms', afterEndifs)
          : Except ParseError _)
          = .ok ([m], [])
      show
        (do
          let (ms', afterChain) ← parseDispatchChainAux
              ((emitDispatchChainL 0 [m]
                  ++ emitEndifsL 0).length + 1) 0 1
              (emitDispatchChainL 0 [m] ++ emitEndifsL 0)
          let afterEndifs ← stripEndifs 0 afterChain
          .ok (ms', afterEndifs)
          : Except ParseError _)
          = .ok ([m], [])
      have hChainNil : emitDispatchChainL 0 [m] ++ emitEndifsL 0
          = emitDispatchHeadLastL 0 ++ emitOpsL m := by
        rw [emitDispatchChainL_singleton]
        show emitDispatchHeadLastL 0 ++ emitOpsL m ++ ([] : List UInt8)
            = emitDispatchHeadLastL 0 ++ emitOpsL m
        simp
      rw [hChainNil]
      have hFuelM' : m.length ≤ (emitDispatchHeadLastL 0 ++ emitOpsL m).length := by
        rw [hENL] at hFuelM; exact hFuelM
      unfold parseDispatchChainAux
      rw [parseDispatchHeadLast?_emit_round_trip_smallI 0 (by omega : 0 ≤ 16)]
      show
        (do
          let (ms', afterChain) ←
            (if ¬ (0 : Nat) = 0 then
               (Except.error (.unknownOpcode (UInt8.ofNat 0))
                 : Except ParseError (List (List StackOp) × List UInt8))
             else
               match parseOpsFuel
                       ((emitDispatchHeadLastL 0 ++ emitOpsL m).length + 1) (emitOpsL m) true with
                | .error e => .error e
                | .ok (body, afterBody) => Except.ok ([body], afterBody))
          let afterEndifs ← stripEndifs 0 afterChain
          .ok (ms', afterEndifs)
          : Except ParseError _)
          = .ok ([m], [])
      rw [if_neg (by simp)]
      rw [parseOpsFuel_emit_round_trip_true_nil m hM
            (emitDispatchHeadLastL 0 ++ emitOpsL m).length hFuelM']
      rfl
  | m₀ :: m₁ :: rest, _ =>
      have hLen2 : (m₀ :: m₁ :: rest).length ≥ 1 := by simp [List.length]
      have hI2 : 0 + (m₀ :: m₁ :: rest).length ≤ 17 := by simpa using hSize
      have hLenSub : (m₀ :: m₁ :: rest).length - 1 = rest.length + 1 := by
        simp [List.length_cons]
      rw [hLenSub]
      have hEndifEq : emitEndifsL (rest.length + 1)
          = (0x68 : UInt8) :: emitEndifsL rest.length := rfl
      rw [hEndifEq]
      -- Rephrase (chain ++ (0x68 :: endif_rest)) so chain-aux fires:
      have hAuxArg :
          emitDispatchChainL 0 (m₀ :: m₁ :: rest)
              ++ ((0x68 : UInt8) :: emitEndifsL rest.length)
          = emitDispatchChainL 0 (m₀ :: m₁ :: rest)
              ++ ((0x68 : UInt8) :: emitEndifsL rest.length) := rfl
      rw [parseDispatchChainAux_emit_round_trip_with_tail
            (m₀ :: m₁ :: rest) hMs hLen2 0 hI2
            (emitDispatchChainL 0 (m₀ :: m₁ :: rest)
              ++ ((0x68 : UInt8) :: emitEndifsL rest.length)).length
            (by
              intro mm hmm
              have h := hFuelMs mm hmm
              -- emitDispatchNL ms = chain 0 ms ++ emitEndifsL (ms.length - 1)
              -- with ms = m₀ :: m₁ :: rest, this is chain ++ (0x68 :: emitEndifsL rest.length)
              have heq :
                  (emitDispatchNL (m₀ :: m₁ :: rest)).length
                  = (emitDispatchChainL 0 (m₀ :: m₁ :: rest)
                      ++ ((0x68 : UInt8) :: emitEndifsL rest.length)).length := by
                show (emitDispatchChainL 0 (m₀ :: m₁ :: rest)
                        ++ emitEndifsL ((m₀ :: m₁ :: rest).length - 1)).length = _
                rw [hLenSub, hEndifEq]
              rw [heq] at h; exact h)
            (s := 0x68) (Or.inr rfl) (emitEndifsL rest.length)]
      show (do
              let afterEndifs ← stripEndifs (rest.length + 1)
                  ((0x68 : UInt8) :: emitEndifsL rest.length)
              .ok (m₀ :: m₁ :: rest, afterEndifs)
            : Except ParseError _) = .ok (m₀ :: m₁ :: rest, [])
      have hStrip : stripEndifs (rest.length + 1)
            ((0x68 : UInt8) :: emitEndifsL rest.length) = .ok [] := by
        show stripEndifs rest.length (emitEndifsL rest.length) = .ok []
        have := stripEndifs_emit rest.length []
        simpa using this
      rw [hStrip]
      rfl

/-! ## `AreRunarEmittableWithIfAndPatches` — wider predicate for C1

Extends `AreRunarEmittableWithIf` by also admitting `pushCodesepIndex`
and `.opcode "OP_CODESEPARATOR"`. These two ops appear in
`compileSafeWithCodeSepPatches`-compiled stateful contracts and are
excluded from `AreRunarEmittableWithIf` because they break the
`emitWithCodeSepPatches → emitFast` byte-equality used in the
no-patch-site round-trip.

This wider predicate is the gate for the C1 round-trip theorem, which
connects `runParsedBytes (emitWithCodeSepPatches ..).bytes` to
`runOpsPc stackM.ops` at the `successAgrees` level.

## Decidability

Defined via Boolean checkers so that the `Decidable` instance is
automatic:

```
AreRunarEmittableWithIfAndPatches ops := areRunarEmittableWithIfAndPatchesL ops = true
```
-/

-- Boolean checkers for the `WithIfAndPatches` class.
-- `isRunarEmittableWithIfAndPatchesOp` mirrors `RunarEmittableWithIf` but adds:
--   * `pushCodesepIndex` — always admitted.
--   * `.opcode "OP_CODESEPARATOR"` — admitted regardless of the 14-name
--     `isAllowedOpcodeName` allowlist.
-- The two functions are mutually recursive because `.ifOp` bodies are lists.
mutual

def isRunarEmittableWithIfAndPatchesOp : StackOp → Bool
  | .dup | .swap | .nip | .over | .rot | .tuck | .drop => true
  | .roll d => decide (1 ≤ d ∧ d ≤ 16)
  | .pick d => decide (1 ≤ d ∧ d ≤ 16)
  | .opcode name => isAllowedOpcodeName name || (name == "OP_CODESEPARATOR")
  | .pushCodesepIndex => true
  | .ifOp thn none => areRunarEmittableWithIfAndPatchesL thn
  | .ifOp thn (some els) =>
      areRunarEmittableWithIfAndPatchesL thn &&
      areRunarEmittableWithIfAndPatchesL els
  | _ => false

def areRunarEmittableWithIfAndPatchesL : List StackOp → Bool
  | [] => true
  | op :: rest =>
      isRunarEmittableWithIfAndPatchesOp op &&
      areRunarEmittableWithIfAndPatchesL rest

end

/-- A list of ops is in the `WithIfAndPatches` class. -/
def AreRunarEmittableWithIfAndPatches (ops : List StackOp) : Prop :=
  areRunarEmittableWithIfAndPatchesL ops = true

instance (ops : List StackOp) : Decidable (AreRunarEmittableWithIfAndPatches ops) :=
  inferInstanceAs (Decidable (areRunarEmittableWithIfAndPatchesL ops = true))

/-! ### Inclusion: `AreRunarEmittableWithIf ⊆ AreRunarEmittableWithIfAndPatches`

Every op admitted by `AreRunarEmittableWithIf` is also admitted by
`AreRunarEmittableWithIfAndPatches`. This gives a monotonicity lemma
free of charge and lets callers narrow from the wider predicate.
-/

-- Mutual inclusion lemmas: `AreRunarEmittableWithIf ⊆ AreRunarEmittableWithIfAndPatches`.
-- Proved by mutual recursion on the WithIf inductive.
mutual

private theorem isRunarEmittableWithIfAndPatchesOp_of_RunarEmittableWithIf
    (op : StackOp) (h : RunarEmittableWithIf op) :
    isRunarEmittableWithIfAndPatchesOp op = true := by
  cases h with
  | flat op hFlat =>
      cases hFlat with
      | dup => rfl
      | swap => rfl
      | nip => rfl
      | over => rfl
      | rot => rfl
      | tuck => rfl
      | drop => rfl
      | roll d hd =>
          simp [isRunarEmittableWithIfAndPatchesOp]; exact ⟨hd.1, hd.2⟩
      | pick d hd =>
          simp [isRunarEmittableWithIfAndPatchesOp]; exact ⟨hd.1, hd.2⟩
      | opcode name hAllow =>
          simp [isRunarEmittableWithIfAndPatchesOp, hAllow]
  | if_none thn hThn =>
      simp [isRunarEmittableWithIfAndPatchesOp,
        areRunarEmittableWithIfAndPatchesL_of_AreRunarEmittableWithIf thn hThn]
  | if_some_cons thn elsHead elsTail hThn hEls =>
      simp [isRunarEmittableWithIfAndPatchesOp,
        areRunarEmittableWithIfAndPatchesL_of_AreRunarEmittableWithIf thn hThn,
        areRunarEmittableWithIfAndPatchesL_of_AreRunarEmittableWithIf
          (elsHead :: elsTail) hEls]

private theorem areRunarEmittableWithIfAndPatchesL_of_AreRunarEmittableWithIf
    (ops : List StackOp) (h : AreRunarEmittableWithIf ops) :
    areRunarEmittableWithIfAndPatchesL ops = true := by
  cases h with
  | nil => rfl
  | cons op rest hOp hRest =>
      simp [areRunarEmittableWithIfAndPatchesL,
        isRunarEmittableWithIfAndPatchesOp_of_RunarEmittableWithIf op hOp,
        areRunarEmittableWithIfAndPatchesL_of_AreRunarEmittableWithIf rest hRest]

end

/-- Every `AreRunarEmittableWithIf` op list is in `AreRunarEmittableWithIfAndPatches`. -/
theorem AreRunarEmittableWithIf.toWithIfAndPatches
    (ops : List StackOp) (h : AreRunarEmittableWithIf ops) :
    AreRunarEmittableWithIfAndPatches ops :=
  areRunarEmittableWithIfAndPatchesL_of_AreRunarEmittableWithIf ops h

/-! ### Key sample checks (decidable by `native_decide`) -/

theorem areRunarEmittableWithIfAndPatchesL_pushCodesepIndex_singleton :
    areRunarEmittableWithIfAndPatchesL [.pushCodesepIndex] = true := rfl

theorem areRunarEmittableWithIfAndPatchesL_opcode_codesep_singleton :
    areRunarEmittableWithIfAndPatchesL [.opcode "OP_CODESEPARATOR"] = true := rfl

theorem areRunarEmittableWithIfAndPatchesL_codesep_then_push_singleton :
    areRunarEmittableWithIfAndPatchesL
      [.opcode "OP_CODESEPARATOR", .pushCodesepIndex] = true := rfl

end Parse
end RunarVerification.Script
