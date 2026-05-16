import RunarVerification.Stack.Syntax
import RunarVerification.Stack.NumEncoding
import RunarVerification.ANF.Eval

/-!
# Stack IR — Big-step evaluation

A big-step semantics for Stack programs operating on `RunarVerification.ANF.Eval.Value`s.

The semantics is designed to make the simulation theorem in `Sim.lean`
straightforward: every primitive opcode either manipulates the stack
typewise (`dup`, `swap`, …) or computes a concrete arithmetic / bytes
operation. Cryptographic opcodes (`OP_SHA256`, `OP_CHECKSIG`, …)
delegate to the existing assumptions and backend parameters in
`RunarVerification.ANF.Eval.Crypto` so that the Stack VM and the ANF
evaluator share a single trusted crypto base.

**Scope.** The opcode dispatch covers exactly the ~52 opcodes the Rúnar
emit pass can produce (see `06-emit.ts:20–123`). Any other opcode name
returns `EvalError.unsupported`; this matches the user-confirmed
"Rúnar-emitted subset" as the *semantic* scope even though the syntax
captures the full BSV opcode set.
-/

namespace RunarVerification.Stack
namespace Eval

open RunarVerification.ANF.Eval (Value EvalError EvalResult Output)
open RunarVerification.ANF.Eval.Crypto

/-! ## VM state -/

/--
Stack VM state.

* `stack`     — the main evaluation stack (head = top).
* `altstack`  — auxiliary stack (`OP_TOALTSTACK` / `OP_FROMALTSTACK`).
* `outputs`   — emitted `Output`s in canonical declaration order.
* `props`     — contract property slots, used by `update_prop`-lowered ops.
* `preimage`  — abstract BIP-143 preimage threaded for `OP_CHECKSIG` /
                `OP_CHECKSIGVERIFY`; it defaults to empty until a
                concrete transaction context is supplied.
-/
structure StackState where
  stack    : List Value := []
  altstack : List Value := []
  outputs  : List Output := []
  props    : List (String × Value) := []
  preimage : ByteArray := ByteArray.empty
  deriving Inhabited

namespace StackState

def push (s : StackState) (v : Value) : StackState :=
  { s with stack := v :: s.stack }

def pop? (s : StackState) : Option (Value × StackState) :=
  match s.stack with
  | []      => none
  | v :: vs => some (v, { s with stack := vs })

end StackState

/-! ## Helper: pop N values, returning them in pop-order (top first) -/

def popN (s : StackState) : Nat → EvalResult (List Value × StackState)
  | 0 => .ok ([], s)
  | Nat.succ k =>
      match s.pop? with
      | none           => .error (.unsupported "stack underflow")
      | some (v, s')   =>
          match popN s' k with
          | .error e => .error e
          | .ok (vs, s'') => .ok (v :: vs, s'')

/-! ## Coercions

Bitcoin Script values are byte-strings; numeric ops interpret them as
sign-magnitude little-endian integers, and `OP_VERIFY` interprets them
as boolean (zero-vs-non-zero). Our typed `Value` already tracks the
intended interpretation; these helpers bridge the two representations
where ops care.
-/

def asInt? : Value → Option Int
  | .vBigint i => some i
  | .vBool b   => some (if b then 1 else 0)
  | _          => none

def asBool? : Value → Option Bool
  | .vBool b   => some b
  | .vBigint i => some (decide (i ≠ 0))
  | .vBytes b  => some (decide (b.size > 0))
  | _          => none

def asBytes? : Value → Option ByteArray
  | .vBytes b  => some b
  | .vOpaque b => some b
  | _          => none

def asNonNegativeNat? (v : Value) : Option Nat :=
  match asInt? v with
  | some i => if i < 0 then none else some i.toNat
  | none => none

/-! ## Primitive stack-manipulation ops -/

def applyDup (s : StackState) : EvalResult StackState :=
  match s.stack with
  | []      => .error (.unsupported "OP_DUP: empty stack")
  | v :: _  => .ok (s.push v)

def applySwap (s : StackState) : EvalResult StackState :=
  match s.stack with
  | a :: b :: rest => .ok { s with stack := b :: a :: rest }
  | _              => .error (.unsupported "OP_SWAP: <2 elements")

def applyDrop (s : StackState) : EvalResult StackState :=
  match s.stack with
  | _ :: rest => .ok { s with stack := rest }
  | _         => .error (.unsupported "OP_DROP: empty stack")

def applyNip (s : StackState) : EvalResult StackState :=
  match s.stack with
  | a :: _ :: rest => .ok { s with stack := a :: rest }
  | _              => .error (.unsupported "OP_NIP: <2 elements")

def applyOver (s : StackState) : EvalResult StackState :=
  match s.stack with
  | a :: b :: rest => .ok { s with stack := b :: a :: b :: rest }
  | _              => .error (.unsupported "OP_OVER: <2 elements")

def applyRot (s : StackState) : EvalResult StackState :=
  match s.stack with
  | a :: b :: c :: rest => .ok { s with stack := c :: a :: b :: rest }
  | _                   => .error (.unsupported "OP_ROT: <3 elements")

def applyTuck (s : StackState) : EvalResult StackState :=
  match s.stack with
  | a :: b :: rest => .ok { s with stack := a :: b :: a :: rest }
  | _              => .error (.unsupported "OP_TUCK: <2 elements")

/-- `roll d`: rolls the element at structural depth `d` to the top of the stack.

This is the *bundled* Stack-IR op exactly as produced by `Stack.Lower` — a bare
`.roll d` with no preceding depth push. `Script/Emit.lean` encodes it as the byte
pair `[push d, OP_ROLL]`, so the IR op models the *combined* effect of that pair:
`runOps [.roll d] s` equals running the parsed bytecode `[push d, OP_ROLL]` on
`s` (the named `OP_ROLL` opcode below pops that pushed depth first). Keeping the
IR op no-pop is what makes the producer (`Lower`), the evaluator (`runOps`), and
the emit/parse round-trip agree. `roll 0` is the identity. -/
def applyRoll (s : StackState) (d : Nat) : EvalResult StackState :=
  if d ≥ s.stack.length then
    .error (.unsupported s!"OP_ROLL: depth {d} ≥ stack size {s.stack.length}")
  else
    let v := s.stack[d]!
    let rest := s.stack.eraseIdx d
    .ok { s with stack := v :: rest }

/-- `pick d`: copies the element at structural depth `d` to the top of the stack.

Like `applyRoll`, this is the bundled Stack-IR op (a bare `.pick d`) that
`Script/Emit.lean` encodes as the byte pair `[push d, OP_PICK]`; the IR op models
the combined effect of that pair. It is definitionally identical to
`applyPickStruct`. `pick 0` duplicates the top of stack. -/
def applyPick (s : StackState) (d : Nat) : EvalResult StackState :=
  if d ≥ s.stack.length then
    .error (.unsupported s!"OP_PICK: depth {d} ≥ stack size {s.stack.length}")
  else
    .ok (s.push s.stack[d]!)

/-- `pickStruct d`: structural pick (no-pop). Copies the element at
structural depth `d` to the top without popping a runtime depth first.
Matches the semantics of `Stack.Lower.loadRef`'s `[.pickStruct d]`
emission for d≥2 — the lowering does not push a separate depth value;
`Script.Emit` synthesises the depth push at the byte level. -/
def applyPickStruct (s : StackState) (d : Nat) : EvalResult StackState :=
  if d ≥ s.stack.length then
    .error (.unsupported s!"pickStruct: depth {d} ≥ stack size {s.stack.length}")
  else
    .ok (s.push s.stack[d]!)

/-! ## Arithmetic on top-of-stack -/

def liftIntBin (s : StackState) (f : Int → Int → Value) : EvalResult StackState :=
  match popN s 2 with
  | .error e => .error e
  | .ok (vs, s') =>
      match vs with
      | [b, a] =>
          match asInt? a, asInt? b with
          | some ai, some bi => .ok (s'.push (f ai bi))
          | _, _ => .error (.typeError "binary numeric op expects two ints")
      | _ => .error (.unsupported "binary op popN bug")

def liftIntUnary (s : StackState) (f : Int → Value) : EvalResult StackState :=
  match s.pop? with
  | none => .error (.unsupported "unary op: empty stack")
  | some (v, s') =>
      match asInt? v with
      | some i => .ok (s'.push (f i))
      | none   => .error (.typeError "unary numeric op expects int")

def liftBytesBin (s : StackState) (f : ByteArray → ByteArray → Value) : EvalResult StackState :=
  match popN s 2 with
  | .error e => .error e
  | .ok (vs, s') =>
      match vs with
      | [b, a] =>
          match asBytes? a, asBytes? b with
          | some ab, some bb => .ok (s'.push (f ab bb))
          | _, _ => .error (.typeError "binary bytes op expects two byte values")
      | _ => .error (.unsupported "binary bytes op popN bug")

def liftBytesUnary (s : StackState) (f : ByteArray → Value) : EvalResult StackState :=
  match s.pop? with
  | none => .error (.unsupported "unary bytes op: empty stack")
  | some (v, s') =>
      match asBytes? v with
      | some b => .ok (s'.push (f b))
      | none   => .error (.typeError "unary bytes op expects bytes")

def liftBytesBinChecked (s : StackState)
    (f : ByteArray → ByteArray → EvalResult Value) : EvalResult StackState :=
  match popN s 2 with
  | .error e => .error e
  | .ok (vs, s') =>
      match vs with
      | [b, a] =>
          match asBytes? a, asBytes? b with
          | some ab, some bb =>
              match f ab bb with
              | .ok v => .ok (s'.push v)
              | .error e => .error e
          | _, _ => .error (.typeError "binary bytes op expects two byte values")
      | _ => .error (.unsupported "binary bytes op popN bug")

def invertBytes (bs : ByteArray) : ByteArray :=
  ByteArray.mk (bs.toList.map (fun b => ~~~b)).toArray

def bitwiseBytes (name : String) (f : UInt8 → UInt8 → UInt8)
    (a b : ByteArray) : EvalResult Value :=
  match zipBytesWith? f a b with
  | some out => .ok (.vBytes out)
  | none => .error (.typeError s!"{name} expects equal-length byte values")

/-! ## Opcode dispatch

Each named opcode either:
1. consumes/produces stack values via a small helper above,
2. delegates to a `Crypto.*` assumption/backend function, or
3. is unsupported (returns `.error .unsupported`).

This dispatch table mirrors the **Rúnar-emitted subset** identified in
`06-emit.ts:20–123` plus the Chronicle extensions (l:82–121).
-/

/-- Local adapter for `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` semantics.

The Stack VM still models multisig under abstract single-pop semantics
(see comment on `OP_CHECKMULTISIG` in `runOpcode` below), so this adapter
routes the raw stack payload into the explicit auth backend field. The
backend has fail-fast codegen; there is no executable `false` default. -/
def checkMultiSigStub (payload : ByteArray) : Bool :=
  checkMultiSigStack payload

def popBytesN (role : String) : Nat → StackState →
    EvalResult (List ByteArray × StackState)
  | 0, s => .ok ([], s)
  | n + 1, s =>
      match s.pop? with
      | none => .error (.unsupported s!"{role}: stack underflow")
      | some (v, s') =>
          match asBytes? v with
          | none => .error (.typeError s!"{role}: expected bytes")
          | some b =>
              match popBytesN role n s' with
              | .error e => .error e
              | .ok (bs, s'') => .ok (b :: bs, s'')

/--
Parse the full Bitcoin `OP_CHECKMULTISIG` stack frame.

Stack head is the top. The opcode consumes:

* `n`
* `n` public keys
* `m`
* `m` signatures
* the historical dummy value

The byte lists are returned in source order rather than pop order.
-/
def parseCheckMultiSigFrame (s : StackState) :
    EvalResult (List ByteArray × List ByteArray × StackState) :=
  match s.pop? with
  | none => .error (.unsupported "OP_CHECKMULTISIG: empty stack")
  | some (nVal, s1) =>
      match asNonNegativeNat? nVal with
      | none => .error (.typeError "OP_CHECKMULTISIG expects pubkey count")
      | some n =>
          match popBytesN "OP_CHECKMULTISIG pubkeys" n s1 with
          | .error e => .error e
          | .ok (pubkeysPop, s2) =>
              match s2.pop? with
              | none => .error (.unsupported "OP_CHECKMULTISIG: missing signature count")
              | some (mVal, s3) =>
                  match asNonNegativeNat? mVal with
                  | none => .error (.typeError "OP_CHECKMULTISIG expects signature count")
                  | some m =>
                      if m > n then
                        .error (.typeError "OP_CHECKMULTISIG signature count exceeds pubkey count")
                      else
                        match popBytesN "OP_CHECKMULTISIG signatures" m s3 with
                        | .error e => .error e
                        | .ok (sigsPop, s4) =>
                            match s4.pop? with
                            | none => .error (.unsupported "OP_CHECKMULTISIG: missing dummy")
                            | some (_dummy, s5) => .ok (sigsPop.reverse, pubkeysPop.reverse, s5)

def runCheckMultiSigFull (verifyOnly : Bool) (s : StackState) :
    EvalResult StackState :=
  match parseCheckMultiSigFrame s with
  | .error e => .error e
  | .ok (sigs, pubkeys, s') =>
      let ok := checkMultiSig sigs pubkeys
      if verifyOnly then
        if ok then .ok s' else .error .assertFailed
      else
        .ok (s'.push (.vBool ok))

def runCheckMultiSigFallback (verifyOnly : Bool) (s : StackState) :
    EvalResult StackState :=
  match s.pop? with
  | none =>
      if verifyOnly then
        .error (.unsupported "OP_CHECKMULTISIGVERIFY: empty stack")
      else
        .error (.unsupported "OP_CHECKMULTISIG: empty stack")
  | some (v, s') =>
      match asBytes? v with
      | some b =>
          let ok := checkMultiSigStub b
          if verifyOnly then
            if ok then .ok s' else .error .assertFailed
          else
            .ok (s'.push (.vBool ok))
      | none =>
          if verifyOnly then
            .error (.typeError "OP_CHECKMULTISIGVERIFY expects frame count or bytes")
          else
            .error (.typeError "OP_CHECKMULTISIG expects frame count or bytes")

def runCheckMultiSig (verifyOnly : Bool) (s : StackState) : EvalResult StackState :=
  match s.stack with
  | [] => runCheckMultiSigFallback verifyOnly s
  | top :: _ =>
      match asNonNegativeNat? top with
      | some _ => runCheckMultiSigFull verifyOnly s
      | none => runCheckMultiSigFallback verifyOnly s

def runOpcode (code : String) (s : StackState) : EvalResult StackState :=
  match code with
  -- ---------------------------------------------------------------- stack
  | "OP_DUP"     => applyDup s
  | "OP_SWAP"    => applySwap s
  | "OP_DROP"    => applyDrop s
  | "OP_NIP"     => applyNip s
  | "OP_OVER"    => applyOver s
  | "OP_ROT"     => applyRot s
  | "OP_TUCK"    => applyTuck s
  | "OP_ROLL" =>
      -- Parsed-bytecode path: the depth is a runtime stack value. Pop it, then
      -- apply the bundled `roll` op (which is itself no-pop) to the remainder.
      match s.pop? with
      | none => .error (.unsupported "OP_ROLL: empty stack")
      | some (v, s') =>
          match asNonNegativeNat? v with
          | some d => applyRoll s' d
          | none => .error (.typeError "OP_ROLL expects non-negative depth")
  | "OP_PICK" =>
      -- Parsed-bytecode path: pop the runtime depth, then apply the bundled
      -- `pick` op (no-pop) to the remainder.
      match s.pop? with
      | none => .error (.unsupported "OP_PICK: empty stack")
      | some (v, s') =>
          match asNonNegativeNat? v with
          | some d => applyPick s' d
          | none => .error (.typeError "OP_PICK expects non-negative depth")
  | "OP_2DUP" =>
      match applyOver s with
      | .error e => .error e
      | .ok s1 => applyOver s1
  | "OP_2DROP" =>
      match applyDrop s with
      | .error e => .error e
      | .ok s1 => applyDrop s1
  | "OP_TOALTSTACK" =>
      match s.pop? with
      | none => .error (.unsupported "OP_TOALTSTACK: empty stack")
      | some (v, s') => .ok { s' with altstack := v :: s'.altstack }
  | "OP_FROMALTSTACK" =>
      match s.altstack with
      | []      => .error (.unsupported "OP_FROMALTSTACK: empty altstack")
      | v :: rs => .ok ({ s with altstack := rs }.push v)
  | "OP_DEPTH"   => .ok (s.push (.vBigint s.stack.length))
  | "OP_IFDUP" =>
      match s.stack with
      | [] => .error (.unsupported "OP_IFDUP: empty stack")
      | v :: _ =>
          match asBool? v with
          | some true  => .ok (s.push v)
          | some false => .ok s
          | none       => .error (.typeError "OP_IFDUP: non-bool")
  -- ---------------------------------------------------------------- pushes
  | "OP_0"  => .ok (s.push (.vBigint 0))
  | "OP_1NEGATE" => .ok (s.push (.vBigint (-1)))
  | "OP_1"  => .ok (s.push (.vBigint 1))
  | "OP_2"  => .ok (s.push (.vBigint 2))
  | "OP_3"  => .ok (s.push (.vBigint 3))
  | "OP_4"  => .ok (s.push (.vBigint 4))
  | "OP_5"  => .ok (s.push (.vBigint 5))
  | "OP_6"  => .ok (s.push (.vBigint 6))
  | "OP_7"  => .ok (s.push (.vBigint 7))
  | "OP_8"  => .ok (s.push (.vBigint 8))
  | "OP_9"  => .ok (s.push (.vBigint 9))
  | "OP_10" => .ok (s.push (.vBigint 10))
  | "OP_11" => .ok (s.push (.vBigint 11))
  | "OP_12" => .ok (s.push (.vBigint 12))
  | "OP_13" => .ok (s.push (.vBigint 13))
  | "OP_14" => .ok (s.push (.vBigint 14))
  | "OP_15" => .ok (s.push (.vBigint 15))
  | "OP_16" => .ok (s.push (.vBigint 16))
  -- ---------------------------------------------------------------- numeric
  | "OP_ADD"     => liftIntBin s (fun a b => .vBigint (a + b))
  | "OP_SUB"     => liftIntBin s (fun a b => .vBigint (a - b))
  | "OP_MUL"     => liftIntBin s (fun a b => .vBigint (a * b))
  | "OP_DIV" =>
      match popN s 2 with
      | .error e => .error e
      | .ok (vs, s') =>
          match vs with
          | [b, a] =>
              match asInt? a, asInt? b with
              | some ai, some bi =>
                  if bi == 0 then .error .divByZero else .ok (s'.push (.vBigint (ai / bi)))
              | _, _ => .error (.typeError "OP_DIV expects ints")
          | _ => .error (.unsupported "OP_DIV popN bug")
  | "OP_MOD" =>
      match popN s 2 with
      | .error e => .error e
      | .ok (vs, s') =>
          match vs with
          | [b, a] =>
              match asInt? a, asInt? b with
              | some ai, some bi =>
                  if bi == 0 then .error .divByZero else .ok (s'.push (.vBigint (ai % bi)))
              | _, _ => .error (.typeError "OP_MOD expects ints")
          | _ => .error (.unsupported "OP_MOD popN bug")
  | "OP_NEGATE"  => liftIntUnary s (fun i => .vBigint (-i))
  | "OP_ABS"     => liftIntUnary s (fun i => .vBigint i.natAbs)
  | "OP_1ADD"    => liftIntUnary s (fun i => .vBigint (i + 1))
  | "OP_1SUB"    => liftIntUnary s (fun i => .vBigint (i - 1))
  | "OP_2MUL"    => liftIntUnary s (fun i => .vBigint (2 * i))
  | "OP_2DIV"    => liftIntUnary s (fun i => .vBigint (i / 2))
  | "OP_LSHIFT"  => liftIntBin s (fun a b => .vBigint (a * (2 ^ b.toNat)))
  | "OP_RSHIFT"  => liftIntBin s (fun a b => .vBigint (a / (2 ^ b.toNat)))
  | "OP_LSHIFTNUM" => liftIntBin s (fun a b => .vBigint (a * (2 ^ b.toNat)))
  | "OP_RSHIFTNUM" => liftIntBin s (fun a b => .vBigint (a / (2 ^ b.toNat)))
  -- ---------------------------------------------------------------- comparison
  | "OP_LESSTHAN"           => liftIntBin s (fun a b => .vBool (decide (a < b)))
  | "OP_GREATERTHAN"        => liftIntBin s (fun a b => .vBool (decide (a > b)))
  | "OP_LESSTHANOREQUAL"    => liftIntBin s (fun a b => .vBool (decide (a ≤ b)))
  | "OP_GREATERTHANOREQUAL" => liftIntBin s (fun a b => .vBool (decide (a ≥ b)))
  | "OP_NUMEQUAL"           => liftIntBin s (fun a b => .vBool (decide (a = b)))
  | "OP_NUMNOTEQUAL"        => liftIntBin s (fun a b => .vBool (decide (a ≠ b)))
  | "OP_BOOLAND"            => liftIntBin s (fun a b => .vBool (decide (a ≠ 0 ∧ b ≠ 0)))
  | "OP_BOOLOR"             => liftIntBin s (fun a b => .vBool (decide (a ≠ 0 ∨ b ≠ 0)))
  | "OP_MIN"                => liftIntBin s (fun a b => .vBigint (min a b))
  | "OP_MAX"                => liftIntBin s (fun a b => .vBigint (max a b))
  | "OP_WITHIN" =>
      match popN s 3 with
      | .error e => .error e
      | .ok (vs, s') =>
          match vs with
          | [hi, lo, x] =>
              match asInt? x, asInt? lo, asInt? hi with
              | some xi, some li, some hii => .ok (s'.push (.vBool (decide (li ≤ xi ∧ xi < hii))))
              | _, _, _ => .error (.typeError "OP_WITHIN expects ints")
          | _ => .error (.unsupported "OP_WITHIN popN bug")
  -- ---------------------------------------------------------------- logic
  | "OP_NOT" =>
      match s.pop? with
      | none => .error (.unsupported "OP_NOT: empty stack")
      | some (v, s') =>
          match asBool? v with
          | some b => .ok (s'.push (.vBool (!b)))
          | none   => .error (.typeError "OP_NOT non-bool")
  | "OP_0NOTEQUAL" =>
      match s.pop? with
      | none => .error (.unsupported "OP_0NOTEQUAL: empty stack")
      | some (v, s') =>
          match asInt? v with
          | some i => .ok (s'.push (.vBool (decide (i ≠ 0))))
          | none   => .error (.typeError "OP_0NOTEQUAL: not int")
  | "OP_EQUAL" =>
      match popN s 2 with
      | .error e => .error e
      | .ok (vs, s') =>
          match vs with
          | [b, a] =>
              let eq := match asBytes? a, asBytes? b with
                | some ab, some bb => decide (ab.toList = bb.toList)
                | _, _ =>
                    match asInt? a, asInt? b with
                    | some ai, some bi => decide (ai = bi)
                    | _, _ => false
              .ok (s'.push (.vBool eq))
          | _ => .error (.unsupported "OP_EQUAL popN bug")
  -- ---------------------------------------------------------------- bytes
  | "OP_CAT" => liftBytesBin s (fun a b => .vBytes (a ++ b))
  | "OP_SPLIT" =>
      match popN s 2 with
      | .error e => .error e
      | .ok (vs, s') =>
          match vs with
          | [idx, v] =>
              match asBytes? v, asNonNegativeNat? idx with
              | some bs, some i =>
                  if i > bs.size then
                    .error (.unsupported "OP_SPLIT: index past end")
                  else
                    .ok ((s'.push (.vBytes (bs.extract 0 i))).push
                      (.vBytes (bs.extract i bs.size)))
              | _, _ => .error (.typeError "OP_SPLIT expects bytes and non-negative index")
          | _ => .error (.unsupported "OP_SPLIT popN bug")
  | "OP_SIZE" =>
      match s.stack with
      | [] => .error (.unsupported "OP_SIZE: empty stack")
      | v :: _ =>
          match asBytes? v with
          | some b => .ok (s.push (.vBigint b.size))
          | none   => .error (.typeError "OP_SIZE: not bytes")
  | "OP_BIN2NUM" =>
      match s.pop? with
      | none => .error (.unsupported "OP_BIN2NUM: empty stack")
      | some (v, s') =>
          match asBytes? v with
          | some b => .ok (s'.push (.vBigint (decodeMinimalLE b)))
          | none   => .error (.typeError "OP_BIN2NUM: not bytes")
  | "OP_NUM2BIN" =>
      match popN s 2 with
      | .error e => .error e
      | .ok (vs, s') =>
          match vs with
          | [size, val] =>
              match asInt? val, asInt? size with
              | some n, some target =>
                  if target < 0 then
                    .error (.typeError "OP_NUM2BIN expects non-negative size")
                  else
                    match num2binEncode? n target.toNat with
                    | some encoded => .ok (s'.push (.vBytes encoded))
                    | none => .error (.unsupported "OP_NUM2BIN: value does not fit target size")
              | _, _ => .error (.typeError "OP_NUM2BIN expects int value and size")
          | _ => .error (.unsupported "OP_NUM2BIN popN bug")
  | "OP_INVERT" => liftBytesUnary s (fun b => .vBytes (invertBytes b))
  | "OP_AND"    => liftBytesBinChecked s (bitwiseBytes "OP_AND" (· &&& ·))
  | "OP_OR"     => liftBytesBinChecked s (bitwiseBytes "OP_OR" (· ||| ·))
  | "OP_XOR"    => liftBytesBinChecked s (bitwiseBytes "OP_XOR" (· ^^^ ·))
  -- ---------------------------------------------------------------- crypto (delegated to Eval.Crypto)
  | "OP_SHA256"    => liftBytesUnary s (fun b => .vBytes (sha256 b))
  | "OP_HASH160"   => liftBytesUnary s (fun b => .vBytes (hash160 b))
  | "OP_HASH256"   => liftBytesUnary s (fun b => .vBytes (hash256 b))
  | "OP_RIPEMD160" => liftBytesUnary s (fun b => .vBytes (ripemd160 b))
  | "OP_CHECKSIG" =>
      match popN s 2 with
      | .error e => .error e
      | .ok (vs, s') =>
          match vs with
          | [pk, sig] =>
              match asBytes? sig, asBytes? pk with
              | some sigB, some pkB => .ok (s'.push (.vBool (checkSig sigB pkB)))
              | _, _ => .error (.typeError "OP_CHECKSIG expects bytes")
          | _ => .error (.unsupported "OP_CHECKSIG popN bug")
  | "OP_VERIFY" =>
      match s.pop? with
      | none => .error (.unsupported "OP_VERIFY: empty stack")
      | some (v, s') =>
          match asBool? v with
          | some true  => .ok s'
          | some false => .error .assertFailed
          | none       => .error (.typeError "OP_VERIFY: non-bool")
  | "OP_CHECKSIGVERIFY" =>
      match popN s 2 with
      | .error e => .error e
      | .ok (vs, s') =>
          match vs with
          | [pk, sig] =>
              match asBytes? sig, asBytes? pk with
              | some sigB, some pkB =>
                  if checkSig sigB pkB then .ok s' else .error .assertFailed
              | _, _ => .error (.typeError "OP_CHECKSIGVERIFY expects bytes")
          | _ => .error (.unsupported "OP_CHECKSIGVERIFY popN bug")
  | "OP_EQUALVERIFY" =>
      match popN s 2 with
      | .error e => .error e
      | .ok (vs, s') =>
          match vs with
          | [b, a] =>
              let eq := match asBytes? a, asBytes? b with
                | some ab, some bb => decide (ab.toList = bb.toList)
                | _, _ =>
                    match asInt? a, asInt? b with
                    | some ai, some bi => decide (ai = bi)
                    | _, _ => false
              if eq then .ok s' else .error .assertFailed
          | _ => .error (.unsupported "OP_EQUALVERIFY popN bug")
  | "OP_NUMEQUALVERIFY" =>
      match popN s 2 with
      | .error e => .error e
      | .ok (vs, s') =>
          match vs with
          | [b, a] =>
              match asInt? a, asInt? b with
              | some ai, some bi =>
                  if decide (ai = bi) then .ok s' else .error .assertFailed
              | _, _ => .error (.typeError "OP_NUMEQUALVERIFY expects ints")
          | _ => .error (.unsupported "OP_NUMEQUALVERIFY popN bug")
  | "OP_CHECKMULTISIG" =>
      -- Full frame semantics when the top value is a count; the older
      -- single-payload adapter remains as fallback for peephole proofs over
      -- abstract multisig payloads.
      runCheckMultiSig false s
  | "OP_CHECKMULTISIGVERIFY" =>
      runCheckMultiSig true s
  | "OP_CODESEPARATOR" => .ok s
      -- Legacy `runOps` keeps the proof-facing state unchanged here.
      -- Use `runOpsPc` when code-separator index tracking is required.
  | "OP_RETURN" => .error (.unsupported "OP_RETURN")
  | _ => .error (.unsupported s!"opcode {code} not in the Rúnar-emitted subset")

/-! ### Concrete byte / number opcode samples

These executable sample theorems pin the Stack VM wiring to
`Stack.NumEncoding` and the bytewise helpers above. They avoid comparing
whole `StackState` values, whose payload types intentionally do not carry
global decidable equality instances.
-/

theorem runOpcode_BIN2NUM_sample :
    (match runOpcode "OP_BIN2NUM"
        { stack := [.vBytes (ByteArray.mk #[0x80, 0x80])] } with
     | .ok s =>
         match s.stack with
         | [.vBigint n] => n == -128
         | _ => false
     | .error _ => false) = true := by
  native_decide

theorem runOpcode_NUM2BIN_sample :
    (match runOpcode "OP_NUM2BIN"
        { stack := [.vBigint 4, .vBigint (-128)] } with
     | .ok s =>
         match s.stack with
         | [.vBytes out] => out.toList == [0x80, 0x00, 0x00, 0x80]
         | _ => false
     | .error _ => false) = true := by
  native_decide

theorem runOpcode_XOR_sample :
    (match runOpcode "OP_XOR"
        { stack := [.vBytes (ByteArray.mk #[0x0f]),
                    .vBytes (ByteArray.mk #[0xf0])] } with
     | .ok s =>
         match s.stack with
         | [.vBytes out] => out.toList == [0xff]
         | _ => false
     | .error _ => false) = true := by
  native_decide

theorem runOpcode_SPLIT_sample :
    (match runOpcode "OP_SPLIT"
        { stack := [.vBigint 2,
                    .vBytes (ByteArray.mk #[0xaa, 0xbb, 0xcc])] } with
     | .ok s =>
         match s.stack with
         | [.vBytes suffix, .vBytes pref] =>
             suffix.toList == [0xcc] && pref.toList == [0xaa, 0xbb]
         | _ => false
     | .error _ => false) = true := by
  native_decide

theorem runOpcode_ROLL_sample :
    (match runOpcode "OP_ROLL"
        { stack := [.vBigint 1,
                    .vBytes (ByteArray.mk #[0xaa]),
                    .vBytes (ByteArray.mk #[0xbb])] } with
     | .ok s =>
         match s.stack with
         | [.vBytes a, .vBytes b] => a.toList == [0xbb] && b.toList == [0xaa]
         | _ => false
     | .error _ => false) = true := by
  native_decide

theorem runOpcode_PICK_sample :
    (match runOpcode "OP_PICK"
        { stack := [.vBigint 1,
                    .vBytes (ByteArray.mk #[0xaa]),
                    .vBytes (ByteArray.mk #[0xbb])] } with
     | .ok s =>
         match s.stack with
         | [.vBytes a, .vBytes b, .vBytes c] =>
             a.toList == [0xbb] && b.toList == [0xaa] && c.toList == [0xbb]
         | _ => false
     | .error _ => false) = true := by
  native_decide

theorem runOpcode_AND_length_mismatch_errors :
    (match runOpcode "OP_AND"
        { stack := [.vBytes (ByteArray.mk #[0x0f]),
                    .vBytes (ByteArray.mk #[0xf0, 0x00])] } with
     | .error (.typeError _) => true
     | _ => false) = true := by
  native_decide

theorem parseCheckMultiSigFrame_sample :
    (match parseCheckMultiSigFrame
        { stack := [
            .vBigint 2,
            .vBytes (ByteArray.mk #[0x02]),
            .vBytes (ByteArray.mk #[0x01]),
            .vBigint 1,
            .vBytes (ByteArray.mk #[0xaa]),
            .vBigint 0,
            .vBigint 99
          ] } with
     | .ok (sigs, pubkeys, s') =>
         sigs.map ByteArray.toList == [[0xaa]]
           && pubkeys.map ByteArray.toList == [[0x01], [0x02]]
           && (match s'.stack with
               | [.vBigint 99] => true
               | _ => false)
     | .error _ => false) = true := by
  native_decide

/-! ## Big-step run

Recurses over the op list. `ifOp` dispatches on the boolean
interpretation of the popped condition value, then descends into the
selected branch.
-/

/--
Single-step evaluation excluding `.ifOp`. The `.ifOp` case is handled
inline by `runOps` (so we avoid mutual recursion and stay structural
on the op-list size).
-/
def stepNonIf (op : StackOp) (s : StackState) : EvalResult StackState :=
  match op with
  | .push (.bigint i) => .ok (s.push (.vBigint i))
  | .push (.bool b)   => .ok (s.push (.vBool b))
  | .push (.bytes b)  => .ok (s.push (.vBytes b))
  | .dup    => applyDup s
  | .swap   => applySwap s
  | .roll d => applyRoll s d
  | .pick d => applyPick s d
  | .pickStruct d => applyPickStruct s d
  | .drop   => applyDrop s
  | .nip    => applyNip s
  | .over   => applyOver s
  | .rot    => applyRot s
  | .tuck   => applyTuck s
  | .opcode code => runOpcode code s
  | .ifOp _ _   => .error (.unsupported "ifOp must be handled by runOps")
  | .placeholder _ _   => .ok (s.push (.vBigint 0))
  | .pushCodesepIndex  => .ok (s.push (.vBigint 0))
  | .rawBytes b        => .ok (s.push (.vBytes b))

/--
Run a list of ops sequentially, threading the state. Inlines the
`.ifOp` case so the recursive structure is bound by op-list size and
needs no mutual block.
-/
def runOps : List StackOp → StackState → EvalResult StackState
  | [],       s => .ok s
  | .ifOp thn els :: rest, s =>
      match s.pop? with
      | none => .error (.unsupported "OP_IF: empty stack")
      | some (v, s') =>
          match asBool? v with
          | some true =>
              match runOps thn s' with
              | .error e => .error e
              | .ok s''  => runOps rest s''
          | some false =>
              match els with
              | none =>
                  runOps rest s'
              | some elsB =>
                  match runOps elsB s' with
                  | .error e => .error e
                  | .ok s''  => runOps rest s''
          | none => .error (.typeError "OP_IF: non-bool condition")
  | op :: rest, s =>
      match stepNonIf op s with
      | .error e => .error e
      | .ok s'   => runOps rest s'
termination_by ops _ => sizeOf ops
decreasing_by
  all_goals
    simp_wf
    omega

/-! ## Program-counter-aware run

The legacy `runOps` relation is intentionally kept stable for the
existing peephole proof surface. `runOpsPc` layers an executable
instruction-index counter on top, recording the last executed
`OP_CODESEPARATOR` and making `pushCodesepIndex` push that index instead
of the legacy zero placeholder.
-/

structure PcState where
  state : StackState := {}
  pc : Nat := 0
  lastCodeSeparator : Option Nat := none
  deriving Inhabited

def stepNonIfPc (op : StackOp) (s : PcState) : EvalResult PcState :=
  match op with
  | .opcode "OP_CODESEPARATOR" =>
      .ok { s with pc := s.pc + 1, lastCodeSeparator := some s.pc }
  | .pushCodesepIndex =>
      .ok { s with
        state := s.state.push (.vBigint (s.lastCodeSeparator.getD 0)),
        pc := s.pc + 1 }
  | .ifOp _ _ =>
      .error (.unsupported "ifOp must be handled by runOpsPc")
  | _ =>
      match stepNonIf op s.state with
      | .error e => .error e
      | .ok state' => .ok { s with state := state', pc := s.pc + 1 }

def runOpsPc : List StackOp → PcState → EvalResult PcState
  | [],       s => .ok s
  | .ifOp thn els :: rest, s =>
      match s.state.pop? with
      | none => .error (.unsupported "OP_IF: empty stack")
      | some (v, s') =>
          let branchStart : PcState := { s with state := s', pc := s.pc + 1 }
          match asBool? v with
          | some true =>
              match runOpsPc thn branchStart with
              | .error e => .error e
              | .ok s''  => runOpsPc rest s''
          | some false =>
              match els with
              | none =>
                  runOpsPc rest branchStart
              | some elsB =>
                  match runOpsPc elsB branchStart with
                  | .error e => .error e
                  | .ok s''  => runOpsPc rest s''
          | none => .error (.typeError "OP_IF: non-bool condition")
  | op :: rest, s =>
      match stepNonIfPc op s with
      | .error e => .error e
      | .ok s'   => runOpsPc rest s'
termination_by ops _ => sizeOf ops
decreasing_by
  all_goals
    simp_wf
    omega

theorem runOpsPc_codeSeparator_sample :
    (match runOpsPc
        [.push (.bigint 7), .opcode "OP_CODESEPARATOR", .pushCodesepIndex]
        {} with
     | .ok s =>
         s.pc == 3
           && s.lastCodeSeparator == some 1
           && (match s.state.stack with
               | [.vBigint idx, .vBigint value] => idx == 1 && value == 7
               | _ => false)
     | .error _ => false) = true := by
  native_decide

/-! ## Reduction lemmas (Phase 3c)

`rfl`-level identities that pin down the shape of `stepNonIf` and
`runOpcode` for the most common ops. These are referenced from the
operational soundness proofs in `Stack.Sim` and `Stack.Peephole`.
-/

theorem stepNonIf_push_bigint (s : StackState) (i : Int) :
    stepNonIf (.push (.bigint i)) s = .ok (s.push (.vBigint i)) := rfl

theorem stepNonIf_push_bool (s : StackState) (b : Bool) :
    stepNonIf (.push (.bool b)) s = .ok (s.push (.vBool b)) := rfl

theorem stepNonIf_push_bytes (s : StackState) (b : ByteArray) :
    stepNonIf (.push (.bytes b)) s = .ok (s.push (.vBytes b)) := rfl

theorem stepNonIf_dup (s : StackState) :
    stepNonIf .dup s = applyDup s := rfl

theorem stepNonIf_drop (s : StackState) :
    stepNonIf .drop s = applyDrop s := rfl

theorem stepNonIf_swap (s : StackState) :
    stepNonIf .swap s = applySwap s := rfl

theorem stepNonIf_opcode (code : String) (s : StackState) :
    stepNonIf (.opcode code) s = runOpcode code s := rfl

theorem stepNonIf_rawBytes (s : StackState) (b : ByteArray) :
    stepNonIf (.rawBytes b) s = .ok (s.push (.vBytes b)) := rfl

theorem runOps_nil (s : StackState) : runOps [] s = .ok s := by
  unfold runOps; rfl

/-! Match-on-`Except.ok` reduction helper.

`(match Except.ok x with | .error _ => f e | .ok s' => g s') = g x` is a
definitional reduction, but Lean's `rfl` doesn't always pull it through
when the surrounding term is already partially reduced. Exposing it as
a `@[simp]` lemma makes downstream proofs (esp. `_extends_<typed>`
lemmas in `Stack.Peephole`) one-line.
-/

@[simp]
theorem match_Except_ok_runOps (x : StackState) (rest : List StackOp) :
    (match (Except.ok x : EvalResult StackState) with
     | .error e => .error e
     | .ok s'  => runOps rest s') = runOps rest x := rfl

/-- A more general `match`-on-Except.ok reduction that doesn't constrain
the match body. Use this when the body involves `runOps` applied to a
concrete cons like `.drop :: rest_outer`. -/
@[simp]
theorem match_Except_ok_general (α β : Type) (x : α) (f : β) (g : α → β) :
    (match (Except.ok x : Except EvalError α) with
     | .error _ => f
     | .ok s'   => g s') = g x := rfl

/-! ## Cons-step note

Lean's `rfl` doesn't reduce `runOps (op :: rest) s` to its
match-on-`stepNonIf` body for an abstract `op` (the inner
match-on-`rest, s'` makes the unfolding non-definitional). Proofs
that need the cons-step shape apply `unfold runOps` followed by
`rw [stepNonIf_<op>]` and `cases` on the match alternatives — see
the verify-fuse proofs in `Stack.Peephole` for the recipe.
-/

/-- Convenience: run a program's named method against an initial state. -/
def runMethod (p : StackProgram) (methodName : String) (initial : StackState) :
    EvalResult StackState :=
  runOps (p.bodyOf methodName) initial

end Eval
end RunarVerification.Stack
