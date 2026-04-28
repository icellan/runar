import RunarVerification.Stack.Syntax
import RunarVerification.ANF.Eval

/-!
# Stack IR — Big-step evaluation

A big-step semantics for Stack programs operating on `RunarVerification.ANF.Eval.Value`s.

The semantics is designed to make the simulation theorem in `Sim.lean`
straightforward: every primitive opcode either manipulates the stack
typewise (`dup`, `swap`, …) or computes a concrete arithmetic / bytes
operation. Cryptographic opcodes (`OP_SHA256`, `OP_CHECKSIG`, …)
delegate to the existing axioms in `RunarVerification.ANF.Eval.Crypto`
so that the Stack VM and the ANF evaluator share a single trusted
crypto base.

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
                `OP_CHECKSIGVERIFY` (mocked to `ByteArray.empty` here;
                concrete tx context is Phase 4 work).
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

/-- `roll d`: bytecode-style `OP_ROLL`. Pops one value off the top of the stack
(the runtime depth, supplied by stack-lower as a `[push d]` immediately preceding
this op), then rolls the element at structural depth `d` to the top. The popped
runtime depth is *not* re-checked against the IR-level parameter `d`: stack-lower
is the trusted producer that guarantees the two agree. `roll 0` is therefore a
no-op once the runtime depth has been popped.

This matches `06-emit.ts` (which lowers `.roll d` to a single `OP_PICK`/`OP_ROLL`
opcode), so the bytecode-level pattern `[push d, OP_ROLL]` aligns with the IR
pattern `[push d, .roll d]`. -/
def applyRoll (s : StackState) (d : Nat) : EvalResult StackState :=
  match s.pop? with
  | none => .error (.unsupported "OP_ROLL: empty stack")
  | some (_, s') =>
      if d ≥ s'.stack.length then
        .error (.unsupported s!"OP_ROLL: depth {d} ≥ stack size {s'.stack.length}")
      else
        let v := s'.stack[d]!
        let rest := s'.stack.eraseIdx d
        .ok { s' with stack := v :: rest }

/-- `pick d`: bytecode-style `OP_PICK`. Pops one value off the top of the stack
(the runtime depth, supplied by stack-lower as a `[push d]` immediately preceding
this op), then copies the element at structural depth `d` to the top. The popped
runtime depth is *not* re-checked against `d` for the same reason as `applyRoll`.
`pick 0` (after the pop) copies the new top to the top — i.e. `dup`. -/
def applyPick (s : StackState) (d : Nat) : EvalResult StackState :=
  match s.pop? with
  | none => .error (.unsupported "OP_PICK: empty stack")
  | some (_, s') =>
      if d ≥ s'.stack.length then
        .error (.unsupported s!"OP_PICK: depth {d} ≥ stack size {s'.stack.length}")
      else
        .ok (s'.push s'.stack[d]!)

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

/-! ## Opcode dispatch

Each named opcode either:
1. consumes/produces stack values via a small helper above,
2. delegates to a `Crypto.*` axiom (hashes, signature verifiers), or
3. is unsupported (returns `.error .unsupported`).

This dispatch table mirrors the **Rúnar-emitted subset** identified in
`06-emit.ts:20–123` plus the Chronicle extensions (l:82–121).
-/

/-- Local stub for `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` semantics.

Wraps `Crypto.checkMultiSig` via a single-bytes argument so the Stack VM
can model multi-sig under abstract single-pop semantics (see comment on
`OP_CHECKMULTISIG` in `runOpcode` below). Marked `opaque` (rather than
forwarded to the underlying axiom) so that `runOpcode` retains compiled
IR — `Crypto.checkMultiSig` is `axiom`-only and would otherwise force
`runOpcode` to be `noncomputable`. The chosen default is `false`,
matching `Crypto.checkSig`'s default. -/
opaque checkMultiSigStub (_ : ByteArray) : Bool := false

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
          | some _ => .ok (s'.push (.vBigint 0))   -- abstract; concrete decoding deferred
          | none   => .error (.typeError "OP_BIN2NUM: not bytes")
  | "OP_NUM2BIN" =>
      match popN s 2 with
      | .error e => .error e
      | .ok (vs, s') =>
          match vs with
          | [_size, _val] => .ok (s'.push (.vBytes ByteArray.empty))   -- abstract
          | _ => .error (.unsupported "OP_NUM2BIN popN bug")
  | "OP_INVERT" => liftBytesUnary s (fun _ => .vBytes ByteArray.empty)   -- abstract
  | "OP_AND"    => liftBytesBin s (fun _ _ => .vBytes ByteArray.empty)   -- abstract
  | "OP_OR"     => liftBytesBin s (fun _ _ => .vBytes ByteArray.empty)   -- abstract
  | "OP_XOR"    => liftBytesBin s (fun _ _ => .vBytes ByteArray.empty)   -- abstract
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
      -- Abstract single-pop semantics. The full Bitcoin opcode pops `n + m + 3`
      -- items (m sigs, n pubkeys, the two counts, and a dummy null), which the
      -- IR can't express without dependent typing on the count values. We take a
      -- pragmatic stub: pop one bytes value `b` and produce
      -- `vBool (checkMultiSigStub b)`. This is sufficient to express the
      -- `[OP_CHECKMULTISIG, OP_VERIFY] → [OP_CHECKMULTISIGVERIFY]` fusion,
      -- which is the only program-level invariant Rúnar's compiler claims.
      match s.pop? with
      | none => .error (.unsupported "OP_CHECKMULTISIG: empty stack")
      | some (v, s') =>
          match asBytes? v with
          | some b => .ok (s'.push (.vBool (checkMultiSigStub b)))
          | none   => .error (.typeError "OP_CHECKMULTISIG expects bytes")
  | "OP_CHECKMULTISIGVERIFY" =>
      -- Mirrors `OP_CHECKMULTISIG` then `OP_VERIFY` under the same pragmatic
      -- stub. See the `OP_CHECKMULTISIG` comment above for rationale.
      match s.pop? with
      | none => .error (.unsupported "OP_CHECKMULTISIGVERIFY: empty stack")
      | some (v, s') =>
          match asBytes? v with
          | some b =>
              if checkMultiSigStub b then .ok s' else .error .assertFailed
          | none   => .error (.typeError "OP_CHECKMULTISIGVERIFY expects bytes")
  | "OP_CODESEPARATOR" => .ok s   -- modeled as a no-op; only affects script-coverage by sighash, abstract here
  | "OP_RETURN" => .error (.unsupported "OP_RETURN")
  | _ => .error (.unsupported s!"opcode {code} not in the Rúnar-emitted subset")

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
  | .drop   => applyDrop s
  | .nip    => applyNip s
  | .over   => applyOver s
  | .rot    => applyRot s
  | .tuck   => applyTuck s
  | .opcode code => runOpcode code s
  | .ifOp _ _   => .error (.unsupported "ifOp must be handled by runOps")
  | .placeholder _ _   => .ok (s.push (.vBigint 0))
  | .pushCodesepIndex  => .ok (s.push (.vBigint 0))

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
