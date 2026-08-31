import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Eval
import RunarVerification.Crypto.Spec

/-!
# Rabin signature verifier codegen — Phase B10 (port of
`packages/runar-compiler/src/passes/rabin-codegen.ts` ⇒ `emitVerifyRabinSig`)

Rabin signature verification checks the modular identity
`(sig² + padding) mod pubKey == SHA256(msg)` using a fixed 15-opcode
script body.

BUG-010 (see `_review/BUG-010-rfc.md`) added a 5-opcode `OP_WITHIN`
range check enforcing `0 ≤ padding < 65536` on-chain, closing the forgery
exploit documented in `_review/BUG-004-finding.md`. It is modelled here as
of 2026-08-16 — `rabinBodyOps` is the 15-opcode body, and
`runOps_rabinBodyOps_eq` carries the two bounds as hypotheses and consumes
them at the `OP_VERIFY` step (outside the range the gate evaluates FALSE
and the run is `.error .assertFailed`, which IS the intended behaviour).
That closed the `oracle-price` divergence in `PipelineGolden`'s
`lowerDivergencePending`.

Mirrors the TypeScript reference one-to-one. The dispatch arm in
`Stack.Lower` (`lowerVerifyRabinSigOpsLive`) brings the four args to the
top of the stack via `loadRefOperand` (consume on last use, modulo the
repeated-operand gate over `[msg, sig, padding, pubKey]`) — yielding the
layout `bottom→top: msg sig padding pubKey` — and then splices the body
defined here.

## Entry / exit shape

* On entry (after the four args have been loaded):
  `bottom→top: ..., msg, sig, padding, pubKey`  (`pubKey` = TOS)
* On exit: `bottom→top: ..., bool`  (`true` on a valid Rabin signature)

The body is the fixed 15-opcode sequence

  `OP_SWAP`
  `OP_DUP OP_0 <65536> OP_WITHIN OP_VERIFY`   (BUG-010 padding gate)
  `OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL`

## Source of truth

* `emitVerifyRabinSig` at
  `packages/runar-compiler/src/passes/rabin-codegen.ts:37-48`
* `lowerVerifyRabinSig` at
  `packages/runar-compiler/src/passes/05-stack-lower.ts:3992` (dispatcher)
* Cross-validated against `compilers/go`, `compilers/rust`,
  `compilers/python`, `compilers/zig`, `compilers/ruby`, `compilers/java`
  via the conformance suite (`conformance/runner/runner.ts`).
* Lean lowering helper:
  `RunarVerification.Stack.lowerVerifyRabinSigOpsLive` at
  `RunarVerification/Stack/Lower.lean:1171-1198`.
-/

namespace RunarVerification.Stack
namespace Rabin

open RunarVerification.Stack
open RunarVerification.Stack.Lower
open RunarVerification.Stack.Eval
open RunarVerification.ANF.Eval (Value)

/-! ## Tiny aliases (mirroring `wOpc`/`wPushI` in `Stack.Wots`). -/

@[inline] def rOpc (s : String) : StackOp := .opcode s

/-! ## Body opcode sequence

Mirrors the TS `emitVerifyRabinSig` callback sequence exactly
(`rabin-codegen.ts:37-48`). The stack effect of each step (with the
top of the stack on the right) is:

```
entry: msg sig padding pubKey
  OP_SWAP   ⇒ msg sig pubKey padding
  OP_DUP    ⇒ msg sig pubKey padding padding
  OP_0      ⇒ msg sig pubKey padding padding 0
  <65536>   ⇒ msg sig pubKey padding padding 0 65536
  OP_WITHIN ⇒ msg sig pubKey padding (0 ≤ padding < 65536)
  OP_VERIFY ⇒ msg sig pubKey padding          (aborts if out of range)
  OP_ROT    ⇒ msg pubKey padding sig
  OP_DUP    ⇒ msg pubKey padding sig sig
  OP_MUL    ⇒ msg pubKey padding sig²
  OP_ADD    ⇒ msg pubKey (sig²+padding)
  OP_SWAP   ⇒ msg (sig²+padding) pubKey
  OP_MOD    ⇒ msg ((sig²+padding) mod pubKey)
  OP_SWAP   ⇒ ((sig²+padding) mod pubKey) msg
  OP_SHA256 ⇒ ((sig²+padding) mod pubKey) SHA256(msg)
  OP_EQUAL  ⇒ bool
```
-/

/-- The 15-opcode Rabin verification body emitted *after* the four args
have been loaded by `loadRefLive`. Mirrors the body section of
`Stack.lowerVerifyRabinSigOpsLive` one-to-one, which in turn mirrors
`emitVerifyRabinSig` (`packages/runar-compiler/src/passes/rabin-codegen.ts:53-70`).
-/
def rabinBodyOps : List StackOp :=
  [ .swap
  -- BUG-010 padding range check: assert `0 ≤ padding < 65536`
  -- (`rabin-codegen.ts:54-60`). Without it a spender can supply a padding
  -- large enough to force `sig² + padding` past the modulus and forge a
  -- residue, so this is a consensus-relevant gate, not a sanity check.
  , .dup
  , .push (.bigint 0)
  , .push (.bigint Lower.rabinPaddingLimit)
  , rOpc "OP_WITHIN"
  , rOpc "OP_VERIFY"
  , .rot
  , .dup
  , rOpc "OP_MUL"
  , rOpc "OP_ADD"
  , .swap
  , rOpc "OP_MOD"
  , .swap
  , rOpc "OP_SHA256"
  -- BUG-011 digest-encoding normalization (`rabin-codegen.ts`). `OP_MOD` leaves
  -- a MINIMAL Script number, which carries a trailing 0x00 sign byte whenever
  -- the digest's most-significant byte has its high bit set (~50% of messages),
  -- while `OP_SHA256` pushes exactly 32 raw bytes. The old `OP_EQUAL` was a
  -- BYTE compare and refused about half of all honest signatures on a real
  -- consensus VM. Append an explicit sign byte, collapse to minimal form, and
  -- compare NUMERICALLY.
  , .push (.bytes (ByteArray.mk #[0x00]))
  , rOpc "OP_CAT"
  , rOpc "OP_BIN2NUM"
  , rOpc "OP_NUMEQUAL"
  ]

/-! ## Codegen bridge

The lowering helper `lowerVerifyRabinSigOpsLive` emits, in order:
the four `loadRefLive` blocks for `msg / sig / padding / pubKey`,
followed by the body defined above. The theorem below pins the
suffix of the emitted op-list to `rabinBodyOps`, which is the
load-bearing fact for any future `runOps`-level reasoning.
-/

/-- The 15-opcode body emitted by `lowerVerifyRabinSigOpsLive` is
byte-identical to `rabinBodyOps`. The four leading `loadRefOperand`
blocks (operand-gated over `[msg, sig, padding, pubKey]`) are
quotiented out by `arg loaders` — they are pure ref-loads that vary
only with the runtime stack map.

This is provable by `rfl` because both sides are constructed by
the same concrete `++` of literal op lists in `Stack/Lower.lean`. -/
theorem lowerVerifyRabinSigOpsLive_body
    (sm : StackMap) (bn : String) (msg sig padding pubKey : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) :
    (lowerVerifyRabinSigOpsLive sm bn msg sig padding pubKey
        currentIndex lastUses outerProtected).fst
      = (loadRefOperand sm msg [msg, sig, padding, pubKey]
            currentIndex lastUses outerProtected).fst
        ++ (loadRefOperand
              (loadRefOperand sm msg [msg, sig, padding, pubKey]
                currentIndex lastUses outerProtected).snd
              sig [msg, sig, padding, pubKey]
              currentIndex lastUses outerProtected).fst
        ++ (loadRefOperand
              (loadRefOperand
                (loadRefOperand sm msg [msg, sig, padding, pubKey]
                  currentIndex lastUses outerProtected).snd
                sig [msg, sig, padding, pubKey]
                currentIndex lastUses outerProtected).snd
              padding [msg, sig, padding, pubKey]
              currentIndex lastUses outerProtected).fst
        ++ (loadRefOperand
              (loadRefOperand
                (loadRefOperand
                  (loadRefOperand sm msg [msg, sig, padding, pubKey]
                    currentIndex lastUses outerProtected).snd
                  sig [msg, sig, padding, pubKey]
                  currentIndex lastUses outerProtected).snd
                padding [msg, sig, padding, pubKey]
                currentIndex lastUses outerProtected).snd
              pubKey [msg, sig, padding, pubKey]
              currentIndex lastUses outerProtected).fst
        ++ rabinBodyOps := by
  rfl

/-- The body is exactly 18 opcodes long (10 + BUG-010's 5-opcode gate
+ BUG-011's 4-opcode digest normalization, less the `OP_EQUAL` that
`OP_NUMEQUAL` replaced). -/
theorem rabinBodyOps_length : rabinBodyOps.length = 18 := rfl

/-! ## Codegen-to-spec equivalence (theorem, Phase B10)

Running `rabinBodyOps` on a stack whose top four elements are
`msg, sig, padding, pubKey` (bottom→top, `pubKey` = TOS) yields
`Crypto.Spec.verifyRabinSig_spec msg sig padding pubKey` on top of
the stack with the other state components untouched.

The theorem is discharged by a 15-step opcode-by-opcode reduction
against `Stack.Eval.runOps`. The terminal `OP_EQUAL` step lands in
the int↔bytes coercion arm widened in **B10-prep** (see
`Stack/Eval.lean#runOpcode "OP_EQUAL"`) — `(sig² + padding) mod
pubKey` lives as a `.vBigint`, the SHA-256 digest of `msg` lives as
a `.vBytes`, and the new arm compares the canonical `encodeMinimalLE`
encoding of the integer against the digest bytes. This matches
`verifyRabinSig_spec` exactly.

The proof takes `pubKey ≠ 0` and BUG-010's `0 ≤ padding < 65536` as
*input-side* domain facts (per `PATH2_PLAN.md §2.1` — input invariants
are allowed, conclusion-restating hypotheses are not). `OP_MOD` errors
on a zero divisor and the padding gate's `OP_VERIFY` errors outside the
range, so both side conditions keep the runtime reduction inside the
`.ok` branch. Real Rabin pubKeys are large RSA-like moduli, and the
padding bounds are exactly what the on-chain gate enforces, so neither
restriction weakens the claim: a padding outside `[0, 65536)` is
*supposed* to abort the script, and that is the behaviour BUG-010 added. -/

namespace Internal

/-! ### Local opcode-reduction helpers

Re-derived inline (rather than importing `Stack.Sim`) so the proof
stays self-contained inside `Stack/Rabin.lean`. Mirrors the
`HashOps.lean` idiom for Phase B primitives. -/

/-- `popN s 2` on a 2-element prefix. -/
private theorem popN_two_local
    (s : StackState) (b a : Value) (rest : List Value)
    (hStk : s.stack = b :: a :: rest) :
    popN s 2 = Except.ok ([b, a], { s with stack := rest }) := by
  unfold popN StackState.pop?
  rw [hStk]
  simp only [popN, StackState.pop?]

/-- `applySwap` on a 2-element prefix. -/
private theorem applySwap_cons
    (s : StackState) (b a : Value) (rest : List Value)
    (hStk : s.stack = b :: a :: rest) :
    applySwap s = Except.ok { s with stack := a :: b :: rest } := by
  unfold applySwap
  rw [hStk]

/-- `applyRot` on a 3-element prefix. -/
private theorem applyRot_cons
    (s : StackState) (a b c : Value) (rest : List Value)
    (hStk : s.stack = a :: b :: c :: rest) :
    applyRot s = Except.ok { s with stack := c :: a :: b :: rest } := by
  unfold applyRot
  rw [hStk]

/-- `applyDup` on a 1-element prefix. -/
private theorem applyDup_cons
    (s : StackState) (v : Value) (rest : List Value)
    (hStk : s.stack = v :: rest) :
    applyDup s = Except.ok { s with stack := v :: v :: rest } := by
  unfold applyDup
  rw [hStk]
  -- After the match reduces, the body is `Except.ok (s.push v)`; unfold
  -- `push` and substitute `hStk` again so `s.stack` becomes `v :: rest`.
  show Except.ok (s.push v) = _
  unfold StackState.push
  rw [hStk]

/-- `OP_MUL` on a 2-int prefix: pushes `a * b`. -/
private theorem runOpcode_MUL_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_MUL" s
    = Except.ok ({ s with stack := rest }.push (.vBigint (a * b))) := by
  have h : runOpcode "OP_MUL" s
      = liftIntBin s (fun a b => .vBigint (a * b)) := rfl
  rw [h]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

/-- `OP_ADD` on a 2-int prefix: pushes `a + b`. -/
private theorem runOpcode_ADD_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_ADD" s
    = Except.ok ({ s with stack := rest }.push (.vBigint (a + b))) := by
  have h : runOpcode "OP_ADD" s
      = liftIntBin s (fun a b => .vBigint (a + b)) := rfl
  rw [h]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

/-- `OP_MOD` def-equation (local copy). -/
private theorem runOpcode_MOD_def_local (s : StackState) :
    runOpcode "OP_MOD" s =
      (match popN s 2 with
       | .error e => .error e
       | .ok (vs, s') =>
           match vs with
           | [b, a] =>
               match asInt? a, asInt? b with
               | some ai, some bi =>
                   if bi == 0 then .error .divByZero
                   else .ok (s'.push (.vBigint (ai % bi)))
               | _, _ => .error (.typeError "OP_MOD expects ints")
           | _ => .error (.unsupported "OP_MOD popN bug")) := rfl

/-- `OP_MOD` on a 2-int prefix with non-zero divisor: pushes `a % b`. -/
private theorem runOpcode_MOD_intInt_nonzero
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest)
    (hNonzero : b ≠ 0) :
    runOpcode "OP_MOD" s
    = Except.ok ({ s with stack := rest }.push (.vBigint (a % b))) := by
  rw [runOpcode_MOD_def_local]
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?, hNonzero]

/-- `popN s 3` on a 3-element prefix. -/
private theorem popN_three_local
    (s : StackState) (c b a : Value) (rest : List Value)
    (hStk : s.stack = c :: b :: a :: rest) :
    popN s 3 = Except.ok ([c, b, a], { s with stack := rest }) := by
  unfold popN StackState.pop?
  rw [hStk]
  simp only [popN, StackState.pop?]

/-- `OP_WITHIN` def-equation (local copy). -/
private theorem runOpcode_WITHIN_def_local (s : StackState) :
    runOpcode "OP_WITHIN" s =
      (match popN s 3 with
       | .error e => .error e
       | .ok (vs, s') =>
           match vs with
           | [hi, lo, x] =>
               match asInt? x, asInt? lo, asInt? hi with
               | some xi, some li, some hii =>
                   .ok (s'.push (.vBool (decide (li ≤ xi ∧ xi < hii))))
               | _, _, _ => .error (.typeError "OP_WITHIN expects ints")
           | _ => .error (.unsupported "OP_WITHIN popN bug")) := rfl

/-- `OP_WITHIN` on a 3-int prefix (`hi` = TOS, then `lo`, then `x`):
pushes `lo ≤ x < hi`. -/
private theorem runOpcode_WITHIN_ints
    (s : StackState) (x lo hi : Int) (rest : List Value)
    (hStk : s.stack = .vBigint hi :: .vBigint lo :: .vBigint x :: rest) :
    runOpcode "OP_WITHIN" s
    = Except.ok ({ s with stack := rest }.push
        (.vBool (decide (lo ≤ x ∧ x < hi)))) := by
  rw [runOpcode_WITHIN_def_local]
  rw [popN_three_local s _ _ _ rest hStk]
  simp [asInt?]

/-- `OP_VERIFY` on a TRUE boolean: pops it and continues. The `.vBool false`
case is `.error .assertFailed`, which is exactly why the padding bounds have
to be hypotheses of `runOps_rabinBodyOps_eq`. -/
private theorem runOpcode_VERIFY_true
    (s : StackState) (rest : List Value)
    (hStk : s.stack = .vBool true :: rest) :
    runOpcode "OP_VERIFY" s = Except.ok { s with stack := rest } := by
  have h : runOpcode "OP_VERIFY" s =
      (match s.pop? with
       | none => .error (.unsupported "OP_VERIFY: empty stack")
       | some (v, s') =>
           match asBool? v with
           | some true  => .ok s'
           | some false => .error .assertFailed
           | none       => .error (.typeError "OP_VERIFY: non-bool")) := rfl
  rw [h]
  unfold StackState.pop?
  rw [hStk]
  simp only [asBool?]

/-- `OP_CAT` on a 2-bytes prefix: pushes `a ++ b`. Local mirror of
`Sim.runOpcode_CAT_bytesBytes` — `Stack.Sim` is not in this file's import
closure, which is why every opcode lemma in this module is restated locally. -/
private theorem runOpcode_CAT_bytes
    (s : StackState) (a b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: .vBytes a :: rest) :
    runOpcode "OP_CAT" s
    = Except.ok ({ s with stack := rest }.push (.vBytes (a ++ b))) := by
  have h : runOpcode "OP_CAT" s
      = liftBytesBin s (fun a b => .vBytes (a ++ b)) := rfl
  rw [h]
  unfold liftBytesBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asBytes?]

/-- `OP_BIN2NUM` on a bytes top: pushes `decodeMinimalLE b`. This is the step
that makes the BUG-011 comparison NUMERIC — the digest bytes are read as a
minimal Script number, so the sign byte `encodeMinimalLE` may carry no longer
decides the result. -/
private theorem runOpcode_BIN2NUM_bytesLocal
    (s : StackState) (b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: rest) :
    runOpcode "OP_BIN2NUM" s
    = Except.ok ({ s with stack := rest }.push (.vBigint (decodeMinimalLE b))) := by
  -- OP_BIN2NUM is INLINED in `runOpcode` (Eval.lean:646) rather than routed
  -- through `liftBytesUnary`, so this unfolds the match directly.
  show (match s.pop? with
        | none => _
        | some (v, s') =>
            match asBytes? v with
            | some b => Except.ok (s'.push (.vBigint (decodeMinimalLE b)))
            | none => _) = _
  unfold StackState.pop?
  rw [hStk]
  rfl

/-- `OP_NUMEQUAL` on a 2-int prefix: pushes `decide (a = b)`. -/
private theorem runOpcode_NUMEQUAL_ints
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_NUMEQUAL" s
    = Except.ok ({ s with stack := rest }.push (.vBool (decide (a = b)))) := by
  have h : runOpcode "OP_NUMEQUAL" s
      = liftIntBinNum s (fun a b => .vBool (decide (a = b))) := rfl
  rw [h]
  unfold liftIntBinNum
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

/-- `OP_SHA256` on a 1-bytes prefix. -/
private theorem runOpcode_SHA256_bytes
    (s : StackState) (bs : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes bs :: rest) :
    runOpcode "OP_SHA256" s
    = Except.ok ({ s with stack := rest }.push
              (.vBytes (RunarVerification.ANF.Eval.Crypto.sha256 bs))) := by
  have h : runOpcode "OP_SHA256" s
      = liftBytesUnary s
          (fun b => .vBytes (RunarVerification.ANF.Eval.Crypto.sha256 b)) := rfl
  rw [h]
  unfold liftBytesUnary StackState.pop?
  rw [hStk]
  rfl

/-- `OP_EQUAL` def-equation (local copy of the body widened in B10-prep). -/
private theorem runOpcode_EQUAL_def_local (s : StackState) :
    runOpcode "OP_EQUAL" s =
      (match popN s 2 with
       | .error e => .error e
       | .ok (vs, s') =>
           match vs with
           | [b, a] =>
               let eq := match asBytes? a, asBytes? b with
                 | some ab, some bb => decide (ab.toList = bb.toList)
                 | _, _ =>
                     match asInt? a, asInt? b with
                     | some ai, some bi => decide (ai = bi)
                     | _, _ =>
                         match asInt? a, asBytes? b with
                         | some ai, some bb =>
                             decide ((encodeMinimalLE ai).toList = bb.toList)
                         | _, _ =>
                             match asBytes? a, asInt? b with
                             | some ab, some bi =>
                                 decide (ab.toList = (encodeMinimalLE bi).toList)
                             | _, _ => false
               .ok (s'.push (.vBool eq))
           | _ => .error (.unsupported "OP_EQUAL popN bug")) := rfl

/-- The OP_EQUAL coercion cascade, specialized to operand `a = .vBigint x`
(the modular residue) and `b = .vBytes h` (the SHA-256 digest), still collapses
to `decide (encodeMinimalLE x = h)` under the Bitcoin-faithful
`asBytes? (vBigint 0) = some empty`.  For `x = 0` the leading bytes/bytes branch
fires (`empty = h`) and `encodeMinimalLE 0 = empty` makes it agree; for `x ≠ 0`
control falls through the (now-`none`) `asBytes? a` exactly as in B10-prep. -/
private theorem equal_intBytes_cascade (x : Int) (h : ByteArray) :
    (match asBytes? (.vBigint x), asBytes? (.vBytes h) with
     | some ab, some bb => decide (ab.toList = bb.toList)
     | _, _ =>
         match asInt? (.vBigint x), asInt? (.vBytes h) with
         | some ai, some bi => decide (ai = bi)
         | _, _ =>
             match asInt? (.vBigint x), asBytes? (.vBytes h) with
             | some ai, some bb =>
                 decide ((encodeMinimalLE ai).toList = bb.toList)
             | _, _ =>
                 match asBytes? (.vBigint x), asInt? (.vBytes h) with
                 | some ab, some bi =>
                     decide (ab.toList = (encodeMinimalLE bi).toList)
                 | _, _ => false)
    = decide ((encodeMinimalLE x).toList = h.toList) := by
  by_cases hx : x = 0
  · subst hx
    simp only [asBytes?, encodeMinimalLE_zero, ByteArray.toList_empty]
  · rw [asBytes?_vBigint_ne_zero hx]
    simp only [asBytes?, asInt?]

/-- The terminal `OP_EQUAL` step in the Rabin body: comparing
`.vBytes h` (TOS, the SHA-256 digest) against `.vBigint x` (the
modular residue) reduces to the int↔bytes coercion arm widened in
B10-prep — `encodeMinimalLE x` is compared bytewise against `h`. -/
private theorem runOpcode_EQUAL_intBytes
    (s : StackState) (x : Int) (h : ByteArray)
    (rest : List Value)
    (hStk : s.stack = .vBytes h :: .vBigint x :: rest) :
    runOpcode "OP_EQUAL" s
    = Except.ok ({ s with stack := rest }.push
              (.vBool (decide
                ((encodeMinimalLE x).toList = h.toList)))) := by
  rw [runOpcode_EQUAL_def_local]
  rw [popN_two_local s _ _ rest hStk]
  simp only []
  rw [equal_intBytes_cascade x h]

/-! ### `runOps` cons reduction for the Rabin body

Each Rabin opcode is non-`.ifOp`, so `runOps (op :: rest) s` reduces
via `runOps_cons_nonIf_eq` to `match stepNonIf op s with ...`. -/

private theorem notIfOp_swap : ∀ thn els, (StackOp.swap : StackOp) ≠ .ifOp thn els := by
  intro thn els h; cases h

private theorem notIfOp_rot : ∀ thn els, (StackOp.rot : StackOp) ≠ .ifOp thn els := by
  intro thn els h; cases h

private theorem notIfOp_dup : ∀ thn els, (StackOp.dup : StackOp) ≠ .ifOp thn els := by
  intro thn els h; cases h

private theorem notIfOp_opcode (code : String) :
    ∀ thn els, (StackOp.opcode code : StackOp) ≠ .ifOp thn els := by
  intro thn els h; cases h

private theorem notIfOp_push (v : PushVal) :
    ∀ thn els, (StackOp.push v : StackOp) ≠ .ifOp thn els := by
  intro thn els h; cases h

/-- `stepNonIf .rot s = applyRot s` (`stepNonIf` is defined by cases on the
constructor; the `.rot` arm immediately delegates to `applyRot`). -/
private theorem stepNonIf_rot (s : StackState) :
    stepNonIf .rot s = applyRot s := rfl

end Internal

open Internal

/-- **B10 — Rabin codegen-to-spec.** Running the 15-opcode
`rabinBodyOps` on a stack whose top four elements are
`pubKey, padding, sig, msg` (TOS first; `vBigint pubKey` is on top)
yields `.vBool (verifyRabinSig_spec msg sig padding pubKey)` on top
with the rest of the state preserved.

The `pubKey ≠ 0` hypothesis is an input-side domain fact: it gates
the runtime `OP_MOD` step (which errors on a zero divisor); real
Rabin moduli are large primes products, so the restriction is
harmless. Per `PATH2_PLAN.md §2.1`, this is an input invariant, not
a conclusion-restating hypothesis. -/
theorem runOps_rabinBodyOps_eq (msg : ByteArray)
    (sig padding pubKey : Int) (s : StackState)
    (hPubKey : pubKey ≠ 0)
    (hPadLo : 0 ≤ padding) (hPadHi : padding < Lower.rabinPaddingLimit) :
    runOps rabinBodyOps
        { s with stack :=
            .vBigint pubKey
              :: .vBigint padding
              :: .vBigint sig
              :: .vBytes msg
              :: s.stack }
      = .ok { s with stack :=
                .vBool (RunarVerification.Crypto.Spec.verifyRabinSig_spec
                          msg sig padding pubKey) :: s.stack } := by
  -- Step 1: OP_SWAP.
  rw [show (rabinBodyOps : List StackOp)
        = .swap :: (rabinBodyOps.drop 1) from rfl,
      runOps_cons_nonIf_eq .swap _ _ notIfOp_swap, stepNonIf_swap,
      applySwap_cons _ _ _ _ rfl]
  simp only []
  -- Steps 2-6: BUG-010's `0 ≤ padding < 65536` gate.
  -- Step 2: OP_DUP (copy the padding for the range test).
  rw [show (rabinBodyOps.drop 1 : List StackOp)
        = .dup :: (rabinBodyOps.drop 2) from rfl,
      runOps_cons_nonIf_eq .dup _ _ notIfOp_dup, stepNonIf_dup,
      applyDup_cons _ _ _ rfl]
  simp only []
  -- Step 3: push 0 (the inclusive lower bound).
  rw [show (rabinBodyOps.drop 2 : List StackOp)
        = .push (.bigint 0) :: (rabinBodyOps.drop 3) from rfl,
      runOps_cons_nonIf_eq (.push (.bigint 0)) _ _ (notIfOp_push _),
      stepNonIf_push_bigint]
  simp only [StackState.push]
  -- Step 4: push 65536 (the exclusive upper bound).
  rw [show (rabinBodyOps.drop 3 : List StackOp)
        = .push (.bigint Lower.rabinPaddingLimit) :: (rabinBodyOps.drop 4) from rfl,
      runOps_cons_nonIf_eq (.push (.bigint Lower.rabinPaddingLimit)) _ _
        (notIfOp_push _),
      stepNonIf_push_bigint]
  simp only [StackState.push]
  -- Step 5: OP_WITHIN.
  rw [show (rabinBodyOps.drop 4 : List StackOp)
        = .opcode "OP_WITHIN" :: (rabinBodyOps.drop 5) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_WITHIN") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_WITHIN_ints _ padding 0 Lower.rabinPaddingLimit _ rfl]
  simp only [StackState.push]
  -- Step 6: OP_VERIFY. This is where the two padding bounds are consumed —
  -- without them the gate evaluates FALSE and the whole run is
  -- `.error .assertFailed`, which is precisely the forgery BUG-010 closes.
  rw [show (decide (0 ≤ padding ∧ padding < Lower.rabinPaddingLimit)) = true from
        decide_eq_true ⟨hPadLo, hPadHi⟩]
  rw [show (rabinBodyOps.drop 5 : List StackOp)
        = .opcode "OP_VERIFY" :: (rabinBodyOps.drop 6) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_VERIFY") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_VERIFY_true _ _ rfl]
  simp only []
  -- Step 7: OP_ROT.
  rw [show (rabinBodyOps.drop 6 : List StackOp)
        = .rot :: (rabinBodyOps.drop 7) from rfl,
      runOps_cons_nonIf_eq .rot _ _ notIfOp_rot, stepNonIf_rot,
      applyRot_cons _ _ _ _ _ rfl]
  simp only []
  -- Step 8: OP_DUP.
  rw [show (rabinBodyOps.drop 7 : List StackOp)
        = .dup :: (rabinBodyOps.drop 8) from rfl,
      runOps_cons_nonIf_eq .dup _ _ notIfOp_dup, stepNonIf_dup,
      applyDup_cons _ _ _ rfl]
  simp only []
  -- Step 9: OP_MUL.
  rw [show (rabinBodyOps.drop 8 : List StackOp)
        = .opcode "OP_MUL" :: (rabinBodyOps.drop 9) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_MUL") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_MUL_intInt _ sig sig _ rfl]
  simp only [StackState.push]
  -- Step 10: OP_ADD.
  rw [show (rabinBodyOps.drop 9 : List StackOp)
        = .opcode "OP_ADD" :: (rabinBodyOps.drop 10) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_ADD") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_ADD_intInt _ padding (sig * sig) _ rfl]
  simp only [StackState.push]
  -- Step 11: OP_SWAP.
  rw [show (rabinBodyOps.drop 10 : List StackOp)
        = .swap :: (rabinBodyOps.drop 11) from rfl,
      runOps_cons_nonIf_eq .swap _ _ notIfOp_swap, stepNonIf_swap,
      applySwap_cons _ _ _ _ rfl]
  simp only []
  -- Step 12: OP_MOD (gated by `pubKey ≠ 0`).
  rw [show (rabinBodyOps.drop 11 : List StackOp)
        = .opcode "OP_MOD" :: (rabinBodyOps.drop 12) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_MOD") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_MOD_intInt_nonzero _ (padding + sig * sig) pubKey _ rfl hPubKey]
  simp only [StackState.push]
  -- Step 13: OP_SWAP.
  rw [show (rabinBodyOps.drop 12 : List StackOp)
        = .swap :: (rabinBodyOps.drop 13) from rfl,
      runOps_cons_nonIf_eq .swap _ _ notIfOp_swap, stepNonIf_swap,
      applySwap_cons _ _ _ _ rfl]
  simp only []
  -- Step 14: OP_SHA256.
  rw [show (rabinBodyOps.drop 13 : List StackOp)
        = .opcode "OP_SHA256" :: (rabinBodyOps.drop 14) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_SHA256") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_SHA256_bytes _ msg _ rfl]
  simp only [StackState.push]
  -- Steps 15-18: BUG-011 digest-encoding normalization, replacing the single
  -- OP_EQUAL byte compare. The digest gets an explicit 0x00 sign byte
  -- (OP_CAT), collapses to a minimal Script number (OP_BIN2NUM), and is
  -- compared NUMERICALLY (OP_NUMEQUAL) against OP_MOD's residue.
  --
  -- Step 15: push the 0x00 sign byte.
  rw [show (rabinBodyOps.drop 14 : List StackOp)
        = .push (.bytes (ByteArray.mk #[0x00])) :: (rabinBodyOps.drop 15) from rfl,
      runOps_cons_nonIf_eq (.push _) _ _ (notIfOp_push _),
      stepNonIf_push_bytes]
  simp only [StackState.push]
  -- Step 16: OP_CAT — digest ++ 0x00.
  rw [show (rabinBodyOps.drop 15 : List StackOp)
        = .opcode "OP_CAT" :: (rabinBodyOps.drop 16) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_CAT") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_CAT_bytes _
        (RunarVerification.ANF.Eval.Crypto.sha256 msg)
        (ByteArray.mk #[0x00]) _ rfl]
  simp only [StackState.push]
  -- Step 17: OP_BIN2NUM — read those bytes as a minimal Script number.
  rw [show (rabinBodyOps.drop 16 : List StackOp)
        = .opcode "OP_BIN2NUM" :: (rabinBodyOps.drop 17) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_BIN2NUM") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_BIN2NUM_bytesLocal _
        (RunarVerification.ANF.Eval.Crypto.sha256 msg ++ ByteArray.mk #[0x00]) _ rfl]
  simp only [StackState.push]
  -- Step 18: OP_NUMEQUAL — the numeric compare the spec now states.
  rw [show (rabinBodyOps.drop 17 : List StackOp)
        = .opcode "OP_NUMEQUAL" :: (rabinBodyOps.drop 18) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_NUMEQUAL") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_NUMEQUAL_ints _
        ((padding + sig * sig) % pubKey)
        (decodeMinimalLE (RunarVerification.ANF.Eval.Crypto.sha256 msg ++ ByteArray.mk #[0x00]))
        _ rfl]
  rw [show (rabinBodyOps.drop 18 : List StackOp) = [] from rfl]
  simp only []
  rw [runOps_nil]
  -- Reconcile algebraic form: `padding + sig*sig = sig*sig + padding`.
  have hAddComm : padding + sig * sig = sig * sig + padding :=
    Int.add_comm padding (sig * sig)
  simp [StackState.push,
        RunarVerification.Crypto.Spec.verifyRabinSig_spec,
        hAddComm]

end Rabin
end RunarVerification.Stack
