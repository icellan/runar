import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Eval
import RunarVerification.Crypto.Spec

/-!
# Rabin signature verifier codegen — Phase B10 (port of
`packages/runar-compiler/src/passes/rabin-codegen.ts` ⇒ `emitVerifyRabinSig`)

Rabin signature verification checks the modular identity
`(sig² + padding) mod pubKey == SHA256(msg)` using a fixed 10-opcode
script body.

Mirrors the TypeScript reference one-to-one. The dispatch arm in
`Stack.Lower` (`lowerVerifyRabinSigOpsLive`) brings the four args to the
top of the stack via `loadRefLive` — yielding the layout
`bottom→top: msg sig padding pubKey` — and then splices the body
defined here.

## Entry / exit shape

* On entry (after the four args have been loaded):
  `bottom→top: ..., msg, sig, padding, pubKey`  (`pubKey` = TOS)
* On exit: `bottom→top: ..., bool`  (`true` on a valid Rabin signature)

The body is the fixed 10-opcode sequence

  `OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL`

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

/-- The 10-opcode Rabin verification body emitted *after* the four args
have been loaded by `loadRefLive`. Mirrors the body section of
`Stack.lowerVerifyRabinSigOpsLive` (lines 1184–1195 of
`Stack/Lower.lean`) one-to-one. -/
def rabinBodyOps : List StackOp :=
  [ .swap
  , .rot
  , .dup
  , rOpc "OP_MUL"
  , rOpc "OP_ADD"
  , .swap
  , rOpc "OP_MOD"
  , .swap
  , rOpc "OP_SHA256"
  , rOpc "OP_EQUAL"
  ]

/-! ## Codegen bridge

The lowering helper `lowerVerifyRabinSigOpsLive` emits, in order:
the four `loadRefLive` blocks for `msg / sig / padding / pubKey`,
followed by the body defined above. The theorem below pins the
suffix of the emitted op-list to `rabinBodyOps`, which is the
load-bearing fact for any future `runOps`-level reasoning.
-/

/-- The 10-opcode body emitted by `lowerVerifyRabinSigOpsLive` is
byte-identical to `rabinBodyOps`. The four leading `loadRefLive`
blocks are quotiented out by `arg loaders` — they are pure
ref-loads that vary only with the runtime stack map.

This is provable by `rfl` because both sides are constructed by
the same concrete `++` of literal op lists in `Stack/Lower.lean`. -/
theorem lowerVerifyRabinSigOpsLive_body
    (sm : StackMap) (bn : String) (msg sig padding pubKey : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) :
    (lowerVerifyRabinSigOpsLive sm bn msg sig padding pubKey
        currentIndex lastUses outerProtected).fst
      = (loadRefLive sm msg currentIndex lastUses outerProtected).fst
        ++ (loadRefLive
              (loadRefLive sm msg currentIndex lastUses outerProtected).snd
              sig currentIndex lastUses outerProtected).fst
        ++ (loadRefLive
              (loadRefLive
                (loadRefLive sm msg currentIndex lastUses outerProtected).snd
                sig currentIndex lastUses outerProtected).snd
              padding currentIndex lastUses outerProtected).fst
        ++ (loadRefLive
              (loadRefLive
                (loadRefLive
                  (loadRefLive sm msg currentIndex lastUses outerProtected).snd
                  sig currentIndex lastUses outerProtected).snd
                padding currentIndex lastUses outerProtected).snd
              pubKey currentIndex lastUses outerProtected).fst
        ++ rabinBodyOps := by
  rfl

/-- The body is exactly 10 opcodes long. -/
theorem rabinBodyOps_length : rabinBodyOps.length = 10 := rfl

/-! ## Codegen-to-spec equivalence (theorem, Phase B10)

Running `rabinBodyOps` on a stack whose top four elements are
`msg, sig, padding, pubKey` (bottom→top, `pubKey` = TOS) yields
`Crypto.Spec.verifyRabinSig_spec msg sig padding pubKey` on top of
the stack with the other state components untouched.

The theorem is discharged by a 10-step opcode-by-opcode reduction
against `Stack.Eval.runOps`. The terminal `OP_EQUAL` step lands in
the int↔bytes coercion arm widened in **B10-prep** (see
`Stack/Eval.lean#runOpcode "OP_EQUAL"`) — `(sig² + padding) mod
pubKey` lives as a `.vBigint`, the SHA-256 digest of `msg` lives as
a `.vBytes`, and the new arm compares the canonical `encodeMinimalLE`
encoding of the integer against the digest bytes. This matches
`verifyRabinSig_spec` exactly.

The proof takes `pubKey ≠ 0` as an *input-side* domain fact (per
`PATH2_PLAN.md §2.1` — input invariants are allowed, conclusion-
restating hypotheses are not). `OP_MOD` errors on a zero divisor;
the non-zero side condition keeps the runtime reduction inside the
`.ok` branch. Real Rabin pubKeys are large RSA-like moduli, so the
restriction is harmless in practice. -/

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
  simp [asBytes?, asInt?]

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

/-- `stepNonIf .rot s = applyRot s` (`stepNonIf` is defined by cases on the
constructor; the `.rot` arm immediately delegates to `applyRot`). -/
private theorem stepNonIf_rot (s : StackState) :
    stepNonIf .rot s = applyRot s := rfl

end Internal

open Internal

/-- **B10 — Rabin codegen-to-spec.** Running the 10-opcode
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
    (hPubKey : pubKey ≠ 0) :
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
  -- Step 2: OP_ROT.
  rw [show (rabinBodyOps.drop 1 : List StackOp)
        = .rot :: (rabinBodyOps.drop 2) from rfl,
      runOps_cons_nonIf_eq .rot _ _ notIfOp_rot, stepNonIf_rot,
      applyRot_cons _ _ _ _ _ rfl]
  simp only []
  -- Step 3: OP_DUP.
  rw [show (rabinBodyOps.drop 2 : List StackOp)
        = .dup :: (rabinBodyOps.drop 3) from rfl,
      runOps_cons_nonIf_eq .dup _ _ notIfOp_dup, stepNonIf_dup,
      applyDup_cons _ _ _ rfl]
  simp only []
  -- Step 4: OP_MUL.
  rw [show (rabinBodyOps.drop 3 : List StackOp)
        = .opcode "OP_MUL" :: (rabinBodyOps.drop 4) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_MUL") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_MUL_intInt _ sig sig _ rfl]
  simp only [StackState.push]
  -- Step 5: OP_ADD.
  rw [show (rabinBodyOps.drop 4 : List StackOp)
        = .opcode "OP_ADD" :: (rabinBodyOps.drop 5) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_ADD") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_ADD_intInt _ padding (sig * sig) _ rfl]
  simp only [StackState.push]
  -- Step 6: OP_SWAP.
  rw [show (rabinBodyOps.drop 5 : List StackOp)
        = .swap :: (rabinBodyOps.drop 6) from rfl,
      runOps_cons_nonIf_eq .swap _ _ notIfOp_swap, stepNonIf_swap,
      applySwap_cons _ _ _ _ rfl]
  simp only []
  -- Step 7: OP_MOD (gated by `pubKey ≠ 0`).
  rw [show (rabinBodyOps.drop 6 : List StackOp)
        = .opcode "OP_MOD" :: (rabinBodyOps.drop 7) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_MOD") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_MOD_intInt_nonzero _ (padding + sig * sig) pubKey _ rfl hPubKey]
  simp only [StackState.push]
  -- Step 8: OP_SWAP.
  rw [show (rabinBodyOps.drop 7 : List StackOp)
        = .swap :: (rabinBodyOps.drop 8) from rfl,
      runOps_cons_nonIf_eq .swap _ _ notIfOp_swap, stepNonIf_swap,
      applySwap_cons _ _ _ _ rfl]
  simp only []
  -- Step 9: OP_SHA256.
  rw [show (rabinBodyOps.drop 8 : List StackOp)
        = .opcode "OP_SHA256" :: (rabinBodyOps.drop 9) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_SHA256") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_SHA256_bytes _ msg _ rfl]
  simp only [StackState.push]
  -- Step 10: OP_EQUAL (mixed int↔bytes via the B10-prep coercion arm).
  rw [show (rabinBodyOps.drop 9 : List StackOp)
        = .opcode "OP_EQUAL" :: (rabinBodyOps.drop 10) from rfl,
      runOps_cons_nonIf_eq (.opcode "OP_EQUAL") _ _ (notIfOp_opcode _),
      stepNonIf_opcode,
      runOpcode_EQUAL_intBytes _
        ((padding + sig * sig) % pubKey)
        (RunarVerification.ANF.Eval.Crypto.sha256 msg) _ rfl]
  -- After OP_EQUAL the residual op list is empty.
  rw [show (rabinBodyOps.drop 10 : List StackOp) = [] from rfl]
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
