import RunarVerification.ANF.Eval
import RunarVerification.Stack.Eval
import RunarVerification.Stack.Ec
import RunarVerification.Crypto.Secp256k1
import RunarVerification.Pipeline

/-! # `Stack/AgreesEC.lean` — single-EC-op codegen-to-spec PoC substrate

**EC sizing PoC (peer of wave-68's `AgreesCrypto.lean`).**  This file is a
STANDALONE sizing proof-of-concept for the secp256k1 EC codegen-to-spec tier
(`Crypto/Spec.lean §7`, the 10 `emitEc*_runOps_eq` axioms).  It is NOT wired
into `RunarVerification.lean`; it is built directly via `lake env lean` to
demonstrate that the SIMPLEST EC op (`ecModReduce`) is dischargeable off the
multi-op operational-M3 template (`runOps_cons_nonIf_eq` chaining), exactly the
way the SHA single-opcode transport was discharged in wave 68 — but for an
8-op fragment rather than a 1-op fragment, and against a FULLY EVALUABLE spec
(no opaque crypto backend).

## What this PoC establishes (and what it deliberately does not)

* `emitEcModReduce` lowers to the 8-op fragment
  `[OP_2DUP, OP_MOD, rot, drop, over, OP_ADD, swap, OP_MOD]`.  Every op is a
  `stepNonIf` arm the Stack VM evaluates concretely.  We prove
  `runOps Stack.Ec.emitEcModReduce stkSt = .ok {... ecModReduce value m ...}`
  by 8 sequential `runOps_cons_nonIf_eq` reductions — the EC analogue of
  `HashOps.runOps_sha256Ops_eq`, scaled to a multi-op fragment.

* **HONEST PRECONDITION (`m ≠ 0`).**  The Stack op `OP_MOD` returns
  `.error .divByZero` when the modulus is `0`, but the spec
  `Crypto.Secp256k1.ecModReduce` returns `0` in that case.  So the
  codegen-to-spec equality holds **only under `m ≠ 0`**.  The former
  `Crypto/Spec.lean` axiom `emitEcModReduce_runOps_eq` carried NO such
  hypothesis — meaning it was FALSE at `m = 0` and could not be discharged
  verbatim.  The fix is (a) adding `m ≠ 0` to the statement.  **This wave does
  exactly that and DISCHARGES the axiom**: Part 6 below restates it with `m ≠ 0`
  and proves it as `emitEcModReduce_runOps_eq` (a theorem) off
  `ecModReduce_step_transport`, removing the `Crypto/Spec` axiom.

* This is a SIZING PoC for ONE op-class (the "tiny / all-evaluable-opcodes"
  class).  It does NOT touch the medium ops (reverse32 ~300-op loops:
  `ecPointX/Y`, `ecMakePoint`, `ecNegate`, `ecEncodeCompressed`, `ecOnCurve`)
  nor the hard ops (`ecAdd`, `ecMul`, `ecMulGen` — Jacobian group law,
  50k+ ops, M4-walled).  See the SIZING REPORT in the task deliverable.

## Constraints honoured

No `sorry`/`admit`.  No new axioms (the spec defs in `Crypto/Secp256k1` and the
Stack VM in `Stack/Eval` are USED, not introduced).  No `...`.  The headline
transport is proved by honest step-chaining (no `simp`/`native_decide` fakes);
`native_decide` appears ONLY in a concrete smoke (the spec is computable, so the
smoke is legitimate, unlike the SHA backend which would panic). -/

-- The per-step `simp only [match_Except_ok_runOps]` reductions trip the
-- unused-simp-arg linter (Lean's iota reducer sometimes fires the match
-- reduction first), but the lemma IS the intended driver and keeping it
-- documents the step. Silence the cosmetic linter only.
set_option linter.unusedSimpArgs false

namespace RunarVerification.Stack.AgreesEC

open RunarVerification.ANF.Eval (Value State EvalResult EvalError evalValue callBuiltin?)
open RunarVerification.Stack
open RunarVerification.Stack.Eval
open RunarVerification.Pipeline.Soundness (successAgrees)

/-! ## Part 1 — the Stack-side multi-op M3 step transport (`ecModReduce`)

`Stack.Ec.emitEcModReduce` is the 8-op fragment

```text
[ .opcode "OP_2DUP", .opcode "OP_MOD", .rot, .drop,
  .over, .opcode "OP_ADD", .swap, .opcode "OP_MOD" ]
```

Run on `stack = vBigint m :: vBigint value :: rest` (TOS = `m`), it computes
`((value % m) + m) % m` = `Crypto.Secp256k1.ecModReduce value m` (the `m ≠ 0`
branch).  This is the EC peer of `HashOps.runOps_sha256Ops_eq` — a
codegen-to-spec operational step, but over 8 ops instead of 1, and against a
concrete (non-axiom) spec. -/

/-- **M3 substrate (ecModReduce).**  Running the lowered `emitEcModReduce`
fragment on `[m, value] ++ rest` (m on TOS) pushes
`Crypto.Secp256k1.ecModReduce value m`, provided `m ≠ 0` (the divByZero guard).

Proof: 8 honest `runOps_cons_nonIf_eq` step reductions.  No `simp` closing the
arithmetic — the result coordinate is exactly the spec def unfolded. -/
theorem ecModReduce_step_transport
    (s : StackState) (value m : Int) (rest : List Value)
    (hStk : s.stack = .vBigint m :: .vBigint value :: rest)
    (hM : m ≠ 0) :
    runOps Stack.Ec.emitEcModReduce s
      = .ok { s with
              stack := .vBigint (RunarVerification.Crypto.Secp256k1.ecModReduce value m)
                        :: rest } := by
  -- Destructure `s` and substitute its stack shape so every `stepNonIf`
  -- reduces by `rfl` (the non-stack fields `alt/out/props/pre` ride along
  -- unchanged through every step). `emitEcModReduce` is a literal 8-op list.
  obtain ⟨stk, alt, out, props, pre⟩ := s
  subst hStk
  -- Generic non-`.ifOp` proofs.
  have niOp : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by
    intro c t e h; cases h
  have niRot : ∀ t e, StackOp.rot ≠ .ifOp t e := by intro t e h; cases h
  have niDrop : ∀ t e, StackOp.drop ≠ .ifOp t e := by intro t e h; cases h
  have niOver : ∀ t e, StackOp.over ≠ .ifOp t e := by intro t e h; cases h
  have niSwap : ∀ t e, StackOp.swap ≠ .ifOp t e := by intro t e h; cases h
  -- Field record carried through every step (only `.stack` changes).
  -- Step 1: OP_2DUP.
  show runOps
      ([ StackOp.opcode "OP_2DUP", StackOp.opcode "OP_MOD", StackOp.rot,
         StackOp.drop, StackOp.over, StackOp.opcode "OP_ADD", StackOp.swap,
         StackOp.opcode "OP_MOD" ])
      { stack := .vBigint m :: .vBigint value :: rest, altstack := alt,
        outputs := out, props := props, preimage := pre } = _
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_2DUP"), stepNonIf_opcode]
  rw [show runOpcode "OP_2DUP"
        { stack := .vBigint m :: .vBigint value :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint m :: .vBigint value :: .vBigint m
                        :: .vBigint value :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 2: OP_MOD  → value % m on top.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_MOD"), stepNonIf_opcode]
  rw [show runOpcode "OP_MOD"
        { stack := .vBigint m :: .vBigint value :: .vBigint m :: .vBigint value :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint (value % m) :: .vBigint m :: .vBigint value :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      show (if m == 0 then (Except.error EvalError.divByZero : EvalResult StackState)
            else .ok (StackState.push
                  { stack := .vBigint m :: .vBigint value :: rest, altstack := alt,
                    outputs := out, props := props, preimage := pre }
                  (.vBigint (value % m)))) = _
      rw [if_neg (by simpa using hM)]; rfl]
  simp only [match_Except_ok_runOps]
  -- Step 3: rot.
  rw [runOps_cons_nonIf_eq _ _ _ niRot]
  rw [show stepNonIf StackOp.rot
        { stack := .vBigint (value % m) :: .vBigint m :: .vBigint value :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint value :: .vBigint (value % m) :: .vBigint m :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 4: drop.
  rw [runOps_cons_nonIf_eq _ _ _ niDrop]
  rw [show stepNonIf StackOp.drop
        { stack := .vBigint value :: .vBigint (value % m) :: .vBigint m :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint (value % m) :: .vBigint m :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 5: over.
  rw [runOps_cons_nonIf_eq _ _ _ niOver]
  rw [show stepNonIf StackOp.over
        { stack := .vBigint (value % m) :: .vBigint m :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint m :: .vBigint (value % m) :: .vBigint m :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 6: OP_ADD  → (value % m) + m on top.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_ADD"), stepNonIf_opcode]
  rw [show runOpcode "OP_ADD"
        { stack := .vBigint m :: .vBigint (value % m) :: .vBigint m :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint (value % m + m) :: .vBigint m :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 7: swap.
  rw [runOps_cons_nonIf_eq _ _ _ niSwap]
  rw [show stepNonIf StackOp.swap
        { stack := .vBigint (value % m + m) :: .vBigint m :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint m :: .vBigint (value % m + m) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 8: OP_MOD  → ((value % m) + m) % m on top.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_MOD"), stepNonIf_opcode]
  rw [show runOpcode "OP_MOD"
        { stack := .vBigint m :: .vBigint (value % m + m) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint ((value % m + m) % m) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      show (if m == 0 then (Except.error EvalError.divByZero : EvalResult StackState)
            else .ok (StackState.push
                  { stack := rest, altstack := alt,
                    outputs := out, props := props, preimage := pre }
                  (.vBigint ((value % m + m) % m)))) = _
      rw [if_neg (by simpa using hM)]; rfl]
  simp only [match_Except_ok_runOps, runOps_nil]
  -- Final: the pushed coordinate equals the spec def at `m ≠ 0`.
  have hSpec :
      RunarVerification.Crypto.Secp256k1.ecModReduce value m = (value % m + m) % m := by
    unfold RunarVerification.Crypto.Secp256k1.ecModReduce
    rw [if_neg hM]
  rw [hSpec]

/-! ## Part 2 — the M2 success-bit agreement (peer of wave-68)

`successAgrees a b := a.toOption.isSome ↔ b.toOption.isSome`.  The Stack side of
the `ecModReduce` fragment succeeds (Part 1).  An ANF side that COMPUTES
`ecModReduce` (the standalone `Crypto.ecModReduce` def already exists in
`ANF/Eval.lean`, line 417, but is NOT yet wired into `callBuiltin?` — see the
SIZING REPORT) would have success bit `true`, giving the M2 agreement.

Until the `callBuiltin?` arm lands, we state the agreement against the
Stack-side success directly: the deployed `emitEcModReduce` fragment SUCCEEDS on
a well-typed nonzero-modulus stack.  This is the leaf a gated dispatch wave would
hand to the consume theorem once the ANF arm is wired. -/

/-- The deployed `emitEcModReduce` fragment SUCCEEDS (success bit `true`) on a
two-int stack with nonzero modulus.  This is the Stack-side half of the M2 leg;
the ANF half is the (not-yet-wired) `callBuiltin? "ecModReduce"` arm. -/
theorem ecModReduce_stack_succeeds
    (s : StackState) (value m : Int) (rest : List Value)
    (hStk : s.stack = .vBigint m :: .vBigint value :: rest)
    (hM : m ≠ 0) :
    (runOps Stack.Ec.emitEcModReduce s).toOption.isSome = true := by
  rw [ecModReduce_step_transport s value m rest hStk hM]; rfl

/-! ## Part 3 — MANDATORY in-file smokes (anti-vacuous, concrete)

Unlike the SHA PoC, the EC spec is fully EVALUABLE, so the smokes may fire by
`native_decide` on the concrete coordinate (the spec is a closed-form `Int`
function — no opaque backend to panic the kernel evaluator). -/

/-- Concrete stack `[7, 23]` (m = 7 on TOS, value = 23 below). -/
private def smokeStk : StackState :=
  { (default : StackState) with stack := [.vBigint 7, .vBigint 23] }

/-- SMOKE (Part 1, structural).  The transport FIRES on the concrete stack:
running `emitEcModReduce` on `[7, 23]` yields `[23 mod 7 = 2]`.  This is the
anti-vacuity witness that the 8-op fragment really evaluates to the spec value. -/
theorem smoke_ecModReduce_transport :
    runOps Stack.Ec.emitEcModReduce smokeStk
      = .ok { smokeStk with
              stack := .vBigint (RunarVerification.Crypto.Secp256k1.ecModReduce 23 7) :: [] } :=
  ecModReduce_step_transport smokeStk 23 7 [] rfl (by decide)

/-- SMOKE (anti-vacuity, the headline).  The deployed result coordinate is
concretely `2` — the spec value `ecModReduce 23 7 = 2` matches by computation.
`native_decide` is LEGITIMATE here: the EC spec is a closed-form computable
`Int` function (contrast the SHA backend, which is a non-executable TCB axiom). -/
theorem smoke_ecModReduce_value_concrete :
    RunarVerification.Crypto.Secp256k1.ecModReduce 23 7 = 2 := by native_decide

/-- SMOKE (Part 2).  The Stack-side M2 success bit fires on the concrete pair. -/
theorem smoke_ecModReduce_succeeds :
    (runOps Stack.Ec.emitEcModReduce smokeStk).toOption.isSome = true :=
  ecModReduce_stack_succeeds smokeStk 23 7 [] rfl (by decide)

/-! ## Part 4 — the wired `callBuiltin?` EC arms (deliverable 2)

Wave 71 left the `callBuiltin? "ecModReduce"` arm UNWIRED (see Part 2's note).
This wave wires the eight in-scope EC ops into `ANF.Eval.callBuiltin?`, each
routing through the concrete `Crypto.Secp256k1.*` backend defs already exposed
in `ANF/Eval.lean` (`Crypto.ecAdd` … `Crypto.ecPointY`).  `ecMul` / `ecMulGen`
stay UNWIRED (scoped out — kept as named codegen-discharge axioms).

The arm lemmas below pin each arm's reduction by `rfl` (the peer of
`AgreesCrypto.callBuiltin_sha256_arm`).  Together with the Part-1 Stack-side
transport they close the M2 leg for `ecModReduce`: the ANF side now COMPUTES
`Crypto.ecModReduce value m` instead of returning `.ok none` → `crypto_call`.
No new axiom: the backend defs are concrete. -/

open RunarVerification.ANF.Eval (callBuiltin?) in
/-- The `ecModReduce` arm now fires on a two-int argument list, returning the
backend reduction.  Pins the ANF half of the `ecModReduce` M2 agreement. -/
theorem callBuiltin_ecModReduce_arm (a m : Int) :
    callBuiltin? "ecModReduce" [.vBigint a, .vBigint m]
      = .ok (some (.vBigint (RunarVerification.ANF.Eval.Crypto.ecModReduce a m))) := rfl

open RunarVerification.ANF.Eval (callBuiltin?) in
/-- The `ecAdd` arm fires on two byte-valued points. -/
theorem callBuiltin_ecAdd_arm (p q : ByteArray) :
    callBuiltin? "ecAdd" [.vBytes p, .vBytes q]
      = .ok (some (.vBytes (RunarVerification.ANF.Eval.Crypto.ecAdd p q))) := rfl

open RunarVerification.ANF.Eval (callBuiltin?) in
/-- The `ecNegate` arm fires on one byte-valued point. -/
theorem callBuiltin_ecNegate_arm (p : ByteArray) :
    callBuiltin? "ecNegate" [.vBytes p]
      = .ok (some (.vBytes (RunarVerification.ANF.Eval.Crypto.ecNegate p))) := rfl

open RunarVerification.ANF.Eval (callBuiltin?) in
/-- The `ecOnCurve` arm fires on one byte-valued point, returning a Bool. -/
theorem callBuiltin_ecOnCurve_arm (p : ByteArray) :
    callBuiltin? "ecOnCurve" [.vBytes p]
      = .ok (some (.vBool (RunarVerification.ANF.Eval.Crypto.ecOnCurve p))) := rfl

open RunarVerification.ANF.Eval (callBuiltin?) in
/-- The `ecEncodeCompressed` arm fires on one byte-valued point. -/
theorem callBuiltin_ecEncodeCompressed_arm (p : ByteArray) :
    callBuiltin? "ecEncodeCompressed" [.vBytes p]
      = .ok (some (.vBytes (RunarVerification.ANF.Eval.Crypto.ecEncodeCompressed p))) := rfl

open RunarVerification.ANF.Eval (callBuiltin?) in
/-- The `ecMakePoint` arm fires on two ints. -/
theorem callBuiltin_ecMakePoint_arm (x y : Int) :
    callBuiltin? "ecMakePoint" [.vBigint x, .vBigint y]
      = .ok (some (.vBytes (RunarVerification.ANF.Eval.Crypto.ecMakePoint x y))) := rfl

open RunarVerification.ANF.Eval (callBuiltin?) in
/-- The `ecPointX` arm fires on one byte-valued point, returning an Int. -/
theorem callBuiltin_ecPointX_arm (p : ByteArray) :
    callBuiltin? "ecPointX" [.vBytes p]
      = .ok (some (.vBigint (RunarVerification.ANF.Eval.Crypto.ecPointX p))) := rfl

open RunarVerification.ANF.Eval (callBuiltin?) in
/-- The `ecPointY` arm fires on one byte-valued point, returning an Int. -/
theorem callBuiltin_ecPointY_arm (p : ByteArray) :
    callBuiltin? "ecPointY" [.vBytes p]
      = .ok (some (.vBigint (RunarVerification.ANF.Eval.Crypto.ecPointY p))) := rfl

/-- SMOKE (deliverable 2, ANF arm anti-vacuity).  The wired `ecModReduce` arm,
applied to the same concrete pair `(23, 7)`, computes the spec value `2` — the
ANF half now AGREES with the Stack-side transport (`smoke_ecModReduce_value_concrete`).
`native_decide` is legitimate: the EC spec is a closed-form computable `Int`. -/
theorem smoke_callBuiltin_ecModReduce_arm :
    (match callBuiltin? "ecModReduce" [.vBigint 23, .vBigint 7] with
     | .ok (some (.vBigint n)) => n == 2
     | _ => false) = true := by native_decide

/-- SMOKE (deliverable 2).  A NOT-wired op (`ecMul`, scoped out) still returns
`.ok none` — confirming the scope boundary: only the eight in-scope arms route
through the backend; `ecMul` / `ecMulGen` keep falling through to `crypto_call`. -/
theorem smoke_callBuiltin_ecMul_unwired :
    callBuiltin? "ecMul" [.vBytes (ByteArray.mk #[0x00]), .vBigint 1] = .ok none := rfl

/-! ## Part 5 — the `reverse32` loop transport (deliverable 3)

`Stack.Ec.emitReverse32Step` is the 7-op fragment

```text
[ .push (.bigint 1), .opcode "OP_SPLIT", .rot, .rot, .swap, .opcode "OP_CAT", .swap ]
```

Run on `stack = vBytes value :: vBytes acc :: rest` (value on TOS, with
`1 ≤ value.size`), it peels the FIRST byte off `value` and PREPENDS it to `acc`,
leaving `stack = vBytes (value.extract 1 value.size) :: vBytes (value.extract 0 1 ++ acc) :: rest`.
The loop `emitReverse32Loop n` iterates this `n` times; over a full-size value it
reverses the byte order into the accumulator (verified empirically: a length-3
value `[10,20,30]` with acc `[99]` becomes `[30,20,10,99]`).

**UNBLOCKED (the OP_0 wrapper).** `emitReverse32Ops = [.opcode "OP_0", .swap] ++ loop ++ [.drop]`
initializes the accumulator with `OP_0`. The Stack VM models `OP_0` as `.vBigint 0`
(`Stack.Eval.runOpcode "OP_0" = s.push (.vBigint 0)`); the parser likewise turns the
wire byte `0x00` into `vBigint 0`. Wave 72 BLOCKED here because the first loop step's
`OP_CAT` rejected the `vBigint 0` accumulator. That was a Bitcoin-faithfulness GAP in
`asBytes?`: on a real Script stack the number 0 IS the empty byte vector
(`encodeMinimalLE 0 = ByteArray.empty`) and `OP_CAT(empty, x) = x`. This wave closes
the gap by making `Stack.Eval.asBytes? (.vBigint 0) = some ByteArray.empty` (the narrow,
fully-faithful zero coercion; see `Stack/Eval.lean`). The wrapper transport
`reverse32_ops_transport` below is now a THEOREM (proved via
`reverse32_step_transport_accV` for the seeded first step + `reverse32_loop_transport`
for the rest + `drop`), with a concrete 32-byte success smoke. No new axiom. -/

/-- **reverse32 single-step transport.**  One `emitReverse32Step` on
`[value, acc] ++ rest` (value on TOS, `1 ≤ value.size`) peels the head byte of
`value` onto the front of `acc`. -/
theorem reverse32_step_transport
    (s : StackState) (value acc : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes value :: .vBytes acc :: rest)
    (hSize : 1 ≤ value.size) :
    runOps Stack.Ec.emitReverse32Step s
      = .ok { s with
              stack := .vBytes (value.extract 1 value.size)
                        :: .vBytes (value.extract 0 1 ++ acc) :: rest } := by
  obtain ⟨stk, alt, out, props, pre⟩ := s
  subst hStk
  have niRot : ∀ t e, StackOp.rot ≠ .ifOp t e := by intro t e h; cases h
  have niSwap : ∀ t e, StackOp.swap ≠ .ifOp t e := by intro t e h; cases h
  have niOp : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by
    intro c t e h; cases h
  have niPush : ∀ (pv : PushVal) t e, StackOp.push pv ≠ .ifOp t e := by
    intro pv t e h; cases h
  have stepNonIf_rot : ∀ (st : StackState), stepNonIf .rot st = applyRot st := by
    intro st; rfl
  -- emitReverse32Step is the literal 7-op list.
  show runOps
      ([ StackOp.push (.bigint 1), StackOp.opcode "OP_SPLIT", StackOp.rot,
         StackOp.rot, StackOp.swap, StackOp.opcode "OP_CAT", StackOp.swap ])
      { stack := .vBytes value :: .vBytes acc :: rest, altstack := alt,
        outputs := out, props := props, preimage := pre } = _
  -- Step 1: push 1.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 1)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- Step 2: OP_SPLIT at index 1.  Guard discharged by hSize.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_SPLIT"), stepNonIf_opcode]
  rw [show runOpcode "OP_SPLIT"
        { stack := .vBigint 1 :: .vBytes value :: .vBytes acc :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (value.extract 1 value.size)
                          :: .vBytes (value.extract 0 1) :: .vBytes acc :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      unfold runOpcode
      simp only [popN, StackState.pop?, asBytes?, asNonNegativeNat?, asInt?,
                 StackState.push, Int.reduceLT, reduceIte, Int.toNat_one]
      rw [if_neg (by omega : ¬ (1 : Nat) > value.size)] ]
  simp only [match_Except_ok_runOps]
  -- Step 3: rot.
  rw [runOps_cons_nonIf_eq _ _ _ niRot, stepNonIf_rot]
  rw [show applyRot
        { stack := .vBytes (value.extract 1 value.size) :: .vBytes (value.extract 0 1)
                    :: .vBytes acc :: rest, altstack := alt, outputs := out,
          props := props, preimage := pre }
        = .ok { stack := .vBytes acc :: .vBytes (value.extract 1 value.size)
                          :: .vBytes (value.extract 0 1) :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 4: rot.
  rw [runOps_cons_nonIf_eq _ _ _ niRot, stepNonIf_rot]
  rw [show applyRot
        { stack := .vBytes acc :: .vBytes (value.extract 1 value.size)
                    :: .vBytes (value.extract 0 1) :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (value.extract 0 1) :: .vBytes acc
                          :: .vBytes (value.extract 1 value.size) :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 5: swap.
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBytes (value.extract 0 1) :: .vBytes acc
                    :: .vBytes (value.extract 1 value.size) :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes acc :: .vBytes (value.extract 0 1)
                          :: .vBytes (value.extract 1 value.size) :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 6: OP_CAT → extract 0 1 ++ acc.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_CAT"), stepNonIf_opcode]
  rw [show runOpcode "OP_CAT"
        { stack := .vBytes acc :: .vBytes (value.extract 0 1)
                    :: .vBytes (value.extract 1 value.size) :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (value.extract 0 1 ++ acc)
                          :: .vBytes (value.extract 1 value.size) :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 7: swap → final layout.
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBytes (value.extract 0 1 ++ acc)
                    :: .vBytes (value.extract 1 value.size) :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (value.extract 1 value.size)
                          :: .vBytes (value.extract 0 1 ++ acc) :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps, runOps_nil]

/-- **reverse32 single-step transport with a coercible non-`vBytes` accumulator.**
Identical to `reverse32_step_transport` but the accumulator slot holds an arbitrary
`accV : Value` whose Bitcoin-faithful byte view is `acc` (`asBytes? accV = some acc`).
This is what lets the FIRST loop step run against the `OP_0`-initialized accumulator
(`accV = .vBigint 0`, `acc = ByteArray.empty`): on a real Script stack `OP_0` is the
empty byte vector, and `OP_CAT(x, empty) = x`.  Only step 6 (`OP_CAT`) differs from
the `vBytes` form — every other op (`OP_SPLIT`, `rot`, `swap`) is value-agnostic. -/
theorem reverse32_step_transport_accV
    (s : StackState) (value acc : ByteArray) (accV : Value) (rest : List Value)
    (hStk : s.stack = .vBytes value :: accV :: rest)
    (hAcc : asBytes? accV = some acc)
    (hSize : 1 ≤ value.size) :
    runOps Stack.Ec.emitReverse32Step s
      = .ok { s with
              stack := .vBytes (value.extract 1 value.size)
                        :: .vBytes (value.extract 0 1 ++ acc) :: rest } := by
  obtain ⟨stk, alt, out, props, pre⟩ := s
  subst hStk
  have niRot : ∀ t e, StackOp.rot ≠ .ifOp t e := by intro t e h; cases h
  have niSwap : ∀ t e, StackOp.swap ≠ .ifOp t e := by intro t e h; cases h
  have niOp : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by
    intro c t e h; cases h
  have niPush : ∀ (pv : PushVal) t e, StackOp.push pv ≠ .ifOp t e := by
    intro pv t e h; cases h
  have stepNonIf_rot : ∀ (st : StackState), stepNonIf .rot st = applyRot st := by
    intro st; rfl
  show runOps
      ([ StackOp.push (.bigint 1), StackOp.opcode "OP_SPLIT", StackOp.rot,
         StackOp.rot, StackOp.swap, StackOp.opcode "OP_CAT", StackOp.swap ])
      { stack := .vBytes value :: accV :: rest, altstack := alt,
        outputs := out, props := props, preimage := pre } = _
  -- Step 1: push 1.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 1)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- Step 2: OP_SPLIT at index 1.  Guard discharged by hSize.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_SPLIT"), stepNonIf_opcode]
  rw [show runOpcode "OP_SPLIT"
        { stack := .vBigint 1 :: .vBytes value :: accV :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (value.extract 1 value.size)
                          :: .vBytes (value.extract 0 1) :: accV :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      unfold runOpcode
      simp only [popN, StackState.pop?, asBytes?, asNonNegativeNat?, asInt?,
                 StackState.push, Int.reduceLT, reduceIte, Int.toNat_one]
      rw [if_neg (by omega : ¬ (1 : Nat) > value.size)] ]
  simp only [match_Except_ok_runOps]
  -- Step 3: rot.
  rw [runOps_cons_nonIf_eq _ _ _ niRot, stepNonIf_rot]
  rw [show applyRot
        { stack := .vBytes (value.extract 1 value.size) :: .vBytes (value.extract 0 1)
                    :: accV :: rest, altstack := alt, outputs := out,
          props := props, preimage := pre }
        = .ok { stack := accV :: .vBytes (value.extract 1 value.size)
                          :: .vBytes (value.extract 0 1) :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 4: rot.
  rw [runOps_cons_nonIf_eq _ _ _ niRot, stepNonIf_rot]
  rw [show applyRot
        { stack := accV :: .vBytes (value.extract 1 value.size)
                    :: .vBytes (value.extract 0 1) :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (value.extract 0 1) :: accV
                          :: .vBytes (value.extract 1 value.size) :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 5: swap.
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBytes (value.extract 0 1) :: accV
                    :: .vBytes (value.extract 1 value.size) :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := accV :: .vBytes (value.extract 0 1)
                          :: .vBytes (value.extract 1 value.size) :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 6: OP_CAT → extract 0 1 ++ acc.  This is the only arm that inspects the
  -- accumulator value; the coercion `asBytes? accV = some acc` feeds `liftBytesBin`.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_CAT"), stepNonIf_opcode]
  rw [show runOpcode "OP_CAT"
        { stack := accV :: .vBytes (value.extract 0 1)
                    :: .vBytes (value.extract 1 value.size) :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (value.extract 0 1 ++ acc)
                          :: .vBytes (value.extract 1 value.size) :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } by
      unfold runOpcode liftBytesBin
      simp only [popN, StackState.pop?]
      rw [hAcc]
      simp only [asBytes?, StackState.push]]
  simp only [match_Except_ok_runOps]
  -- Step 7: swap → final layout.
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBytes (value.extract 0 1 ++ acc)
                    :: .vBytes (value.extract 1 value.size) :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (value.extract 1 value.size)
                          :: .vBytes (value.extract 0 1 ++ acc) :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps, runOps_nil]

/-! ### The loop spec and transport (by induction on the iteration count)

`reverseTail`/`reverseAcc` recursively model the value-residue and accumulator
that `emitReverse32Loop n` leaves on the stack: each iteration peels the head
byte (`extract 0 1`) onto the front of the accumulator and recurses on the tail
(`extract 1 size`).  `reverse32_loop_transport` then proves the loop's `runOps`
matches these specs, threaded by `n` honest applications of the step lemma.

These are closed-form `ByteArray` functions (no axiom).  For a full-size value
the residue is empty and the accumulator is the byte-reversed value prefixed onto
the original `acc` — the byte-reversal the medium EC ops need (witnessed by the
concrete smoke below). -/

/-- The value-residue after `n` reverse-loop iterations. -/
def reverseTail : Nat → ByteArray → ByteArray
  | 0,     v => v
  | k + 1, v => reverseTail k (v.extract 1 v.size)

/-- The accumulator after `n` reverse-loop iterations: each step prepends the
current head byte (`extract 0 1`) to the front of the running accumulator. -/
def reverseAcc : Nat → ByteArray → ByteArray → ByteArray
  | 0,     _, acc => acc
  | k + 1, v, acc => reverseAcc k (v.extract 1 v.size) (v.extract 0 1 ++ acc)

/-- **reverse32 loop transport.**  Running `emitReverse32Loop n` on
`[value, acc] ++ rest` (value on TOS, `n ≤ value.size`) leaves
`[reverseTail n value, reverseAcc n value acc] ++ rest`.  Proved by induction on
`n` via `reverse32_step_transport`.  The `n ≤ value.size` precondition keeps every
intermediate `OP_SPLIT` index in range. -/
theorem reverse32_loop_transport
    (n : Nat) :
    ∀ (s : StackState) (value acc : ByteArray) (rest : List Value),
      s.stack = .vBytes value :: .vBytes acc :: rest →
      n ≤ value.size →
      runOps (Stack.Ec.emitReverse32Loop n) s
        = .ok { s with
                stack := .vBytes (reverseTail n value)
                          :: .vBytes (reverseAcc n value acc) :: rest } := by
  induction n with
  | zero =>
      intro s value acc rest hStk _
      show runOps [] s = _
      rw [runOps_nil]
      obtain ⟨stk, alt, out, props, pre⟩ := s
      simp only at hStk
      subst hStk
      rfl
  | succ k ih =>
      intro s value acc rest hStk hLe
      -- emitReverse32Loop (k+1) = emitReverse32Step ++ emitReverse32Loop k
      have hUnfold : Stack.Ec.emitReverse32Loop (k + 1)
          = Stack.Ec.emitReverse32Step ++ Stack.Ec.emitReverse32Loop k := rfl
      rw [hUnfold, runOps_append]
      -- One step peels the head byte.
      rw [reverse32_step_transport s value acc rest hStk (by omega)]
      simp only [match_Except_ok_runOps]
      -- Recurse on the tail.  `(value.extract 1 value.size).size = value.size - 1 ≥ k`.
      have hTailSize : (value.extract 1 value.size).size = value.size - 1 := by
        rw [ByteArray.size_extract]
        omega
      rw [ih { s with stack := .vBytes (value.extract 1 value.size)
                        :: .vBytes (value.extract 0 1 ++ acc) :: rest }
            (value.extract 1 value.size) (value.extract 0 1 ++ acc) rest rfl
            (by rw [hTailSize]; omega)]
      rfl

/-! ### MANDATORY smokes for the loop transport (deliverable 3) -/

/-- Concrete value `[10,20,30]` (TOS), accumulator `[99]`. -/
private def smokeRevStk : StackState :=
  { (default : StackState) with
    stack := [.vBytes (ByteArray.mk #[10, 20, 30]), .vBytes (ByteArray.mk #[99])] }

/-- SMOKE (step, anti-vacuity).  One step on `[[10,20,30],[99]]` peels `10`:
result `[[20,30], [10,99]]`. -/
theorem smoke_reverse32_step :
    runOps Stack.Ec.emitReverse32Step smokeRevStk
      = .ok { smokeRevStk with
              stack := [.vBytes ((ByteArray.mk #[10, 20, 30]).extract 1 3),
                        .vBytes ((ByteArray.mk #[10, 20, 30]).extract 0 1
                                  ++ ByteArray.mk #[99])] } :=
  reverse32_step_transport smokeRevStk (ByteArray.mk #[10, 20, 30]) (ByteArray.mk #[99]) []
    rfl (by decide)

/-- SMOKE (loop, the headline).  Running the 3-iteration loop on `[[10,20,30],[99]]`
reverses the value into the accumulator: the result accumulator byte-list is
`[30, 20, 10, 99]` and the residue is empty.  `native_decide` is legitimate —
`reverseTail` / `reverseAcc` are closed-form computable `ByteArray` functions. -/
theorem smoke_reverse32_loop_value_concrete :
    (reverseAcc 3 (ByteArray.mk #[10, 20, 30]) (ByteArray.mk #[99])).toList
        = [30, 20, 10, 99]
      ∧ (reverseTail 3 (ByteArray.mk #[10, 20, 30])).toList = [] := by
  native_decide

/-- SMOKE (loop transport fires).  The loop `runOps` on the concrete stack
succeeds and lands the reversed accumulator — the step lemma really composes. -/
theorem smoke_reverse32_loop_succeeds :
    (runOps (Stack.Ec.emitReverse32Loop 3) smokeRevStk).toOption.isSome = true := by
  rw [reverse32_loop_transport 3 smokeRevStk (ByteArray.mk #[10, 20, 30])
        (ByteArray.mk #[99]) [] rfl (by decide)]
  rfl

/-! ### The `emitReverse32Ops` wrapper transport (UNBLOCKED by the faithful `asBytes?`)

`emitReverse32Ops = [OP_0, swap] ++ emitReverse32Loop 32 ++ [drop]`.  Wave-72 BLOCKED
here because `OP_0` pushes `vBigint 0` and the first loop step's `OP_CAT` rejected the
non-`vBytes` accumulator.  With the Bitcoin-faithful `asBytes? (vBigint 0) = some empty`
(the number 0 IS the empty byte vector; `OP_CAT(empty, x) = x`) the wrapper now RUNS:
* `OP_0` seeds `vBigint 0`, `swap` puts it under the value;
* the FIRST loop step runs via `reverse32_step_transport_accV` (accumulator `vBigint 0`,
  byte view `empty`), turning the accumulator into `.vBytes (value.extract 0 1 ++ empty)`;
* the remaining 31 steps run via `reverse32_loop_transport`;
* `drop` removes the empty value residue, leaving `.vBytes (reverseAcc 32 value empty)`
  — the byte-reversed `value`.  This is the substrate the 5 medium EC ops consume. -/
theorem reverse32_ops_transport
    (s : StackState) (value : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes value :: rest)
    (hSize : 32 ≤ value.size) :
    runOps Stack.Ec.emitReverse32Ops s
      = .ok { s with stack := .vBytes (reverseAcc 32 value ByteArray.empty) :: rest } := by
  have niSwap : ∀ t e, StackOp.swap ≠ .ifOp t e := by intro t e h; cases h
  have niDrop : ∀ t e, StackOp.drop ≠ .ifOp t e := by intro t e h; cases h
  have niOp : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by
    intro c t e h; cases h
  -- emitReverse32Ops = [OP_0, swap] ++ (emitReverse32Loop 32 ++ [drop]).
  have hUnfold : Stack.Ec.emitReverse32Ops
      = StackOp.opcode "OP_0" :: StackOp.swap
          :: (Stack.Ec.emitReverse32Loop 32 ++ [StackOp.drop]) := rfl
  rw [hUnfold]
  -- Step A: OP_0 pushes vBigint 0.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_0"), stepNonIf_opcode]
  rw [show runOpcode "OP_0" s = .ok (s.push (.vBigint 0)) from rfl]
  simp only [match_Except_ok_runOps]
  -- Step B: swap → [value, vBigint 0] ++ rest.
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  obtain ⟨stk, alt, out, props, pre⟩ := s
  simp only [StackState.push] at hStk ⊢
  subst hStk
  rw [show applySwap
        { stack := .vBigint 0 :: .vBytes value :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes value :: .vBigint 0 :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- The loop+drop on [value, vBigint 0].  Split the loop's first step out.
  rw [runOps_append]
  -- emitReverse32Loop 32 = emitReverse32Step ++ emitReverse32Loop 31.
  have hLoop : Stack.Ec.emitReverse32Loop 32
      = Stack.Ec.emitReverse32Step ++ Stack.Ec.emitReverse32Loop 31 := rfl
  rw [hLoop, runOps_append]
  -- First step against the vBigint-0 accumulator (byte view = empty).
  rw [reverse32_step_transport_accV
        { stack := .vBytes value :: .vBigint 0 :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        value ByteArray.empty (.vBigint 0) rest rfl asBytes?_vBigint_zero (by omega)]
  simp only [match_Except_ok_runOps]
  -- Remaining 31 steps via the bytes-accumulator loop transport.
  have hTailSize : (value.extract 1 value.size).size = value.size - 1 := by
    rw [ByteArray.size_extract]; omega
  rw [reverse32_loop_transport 31
        { stack := .vBytes (value.extract 1 value.size)
                    :: .vBytes (value.extract 0 1 ++ ByteArray.empty) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        (value.extract 1 value.size) (value.extract 0 1 ++ ByteArray.empty) rest rfl
        (by rw [hTailSize]; omega)]
  simp only [match_Except_ok_runOps]
  -- drop removes the residue (reverseTail 32 value).
  rw [runOps_cons_nonIf_eq _ _ _ niDrop, stepNonIf_drop]
  rw [show applyDrop
        { stack := .vBytes (reverseTail 31 (value.extract 1 value.size))
                    :: .vBytes (reverseAcc 31 (value.extract 1 value.size)
                                  (value.extract 0 1 ++ ByteArray.empty)) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (reverseAcc 31 (value.extract 1 value.size)
                                    (value.extract 0 1 ++ ByteArray.empty)) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps, runOps_nil]
  -- reverseAcc 32 value empty = reverseAcc 31 (extract 1..) (extract 0 1 ++ empty)
  -- by one unfold of reverseAcc.
  rfl

/-- SMOKE (the headline — UNBLOCKED).  On a concrete 32-byte input the full
production `emitReverse32Ops` wrapper now SUCCEEDS (was BLOCKED in wave 72) and
lands the byte-reversed value.  The reversed bytes match the closed-form
`reverseAcc` spec, confirmed by `native_decide`.  `OP_0`'s `vBigint 0` is now
consumed by `OP_CAT` exactly as the empty byte vector on a real Script stack. -/
private def smokeRev32Val : ByteArray :=
  ByteArray.mk #[ 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
                 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]

private def smokeRev32Stk : StackState :=
  { (default : StackState) with stack := [.vBytes smokeRev32Val] }

theorem smoke_reverse32_ops_succeeds :
    runOps Stack.Ec.emitReverse32Ops smokeRev32Stk
      = .ok { smokeRev32Stk with
              stack := [.vBytes (reverseAcc 32 smokeRev32Val ByteArray.empty)] } :=
  reverse32_ops_transport smokeRev32Stk smokeRev32Val [] rfl (by decide)

/-- SMOKE (anti-vacuity).  The reversed accumulator really is `value` byte-reversed:
`[32, 31, …, 2, 1]`.  `reverseAcc` is a closed-form computable `ByteArray` function,
so `native_decide` legitimately runs it. -/
theorem smoke_reverse32_ops_value_concrete :
    (reverseAcc 32 smokeRev32Val ByteArray.empty).toList
      = [32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
         16, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1] := by
  native_decide

/-! ## Part 6 — DISCHARGED `Crypto/Spec.lean §7` axioms (this wave)

Two of the ten `emitEc*_runOps_eq` codegen-to-spec links (`Crypto/Spec.lean §7`)
move here from `axiom` to `theorem`:

* `emitEcModReduce_runOps_eq` — the 8-op `OP_2DUP/OP_MOD/…` fragment.  The
  `Crypto/Spec` axiom carried NO precondition and so was FALSE at `m = 0`
  (Stack `OP_MOD` errors with `divByZero`; the spec returns `0`).  Restated
  **with `m ≠ 0`** (the honest fix — the axiom had no consumers, so
  strengthening the hypothesis is harmless) and discharged directly off the
  wave-71 `ecModReduce_step_transport`.

* `emitEcEncodeCompressed_runOps_eq` — the `OP_SPLIT/OP_SIZE/OP_SUB/OP_BIN2NUM/
  OP_MOD/OP_CAT` + `.ifOp` fragment.  Proved by an honest 14-op step-chain
  (`ec_encode_op_transport`) that lands the codegen output expressed in `p`'s
  byte extracts, then lifted to the spec `Crypto.Secp256k1.ecEncodeCompressed`
  under explicit input-level well-formedness:

  - `hSplit : 32 ≤ p.size` and `hY : 1 ≤ (p.extract 32 p.size).size` keep both
    `OP_SPLIT` indices in range (a 64-byte point satisfies both);
  - `hX` — the x-half of `p` is the canonical 32-byte big-endian encoding of the
    spec x-coordinate (`p` round-trips its x);
  - `hPar` — the parity the codegen reads off the LAST byte of the y-half equals
    the spec's `pointY p % 2` (the LSB of a big-endian coordinate carries its
    parity).

  Both `hX`/`hPar` are honest invariants of every canonically-encoded point the
  EC codegen emits (witnessed by `smoke_ecEncodeCompressed_*`).  They are NOT
  assumptions about the OUTPUT — they constrain only the input `p`.

No new axiom (the spec defs and the Stack VM are USED, not introduced); both
theorems `#print axioms`-clean (only the inherited backend/`propext`/`Quot.sound`
TCB, never `sorryAx` and never the axioms they replace). -/

/-- **DISCHARGED (deliverable 1).**  `Stack.Ec.emitEcModReduce` agrees with the
spec `Crypto.Secp256k1.ecModReduce`, under the divByZero guard `m ≠ 0`.  This is
the theorem that replaces the `Crypto.Spec.emitEcModReduce_runOps_eq` axiom. -/
theorem emitEcModReduce_runOps_eq
    (stkSt : StackState) (value m : Int) (rest : List Value)
    (hStk : stkSt.stack = .vBigint m :: .vBigint value :: rest)
    (hM : m ≠ 0) :
    runOps Stack.Ec.emitEcModReduce stkSt
      = .ok { stkSt with
              stack := .vBigint (RunarVerification.Crypto.Secp256k1.ecModReduce value m)
                        :: rest } :=
  ecModReduce_step_transport stkSt value m rest hStk hM

/-- **Operational transport for `emitEcEncodeCompressed`.**  Running the 14-op
fragment on `[p] ++ rest` (p on TOS) lands `prefix ++ p.extract 0 32`, where the
`prefix` byte is `0x03` iff the last byte of the y-half (`p.extract 32 p.size`)
decodes to an odd parity, else `0x02`.  Preconditions keep both `OP_SPLIT`
indices in range.  Proof: 14 honest step reductions (`runOps_cons_nonIf_eq` for
the non-`.ifOp` ops; a `pop?`/`asBool?` branch split for the `.ifOp`). -/
theorem ec_encode_op_transport
    (s : StackState) (p : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes p :: rest)
    (hSplit : (32 : Nat) ≤ p.size)
    (hY : (1 : Nat) ≤ (p.extract 32 p.size).size) :
    runOps Stack.Ec.emitEcEncodeCompressed s
      = .ok { s with
          stack :=
            .vBytes
              ((if decodeMinimalLE
                    ((p.extract 32 p.size).extract ((p.extract 32 p.size).size - 1)
                      (p.extract 32 p.size).size) % 2 ≠ 0
                then ByteArray.mk #[0x03] else ByteArray.mk #[0x02])
                ++ p.extract 0 32) :: rest } := by
  obtain ⟨stk, alt, out, props, pre⟩ := s
  subst hStk
  have niOp : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by
    intro c t e h; cases h
  have niSwap : ∀ t e, StackOp.swap ≠ .ifOp t e := by intro t e h; cases h
  have niDrop : ∀ t e, StackOp.drop ≠ .ifOp t e := by intro t e h; cases h
  have niPush : ∀ (pv : PushVal) t e, StackOp.push pv ≠ .ifOp t e := by
    intro pv t e h; cases h
  -- emitEcEncodeCompressed is the literal op list.
  show runOps
      ([ StackOp.push (.bigint 32), StackOp.opcode "OP_SPLIT", StackOp.opcode "OP_SIZE",
         StackOp.push (.bigint 1), StackOp.opcode "OP_SUB", StackOp.opcode "OP_SPLIT",
         StackOp.opcode "OP_BIN2NUM", StackOp.push (.bigint 2), StackOp.opcode "OP_MOD",
         StackOp.swap, StackOp.drop,
         StackOp.ifOp [StackOp.push (.bytes (ByteArray.mk #[0x03]))]
                      (some [StackOp.push (.bytes (ByteArray.mk #[0x02]))]),
         StackOp.swap, StackOp.opcode "OP_CAT" ])
      { stack := .vBytes p :: rest, altstack := alt,
        outputs := out, props := props, preimage := pre } = _
  -- Step 1: push 32.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 32)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- Step 2: OP_SPLIT at index 32 → [yb, xb].
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_SPLIT"), stepNonIf_opcode]
  rw [show runOpcode "OP_SPLIT"
        { stack := .vBigint 32 :: .vBytes p :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (p.extract 32 p.size) :: .vBytes (p.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      unfold runOpcode
      simp only [popN, StackState.pop?, asBytes?, asNonNegativeNat?, asInt?,
                 StackState.push, Int.reduceLT, reduceIte]
      rw [if_neg (by omega : ¬ (32 : Int).toNat > p.size)]
      rfl ]
  simp only [match_Except_ok_runOps]
  -- Step 3: OP_SIZE → size of yb on top.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_SIZE"), stepNonIf_opcode]
  rw [show runOpcode "OP_SIZE"
        { stack := .vBytes (p.extract 32 p.size) :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint (p.extract 32 p.size).size
                          :: .vBytes (p.extract 32 p.size) :: .vBytes (p.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 4: push 1.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 1)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- Step 5: OP_SUB → (yb.size) - 1.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_SUB"), stepNonIf_opcode]
  rw [show runOpcode "OP_SUB"
        { stack := .vBigint 1 :: .vBigint (p.extract 32 p.size).size
                    :: .vBytes (p.extract 32 p.size) :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint (((p.extract 32 p.size).size : Int) - 1)
                          :: .vBytes (p.extract 32 p.size) :: .vBytes (p.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 6: OP_SPLIT at index (yb.size - 1).
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_SPLIT"), stepNonIf_opcode]
  rw [show runOpcode "OP_SPLIT"
        { stack := .vBigint (((p.extract 32 p.size).size : Int) - 1)
                    :: .vBytes (p.extract 32 p.size) :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes ((p.extract 32 p.size).extract ((p.extract 32 p.size).size - 1)
                                    (p.extract 32 p.size).size)
                          :: .vBytes ((p.extract 32 p.size).extract 0 ((p.extract 32 p.size).size - 1))
                          :: .vBytes (p.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      unfold runOpcode
      simp only [popN, StackState.pop?, asBytes?, asNonNegativeNat?, asInt?,
                 StackState.push, reduceIte]
      rw [if_neg (show ¬ ((p.extract 32 p.size).size : Int) - 1 < 0 by omega)]
      have htn : (((p.extract 32 p.size).size : Int) - 1).toNat = (p.extract 32 p.size).size - 1 := by omega
      rw [htn]
      dsimp only
      rw [if_neg (show ¬ (p.extract 32 p.size).size - 1 > (p.extract 32 p.size).size by omega)] ]
  simp only [match_Except_ok_runOps]
  -- Step 7: OP_BIN2NUM → decodeMinimalLE last_byte.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_BIN2NUM"), stepNonIf_opcode]
  rw [show runOpcode "OP_BIN2NUM"
        { stack := .vBytes ((p.extract 32 p.size).extract ((p.extract 32 p.size).size - 1)
                              (p.extract 32 p.size).size)
                    :: .vBytes ((p.extract 32 p.size).extract 0 ((p.extract 32 p.size).size - 1))
                    :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint (decodeMinimalLE ((p.extract 32 p.size).extract
                            ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size))
                          :: .vBytes ((p.extract 32 p.size).extract 0 ((p.extract 32 p.size).size - 1))
                          :: .vBytes (p.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 8: push 2.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 2)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- Step 9: OP_MOD → parity = num % 2.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_MOD"), stepNonIf_opcode]
  rw [show runOpcode "OP_MOD"
        { stack := .vBigint 2
                    :: .vBigint (decodeMinimalLE ((p.extract 32 p.size).extract
                          ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size))
                    :: .vBytes ((p.extract 32 p.size).extract 0 ((p.extract 32 p.size).size - 1))
                    :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint (decodeMinimalLE ((p.extract 32 p.size).extract
                            ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2)
                          :: .vBytes ((p.extract 32 p.size).extract 0 ((p.extract 32 p.size).size - 1))
                          :: .vBytes (p.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      show (if (2 : Int) == 0 then (Except.error EvalError.divByZero : EvalResult StackState)
            else .ok _) = _
      rw [if_neg (by decide)]; rfl ]
  simp only [match_Except_ok_runOps]
  -- Step 10: swap → [y_prefix, parity, xb].
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBigint (decodeMinimalLE ((p.extract 32 p.size).extract
                      ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2)
                    :: .vBytes ((p.extract 32 p.size).extract 0 ((p.extract 32 p.size).size - 1))
                    :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes ((p.extract 32 p.size).extract 0 ((p.extract 32 p.size).size - 1))
                          :: .vBigint (decodeMinimalLE ((p.extract 32 p.size).extract
                                ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2)
                          :: .vBytes (p.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 11: drop → [parity, xb].
  rw [runOps_cons_nonIf_eq _ _ _ niDrop, stepNonIf_drop]
  rw [show applyDrop
        { stack := .vBytes ((p.extract 32 p.size).extract 0 ((p.extract 32 p.size).size - 1))
                    :: .vBigint (decodeMinimalLE ((p.extract 32 p.size).extract
                          ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2)
                    :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint (decodeMinimalLE ((p.extract 32 p.size).extract
                            ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2)
                          :: .vBytes (p.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 12: ifOp — pops parity, picks prefix byte by parity ≠ 0.
  rw [show runOps
        ([ StackOp.ifOp [StackOp.push (.bytes (ByteArray.mk #[0x03]))]
                        (some [StackOp.push (.bytes (ByteArray.mk #[0x02]))]),
           StackOp.swap, StackOp.opcode "OP_CAT" ])
        { stack := .vBigint (decodeMinimalLE ((p.extract 32 p.size).extract
                      ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2)
                    :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = runOps ([ StackOp.swap, StackOp.opcode "OP_CAT" ])
            { stack := (if decodeMinimalLE ((p.extract 32 p.size).extract
                            ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2 ≠ 0
                        then .vBytes (ByteArray.mk #[0x03]) else .vBytes (ByteArray.mk #[0x02]))
                        :: .vBytes (p.extract 0 32) :: rest,
              altstack := alt, outputs := out, props := props, preimage := pre } by
      rw [runOps]
      by_cases hpar : decodeMinimalLE ((p.extract 32 p.size).extract
                        ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2 = 0
      · rw [if_neg (not_not_intro hpar)]
        show (match asBool? (.vBigint (decodeMinimalLE ((p.extract 32 p.size).extract
                ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2)) with
              | some true => _ | some false => _ | none => _) = _
        rw [show asBool? (.vBigint (decodeMinimalLE ((p.extract 32 p.size).extract
              ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2))
              = some false by simp only [asBool?, ne_eq, hpar, not_true_eq_false, decide_false]]
        simp only []
        rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bytes (ByteArray.mk #[0x02]))),
            stepNonIf_push_bytes]
        simp only [match_Except_ok_runOps, StackState.push, runOps_nil]
      · rw [if_pos hpar]
        show (match asBool? (.vBigint (decodeMinimalLE ((p.extract 32 p.size).extract
                ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2)) with
              | some true => _ | some false => _ | none => _) = _
        rw [show asBool? (.vBigint (decodeMinimalLE ((p.extract 32 p.size).extract
              ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2))
              = some true by simp only [asBool?, ne_eq, hpar, not_false_eq_true, decide_true]]
        simp only []
        rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bytes (ByteArray.mk #[0x03]))),
            stepNonIf_push_bytes]
        simp only [match_Except_ok_runOps, StackState.push, runOps_nil] ]
  -- Step 13: swap → [xb, prefix].
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := (if decodeMinimalLE ((p.extract 32 p.size).extract
                        ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2 ≠ 0
                    then .vBytes (ByteArray.mk #[0x03]) else .vBytes (ByteArray.mk #[0x02]))
                    :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (p.extract 0 32)
                          :: (if decodeMinimalLE ((p.extract 32 p.size).extract
                                  ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2 ≠ 0
                              then .vBytes (ByteArray.mk #[0x03]) else .vBytes (ByteArray.mk #[0x02]))
                          :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 14: OP_CAT → prefix ++ xb.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_CAT"), stepNonIf_opcode]
  rw [show runOpcode "OP_CAT"
        { stack := .vBytes (p.extract 0 32)
                    :: (if decodeMinimalLE ((p.extract 32 p.size).extract
                            ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2 ≠ 0
                        then .vBytes (ByteArray.mk #[0x03]) else .vBytes (ByteArray.mk #[0x02]))
                    :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes ((if decodeMinimalLE ((p.extract 32 p.size).extract
                              ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2 ≠ 0
                            then ByteArray.mk #[0x03] else ByteArray.mk #[0x02]) ++ p.extract 0 32)
                          :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      by_cases hpar : decodeMinimalLE ((p.extract 32 p.size).extract
                        ((p.extract 32 p.size).size - 1) (p.extract 32 p.size).size) % 2 = 0
      · rw [if_neg (not_not_intro hpar), if_neg (not_not_intro hpar)]; rfl
      · rw [if_pos hpar, if_pos hpar]; rfl ]
  simp only [match_Except_ok_runOps, runOps_nil]

open RunarVerification.Crypto.Secp256k1 (ecEncodeCompressed pointX pointY intToBE32) in
/-- **DISCHARGED (deliverable 2).**  `Stack.Ec.emitEcEncodeCompressed` agrees with
the spec `Crypto.Secp256k1.ecEncodeCompressed`, under canonical-encoding
well-formedness on the input point `p` (`hX`, `hPar`) plus the two split-range
preconditions (`hSplit`, `hY`).  This is the theorem that replaces the
`Crypto.Spec.emitEcEncodeCompressed_runOps_eq` axiom (which was missing all four
hypotheses, hence not dischargeable verbatim). -/
theorem emitEcEncodeCompressed_runOps_eq
    (stkSt : StackState) (p : ByteArray) (rest : List Value)
    (hStk : stkSt.stack = .vBytes p :: rest)
    (hSplit : (32 : Nat) ≤ p.size)
    (hY : (1 : Nat) ≤ (p.extract 32 p.size).size)
    (hX : p.extract 0 32 = intToBE32 (pointX p))
    (hPar : decodeMinimalLE ((p.extract 32 p.size).extract ((p.extract 32 p.size).size - 1)
              (p.extract 32 p.size).size) % 2 = pointY p % 2) :
    runOps Stack.Ec.emitEcEncodeCompressed stkSt
      = .ok { stkSt with stack := .vBytes (ecEncodeCompressed p) :: rest } := by
  rw [ec_encode_op_transport stkSt p rest hStk hSplit hY]
  congr 2
  rw [hX]
  unfold ecEncodeCompressed
  simp only []
  rw [hPar]
  by_cases hy : pointY p % 2 = 0
  · rw [if_neg (not_not_intro hy), if_pos hy]
  · rw [if_pos hy, if_neg hy]

/-! ### MANDATORY in-file smokes (deliverable 1 + 2, anti-vacuous, concrete) -/

/-- Concrete two-int stack `[7, 23]` (m = 7 on TOS, value = 23) for the
ecModReduce discharge. -/
private def smokeModStk : StackState :=
  { (default : StackState) with stack := [.vBigint 7, .vBigint 23] }

/-- SMOKE (deliverable 1).  The discharged `emitEcModReduce_runOps_eq` FIRES on
`[7, 23]`, landing `ecModReduce 23 7 = 2`. -/
theorem smoke_emitEcModReduce_runOps_eq :
    runOps Stack.Ec.emitEcModReduce smokeModStk
      = .ok { smokeModStk with
              stack := .vBigint (RunarVerification.Crypto.Secp256k1.ecModReduce 23 7) :: [] } :=
  emitEcModReduce_runOps_eq smokeModStk 23 7 [] rfl (by decide)

/-- A concrete CANONICALLY-ENCODED point `p = makePoint 5 6` (x = 5, y = 6), so
the wf hypotheses `hX`/`hPar` hold by computation, and `p.size = 64`. -/
private def smokeEncPt : ByteArray :=
  RunarVerification.Crypto.Secp256k1.makePoint 5 6

/-- Concrete one-point stack `[p]` for the ecEncodeCompressed discharge. -/
private def smokeEncStk : StackState :=
  { (default : StackState) with stack := [.vBytes smokeEncPt] }

/-- SMOKE (deliverable 2, wf anti-vacuity).  The two well-formedness hypotheses
of `emitEcEncodeCompressed_runOps_eq` are SATISFIABLE — they hold concretely for
the canonically-encoded point `makePoint 5 6`.  `native_decide` is legitimate:
`intToBE32`, `pointX/Y`, `decodeMinimalLE`, `extract` are all closed-form
computable.  This rules out a vacuous discharge. -/
theorem smoke_ecEncodeCompressed_wf_satisfiable :
    (32 : Nat) ≤ smokeEncPt.size
      ∧ (1 : Nat) ≤ (smokeEncPt.extract 32 smokeEncPt.size).size
      ∧ smokeEncPt.extract 0 32
          = RunarVerification.Crypto.Secp256k1.intToBE32
              (RunarVerification.Crypto.Secp256k1.pointX smokeEncPt)
      ∧ decodeMinimalLE ((smokeEncPt.extract 32 smokeEncPt.size).extract
            ((smokeEncPt.extract 32 smokeEncPt.size).size - 1)
            (smokeEncPt.extract 32 smokeEncPt.size).size) % 2
          = RunarVerification.Crypto.Secp256k1.pointY smokeEncPt % 2 := by
  native_decide

/-- SMOKE (deliverable 2, the headline).  The discharged
`emitEcEncodeCompressed_runOps_eq` FIRES on the concrete well-formed point: the
14-op fragment lands exactly `ecEncodeCompressed (makePoint 5 6)`. -/
theorem smoke_emitEcEncodeCompressed_runOps_eq :
    runOps Stack.Ec.emitEcEncodeCompressed smokeEncStk
      = .ok { smokeEncStk with
              stack := .vBytes (RunarVerification.Crypto.Secp256k1.ecEncodeCompressed smokeEncPt)
                        :: [] } :=
  emitEcEncodeCompressed_runOps_eq smokeEncStk smokeEncPt [] rfl
    (by native_decide) (by native_decide) (by native_decide) (by native_decide)

/-- SMOKE (deliverable 2, value anti-vacuity).  The deployed compressed encoding
of `makePoint 5 6` is concretely the 33-byte `0x02 ‖ 32-byte BE x` (y = 6 is even
→ prefix `0x02`).  `native_decide` is legitimate (the spec is closed-form). -/
theorem smoke_ecEncodeCompressed_value_concrete :
    (RunarVerification.Crypto.Secp256k1.ecEncodeCompressed smokeEncPt).toList
      = (0x02 :: (List.replicate 31 (0 : UInt8)) ++ [(5 : UInt8)]) := by
  native_decide

/-! ## Part 7 — DISCHARGED `Crypto/Spec.lean §7` axioms: the four
`reverse32`-routed "medium" coordinate ops

`ecPointX`, `ecPointY`, and `ecMakePoint` are plain op-lists whose only
non-trivial sub-block is `emitReverse32Ops` (now a theorem, Part 5).  Each runs:
* a 32-byte `OP_SPLIT` (range-guarded by `32 ≤ p.size`),
* `drop`/`swap+drop` to isolate the wanted half,
* `emitReverse32Ops` to byte-reverse it (LE) — discharged by
  `reverse32_ops_transport`,
* (X/Y) `push 0x00 ; OP_CAT ; OP_BIN2NUM` to decode the LE run as a non-negative
  `Int`, or
* (MakePoint) `push 33 ; OP_NUM2BIN ; push 32 ; OP_SPLIT ; drop ; reverse` per
  coordinate then `OP_CAT`.

Each lands the codegen output expressed in `p`'s byte extracts (or the
`num2binEncode?` of the inputs); the discharge then lifts it to the spec
(`Crypto.Secp256k1.ecPointX / ecPointY / ecMakePoint`) under input-level
canonical-encoding well-formedness — the byte-arith bridge that
`decodeMinimalLE`/`num2binEncode?` round-trip the spec's big-endian `be32At` /
`intToBE32`.  These are NOT output assumptions: they constrain only the input
`p` (or the relation between the `OP_NUM2BIN` encoding and `intToBE32`), exactly
as the wave-73 `hX`/`hPar` did for `ecEncodeCompressed`.  Both `OP_SPLIT` index
guards (`32 ≤ p.size`) are honest input wf (a 64-byte point satisfies them). -/

/-- **Operational transport for `emitEcPointX`.**  Running the
`[push 32, OP_SPLIT, drop] ++ emitReverse32Ops ++ [push 0x00, OP_CAT, OP_BIN2NUM]`
fragment on `[p] ++ rest` lands `decodeMinimalLE (revLE ++ 0x00)`, where
`revLE = reverseAcc 32 (p.extract 0 32) empty` is the byte-reversed (little-endian)
x-half.  Precondition `32 ≤ p.size` keeps the `OP_SPLIT` index in range and makes
the x-half exactly 32 bytes (so `reverse32_ops_transport` applies). -/
theorem ec_pointX_op_transport
    (s : StackState) (p : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes p :: rest)
    (hSplit : (32 : Nat) ≤ p.size) :
    runOps Stack.Ec.emitEcPointX s
      = .ok { s with
          stack := .vBigint (decodeMinimalLE
            (reverseAcc 32 (p.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00]))
            :: rest } := by
  obtain ⟨stk, alt, out, props, pre⟩ := s
  subst hStk
  have niOp : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by
    intro c t e h; cases h
  have niDrop : ∀ t e, StackOp.drop ≠ .ifOp t e := by intro t e h; cases h
  have niPush : ∀ (pv : PushVal) t e, StackOp.push pv ≠ .ifOp t e := by
    intro pv t e h; cases h
  have hXsize : (p.extract 0 32).size = 32 := by rw [ByteArray.size_extract]; omega
  -- emitEcPointX = [push 32, OP_SPLIT, drop] ++ emitReverse32Ops ++ [push 0x00, OP_CAT, OP_BIN2NUM]
  have hUnfold : Stack.Ec.emitEcPointX
      = StackOp.push (.bigint 32) :: StackOp.opcode "OP_SPLIT" :: StackOp.drop
          :: (Stack.Ec.emitReverse32Ops
              ++ [StackOp.push (.bytes (ByteArray.mk #[0x00])), StackOp.opcode "OP_CAT",
                  StackOp.opcode "OP_BIN2NUM"]) := rfl
  rw [hUnfold]
  -- Step 1: push 32.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 32)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- Step 2: OP_SPLIT at index 32 → [x_high(=p.extract 32 size), p.extract 0 32].
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_SPLIT"), stepNonIf_opcode]
  rw [show runOpcode "OP_SPLIT"
        { stack := .vBigint 32 :: .vBytes p :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (p.extract 32 p.size) :: .vBytes (p.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      unfold runOpcode
      simp only [popN, StackState.pop?, asBytes?, asNonNegativeNat?, asInt?,
                 StackState.push, Int.reduceLT, reduceIte]
      rw [if_neg (by omega : ¬ (32 : Int).toNat > p.size)]
      rfl ]
  simp only [match_Except_ok_runOps]
  -- Step 3: drop → [p.extract 0 32].
  rw [runOps_cons_nonIf_eq _ _ _ niDrop, stepNonIf_drop]
  rw [show applyDrop
        { stack := .vBytes (p.extract 32 p.size) :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (p.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- emitReverse32Ops ++ tail.
  rw [runOps_append]
  -- The reverse32 wrapper transport on the 32-byte x-half.
  rw [reverse32_ops_transport
        { stack := .vBytes (p.extract 0 32) :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        (p.extract 0 32) rest rfl (by rw [hXsize]; omega)]
  simp only [match_Except_ok_runOps]
  -- Step: push 0x00.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bytes (ByteArray.mk #[0x00]))), stepNonIf_push_bytes]
  simp only [match_Except_ok_runOps, StackState.push]
  -- Step: OP_CAT → revLE ++ 0x00.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_CAT"), stepNonIf_opcode]
  rw [show runOpcode "OP_CAT"
        { stack := .vBytes (ByteArray.mk #[0x00])
                    :: .vBytes (reverseAcc 32 (p.extract 0 32) ByteArray.empty) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (reverseAcc 32 (p.extract 0 32) ByteArray.empty
                                    ++ ByteArray.mk #[0x00]) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step: OP_BIN2NUM → decodeMinimalLE (revLE ++ 0x00).
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_BIN2NUM"), stepNonIf_opcode]
  rw [show runOpcode "OP_BIN2NUM"
        { stack := .vBytes (reverseAcc 32 (p.extract 0 32) ByteArray.empty
                              ++ ByteArray.mk #[0x00]) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint (decodeMinimalLE (reverseAcc 32 (p.extract 0 32)
                            ByteArray.empty ++ ByteArray.mk #[0x00])) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps, runOps_nil]

open RunarVerification.Crypto.Secp256k1 (ecPointX) in
/-- **DISCHARGED.**  `Stack.Ec.emitEcPointX` agrees with `Crypto.Secp256k1.ecPointX`,
under the split-range guard `32 ≤ p.size` plus the canonical-decode bridge
`hDec`: the little-endian byte-reversed x-half (with the `0x00` sign byte the
codegen appends) decodes to the spec x-coordinate.  `hDec` is an honest invariant
of every canonically big-endian-encoded 64-byte point the EC codegen emits — it
constrains only the input `p`, not the output, mirroring wave-73's `hX`.  This is
the theorem that replaces the `Crypto.Spec.emitEcPointX_runOps_eq` axiom. -/
theorem emitEcPointX_runOps_eq
    (stkSt : StackState) (pt : ByteArray) (rest : List Value)
    (hStk : stkSt.stack = .vBytes pt :: rest)
    (hSplit : (32 : Nat) ≤ pt.size)
    (hDec : decodeMinimalLE
              (reverseAcc 32 (pt.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
              = ecPointX pt) :
    runOps Stack.Ec.emitEcPointX stkSt
      = .ok { stkSt with stack := .vBigint (ecPointX pt) :: rest } := by
  rw [ec_pointX_op_transport stkSt pt rest hStk hSplit, hDec]

/-! ### MANDATORY smokes for the ecPointX discharge -/

/-- A concrete canonically-encoded point `p = makePoint 11 22`, so `p.size = 64`
and the decode bridge holds by computation. -/
private def smokePtX : ByteArray :=
  RunarVerification.Crypto.Secp256k1.makePoint 11 22

private def smokePtXStk : StackState :=
  { (default : StackState) with stack := [.vBytes smokePtX] }

/-- SMOKE (wf anti-vacuity).  The split-range and decode-bridge hypotheses of
`emitEcPointX_runOps_eq` are SATISFIABLE — they hold concretely for the
canonically-encoded `makePoint 11 22`.  `native_decide` is legitimate (every
function involved is closed-form computable).  Rules out a vacuous discharge. -/
theorem smoke_ecPointX_wf_satisfiable :
    (32 : Nat) ≤ smokePtX.size
      ∧ decodeMinimalLE
          (reverseAcc 32 (smokePtX.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
          = RunarVerification.Crypto.Secp256k1.ecPointX smokePtX := by
  native_decide

/-- SMOKE (the headline).  The discharged `emitEcPointX_runOps_eq` FIRES on the
concrete point: the fragment lands exactly `ecPointX (makePoint 11 22) = 11`. -/
theorem smoke_emitEcPointX_runOps_eq :
    runOps Stack.Ec.emitEcPointX smokePtXStk
      = .ok { smokePtXStk with
              stack := .vBigint (RunarVerification.Crypto.Secp256k1.ecPointX smokePtX) :: [] } :=
  emitEcPointX_runOps_eq smokePtXStk smokePtX [] rfl (by native_decide) (by native_decide)

/-- SMOKE (value anti-vacuity).  The extracted x is concretely `11`.
`native_decide` is legitimate (the spec is closed-form). -/
theorem smoke_ecPointX_value_concrete :
    RunarVerification.Crypto.Secp256k1.ecPointX smokePtX = 11 := by
  native_decide

/-- **Operational transport for `emitEcPointY`.**  Running the
`[push 32, OP_SPLIT, swap, drop] ++ emitReverse32Ops ++ [push 0x00, OP_CAT, OP_BIN2NUM]`
fragment on `[p] ++ rest` lands `decodeMinimalLE (revLE ++ 0x00)`, where
`revLE = reverseAcc 32 (p.extract 32 p.size) empty` is the byte-reversed
(little-endian) y-half.  Precondition `64 ≤ p.size` keeps the `OP_SPLIT` index in
range AND makes the y-half ≥ 32 bytes (so `reverse32_ops_transport` applies). -/
theorem ec_pointY_op_transport
    (s : StackState) (p : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes p :: rest)
    (hSplit : (64 : Nat) ≤ p.size) :
    runOps Stack.Ec.emitEcPointY s
      = .ok { s with
          stack := .vBigint (decodeMinimalLE
            (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty ++ ByteArray.mk #[0x00]))
            :: rest } := by
  obtain ⟨stk, alt, out, props, pre⟩ := s
  subst hStk
  have niOp : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by
    intro c t e h; cases h
  have niDrop : ∀ t e, StackOp.drop ≠ .ifOp t e := by intro t e h; cases h
  have niSwap : ∀ t e, StackOp.swap ≠ .ifOp t e := by intro t e h; cases h
  have niPush : ∀ (pv : PushVal) t e, StackOp.push pv ≠ .ifOp t e := by
    intro pv t e h; cases h
  have hYsize : (p.extract 32 p.size).size = p.size - 32 := by rw [ByteArray.size_extract]; omega
  -- emitEcPointY = [push 32, OP_SPLIT, swap, drop] ++ emitReverse32Ops ++ tail
  have hUnfold : Stack.Ec.emitEcPointY
      = StackOp.push (.bigint 32) :: StackOp.opcode "OP_SPLIT" :: StackOp.swap :: StackOp.drop
          :: (Stack.Ec.emitReverse32Ops
              ++ [StackOp.push (.bytes (ByteArray.mk #[0x00])), StackOp.opcode "OP_CAT",
                  StackOp.opcode "OP_BIN2NUM"]) := rfl
  rw [hUnfold]
  -- Step 1: push 32.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 32)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- Step 2: OP_SPLIT at index 32 → [p.extract 32 size, p.extract 0 32].
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_SPLIT"), stepNonIf_opcode]
  rw [show runOpcode "OP_SPLIT"
        { stack := .vBigint 32 :: .vBytes p :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (p.extract 32 p.size) :: .vBytes (p.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      unfold runOpcode
      simp only [popN, StackState.pop?, asBytes?, asNonNegativeNat?, asInt?,
                 StackState.push, Int.reduceLT, reduceIte]
      rw [if_neg (by omega : ¬ (32 : Int).toNat > p.size)]
      rfl ]
  simp only [match_Except_ok_runOps]
  -- Step 3: swap → [p.extract 0 32, p.extract 32 size].
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBytes (p.extract 32 p.size) :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (p.extract 0 32) :: .vBytes (p.extract 32 p.size) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step 4: drop → [p.extract 32 size].
  rw [runOps_cons_nonIf_eq _ _ _ niDrop, stepNonIf_drop]
  rw [show applyDrop
        { stack := .vBytes (p.extract 0 32) :: .vBytes (p.extract 32 p.size) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (p.extract 32 p.size) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- emitReverse32Ops ++ tail.
  rw [runOps_append]
  rw [reverse32_ops_transport
        { stack := .vBytes (p.extract 32 p.size) :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        (p.extract 32 p.size) rest rfl (by rw [hYsize]; omega)]
  simp only [match_Except_ok_runOps]
  -- Step: push 0x00.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bytes (ByteArray.mk #[0x00]))), stepNonIf_push_bytes]
  simp only [match_Except_ok_runOps, StackState.push]
  -- Step: OP_CAT → revLE ++ 0x00.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_CAT"), stepNonIf_opcode]
  rw [show runOpcode "OP_CAT"
        { stack := .vBytes (ByteArray.mk #[0x00])
                    :: .vBytes (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty
                                    ++ ByteArray.mk #[0x00]) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- Step: OP_BIN2NUM → decodeMinimalLE (revLE ++ 0x00).
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_BIN2NUM"), stepNonIf_opcode]
  rw [show runOpcode "OP_BIN2NUM"
        { stack := .vBytes (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty
                              ++ ByteArray.mk #[0x00]) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint (decodeMinimalLE (reverseAcc 32 (p.extract 32 p.size)
                            ByteArray.empty ++ ByteArray.mk #[0x00])) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps, runOps_nil]

open RunarVerification.Crypto.Secp256k1 (ecPointY) in
/-- **DISCHARGED.**  `Stack.Ec.emitEcPointY` agrees with `Crypto.Secp256k1.ecPointY`,
under the split-range guard `64 ≤ p.size` plus the canonical-decode bridge `hDec`:
the little-endian byte-reversed y-half (with the `0x00` sign byte the codegen
appends) decodes to the spec y-coordinate.  `hDec` constrains only the input `p`
(honest invariant of canonically-encoded points), mirroring wave-73's `hX`.
Replaces the `Crypto.Spec.emitEcPointY_runOps_eq` axiom. -/
theorem emitEcPointY_runOps_eq
    (stkSt : StackState) (pt : ByteArray) (rest : List Value)
    (hStk : stkSt.stack = .vBytes pt :: rest)
    (hSplit : (64 : Nat) ≤ pt.size)
    (hDec : decodeMinimalLE
              (reverseAcc 32 (pt.extract 32 pt.size) ByteArray.empty ++ ByteArray.mk #[0x00])
              = ecPointY pt) :
    runOps Stack.Ec.emitEcPointY stkSt
      = .ok { stkSt with stack := .vBigint (ecPointY pt) :: rest } := by
  rw [ec_pointY_op_transport stkSt pt rest hStk hSplit, hDec]

/-! ### MANDATORY smokes for the ecPointY discharge -/

private def smokePtY : ByteArray :=
  RunarVerification.Crypto.Secp256k1.makePoint 11 22

private def smokePtYStk : StackState :=
  { (default : StackState) with stack := [.vBytes smokePtY] }

/-- SMOKE (wf anti-vacuity).  The split-range and decode-bridge hypotheses of
`emitEcPointY_runOps_eq` hold concretely for `makePoint 11 22`. -/
theorem smoke_ecPointY_wf_satisfiable :
    (64 : Nat) ≤ smokePtY.size
      ∧ decodeMinimalLE
          (reverseAcc 32 (smokePtY.extract 32 smokePtY.size) ByteArray.empty ++ ByteArray.mk #[0x00])
          = RunarVerification.Crypto.Secp256k1.ecPointY smokePtY := by
  native_decide

/-- SMOKE (the headline).  The discharged `emitEcPointY_runOps_eq` FIRES,
landing `ecPointY (makePoint 11 22) = 22`. -/
theorem smoke_emitEcPointY_runOps_eq :
    runOps Stack.Ec.emitEcPointY smokePtYStk
      = .ok { smokePtYStk with
              stack := .vBigint (RunarVerification.Crypto.Secp256k1.ecPointY smokePtY) :: [] } :=
  emitEcPointY_runOps_eq smokePtYStk smokePtY [] rfl (by native_decide) (by native_decide)

/-- SMOKE (value anti-vacuity).  The extracted y is concretely `22`. -/
theorem smoke_ecPointY_value_concrete :
    RunarVerification.Crypto.Secp256k1.ecPointY smokePtY = 22 := by
  native_decide

set_option maxRecDepth 8192 in
/-- **Operational transport for `emitEcMakePoint`.**  Input stack `[y, x] ++ rest`
(y on TOS, per the spec arg order — the deepest input is the leftmost spec arg).
Each coordinate is `OP_NUM2BIN`-encoded to 33 LE bytes, split to its low 32 bytes,
then byte-reversed to big-endian; the two BE halves are concatenated `x ‖ y`.
Output: `revBE encX ++ revBE encY`, where `encX`/`encY` are the `num2binEncode?`
images of `x`/`y` at width 33.  Preconditions: both encodings succeed and are ≥32
bytes (honest input wf — every in-field coordinate fits in 33 bytes). -/
theorem ec_makePoint_op_transport
    (s : StackState) (x y : Int) (encX encY : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBigint y :: .vBigint x :: rest)
    (hEncX : num2binEncode? x 33 = some encX)
    (hEncY : num2binEncode? y 33 = some encY)
    (hSzX : (32 : Nat) ≤ encX.size)
    (hSzY : (32 : Nat) ≤ encY.size) :
    runOps Stack.Ec.emitEcMakePoint s
      = .ok { s with
          stack := .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty
                            ++ reverseAcc 32 (encY.extract 0 32) ByteArray.empty)
            :: rest } := by
  obtain ⟨stk, alt, out, props, pre⟩ := s
  subst hStk
  have niOp : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by
    intro c t e h; cases h
  have niDrop : ∀ t e, StackOp.drop ≠ .ifOp t e := by intro t e h; cases h
  have niSwap : ∀ t e, StackOp.swap ≠ .ifOp t e := by intro t e h; cases h
  have niPush : ∀ (pv : PushVal) t e, StackOp.push pv ≠ .ifOp t e := by
    intro pv t e h; cases h
  -- Reusable OP_NUM2BIN reduction at width 33.
  have hNum2Bin : ∀ (n : Int) (enc : ByteArray) (r : List Value),
      num2binEncode? n 33 = some enc →
      runOpcode "OP_NUM2BIN"
        { stack := .vBigint 33 :: .vBigint n :: r, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes enc :: r, altstack := alt,
                outputs := out, props := props, preimage := pre } := by
    intro n enc r hEnc
    unfold runOpcode
    simp only [popN, StackState.pop?, asInt?, StackState.push, Int.reduceLT, reduceIte]
    rw [show (33 : Int).toNat = 33 from rfl, hEnc]
  have hSzXextract : (encX.extract 0 32).size = 32 := by rw [ByteArray.size_extract]; omega
  have hSzYextract : (encY.extract 0 32).size = 32 := by rw [ByteArray.size_extract]; omega
  -- emitEcMakePoint as the literal op list.
  have hUnfold : Stack.Ec.emitEcMakePoint
      = StackOp.push (.bigint 33) :: StackOp.opcode "OP_NUM2BIN" :: StackOp.push (.bigint 32)
          :: StackOp.opcode "OP_SPLIT" :: StackOp.drop
          :: (Stack.Ec.emitReverse32Ops
              ++ (StackOp.swap :: StackOp.push (.bigint 33) :: StackOp.opcode "OP_NUM2BIN"
                  :: StackOp.push (.bigint 32) :: StackOp.opcode "OP_SPLIT" :: StackOp.drop
                  :: (Stack.Ec.emitReverse32Ops
                      ++ [StackOp.swap, StackOp.opcode "OP_CAT"]))) := rfl
  rw [hUnfold]
  -- y-branch.  push 33.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 33)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- OP_NUM2BIN → encY.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_NUM2BIN"), stepNonIf_opcode]
  rw [hNum2Bin y encY (.vBigint x :: rest) hEncY]
  simp only [match_Except_ok_runOps]
  -- push 32.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 32)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- OP_SPLIT at 32.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_SPLIT"), stepNonIf_opcode]
  rw [show runOpcode "OP_SPLIT"
        { stack := .vBigint 32 :: .vBytes encY :: .vBigint x :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (encY.extract 32 encY.size) :: .vBytes (encY.extract 0 32)
                          :: .vBigint x :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      unfold runOpcode
      simp only [popN, StackState.pop?, asBytes?, asNonNegativeNat?, asInt?,
                 StackState.push, Int.reduceLT, reduceIte]
      rw [if_neg (by omega : ¬ (32 : Int).toNat > encY.size)]
      rfl ]
  simp only [match_Except_ok_runOps]
  -- drop → [encY.extract 0 32, x].
  rw [runOps_cons_nonIf_eq _ _ _ niDrop, stepNonIf_drop]
  rw [show applyDrop
        { stack := .vBytes (encY.extract 32 encY.size) :: .vBytes (encY.extract 0 32)
                    :: .vBigint x :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (encY.extract 0 32) :: .vBigint x :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- reverse32 (y-half) ++ tail.
  rw [runOps_append]
  rw [reverse32_ops_transport
        { stack := .vBytes (encY.extract 0 32) :: .vBigint x :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        (encY.extract 0 32) (.vBigint x :: rest) rfl (by rw [hSzYextract]; omega)]
  simp only [match_Except_ok_runOps]
  -- swap → [x, revY_be].
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty)
                    :: .vBigint x :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint x
                          :: .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- x-branch.  push 33.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 33)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- OP_NUM2BIN → encX.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_NUM2BIN"), stepNonIf_opcode]
  rw [hNum2Bin x encX (.vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest) hEncX]
  simp only [match_Except_ok_runOps]
  -- push 32.
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 32)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- OP_SPLIT at 32.
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_SPLIT"), stepNonIf_opcode]
  rw [show runOpcode "OP_SPLIT"
        { stack := .vBigint 32 :: .vBytes encX
                    :: .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (encX.extract 32 encX.size) :: .vBytes (encX.extract 0 32)
                          :: .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      unfold runOpcode
      simp only [popN, StackState.pop?, asBytes?, asNonNegativeNat?, asInt?,
                 StackState.push, Int.reduceLT, reduceIte]
      rw [if_neg (by omega : ¬ (32 : Int).toNat > encX.size)]
      rfl ]
  simp only [match_Except_ok_runOps]
  -- drop.
  rw [runOps_cons_nonIf_eq _ _ _ niDrop, stepNonIf_drop]
  rw [show applyDrop
        { stack := .vBytes (encX.extract 32 encX.size) :: .vBytes (encX.extract 0 32)
                    :: .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (encX.extract 0 32)
                          :: .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- reverse32 (x-half) ++ [swap, OP_CAT].
  rw [runOps_append]
  rw [reverse32_ops_transport
        { stack := .vBytes (encX.extract 0 32)
                    :: .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        (encX.extract 0 32) (.vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest)
        rfl (by rw [hSzXextract]; omega)]
  simp only [match_Except_ok_runOps]
  -- swap → [revY_be, revX_be].
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty)
                    :: .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty)
                          :: .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- OP_CAT → revX_be ++ revY_be (popN gives [top, below] = [revY_be, revX_be]; f a b = a++b).
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_CAT"), stepNonIf_opcode]
  rw [show runOpcode "OP_CAT"
        { stack := .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty)
                    :: .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty
                                    ++ reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps, runOps_nil]

set_option maxRecDepth 8192 in
open RunarVerification.Crypto.Secp256k1 (ecMakePoint intToBE32) in
/-- **DISCHARGED.**  `Stack.Ec.emitEcMakePoint` agrees with
`Crypto.Secp256k1.ecMakePoint`, under the two `OP_NUM2BIN`-encoding hypotheses
(`hEncX`/`hEncY` — the coordinates fit in 33 bytes), the two size guards, and the
canonical-encoding bridges `hBeX`/`hBeY`: each byte-reversed low-32 `OP_NUM2BIN`
half equals the spec's big-endian `intToBE32`.  All hypotheses constrain only the
INPUTS `x`/`y` (and their canonical encodings), not the output — honest invariants
of every in-field coordinate.  Replaces the `Crypto.Spec.emitEcMakePoint_runOps_eq`
axiom. -/
theorem emitEcMakePoint_runOps_eq
    (stkSt : StackState) (x y : Int) (encX encY : ByteArray) (rest : List Value)
    (hStk : stkSt.stack = .vBigint y :: .vBigint x :: rest)
    (hEncX : num2binEncode? x 33 = some encX)
    (hEncY : num2binEncode? y 33 = some encY)
    (hSzX : (32 : Nat) ≤ encX.size)
    (hSzY : (32 : Nat) ≤ encY.size)
    (hBeX : reverseAcc 32 (encX.extract 0 32) ByteArray.empty = intToBE32 x)
    (hBeY : reverseAcc 32 (encY.extract 0 32) ByteArray.empty = intToBE32 y) :
    runOps Stack.Ec.emitEcMakePoint stkSt
      = .ok { stkSt with stack := .vBytes (ecMakePoint x y) :: rest } := by
  rw [ec_makePoint_op_transport stkSt x y encX encY rest hStk hEncX hEncY hSzX hSzY,
      hBeX, hBeY]
  rfl

/-! ### MANDATORY smokes for the ecMakePoint discharge -/

private def smokeMkX : Int := 11
private def smokeMkY : Int := 22

private def smokeMkStk : StackState :=
  { (default : StackState) with stack := [.vBigint smokeMkY, .vBigint smokeMkX] }

/-- Concrete `OP_NUM2BIN` encodings of the two coordinates at width 33. -/
private def smokeMkEncX : ByteArray :=
  (num2binEncode? smokeMkX 33).getD ByteArray.empty
private def smokeMkEncY : ByteArray :=
  (num2binEncode? smokeMkY 33).getD ByteArray.empty

/-- SMOKE (wf anti-vacuity).  All six discharge hypotheses are SATISFIABLE for
`x = 11, y = 22`: both coordinates encode at width 33 (size 33 ≥ 32) and each
byte-reversed low-32 half equals the spec `intToBE32`.  `native_decide` is
legitimate (every function is closed-form). -/
theorem smoke_ecMakePoint_wf_satisfiable :
    num2binEncode? smokeMkX 33 = some smokeMkEncX
      ∧ num2binEncode? smokeMkY 33 = some smokeMkEncY
      ∧ (32 : Nat) ≤ smokeMkEncX.size
      ∧ (32 : Nat) ≤ smokeMkEncY.size
      ∧ reverseAcc 32 (smokeMkEncX.extract 0 32) ByteArray.empty
          = RunarVerification.Crypto.Secp256k1.intToBE32 smokeMkX
      ∧ reverseAcc 32 (smokeMkEncY.extract 0 32) ByteArray.empty
          = RunarVerification.Crypto.Secp256k1.intToBE32 smokeMkY := by
  native_decide

/-- SMOKE (the headline).  The discharged `emitEcMakePoint_runOps_eq` FIRES on
`[22, 11]`, landing exactly `ecMakePoint 11 22 = makePoint 11 22`. -/
theorem smoke_emitEcMakePoint_runOps_eq :
    runOps Stack.Ec.emitEcMakePoint smokeMkStk
      = .ok { smokeMkStk with
              stack := .vBytes
                (RunarVerification.Crypto.Secp256k1.ecMakePoint smokeMkX smokeMkY) :: [] } :=
  emitEcMakePoint_runOps_eq smokeMkStk smokeMkX smokeMkY smokeMkEncX smokeMkEncY [] rfl
    (by native_decide) (by native_decide) (by native_decide) (by native_decide)
    (by native_decide) (by native_decide)

/-- SMOKE (value anti-vacuity).  The packed point round-trips: its x-coordinate is
`11` and y-coordinate is `22`. -/
theorem smoke_ecMakePoint_value_concrete :
    RunarVerification.Crypto.Secp256k1.ecPointX
        (RunarVerification.Crypto.Secp256k1.ecMakePoint smokeMkX smokeMkY) = 11
      ∧ RunarVerification.Crypto.Secp256k1.ecPointY
        (RunarVerification.Crypto.Secp256k1.ecMakePoint smokeMkX smokeMkY) = 22 := by
  native_decide

/-! ## Part 8 — the Tracker simulation invariant + model substrate (deliverable 1)

`emitEcNegate` / `emitEcOnCurve` are produced by RUNNING the `Stack.Ec.Tracker`
state machine: their `.roll d` / `.pickStruct d` ops carry depths `d =
Tracker.findDepth nm name`, picked at codegen time against the threaded name array
`nm`.  An honest `runOps` transport for either op list needs a *Tracker-to-runtime
simulation invariant*: the runtime stack `stk` (head = TOS) must mirror the
tracker name array `nm` (bottom→top) slot-for-slot, so that each `.roll`/`.pick`
depth lands on the value of the named slot it addresses.

This Part lands that invariant (`TrackerSim`) plus the reusable model substrate it
needs — all `sorry`-free, all axiom-clean (`propext`/`Quot.sound` only).  See the
BLOCK note in Part 9 for the ONE remaining kernel-level obstacle that gates the
final per-op discharge (`Tracker.findDepth` is built on the `partial`
`Lean.Loop.forIn`, which the kernel cannot reduce or induct over, so the bridge
`Tracker.findDepth = findDepthList ∘ reverse` cannot be proven without editing
`Stack/Ec.lean` — explicitly out of scope). -/

/-- Resolve a tracker slot against valuation `σ`; `none` slots are unconstrained. -/
def slotAgrees (σ : String → Value) (slot : Option String) (v : Value) : Prop :=
  match slot with
  | some n => v = σ n
  | none   => True

/-- **Tracker simulation invariant (deliverable 1).**  Runtime stack `stk`
(head = TOS) mirrors the tracker name array `nm` (bottom→top).  Reversing `nm` to
top→bottom, every named slot holds its `σ`-value; `none` slots are free.  Lengths
agree (so every `findDepth` depth lands in range).  `Tracker.findDepth nm name`
(the codegen `.roll`/`.pick` depth) is asserted-equal to the runtime structural
depth of `name`'s slot via the `findDepthList` model below (`findDepthList_sim`). -/
def TrackerSim (nm : Array (Option String)) (σ : String → Value) (stk : List Value) : Prop :=
  stk.length = nm.size ∧
  ∀ i (h : i < nm.size), slotAgrees σ (nm[i]) (stk[nm.size - 1 - i]!)

/-- Recursive model of `Tracker.findDepth` over the TOP-first name list
(`nm.toList.reverse`): index of the first matching name, else list length.  This
is the kernel-reducible counterpart the opaque `Loop.forIn`-based
`Tracker.findDepth` lacks (see Part 9). -/
def findDepthList (name : String) : List (Option String) → Nat
  | []      => 0
  | x :: xs => if x = some name then 0 else findDepthList name xs + 1

/-- The model depth is `< length` when the name is present. -/
theorem findDepthList_lt (name : String) :
    ∀ (l : List (Option String)), some name ∈ l → findDepthList name l < l.length := by
  intro l
  induction l with
  | nil => intro h; cases h
  | cons x xs ih =>
      intro hmem
      unfold findDepthList
      by_cases hx : x = some name
      · simp [hx]
      · simp only [hx, if_false]
        rw [List.length_cons]
        have hmem' : some name ∈ xs := by
          rcases List.mem_cons.mp hmem with h | h
          · exact absurd h.symm hx
          · exact h
        have := ih hmem'
        omega

/-- The model depth points at a slot actually named `name` (in the TOP-first list). -/
theorem findDepthList_get (name : String) :
    ∀ (l : List (Option String)), some name ∈ l →
      l[findDepthList name l]! = some name := by
  intro l
  induction l with
  | nil => intro h; cases h
  | cons x xs ih =>
      intro hmem
      unfold findDepthList
      by_cases hx : x = some name
      · simp [hx]
      · simp only [hx, if_false]
        have hmem' : some name ∈ xs := by
          rcases List.mem_cons.mp hmem with h | h
          · exact absurd h.symm hx
          · exact h
        rw [show findDepthList name xs + 1 = (findDepthList name xs).succ from rfl]
        rw [List.getElem!_cons_succ]
        exact ih hmem'

/-- Reverse-index bridge: the `d`-th element (top-first) of `nm.toList.reverse`
is the `(size-1-d)`-th element of `nm` (bottom-first), for `d < size`. -/
theorem reverse_getElem_bridge (nm : Array (Option String)) (d : Nat) (hd : d < nm.size) :
    (nm.toList.reverse)[d]! = nm[nm.size - 1 - d]! := by
  have hlen : nm.toList.length = nm.size := by simp
  have hd' : d < nm.toList.reverse.length := by rw [List.length_reverse, hlen]; omega
  rw [getElem!_pos (nm.toList.reverse) d hd', List.getElem_reverse]
  rw [getElem!_pos nm (nm.size - 1 - d) (show nm.size - 1 - d < nm.size by omega)]
  rw [← Array.getElem_toList]
  congr 1

/-- **`findDepthAux`-to-`findDepthList` agreement (wave-77).**  The structural
`Stack.Ec.Tracker.findDepthAux` (the kernel-reducible scan introduced by the
`Stack/Ec.lean` `findDepth` refactor) returns `some (findDepthList name l)`
whenever `name` is present in the top-first list `l`.  The two differ only in the
NOT-found case (`findDepthAux ⇒ none`, `findDepthList ⇒ l.length`); under presence
they coincide.  Proven by structural induction, `propext`/`Quot.sound`-clean. -/
theorem findDepthAux_eq_findDepthList (name : String) :
    ∀ (l : List (Option String)), some name ∈ l →
      Ec.Tracker.findDepthAux name l = some (findDepthList name l) := by
  intro l
  induction l with
  | nil => intro h; cases h
  | cons x xs ih =>
      intro hmem
      unfold Ec.Tracker.findDepthAux findDepthList
      by_cases hx : x = some name
      · simp [hx]
      · have hbeq : (x == some name) = false := by
          simp [beq_eq_false_iff_ne, hx]
        rw [hbeq]
        simp only [Bool.false_eq_true, if_false, hx]
        have hmem' : some name ∈ xs := by
          rcases List.mem_cons.mp hmem with h | h
          · exact absurd h.symm hx
          · exact h
        rw [ih hmem']
        rfl

/-- **The Part-9 BRIDGE (wave-77, was the wave-76 BLOCKER).**
`Tracker.findDepth t name = findDepthList name t.nm.toList.reverse` whenever
`name` is present in the (top-first) name list.  This is the one-line bridge the
wave-76 substrate was gated on.  It is now provable — NOT by `native_decide` — but
by unfolding the refactored structural `Stack.Ec.Tracker.findDepth`
(`(findDepthAux name t.nm.toList.reverse).getD 0`) and discharging via
`findDepthAux_eq_findDepthList` (structural induction).  This rewrites every
codegen-emitted `.roll (Tracker.findDepth …)` / `.pickStruct (Tracker.findDepth …)`
into the `findDepthList` form the wave-76 preservation lemmas
(`applyRoll_findDepth_sim` / `applyPick_findDepth_sim`) address. -/
theorem findDepth_eq_findDepthList (t : Ec.Tracker) (name : String)
    (hmem : some name ∈ t.nm.toList.reverse) :
    t.findDepth name = findDepthList name t.nm.toList.reverse := by
  unfold Ec.Tracker.findDepth
  rw [findDepthAux_eq_findDepthList name t.nm.toList.reverse hmem]
  rfl

/-- **`findDepth` model correctness under `TrackerSim` (keystone).**  When `name`
is present in the tracker, the runtime stack value at structural depth
`d := findDepthList name nm.toList.reverse` is exactly `σ name`, and `d` is in
range.  This is the lemma that — once a kernel-reducible
`Tracker.findDepth = findDepthList ∘ reverse` bridge exists (Part 9) — lets every
`toTop`/`copyToTop` step land on the correctly-named runtime slot. -/
theorem findDepthList_sim (nm : Array (Option String)) (σ : String → Value)
    (stk : List Value) (name : String)
    (hSim : TrackerSim nm σ stk)
    (hmem : some name ∈ nm.toList.reverse) :
    let d := findDepthList name nm.toList.reverse
    d < stk.length ∧ stk[d]! = σ name := by
  intro d
  obtain ⟨hlen, hslot⟩ := hSim
  have hrevlen : nm.toList.reverse.length = nm.size := by rw [List.length_reverse]; simp
  have hd_lt : d < nm.size := by
    have := findDepthList_lt name nm.toList.reverse hmem
    rwa [hrevlen] at this
  refine ⟨by omega, ?_⟩
  have hget : nm.toList.reverse[d]! = some name := findDepthList_get name nm.toList.reverse hmem
  rw [reverse_getElem_bridge nm d hd_lt] at hget
  have hidx : nm.size - 1 - d < nm.size := by omega
  have hslotd := hslot (nm.size - 1 - d) hidx
  have heq : nm.size - 1 - (nm.size - 1 - d) = d := by omega
  rw [heq] at hslotd
  have hgetbang : nm[nm.size - 1 - d] = some name := by
    rw [← hget, getElem!_pos nm (nm.size - 1 - d) hidx]
  unfold slotAgrees at hslotd
  rw [hgetbang] at hslotd
  exact hslotd

/-- Updating the valuation at a fresh name preserves agreement at all OTHER names. -/
theorem slotAgrees_update_ne (σ : String → Value) (name : String) (v : Value)
    (slot : Option String) (w : Value) (hne : slot ≠ some name) :
    slotAgrees σ slot w → slotAgrees (fun s => if s = name then v else σ s) slot w := by
  intro h
  cases slot with
  | none => exact h
  | some n =>
      unfold slotAgrees at h ⊢
      have : n ≠ name := by intro hc; exact hne (by rw [hc])
      simp only [this, if_false]
      exact h

/-- **Push preservation.**  Pushing a value `v` for a fresh `some name` slot
(`nm.push (some name)`, runtime `v :: stk`) preserves `TrackerSim` under the
valuation updated to map `name ↦ v`, PROVIDED `name` does not already occur in
`nm` (the codegen always pushes fresh intermediate names — `pushInt`/`pushBytes`).
This is the `push`/`rawBlock`-produce preservation lemma the helpers compose. -/
theorem TrackerSim_push (nm : Array (Option String)) (σ : String → Value)
    (stk : List Value) (name : String) (v : Value)
    (hSim : TrackerSim nm σ stk)
    (hfresh : some name ∉ nm.toList) :
    TrackerSim (nm.push (some name)) (fun s => if s = name then v else σ s) (v :: stk) := by
  obtain ⟨hlen, hslot⟩ := hSim
  constructor
  · simp [hlen]
  · intro i hi
    rw [Array.size_push] at hi
    by_cases htop : i = nm.size
    · subst htop
      have hidx : (nm.push (some name))[nm.size] = some name := by
        simp [Array.getElem_push_eq]
      rw [hidx]
      have : (nm.push (some name)).size - 1 - nm.size = 0 := by rw [Array.size_push]; omega
      rw [this]
      show slotAgrees _ (some name) ((v :: stk)[0]!)
      unfold slotAgrees
      simp
    · have hi' : i < nm.size := by omega
      have hpushlow : (nm.push (some name))[i] = nm[i]'hi' := by
        rw [Array.getElem_push_lt]
      rw [hpushlow]
      have hszp : (nm.push (some name)).size = nm.size + 1 := by rw [Array.size_push]
      rw [hszp]
      have hcons : (nm.size + 1 - 1 - i) = (nm.size - 1 - i) + 1 := by omega
      rw [hcons]
      rw [List.getElem!_cons_succ]
      have horig := hslot i hi'
      have hne : nm[i]'hi' ≠ some name := by
        intro hc
        exact hfresh (by rw [← hc]; exact Array.getElem_mem_toList hi')
      exact slotAgrees_update_ne σ name v (nm[i]'hi') (stk[nm.size - 1 - i]!) hne horig

/-- **`applyRoll`-at-model-depth transport (`roll`/`toTop` preservation).**  Under
`TrackerSim`, rolling the slot named `name` (at structural depth
`d := findDepthList name nm.toList.reverse`) to the top puts exactly `σ name` on
top — the runtime witness of `Tracker.toTop name`.  The remaining stack is
`s.stack.eraseIdx d`.  This is the `roll` preservation lemma the field-arith
helpers (`fieldMod`/`fieldAdd`/`fieldSub`/`fieldMul`/`fieldSqr`) compose, once the
kernel `findDepth = findDepthList` bridge (Part 9) lands. -/
theorem applyRoll_findDepth_sim (s : StackState) (nm : Array (Option String))
    (σ : String → Value) (name : String)
    (hSim : TrackerSim nm σ s.stack)
    (hmem : some name ∈ nm.toList.reverse) :
    applyRoll s (findDepthList name nm.toList.reverse)
      = .ok { s with stack := σ name :: s.stack.eraseIdx (findDepthList name nm.toList.reverse) } := by
  obtain ⟨hlt, hval⟩ := findDepthList_sim nm σ s.stack name hSim hmem
  unfold applyRoll
  rw [if_neg (by omega : ¬ findDepthList name nm.toList.reverse ≥ s.stack.length)]
  rw [hval]

/-- **`applyPick`-at-model-depth transport (`pick`/`copyToTop` preservation).**
Under `TrackerSim`, structurally picking the slot named `name` (at depth
`d := findDepthList name nm.toList.reverse`) COPIES exactly `σ name` to the top
without removing it — the runtime witness of `Tracker.copyToTop name`. -/
theorem applyPick_findDepth_sim (s : StackState) (nm : Array (Option String))
    (σ : String → Value) (name : String)
    (hSim : TrackerSim nm σ s.stack)
    (hmem : some name ∈ nm.toList.reverse) :
    applyPick s (findDepthList name nm.toList.reverse)
      = .ok (s.push (σ name)) := by
  obtain ⟨hlt, hval⟩ := findDepthList_sim nm σ s.stack name hSim hmem
  unfold applyPick
  rw [if_neg (by omega : ¬ findDepthList name nm.toList.reverse ≥ s.stack.length)]
  rw [hval]

/-! ### MANDATORY smokes for the Tracker simulation substrate (deliverable 1) -/

/-- Concrete tracker name array `[some "a", some "b", some "c"]` (bottom→top). -/
private def simNm : Array (Option String) := #[some "a", some "b", some "c"]

/-- Concrete valuation. -/
private def simσ : String → Value
  | "a" => .vBigint 10
  | "b" => .vBigint 20
  | "c" => .vBigint 30
  | _   => .vBigint 0

/-- Runtime stack mirroring `simNm` (TOS = c = 30). -/
private def simStk : List Value := [.vBigint 30, .vBigint 20, .vBigint 10]

/-- SMOKE (invariant satisfiability — anti-vacuity).  `TrackerSim` is inhabited:
the concrete stack `[c,b,a]` mirrors the name array `[a,b,c]` under `simσ`. -/
theorem smoke_TrackerSim_satisfiable : TrackerSim simNm simσ simStk := by
  refine ⟨by decide, ?_⟩
  intro i hi
  rw [getElem!_pos simNm i hi |>.symm]
  have hsz : simNm.size = 3 := by decide
  have h3 : i = 0 ∨ i = 1 ∨ i = 2 := by omega
  clear hi
  unfold slotAgrees
  rcases h3 with rfl | rfl | rfl <;>
    (unfold simNm simStk simσ; rfl)

/-- SMOKE (keystone fires).  Under the concrete `TrackerSim`, the model depth of
`"a"` is 2 and the runtime stack value there is `σ "a" = 10`. -/
theorem smoke_findDepthList_sim :
    (findDepthList "a" simNm.toList.reverse = 2)
      ∧ simStk[findDepthList "a" simNm.toList.reverse]! = simσ "a" := by
  refine ⟨by decide, ?_⟩
  exact (findDepthList_sim simNm simσ simStk "a" smoke_TrackerSim_satisfiable (by decide)).2

/-- SMOKE (roll transport fires).  Rolling `"a"` (depth 2) to the top of the
concrete state lands `σ "a" = 10` on top, with that slot erased from the rest. -/
theorem smoke_applyRoll_findDepth_sim :
    applyRoll { (default : StackState) with stack := simStk }
        (findDepthList "a" simNm.toList.reverse)
      = .ok { (default : StackState) with
              stack := simσ "a"
                :: simStk.eraseIdx (findDepthList "a" simNm.toList.reverse) } := by
  apply applyRoll_findDepth_sim
  · exact smoke_TrackerSim_satisfiable
  · decide

/-- SMOKE (pick transport fires).  Picking `"a"` (depth 2) COPIES `σ "a" = 10` to
the top, leaving the rest intact. -/
theorem smoke_applyPick_findDepth_sim :
    applyPick { (default : StackState) with stack := simStk }
        (findDepthList "a" simNm.toList.reverse)
      = .ok (({ (default : StackState) with stack := simStk }).push (simσ "a")) := by
  apply applyPick_findDepth_sim
  · exact smoke_TrackerSim_satisfiable
  · decide

/-- SMOKE (push preservation fires).  Pushing a fresh `"d" ↦ 40` extends the
concrete `TrackerSim`. -/
theorem smoke_TrackerSim_push :
    TrackerSim (simNm.push (some "d"))
      (fun s => if s = "d" then .vBigint 40 else simσ s) (.vBigint 40 :: simStk) :=
  TrackerSim_push simNm simσ simStk "d" (.vBigint 40) smoke_TrackerSim_satisfiable (by decide)

/-- Concrete tracker whose name array is `simNm = [a, b, c]` (bottom→top). -/
private def simTracker : Ec.Tracker := Ec.Tracker.init [some "a", some "b", some "c"]

/-- SMOKE (bridge fires — anti-vacuity).  On the concrete `simTracker`, the
refactored structural `Tracker.findDepth "a"` equals the model
`findDepthList "a" simTracker.nm.toList.reverse` (both `= 2`).  Discharged via the
BRIDGE THEOREM `findDepth_eq_findDepthList` (proved by structural induction, never
`native_decide`); the only `decide` is the concrete membership side-goal. -/
theorem smoke_findDepth_eq_findDepthList :
    simTracker.findDepth "a" = findDepthList "a" simTracker.nm.toList.reverse := by
  apply findDepth_eq_findDepthList
  decide

/-- SMOKE (bridge produces the right concrete value).  The bridged depth on
`simTracker` is exactly `2`, matching the topmost match's depth-from-TOS. -/
theorem smoke_findDepth_bridge_value :
    simTracker.findDepth "a" = 2 := by
  rw [smoke_findDepth_eq_findDepthList]; decide

/-! ### Per-helper transports (wave-77 deliverable 3)

The wave-76 substrate (`TrackerSim`, `findDepthList_sim`, `applyRoll/applyPick`
preservation) + the wave-77 bridge (`findDepth_eq_findDepthList`) compose into the
reusable per-helper transports below.  Three families are landed here, each with a
smoke:

* **`pickStruct` peer** — `applyPickStruct_findDepth_sim` (the codegen emits
  `.pickStruct d`, not the `.pick d` the substrate addressed; the two ops are
  in-bounds-equivalent, so the substrate's `applyPick_findDepth_sim` lifts).
* **`fieldMod` opcode-sequence transport** — `fieldModOps_transport`.  The 8-op
  `fieldModOps` block is byte-identical to `emitEcModReduce`, so the wave-71
  `ecModReduce_step_transport` lifts to `Secp256k1.fieldMod` (divisor `fieldP ≠ 0`).
* **`fieldAdd/fieldSub/fieldMul` opcode-tail transports** — the
  `[OP_BINOP, push fieldP] ++ fieldModOps` tail each composing the corresponding
  `runOpcode_{ADD,SUB,MUL}_bigint_local` into `Secp256k1.field{Add,Sub,Mul}`.

These are the field-arith leaves the per-op discharge of `emitEcNegate` /
`emitEcOnCurve` consumes.  See the Part-9 BLOCK note for the remaining whole-program
ops-append scaffolding that gates the final per-op assembly. -/

/-- `applyPickStruct = applyPick` whenever the depth is in range (the two differ
only in the out-of-range error string). -/
theorem applyPickStruct_eq_applyPick (s : StackState) (d : Nat)
    (hd : ¬ d ≥ s.stack.length) :
    applyPickStruct s d = applyPick s d := by
  unfold applyPickStruct applyPick
  rw [if_neg hd, if_neg hd]

/-- **`pickStruct`-at-model-depth transport (the codegen-faithful `copyToTop`
witness).**  Under `TrackerSim`, the `.pickStruct (findDepthList …)` op the Tracker
emits for `pick (k+2)` COPIES exactly `σ name` to the top — the `applyPick` peer for
the op the codegen actually emits. -/
theorem applyPickStruct_findDepth_sim (s : StackState) (nm : Array (Option String))
    (σ : String → Value) (name : String)
    (hSim : TrackerSim nm σ s.stack)
    (hmem : some name ∈ nm.toList.reverse) :
    applyPickStruct s (findDepthList name nm.toList.reverse)
      = .ok (s.push (σ name)) := by
  have hlt := (findDepthList_sim nm σ s.stack name hSim hmem).1
  rw [applyPickStruct_eq_applyPick s _ (by omega)]
  exact applyPick_findDepth_sim s nm σ name hSim hmem

/-- The codegen field modulus `Ec.fieldP` equals the spec modulus
`Secp256k1.FIELD_P` (same literal; kernel-checkable, NOT `native_decide`). -/
theorem ec_fieldP_eq_spec : Ec.fieldP = Crypto.Secp256k1.FIELD_P := rfl

/-- `Ec.fieldP ≠ 0` — the `OP_MOD` divisor guard for every `fieldMod` (kernel
`decide`, NOT `native_decide`, so the transports stay free of `Lean.ofReduceBool`). -/
theorem ec_fieldP_ne_zero : Ec.fieldP ≠ 0 := by decide

/-- `fieldModOps` is the same 8-op list as `emitEcModReduce`. -/
theorem fieldModOps_eq_emitEcModReduce :
    Ec.fieldModOps = Stack.Ec.emitEcModReduce := rfl

/-- **`fieldMod` opcode-sequence transport.**  Running `fieldModOps` on
`[a, fieldP]` (fieldP on TOS) lands `Secp256k1.fieldMod a`.  Lifts the wave-71
`ecModReduce_step_transport` (divisor `fieldP ≠ 0`). -/
theorem fieldModOps_transport
    (s : StackState) (a : Int) (rest : List Value)
    (hStk : s.stack = .vBigint Ec.fieldP :: .vBigint a :: rest) :
    runOps Ec.fieldModOps s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldMod a) :: rest } := by
  rw [fieldModOps_eq_emitEcModReduce]
  rw [ecModReduce_step_transport s a Ec.fieldP rest hStk ec_fieldP_ne_zero]
  have hSpec : Crypto.Secp256k1.ecModReduce a Ec.fieldP = Crypto.Secp256k1.fieldMod a := by
    unfold Crypto.Secp256k1.ecModReduce Crypto.Secp256k1.fieldMod
    rw [if_neg ec_fieldP_ne_zero, ec_fieldP_eq_spec]
  rw [hSpec]

private theorem niOpcode : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by
  intro c t e h; cases h
private theorem niPush : ∀ (v : PushVal) t e, StackOp.push v ≠ .ifOp t e := by
  intro v t e h; cases h

/-- **Generic field-binop opcode-tail transport.**  For a binop opcode reducing the
top-two ints by `f`, the tail `[OP_BINOP, push fieldP] ++ fieldModOps` run on
`[a, b]` (b on TOS) lands `Secp256k1.fieldMod (f a b)`. -/
theorem fieldBinop_optail_transport
    (binop : String) (f : Int → Int → Int)
    (s : StackState) (a b : Int) (rest : List Value)
    (hBinop : runOpcode binop s = .ok ({ s with stack := rest }.push (.vBigint (f a b)))) :
    runOps ([.opcode binop, .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldMod (f a b)) :: rest } := by
  rw [show ([.opcode binop, .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps)
        = (.opcode binop :: .push (.bigint Ec.fieldP) :: Ec.fieldModOps) from rfl]
  rw [runOps_cons_nonIf_eq _ _ _ (niOpcode binop), stepNonIf_opcode, hBinop]
  simp only [match_Except_ok_runOps]
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint Ec.fieldP)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps]
  rw [fieldModOps_transport _ (f a b) rest rfl]
  simp only [StackState.push]

/-- `fieldAdd` opcode-tail transport: `(a + b) mod p = Secp256k1.fieldAdd a b`. -/
theorem fieldAdd_optail_transport
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps ([.opcode "OP_ADD", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldAdd a b) :: rest } :=
  fieldBinop_optail_transport "OP_ADD" (· + ·) s a b rest
    (runOpcode_ADD_bigint_local s a b rest hStk)

/-- `fieldSub` opcode-tail transport: `(a - b) mod p = Secp256k1.fieldSub a b`. -/
theorem fieldSub_optail_transport
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps ([.opcode "OP_SUB", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldSub a b) :: rest } :=
  fieldBinop_optail_transport "OP_SUB" (· - ·) s a b rest
    (runOpcode_SUB_bigint_local s a b rest hStk)

/-- `fieldMul` opcode-tail transport: `(a * b) mod p = Secp256k1.fieldMul a b`. -/
theorem fieldMul_optail_transport
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps ([.opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldMul a b) :: rest } :=
  fieldBinop_optail_transport "OP_MUL" (· * ·) s a b rest
    (runOpcode_MUL_bigint_local s a b rest hStk)

/-! ### MANDATORY smokes for the per-helper transports (deliverable 3) -/

/-- Concrete state for the field-helper smokes: `[a=10, b=7]` (b on TOS). -/
private def fieldSmokeStk : StackState :=
  { (default : StackState) with stack := [.vBigint 7, .vBigint 10] }

/-- SMOKE (`fieldMod` fires).  `fieldModOps` on `[42, p]` lands
`Secp256k1.fieldMod 42 = 42`. -/
theorem smoke_fieldModOps_transport :
    runOps Ec.fieldModOps
        { (default : StackState) with stack := [.vBigint Ec.fieldP, .vBigint 42] }
      = .ok { (default : StackState) with
              stack := [.vBigint (Crypto.Secp256k1.fieldMod 42)] } :=
  fieldModOps_transport _ 42 [] rfl

/-- SMOKE (`fieldMod` value anti-vacuity).  The reduced value is concretely `42`. -/
theorem smoke_fieldMod_value : Crypto.Secp256k1.fieldMod 42 = 42 := by native_decide

/-- SMOKE (`fieldAdd` fires).  `[10, 7]` ⇒ `Secp256k1.fieldAdd 10 7 = 17`. -/
theorem smoke_fieldAdd_optail_transport :
    runOps ([.opcode "OP_ADD", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) fieldSmokeStk
      = .ok { fieldSmokeStk with stack := [.vBigint (Crypto.Secp256k1.fieldAdd 10 7)] } :=
  fieldAdd_optail_transport fieldSmokeStk 10 7 [] rfl

/-- SMOKE (`fieldSub` fires).  `[10, 7]` ⇒ `Secp256k1.fieldSub 10 7 = 3`. -/
theorem smoke_fieldSub_optail_transport :
    runOps ([.opcode "OP_SUB", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) fieldSmokeStk
      = .ok { fieldSmokeStk with stack := [.vBigint (Crypto.Secp256k1.fieldSub 10 7)] } :=
  fieldSub_optail_transport fieldSmokeStk 10 7 [] rfl

/-- SMOKE (`fieldMul` fires).  `[10, 7]` ⇒ `Secp256k1.fieldMul 10 7 = 70`. -/
theorem smoke_fieldMul_optail_transport :
    runOps ([.opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) fieldSmokeStk
      = .ok { fieldSmokeStk with stack := [.vBigint (Crypto.Secp256k1.fieldMul 10 7)] } :=
  fieldMul_optail_transport fieldSmokeStk 10 7 [] rfl

/-- SMOKE (field-arith value anti-vacuity).  The three field ops land `17 / 3 / 70`. -/
theorem smoke_field_values :
    Crypto.Secp256k1.fieldAdd 10 7 = 17
      ∧ Crypto.Secp256k1.fieldSub 10 7 = 3
      ∧ Crypto.Secp256k1.fieldMul 10 7 = 70 := by native_decide

/-- SMOKE (`pickStruct` peer fires).  Under the concrete `TrackerSim`, the
codegen-faithful `.pickStruct (depth "a")` COPIES `σ "a" = 10` to the top. -/
theorem smoke_applyPickStruct_findDepth_sim :
    applyPickStruct { (default : StackState) with stack := simStk }
        (findDepthList "a" simNm.toList.reverse)
      = .ok (({ (default : StackState) with stack := simStk }).push (simσ "a")) := by
  apply applyPickStruct_findDepth_sim
  · exact smoke_TrackerSim_satisfiable
  · decide

/-! ### `toTop` / `copyToTop` runtime transports (wave-78 deliverable 1)

`Tracker.toTop name` emits `Tracker.roll d` and `Tracker.copyToTop name newName`
emits `Tracker.pick d newName`, with `d = Tracker.findDepth name` decided at
codegen time.  Both emit a DEPTH-DEPENDENT op:

  * `roll d` :  0 → nop, 1 → `.swap`, 2 → `.rot`, `n+3` → `.roll (n+3)`.
  * `pick d` :  0 → `.dup`, 1 → `.over`, `k+2` → `.pickStruct (k+2)`.

To thread `runOps` over the whole codegen op-list we need, for each, (a) the
ops-append lemma `(helper t).ops = t.ops ++ extraOps d` and (b) the runtime
transport `runOps (extraOps d) s = applyRoll/applyPick s d` (in range).  Composing
(b) with the wave-76 `applyRoll_findDepth_sim` / `applyPick_findDepth_sim` and the
wave-77 `findDepth_eq_findDepthList` bridge yields the per-step `toTop`/`copyToTop`
transport that lands `σ name` on top under `TrackerSim`. -/

/-- The op-list `Tracker.roll d` appends to `t.ops` (depth-case-uniform). -/
def rollExtraOps (d : Nat) : List StackOp :=
  match d with
  | 0     => []
  | 1     => [.swap]
  | 2     => [.rot]
  | n + 3 => [.roll (n + 3)]

/-- The op-list `Tracker.pick d n` appends to `t.ops` (depth-case-uniform). -/
def pickExtraOps (d : Nat) : List StackOp :=
  match d with
  | 0     => [.dup]
  | 1     => [.over]
  | k + 2 => [.pickStruct (k + 2)]

/-- **`roll` ops-append.**  `(t.roll d).ops = t.ops ++ rollExtraOps d`.  Both
branches of the internal `if L ≥ …` mutate only `nm`, leaving `ops` identical. -/
theorem roll_ops_append (t : Ec.Tracker) (d : Nat) :
    (t.roll d).ops.toList = t.ops.toList ++ rollExtraOps d := by
  unfold Ec.Tracker.roll rollExtraOps
  match d with
  | 0     => simp
  | 1     => simp only []; unfold Ec.Tracker.swap Ec.Tracker.emit; dsimp only; split <;> simp
  | 2     => simp only []; unfold Ec.Tracker.rot Ec.Tracker.emit; dsimp only; split <;> simp
  | n + 3 => simp only []; unfold Ec.Tracker.emit; dsimp only; split <;> simp

/-- **`pick` ops-append.**  `(t.pick d n).ops = t.ops ++ pickExtraOps d`. -/
theorem pick_ops_append (t : Ec.Tracker) (d : Nat) (n : String) :
    (t.pick d n).ops.toList = t.ops.toList ++ pickExtraOps d := by
  unfold Ec.Tracker.pick pickExtraOps
  match d with
  | 0     => unfold Ec.Tracker.dup Ec.Tracker.emit; simp
  | 1     => unfold Ec.Tracker.over Ec.Tracker.emit; simp
  | k + 2 => unfold Ec.Tracker.emit; simp

/-- **`pick` always pushes `some n`** to `nm` (depth-case-uniform).  The runtime
peer pushes the copied value, so `copyToTop` preservation is exactly
`TrackerSim_push`. -/
theorem pick_nm_push (t : Ec.Tracker) (d : Nat) (n : String) :
    (t.pick d n).nm = t.nm.push (some n) := by
  unfold Ec.Tracker.pick
  match d with
  | 0     => unfold Ec.Tracker.dup Ec.Tracker.emit; rfl
  | 1     => unfold Ec.Tracker.over Ec.Tracker.emit; rfl
  | k + 2 => unfold Ec.Tracker.emit; rfl

/-- `applySwap = applyRoll · 1` when the stack has ≥2 elements. -/
theorem applySwap_eq_applyRoll1 (s : StackState) (h : 2 ≤ s.stack.length) :
    applySwap s = applyRoll s 1 := by
  unfold applyRoll applySwap; rw [if_neg (by omega)]
  cases hs : s.stack with
  | nil => rw [hs] at h; simp at h
  | cons a rest =>
    cases hr : rest with
    | nil => rw [hs, hr] at h; simp at h
    | cons b rest2 => simp [List.eraseIdx]

/-- `applyRot = applyRoll · 2` when the stack has ≥3 elements. -/
theorem applyRot_eq_applyRoll2 (s : StackState) (h : 3 ≤ s.stack.length) :
    applyRot s = applyRoll s 2 := by
  unfold applyRoll applyRot; rw [if_neg (by omega)]
  cases hs : s.stack with
  | nil => rw [hs] at h; simp at h
  | cons a rest =>
    cases hr : rest with
    | nil => rw [hs, hr] at h; simp at h
    | cons b rest2 =>
      cases hr2 : rest2 with
      | nil => rw [hs, hr, hr2] at h; simp at h
      | cons c rest3 => simp [List.eraseIdx]

/-- `applyDup = applyPick · 0` when the stack is nonempty. -/
theorem applyDup_eq_applyPick0 (s : StackState) (h : 1 ≤ s.stack.length) :
    applyDup s = applyPick s 0 := by
  unfold applyPick applyDup StackState.push; rw [if_neg (by omega)]
  cases hs : s.stack with
  | nil => rw [hs] at h; simp at h
  | cons a rest => simp

/-- `applyOver = applyPick · 1` when the stack has ≥2 elements. -/
theorem applyOver_eq_applyPick1 (s : StackState) (h : 2 ≤ s.stack.length) :
    applyOver s = applyPick s 1 := by
  unfold applyPick applyOver StackState.push; rw [if_neg (by omega)]
  cases hs : s.stack with
  | nil => rw [hs] at h; simp at h
  | cons a rest =>
    cases hr : rest with
    | nil => rw [hs, hr] at h; simp at h
    | cons b rest2 => simp

private theorem niSwap' : ∀ t e, StackOp.swap ≠ .ifOp t e := by intro t e h; cases h
private theorem niRot' : ∀ t e, StackOp.rot ≠ .ifOp t e := by intro t e h; cases h
private theorem niRoll' : ∀ d t e, StackOp.roll d ≠ .ifOp t e := by intro d t e h; cases h
private theorem niDup' : ∀ t e, StackOp.dup ≠ .ifOp t e := by intro t e h; cases h
private theorem niOver' : ∀ t e, StackOp.over ≠ .ifOp t e := by intro t e h; cases h
private theorem niPickStruct' : ∀ d t e, StackOp.pickStruct d ≠ .ifOp t e := by
  intro d t e h; cases h

/-- **`roll` runtime transport.**  Running the depth-`d` op-list `Tracker.roll`
emits equals `applyRoll s d` whenever `d` is in range — the depth-0/1/2 special
cases (`nop`/`.swap`/`.rot`) collapse to `applyRoll · d` via the conditional
`applySwap/applyRot = applyRoll` bridges; the `≥3` case is the bare `.roll d`. -/
theorem runOps_rollExtraOps (s : StackState) (d : Nat) (h : d < s.stack.length) :
    runOps (rollExtraOps d) s = applyRoll s d := by
  unfold rollExtraOps
  match d with
  | 0 =>
    simp only [runOps_nil]
    unfold applyRoll; rw [if_neg (by omega)]
    cases hs : s.stack with
    | nil => rw [hs] at h; simp at h
    | cons a rest =>
      simp only [hs, List.getElem!_cons_zero, List.eraseIdx_cons_zero]
      cases s; simp_all
  | 1 =>
    rw [runOps_cons_nonIf_eq _ _ _ niSwap',
        show stepNonIf .swap s = applySwap s from rfl, applySwap_eq_applyRoll1 s (by omega)]
    cases happ : applyRoll s 1 with
    | error e => exfalso; unfold applyRoll at happ; rw [if_neg (by omega)] at happ; simp at happ
    | ok s' => simp [runOps_nil]
  | 2 =>
    rw [runOps_cons_nonIf_eq _ _ _ niRot',
        show stepNonIf .rot s = applyRot s from rfl, applyRot_eq_applyRoll2 s (by omega)]
    cases happ : applyRoll s 2 with
    | error e => exfalso; unfold applyRoll at happ; rw [if_neg (by omega)] at happ; simp at happ
    | ok s' => simp [runOps_nil]
  | n + 3 =>
    rw [runOps_cons_nonIf_eq _ _ _ (niRoll' (n+3)),
        show stepNonIf (.roll (n+3)) s = applyRoll s (n+3) from rfl]
    cases happ : applyRoll s (n+3) with
    | error e => exfalso; unfold applyRoll at happ; rw [if_neg (by omega)] at happ; simp at happ
    | ok s' => simp [runOps_nil]

/-- **`pick` runtime transport.**  Running the depth-`d` op-list `Tracker.pick`
emits equals `applyPick s d` whenever `d` is in range — depth-0/1 (`.dup`/`.over`)
collapse to `applyPick · d` via the conditional bridges; `≥2` is `.pickStruct d`
(= `applyPick` in range, the wave-77 `applyPickStruct_eq_applyPick`). -/
theorem runOps_pickExtraOps (s : StackState) (d : Nat) (h : d < s.stack.length) :
    runOps (pickExtraOps d) s = applyPick s d := by
  unfold pickExtraOps
  match d with
  | 0 =>
    rw [runOps_cons_nonIf_eq _ _ _ niDup',
        show stepNonIf .dup s = applyDup s from rfl, applyDup_eq_applyPick0 s (by omega)]
    cases happ : applyPick s 0 with
    | error e => exfalso; unfold applyPick at happ; rw [if_neg (by omega)] at happ; simp at happ
    | ok s' => simp [runOps_nil]
  | 1 =>
    rw [runOps_cons_nonIf_eq _ _ _ niOver',
        show stepNonIf .over s = applyOver s from rfl, applyOver_eq_applyPick1 s (by omega)]
    cases happ : applyPick s 1 with
    | error e => exfalso; unfold applyPick at happ; rw [if_neg (by omega)] at happ; simp at happ
    | ok s' => simp [runOps_nil]
  | k + 2 =>
    rw [runOps_cons_nonIf_eq _ _ _ (niPickStruct' (k+2)),
        show stepNonIf (.pickStruct (k+2)) s = applyPickStruct s (k+2) from rfl,
        applyPickStruct_eq_applyPick s (k+2) (by omega)]
    cases happ : applyPick s (k+2) with
    | error e => exfalso; unfold applyPick at happ; rw [if_neg (by omega)] at happ; simp at happ
    | ok s' => simp [runOps_nil]

/-- **`toTop` per-step runtime transport (deliverable 1).**  Under `TrackerSim`,
running the op-list `Tracker.toTop name` emits (= `rollExtraOps (findDepthList …)`,
via the wave-77 bridge) brings exactly `σ name` to the top of the runtime stack,
leaving the rest as `s.stack.eraseIdx d`.  This is the runtime witness of
`Tracker.toTop` the field-arith helpers compose. -/
theorem runOps_toTop_extraOps_sim (s : StackState) (nm : Array (Option String))
    (σ : String → Value) (name : String)
    (hSim : TrackerSim nm σ s.stack)
    (hmem : some name ∈ nm.toList.reverse) :
    runOps (rollExtraOps (findDepthList name nm.toList.reverse)) s
      = .ok { s with
              stack := σ name :: s.stack.eraseIdx (findDepthList name nm.toList.reverse) } := by
  have hlt := (findDepthList_sim nm σ s.stack name hSim hmem).1
  rw [runOps_rollExtraOps s _ (by omega)]
  exact applyRoll_findDepth_sim s nm σ name hSim hmem

/-- **`copyToTop` per-step runtime transport (deliverable 1).**  Under
`TrackerSim`, running the op-list `Tracker.copyToTop name newName` emits
(= `pickExtraOps (findDepthList …)`) COPIES exactly `σ name` to the top, without
removing it.  Runtime witness of `Tracker.copyToTop`. -/
theorem runOps_copyToTop_extraOps_sim (s : StackState) (nm : Array (Option String))
    (σ : String → Value) (name : String)
    (hSim : TrackerSim nm σ s.stack)
    (hmem : some name ∈ nm.toList.reverse) :
    runOps (pickExtraOps (findDepthList name nm.toList.reverse)) s
      = .ok (s.push (σ name)) := by
  have hlt := (findDepthList_sim nm σ s.stack name hSim hmem).1
  rw [runOps_pickExtraOps s _ (by omega)]
  exact applyPick_findDepth_sim s nm σ name hSim hmem

/-- **`copyToTop` `TrackerSim` preservation (deliverable 1).**  After
`Tracker.copyToTop name newName`, the tracker pushes `some newName` to `nm` and the
runtime pushes `σ name`.  Provided `newName` is fresh (the codegen always picks
fresh copy-target names) the invariant is preserved under the valuation updated to
`newName ↦ σ name`.  Reduces to `TrackerSim_push`. -/
theorem TrackerSim_copyToTop (s : StackState) (nm : Array (Option String))
    (σ : String → Value) (name newName : String)
    (hSim : TrackerSim nm σ s.stack)
    (hfresh : some newName ∉ nm.toList) :
    TrackerSim (nm.push (some newName))
      (fun t => if t = newName then σ name else σ t) (σ name :: s.stack) :=
  TrackerSim_push nm σ s.stack newName (σ name) hSim hfresh

/-! ### THE KEYSTONE — `toTop` nm-side `TrackerSim` preservation (deliverable 1)

The wave-78 hand-off (Part-9 sub-goal (a)) named this as the ONE remaining
model-preservation lemma: the `copyToTop` peer is `TrackerSim_copyToTop`
(= `TrackerSim_push`); the `toTop` peer (`Tracker.roll`) erases the slot at array
index `nm.size-1-d` and pushes it back on top, while the runtime erases the slot at
structural depth `d` and conses `σ name` on top.  The genuine content is the
slot-reindexing across "array-erase-then-push vs list-cons-after-erase" under the
`size-1-i ↔ i` reverse correspondence, split at the erase point `d`
(`TrackerSim_canonical`); the per-`roll`-branch reduction to that canonical
erase-push array shape is `roll_nm_canonical` (the `d=0` identity-of-`eraseLast`,
`d=1` swap-as-erase-push, `d=2`/`d≥3` definitional cases).  All `propext`/
`Quot.sound`-clean, NO `native_decide`, NO `sorry`, NO new axiom. -/

/-- `getElem!` peer of `List.getElem_set`. -/
private theorem getElemBang_set {α : Type} [Inhabited α] (l : List α) (i j : Nat) (v : α)
    (hj : j < l.length) :
    (l.set i v)[j]! = if i = j then v else l[j]! := by
  rw [getElem!_pos (l.set i v) j (by rw [List.length_set]; exact hj),
      getElem!_pos l j hj, List.getElem_set]

/-- `getElem!`-level list extensionality (equal lengths + per-index `[·]!` agreement). -/
private theorem list_ext_getElemBang {α : Type} [Inhabited α] (a b : List α)
    (hlen : a.length = b.length) (h : ∀ n, n < a.length → a[n]! = b[n]!) : a = b := by
  apply List.ext_getElem hlen
  intro n h1 h2
  have := h n h1
  rwa [getElem!_pos a n h1, getElem!_pos b n h2] at this

/-- `getElem!` of `eraseIdx` below the erase point. -/
private theorem getElemBang_eraseIdx_lt {α : Type} [Inhabited α] (l : List α) (e j : Nat)
    (hj : j < e) (he : e < l.length) :
    (l.eraseIdx e)[j]! = l[j]! := by
  have hjlen : j < (l.eraseIdx e).length := by rw [List.length_eraseIdx_of_lt he]; omega
  rw [getElem!_pos (l.eraseIdx e) j hjlen, getElem!_pos l j (by omega)]
  exact List.getElem_eraseIdx_of_lt hjlen hj

/-- `getElem!` of `eraseIdx` at/above the erase point (shifts the index up by one). -/
private theorem getElemBang_eraseIdx_ge {α : Type} [Inhabited α] (l : List α) (e j : Nat)
    (hge : e ≤ j) (he : e < l.length) (hjlen : j < (l.eraseIdx e).length) :
    (l.eraseIdx e)[j]! = l[j+1]! := by
  rw [getElem!_pos (l.eraseIdx e) j hjlen]
  have hj1 : j + 1 < l.length := by rw [List.length_eraseIdx_of_lt he] at hjlen; omega
  rw [getElem!_pos l (j+1) hj1]
  exact List.getElem_eraseIdx_of_ge hjlen hge

/-- `getElem!` of `xs ++ [x]` strictly inside the `xs` part. -/
private theorem getElemBang_append_left {α : Type} [Inhabited α] (xs : List α) (x : α)
    (i : Nat) (h : i < xs.length) :
    (xs ++ [x])[i]! = xs[i]! := by
  rw [getElem!_pos (xs ++ [x]) i (by simp; omega), getElem!_pos xs i h, List.getElem_append_left h]

/-- `getElem!` of `xs ++ [x]` at the appended slot. -/
private theorem getElemBang_append_right {α : Type} [Inhabited α] (xs : List α) (x : α) :
    (xs ++ [x])[xs.length]! = x := by
  rw [getElem!_pos (xs ++ [x]) xs.length (by simp)]; simp

/-- `getElem!` bridge `Array → toList`, in range. -/
private theorem arr_getElemBang_toList {α : Type} [Inhabited α] (a : Array α) (i : Nat)
    (h : i < a.size) : a[i]! = a.toList[i]! := by
  rw [getElem!_pos a i h, getElem!_pos a.toList i (by rw [Array.length_toList]; exact h),
      Array.getElem_toList]

/-- The `d=1` swap nm-update at the list level is exactly the canonical
erase-second-then-append (`e = length-2`): both produce the same list pointwise
(proved by `getElem!` extensionality, three index cases). -/
private theorem swap_toList_canonical {α : Type} [Inhabited α] (l : List α) (h : 2 ≤ l.length) :
    (l.set (l.length - 1) (l[l.length - 2]!)).set (l.length - 2) (l[l.length - 1]!)
      = (l.eraseIdx (l.length - 2)) ++ [l[l.length - 2]!] := by
  have herasel : (l.eraseIdx (l.length - 2)).length = l.length - 1 := by
    rw [List.length_eraseIdx_of_lt (by omega)]
  apply list_ext_getElemBang
  · rw [List.length_set, List.length_set, List.length_append, List.length_singleton, herasel]
    omega
  · intro n hn
    rw [List.length_set, List.length_set] at hn
    rw [getElemBang_set (l.set (l.length - 1) (l[l.length - 2]!)) (l.length - 2) n
          (l[l.length - 1]!) (by rw [List.length_set]; exact hn)]
    rw [getElemBang_set l (l.length - 1) n (l[l.length - 2]!) hn]
    by_cases h2 : l.length - 2 = n
    · subst h2
      simp only [if_pos]
      have hbelow : l.length - 2 < (l.eraseIdx (l.length - 2)).length := by rw [herasel]; omega
      rw [getElemBang_append_left (l.eraseIdx (l.length - 2)) (l[l.length - 2]!) (l.length - 2)
            hbelow]
      rw [getElemBang_eraseIdx_ge l (l.length - 2) (l.length - 2) (Nat.le_refl _) (by omega)
            (by rw [herasel]; omega)]
      congr 1; omega
    · by_cases h1 : l.length - 1 = n
      · subst h1
        rw [if_neg h2, if_pos rfl]
        have hidx : l.length - 1 = (l.eraseIdx (l.length - 2)).length := by rw [herasel]
        rw [hidx]
        exact (getElemBang_append_right (l.eraseIdx (l.length - 2)) (l[l.length - 2]!)).symm
      · simp only [if_neg h2, if_neg h1]
        have hnlt : n < l.length - 2 := by omega
        have hbelow : n < (l.eraseIdx (l.length - 2)).length := by rw [herasel]; omega
        rw [getElemBang_append_left (l.eraseIdx (l.length - 2)) (l[l.length - 2]!) n hbelow]
        rw [getElemBang_eraseIdx_lt l (l.length - 2) n hnlt (by omega)]

/-- The `d=0` nm-update is identity: erasing the last slot and pushing it back
yields the original list. -/
private theorem eraseLast_append {α : Type} [Inhabited α] (l : List α) (h : 0 < l.length) :
    (l.eraseIdx (l.length - 1)) ++ [l[l.length - 1]!] = l := by
  rw [List.eraseIdx_length_sub_one]
  have hne : l ≠ [] := by intro hc; rw [hc] at h; simp at h
  have hgl : l[l.length - 1]! = l.getLast hne := by
    rw [List.getLast_eq_getElem, getElem!_pos l (l.length - 1) (by omega)]
  rw [hgl, List.dropLast_concat_getLast]

/-- **Canonical erase-push `TrackerSim` preservation (the slot-reindexing core).**
Erasing the array slot at index `nm.size-1-d` and pushing it on top mirrors the
runtime erasing structural depth `d` and consing `stk[d]!` on top.  Length: off
`Array.toList_eraseIdxIfInBounds` + `List.length_eraseIdx`.  Slots: per-index
reindexing across array-erase-then-push vs list-cons-after-erase, split at the
erase point `d` (top slot / below-`d` / at-or-above-`d`). -/
private theorem TrackerSim_canonical (nm : Array (Option String)) (σ : String → Value)
    (stk : List Value) (d : Nat) (hd : d < nm.size) (hSim : TrackerSim nm σ stk) :
    TrackerSim ((nm.eraseIdxIfInBounds (nm.size - 1 - d)).push (nm[nm.size - 1 - d]!))
      σ (stk[d]! :: stk.eraseIdx d) := by
  obtain ⟨hlen, hslot⟩ := hSim
  generalize he_def : nm.size - 1 - d = e at *
  have he_lt : e < nm.size := by omega
  have herase_tl : (nm.eraseIdxIfInBounds e).toList = nm.toList.eraseIdx e :=
    Array.toList_eraseIdxIfInBounds
  have hnm_tllen : nm.toList.length = nm.size := Array.length_toList
  have herase_size : (nm.eraseIdxIfInBounds e).size = nm.size - 1 := by
    rw [← Array.length_toList, herase_tl,
        List.length_eraseIdx_of_lt (by rw [hnm_tllen]; exact he_lt), hnm_tllen]
  have hnm'_size : ((nm.eraseIdxIfInBounds e).push (nm[e]!)).size = nm.size := by
    rw [Array.size_push, herase_size]; omega
  have hnm'_tl : ((nm.eraseIdxIfInBounds e).push (nm[e]!)).toList
      = nm.toList.eraseIdx e ++ [nm[e]!] := by rw [Array.toList_push, herase_tl]
  refine ⟨?_, ?_⟩
  · rw [List.length_cons, List.length_eraseIdx_of_lt (by omega : d < stk.length), hnm'_size]
    omega
  · intro i hi
    have hi' : i < nm.size := by rwa [hnm'_size] at hi
    have hnm'_get : ((nm.eraseIdxIfInBounds e).push (nm[e]!))[i]
        = ((nm.eraseIdxIfInBounds e).push (nm[e]!)).toList[i]! :=
      Eq.symm (getElem!_pos ((nm.eraseIdxIfInBounds e).push (nm[e]!)).toList i
        (by rw [Array.length_toList, hnm'_size]; exact hi'))
    rw [hnm'_get, hnm'_tl, hnm'_size]
    have herasel : (nm.toList.eraseIdx e).length = nm.size - 1 := by
      rw [List.length_eraseIdx_of_lt (by rw [hnm_tllen]; exact he_lt), hnm_tllen]
    by_cases htop : i = nm.size - 1
    · subst htop
      have hsizeerasel : (nm.toList.eraseIdx e).length = nm.size - 1 := herasel
      have happend_top : (nm.toList.eraseIdx e ++ [nm[e]!])[nm.size - 1]! = nm[e]! := by
        rw [← hsizeerasel]; exact getElemBang_append_right (nm.toList.eraseIdx e) (nm[e]!)
      rw [happend_top]
      have hidx0 : nm.size - 1 - (nm.size - 1) = 0 := by omega
      rw [hidx0, List.getElem!_cons_zero]
      have horig := hslot e he_lt
      have hed : nm.size - 1 - e = d := by omega
      rw [hed] at horig
      have hnmebang : nm[e]! = nm[e]'he_lt := by rw [getElem!_pos nm e he_lt]
      rw [hnmebang]
      exact horig
    · have hilt : i < nm.size - 1 := by omega
      have happend_low : (nm.toList.eraseIdx e ++ [nm[e]!])[i]! = (nm.toList.eraseIdx e)[i]! :=
        getElemBang_append_left (nm.toList.eraseIdx e) (nm[e]!) i (by rw [herasel]; omega)
      rw [happend_low]
      have hrt_succ : nm.size - 1 - i = (nm.size - 2 - i) + 1 := by omega
      rw [hrt_succ, List.getElem!_cons_succ]
      have he_lt_tl : e < nm.toList.length := by rw [hnm_tllen]; exact he_lt
      by_cases hsplit : i < e
      · rw [getElemBang_eraseIdx_lt nm.toList e i hsplit he_lt_tl]
        have hnmi : nm.toList[i]! = nm[i]'hi' := by
          rw [getElem!_pos nm.toList i (by rw [hnm_tllen]; exact hi'), Array.getElem_toList]
        rw [hnmi]
        have horig := hslot i hi'
        have hge_d : d ≤ nm.size - 2 - i := by omega
        have hd_stk : d < stk.length := by omega
        have herasestk : (stk.eraseIdx d)[nm.size - 2 - i]! = stk[(nm.size - 2 - i) + 1]! := by
          apply getElemBang_eraseIdx_ge stk d (nm.size - 2 - i) hge_d hd_stk
          rw [List.length_eraseIdx_of_lt hd_stk]; omega
        rw [herasestk]
        have hh : (nm.size - 2 - i) + 1 = nm.size - 1 - i := by omega
        rw [hh]
        exact horig
      · have hsplit' : e ≤ i := Nat.le_of_not_lt hsplit
        rw [getElemBang_eraseIdx_ge nm.toList e i hsplit' he_lt_tl
              (by rw [List.length_eraseIdx_of_lt he_lt_tl, hnm_tllen]; omega)]
        have hi1 : i + 1 < nm.size := by omega
        have hnmi1 : nm.toList[i+1]! = nm[i+1]'hi1 := by
          rw [getElem!_pos nm.toList (i+1) (by rw [hnm_tllen]; exact hi1), Array.getElem_toList]
        rw [hnmi1]
        have horig := hslot (i+1) hi1
        have hlt_d : nm.size - 2 - i < d := by omega
        have hd_stk : d < stk.length := by omega
        have herasestk : (stk.eraseIdx d)[nm.size - 2 - i]! = stk[nm.size - 2 - i]! :=
          getElemBang_eraseIdx_lt stk d (nm.size - 2 - i) hlt_d hd_stk
        rw [herasestk]
        have hidxeq : nm.size - 1 - (i + 1) = nm.size - 2 - i := by omega
        rw [hidxeq] at horig
        exact horig

/-- **`Tracker.roll d` nm = the canonical erase-push form**, all four `roll`
branches (`d=0` identity, `d=1` swap, `d=2` rot, `d≥3` bare roll), for `d` in
range.  Bridges the concrete `roll`/`swap`/`rot` nm-updates to the single
`TrackerSim_canonical` shape. -/
private theorem roll_nm_canonical (t : Ec.Tracker) (d : Nat) (hd : d < t.nm.size) :
    (t.roll d).nm = (t.nm.eraseIdxIfInBounds (t.nm.size - 1 - d)).push (t.nm[t.nm.size - 1 - d]!) := by
  match d with
  | 0 =>
    show t.nm = _
    apply Array.ext'
    rw [Array.toList_push, Array.toList_eraseIdxIfInBounds]
    have ht : t.nm.size - 1 - 0 = t.nm.toList.length - 1 := by rw [Array.length_toList]; omega
    rw [ht, arr_getElemBang_toList t.nm (t.nm.toList.length - 1)
          (by rw [Array.length_toList] at *; omega)]
    exact (eraseLast_append t.nm.toList (by rw [Array.length_toList]; omega)).symm
  | 1 =>
    unfold Ec.Tracker.roll Ec.Tracker.swap
    simp only [Ec.Tracker.emit]
    rw [if_pos (by omega : t.nm.size ≥ 2)]
    apply Array.ext'
    rw [Array.toList_push, Array.toList_eraseIdxIfInBounds]
    show ((t.nm.set! (t.nm.size - 1) (t.nm[t.nm.size - 2]!)).set! (t.nm.size - 2)
            (t.nm[t.nm.size - 1]!)).toList = _
    rw [Array.set!, Array.set!, Array.toList_setIfInBounds, Array.toList_setIfInBounds]
    have hl : t.nm.toList.length = t.nm.size := Array.length_toList
    rw [arr_getElemBang_toList t.nm (t.nm.size - 2) (by omega),
        arr_getElemBang_toList t.nm (t.nm.size - 1) (by omega),
        arr_getElemBang_toList t.nm (t.nm.size - 1 - 1) (by omega)]
    have he1 : t.nm.size - 1 = t.nm.toList.length - 1 := by rw [hl]
    have he2 : t.nm.size - 2 = t.nm.toList.length - 2 := by rw [hl]
    have he3 : t.nm.size - 1 - 1 = t.nm.toList.length - 2 := by rw [hl]; omega
    rw [he3, he2, he1]
    exact swap_toList_canonical t.nm.toList (by rw [hl]; omega)
  | 2 =>
    unfold Ec.Tracker.roll Ec.Tracker.rot
    simp only [Ec.Tracker.emit]
    rw [if_pos (by omega : t.nm.size ≥ 3)]
    have he : t.nm.size - 1 - 2 = t.nm.size - 3 := by omega
    rw [he]
  | n + 3 =>
    unfold Ec.Tracker.roll
    simp only [Ec.Tracker.emit]
    rw [if_pos (by omega : t.nm.size ≥ (n + 3) + 1)]

/-- **THE KEYSTONE (deliverable 1) — `toTop` nm-side `TrackerSim` preservation.**
After `Tracker.toTop name` (= `roll (findDepth name)`), the tracker's name array and
the runtime stack stay in lock-step: the runtime brings `σ name` to the top
(remainder `stk.eraseIdx d`, the `runOps_toTop_extraOps_sim` witness), and the
tracker's `nm` becomes the canonical erase-push form (`roll_nm_canonical`), which
preserves `TrackerSim` by the slot-reindexing core (`TrackerSim_canonical`), since
`stk[d]! = σ name` (`findDepthList_sim`).  `d := findDepthList name nm.toList.reverse`
is the codegen depth via the wave-77 bridge `findDepth_eq_findDepthList`.  This is
the `toTop` peer of `TrackerSim_copyToTop` and the last model-preservation lemma the
Part-9 hand-off named. -/
theorem TrackerSim_toTop (t : Ec.Tracker) (σ : String → Value) (stk : List Value)
    (name : String)
    (hSim : TrackerSim t.nm σ stk)
    (hmem : some name ∈ t.nm.toList.reverse) :
    TrackerSim (t.toTop name).nm σ
      (σ name :: stk.eraseIdx (findDepthList name t.nm.toList.reverse)) := by
  have hbridge : t.findDepth name = findDepthList name t.nm.toList.reverse :=
    findDepth_eq_findDepthList t name hmem
  have hsim := findDepthList_sim t.nm σ stk name hSim hmem
  obtain ⟨hlt, hval⟩ := hsim
  have hd_lt : findDepthList name t.nm.toList.reverse < t.nm.size := by
    obtain ⟨hlen, _⟩ := hSim; omega
  unfold Ec.Tracker.toTop
  rw [hbridge, roll_nm_canonical t (findDepthList name t.nm.toList.reverse) hd_lt]
  have hcanon := TrackerSim_canonical t.nm σ stk (findDepthList name t.nm.toList.reverse) hd_lt hSim
  rwa [hval] at hcanon

/-! ### MANDATORY smokes for the `toTop`/`copyToTop` transports (deliverable 1) -/

/-- SMOKE (`roll` ops-append fires).  `(simTracker.roll 2).ops = simTracker.ops ++ [.rot]`. -/
theorem smoke_roll_ops_append :
    (simTracker.roll 2).ops.toList = simTracker.ops.toList ++ [StackOp.rot] := by
  rw [roll_ops_append]; rfl

/-- SMOKE (`pick` ops-append fires).  `(simTracker.pick 3 "z").ops = … ++ [.pickStruct 3]`. -/
theorem smoke_pick_ops_append :
    (simTracker.pick 3 "z").ops.toList = simTracker.ops.toList ++ [StackOp.pickStruct 3] := by
  rw [pick_ops_append]; rfl

/-- SMOKE (`pick` nm-push fires).  `(simTracker.pick 3 "z").nm = simTracker.nm.push (some "z")`. -/
theorem smoke_pick_nm_push :
    (simTracker.pick 3 "z").nm = simTracker.nm.push (some "z") := by
  rw [pick_nm_push]

/-- SMOKE (`roll` runtime transport fires).  `rollExtraOps 1 = [.swap]` on
`[30, 20, 10]` swaps the top two: `[20, 30, 10]` = `applyRoll · 1`. -/
theorem smoke_runOps_rollExtraOps :
    runOps (rollExtraOps 1) { (default : StackState) with stack := simStk }
      = applyRoll { (default : StackState) with stack := simStk } 1 := by
  apply runOps_rollExtraOps; decide

/-- SMOKE (`pick` runtime transport fires).  `pickExtraOps 2 = [.pickStruct 2]` on
`[30, 20, 10]` copies depth-2 (= 10): `[10, 30, 20, 10]` = `applyPick · 2`. -/
theorem smoke_runOps_pickExtraOps :
    runOps (pickExtraOps 2) { (default : StackState) with stack := simStk }
      = applyPick { (default : StackState) with stack := simStk } 2 := by
  apply runOps_pickExtraOps; decide

/-- SMOKE (`toTop` transport fires under the concrete `TrackerSim`).  Bringing
`"a"` (depth 2) to the top lands `σ "a" = 10` over the erased remainder. -/
theorem smoke_runOps_toTop_extraOps_sim :
    runOps (rollExtraOps (findDepthList "a" simNm.toList.reverse))
        { (default : StackState) with stack := simStk }
      = .ok { (default : StackState) with
              stack := simσ "a"
                :: simStk.eraseIdx (findDepthList "a" simNm.toList.reverse) } := by
  apply runOps_toTop_extraOps_sim
  · exact smoke_TrackerSim_satisfiable
  · decide

/-- SMOKE (`copyToTop` transport fires under the concrete `TrackerSim`).  Copying
`"a"` (depth 2) lands `σ "a" = 10` on top without removing it. -/
theorem smoke_runOps_copyToTop_extraOps_sim :
    runOps (pickExtraOps (findDepthList "a" simNm.toList.reverse))
        { (default : StackState) with stack := simStk }
      = .ok (({ (default : StackState) with stack := simStk }).push (simσ "a")) := by
  apply runOps_copyToTop_extraOps_sim
  · exact smoke_TrackerSim_satisfiable
  · decide

/-- SMOKE (`copyToTop` preservation fires).  Copying `"a"` to a fresh `"d"` extends
the concrete `TrackerSim` with `"d" ↦ σ "a" = 10`. -/
theorem smoke_TrackerSim_copyToTop :
    TrackerSim (simNm.push (some "d"))
      (fun t => if t = "d" then simσ "a" else simσ t) (simσ "a" :: simStk) := by
  apply TrackerSim_copyToTop { (default : StackState) with stack := simStk }
  · exact smoke_TrackerSim_satisfiable
  · decide

/-- SMOKE (the KEYSTONE fires — anti-vacuity).  `simTracker.nm = [a,b,c]`; bringing
`"a"` (codegen depth 2) to the top via `toTop` keeps `TrackerSim`: the new name
array is `[b,c,a]` and the runtime is `σ "a" :: simStk.eraseIdx 2 = [10, 30, 20]`.
Discharged through the keystone `TrackerSim_toTop` on the concrete tracker. -/
theorem smoke_TrackerSim_toTop :
    TrackerSim (simTracker.toTop "a").nm simσ
      (simσ "a" :: simStk.eraseIdx (findDepthList "a" simTracker.nm.toList.reverse)) := by
  apply TrackerSim_toTop simTracker simσ simStk "a"
  · refine ⟨by decide, ?_⟩
    intro i hi
    rw [getElem!_pos simTracker.nm i hi |>.symm]
    have hsz : simTracker.nm.size = 3 := by decide
    have h3 : i = 0 ∨ i = 1 ∨ i = 2 := by omega
    clear hi
    unfold slotAgrees
    rcases h3 with rfl | rfl | rfl <;> (unfold simTracker simStk simσ; rfl)
  · decide

/-! ### Per-helper ops-append lemmas (wave-78 deliverable 2)

Each Tracker helper APPENDS a determined op-list to `t.ops`, so `runOps_append`
decomposes the 945/518-op codegen list helper-by-helper.  The leaf primitives —
`rawBlock`, `pushInt`/`pushBytes`/`pushFieldP`, `toTop`, `copyToTop` — append a
list expressible via `rollExtraOps`/`pickExtraOps` (D1) at the depth the codegen
decides (`Tracker.findDepth`).  The field helpers compose those leaves; we ship
`fieldMod` as the worked non-nested example (the binop helpers nest a second
`toTop` whose depth is taken against the post-first-`toTop` tracker — provable by
the same `rw` chain, but the conclusion is a nested-tracker term, so we leave the
binop expansions to the assembly site rather than pre-baking a verbose lemma). -/

/-- **Id-monad `forIn`-push fold = append.**  The `rawBlock` ops loop folds
`Array.push` over the extra-ops list; its `toList` is `arr.toList ++ e`. -/
theorem forIn_id_push_toList :
    ∀ (e : List StackOp) (arr : Array StackOp),
      (forIn (m := Id) e arr fun op r => ForInStep.yield (r.push op)).toList
        = arr.toList ++ e := by
  intro e
  induction e with
  | nil => intro arr; rw [List.forIn_nil]; show arr.toList = arr.toList ++ []; simp
  | cons hd tl ih =>
    intro arr
    rw [List.forIn_cons]
    show (forIn (m := Id) tl (arr.push hd) fun op r => ForInStep.yield (r.push op)).toList = _
    rw [ih (arr.push hd)]; simp

/-- The `.ops` field of `rawBlock` is the `forIn`-push fold of the extra ops over
`t.ops`, independent of `produce` and the (ops-irrelevant) `nm` pop loop. -/
theorem rawBlock_ops_eq (t : Ec.Tracker) (c : Nat) (p : Option String) (e : List StackOp) :
    (t.rawBlock c p e).ops
      = forIn (m := Id) e t.ops fun op r => ForInStep.yield (r.push op) := by
  unfold Ec.Tracker.rawBlock; cases p <;> rfl

/-- **`rawBlock` ops-append.**  `(t.rawBlock c p e).ops = t.ops ++ e`. -/
theorem rawBlock_ops_append (t : Ec.Tracker) (c : Nat) (p : Option String) (e : List StackOp) :
    (t.rawBlock c p e).ops.toList = t.ops.toList ++ e := by
  rw [rawBlock_ops_eq]; exact forIn_id_push_toList e t.ops

/-- **`pushInt` ops-append.** -/
theorem pushInt_ops_append (t : Ec.Tracker) (n : String) (v : Int) :
    (t.pushInt n v).ops.toList = t.ops.toList ++ [.push (.bigint v)] := by
  unfold Ec.Tracker.pushInt Ec.Tracker.emit; simp

/-- **`pushBytes` ops-append.** -/
theorem pushBytes_ops_append (t : Ec.Tracker) (n : String) (v : ByteArray) :
    (t.pushBytes n v).ops.toList = t.ops.toList ++ [.push (.bytes v)] := by
  unfold Ec.Tracker.pushBytes Ec.Tracker.emit; simp

/-- **`pushFieldP` ops-append.**  Pushes the field prime literal. -/
theorem pushFieldP_ops_append (t : Ec.Tracker) (n : String) :
    (Ec.pushFieldP t n).ops.toList = t.ops.toList ++ [.push (.bigint Ec.fieldP)] := by
  unfold Ec.pushFieldP; exact pushInt_ops_append t n Ec.fieldP

/-- **`toTop` ops-append.**  `(t.toTop name).ops = t.ops ++ rollExtraOps (findDepth name)`.
The appended op is the depth-`Tracker.findDepth name` `roll` op (D1 `rollExtraOps`). -/
theorem toTop_ops_append (t : Ec.Tracker) (name : String) :
    (t.toTop name).ops.toList = t.ops.toList ++ rollExtraOps (t.findDepth name) := by
  unfold Ec.Tracker.toTop; exact roll_ops_append t (t.findDepth name)

/-- **`copyToTop` ops-append.**  `(t.copyToTop name newName).ops = t.ops ++
pickExtraOps (findDepth name)` (D1 `pickExtraOps`, depth-`Tracker.findDepth name`). -/
theorem copyToTop_ops_append (t : Ec.Tracker) (name newName : String) :
    (t.copyToTop name newName).ops.toList = t.ops.toList ++ pickExtraOps (t.findDepth name) := by
  unfold Ec.Tracker.copyToTop; exact pick_ops_append t (t.findDepth name) newName

/-- **`fieldMod` ops-append (worked field-helper example).**  `fieldMod` is
`toTop a → pushFieldP → rawBlock 2 r fieldModOps`; its ops append in that order. -/
theorem fieldMod_ops_append (t : Ec.Tracker) (a r : String) :
    (Ec.fieldMod t a r).ops.toList
      = t.ops.toList ++ rollExtraOps (t.findDepth a)
        ++ [.push (.bigint Ec.fieldP)] ++ Ec.fieldModOps := by
  unfold Ec.fieldMod
  rw [rawBlock_ops_append, pushFieldP_ops_append, toTop_ops_append]

/-- **Generic field-binop ops-append (deliverable 2 — the nested helper template).**
`fieldAdd`/`fieldSub`/`fieldMul` all share the shape `toTop a → toTop b →
rawBlock 2 prod [binop] → fieldMod prod r`.  Each nested `toTop`/`fieldMod` depth
is `Tracker.findDepth` against the *cumulative* tracker at that step, so the
appended op-blocks name the intermediate trackers explicitly (`t1 = toTop a`,
`t2 = toTop b t1`, `t3 = rawBlock … t2`).  This is the leaf-level decomposition the
whole-program assembly threads, mirroring the codegen's left-to-right helper order. -/
theorem fieldBinop_ops_append (t : Ec.Tracker) (a b prod r : String) (binop : StackOp) :
    (Ec.fieldMod (((t.toTop a).toTop b).rawBlock 2 (some prod) [binop]) prod r).ops.toList
      = t.ops.toList ++ rollExtraOps (t.findDepth a)
        ++ rollExtraOps ((t.toTop a).findDepth b)
        ++ [binop]
        ++ rollExtraOps ((((t.toTop a).toTop b).rawBlock 2 (some prod) [binop]).findDepth prod)
        ++ [.push (.bigint Ec.fieldP)] ++ Ec.fieldModOps := by
  rw [fieldMod_ops_append, rawBlock_ops_append, toTop_ops_append, toTop_ops_append]

/-- **`fieldMul` ops-append.**  Instantiates `fieldBinop_ops_append` at `OP_MUL`. -/
theorem fieldMul_ops_append (t : Ec.Tracker) (a b r : String) :
    (Ec.fieldMul t a b r).ops.toList
      = t.ops.toList ++ rollExtraOps (t.findDepth a)
        ++ rollExtraOps ((t.toTop a).findDepth b)
        ++ [.opcode "OP_MUL"]
        ++ rollExtraOps ((((t.toTop a).toTop b).rawBlock 2 (some "_fmul_prod")
              [.opcode "OP_MUL"]).findDepth "_fmul_prod")
        ++ [.push (.bigint Ec.fieldP)] ++ Ec.fieldModOps := by
  unfold Ec.fieldMul
  exact fieldBinop_ops_append t a b "_fmul_prod" r (.opcode "OP_MUL")

/-- **`fieldAdd` ops-append.**  Instantiates `fieldBinop_ops_append` at `OP_ADD`. -/
theorem fieldAdd_ops_append (t : Ec.Tracker) (a b r : String) :
    (Ec.fieldAdd t a b r).ops.toList
      = t.ops.toList ++ rollExtraOps (t.findDepth a)
        ++ rollExtraOps ((t.toTop a).findDepth b)
        ++ [.opcode "OP_ADD"]
        ++ rollExtraOps ((((t.toTop a).toTop b).rawBlock 2 (some "_fadd_sum")
              [.opcode "OP_ADD"]).findDepth "_fadd_sum")
        ++ [.push (.bigint Ec.fieldP)] ++ Ec.fieldModOps := by
  unfold Ec.fieldAdd
  exact fieldBinop_ops_append t a b "_fadd_sum" r (.opcode "OP_ADD")

/-! ### MANDATORY smokes for the per-helper ops-append lemmas (deliverable 2) -/

/-- SMOKE (`rawBlock` ops-append fires).  Appending `[OP_ADD]` to `simTracker.ops`. -/
theorem smoke_rawBlock_ops_append :
    (simTracker.rawBlock 2 (some "s") [.opcode "OP_ADD"]).ops.toList
      = simTracker.ops.toList ++ [StackOp.opcode "OP_ADD"] := by
  rw [rawBlock_ops_append]

/-- SMOKE (`pushFieldP` ops-append fires).  Appends the field-prime push. -/
theorem smoke_pushFieldP_ops_append :
    (Ec.pushFieldP simTracker "p").ops.toList
      = simTracker.ops.toList ++ [StackOp.push (.bigint Ec.fieldP)] := by
  rw [pushFieldP_ops_append]

/-- SMOKE (`toTop` ops-append fires + concrete depth).  `simTracker` has `nm =
[a,b,c]`; `toTop "a"` rolls depth 2, appending `rollExtraOps 2 = [.rot]`. -/
theorem smoke_toTop_ops_append :
    (simTracker.toTop "a").ops.toList = simTracker.ops.toList ++ [StackOp.rot] := by
  rw [toTop_ops_append]
  have : simTracker.findDepth "a" = 2 := by decide
  rw [this]; rfl

/-- SMOKE (`copyToTop` ops-append fires + concrete depth).  `copyToTop "a"` picks
depth 2, appending `pickExtraOps 2 = [.pickStruct 2]`. -/
theorem smoke_copyToTop_ops_append :
    (simTracker.copyToTop "a" "z").ops.toList
      = simTracker.ops.toList ++ [StackOp.pickStruct 2] := by
  rw [copyToTop_ops_append]
  have : simTracker.findDepth "a" = 2 := by decide
  rw [this]; rfl

/-- SMOKE (`fieldMod` ops-append fires).  Full decomposition of `fieldMod "a" "r"`
on `simTracker`: `toTop` (depth 2 → `.rot`), push prime, then `fieldModOps`. -/
theorem smoke_fieldMod_ops_append :
    (Ec.fieldMod simTracker "a" "r").ops.toList
      = simTracker.ops.toList ++ rollExtraOps (simTracker.findDepth "a")
        ++ [StackOp.push (.bigint Ec.fieldP)] ++ Ec.fieldModOps := by
  rw [fieldMod_ops_append]

/-- SMOKE (`fieldMul` ops-append fires).  Full nested decomposition of
`fieldMul "a" "b" "r"` on `simTracker`: two `toTop`s (against the cumulative
trackers), `OP_MUL`, the result `toTop`, push prime, then `fieldModOps`. -/
theorem smoke_fieldMul_ops_append :
    (Ec.fieldMul simTracker "a" "b" "r").ops.toList
      = simTracker.ops.toList ++ rollExtraOps (simTracker.findDepth "a")
        ++ rollExtraOps ((simTracker.toTop "a").findDepth "b")
        ++ [StackOp.opcode "OP_MUL"]
        ++ rollExtraOps ((((simTracker.toTop "a").toTop "b").rawBlock 2 (some "_fmul_prod")
              [.opcode "OP_MUL"]).findDepth "_fmul_prod")
        ++ [StackOp.push (.bigint Ec.fieldP)] ++ Ec.fieldModOps := by
  rw [fieldMul_ops_append]

/-- SMOKE (`fieldAdd` ops-append fires).  Same nested shape at `OP_ADD`. -/
theorem smoke_fieldAdd_ops_append :
    (Ec.fieldAdd simTracker "a" "b" "r").ops.toList
      = simTracker.ops.toList ++ rollExtraOps (simTracker.findDepth "a")
        ++ rollExtraOps ((simTracker.toTop "a").findDepth "b")
        ++ [StackOp.opcode "OP_ADD"]
        ++ rollExtraOps ((((simTracker.toTop "a").toTop "b").rawBlock 2 (some "_fadd_sum")
              [.opcode "OP_ADD"]).findDepth "_fadd_sum")
        ++ [StackOp.push (.bigint Ec.fieldP)] ++ Ec.fieldModOps := by
  rw [fieldAdd_ops_append]

/-! ## Part 10 — `decomposePoint` runtime base step (deliverable 1)

`decomposePoint t "_pt" "_x" "_y"` is the FIRST helper `emitEcOnCurve`/`emitEcNegate`
run; it is the base TrackerSim over `[_x, _y]` the rest of the chain threads off.  It
is built from `Tracker.init [some "_pt"]`, so its `nm` is fully concrete at every
step and its op-list reduces to a determined list (`decomposePoint_ops`); the
runtime transport (`decomposePoint_op_transport`) then runs that determined list
on `[pt] ++ rest` symbolically in `pt`'s bytes — same shape as the discharged
`emitEcPointX/Y_runOps_eq` but with the single-split-convert-BOTH ordering
(`OP_SPLIT` at 32 → convert y-half → swap → convert x-half → swap), reusing
`reverse32_ops_transport` twice via the shared `convTail_transport` leaf.  The
spec bridge (`decomposePoint_runOps`) lifts the two byte-decodes to
`Crypto.Secp256k1.pointX`/`pointY` under the SAME two canonical-decode hypotheses
(`hDecX`/`hDecY`) the pointX/pointY discharges carry, plus `64 ≤ p.size` (a 64-byte
point).  All `propext`/`Quot.sound`-clean (plus the inherited backend opaques on
the `runOps`-bearing transports), NO `sorry`, NO new axiom, `native_decide` only in
the concrete smokes. -/

/-- **`swap` ops-append.**  `(t.swap).ops = t.ops ++ [.swap]` (both `if`-branches
push the op). -/
theorem swap_ops_append (t : Ec.Tracker) :
    (t.swap).ops.toList = t.ops.toList ++ [StackOp.swap] := by
  unfold Ec.Tracker.swap Ec.Tracker.emit
  simp only [ge_iff_le]
  split <;> simp

/-- **`rawBlock` nm at `consumeCnt = 1`, `produce = some n`.**  Pops one slot,
pushes `some n`.  Reduces the `Id.run`/`forIn [0:1]` pop-loop. -/
theorem rawBlock_nm_some1 (t : Ec.Tracker) (n : String) (e : List StackOp) :
    (t.rawBlock 1 (some n) e).nm = t.nm.pop.push (some n) := by
  unfold Ec.Tracker.rawBlock; simp [Id.run]; rfl

/-- **`rawBlock` nm at `consumeCnt = 1`, `produce = none`.**  Pops one slot. -/
theorem rawBlock_nm_none1 (t : Ec.Tracker) (e : List StackOp) :
    (t.rawBlock 1 none e).nm = t.nm.pop := by
  unfold Ec.Tracker.rawBlock; simp [Id.run]; rfl

/-- The LE-decode conversion tail `emitReverse32Ops ++ [push 0x00, OP_CAT, OP_BIN2NUM]`
shared by both `decomposePoint` coordinate conversions. -/
def dpConvTail : List StackOp :=
  [StackOp.push (.bytes (ByteArray.mk #[0x00])), StackOp.opcode "OP_CAT", StackOp.opcode "OP_BIN2NUM"]

/-- The intermediate `decomposePoint` trackers (named so the `findDepth` of the
inner `toTop "_dp_xb"` can be folded). -/
def dpT1 : Ec.Tracker := (Ec.Tracker.init [some "_pt"]).toTop "_pt"
def dpT2 : Ec.Tracker := dpT1.rawBlock 1 none [.push (.bigint 32), .opcode "OP_SPLIT"]
def dpT3 : Ec.Tracker := { dpT2 with nm := (dpT2.nm.push (some "_dp_xb")).push (some "_dp_yb") }
def dpT4 : Ec.Tracker := dpT3.rawBlock 1 (some "_y") (Ec.emitReverse32Ops ++ dpConvTail)

theorem dpT1_nm : dpT1.nm = #[some "_pt"] := by
  unfold dpT1 Ec.Tracker.toTop
  rw [show (Ec.Tracker.init [some "_pt"]).findDepth "_pt" = 0 from by
    rw [findDepth_eq_findDepthList _ _ (by unfold Ec.Tracker.init; decide)]
    unfold Ec.Tracker.init; decide]
  rfl

theorem dpT2_nm : dpT2.nm = #[] := by rw [dpT2, rawBlock_nm_none1, dpT1_nm]; rfl

theorem dpT4_nm : dpT4.nm = #[some "_dp_xb", some "_y"] := by
  rw [dpT4, rawBlock_nm_some1]
  show (dpT3.nm.pop.push (some "_y")) = _
  rw [dpT3]
  show ((((dpT2.nm.push (some "_dp_xb")).push (some "_dp_yb")).pop).push (some "_y")) = _
  rw [dpT2_nm]; rfl

theorem dpT1_fd0 : dpT1.findDepth "_pt" = 0 := by
  unfold dpT1 Ec.Tracker.toTop
  rw [findDepth_eq_findDepthList _ _ (by unfold Ec.Tracker.init; decide)]
  unfold Ec.Tracker.init; decide

theorem dpT4_fd1 : dpT4.findDepth "_dp_xb" = 1 := by
  rw [findDepth_eq_findDepthList _ _ (by rw [dpT4_nm]; decide)]
  rw [dpT4_nm]; decide

/-- The determined `decomposePoint` op-list (split + 2× convert + 2× swap). -/
def expectedDecomposePoint : List StackOp :=
  [StackOp.push (.bigint 32), StackOp.opcode "OP_SPLIT"]
  ++ (Ec.emitReverse32Ops ++ dpConvTail) ++ [StackOp.swap]
  ++ (Ec.emitReverse32Ops ++ dpConvTail) ++ [StackOp.swap]

set_option maxRecDepth 8192 in
/-- **`decomposePoint` op-list = the determined list.**  Threads the four ops-append
leaf lemmas through the (concrete-`nm`) tracker, folding the two `findDepth` depths
(0 for `_pt`, 1 for `_dp_xb`) via the wave-77 bridge. -/
theorem decomposePoint_ops :
    (Ec.decomposePoint (Ec.Tracker.init [some "_pt"]) "_pt" "_x" "_y").ops.toList
      = expectedDecomposePoint := by
  show (dpT4.toTop "_dp_xb" |>.rawBlock 1 (some "_x")
        (Ec.emitReverse32Ops ++ dpConvTail) |>.swap).ops.toList = _
  rw [swap_ops_append, rawBlock_ops_append, toTop_ops_append, dpT4_fd1]
  show (dpT4.ops.toList ++ rollExtraOps 1 ++ (Ec.emitReverse32Ops ++ dpConvTail)
        ++ [StackOp.swap]) = _
  rw [dpT4, rawBlock_ops_append]
  show ((dpT3.ops.toList ++ (Ec.emitReverse32Ops ++ dpConvTail)) ++ rollExtraOps 1
        ++ (Ec.emitReverse32Ops ++ dpConvTail) ++ [StackOp.swap]) = _
  rw [dpT3]
  show ((dpT2.ops.toList ++ (Ec.emitReverse32Ops ++ dpConvTail)) ++ rollExtraOps 1
        ++ (Ec.emitReverse32Ops ++ dpConvTail) ++ [StackOp.swap]) = _
  rw [dpT2, rawBlock_ops_append, dpT1, toTop_ops_append]
  rw [show (Ec.Tracker.init [some "_pt"]).findDepth "_pt" = 0 from dpT1_fd0]
  simp only [rollExtraOps, Ec.Tracker.init, dpConvTail, expectedDecomposePoint]
  rfl

/-- **The shared LE-decode conversion leaf.**  On `[b] ++ rest` with `32 ≤ b.size`,
`emitReverse32Ops ++ [push 0x00, OP_CAT, OP_BIN2NUM]` lands
`decodeMinimalLE (reverseAcc 32 b empty ++ 0x00)` (reuses `reverse32_ops_transport`). -/
theorem dpConvTail_transport (s : StackState) (b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: rest) (hSize : 32 ≤ b.size) :
    runOps (Ec.emitReverse32Ops ++ dpConvTail) s
      = .ok { s with stack := .vBigint (decodeMinimalLE (reverseAcc 32 b ByteArray.empty ++ ByteArray.mk #[0x00])) :: rest } := by
  obtain ⟨stk, alt, out, props, pre⟩ := s
  subst hStk
  have niOp : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by intro c t e h; cases h
  have niPush : ∀ (pv : PushVal) t e, StackOp.push pv ≠ .ifOp t e := by intro pv t e h; cases h
  rw [runOps_append, reverse32_ops_transport
        { stack := .vBytes b :: rest, altstack := alt, outputs := out, props := props,
          preimage := pre } b rest rfl hSize]
  simp only [match_Except_ok_runOps]
  unfold dpConvTail
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bytes (ByteArray.mk #[0x00]))), stepNonIf_push_bytes]
  simp only [match_Except_ok_runOps, StackState.push]
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_CAT"), stepNonIf_opcode]
  rw [show runOpcode "OP_CAT"
        { stack := .vBytes (ByteArray.mk #[0x00]) :: .vBytes (reverseAcc 32 b ByteArray.empty)
                    :: rest, altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (reverseAcc 32 b ByteArray.empty ++ ByteArray.mk #[0x00]) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_BIN2NUM"), stepNonIf_opcode]
  rw [show runOpcode "OP_BIN2NUM"
        { stack := .vBytes (reverseAcc 32 b ByteArray.empty ++ ByteArray.mk #[0x00]) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint
                  (decodeMinimalLE (reverseAcc 32 b ByteArray.empty ++ ByteArray.mk #[0x00])) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps, runOps_nil]

set_option maxRecDepth 8192 in
/-- **Operational transport for the determined `decomposePoint` list.**  On `[p] ++ rest`
with `64 ≤ p.size`, lands `[y_num, x_num] ++ rest` (y on TOS), where each coord is the
LE-decode of the byte-reversed half — the same `decodeMinimalLE … ++ 0x00` shape as
`ec_pointX/Y_op_transport`, but produced by the single-split-both-convert ordering. -/
theorem decomposePoint_op_transport (s : StackState) (p : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes p :: rest) (hSize : 64 ≤ p.size) :
    runOps expectedDecomposePoint s
      = .ok { s with stack := .vBigint (decodeMinimalLE (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty ++ ByteArray.mk #[0x00])) :: .vBigint (decodeMinimalLE (reverseAcc 32 (p.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])) :: rest } := by
  obtain ⟨stk, alt, out, props, pre⟩ := s
  subst hStk
  have niOp : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by intro c t e h; cases h
  have niPush : ∀ (pv : PushVal) t e, StackOp.push pv ≠ .ifOp t e := by intro pv t e h; cases h
  have niSwap : ∀ t e, StackOp.swap ≠ .ifOp t e := by intro t e h; cases h
  have hXsize : (p.extract 0 32).size = 32 := by rw [ByteArray.size_extract]; omega
  have hYsize : (p.extract 32 p.size).size = p.size - 32 := by rw [ByteArray.size_extract]; omega
  have hXle : 32 ≤ (p.extract 0 32).size := by omega
  rw [show expectedDecomposePoint = StackOp.push (.bigint 32) :: StackOp.opcode "OP_SPLIT"
        :: ((Ec.emitReverse32Ops ++ dpConvTail) ++ ([StackOp.swap]
            ++ ((Ec.emitReverse32Ops ++ dpConvTail) ++ [StackOp.swap]))) from rfl]
  -- push 32
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 32)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- OP_SPLIT at 32 → [y_bytes, x_bytes]
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_SPLIT"), stepNonIf_opcode]
  rw [show runOpcode "OP_SPLIT"
        { stack := .vBigint 32 :: .vBytes p :: rest, altstack := alt, outputs := out,
          props := props, preimage := pre }
        = .ok { stack := .vBytes (p.extract 32 p.size) :: .vBytes (p.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      unfold runOpcode
      simp only [popN, StackState.pop?, asBytes?, asNonNegativeNat?, asInt?, StackState.push,
                 Int.reduceLT, reduceIte]
      rw [if_neg (by omega : ¬ (32 : Int).toNat > p.size)]; rfl]
  simp only [match_Except_ok_runOps]
  -- convert y-half
  rw [runOps_append]
  rw [dpConvTail_transport
        { stack := .vBytes (p.extract 32 p.size) :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        (p.extract 32 p.size) (.vBytes (p.extract 0 32) :: rest) rfl (by rw [hYsize]; omega)]
  simp only [match_Except_ok_runOps, List.singleton_append]
  -- swap → [x_bytes, y_num]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBigint (decodeMinimalLE (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty ++ ByteArray.mk #[0x00])) :: .vBytes (p.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (p.extract 0 32) :: .vBigint (decodeMinimalLE (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty ++ ByteArray.mk #[0x00])) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- convert x-half
  rw [runOps_append]
  rw [dpConvTail_transport
        { stack := .vBytes (p.extract 0 32) :: .vBigint (decodeMinimalLE (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty ++ ByteArray.mk #[0x00])) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        (p.extract 0 32) (.vBigint (decodeMinimalLE (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty ++ ByteArray.mk #[0x00])) :: rest) rfl hXle]
  simp only [match_Except_ok_runOps, List.singleton_append]
  -- final swap → [y_num, x_num]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBigint (decodeMinimalLE (reverseAcc 32 (p.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])) :: .vBigint (decodeMinimalLE (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty ++ ByteArray.mk #[0x00])) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint (decodeMinimalLE (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty ++ ByteArray.mk #[0x00])) :: .vBigint (decodeMinimalLE (reverseAcc 32 (p.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps, runOps_nil]

open RunarVerification.Crypto.Secp256k1 (pointX pointY) in
/-- **DISCHARGED base step (deliverable 1) — `decomposePoint` ↔ `(pointX, pointY)`.**
Running `Stack.Ec.decomposePoint (Tracker.init [some "_pt"]) "_pt" "_x" "_y"` on
`[p] ++ rest` lands `[pointY p, pointX p] ++ rest` (y on TOS, matching the produced
`nm = #[_x, _y]`), under `64 ≤ p.size` plus the two canonical-decode bridges
`hDecX`/`hDecY` — the SAME hypotheses the discharged `emitEcPointX/Y_runOps_eq`
carry, restated here for `decomposePoint`'s split-convert-both ordering.  This is
the base `TrackerSim`-bearing transport the wave-79 hand-off named as Part-9
sub-goal (c); it establishes the runtime stack the `ecOnCurve`/`ecNegate` field
chain threads off. -/
theorem decomposePoint_runOps (s : StackState) (p : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes p :: rest) (hSize : 64 ≤ p.size)
    (hDecX : decodeMinimalLE
              (reverseAcc 32 (p.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00]) = pointX p)
    (hDecY : decodeMinimalLE
              (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty ++ ByteArray.mk #[0x00]) = pointY p) :
    runOps (Ec.decomposePoint (Ec.Tracker.init [some "_pt"]) "_pt" "_x" "_y").ops.toList s
      = .ok { s with stack := .vBigint (pointY p) :: .vBigint (pointX p) :: rest } := by
  rw [decomposePoint_ops, decomposePoint_op_transport s p rest hStk hSize, hDecX, hDecY]

/-! ### MANDATORY smokes for the decomposePoint base step (deliverable 1) -/

private def smokeDpPt : ByteArray := RunarVerification.Crypto.Secp256k1.makePoint 11 22
private def smokeDpStk : StackState :=
  { (default : StackState) with stack := [.vBytes smokeDpPt] }

/-- SMOKE (wf anti-vacuity).  The `64 ≤ size` + two decode bridges hold concretely
for `makePoint 11 22`.  Rules out a vacuous discharge. -/
theorem smoke_decomposePoint_wf_satisfiable :
    (64 : Nat) ≤ smokeDpPt.size
      ∧ decodeMinimalLE (reverseAcc 32 (smokeDpPt.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
          = RunarVerification.Crypto.Secp256k1.pointX smokeDpPt
      ∧ decodeMinimalLE (reverseAcc 32 (smokeDpPt.extract 32 smokeDpPt.size) ByteArray.empty ++ ByteArray.mk #[0x00])
          = RunarVerification.Crypto.Secp256k1.pointY smokeDpPt := by
  native_decide

/-- SMOKE (the headline).  The discharged `decomposePoint_runOps` FIRES on the
concrete point, landing `[pointY, pointX] = [22, 11]`. -/
theorem smoke_decomposePoint_runOps :
    runOps (Ec.decomposePoint (Ec.Tracker.init [some "_pt"]) "_pt" "_x" "_y").ops.toList smokeDpStk
      = .ok { smokeDpStk with stack := .vBigint (RunarVerification.Crypto.Secp256k1.pointY smokeDpPt) :: .vBigint (RunarVerification.Crypto.Secp256k1.pointX smokeDpPt) :: [] } :=
  decomposePoint_runOps smokeDpStk smokeDpPt [] rfl (by native_decide) (by native_decide) (by native_decide)

/-- SMOKE (value anti-vacuity).  The decoded coords are concretely `(11, 22)`. -/
theorem smoke_decomposePoint_value_concrete :
    RunarVerification.Crypto.Secp256k1.pointX smokeDpPt = 11
      ∧ RunarVerification.Crypto.Secp256k1.pointY smokeDpPt = 22 := by
  native_decide

/-! ## Part 11 — `ecOnCurve` base `TrackerSim` (deliverable 2, first threading step)

The base step (`decomposePoint_runOps`, Part 10) lands the runtime stack
`[pointY p, pointX p]` and the tracker `nm = #[_x, _y]`.  This Part packages that
into the rolling `TrackerSim` the field chain threads off — the FIRST step of the
whole-program assembly, demonstrating the threading composes off deliverable 1.

`decomposePoint_final_nm` computes the produced `nm` (via the `dpT5`/`dpT6` nm-chain,
the `toTop "_dp_xb"` = `roll 1` = `swap`, the `swap`/`rawBlock` nm lemmas + the
wave-77 `findDepth` bridge).  `decomposePoint_baseTrackerSim` then exhibits the base
`TrackerSim` over the produced `nm` under the canonical base valuation
`ecOnCurveBaseσ` (`_x ↦ pointX p`, `_y ↦ pointY p`) — the entry invariant for the
`fieldSqr`/`fieldMul`/`fieldAdd`/`OP_EQUAL` chain.  All `propext`/`Quot.sound`-clean,
NO `sorry`, NO new axiom.  (See the Part-9 BLOCK note for the precise next step that
gates the full `emitEcOnCurve` discharge.) -/

/-- **`swap` nm at size ≥ 2.**  Swaps the top two name slots. -/
theorem swap_nm_ge2 (t : Ec.Tracker) (h : t.nm.size ≥ 2) :
    (t.swap).nm
      = (t.nm.set! (t.nm.size - 1) t.nm[t.nm.size - 2]!).set! (t.nm.size - 2) t.nm[t.nm.size - 1]! := by
  unfold Ec.Tracker.swap Ec.Tracker.emit; simp only [ge_iff_le]; rw [if_pos h]

/-- Continued `decomposePoint` tracker chain (past `dpT4`): `toTop "_dp_xb"` (depth 1
= `swap`), then the x-coordinate `rawBlock`. -/
def dpT5 : Ec.Tracker := dpT4.toTop "_dp_xb"
def dpT6 : Ec.Tracker := dpT5.rawBlock 1 (some "_x") (Ec.emitReverse32Ops ++ dpConvTail)

theorem dpT5_nm : dpT5.nm = #[some "_y", some "_dp_xb"] := by
  unfold dpT5 Ec.Tracker.toTop
  rw [dpT4_fd1]
  show (dpT4.swap).nm = _
  rw [swap_nm_ge2 dpT4 (by rw [dpT4_nm]; decide), dpT4_nm]; rfl

theorem dpT6_nm : dpT6.nm = #[some "_y", some "_x"] := by
  unfold dpT6; rw [rawBlock_nm_some1, dpT5_nm]; rfl

/-- **`decomposePoint` produced `nm` = `#[_x, _y]`.**  The codegen name array the
`ecOnCurve`/`ecNegate` field chain reads its slots from. -/
theorem decomposePoint_final_nm :
    (Ec.decomposePoint (Ec.Tracker.init [some "_pt"]) "_pt" "_x" "_y").nm
      = #[some "_x", some "_y"] := by
  show (dpT6.swap).nm = _
  rw [swap_nm_ge2 dpT6 (by rw [dpT6_nm]; decide), dpT6_nm]; rfl

/-- Canonical base valuation for the `ecOnCurve` field chain: the two decomposed
coordinates. -/
def ecOnCurveBaseσ (p : ByteArray) : String → Value
  | "_x" => Value.vBigint (Crypto.Secp256k1.pointX p)
  | "_y" => Value.vBigint (Crypto.Secp256k1.pointY p)
  | _    => Value.vBigint 0

/-- **The base `TrackerSim` (deliverable 2, first threading step).**  After
`decomposePoint`, the runtime stack `[pointY p, pointX p]` mirrors the produced
`nm = #[_x, _y]` under `ecOnCurveBaseσ` — the entry invariant the `fieldSqr`/
`fieldMul`/`fieldAdd`/`OP_EQUAL` chain threads.  Composes `decomposePoint_final_nm`
with the slot-by-slot agreement.  This is the first step of the Part-9 sub-goal (b)
whole-program assembly that COMPOSES off deliverable 1. -/
theorem decomposePoint_baseTrackerSim (p : ByteArray) :
    TrackerSim (Ec.decomposePoint (Ec.Tracker.init [some "_pt"]) "_pt" "_x" "_y").nm
      (ecOnCurveBaseσ p)
      [Value.vBigint (Crypto.Secp256k1.pointY p), Value.vBigint (Crypto.Secp256k1.pointX p)] := by
  rw [decomposePoint_final_nm]
  refine ⟨rfl, ?_⟩
  intro i hi
  rw [getElem!_pos _ i hi |>.symm]
  have hsz : (#[some "_x", some "_y"] : Array (Option String)).size = 2 := by decide
  have hi2 : i = 0 ∨ i = 1 := by omega
  unfold slotAgrees ecOnCurveBaseσ
  rcases hi2 with rfl | rfl <;> simp <;> rfl

/-! ### MANDATORY smoke for the base `TrackerSim` (deliverable 2) -/

/-- SMOKE (base sim fires — anti-vacuity).  On the concrete `makePoint 11 22`, the
base `TrackerSim` holds: produced `nm = #[_x, _y]`, runtime stack `[22, 11]`. -/
theorem smoke_decomposePoint_baseTrackerSim :
    TrackerSim (Ec.decomposePoint (Ec.Tracker.init [some "_pt"]) "_pt" "_x" "_y").nm
      (ecOnCurveBaseσ smokeDpPt)
      [Value.vBigint (Crypto.Secp256k1.pointY smokeDpPt),
       Value.vBigint (Crypto.Secp256k1.pointX smokeDpPt)] :=
  decomposePoint_baseTrackerSim smokeDpPt

/-! ## Part 12 — Tail-general `TrackerSim` + per-field-helper composed sims (D1+D2)

The strict `TrackerSim nm σ stk` (Part 9 substrate) demands `stk.length = nm.size`:
no passive tail.  But the WHOLE-PROGRAM `emitEcOnCurve`/`emitEcNegate` run on
`[pt] ++ rest`, so after `decomposePoint` the field chain runs over `tracked ++ rest`
(`tracked = [pointY, pointX]`, `rest` arbitrary).  Every `toTop`/`copyToTop` op the
field helpers emit acts at a depth `d < nm.size ≤ tracked.length`, so it only touches
the top `tracked` region and leaves `rest` byte-for-byte untouched.

This Part adds the MINIMAL-VIABLE tail-general form: `TrackerSimT nm σ tracked rest`
(= `TrackerSim nm σ tracked` over the `tracked` prefix of the runtime stack
`tracked ++ rest`).  The genuine content is the APPEND-TRANSPORTS — `applyRoll`/
`applyPick` at depth `< tracked.length` on `tracked ++ rest` equal the strict result
over `tracked`, with `rest` appended (`applyRoll_append` / `applyPick_append`).  These
lift the strict per-step transports (`runOps_toTop/copyToTop_extraOps_sim`) + the
keystone (`TrackerSim_toTop`/`copyToTop`) to the tail-general `tracked ++ rest` shape.
The per-field-helper composed sims (`fieldSqr_runOps_sim`, `fieldMul_runOps_sim`,
`fieldAdd_runOps_sim`) then thread the rolling `TrackerSimT` through each helper's
toTop/copyToTop/rawBlock/fieldMod sub-steps, binding a fresh named slot to the
`Crypto.Secp256k1` field-op result.  All `propext`/`Quot.sound`-clean (plus inherited
backend opaques on the `runOps`-bearing transports), NO `sorry`, NO new axiom,
`native_decide` only in concrete smokes. -/

/-- **Tail-general `TrackerSim` (deliverable 1).**  The runtime stack is
`tracked ++ rest`; the `tracked` prefix mirrors the tracker name array `nm` (strict
`TrackerSim`), and `rest` is an arbitrary passive tail untouched by the field chain's
depth-`< nm.size` rolls/picks.  Minimal-viable form: a strict `TrackerSim` on the
prefix, with the append shape made explicit at every transport. -/
def TrackerSimT (nm : Array (Option String)) (σ : String → Value)
    (tracked rest : List Value) : Prop :=
  TrackerSim nm σ tracked

/-- `getElem!` of `tracked ++ rest` strictly inside the `tracked` part. -/
private theorem getElemBang_append_lt {α : Type} [Inhabited α] (tracked rest : List α)
    (d : Nat) (h : d < tracked.length) :
    (tracked ++ rest)[d]! = tracked[d]! := by
  rw [getElem!_pos (tracked ++ rest) d (by rw [List.length_append]; omega),
      getElem!_pos tracked d h, List.getElem_append_left h]

/-- `eraseIdx` of `tracked ++ rest` strictly inside the `tracked` part keeps `rest`. -/
private theorem eraseIdx_append_lt {α : Type} (tracked rest : List α)
    (d : Nat) (h : d < tracked.length) :
    (tracked ++ rest).eraseIdx d = tracked.eraseIdx d ++ rest := by
  rw [List.eraseIdx_append_of_lt_length h]

/-- **`applyRoll` append-transport (deliverable 1).**  Rolling depth `d < tracked.length`
on `tracked ++ rest` brings `tracked[d]!` to the top, erases it from `tracked`, and
keeps `rest` below — the strict `applyRoll` result with `rest` appended. -/
private theorem applyRoll_append (s : StackState) (tracked rest : List Value) (d : Nat)
    (hStk : s.stack = tracked ++ rest) (hd : d < tracked.length) :
    applyRoll s d = .ok { s with stack := tracked[d]! :: (tracked.eraseIdx d ++ rest) } := by
  unfold applyRoll
  rw [hStk]
  rw [if_neg (by rw [List.length_append]; omega : ¬ d ≥ (tracked ++ rest).length)]
  rw [getElemBang_append_lt tracked rest d hd, eraseIdx_append_lt tracked rest d hd]

/-- **`applyPick` append-transport (deliverable 1).**  Picking depth `d < tracked.length`
on `tracked ++ rest` copies `tracked[d]!` to the top, keeping all of `tracked ++ rest`. -/
private theorem applyPick_append (s : StackState) (tracked rest : List Value) (d : Nat)
    (hStk : s.stack = tracked ++ rest) (hd : d < tracked.length) :
    applyPick s d = .ok (s.push tracked[d]!) := by
  unfold applyPick StackState.push
  rw [hStk]
  rw [if_neg (by rw [List.length_append]; omega : ¬ d ≥ (tracked ++ rest).length)]
  rw [getElemBang_append_lt tracked rest d hd]

/-- **`toTop` per-step tail-general transport (deliverable 1).**  Under
`TrackerSimT nm σ tracked rest`, running `Tracker.toTop name`'s emit on the runtime
stack `tracked ++ rest` brings `σ name` to the top, with the rest of the TRACKED
region erased and `rest` preserved below.  The append-form of
`runOps_toTop_extraOps_sim`. -/
theorem runOps_toTop_extraOps_simT (s : StackState) (nm : Array (Option String))
    (σ : String → Value) (tracked rest : List Value) (name : String)
    (hStk : s.stack = tracked ++ rest)
    (hSim : TrackerSimT nm σ tracked rest)
    (hmem : some name ∈ nm.toList.reverse) :
    runOps (rollExtraOps (findDepthList name nm.toList.reverse)) s
      = .ok { s with
              stack := σ name
                :: (tracked.eraseIdx (findDepthList name nm.toList.reverse) ++ rest) } := by
  unfold TrackerSimT at hSim
  obtain ⟨hlt, hval⟩ := findDepthList_sim nm σ tracked name hSim hmem
  have hd_lt : findDepthList name nm.toList.reverse < tracked.length := hlt
  have hstklen : findDepthList name nm.toList.reverse < s.stack.length := by
    rw [hStk, List.length_append]; omega
  rw [runOps_rollExtraOps s _ hstklen]
  rw [applyRoll_append s tracked rest _ hStk hd_lt, hval]

/-- **`copyToTop` per-step tail-general transport (deliverable 1).**  Under
`TrackerSimT nm σ tracked rest`, running `Tracker.copyToTop name newName`'s emit on
`tracked ++ rest` COPIES `σ name` to the top, keeping all of `tracked ++ rest`. -/
theorem runOps_copyToTop_extraOps_simT (s : StackState) (nm : Array (Option String))
    (σ : String → Value) (tracked rest : List Value) (name : String)
    (hStk : s.stack = tracked ++ rest)
    (hSim : TrackerSimT nm σ tracked rest)
    (hmem : some name ∈ nm.toList.reverse) :
    runOps (pickExtraOps (findDepthList name nm.toList.reverse)) s
      = .ok (s.push (σ name)) := by
  unfold TrackerSimT at hSim
  obtain ⟨hlt, hval⟩ := findDepthList_sim nm σ tracked name hSim hmem
  have hd_lt : findDepthList name nm.toList.reverse < tracked.length := hlt
  have hstklen : findDepthList name nm.toList.reverse < s.stack.length := by
    rw [hStk, List.length_append]; omega
  rw [runOps_pickExtraOps s _ hstklen]
  rw [applyPick_append s tracked rest _ hStk hd_lt, hval]

/-- **`toTop` tail-general `TrackerSimT` preservation (deliverable 1).**  After
`Tracker.toTop name`, the TRACKED region stays in lock-step (keystone
`TrackerSim_toTop` on the prefix), and `rest` is unchanged.  The append peer of the
keystone. -/
theorem TrackerSimT_toTop (t : Ec.Tracker) (σ : String → Value) (tracked rest : List Value)
    (name : String)
    (hSim : TrackerSimT t.nm σ tracked rest)
    (hmem : some name ∈ t.nm.toList.reverse) :
    TrackerSimT (t.toTop name).nm σ
      (σ name :: tracked.eraseIdx (findDepthList name t.nm.toList.reverse)) rest :=
  TrackerSim_toTop t σ tracked name hSim hmem

/-- **`copyToTop` tail-general `TrackerSimT` preservation (deliverable 1).**  After
`Tracker.copyToTop name newName` with `newName` fresh, the prefix extends with
`newName ↦ σ name`; `rest` is unchanged.  Append peer of `TrackerSim_copyToTop`. -/
theorem TrackerSimT_copyToTop (nm : Array (Option String)) (σ : String → Value)
    (tracked rest : List Value) (name newName : String)
    (hSim : TrackerSimT nm σ tracked rest)
    (hfresh : some newName ∉ nm.toList) :
    TrackerSimT (nm.push (some newName))
      (fun u => if u = newName then σ name else σ u) (σ name :: tracked) rest :=
  TrackerSim_push nm σ tracked newName (σ name) hSim hfresh

/-! ### Per-field-helper composed runtime sims (deliverable 2)

Each field helper's INCREMENTAL op-list (the ops appended to the entry tracker) is a
determined list — the toTop/copyToTop depths the codegen decides are concrete at the
`emitEcOnCurve` chain.  Reading them off the chain (via the ops-append leaves):

* `fieldSqr "_y" "_y2"` off the base `[Y, X] ++ rest`: `copyToTop "_y"` (depth 0 =
  `.dup`) → `toTop "_y"`/`toTop "_fsqr_copy"` (both depth 1 = `.swap`) → `OP_MUL` →
  `toTop "_fmul_prod"` (depth 0 = nop) → `push fieldP` → `fieldModOps`.  Net runtime:
  `[dup, swap, swap, OP_MUL, push fieldP] ++ fieldModOps`, landing `Y² :: X :: rest`.
* `fieldMul "_x2" "_x_copy" "_x3"` off `[X2, Y2, X] ++ rest`: `swap, OP_MUL, push
  fieldP, fieldModOps`, landing `(X2·X) :: Y2 :: rest`.
* `fieldAdd "_x3" "_seven" "_rhs"` off `[7, X3, Y2] ++ rest`: `swap, swap, OP_ADD,
  push fieldP, fieldModOps`, landing `(X3+7) :: Y2 :: rest`.

Each composed sim runs the determined increment off the entry runtime stack via the
toTop/copyToTop step transports + the `fieldXxx_optail_transport`, landing the
`Crypto.Secp256k1` field-op result with a fresh bound slot — the runtime witness the
whole-program assembly threads.  All `propext`/`Quot.sound`-clean (inherited backend
opaques on the `runOps` transports), `native_decide` only in smokes. -/

/-- The determined `fieldSqr "_y" "_y2"` increment off the `decomposePoint` base. -/
def fieldSqrYInc : List StackOp :=
  [.dup, .swap, .swap, .opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps

/-- The determined `fieldMul`/`fieldSqr`-with-`swap`-lead increment (`fieldMul
"_x2" "_x_copy"` off `[X2, Y2, X]`). -/
def fieldMulSwapInc : List StackOp :=
  [.swap, .opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps

/-- The determined `fieldAdd "_x3" "_seven"` increment off `[7, X3, Y2]`. -/
def fieldAddSwap2Inc : List StackOp :=
  [.swap, .swap, .opcode "OP_ADD", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps

private theorem niDup2 : ∀ t e, StackOp.dup ≠ .ifOp t e := by intro t e h; cases h
private theorem niSwap2 : ∀ t e, StackOp.swap ≠ .ifOp t e := by intro t e h; cases h

/-- **`fieldSqr "_y" "_y2"` composed runtime sim (deliverable 2, FIRST instance).**
Running the determined `fieldSqr` increment on `[Y, X] ++ rest` lands
`Secp256k1.fieldMul Y Y :: X :: rest` — the runtime witness of the y² slot the
`emitEcOnCurve` chain threads off `decomposePoint_baseTrackerSim`.  Composes the
`copyToTop`/`toTop` step collapses (`dup`/`swap`/`swap`) + `fieldMul_optail_transport`. -/
theorem fieldSqr_runOps_sim (s : StackState) (Y X : Int) (rest : List Value)
    (hStk : s.stack = (.vBigint Y) :: (.vBigint X) :: rest) :
    runOps fieldSqrYInc s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldMul Y Y) :: (.vBigint X) :: rest } := by
  unfold fieldSqrYInc
  rw [show ([StackOp.dup, .swap, .swap, .opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps)
        = StackOp.dup :: .swap :: .swap
            :: ([.opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) from rfl]
  rw [runOps_cons_nonIf_eq _ _ _ niDup2, stepNonIf_dup]
  rw [show applyDup s = .ok { s with stack := (.vBigint Y) :: (.vBigint Y) :: (.vBigint X) :: rest } by
        unfold applyDup StackState.push; rw [hStk]]
  simp only [match_Except_ok_runOps]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap2, stepNonIf_swap]
  rw [show applySwap { s with stack := (.vBigint Y) :: (.vBigint Y) :: (.vBigint X) :: rest }
        = .ok { s with stack := (.vBigint Y) :: (.vBigint Y) :: (.vBigint X) :: rest } from rfl]
  simp only [match_Except_ok_runOps]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap2, stepNonIf_swap]
  rw [show applySwap { s with stack := (.vBigint Y) :: (.vBigint Y) :: (.vBigint X) :: rest }
        = .ok { s with stack := (.vBigint Y) :: (.vBigint Y) :: (.vBigint X) :: rest } from rfl]
  simp only [match_Except_ok_runOps]
  rw [fieldMul_optail_transport { s with stack := (.vBigint Y) :: (.vBigint Y) :: (.vBigint X) :: rest }
        Y Y ((.vBigint X) :: rest) rfl]

/-- **`fieldMul`-with-swap-lead composed runtime sim (deliverable 2).**  Running the
determined `swap, OP_MUL, push fieldP, fieldModOps` increment on `[A, B, C] ++ rest`
lands `Secp256k1.fieldMul A C :: B :: rest` — `swap` brings `A` over `B`... in the
`emitEcOnCurve` use (`fieldMul "_x2" "_x_copy"` off `[X2, Y2, X]`) the toTop choreography
is `toTop "_x2"` (depth 0, nop) → `toTop "_x_copy"` (depth 2 = `swap`-collapsed since
`_x_copy` sits below); the determined single-`swap` lead pairs `_x2` (top) with `_x_copy`
(third) over `OP_MUL`.  Generalised: on `[a, b, c] ++ rest`, `swap` → `[b, a, c]`, then
`OP_MUL` multiplies the top two (`b, a`), so the result is `fieldMul a b :: c :: rest`. -/
theorem fieldMul_runOps_sim (s : StackState) (a b c : Int) (rest : List Value)
    (hStk : s.stack = (.vBigint a) :: (.vBigint b) :: (.vBigint c) :: rest) :
    runOps fieldMulSwapInc s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldMul a b) :: (.vBigint c) :: rest } := by
  unfold fieldMulSwapInc
  rw [show ([StackOp.swap, .opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps)
        = StackOp.swap :: ([.opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) from rfl]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap2, stepNonIf_swap]
  rw [show applySwap s = .ok { s with stack := (.vBigint b) :: (.vBigint a) :: (.vBigint c) :: rest } by
        unfold applySwap; rw [hStk]]
  simp only [match_Except_ok_runOps]
  rw [fieldMul_optail_transport { s with stack := (.vBigint b) :: (.vBigint a) :: (.vBigint c) :: rest }
        a b ((.vBigint c) :: rest) rfl]

/-- **`fieldAdd`-with-double-swap-lead composed runtime sim (deliverable 2).**  Running
`swap, swap, OP_ADD, push fieldP, fieldModOps` on `[a, b, c] ++ rest` (the two `swap`s
cancel) lands `Secp256k1.fieldAdd a b :: c :: rest` — the `fieldAdd "_x3" "_seven"` step
off `[7, X3, Y2] ++ rest`. -/
theorem fieldAdd_runOps_sim (s : StackState) (a b c : Int) (rest : List Value)
    (hStk : s.stack = (.vBigint a) :: (.vBigint b) :: (.vBigint c) :: rest) :
    runOps fieldAddSwap2Inc s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldAdd b a) :: (.vBigint c) :: rest } := by
  unfold fieldAddSwap2Inc
  rw [show ([StackOp.swap, .swap, .opcode "OP_ADD", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps)
        = StackOp.swap :: .swap :: ([.opcode "OP_ADD", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) from rfl]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap2, stepNonIf_swap]
  rw [show applySwap s = .ok { s with stack := (.vBigint b) :: (.vBigint a) :: (.vBigint c) :: rest } by
        unfold applySwap; rw [hStk]]
  simp only [match_Except_ok_runOps]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap2, stepNonIf_swap]
  rw [show applySwap { s with stack := (.vBigint b) :: (.vBigint a) :: (.vBigint c) :: rest }
        = .ok { s with stack := (.vBigint a) :: (.vBigint b) :: (.vBigint c) :: rest } from rfl]
  simp only [match_Except_ok_runOps]
  rw [fieldAdd_optail_transport { s with stack := (.vBigint a) :: (.vBigint b) :: (.vBigint c) :: rest }
        b a ((.vBigint c) :: rest) rfl]

private theorem niPickStruct2 : ∀ d t e, StackOp.pickStruct d ≠ .ifOp t e := by
  intro d t e h; cases h
private theorem niRoll2 : ∀ d t e, StackOp.roll d ≠ .ifOp t e := by intro d t e h; cases h

/-- The determined `fieldSqr "_x" "_x2"` increment off `[X, Y2, X] ++ rest` (the
`copyToTop "_x"` is depth-2 = `.pickStruct 2`, the inner `toTop "_x"` is depth-3 =
`.roll 3`).  `copyToTop` duplicates the deep `_x`; `roll 3 → swap` pair it for
`OP_MUL`. -/
def fieldSqrXInc : List StackOp :=
  [.pickStruct 2, .roll 3, .swap, .opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps

/-- **`fieldSqr "_x" "_x2"` composed runtime sim (deliverable 2).**  Running the
determined `fieldSqr "_x"` increment on `[X, Y2, X] ++ rest` (the two `_x` copies hold
the SAME value `X`) lands `Secp256k1.fieldMul X X :: X :: Y2 :: rest` — the runtime
witness of the x² slot, keeping a spare `X` (for the later `_x³` mul) and `Y2` below. -/
theorem fieldSqrX_runOps_sim (s : StackState) (X Y2 : Int) (rest : List Value)
    (hStk : s.stack = (.vBigint X) :: (.vBigint Y2) :: (.vBigint X) :: rest) :
    runOps fieldSqrXInc s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldMul X X)
                       :: (.vBigint X) :: (.vBigint Y2) :: rest } := by
  unfold fieldSqrXInc
  rw [show ([StackOp.pickStruct 2, .roll 3, .swap, .opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps)
        = StackOp.pickStruct 2 :: .roll 3 :: .swap
            :: ([.opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) from rfl]
  rw [runOps_cons_nonIf_eq _ _ _ (niPickStruct2 2)]
  rw [show stepNonIf (.pickStruct 2) s = applyPickStruct s 2 from rfl]
  rw [show applyPickStruct s 2
        = .ok { s with stack := (.vBigint X) :: (.vBigint X) :: (.vBigint Y2) :: (.vBigint X) :: rest } by
        unfold applyPickStruct StackState.push
        rw [if_neg (by rw [hStk]; simp), hStk]; rfl]
  simp only [match_Except_ok_runOps]
  rw [runOps_cons_nonIf_eq _ _ _ (niRoll2 3)]
  rw [show stepNonIf (.roll 3) { s with stack := (.vBigint X) :: (.vBigint X) :: (.vBigint Y2) :: (.vBigint X) :: rest }
        = applyRoll { s with stack := (.vBigint X) :: (.vBigint X) :: (.vBigint Y2) :: (.vBigint X) :: rest } 3 from rfl]
  rw [show applyRoll { s with stack := (.vBigint X) :: (.vBigint X) :: (.vBigint Y2) :: (.vBigint X) :: rest } 3
        = .ok { s with stack := (.vBigint X) :: (.vBigint X) :: (.vBigint X) :: (.vBigint Y2) :: rest } by
        unfold applyRoll
        rw [if_neg (by simp)]; rfl]
  simp only [match_Except_ok_runOps]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap2, stepNonIf_swap]
  rw [show applySwap { s with stack := (.vBigint X) :: (.vBigint X) :: (.vBigint X) :: (.vBigint Y2) :: rest }
        = .ok { s with stack := (.vBigint X) :: (.vBigint X) :: (.vBigint X) :: (.vBigint Y2) :: rest } from rfl]
  simp only [match_Except_ok_runOps]
  rw [fieldMul_optail_transport { s with stack := (.vBigint X) :: (.vBigint X) :: (.vBigint X) :: (.vBigint Y2) :: rest }
        X X ((.vBigint X) :: (.vBigint Y2) :: rest) rfl]

/-! ### MANDATORY smokes for the per-field-helper composed sims (deliverable 2) -/

private def fhSmokeRest : List Value := [Value.vBigint 777]

/-- SMOKE (`fieldSqr` sim fires — anti-vacuity).  On `[5, 9] ++ [777]`, lands
`fieldMul 5 5 = 25 :: 9 :: 777`. -/
theorem smoke_fieldSqr_runOps_sim :
    runOps fieldSqrYInc { (default : StackState) with stack := [.vBigint 5, .vBigint 9] ++ fhSmokeRest }
      = .ok { (default : StackState) with
              stack := .vBigint (Crypto.Secp256k1.fieldMul 5 5) :: .vBigint 9 :: fhSmokeRest } :=
  fieldSqr_runOps_sim _ 5 9 fhSmokeRest rfl

/-- SMOKE (`fieldMul` sim fires).  On `[81, 25, 9] ++ [777]` (= `[X2, Y2, X]`), lands
`fieldMul 81 25 :: 9 :: 777`. -/
theorem smoke_fieldMul_runOps_sim :
    runOps fieldMulSwapInc { (default : StackState) with stack := [.vBigint 81, .vBigint 25, .vBigint 9] ++ fhSmokeRest }
      = .ok { (default : StackState) with
              stack := .vBigint (Crypto.Secp256k1.fieldMul 81 25) :: .vBigint 9 :: fhSmokeRest } :=
  fieldMul_runOps_sim _ 81 25 9 fhSmokeRest rfl

/-- SMOKE (`fieldAdd` sim fires).  On `[7, 729, 25] ++ [777]` (= `[seven, X3, Y2]`), lands
`fieldAdd 729 7 :: 25 :: 777`. -/
theorem smoke_fieldAdd_runOps_sim :
    runOps fieldAddSwap2Inc { (default : StackState) with stack := [.vBigint 7, .vBigint 729, .vBigint 25] ++ fhSmokeRest }
      = .ok { (default : StackState) with
              stack := .vBigint (Crypto.Secp256k1.fieldAdd 729 7) :: .vBigint 25 :: fhSmokeRest } :=
  fieldAdd_runOps_sim _ 7 729 25 fhSmokeRest rfl

/-- SMOKE (field-helper sim values anti-vacuity).  `25 / 2025 / 736`. -/
theorem smoke_field_helper_sim_values :
    Crypto.Secp256k1.fieldMul 5 5 = 25
      ∧ Crypto.Secp256k1.fieldMul 81 25 = 2025
      ∧ Crypto.Secp256k1.fieldAdd 729 7 = 736 := by native_decide

/-! ## Part 13 — `emitEcOnCurve` op-list = the determined concatenation (deliverable 3)

`emitEcOnCurve`'s `t.ops.toList` after its 10-step tracker chain decomposes — via the
per-helper ops-append leaves (D2) with the CODEGEN findDepths folded (the `dpT`-style
concrete-`nm` computation) — into a determined concatenation:

  `decomposePoint.ops ++ fieldSqrYInc ++ [.over] ++ fieldSqrXInc ++ fieldMulSwapInc`
  `  ++ [.push (.bigint 7)] ++ fieldAddSwap2Inc ++ [.swap, .swap, .opcode "OP_EQUAL"]`

Each field-helper increment matches the Part-12 determined increments at its concrete
codegen depths (`fieldSqrY`: copy 0 / toTops 1,1 / prod 0; `fieldSqrX`: copy 2 /
toTops 3,1 / prod 0; `fieldMul`: toTops 0,1 / prod 0; `fieldAdd`: toTops 1,1 / sum 0).
This is the OUTPUT-PRESERVING op-list bridge the runtime threading runs over. -/

/-- The `emitEcOnCurve` tracker chain (named so the per-helper findDepths fold). -/
def eocT1 : Ec.Tracker := Ec.decomposePoint (Ec.Tracker.init [some "_pt"]) "_pt" "_x" "_y"
def eocT2 : Ec.Tracker := Ec.fieldSqr eocT1 "_y" "_y2"
def eocT3 : Ec.Tracker := eocT2.copyToTop "_x" "_x_copy"
def eocT4 : Ec.Tracker := Ec.fieldSqr eocT3 "_x" "_x2"
def eocT5 : Ec.Tracker := Ec.fieldMul eocT4 "_x2" "_x_copy" "_x3"
def eocT6 : Ec.Tracker := eocT5.pushInt "_seven" 7
def eocT7 : Ec.Tracker := Ec.fieldAdd eocT6 "_x3" "_seven" "_rhs"
def eocT8 : Ec.Tracker := eocT7.toTop "_y2"
def eocT9 : Ec.Tracker := eocT8.toTop "_rhs"

/-- **`toTop` nm in the canonical erase-push form**, given the codegen depth (folded
via the wave-77 bridge).  Pure restatement of `roll_nm_canonical` at `t.findDepth`. -/
theorem toTop_nm_canonical (t : Ec.Tracker) (name : String) (d : Nat)
    (hfd : t.findDepth name = d) (hd : d < t.nm.size) :
    (t.toTop name).nm
      = (t.nm.eraseIdxIfInBounds (t.nm.size - 1 - d)).push (t.nm[t.nm.size - 1 - d]!) := by
  unfold Ec.Tracker.toTop; rw [hfd]; exact roll_nm_canonical t d hd

/-- **`rawBlock 2 (some n)` nm.**  Pops two slots, pushes `some n`.  Reduces the
`Id.run`/`forIn [0:2]` pop-loop. -/
theorem rawBlock_nm_some2 (t : Ec.Tracker) (n : String) (e : List StackOp) :
    (t.rawBlock 2 (some n) e).nm = t.nm.pop.pop.push (some n) := by
  unfold Ec.Tracker.rawBlock; simp [Id.run]; rfl

/-- `pushInt` nm: pushes `some n` (ops-irrelevant). -/
theorem pushInt_nm (t : Ec.Tracker) (n : String) (v : Int) :
    (t.pushInt n v).nm = t.nm.push (some n) := by
  unfold Ec.Tracker.pushInt; rfl

/-- `pushFieldP` nm: pushes `some n`. -/
theorem pushFieldP_nm (t : Ec.Tracker) (n : String) :
    (Ec.pushFieldP t n).nm = t.nm.push (some n) := by
  unfold Ec.pushFieldP; exact pushInt_nm t n Ec.fieldP

/-- **`fieldMod t a r` nm** in terms of input nm + the `toTop a` depth.  `toTop a`
(roll-canonical) → `pushFieldP` (push) → `rawBlock 2 (some r)` (pop2-push1). -/
theorem fieldMod_nm (t : Ec.Tracker) (a r : String) (da : Nat)
    (hfd : t.findDepth a = da) (hd : da < t.nm.size) :
    (Ec.fieldMod t a r).nm
      = ((((t.nm.eraseIdxIfInBounds (t.nm.size - 1 - da)).push (t.nm[t.nm.size - 1 - da]!)).push
          (some "_fmod_p")).pop.pop).push (some r) := by
  unfold Ec.fieldMod
  rw [rawBlock_nm_some2, pushFieldP_nm, toTop_nm_canonical t a da hfd hd]

theorem eocT1_nm : eocT1.nm = #[some "_x", some "_y"] := decomposePoint_final_nm
/-- **Generic `fieldMul`/`fieldSqr`-inner nm transport.**  Given an entry tracker `t`
with `_x2 := aName` at depth `da` and `_x_copy := bName` at depth `db` against the
post-first-`toTop` tracker, and the product/result depths 0, the produced `nm` is the
chained roll/rawBlock form.  We instead prove the four chain instances inline below to
keep the depth folds concrete (no `set`/Mathlib). -/
theorem eocT2_nm : eocT2.nm = #[some "_x", some "_y2"] := by
  show (Ec.fieldSqr eocT1 "_y" "_y2").nm = _
  unfold Ec.fieldSqr
  show (Ec.fieldMul (eocT1.copyToTop "_y" "_fsqr_copy") "_y" "_fsqr_copy" "_y2").nm = _
  have hc_nm : (eocT1.copyToTop "_y" "_fsqr_copy").nm = #[some "_x", some "_y", some "_fsqr_copy"] := by
    rw [Ec.Tracker.copyToTop, pick_nm_push, eocT1_nm]; apply Array.ext' <;> simp
  unfold Ec.fieldMul
  have hm1_nm : ((eocT1.copyToTop "_y" "_fsqr_copy").toTop "_y").nm
      = #[some "_x", some "_fsqr_copy", some "_y"] := by
    rw [toTop_nm_canonical _ "_y" 1
          (by rw [findDepth_eq_findDepthList _ _ (by rw [hc_nm]; decide)]; rw [hc_nm]; decide)
          (by rw [hc_nm]; decide), hc_nm]; apply Array.ext' <;> simp
  have hm2_nm : (((eocT1.copyToTop "_y" "_fsqr_copy").toTop "_y").toTop "_fsqr_copy").nm
      = #[some "_x", some "_y", some "_fsqr_copy"] := by
    rw [toTop_nm_canonical _ "_fsqr_copy" 1
          (by rw [findDepth_eq_findDepthList _ _ (by rw [hm1_nm]; decide)]; rw [hm1_nm]; decide)
          (by rw [hm1_nm]; decide), hm1_nm]; apply Array.ext' <;> simp
  have hm3_nm : ((((eocT1.copyToTop "_y" "_fsqr_copy").toTop "_y").toTop "_fsqr_copy").rawBlock 2
        (some "_fmul_prod") [.opcode "OP_MUL"]).nm = #[some "_x", some "_fmul_prod"] := by
    rw [rawBlock_nm_some2, hm2_nm]; apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fmul_prod" "_y2" 0
        (by rw [findDepth_eq_findDepthList _ _ (by rw [hm3_nm]; decide)]; rw [hm3_nm]; decide)
        (by rw [hm3_nm]; decide), hm3_nm]
  apply Array.ext' <;> simp
theorem eocT3_nm : eocT3.nm = #[some "_x", some "_y2", some "_x_copy"] := by
  show (eocT2.copyToTop "_x" "_x_copy").nm = _; rw [Ec.Tracker.copyToTop, pick_nm_push, eocT2_nm]; apply Array.ext' <;> simp
theorem eocT4_nm : eocT4.nm = #[some "_y2", some "_x_copy", some "_x2"] := by
  show (Ec.fieldSqr eocT3 "_x" "_x2").nm = _
  unfold Ec.fieldSqr
  show (Ec.fieldMul (eocT3.copyToTop "_x" "_fsqr_copy") "_x" "_fsqr_copy" "_x2").nm = _
  have hc_nm : (eocT3.copyToTop "_x" "_fsqr_copy").nm
      = #[some "_x", some "_y2", some "_x_copy", some "_fsqr_copy"] := by
    rw [Ec.Tracker.copyToTop, pick_nm_push, eocT3_nm]; apply Array.ext' <;> simp
  unfold Ec.fieldMul
  have hm1_nm : ((eocT3.copyToTop "_x" "_fsqr_copy").toTop "_x").nm
      = #[some "_y2", some "_x_copy", some "_fsqr_copy", some "_x"] := by
    rw [toTop_nm_canonical _ "_x" 3
          (by rw [findDepth_eq_findDepthList _ _ (by rw [hc_nm]; decide)]; rw [hc_nm]; decide)
          (by rw [hc_nm]; decide), hc_nm]; apply Array.ext' <;> simp
  have hm2_nm : (((eocT3.copyToTop "_x" "_fsqr_copy").toTop "_x").toTop "_fsqr_copy").nm
      = #[some "_y2", some "_x_copy", some "_x", some "_fsqr_copy"] := by
    rw [toTop_nm_canonical _ "_fsqr_copy" 1
          (by rw [findDepth_eq_findDepthList _ _ (by rw [hm1_nm]; decide)]; rw [hm1_nm]; decide)
          (by rw [hm1_nm]; decide), hm1_nm]; apply Array.ext' <;> simp
  have hm3_nm : ((((eocT3.copyToTop "_x" "_fsqr_copy").toTop "_x").toTop "_fsqr_copy").rawBlock 2
        (some "_fmul_prod") [.opcode "OP_MUL"]).nm = #[some "_y2", some "_x_copy", some "_fmul_prod"] := by
    rw [rawBlock_nm_some2, hm2_nm]; apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fmul_prod" "_x2" 0
        (by rw [findDepth_eq_findDepthList _ _ (by rw [hm3_nm]; decide)]; rw [hm3_nm]; decide)
        (by rw [hm3_nm]; decide), hm3_nm]
  apply Array.ext' <;> simp
theorem eocT5_nm : eocT5.nm = #[some "_y2", some "_x3"] := by
  show (Ec.fieldMul eocT4 "_x2" "_x_copy" "_x3").nm = _
  unfold Ec.fieldMul
  have hm1_nm : (eocT4.toTop "_x2").nm = #[some "_y2", some "_x_copy", some "_x2"] := by
    rw [toTop_nm_canonical eocT4 "_x2" 0
          (by rw [findDepth_eq_findDepthList _ _ (by rw [eocT4_nm]; decide)]; rw [eocT4_nm]; decide)
          (by rw [eocT4_nm]; decide), eocT4_nm]; apply Array.ext' <;> simp
  have hm2_nm : ((eocT4.toTop "_x2").toTop "_x_copy").nm = #[some "_y2", some "_x2", some "_x_copy"] := by
    rw [toTop_nm_canonical _ "_x_copy" 1
          (by rw [findDepth_eq_findDepthList _ _ (by rw [hm1_nm]; decide)]; rw [hm1_nm]; decide)
          (by rw [hm1_nm]; decide), hm1_nm]; apply Array.ext' <;> simp
  have hm3_nm : (((eocT4.toTop "_x2").toTop "_x_copy").rawBlock 2 (some "_fmul_prod")
        [.opcode "OP_MUL"]).nm = #[some "_y2", some "_fmul_prod"] := by
    rw [rawBlock_nm_some2, hm2_nm]; apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fmul_prod" "_x3" 0
        (by rw [findDepth_eq_findDepthList _ _ (by rw [hm3_nm]; decide)]; rw [hm3_nm]; decide)
        (by rw [hm3_nm]; decide), hm3_nm]
  apply Array.ext' <;> simp
theorem eocT6_nm : eocT6.nm = #[some "_y2", some "_x3", some "_seven"] := by
  show (eocT5.pushInt "_seven" 7).nm = _
  rw [pushInt_nm, eocT5_nm]; apply Array.ext' <;> simp
theorem eocT7_nm : eocT7.nm = #[some "_y2", some "_rhs"] := by
  show (Ec.fieldAdd eocT6 "_x3" "_seven" "_rhs").nm = _
  unfold Ec.fieldAdd
  have hm1_nm : (eocT6.toTop "_x3").nm = #[some "_y2", some "_seven", some "_x3"] := by
    rw [toTop_nm_canonical eocT6 "_x3" 1
          (by rw [findDepth_eq_findDepthList _ _ (by rw [eocT6_nm]; decide)]; rw [eocT6_nm]; decide)
          (by rw [eocT6_nm]; decide), eocT6_nm]; apply Array.ext' <;> simp
  have hm2_nm : ((eocT6.toTop "_x3").toTop "_seven").nm = #[some "_y2", some "_x3", some "_seven"] := by
    rw [toTop_nm_canonical _ "_seven" 1
          (by rw [findDepth_eq_findDepthList _ _ (by rw [hm1_nm]; decide)]; rw [hm1_nm]; decide)
          (by rw [hm1_nm]; decide), hm1_nm]; apply Array.ext' <;> simp
  have hm3_nm : (((eocT6.toTop "_x3").toTop "_seven").rawBlock 2 (some "_fadd_sum")
        [.opcode "OP_ADD"]).nm = #[some "_y2", some "_fadd_sum"] := by
    rw [rawBlock_nm_some2, hm2_nm]; apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fadd_sum" "_rhs" 0
        (by rw [findDepth_eq_findDepthList _ _ (by rw [hm3_nm]; decide)]; rw [hm3_nm]; decide)
        (by rw [hm3_nm]; decide), hm3_nm]
  apply Array.ext' <;> simp
theorem eocT8_nm : eocT8.nm = #[some "_rhs", some "_y2"] := by
  show (eocT7.toTop "_y2").nm = _
  rw [show eocT7.toTop "_y2" = eocT7.roll 1 from by
        rw [Ec.Tracker.toTop, show eocT7.findDepth "_y2" = 1 from by
          rw [findDepth_eq_findDepthList _ _ (by rw [eocT7_nm]; decide)]; rw [eocT7_nm]; decide]]
  show (eocT7.swap).nm = _
  rw [swap_nm_ge2 eocT7 (by rw [eocT7_nm]; decide), eocT7_nm]; rfl

/-! ### `emitEcOnCurve` op-list = the determined concatenation (deliverable 3) -/

/-- **`fieldMod t a r` ops-append at a concrete `toTop a` depth.**  Folds
`fieldMod_ops_append`'s `rollExtraOps (findDepth a)` to the concrete `rollExtraOps da`
once `t.findDepth a = da` (wave-77 bridge). -/
theorem fieldMod_ops_concrete (t : Ec.Tracker) (a r : String) (da : Nat)
    (hfd : t.findDepth a = da) :
    (Ec.fieldMod t a r).ops.toList
      = t.ops.toList ++ rollExtraOps da ++ [.push (.bigint Ec.fieldP)] ++ Ec.fieldModOps := by
  rw [fieldMod_ops_append, hfd]

/-- **`fieldMul t a b r` ops-append at concrete depths.**  Folds the three nested
`rollExtraOps (findDepth …)` of `fieldMul_ops_append` to concrete depths (`da` for
`toTop a` against `t`, `db` for `toTop b` against `t.toTop a`, `dp` for `toTop _fmul_prod`
against the post-rawBlock tracker). -/
theorem fieldMul_ops_concrete (t : Ec.Tracker) (a b r : String) (da db dp : Nat)
    (hda : t.findDepth a = da) (hdb : (t.toTop a).findDepth b = db)
    (hdp : (((t.toTop a).toTop b).rawBlock 2 (some "_fmul_prod") [.opcode "OP_MUL"]).findDepth "_fmul_prod" = dp) :
    (Ec.fieldMul t a b r).ops.toList
      = t.ops.toList ++ rollExtraOps da ++ rollExtraOps db ++ [.opcode "OP_MUL"]
        ++ rollExtraOps dp ++ [.push (.bigint Ec.fieldP)] ++ Ec.fieldModOps := by
  rw [fieldMul_ops_append, hda, hdb, hdp]

/-- **`fieldAdd t a b r` ops-append at concrete depths.**  Peer of `fieldMul_ops_concrete`
at `OP_ADD` / `_fadd_sum`. -/
theorem fieldAdd_ops_concrete (t : Ec.Tracker) (a b r : String) (da db dp : Nat)
    (hda : t.findDepth a = da) (hdb : (t.toTop a).findDepth b = db)
    (hdp : (((t.toTop a).toTop b).rawBlock 2 (some "_fadd_sum") [.opcode "OP_ADD"]).findDepth "_fadd_sum" = dp) :
    (Ec.fieldAdd t a b r).ops.toList
      = t.ops.toList ++ rollExtraOps da ++ rollExtraOps db ++ [.opcode "OP_ADD"]
        ++ rollExtraOps dp ++ [.push (.bigint Ec.fieldP)] ++ Ec.fieldModOps := by
  rw [fieldAdd_ops_append, hda, hdb, hdp]

/-- **`copyToTop` ops-append at a concrete depth.** -/
theorem copyToTop_ops_concrete (t : Ec.Tracker) (name newName : String) (d : Nat)
    (hfd : t.findDepth name = d) :
    (t.copyToTop name newName).ops.toList = t.ops.toList ++ pickExtraOps d := by
  rw [copyToTop_ops_append, hfd]

/-- **`toTop` ops-append at a concrete depth.** -/
theorem toTop_ops_concrete (t : Ec.Tracker) (name : String) (d : Nat)
    (hfd : t.findDepth name = d) :
    (t.toTop name).ops.toList = t.ops.toList ++ rollExtraOps d := by
  rw [toTop_ops_append, hfd]

/-- Depth helper: `t.findDepth name = d` from a concrete `nm` (wave-77 bridge). -/
private theorem fd_of_nm (t : Ec.Tracker) (name : String) (d : Nat) (nm : Array (Option String))
    (hnm : t.nm = nm) (hmem : some name ∈ nm.toList.reverse)
    (hd : findDepthList name nm.toList.reverse = d) :
    t.findDepth name = d := by
  rw [findDepth_eq_findDepthList _ _ (by rw [hnm]; exact hmem), hnm, hd]

/-- **`fieldSqr "_y" "_y2"` ops = `eocT1.ops ++ fieldSqrYInc`.**  fieldSqr = copyToTop
(depth 0) + fieldMul (`_y` depth 1, `_fsqr_copy` depth 1, prod depth 0). -/
theorem eocFieldSqrY_ops : eocT2.ops.toList = eocT1.ops.toList ++ fieldSqrYInc := by
  show (Ec.fieldSqr eocT1 "_y" "_y2").ops.toList = _
  unfold Ec.fieldSqr
  show (Ec.fieldMul (eocT1.copyToTop "_y" "_fsqr_copy") "_y" "_fsqr_copy" "_y2").ops.toList = _
  have hc_nm : (eocT1.copyToTop "_y" "_fsqr_copy").nm = #[some "_x", some "_y", some "_fsqr_copy"] := by
    rw [Ec.Tracker.copyToTop, pick_nm_push, eocT1_nm]; rfl
  have hc_ops : (eocT1.copyToTop "_y" "_fsqr_copy").ops.toList = eocT1.ops.toList ++ pickExtraOps 0 :=
    copyToTop_ops_concrete eocT1 "_y" "_fsqr_copy" 0
      (fd_of_nm eocT1 "_y" 0 _ eocT1_nm (by decide) (by decide))
  have hm1_nm : ((eocT1.copyToTop "_y" "_fsqr_copy").toTop "_y").nm
      = #[some "_x", some "_fsqr_copy", some "_y"] := by
    rw [toTop_nm_canonical _ "_y" 1
          (fd_of_nm _ "_y" 1 _ hc_nm (by decide) (by decide)) (by rw [hc_nm]; decide), hc_nm]
    apply Array.ext' <;> simp
  have hm2_nm : ((((eocT1.copyToTop "_y" "_fsqr_copy").toTop "_y").toTop "_fsqr_copy").rawBlock 2
        (some "_fmul_prod") [.opcode "OP_MUL"]).nm = #[some "_x", some "_fmul_prod"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_fsqr_copy" 1
          (fd_of_nm _ "_fsqr_copy" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide),
        hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldMul_ops_concrete (eocT1.copyToTop "_y" "_fsqr_copy") "_y" "_fsqr_copy" "_y2" 1 1 0
        (fd_of_nm _ "_y" 1 _ hc_nm (by decide) (by decide))
        (fd_of_nm _ "_fsqr_copy" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fmul_prod" 0 _ hm2_nm (by decide) (by decide))]
  rw [hc_ops]
  simp only [fieldSqrYInc, rollExtraOps, pickExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- **`fieldSqr "_x" "_x2"` ops = `eocT3.ops ++ fieldSqrXInc`.**  copyToTop depth 2,
fieldMul (`_x` depth 3, `_fsqr_copy` depth 1, prod depth 0). -/
theorem eocFieldSqrX_ops : eocT4.ops.toList = eocT3.ops.toList ++ fieldSqrXInc := by
  show (Ec.fieldSqr eocT3 "_x" "_x2").ops.toList = _
  unfold Ec.fieldSqr
  show (Ec.fieldMul (eocT3.copyToTop "_x" "_fsqr_copy") "_x" "_fsqr_copy" "_x2").ops.toList = _
  have hc_nm : (eocT3.copyToTop "_x" "_fsqr_copy").nm
      = #[some "_x", some "_y2", some "_x_copy", some "_fsqr_copy"] := by
    rw [Ec.Tracker.copyToTop, pick_nm_push, eocT3_nm]; rfl
  have hc_ops : (eocT3.copyToTop "_x" "_fsqr_copy").ops.toList = eocT3.ops.toList ++ pickExtraOps 2 :=
    copyToTop_ops_concrete eocT3 "_x" "_fsqr_copy" 2
      (fd_of_nm eocT3 "_x" 2 _ eocT3_nm (by decide) (by decide))
  have hm1_nm : ((eocT3.copyToTop "_x" "_fsqr_copy").toTop "_x").nm
      = #[some "_y2", some "_x_copy", some "_fsqr_copy", some "_x"] := by
    rw [toTop_nm_canonical _ "_x" 3
          (fd_of_nm _ "_x" 3 _ hc_nm (by decide) (by decide)) (by rw [hc_nm]; decide), hc_nm]
    apply Array.ext' <;> simp
  have hm2_nm : ((((eocT3.copyToTop "_x" "_fsqr_copy").toTop "_x").toTop "_fsqr_copy").rawBlock 2
        (some "_fmul_prod") [.opcode "OP_MUL"]).nm = #[some "_y2", some "_x_copy", some "_fmul_prod"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_fsqr_copy" 1
          (fd_of_nm _ "_fsqr_copy" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide),
        hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldMul_ops_concrete (eocT3.copyToTop "_x" "_fsqr_copy") "_x" "_fsqr_copy" "_x2" 3 1 0
        (fd_of_nm _ "_x" 3 _ hc_nm (by decide) (by decide))
        (fd_of_nm _ "_fsqr_copy" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fmul_prod" 0 _ hm2_nm (by decide) (by decide))]
  rw [hc_ops]
  simp only [fieldSqrXInc, rollExtraOps, pickExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- **`fieldMul "_x2" "_x_copy" "_x3"` ops = `eocT4.ops ++ fieldMulSwapInc`.**  toTop
`_x2` depth 0, `_x_copy` depth 1, prod depth 0. -/
theorem eocFieldMul_ops : eocT5.ops.toList = eocT4.ops.toList ++ fieldMulSwapInc := by
  show (Ec.fieldMul eocT4 "_x2" "_x_copy" "_x3").ops.toList = _
  have hm1_nm : (eocT4.toTop "_x2").nm = #[some "_y2", some "_x_copy", some "_x2"] := by
    rw [toTop_nm_canonical eocT4 "_x2" 0
          (fd_of_nm eocT4 "_x2" 0 _ eocT4_nm (by decide) (by decide)) (by rw [eocT4_nm]; decide), eocT4_nm]
    apply Array.ext' <;> simp
  have hm2_nm : (((eocT4.toTop "_x2").toTop "_x_copy").rawBlock 2 (some "_fmul_prod")
        [.opcode "OP_MUL"]).nm = #[some "_y2", some "_fmul_prod"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_x_copy" 1
          (fd_of_nm _ "_x_copy" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide),
        hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldMul_ops_concrete eocT4 "_x2" "_x_copy" "_x3" 0 1 0
        (fd_of_nm eocT4 "_x2" 0 _ eocT4_nm (by decide) (by decide))
        (fd_of_nm _ "_x_copy" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fmul_prod" 0 _ hm2_nm (by decide) (by decide))]
  simp only [fieldMulSwapInc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- **`fieldAdd "_x3" "_seven" "_rhs"` ops = `eocT6.ops ++ fieldAddSwap2Inc`.**  toTop
`_x3` depth 1, `_seven` depth 1, sum depth 0. -/
theorem eocFieldAdd_ops : eocT7.ops.toList = eocT6.ops.toList ++ fieldAddSwap2Inc := by
  show (Ec.fieldAdd eocT6 "_x3" "_seven" "_rhs").ops.toList = _
  have hm1_nm : (eocT6.toTop "_x3").nm = #[some "_y2", some "_seven", some "_x3"] := by
    rw [toTop_nm_canonical eocT6 "_x3" 1
          (fd_of_nm eocT6 "_x3" 1 _ eocT6_nm (by decide) (by decide)) (by rw [eocT6_nm]; decide), eocT6_nm]
    apply Array.ext' <;> simp
  have hm2_nm : (((eocT6.toTop "_x3").toTop "_seven").rawBlock 2 (some "_fadd_sum")
        [.opcode "OP_ADD"]).nm = #[some "_y2", some "_fadd_sum"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_seven" 1
          (fd_of_nm _ "_seven" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide),
        hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldAdd_ops_concrete eocT6 "_x3" "_seven" "_rhs" 1 1 0
        (fd_of_nm eocT6 "_x3" 1 _ eocT6_nm (by decide) (by decide))
        (fd_of_nm _ "_seven" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fadd_sum" 0 _ hm2_nm (by decide) (by decide))]
  simp only [fieldAddSwap2Inc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- **The determined `emitEcOnCurve` op-list.** -/
def expectedEcOnCurve : List StackOp :=
  eocT1.ops.toList ++ fieldSqrYInc ++ [.over]
    ++ fieldSqrXInc ++ fieldMulSwapInc ++ [.push (.bigint 7)]
    ++ fieldAddSwap2Inc ++ [.swap, .swap, .opcode "OP_EQUAL"]

/-- **`emitEcOnCurve` op-list = the determined concatenation (deliverable 3).**  Threads
the 10 per-helper ops-append leaves (`eocFieldSqrY/X_ops`, `eocFieldMul/Add_ops`,
copyToTop/pushInt/toTop/rawBlock) through the tracker chain, each depth folded via the
wave-77 bridge.  OUTPUT-PRESERVING. -/
theorem emitEcOnCurve_ops : Ec.emitEcOnCurve = expectedEcOnCurve := by
  show (eocT9.rawBlock 2 (some "_result") [.opcode "OP_EQUAL"]).ops.toList = _
  rw [rawBlock_ops_append]
  show eocT9.ops.toList ++ [.opcode "OP_EQUAL"] = _
  show (eocT8.toTop "_rhs").ops.toList ++ [.opcode "OP_EQUAL"] = _
  rw [toTop_ops_concrete eocT8 "_rhs" 1 (fd_of_nm eocT8 "_rhs" 1 _ eocT8_nm (by decide) (by decide))]
  show (eocT7.toTop "_y2").ops.toList ++ rollExtraOps 1 ++ [.opcode "OP_EQUAL"] = _
  rw [toTop_ops_concrete eocT7 "_y2" 1 (fd_of_nm eocT7 "_y2" 1 _ eocT7_nm (by decide) (by decide))]
  rw [eocFieldAdd_ops]
  show (eocT5.pushInt "_seven" 7).ops.toList ++ fieldAddSwap2Inc ++ rollExtraOps 1 ++ rollExtraOps 1
        ++ [.opcode "OP_EQUAL"] = _
  rw [pushInt_ops_append, eocFieldMul_ops, eocFieldSqrX_ops]
  show (eocT2.copyToTop "_x" "_x_copy").ops.toList ++ fieldSqrXInc ++ fieldMulSwapInc
        ++ [.push (.bigint 7)] ++ fieldAddSwap2Inc ++ rollExtraOps 1 ++ rollExtraOps 1
        ++ [.opcode "OP_EQUAL"] = _
  rw [copyToTop_ops_concrete eocT2 "_x" "_x_copy" 1 (fd_of_nm eocT2 "_x" 1 _ eocT2_nm (by decide) (by decide))]
  rw [eocFieldSqrY_ops]
  simp only [expectedEcOnCurve, pickExtraOps, rollExtraOps, List.append_assoc, List.cons_append,
    List.nil_append, List.singleton_append]

/-! ### `emitEcOnCurve` runtime threading + the discharge (deliverable 3) -/

private theorem niOver2 : ∀ t e, StackOp.over ≠ .ifOp t e := by intro t e h; cases h
private theorem niPush3 : ∀ (v : PushVal) t e, StackOp.push v ≠ .ifOp t e := by intro v t e h; cases h
private theorem niEqual : ∀ t e, StackOp.opcode "OP_EQUAL" ≠ .ifOp t e := by intro t e h; cases h

/-- `asBytes?` of a NON-zero `vBigint` is `none` (the only `vBigint`→bytes coercion is
the zero literal `OP_0`). -/
private theorem asBytes_vBigint_ne_zero (k : Int) (hk : k ≠ 0) : asBytes? (.vBigint k) = none := by
  unfold asBytes?
  split <;> first | rfl | (rename_i h; simp at h; omega) | (rename_i h; exact absurd h (by simp))

/-- **The final `OP_EQUAL` transport.**  On `[rhs, y2] ++ rest` (rhs on TOS),
`OP_EQUAL` lands `vBool (decide (y2 = rhs)) :: rest`, the script-bool peer of the
spec's `decide (lhs = rhs)`. -/
theorem opEqual_int_transport (s : StackState) (y2 rhs : Int) (rest : List Value)
    (hStk : s.stack = (.vBigint rhs) :: (.vBigint y2) :: rest) :
    runOpcode "OP_EQUAL" s = .ok { s with stack := .vBool (decide (y2 = rhs)) :: rest } := by
  -- `asBytes? (vBigint k) = if k = 0 then some [] else none`, so case-split at 0:
  -- every branch lands `decide (y2 = rhs)` (the bytes path only fires when both = 0,
  -- where `decide ([] = []) = decide (0 = 0) = true`).
  simp only [runOpcode, popN_two_bigint_local s y2 rhs rest hStk]
  by_cases hy : y2 = 0 <;> by_cases hr : rhs = 0
  · subst hy; subst hr; simp only [asBytes?, StackState.push]
  · subst hy
    rw [show asBytes? (Value.vBigint rhs) = none from asBytes_vBigint_ne_zero rhs hr]
    simp only [asBytes?, asInt?, StackState.push]
  · subst hr
    rw [show asBytes? (Value.vBigint y2) = none from asBytes_vBigint_ne_zero y2 hy]
    simp only [asBytes?, asInt?, StackState.push]
  · rw [show asBytes? (Value.vBigint y2) = none from asBytes_vBigint_ne_zero y2 hy,
        show asBytes? (Value.vBigint rhs) = none from asBytes_vBigint_ne_zero rhs hr]
    simp only [asInt?, StackState.push]

set_option maxRecDepth 4096 in
/-- **`emitEcOnCurve` runtime transport (deliverable 3).**  Running the determined
op-list on `[pt] ++ rest` threads the base `decomposePoint_runOps` + the four
per-field-helper sims (`fieldSqr`/`fieldSqrX`/`fieldMul`/`fieldAdd`) + the `over`/
`push 7`/`swap`/`swap`/`OP_EQUAL` glue, landing `vBool (ecOnCurve pt) :: rest`.  The wf
hypotheses are the INPUT-side `decomposePoint` decode bridges (the same `emitEcPointX/Y`
carry).  `propext`/`Quot.sound`-clean + inherited backend opaques, NO new axiom. -/
theorem emitEcOnCurve_runOps_eq (stkSt : StackState) (pt : ByteArray) (rest : List Value)
    (hStk : stkSt.stack = .vBytes pt :: rest) (hSize : 64 ≤ pt.size)
    (hDecX : decodeMinimalLE
              (reverseAcc 32 (pt.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointX pt)
    (hDecY : decodeMinimalLE
              (reverseAcc 32 (pt.extract 32 pt.size) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointY pt) :
    runOps Ec.emitEcOnCurve stkSt
      = .ok { stkSt with stack := .vBool (RunarVerification.ANF.Eval.Crypto.ecOnCurve pt) :: rest } := by
  rw [emitEcOnCurve_ops]
  unfold expectedEcOnCurve
  -- right-associate the op-list so `runOps_append` peels each chunk from the left;
  -- single-op chunks (`[.over]`, `[.push 7]`) collapse to `cons` for the step transports
  simp only [List.append_assoc, List.cons_append, List.nil_append]
  have hbase : runOps eocT1.ops.toList stkSt
      = .ok { stkSt with stack := .vBigint (Crypto.Secp256k1.pointY pt)
                :: .vBigint (Crypto.Secp256k1.pointX pt) :: rest } :=
    decomposePoint_runOps stkSt pt rest hStk hSize hDecX hDecY
  -- base: decomposePoint → [(Crypto.Secp256k1.pointY pt), (Crypto.Secp256k1.pointX pt)] ++ rest
  rw [runOps_append, hbase]
  simp only [match_Except_ok_runOps]
  -- fieldSqr "_y" → [Y², (Crypto.Secp256k1.pointX pt)] ++ rest
  rw [runOps_append]
  rw [fieldSqr_runOps_sim { stkSt with stack := .vBigint (Crypto.Secp256k1.pointY pt) :: .vBigint (Crypto.Secp256k1.pointX pt) :: rest } (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointX pt) rest rfl]
  simp only [match_Except_ok_runOps]
  -- over (copyToTop "_x") → [(Crypto.Secp256k1.pointX pt), Y², (Crypto.Secp256k1.pointX pt)] ++ rest
  rw [runOps_cons_nonIf_eq _ _ _ niOver2,
      show stepNonIf .over { stkSt with stack := (.vBigint (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointY pt)))
            :: (.vBigint (Crypto.Secp256k1.pointX pt)) :: rest }
        = applyOver { stkSt with stack := (.vBigint (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointY pt)))
            :: (.vBigint (Crypto.Secp256k1.pointX pt)) :: rest } from rfl]
  rw [show applyOver { stkSt with stack := (.vBigint (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointY pt)))
            :: (.vBigint (Crypto.Secp256k1.pointX pt)) :: rest }
        = .ok { stkSt with stack := (.vBigint (Crypto.Secp256k1.pointX pt)) :: (.vBigint (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointY pt)))
            :: (.vBigint (Crypto.Secp256k1.pointX pt)) :: rest } from rfl]
  simp only [match_Except_ok_runOps]
  -- fieldSqr "_x" → [X², (Crypto.Secp256k1.pointX pt), Y²] ++ rest
  rw [runOps_append, fieldSqrX_runOps_sim _ (Crypto.Secp256k1.pointX pt) (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointY pt)) rest rfl]
  simp only [match_Except_ok_runOps]
  -- fieldMul "_x2" "_x_copy" → [X³, Y²] ++ rest
  rw [runOps_append, fieldMul_runOps_sim _ (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointX pt) (Crypto.Secp256k1.pointX pt)) (Crypto.Secp256k1.pointX pt)
        (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointY pt)) rest rfl]
  simp only [match_Except_ok_runOps]
  -- push 7 → [7, X³, Y²] ++ rest
  rw [runOps_cons_nonIf_eq _ _ _ (niPush3 (.bigint 7)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- fieldAdd "_x3" "_seven" → [RHS, Y²] ++ rest
  rw [runOps_append, fieldAdd_runOps_sim _ 7 (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointX pt) (Crypto.Secp256k1.pointX pt)) (Crypto.Secp256k1.pointX pt))
        (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointY pt)) rest rfl]
  simp only [match_Except_ok_runOps]
  -- swap, swap, OP_EQUAL
  rw [runOps_cons_nonIf_eq _ _ _ niSwap2, stepNonIf_swap]
  rw [show applySwap { stkSt with stack := (.vBigint (Crypto.Secp256k1.fieldAdd
            (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointX pt) (Crypto.Secp256k1.pointX pt)) (Crypto.Secp256k1.pointX pt)) 7))
            :: (.vBigint (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointY pt))) :: rest }
        = .ok { stkSt with stack := (.vBigint (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointY pt)))
            :: (.vBigint (Crypto.Secp256k1.fieldAdd
                 (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointX pt) (Crypto.Secp256k1.pointX pt)) (Crypto.Secp256k1.pointX pt)) 7)) :: rest } from rfl]
  simp only [match_Except_ok_runOps]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap2, stepNonIf_swap]
  rw [show applySwap { stkSt with stack := (.vBigint (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointY pt)))
            :: (.vBigint (Crypto.Secp256k1.fieldAdd
                 (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointX pt) (Crypto.Secp256k1.pointX pt)) (Crypto.Secp256k1.pointX pt)) 7)) :: rest }
        = .ok { stkSt with stack := (.vBigint (Crypto.Secp256k1.fieldAdd
                 (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointX pt) (Crypto.Secp256k1.pointX pt)) (Crypto.Secp256k1.pointX pt)) 7))
            :: (.vBigint (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointY pt))) :: rest } from rfl]
  simp only [match_Except_ok_runOps]
  rw [runOps_cons_nonIf_eq _ _ _ niEqual, stepNonIf_opcode]
  rw [opEqual_int_transport _ (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointY pt))
        (Crypto.Secp256k1.fieldAdd (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.pointX pt) (Crypto.Secp256k1.pointX pt)) (Crypto.Secp256k1.pointX pt)) 7)
        rest rfl]
  -- the script-bool `decide (y2 = rhs)` IS `Crypto.ecOnCurve pt` (= `decide (lhs = rhs)`)
  -- definitionally (`ecOnCurve = Secp256k1.ecOnCurve`, `lhs = fieldMul y y`,
  -- `rhs = fieldAdd (fieldMul (fieldMul x x) x) 7`).
  simp only [match_Except_ok_runOps, runOps_nil]
  rfl

/-! ### MANDATORY smoke for the `emitEcOnCurve` discharge (deliverable 3) -/

/-- SMOKE (wf anti-vacuity).  The three INPUT wf hypotheses (`64 ≤ size` + the two
decode bridges) hold concretely for `makePoint 11 22` — rules out a vacuous discharge. -/
theorem smoke_emitEcOnCurve_wf_satisfiable :
    (64 : Nat) ≤ smokeDpPt.size
      ∧ decodeMinimalLE (reverseAcc 32 (smokeDpPt.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
          = Crypto.Secp256k1.pointX smokeDpPt
      ∧ decodeMinimalLE (reverseAcc 32 (smokeDpPt.extract 32 smokeDpPt.size) ByteArray.empty ++ ByteArray.mk #[0x00])
          = Crypto.Secp256k1.pointY smokeDpPt := by
  native_decide

/-- Concrete entry state for the discharge smoke: `[makePoint 11 22, 999]`. -/
private def smokeEocStk : StackState :=
  { (default : StackState) with stack := [.vBytes smokeDpPt, .vBigint 999] }

/-- SMOKE (the headline — discharge FIRES).  `emitEcOnCurve` on the concrete point
`makePoint 11 22` lands `vBool (ecOnCurve …) :: rest`, with `rest` preserved beneath. -/
theorem smoke_emitEcOnCurve_runOps_eq :
    runOps Ec.emitEcOnCurve smokeEocStk
      = .ok { smokeEocStk with
          stack := .vBool (RunarVerification.ANF.Eval.Crypto.ecOnCurve smokeDpPt) :: [.vBigint 999] } :=
  emitEcOnCurve_runOps_eq smokeEocStk smokeDpPt [.vBigint 999] rfl (by native_decide)
    (by native_decide) (by native_decide)

/-- SMOKE (value anti-vacuity).  `makePoint 11 22` is NOT on the curve
(`22² ≠ 11³ + 7 mod p`), so the discharge yields `vBool false` — a non-trivial result. -/
theorem smoke_emitEcOnCurve_value_concrete :
    RunarVerification.ANF.Eval.Crypto.ecOnCurve smokeDpPt = false := by native_decide

/-! ## Part 9 — BLOCKED `Crypto/Spec.lean §7` axioms: `ecNegate`, `ecOnCurve`

The remaining two "medium" EC ops are NOT plain op-lists.  Unlike `ecPointX/Y`
and `ecMakePoint` (whose only non-trivial sub-block is `emitReverse32Ops`), both
`emitEcNegate` and `emitEcOnCurve` are produced by RUNNING the `Stack.Ec.Tracker`
state machine: their op lists are `t.ops.toList` after a chain of
`decomposePoint` / `composePoint` / `fieldSub` / `fieldSqr` / `fieldMul` /
`fieldAdd`, each of which interleaves `t.toTop` / `t.copyToTop` operations that
emit `.roll d` / `.pickStruct d` whose depth `d = Tracker.findDepth name` is
computed at CODEGEN TIME against the threaded name array `nm`.

* `emitEcNegate`  : 945 ops — 257 `.rot`, 2 `OP_MOD` (one `fieldSub`, no
  `OP_MUL`), routed through two `emitReverse32Ops` blocks in `decompose`/`compose`.
* `emitEcOnCurve` : 518 ops — 1 `.roll`, 1 `.pickStruct`, 132 `.rot`, 8 `OP_MOD`,
  3 `OP_MUL` (two `fieldSqr`, one `fieldMul`, one `fieldAdd`) + a final `OP_EQUAL`.

**SUBSTRATE LANDED (Part 8).**  The Tracker-to-runtime simulation invariant
`TrackerSim` and its model substrate are now in place, all `sorry`-free /
axiom-clean:

  * `TrackerSim nm σ stk` — the runtime stack mirrors the tracker name array.
  * `findDepthList` — the kernel-reducible recursive model of `Tracker.findDepth`,
    with `findDepthList_lt`, `findDepthList_get`, `reverse_getElem_bridge`.
  * `findDepthList_sim` (KEYSTONE) — under `TrackerSim`, the runtime stack value at
    structural depth `findDepthList name (nm.toList.reverse)` is exactly `σ name`.
  * `TrackerSim_push` (push/rawBlock-produce preservation),
    `applyRoll_findDepth_sim` (`roll`/`toTop` preservation),
    `applyPick_findDepth_sim` (`pick`/`copyToTop` preservation).

**WAVE-76 BLOCKER CLEARED (wave-77).**  The wave-76 BLOCK was the kernel wall that
`Tracker.findDepth` was an `Id.run do … while …` (→ `Lean.Loop.forIn`, a
`partial def` with no equational lemma / no `.induct` / no kernel reduction), so
the bridge `Tracker.findDepth t name = findDepthList name t.nm.toList.reverse` was
unprovable without editing `Stack/Ec.lean`.  Wave-77 PERFORMS that sanctioned,
OUTPUT-PRESERVING refactor: `findDepth` is now a structural fold
(`(Ec.Tracker.findDepthAux name t.nm.toList.reverse).getD 0`), kernel-reducible,
computing byte-identical depths (verified: the EC conformance goldens
`convergence-proof`/`ec-demo`/`ec-primitives`/`ec-unit` recompile byte-exact via
the Lean `compileHex`; `schnorr-zkp` overflows the macOS 64 MB native stack in the
DOWNSTREAM peephole pass identically under both the old and new `findDepth`, i.e.
the overflow is pre-existing and independent of this change).  The bridge
`findDepth_eq_findDepthList` (above) is now proved by structural induction
(`findDepthAux_eq_findDepthList`), NOT `native_decide`, `propext`/`Quot.sound`-clean.

**LANDED WAVE-77 (the bridge + field-helper transports).**
  * The `findDepth` refactor (output-preserving) + the bridge.
  * The per-helper transports: `fieldModOps_transport`,
    `fieldBinop_optail_transport` + `fieldAdd/fieldSub/fieldMul_optail_transport`
    (each → `Crypto.Secp256k1.field*`, divisor `fieldP ≠ 0` via kernel `decide`),
    and `applyPickStruct_findDepth_sim` (the codegen-emitted-op peer of the
    substrate's `applyPick_findDepth_sim`).  All `propext`/`Quot.sound`-clean (plus
    the pre-existing `authBackend`/`hashBackend` opaques inherited via
    `ecModReduce_step_transport`), each with an anti-vacuity smoke.

**LANDED THIS WAVE (wave-78 — deliverables 1 & 2, the per-op assembly scaffolding).**
The two scaffolding pieces the wave-77 hand-off named as the remaining gap are now
in place above, all `propext`/`Quot.sound`-clean (plus the inherited
`authBackend`/`hashBackend` opaques on the `runOps`-bearing transports), each with
an anti-vacuity smoke:

  1. **`toTop` / `copyToTop` runtime transports** — `rollExtraOps`/`pickExtraOps`
     model the depth-dependent op the Tracker emits; `runOps_rollExtraOps` /
     `runOps_pickExtraOps` collapse the depth-0/1/2 special cases (`nop`/`.swap`/
     `.rot` and `.dup`/`.over`) to `applyRoll`/`applyPick` via the conditional
     bridges `applySwap_eq_applyRoll1` / `applyRot_eq_applyRoll2` /
     `applyDup_eq_applyPick0` / `applyOver_eq_applyPick1` (the `applySwap`/`applyRot`/
     `applyDup`/`applyOver` peers the hand-off asked for), and the `≥3`/`≥2` cases to
     the bare `.roll d`/`.pickStruct d`.  Composed with the wave-76 model lemmas +
     the wave-77 bridge: `runOps_toTop_extraOps_sim` brings `σ name` to the TOS
     (remainder `eraseIdx d`), `runOps_copyToTop_extraOps_sim` copies it.
     `TrackerSim_copyToTop` (= `TrackerSim_push`) is the copyToTop invariant
     preservation.

  2. **Per-helper ops-append lemmas** — `forIn_id_push_toList` →
     `rawBlock_ops_eq`/`rawBlock_ops_append`, `pushInt`/`pushBytes`/`pushFieldP_ops_append`,
     `toTop_ops_append` (`= … ++ rollExtraOps (findDepth name)`),
     `copyToTop_ops_append` (`= … ++ pickExtraOps (findDepth name)`), and the worked
     `fieldMod_ops_append`.  These let `runOps_append` decompose the 945/518-op list
     helper-by-helper at the leaf level.

**LANDED THIS WAVE (wave-79 — THE KEYSTONE + field-binop ops-append template).**
The Part-9 sub-goal (a) the wave-78 hand-off named as "the one remaining
model-preservation lemma" is now CLOSED, all `propext`/`Classical.choice`/
`Quot.sound`-clean, NO `sorry`, NO `native_decide` (only in the concrete smokes),
NO new axiom:

  (a) **`toTop` `nm`-side `TrackerSim` preservation — `TrackerSim_toTop`** (the
      slot-reindexing keystone).  Proved via `TrackerSim_canonical` (the genuine
      slot-reindexing core: length off `Array.toList_eraseIdxIfInBounds` +
      `List.length_eraseIdx`; slots a three-way index split — top / below-`d` /
      at-or-above-`d` — across array-erase-then-push vs list-cons-after-erase under
      the `size-1-i ↔ i` reverse correspondence) + `roll_nm_canonical` (the four
      `roll` branches reduced to the single canonical erase-push array shape:
      `d=0` via `eraseLast_append`, `d=1` via `swap_toList_canonical`, `d=2`/`d≥3`
      definitional).  Composed with `findDepth_eq_findDepthList` (bridge) +
      `findDepthList_sim` (`stk[d]! = σ name`).  This is the `toTop` peer of
      `TrackerSim_copyToTop`.  Smoke: `smoke_TrackerSim_toTop`
      (`[a,b,c]`, `toTop "a"` → `[b,c,a]` / runtime `[10,30,20]`).

  Plus the field-binop ops-append template `fieldBinop_ops_append` and its
  instances `fieldMul_ops_append` / `fieldAdd_ops_append` (the nested-`toTop`
  decomposition the wave-78 note left to the assembly site), each with a smoke.

**LANDED THIS WAVE (wave-80 — sub-goal (c) DISCHARGED + the base `TrackerSim`).**
The wave-79 hand-off named sub-goal (c) (`decomposePoint`'s runtime transport) as
"the one remaining helper-step whose `TrackerSim`-bearing runtime transport is
unwritten."  It is now WRITTEN and DISCHARGED (Part 10 + Part 11), all
`propext`/`Quot.sound`-clean (plus the inherited backend opaques on the
`runOps`-bearing transports), NO `sorry`, NO new axiom, `native_decide` only in the
concrete smokes:

  (c) **`decomposePoint` ↔ `(pointX p, pointY p)` — `decomposePoint_runOps` (Part 10).**
      The op-list `decomposePoint_ops` (via the four ops-append leaves + the two
      concrete `findDepth` folds `dpT1_fd0`/`dpT4_fd1`; the new `rawBlock_nm_some1/
      none1` reduce the `Id.run`/`forIn [0:1]` pop-loop so the cumulative `nm` is
      kernel-computable), the runtime transport `decomposePoint_op_transport`
      (single `OP_SPLIT` at 32 → `dpConvTail_transport` on the y-half → `swap` →
      `dpConvTail_transport` on the x-half → `swap`, reusing `reverse32_ops_transport`
      twice via the shared `dpConvTail` leaf), and the spec bridge `decomposePoint_runOps`
      lifting both decodes to `Secp256k1.pointX`/`pointY` under `64 ≤ p.size` + the two
      `hDecX`/`hDecY` canonical-decode hypotheses (the SAME ones `emitEcPointX/Y_runOps_eq`
      carry).  Lands `[pointY p, pointX p]` (y on TOS, matching produced `nm = #[_x,_y]`).

  (b-first) **The base `TrackerSim` — `decomposePoint_baseTrackerSim` (Part 11).**
      `decomposePoint_final_nm` (the `dpT5`/`dpT6` nm-chain: `toTop "_dp_xb"` = `roll 1`
      = `swap` via the new `swap_nm_ge2`, then the x `rawBlock`) gives produced
      `nm = #[_x, _y]`; the base sim then mirrors the runtime `[pointY p, pointX p]`
      against it under `ecOnCurveBaseσ`.  This is the FIRST step of the (b)
      whole-program assembly, demonstrating the threading COMPOSES off (c).

**PRECISE REMAINING SUB-GOAL (deliverable 3 — the per-field-helper RUNTIME sim, BLOCKED).**
With (c)+(b-first) landed, the entry `TrackerSim` for the field chain is in hand.  The
ONE remaining gap before `emitEcOnCurve` discharges is the **per-field-helper composed
runtime-sim transport** — the substrate ships the LEAVES (`runOps_toTop_extraOps_sim`,
`runOps_copyToTop_extraOps_sim`, `TrackerSim_toTop`/`copyToTop`, the `field*_optail`
transports) but NOT a lemma composing a WHOLE field helper end-to-end at runtime, e.g.

    fieldSqr_runOps_sim :
      TrackerSim t.nm σ stk → some a ∈ t.nm.toList.reverse →
        runOps (fieldSqr-ops-chunk) { stk } =
          .ok { σ a-squared :: stk-extended } ∧ TrackerSim (fieldSqr t a r).nm σ' …

  Each field helper internally runs 3–4 `toTop`/`copyToTop`/`rawBlock`/`fieldMod`
  sub-steps; the composed lemma must thread the rolling `TrackerSim` through ALL of
  them (each sub-step's `findDepth` evaluated against the cumulative non-literal `nm`
  via the wave-77 bridge + a per-step `nm`-toList lemma in the `dpT*_nm` style) and
  land the spec field value via the `*_optail` transport.  The FIRST concrete instance
  the `emitEcOnCurve` chain needs is `fieldSqr "_y" "_y2"` off the base sim
  (`decomposePoint_baseTrackerSim`).  This composed-helper sim lemma is unwritten for
  every field helper (`fieldSqr`/`fieldMul`/`fieldAdd`) and is the genuine bulk of the
  discharge; the final `OP_EQUAL` ↔ `decide (lhs = rhs)` comparison is the closing leaf.

  Secondary gap (orthogonal): the substrate `TrackerSim` requires `stk.length = nm.size`
  (no passive tail), so the chain currently threads only for `rest = []`.  The axiom
  carries arbitrary `rest`; discharging it needs either a tail-generalized `TrackerSim`
  (re-deriving the keystone + transports modulo a fixed suffix) or a `rest`-erasure
  argument.  The base step `decomposePoint_runOps` itself is already `rest`-polymorphic
  (Part 10); only the field-chain TrackerSim threading needs the generalization.

The discharge is all-or-nothing per axiom (partial threading discharges neither
axiom), so per the task BLOCK protocol the two axioms are LEFT IN PLACE and the
drift stays `76 → 76` (0 axioms discharged this wave; sub-goal (c) + the base
`TrackerSim` landed).  The same Part 10/11 base + the model-preservation layer
((1)+(2)+(a)) feed `emitEcNegate` (same `decomposePoint` base, then `composePoint`)
on the identical per-field-helper-sim template, and unblock `emitEcAdd`/`emitEcMul`
(the wave-76 hand-off). -/

/-! ## Part 14 — `emitEcNegate` discharge (deliverables 1-3)

`emitEcNegate` reuses the IDENTICAL machinery the `emitEcOnCurve` discharge proved
(Part 10-13): the `decomposePoint_runOps` base, the determined per-helper increment
sims, the op-list-equals-determined-concatenation bridge, and the runtime threading.
The codegen (`Stack.Ec.emitEcNegate`) runs the 4-step tracker chain
`decomposePoint "_pt" "_nx" "_ny"` → `pushFieldP "_fp"` →
`fieldSub "_fp" "_ny" "_neg_y"` → `composePoint "_nx" "_neg_y" "_result"`, computing
`(x, y) ↦ (x, p − y)`.

Deliverables landed here:
  1. **`fieldSub_runOps_sim`** — the composed-helper sim for field subtraction (the
     `fieldMul_runOps_sim` peer at `OP_SUB`, off `fieldSub_optail_transport`).
  2. **`composePoint_runOps_sim`** — the build-back runtime transport (the
     `decomposePoint_runOps` peer): on the post-`fieldSub` runtime stack
     `[neg_y, x] ++ rest`, encodes both coords (`OP_NUM2BIN`/`OP_SPLIT`/`reverse32`
     per coord, the same encode leaf as `emitEcMakePoint`) and concatenates to the
     64-byte point `intToBE32 x ++ intToBE32 neg_y = makePoint x neg_y`.
  3. **`emitEcNegate_runOps_eq`** — the discharge: `emitEcNegate_ops` (op-list =
     determined concat via the intermediate-nm chain, mirroring `emitEcOnCurve_ops`)
     + the runtime threading (`decomposePoint_runOps` base → `fieldSub_runOps_sim`
     on y → `composePoint_runOps_sim`), reduced to `Crypto.Secp256k1.ecNegate` via
     the spec bridge `ecNegate_eq_makePoint` (`fieldSub p y` ≡ `fieldSub 0 y` under
     `fieldMod`, the canonical form `intToBE32` applies).

All `propext`/`Quot.sound`-clean (plus the inherited backend opaques on the
`runOps`-bearing transports), NO `sorry`, NO new axiom, `native_decide` only in the
concrete smokes. -/

/-! ### Deliverable 1 — `fieldSub_runOps_sim` -/

/-- The determined `fieldSub "_fp" "_ny"` increment off `[fp, ny, nx] ++ rest`
(the `toTop "_fp"` is depth 0 = nop, the `toTop "_ny"` is depth 1 = `swap`).  Peer of
`fieldMulSwapInc` at `OP_SUB`. -/
def fieldSubSwapInc : List StackOp :=
  [.swap, .opcode "OP_SUB", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps

/-- **`fieldSub`-with-swap-lead composed runtime sim (deliverable 1).**  Running the
determined `swap, OP_SUB, push fieldP, fieldModOps` increment on `[a, b, c] ++ rest`
lands `Secp256k1.fieldSub a b :: c :: rest` — `swap` pairs `a` (top) over `b` for
`OP_SUB`.  The `emitEcNegate` use is `fieldSub "_fp" "_ny"` off `[fp, ny, nx] ++ rest`
(`a = fp`, `b = ny`, `c = nx`), landing `(p − y) :: x :: rest`.  Peer of
`fieldMul_runOps_sim`. -/
theorem fieldSub_runOps_sim (s : StackState) (a b c : Int) (rest : List Value)
    (hStk : s.stack = (.vBigint a) :: (.vBigint b) :: (.vBigint c) :: rest) :
    runOps fieldSubSwapInc s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldSub a b) :: (.vBigint c) :: rest } := by
  unfold fieldSubSwapInc
  rw [show ([StackOp.swap, .opcode "OP_SUB", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps)
        = StackOp.swap :: ([.opcode "OP_SUB", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) from rfl]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap2, stepNonIf_swap]
  rw [show applySwap s = .ok { s with stack := (.vBigint b) :: (.vBigint a) :: (.vBigint c) :: rest } by
        unfold applySwap; rw [hStk]]
  simp only [match_Except_ok_runOps]
  rw [fieldSub_optail_transport { s with stack := (.vBigint b) :: (.vBigint a) :: (.vBigint c) :: rest }
        a b ((.vBigint c) :: rest) rfl]

/-- SMOKE (`fieldSub` sim fires).  On `[10, 7, 9] ++ [777]` (= `[fp, ny, nx]`), lands
`fieldSub 10 7 = 3 :: 9 :: 777`. -/
theorem smoke_fieldSub_runOps_sim :
    runOps fieldSubSwapInc { (default : StackState) with stack := [.vBigint 10, .vBigint 7, .vBigint 9] ++ fhSmokeRest }
      = .ok { (default : StackState) with
              stack := .vBigint (Crypto.Secp256k1.fieldSub 10 7) :: .vBigint 9 :: fhSmokeRest } :=
  fieldSub_runOps_sim _ 10 7 9 fhSmokeRest rfl

/-- SMOKE (`fieldSub` sim value anti-vacuity).  `fieldSub 10 7 = 3`. -/
theorem smoke_fieldSub_runOps_sim_value :
    Crypto.Secp256k1.fieldSub 10 7 = 3 := by native_decide

/-! ### Deliverable 2 — `composePoint_runOps_sim` (the build-back transport) -/

/-- The single-coordinate big-endian encode op-list (the per-coord chunk
`composePoint`/`emitEcMakePoint` share): `OP_NUM2BIN` to 33 LE bytes, split to the
low 32, drop the high byte, then `emitReverse32Ops` to big-endian. -/
def coordEncodeOps : List StackOp :=
  [.push (.bigint 33), .opcode "OP_NUM2BIN", .push (.bigint 32), .opcode "OP_SPLIT", .drop]
  ++ Ec.emitReverse32Ops

/-- **Single-coordinate encode leaf (deliverable 2 sub-step).**  Running `coordEncodeOps`
on `[v] ++ rest` encodes `v` to 33 LE bytes (`OP_NUM2BIN`), splits to the low 32, drops
the high byte, and byte-reverses to big-endian — landing
`reverseAcc 32 (enc.extract 0 32) empty :: rest`, where `enc = num2binEncode? v 33`.
This is the first chunk of `ec_makePoint_op_transport`, extracted as a reusable leaf. -/
theorem coordEncode_transport (s : StackState) (v : Int) (enc : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBigint v :: rest)
    (hEnc : num2binEncode? v 33 = some enc)
    (hSz : (32 : Nat) ≤ enc.size) :
    runOps coordEncodeOps s
      = .ok { s with stack := .vBytes (reverseAcc 32 (enc.extract 0 32) ByteArray.empty) :: rest } := by
  obtain ⟨stk, alt, out, props, pre⟩ := s
  subst hStk
  have niOp : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by intro c t e h; cases h
  have niDrop : ∀ t e, StackOp.drop ≠ .ifOp t e := by intro t e h; cases h
  have niPush : ∀ (pv : PushVal) t e, StackOp.push pv ≠ .ifOp t e := by intro pv t e h; cases h
  have hSzExtract : (enc.extract 0 32).size = 32 := by rw [ByteArray.size_extract]; omega
  rw [show coordEncodeOps = StackOp.push (.bigint 33) :: StackOp.opcode "OP_NUM2BIN"
        :: StackOp.push (.bigint 32) :: StackOp.opcode "OP_SPLIT" :: StackOp.drop
        :: Ec.emitReverse32Ops from rfl]
  -- push 33
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 33)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- OP_NUM2BIN → enc
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_NUM2BIN"), stepNonIf_opcode]
  rw [show runOpcode "OP_NUM2BIN"
        { stack := .vBigint 33 :: .vBigint v :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes enc :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } by
      unfold runOpcode
      simp only [popN, StackState.pop?, asInt?, StackState.push, Int.reduceLT, reduceIte]
      rw [show (33 : Int).toNat = 33 from rfl, hEnc]]
  simp only [match_Except_ok_runOps]
  -- push 32
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint 32)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- OP_SPLIT at 32
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_SPLIT"), stepNonIf_opcode]
  rw [show runOpcode "OP_SPLIT"
        { stack := .vBigint 32 :: .vBytes enc :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (enc.extract 32 enc.size) :: .vBytes (enc.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } by
      unfold runOpcode
      simp only [popN, StackState.pop?, asBytes?, asNonNegativeNat?, asInt?,
                 StackState.push, Int.reduceLT, reduceIte]
      rw [if_neg (by omega : ¬ (32 : Int).toNat > enc.size)]; rfl]
  simp only [match_Except_ok_runOps]
  -- drop → [enc.extract 0 32]
  rw [runOps_cons_nonIf_eq _ _ _ niDrop, stepNonIf_drop]
  rw [show applyDrop
        { stack := .vBytes (enc.extract 32 enc.size) :: .vBytes (enc.extract 0 32) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (enc.extract 0 32) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- emitReverse32Ops on the 32-byte low half
  rw [reverse32_ops_transport
        { stack := .vBytes (enc.extract 0 32) :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        (enc.extract 0 32) rest rfl (by rw [hSzExtract]; omega)]

/-- The determined `composePoint "_nx" "_neg_y"` increment off the post-`fieldSub`
runtime stack `[neg_y, x] ++ rest`: `toTop "_nx"` (depth 1 = `swap`) → encode x →
`toTop "_neg_y"` (depth 1 = `swap`) → encode neg_y → `toTop "_cp_xb"`/`toTop "_cp_yb"`
(both depth 1 = `swap`) → `OP_CAT`. -/
def composeInc : List StackOp :=
  [.swap] ++ coordEncodeOps ++ [.swap] ++ coordEncodeOps ++ [.swap, .swap, .opcode "OP_CAT"]

set_option maxRecDepth 8192 in
/-- **`composePoint` build-back composed runtime sim (deliverable 2).**  The
`decomposePoint_runOps` peer: running the determined `composePoint` increment on
`[Y, X] ++ rest` (Y on TOS, mirroring the post-`fieldSub` nm `#[_nx, _neg_y]`) encodes
each coordinate to 32-byte big-endian (the `coordEncode_transport` leaf) and `OP_CAT`s
`X ‖ Y`, landing `makePoint X Y :: rest`.  Carries the SAME INPUT-side hypotheses as
`emitEcMakePoint` (two `num2binEncode?` encodings, two size guards, two BE-encode
bridges `hBeX`/`hBeY`). -/
theorem composePoint_runOps_sim (s : StackState) (X Y : Int) (encX encY : ByteArray)
    (rest : List Value)
    (hStk : s.stack = .vBigint Y :: .vBigint X :: rest)
    (hEncX : num2binEncode? X 33 = some encX)
    (hEncY : num2binEncode? Y 33 = some encY)
    (hSzX : (32 : Nat) ≤ encX.size)
    (hSzY : (32 : Nat) ≤ encY.size)
    (hBeX : reverseAcc 32 (encX.extract 0 32) ByteArray.empty = Crypto.Secp256k1.intToBE32 X)
    (hBeY : reverseAcc 32 (encY.extract 0 32) ByteArray.empty = Crypto.Secp256k1.intToBE32 Y) :
    runOps composeInc s
      = .ok { s with stack := .vBytes (Crypto.Secp256k1.makePoint X Y) :: rest } := by
  obtain ⟨stk, alt, out, props, pre⟩ := s
  subst hStk
  have niSwap : ∀ t e, StackOp.swap ≠ .ifOp t e := by intro t e h; cases h
  have niOp : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by intro c t e h; cases h
  rw [show composeInc = StackOp.swap
        :: (coordEncodeOps ++ ([StackOp.swap] ++ (coordEncodeOps
            ++ [StackOp.swap, StackOp.swap, StackOp.opcode "OP_CAT"]))) from by
      simp only [composeInc, List.append_assoc, List.cons_append, List.nil_append]]
  -- swap → [X, Y]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBigint Y :: .vBigint X :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint X :: .vBigint Y :: rest, altstack := alt,
                outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- encode X → [enc_x_be, Y]
  rw [runOps_append, coordEncode_transport
        { stack := .vBigint X :: .vBigint Y :: rest, altstack := alt,
          outputs := out, props := props, preimage := pre }
        X encX (.vBigint Y :: rest) rfl hEncX hSzX]
  simp only [match_Except_ok_runOps, List.singleton_append]
  -- swap → [Y, enc_x_be]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty) :: .vBigint Y :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBigint Y :: .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- encode Y → [enc_y_be, enc_x_be]
  rw [runOps_append, coordEncode_transport
        { stack := .vBigint Y :: .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        Y encY (.vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty) :: rest) rfl hEncY hSzY]
  simp only [match_Except_ok_runOps]
  -- swap → [enc_x_be, enc_y_be]
  rw [show ([StackOp.swap, StackOp.swap, StackOp.opcode "OP_CAT"])
        = StackOp.swap :: StackOp.swap :: [StackOp.opcode "OP_CAT"] from rfl]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty)
                    :: .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty)
                          :: .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- swap → [enc_y_be, enc_x_be]
  rw [runOps_cons_nonIf_eq _ _ _ niSwap, stepNonIf_swap]
  rw [show applySwap
        { stack := .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty)
                    :: .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty)
                          :: .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps]
  -- OP_CAT → enc_x_be ++ enc_y_be (below ++ top)
  rw [runOps_cons_nonIf_eq _ _ _ (niOp "OP_CAT"), stepNonIf_opcode]
  rw [show runOpcode "OP_CAT"
        { stack := .vBytes (reverseAcc 32 (encY.extract 0 32) ByteArray.empty)
                    :: .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty) :: rest,
          altstack := alt, outputs := out, props := props, preimage := pre }
        = .ok { stack := .vBytes (reverseAcc 32 (encX.extract 0 32) ByteArray.empty
                                    ++ reverseAcc 32 (encY.extract 0 32) ByteArray.empty) :: rest,
                altstack := alt, outputs := out, props := props, preimage := pre } from rfl]
  simp only [match_Except_ok_runOps, runOps_nil]
  rw [hBeX, hBeY]
  rfl

/-! ### MANDATORY smokes for `composePoint_runOps_sim` (deliverable 2) -/

private def smokeCpX : Int := 11
private def smokeCpY : Int := 22
private def smokeCpEncX : ByteArray := (num2binEncode? smokeCpX 33).getD ByteArray.empty
private def smokeCpEncY : ByteArray := (num2binEncode? smokeCpY 33).getD ByteArray.empty

/-- SMOKE (wf anti-vacuity).  All six `composePoint_runOps_sim` hypotheses are
SATISFIABLE for `X = 11, Y = 22`.  `native_decide` is legitimate (closed-form). -/
theorem smoke_composePoint_wf_satisfiable :
    num2binEncode? smokeCpX 33 = some smokeCpEncX
      ∧ num2binEncode? smokeCpY 33 = some smokeCpEncY
      ∧ (32 : Nat) ≤ smokeCpEncX.size
      ∧ (32 : Nat) ≤ smokeCpEncY.size
      ∧ reverseAcc 32 (smokeCpEncX.extract 0 32) ByteArray.empty
          = Crypto.Secp256k1.intToBE32 smokeCpX
      ∧ reverseAcc 32 (smokeCpEncY.extract 0 32) ByteArray.empty
          = Crypto.Secp256k1.intToBE32 smokeCpY := by
  native_decide

/-- SMOKE (the headline — build-back FIRES).  `composePoint`'s increment on
`[22, 11] ++ [999]` (Y on TOS) lands `makePoint 11 22 :: [999]`. -/
theorem smoke_composePoint_runOps_sim :
    runOps composeInc
        { (default : StackState) with stack := [.vBigint smokeCpY, .vBigint smokeCpX, .vBigint 999] }
      = .ok { (default : StackState) with
              stack := .vBytes (Crypto.Secp256k1.makePoint smokeCpX smokeCpY) :: [.vBigint 999] } :=
  composePoint_runOps_sim _ smokeCpX smokeCpY smokeCpEncX smokeCpEncY [.vBigint 999] rfl
    (by native_decide) (by native_decide) (by native_decide) (by native_decide)
    (by native_decide) (by native_decide)

/-- SMOKE (value anti-vacuity).  The composed point round-trips: x = 11, y = 22. -/
theorem smoke_composePoint_value_concrete :
    Crypto.Secp256k1.pointX (Crypto.Secp256k1.makePoint smokeCpX smokeCpY) = 11
      ∧ Crypto.Secp256k1.pointY (Crypto.Secp256k1.makePoint smokeCpX smokeCpY) = 22 := by
  native_decide

/-! ### Deliverable 3a — `decomposePoint` with the `emitEcNegate` output names

`emitEcNegate` decomposes into `"_nx"`/`"_ny"` (vs `emitEcOnCurve`'s `"_x"`/`"_y"`).
The op-list and runtime transport are name-independent (the produced names only label
`nm` slots, not ops), but the depth `decide`s need a concrete output name, so we
re-derive the negate-named peers of `decomposePoint_ops` / `decomposePoint_runOps`. -/

/-- The `decomposePoint` x-coordinate `rawBlock` tracker for the negate output name. -/
def endpT4 : Ec.Tracker := dpT3.rawBlock 1 (some "_ny") (Ec.emitReverse32Ops ++ dpConvTail)

theorem endpT4_nm : endpT4.nm = #[some "_dp_xb", some "_ny"] := by
  rw [endpT4, rawBlock_nm_some1]
  show (dpT3.nm.pop.push (some "_ny")) = _
  rw [dpT3]
  show ((((dpT2.nm.push (some "_dp_xb")).push (some "_dp_yb")).pop).push (some "_ny")) = _
  rw [dpT2_nm]; rfl

theorem endpT4_fd1 : endpT4.findDepth "_dp_xb" = 1 := by
  rw [findDepth_eq_findDepthList _ _ (by rw [endpT4_nm]; decide)]
  rw [endpT4_nm]; decide

set_option maxRecDepth 8192 in
/-- **`decomposePoint "_pt" "_nx" "_ny"` op-list = the determined list.**  The
negate-named peer of `decomposePoint_ops` (same `expectedDecomposePoint`; ops are
output-name-independent). -/
theorem decomposePoint_ops_neg :
    (Ec.decomposePoint (Ec.Tracker.init [some "_pt"]) "_pt" "_nx" "_ny").ops.toList
      = expectedDecomposePoint := by
  show (endpT4.toTop "_dp_xb" |>.rawBlock 1 (some "_nx")
        (Ec.emitReverse32Ops ++ dpConvTail) |>.swap).ops.toList = _
  rw [swap_ops_append, rawBlock_ops_append, toTop_ops_append, endpT4_fd1]
  show (endpT4.ops.toList ++ rollExtraOps 1 ++ (Ec.emitReverse32Ops ++ dpConvTail)
        ++ [StackOp.swap]) = _
  rw [endpT4, rawBlock_ops_append]
  show ((dpT3.ops.toList ++ (Ec.emitReverse32Ops ++ dpConvTail)) ++ rollExtraOps 1
        ++ (Ec.emitReverse32Ops ++ dpConvTail) ++ [StackOp.swap]) = _
  rw [dpT3]
  show ((dpT2.ops.toList ++ (Ec.emitReverse32Ops ++ dpConvTail)) ++ rollExtraOps 1
        ++ (Ec.emitReverse32Ops ++ dpConvTail) ++ [StackOp.swap]) = _
  rw [dpT2, rawBlock_ops_append, dpT1, toTop_ops_append]
  rw [show (Ec.Tracker.init [some "_pt"]).findDepth "_pt" = 0 from dpT1_fd0]
  simp only [rollExtraOps, Ec.Tracker.init, dpConvTail, expectedDecomposePoint]
  rfl

open RunarVerification.Crypto.Secp256k1 (pointX pointY) in
/-- **`decomposePoint "_pt" "_nx" "_ny"` runtime transport.**  Negate-named peer of
`decomposePoint_runOps`: lands `[pointY p, pointX p] ++ rest` under the same wf hyps. -/
theorem decomposePoint_runOps_neg (s : StackState) (p : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes p :: rest) (hSize : 64 ≤ p.size)
    (hDecX : decodeMinimalLE
              (reverseAcc 32 (p.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00]) = pointX p)
    (hDecY : decodeMinimalLE
              (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty ++ ByteArray.mk #[0x00]) = pointY p) :
    runOps (Ec.decomposePoint (Ec.Tracker.init [some "_pt"]) "_pt" "_nx" "_ny").ops.toList s
      = .ok { s with stack := .vBigint (pointY p) :: .vBigint (pointX p) :: rest } := by
  rw [decomposePoint_ops_neg, decomposePoint_op_transport s p rest hStk hSize, hDecX, hDecY]

/-- **`decomposePoint "_pt" "_nx" "_ny"` produced `nm` = `#[_nx, _ny]`.**  Negate-named
peer of `decomposePoint_final_nm` (the `endpT5`/`endpT6` nm-chain). -/
def endpT5 : Ec.Tracker := endpT4.toTop "_dp_xb"
def endpT6 : Ec.Tracker := endpT5.rawBlock 1 (some "_nx") (Ec.emitReverse32Ops ++ dpConvTail)

theorem endpT5_nm : endpT5.nm = #[some "_ny", some "_dp_xb"] := by
  unfold endpT5 Ec.Tracker.toTop
  rw [endpT4_fd1]
  show (endpT4.swap).nm = _
  rw [swap_nm_ge2 endpT4 (by rw [endpT4_nm]; decide), endpT4_nm]; rfl

theorem endpT6_nm : endpT6.nm = #[some "_ny", some "_nx"] := by
  unfold endpT6; rw [rawBlock_nm_some1, endpT5_nm]; rfl

theorem decomposePoint_final_nm_neg :
    (Ec.decomposePoint (Ec.Tracker.init [some "_pt"]) "_pt" "_nx" "_ny").nm
      = #[some "_nx", some "_ny"] := by
  show (endpT6.swap).nm = _
  rw [swap_nm_ge2 endpT6 (by rw [endpT6_nm]; decide), endpT6_nm]; rfl

/-! ### Deliverable 3b — the `emitEcNegate` tracker chain + op-list bridge -/

/-- The `emitEcNegate` tracker chain (named so the per-helper findDepths fold). -/
def enT1 : Ec.Tracker := Ec.decomposePoint (Ec.Tracker.init [some "_pt"]) "_pt" "_nx" "_ny"
def enT2 : Ec.Tracker := Ec.pushFieldP enT1 "_fp"
def enT3 : Ec.Tracker := Ec.fieldSub enT2 "_fp" "_ny" "_neg_y"

theorem enT1_nm : enT1.nm = #[some "_nx", some "_ny"] := decomposePoint_final_nm_neg

theorem enT2_nm : enT2.nm = #[some "_nx", some "_ny", some "_fp"] := by
  show (Ec.pushFieldP enT1 "_fp").nm = _
  rw [pushFieldP_nm, enT1_nm]; rfl

theorem enT3_nm : enT3.nm = #[some "_nx", some "_neg_y"] := by
  show (Ec.fieldSub enT2 "_fp" "_ny" "_neg_y").nm = _
  unfold Ec.fieldSub
  have hm1_nm : (enT2.toTop "_fp").nm = #[some "_nx", some "_ny", some "_fp"] := by
    rw [toTop_nm_canonical enT2 "_fp" 0
          (fd_of_nm enT2 "_fp" 0 _ enT2_nm (by decide) (by decide)) (by rw [enT2_nm]; decide), enT2_nm]
    apply Array.ext' <;> simp
  have hm2_nm : ((enT2.toTop "_fp").toTop "_ny").nm = #[some "_nx", some "_fp", some "_ny"] := by
    rw [toTop_nm_canonical _ "_ny" 1
          (fd_of_nm _ "_ny" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  have hm3_nm : (((enT2.toTop "_fp").toTop "_ny").rawBlock 2 (some "_fsub_diff")
        [.opcode "OP_SUB"]).nm = #[some "_nx", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2, hm2_nm]; apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fsub_diff" "_neg_y" 0
        (fd_of_nm _ "_fsub_diff" 0 _ hm3_nm (by decide) (by decide)) (by rw [hm3_nm]; decide), hm3_nm]
  apply Array.ext' <;> simp

/-- **`fieldSub "_fp" "_ny" "_neg_y"` ops = `enT2.ops ++ fieldSubSwapInc`.**  toTop
`_fp` depth 0, `_ny` depth 1, diff depth 0 (peer of `eocFieldMul_ops` at `OP_SUB`). -/
theorem enFieldSub_ops : enT3.ops.toList = enT2.ops.toList ++ fieldSubSwapInc := by
  show (Ec.fieldSub enT2 "_fp" "_ny" "_neg_y").ops.toList = _
  unfold Ec.fieldSub
  have hm1_nm : (enT2.toTop "_fp").nm = #[some "_nx", some "_ny", some "_fp"] := by
    rw [toTop_nm_canonical enT2 "_fp" 0
          (fd_of_nm enT2 "_fp" 0 _ enT2_nm (by decide) (by decide)) (by rw [enT2_nm]; decide), enT2_nm]
    apply Array.ext' <;> simp
  have hm2_nm : (((enT2.toTop "_fp").toTop "_ny").rawBlock 2 (some "_fsub_diff")
        [.opcode "OP_SUB"]).nm = #[some "_nx", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_ny" 1
          (fd_of_nm _ "_ny" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [show (Ec.fieldMod (((enT2.toTop "_fp").toTop "_ny").rawBlock 2 (some "_fsub_diff")
        [.opcode "OP_SUB"]) "_fsub_diff" "_neg_y").ops.toList
        = _ from fieldBinop_ops_append enT2 "_fp" "_ny" "_fsub_diff" "_neg_y" (.opcode "OP_SUB")]
  rw [fd_of_nm enT2 "_fp" 0 _ enT2_nm (by decide) (by decide),
      fd_of_nm _ "_ny" 1 _ hm1_nm (by decide) (by decide),
      fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide)]
  simp only [fieldSubSwapInc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- **`composePoint "_nx" "_neg_y" "_result"` ops = `enT3.ops ++ composeInc`.**  All four
internal toTops are depth 1 (the post-`fieldSub` nm `#[_nx, _neg_y]` then the two encode
slots).  The body's per-coord conv-ops literal is definitionally `coordEncodeOps`. -/
theorem enComposePoint_ops :
    (Ec.composePoint enT3 "_nx" "_neg_y" "_result").ops.toList = enT3.ops.toList ++ composeInc := by
  rw [show Ec.composePoint enT3 "_nx" "_neg_y" "_result"
        = ((((((enT3.toTop "_nx").rawBlock 1 (some "_cp_xb") coordEncodeOps).toTop "_neg_y").rawBlock
            1 (some "_cp_yb") coordEncodeOps).toTop "_cp_xb").toTop "_cp_yb").rawBlock 2 (some "_result")
            [.opcode "OP_CAT"] from rfl]
  -- name the four-toTop/two-rawBlock chain explicitly to fold each depth-1 findDepth
  have hc1_nm : (enT3.toTop "_nx").nm = #[some "_neg_y", some "_nx"] := by
    rw [toTop_nm_canonical enT3 "_nx" 1
          (fd_of_nm enT3 "_nx" 1 _ enT3_nm (by decide) (by decide)) (by rw [enT3_nm]; decide), enT3_nm]
    apply Array.ext' <;> simp
  have hc2_nm : ((enT3.toTop "_nx").rawBlock 1 (some "_cp_xb") coordEncodeOps).nm
      = #[some "_neg_y", some "_cp_xb"] := by
    rw [rawBlock_nm_some1, hc1_nm]; rfl
  have hc3_nm : (((enT3.toTop "_nx").rawBlock 1 (some "_cp_xb") coordEncodeOps).toTop "_neg_y").nm
      = #[some "_cp_xb", some "_neg_y"] := by
    rw [toTop_nm_canonical _ "_neg_y" 1
          (fd_of_nm _ "_neg_y" 1 _ hc2_nm (by decide) (by decide)) (by rw [hc2_nm]; decide), hc2_nm]
    apply Array.ext' <;> simp
  have hc4_nm : ((((enT3.toTop "_nx").rawBlock 1 (some "_cp_xb") coordEncodeOps).toTop "_neg_y").rawBlock
        1 (some "_cp_yb") coordEncodeOps).nm = #[some "_cp_xb", some "_cp_yb"] := by
    rw [rawBlock_nm_some1, hc3_nm]; rfl
  have hc5_nm : (((((enT3.toTop "_nx").rawBlock 1 (some "_cp_xb") coordEncodeOps).toTop "_neg_y").rawBlock
        1 (some "_cp_yb") coordEncodeOps).toTop "_cp_xb").nm = #[some "_cp_yb", some "_cp_xb"] := by
    rw [toTop_nm_canonical _ "_cp_xb" 1
          (fd_of_nm _ "_cp_xb" 1 _ hc4_nm (by decide) (by decide)) (by rw [hc4_nm]; decide), hc4_nm]
    apply Array.ext' <;> simp
  rw [rawBlock_ops_append, toTop_ops_append, toTop_ops_append, rawBlock_ops_append,
      toTop_ops_append, rawBlock_ops_append, toTop_ops_append]
  rw [fd_of_nm enT3 "_nx" 1 _ enT3_nm (by decide) (by decide),
      fd_of_nm _ "_neg_y" 1 _ hc2_nm (by decide) (by decide),
      fd_of_nm _ "_cp_xb" 1 _ hc4_nm (by decide) (by decide),
      fd_of_nm _ "_cp_yb" 1 _ hc5_nm (by decide) (by decide)]
  simp only [composeInc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append,
    List.singleton_append]

/-- **The determined `emitEcNegate` op-list.** -/
def expectedEcNegate : List StackOp :=
  expectedDecomposePoint ++ [.push (.bigint Ec.fieldP)] ++ fieldSubSwapInc ++ composeInc

/-- **`emitEcNegate` op-list = the determined concatenation (deliverable 3).**  Threads
the decomposePoint ops + `pushFieldP` + the `fieldSub` increment + the `composePoint`
increment, each depth folded via the wave-77 bridge.  OUTPUT-PRESERVING. -/
theorem emitEcNegate_ops : Ec.emitEcNegate = expectedEcNegate := by
  show (Ec.composePoint enT3 "_nx" "_neg_y" "_result").ops.toList = _
  rw [enComposePoint_ops, enFieldSub_ops]
  show enT2.ops.toList ++ fieldSubSwapInc ++ composeInc = _
  show (Ec.pushFieldP enT1 "_fp").ops.toList ++ fieldSubSwapInc ++ composeInc = _
  rw [pushFieldP_ops_append]
  show enT1.ops.toList ++ [.push (.bigint Ec.fieldP)] ++ fieldSubSwapInc ++ composeInc = _
  show (Ec.decomposePoint (Ec.Tracker.init [some "_pt"]) "_pt" "_nx" "_ny").ops.toList
        ++ [.push (.bigint Ec.fieldP)] ++ fieldSubSwapInc ++ composeInc = _
  rw [decomposePoint_ops_neg]
  simp only [expectedEcNegate, List.append_assoc]

/-! ### Deliverable 3c — the spec bridge `ecNegate = makePoint x (fieldSub p y)` -/

/-- **`fieldMod` collapses `fieldSub p y` to `fieldSub 0 y`.**  `p − y ≡ −y (mod p)`,
so the two land the SAME canonical residue.  Pure `Int.emod` arithmetic. -/
theorem fieldMod_fieldSub_p_eq (y : Int) :
    Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.fieldSub Crypto.Secp256k1.FIELD_P y)
      = Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.fieldSub 0 y) := by
  unfold Crypto.Secp256k1.fieldSub Crypto.Secp256k1.fieldMod
  rw [show ((Crypto.Secp256k1.FIELD_P - y) % Crypto.Secp256k1.FIELD_P + Crypto.Secp256k1.FIELD_P)
            % Crypto.Secp256k1.FIELD_P % Crypto.Secp256k1.FIELD_P
        = ((0 - y) % Crypto.Secp256k1.FIELD_P + Crypto.Secp256k1.FIELD_P)
            % Crypto.Secp256k1.FIELD_P % Crypto.Secp256k1.FIELD_P from by
      rw [Int.sub_emod Crypto.Secp256k1.FIELD_P y Crypto.Secp256k1.FIELD_P,
          Int.sub_emod 0 y Crypto.Secp256k1.FIELD_P, Int.emod_self, Int.zero_emod]]

/-- `intToBE32` depends only on `fieldMod` of its argument. -/
theorem intToBE32_fieldMod_congr (a b : Int)
    (h : Crypto.Secp256k1.fieldMod a = Crypto.Secp256k1.fieldMod b) :
    Crypto.Secp256k1.intToBE32 a = Crypto.Secp256k1.intToBE32 b := by
  unfold Crypto.Secp256k1.intToBE32; rw [h]

/-- **`ecNegate p = makePoint (pointX p) (fieldSub p (pointY p))`.**  The spec
`ecNegate p = makePoint x (fieldSub 0 y)` computes the negated y as `fieldSub 0 y`;
the codegen pushes `fieldP` and computes `fieldSub fieldP y`.  Both encode to the same
big-endian bytes via `intToBE32` (which `fieldMod`s first).  This is the bridge that
lets the runtime output `makePoint x (fieldSub FIELD_P y)` close to `ecNegate p`. -/
theorem ecNegate_eq_makePoint (p : ByteArray) :
    Crypto.Secp256k1.ecNegate p
      = Crypto.Secp256k1.makePoint (Crypto.Secp256k1.pointX p)
          (Crypto.Secp256k1.fieldSub Crypto.Secp256k1.FIELD_P (Crypto.Secp256k1.pointY p)) := by
  show Crypto.Secp256k1.intToBE32 (Crypto.Secp256k1.pointX p)
        ++ Crypto.Secp256k1.intToBE32 (Crypto.Secp256k1.fieldSub 0 (Crypto.Secp256k1.pointY p))
      = Crypto.Secp256k1.intToBE32 (Crypto.Secp256k1.pointX p)
        ++ Crypto.Secp256k1.intToBE32 (Crypto.Secp256k1.fieldSub Crypto.Secp256k1.FIELD_P (Crypto.Secp256k1.pointY p))
  rw [intToBE32_fieldMod_congr (Crypto.Secp256k1.fieldSub 0 (Crypto.Secp256k1.pointY p))
        (Crypto.Secp256k1.fieldSub Crypto.Secp256k1.FIELD_P (Crypto.Secp256k1.pointY p))
        (fieldMod_fieldSub_p_eq (Crypto.Secp256k1.pointY p)).symm]

/-! ### Deliverable 3 — the `emitEcNegate` runtime threading + discharge -/

set_option maxRecDepth 4096 in
/-- **DISCHARGED — `emitEcNegate` agrees with `Crypto.Secp256k1.ecNegate`.**  Running the
determined op-list on `[pt] ++ rest` threads the `decomposePoint_runOps_neg` base →
`fieldSub_runOps_sim` on y (pushing `fieldP` first) → `composePoint_runOps_sim`, landing
`vBytes (ecNegate pt) :: rest`.  The wf hypotheses are the INPUT-side `decomposePoint`
decode bridges (the same `emitEcPointX/Y` carry) PLUS the two `composePoint`
`OP_NUM2BIN`-encode + BE-bridge hypotheses (the same `emitEcMakePoint` carries), here at
the coordinates `pointX pt` and `fieldSub FIELD_P (pointY pt)`.  `propext`/`Quot.sound`
-clean + inherited backend opaques, NO new axiom.  Replaces the
`Crypto.Spec.emitEcNegate_runOps_eq` axiom. -/
theorem emitEcNegate_runOps_eq (stkSt : StackState) (pt : ByteArray) (rest : List Value)
    (hStk : stkSt.stack = .vBytes pt :: rest) (hSize : 64 ≤ pt.size)
    (hDecX : decodeMinimalLE
              (reverseAcc 32 (pt.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointX pt)
    (hDecY : decodeMinimalLE
              (reverseAcc 32 (pt.extract 32 pt.size) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointY pt)
    (encX encNegY : ByteArray)
    (hEncX : num2binEncode? (Crypto.Secp256k1.pointX pt) 33 = some encX)
    (hEncNegY : num2binEncode? (Crypto.Secp256k1.fieldSub Crypto.Secp256k1.FIELD_P (Crypto.Secp256k1.pointY pt)) 33
                  = some encNegY)
    (hSzX : (32 : Nat) ≤ encX.size)
    (hSzNegY : (32 : Nat) ≤ encNegY.size)
    (hBeX : reverseAcc 32 (encX.extract 0 32) ByteArray.empty
              = Crypto.Secp256k1.intToBE32 (Crypto.Secp256k1.pointX pt))
    (hBeNegY : reverseAcc 32 (encNegY.extract 0 32) ByteArray.empty
              = Crypto.Secp256k1.intToBE32 (Crypto.Secp256k1.fieldSub Crypto.Secp256k1.FIELD_P (Crypto.Secp256k1.pointY pt))) :
    runOps Ec.emitEcNegate stkSt
      = .ok { stkSt with stack := .vBytes (Crypto.Secp256k1.ecNegate pt) :: rest } := by
  rw [emitEcNegate_ops]
  unfold expectedEcNegate
  simp only [List.append_assoc]
  -- base: decomposePoint → [pointY pt, pointX pt] ++ rest
  have hbase : runOps enT1.ops.toList stkSt
      = .ok { stkSt with stack := .vBigint (Crypto.Secp256k1.pointY pt)
                :: .vBigint (Crypto.Secp256k1.pointX pt) :: rest } :=
    decomposePoint_runOps_neg stkSt pt rest hStk hSize hDecX hDecY
  rw [runOps_append, show enT1.ops.toList = expectedDecomposePoint from decomposePoint_ops_neg] at *
  rw [hbase]
  simp only [match_Except_ok_runOps, List.singleton_append]
  -- push fieldP → [fieldP, pointY pt, pointX pt] ++ rest
  rw [runOps_cons_nonIf_eq _ _ _ (niPush (.bigint Ec.fieldP)), stepNonIf_push_bigint]
  simp only [match_Except_ok_runOps, StackState.push]
  -- fieldSub "_fp" "_ny" → [fieldSub fieldP (pointY pt), pointX pt] ++ rest
  rw [runOps_append, fieldSub_runOps_sim _ Ec.fieldP (Crypto.Secp256k1.pointY pt) (Crypto.Secp256k1.pointX pt) rest rfl]
  simp only [match_Except_ok_runOps]
  -- composePoint → [makePoint (pointX pt) (fieldSub fieldP (pointY pt))] ++ rest
  rw [show Ec.fieldP = Crypto.Secp256k1.FIELD_P from ec_fieldP_eq_spec]
  rw [composePoint_runOps_sim
        { stkSt with stack := .vBigint (Crypto.Secp256k1.fieldSub Crypto.Secp256k1.FIELD_P (Crypto.Secp256k1.pointY pt))
            :: .vBigint (Crypto.Secp256k1.pointX pt) :: rest }
        (Crypto.Secp256k1.pointX pt)
        (Crypto.Secp256k1.fieldSub Crypto.Secp256k1.FIELD_P (Crypto.Secp256k1.pointY pt))
        encX encNegY rest rfl hEncX hEncNegY hSzX hSzNegY hBeX hBeNegY]
  rw [← ecNegate_eq_makePoint pt]

/-! ### MANDATORY smoke for the `emitEcNegate` discharge (deliverable 3) -/

/-- Concrete `OP_NUM2BIN` encodings for the discharge smoke at `makePoint 11 22`. -/
private def smokeNegEncX : ByteArray :=
  (num2binEncode? (Crypto.Secp256k1.pointX smokeDpPt) 33).getD ByteArray.empty
private def smokeNegEncNegY : ByteArray :=
  (num2binEncode? (Crypto.Secp256k1.fieldSub Crypto.Secp256k1.FIELD_P (Crypto.Secp256k1.pointY smokeDpPt)) 33).getD ByteArray.empty

/-- SMOKE (wf anti-vacuity).  ALL discharge hypotheses are SATISFIABLE for
`makePoint 11 22`: the two decode bridges, the two `num2binEncode?` encodings, the two
size guards, and the two BE bridges all hold concretely.  Rules out a vacuous discharge. -/
theorem smoke_emitEcNegate_wf_satisfiable :
    (64 : Nat) ≤ smokeDpPt.size
      ∧ decodeMinimalLE (reverseAcc 32 (smokeDpPt.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
          = Crypto.Secp256k1.pointX smokeDpPt
      ∧ decodeMinimalLE (reverseAcc 32 (smokeDpPt.extract 32 smokeDpPt.size) ByteArray.empty ++ ByteArray.mk #[0x00])
          = Crypto.Secp256k1.pointY smokeDpPt
      ∧ num2binEncode? (Crypto.Secp256k1.pointX smokeDpPt) 33 = some smokeNegEncX
      ∧ num2binEncode? (Crypto.Secp256k1.fieldSub Crypto.Secp256k1.FIELD_P (Crypto.Secp256k1.pointY smokeDpPt)) 33
          = some smokeNegEncNegY
      ∧ (32 : Nat) ≤ smokeNegEncX.size
      ∧ (32 : Nat) ≤ smokeNegEncNegY.size
      ∧ reverseAcc 32 (smokeNegEncX.extract 0 32) ByteArray.empty
          = Crypto.Secp256k1.intToBE32 (Crypto.Secp256k1.pointX smokeDpPt)
      ∧ reverseAcc 32 (smokeNegEncNegY.extract 0 32) ByteArray.empty
          = Crypto.Secp256k1.intToBE32 (Crypto.Secp256k1.fieldSub Crypto.Secp256k1.FIELD_P (Crypto.Secp256k1.pointY smokeDpPt)) := by
  native_decide

/-- Concrete entry state for the discharge smoke: `[makePoint 11 22, 999]`. -/
private def smokeNegStk : StackState :=
  { (default : StackState) with stack := [.vBytes smokeDpPt, .vBigint 999] }

/-- SMOKE (the headline — discharge FIRES).  `emitEcNegate` on the concrete point
`makePoint 11 22` lands `vBytes (ecNegate …) :: rest`, with `rest` preserved beneath. -/
theorem smoke_emitEcNegate_runOps_eq :
    runOps Ec.emitEcNegate smokeNegStk
      = .ok { smokeNegStk with
          stack := .vBytes (Crypto.Secp256k1.ecNegate smokeDpPt) :: [.vBigint 999] } :=
  emitEcNegate_runOps_eq smokeNegStk smokeDpPt [.vBigint 999] rfl (by native_decide)
    (by native_decide) (by native_decide) smokeNegEncX smokeNegEncNegY
    (by native_decide) (by native_decide) (by native_decide) (by native_decide)
    (by native_decide) (by native_decide)

/-- SMOKE (value anti-vacuity).  `ecNegate (makePoint 11 22)` keeps x = 11 and negates
y to `fieldSub 0 22 = p − 22` (≠ 22), so the discharge yields a non-trivial result. -/
theorem smoke_emitEcNegate_value_concrete :
    Crypto.Secp256k1.pointX (Crypto.Secp256k1.ecNegate smokeDpPt) = 11
      ∧ Crypto.Secp256k1.pointY (Crypto.Secp256k1.ecNegate smokeDpPt)
          = Crypto.Secp256k1.fieldSub 0 22 := by native_decide

/-! ## Part 15 — `fieldInv` square-and-multiply correctness (the `emitEcAdd` crux)

`Crypto.Secp256k1.fieldInv a = fieldPowNat (fieldMod a) (FIELD_P − 2).toNat` (Fermat:
`a^(p−2) ≡ a⁻¹ mod p`).  The codegen unrolls a square-and-multiply over the
COMPILE-TIME-CONSTANT exponent `p − 2`, whose bit pattern is fixed:

* bit 255 = 1  (start `r := a`),
* bits 254..33 = 222 ones  (`fieldInvHighLoop 222`: each step `r := (r² · a)`),
* bit 32 = 0  (one square),
* bits 31..0 = `0xFFFFFC2D`  (`fieldInvLowLoop 32`: each step `r := r²`, ×a if bit set).

This section proves the **spec-level** square-and-multiply correctness: the accumulator
the codegen builds (mirrored by `fieldInvAccum`) equals `fieldInv a`.  The proof is a
GENUINE structural induction over the loop structure (`samHigh_pow` / `samLow_pow`),
NOT `native_decide` — the only `decide`/rewrite-to-numeral steps are the
closed-form exponent identities (`final_exp_eq`, `fieldPm2_toNat`), which are concrete
arithmetic facts about the constant exponent's bit pattern, not the correctness claim.

The genuine algebra (`fpow_add`, the loop inductions) is `propext`/`Quot.sound`-clean
and kernel-checkable.  The runtime threading that lands `fieldInvAccum a` on the Script
VM stack across the ~2 k unrolled ops is the remaining `emitEcAdd` gap (documented at
the section end). -/

namespace FieldInvSpec

open Crypto.Secp256k1 (fieldMod fieldMul fieldPowNat fieldInv FIELD_P)

/-- `fieldMod a = a % p` (the canonical-residue normaliser collapses to `Int.emod`). -/
theorem fmod_eq_emod (a : Int) : fieldMod a = a % FIELD_P := by
  unfold fieldMod
  rw [Int.add_emod_right, Int.emod_emod_of_dvd _ (Int.dvd_refl _)]

/-- `fieldMod 1 = 1`. -/
theorem fmod_one : fieldMod 1 = 1 := by rw [fmod_eq_emod]; decide

/-- `fieldMod` is idempotent. -/
theorem fmod_emod (a : Int) : fieldMod (fieldMod a) = fieldMod a := by
  rw [fmod_eq_emod, fmod_eq_emod, Int.emod_emod_of_dvd _ (Int.dvd_refl _)]

/-- `fieldMul` is commutative. -/
theorem fmul_comm (a b : Int) : fieldMul a b = fieldMul b a := by
  unfold fieldMul; rw [Int.mul_comm]

/-- `fieldMod (fieldMod a · b) = fieldMod (a · b)` — left-arg `fieldMod` absorbs. -/
theorem fmod_mul_left (a b : Int) :
    fieldMod (fieldMod a * b) = fieldMod (a * b) := by
  rw [fmod_eq_emod, fmod_eq_emod a, fmod_eq_emod (a*b), Int.mul_emod,
      Int.emod_emod_of_dvd _ (Int.dvd_refl _), ← Int.mul_emod]

/-- `fieldMod (a · fieldMod b) = fieldMod (a · b)` — right-arg `fieldMod` absorbs. -/
theorem fmod_mul_right (a b : Int) :
    fieldMod (a * fieldMod b) = fieldMod (a * b) := by
  rw [Int.mul_comm a, fmod_mul_left, Int.mul_comm]

/-- `fieldMul` is associative (mod p). -/
theorem fmul_assoc (a b c : Int) :
    fieldMul (fieldMul a b) c = fieldMul a (fieldMul b c) := by
  unfold fieldMul
  rw [fmod_mul_left (a*b) c, fmod_mul_right a (b*c), Int.mul_assoc]

/-- `fieldMul a b` is already a canonical residue. -/
theorem fmod_fmul (a b : Int) : fieldMod (fieldMul a b) = fieldMul a b := by
  unfold fieldMul; rw [fmod_emod]

/-- `fieldPowNat a n` is already a canonical residue. -/
theorem fmod_fpow (a : Int) (n : Nat) :
    fieldMod (fieldPowNat a n) = fieldPowNat a n := by
  cases n with
  | zero => exact fmod_one
  | succ k => exact fmod_fmul a (fieldPowNat a k)

/-- `fieldMul x 1 = fieldMod x`. -/
theorem fmul_one_right (x : Int) : fieldMul x 1 = fieldMod x := by
  unfold fieldMul; rw [Int.mul_one]

/-- `fieldMul (fieldMod a) b = fieldMul a b`. -/
theorem fmul_left_fieldMod (a b : Int) :
    fieldMul (fieldMod a) b = fieldMul a b := by
  unfold fieldMul; rw [fmod_mul_left]

/-- `fieldMul a (fieldMod b) = fieldMul a b`. -/
theorem fmul_right_fieldMod (a b : Int) :
    fieldMul a (fieldMod b) = fieldMul a b := by
  unfold fieldMul; rw [fmod_mul_right]

/-- **Exponent addition law:** `a^(m+n) = a^m · a^n` (mod p).  Genuine induction on `n`. -/
theorem fpow_add (a : Int) (m n : Nat) :
    fieldPowNat a (m + n) = fieldMul (fieldPowNat a m) (fieldPowNat a n) := by
  induction n with
  | zero =>
    show fieldPowNat a m = _
    show _ = fieldMul (fieldPowNat a m) 1
    rw [fmul_one_right, fmod_fpow]
  | succ k ih =>
    show fieldPowNat a (m+k+1) = _
    show fieldMul a (fieldPowNat a (m+k)) = _
    rw [ih]
    show _ = fieldMul (fieldPowNat a m) (fieldMul a (fieldPowNat a k))
    rw [← fmul_assoc, fmul_comm a (fieldPowNat a m), fmul_assoc]

/-- `a^1 = fieldMod a`. -/
theorem fpow_one (a : Int) : fieldPowNat a 1 = fieldMod a := by
  show fieldMul a (fieldPowNat a 0) = _
  show fieldMul a 1 = _
  rw [fmul_one_right]

/-- `(fieldMod a)^n = a^n` — the spec's `fieldInv` `fieldMod`s its input first; the
codegen multiplies by the raw input.  Both yield the same power. -/
theorem fpow_fieldMod (a : Int) (n : Nat) :
    fieldPowNat (fieldMod a) n = fieldPowNat a n := by
  induction n with
  | zero => rfl
  | succ k ih =>
    show fieldMul (fieldMod a) (fieldPowNat (fieldMod a) k) = fieldMul a (fieldPowNat a k)
    rw [ih, fmul_left_fieldMod]

/-- **One square-and-multiply step:** `(a^e)² · a = a^(2e+1)`. -/
theorem one_high_step (a : Int) (e : Nat) :
    fieldMul (fieldMul (fieldPowNat a e) (fieldPowNat a e)) a = fieldPowNat a (2*e + 1) := by
  rw [show 2*e+1 = 1 + (e+e) from by omega, fpow_add, fpow_add]
  show _ = fieldMul (fieldPowNat a 1) (fieldMul (fieldPowNat a e) (fieldPowNat a e))
  rw [fmul_comm (fieldPowNat a 1), fpow_one, fmul_right_fieldMod]

/-- **One square step:** `(a^e)² = a^(2e)`. -/
theorem one_sqr_step (a : Int) (e : Nat) :
    fieldMul (fieldPowNat a e) (fieldPowNat a e) = fieldPowNat a (2*e) := by
  rw [show 2*e = e + e from by omega, fpow_add]

/-- Spec-level high loop: `n` iterations of `r := (r² · a)` (each bit = 1).  Mirrors
`Stack.Ec.fieldInvHighLoop`'s value transformation. -/
def samHigh (a : Int) : Nat → Int → Int
  | 0,     r => r
  | n + 1, r => samHigh a n (fieldMul (fieldMul r r) a)

/-- Exponent after `n` high iters from start exp `e` (each step `e ↦ 2e+1`). -/
def highExpN : Nat → Nat → Nat
  | 0,     e => e
  | n + 1, e => highExpN n (2*e + 1)

/-- **High-loop correctness:** from `r = a^e`, `n` iters give `a^(highExpN n e)`.
Genuine induction on `n` via `one_high_step`. -/
theorem samHigh_pow (a : Int) (n : Nat) :
    ∀ e : Nat, samHigh a n (fieldPowNat a e) = fieldPowNat a (highExpN n e) := by
  induction n with
  | zero => intro e; rfl
  | succ k ih =>
    intro e
    show samHigh a k (fieldMul (fieldMul (fieldPowNat a e) (fieldPowNat a e)) a) = _
    rw [one_high_step, ih]; rfl

/-- Spec-level low loop: `steps` iters, MSB-first over `lowBits`; each iter squares,
and multiplies by `a` when the current bit is set.  Mirrors `fieldInvLowLoop`. -/
def samLow (a lowBits : Int) : Nat → Int → Int
  | 0,     r => r
  | k + 1, r =>
    let r2 := fieldMul r r
    let r' := if ((lowBits / (2 ^ k)) % 2) = 1 then fieldMul r2 a else r2
    samLow a lowBits k r'

/-- Exponent after `steps` low iters (each `e ↦ 2e + bit_k`). -/
def lowExpN (lowBits : Int) : Nat → Nat → Nat
  | 0,     e => e
  | k + 1, e => lowExpN lowBits k (2*e + (if ((lowBits / (2 ^ k)) % 2) = 1 then 1 else 0))

/-- **Low-loop correctness:** from `r = a^e`, `steps` iters give `a^(lowExpN …)`.
Genuine induction on `steps` (case-split on each bit) via `one_high_step`/`one_sqr_step`. -/
theorem samLow_pow (a lowBits : Int) (steps : Nat) :
    ∀ e : Nat, samLow a lowBits steps (fieldPowNat a e)
      = fieldPowNat a (lowExpN lowBits steps e) := by
  induction steps with
  | zero => intro e; rfl
  | succ k ih =>
    intro e
    show samLow a lowBits k
          (if ((lowBits / (2 ^ k)) % 2) = 1
           then fieldMul (fieldMul (fieldPowNat a e) (fieldPowNat a e)) a
           else fieldMul (fieldPowNat a e) (fieldPowNat a e)) = _
    by_cases hb : ((lowBits / (2 ^ k)) % 2) = 1
    · rw [if_pos hb, one_high_step, ih]
      show fieldPowNat a (lowExpN lowBits k (2*e+1)) = fieldPowNat a (lowExpN lowBits (k+1) e)
      congr 1
      show _ = lowExpN lowBits k (2*e + (if ((lowBits / (2 ^ k)) % 2) = 1 then 1 else 0))
      rw [if_pos hb]
    · rw [if_neg hb, one_sqr_step, ih]
      show fieldPowNat a (lowExpN lowBits k (2*e)) = fieldPowNat a (lowExpN lowBits (k+1) e)
      congr 1
      show lowExpN lowBits k (2*e)
            = lowExpN lowBits k (2*e + (if ((lowBits / (2 ^ k)) % 2) = 1 then 1 else 0))
      rw [if_neg hb, Nat.add_zero]

/-- Closed form for `highExpN` (avoids `Nat` subtraction): `highExpN n e + 1 = 2^n·(e+1)`. -/
theorem highExpN_succ_closed (n e : Nat) : highExpN n e + 1 = 2^n * (e+1) := by
  induction n generalizing e with
  | zero => show e + 1 = 2^0 * (e+1); rw [Nat.pow_zero, Nat.one_mul]
  | succ k ih =>
    show highExpN k (2*e+1) + 1 = 2^(k+1) * (e+1)
    rw [ih (2*e+1), Nat.pow_succ, show 2*e+1+1 = 2*(e+1) from by omega,
        ← Nat.mul_assoc, Nat.mul_comm (2^k) 2, Nat.mul_assoc]

/-- `lowExpN` splits its start exponent: `lowExpN bits s e = 2^s·e + lowExpN bits s 0`. -/
theorem lowExpN_split (lowBits : Int) (steps e : Nat) :
    lowExpN lowBits steps e = 2^steps * e + (lowExpN lowBits steps 0) := by
  induction steps generalizing e with
  | zero => show e = 2^0 * e + 0; rw [Nat.pow_zero, Nat.one_mul, Nat.add_zero]
  | succ k ih =>
    show lowExpN lowBits k (2*e + (if ((lowBits / (2 ^ k)) % 2) = 1 then 1 else 0))
          = 2^(k+1) * e + lowExpN lowBits k (2*0 + (if ((lowBits / (2 ^ k)) % 2) = 1 then 1 else 0))
    rw [ih (2*e + (if ((lowBits / (2 ^ k)) % 2) = 1 then 1 else 0))]
    rw [ih (2*0 + (if ((lowBits / (2 ^ k)) % 2) = 1 then 1 else 0))]
    rw [Nat.pow_succ, Nat.mul_zero, Nat.zero_add, Nat.mul_add,
        show 2^k * (2*e) = 2^k * 2 * e from by rw [← Nat.mul_assoc]]
    omega

/-- `highExpN 222 1 = 2^223 − 1` (the 223 high bits 255..33). -/
theorem highExpN_222_1 : highExpN 222 1 = 2^223 - 1 := by
  have h := highExpN_succ_closed 222 1
  rw [show (1:Nat)+1 = 2 from rfl] at h
  rw [show 2^222 * 2 = 2^223 from by rw [Nat.pow_succ]] at h
  omega

set_option maxRecDepth 2048 in
/-- `lowExpN 0xFFFFFC2D 32 0 = 0xFFFFFC2D` — the low 32 bits decode to their value.
`decide` is a kernel reduction of a 32-step recursion (concrete, no `ofReduceBool`). -/
theorem lowExpN_val : lowExpN 0xFFFFFC2D 32 0 = 0xFFFFFC2D := by decide

set_option maxRecDepth 4096 in
/-- `(FIELD_P − 2).toNat = 2^256 − 2^33 + 0xFFFFFC2D` — the constant exponent's value
in power form.  `decide` on a concrete numeral identity (no `ofReduceBool`). -/
theorem fieldPm2_toNat : (FIELD_P - 2).toNat = 2^256 - 2^33 + 0xFFFFFC2D := by decide

set_option maxRecDepth 4096 in
/-- **The constant exponent assembles:** `lowExpN 0xFFFFFC2D 32 (2 · highExpN 222 1)
= (FIELD_P − 2).toNat`.  Concrete arithmetic on the constant exponent's bit pattern. -/
theorem final_exp_eq :
    lowExpN 0xFFFFFC2D 32 (2 * highExpN 222 1) = (FIELD_P - 2).toNat := by
  rw [lowExpN_split, lowExpN_val, highExpN_222_1, fieldPm2_toNat]

/-- `a³ = (a · a) · a` (the codegen's first high step from the RAW input `a`, whose
`fieldMod` only kicks in from the first `fieldMul`). -/
theorem cube_eq (a : Int) : fieldMul (fieldMul a a) a = fieldPowNat a 3 := by
  rw [show (3:Nat) = 1 + (1 + 1) from rfl, fpow_add, fpow_add]
  show fieldMul (fieldMul a a) a
        = fieldMul (fieldPowNat a 1) (fieldMul (fieldPowNat a 1) (fieldPowNat a 1))
  rw [fpow_one, fmul_right_fieldMod, fmul_left_fieldMod, fmul_left_fieldMod,
      fmul_comm (fieldMul a a) a]

/-- `highExpN (n+1) 1 = highExpN n 3` (the first high step takes exp 1 → 3). -/
theorem highExpN_succ_one (n : Nat) : highExpN (n+1) 1 = highExpN n 3 := rfl

/-- **High loop from the raw input:** `samHigh a (n+1) a = a^(highExpN (n+1) 1)`.
Bridges the RAW-`a` start (codegen) to the `fieldPowNat a 1` start (`samHigh_pow`). -/
theorem samHigh_from_a (a : Int) (n : Nat) :
    samHigh a (n+1) a = fieldPowNat a (highExpN (n+1) 1) := by
  show samHigh a n (fieldMul (fieldMul a a) a) = _
  rw [cube_eq, samHigh_pow, highExpN_succ_one]

/-- The full square-and-multiply accumulator the codegen builds, as a spec value:
start `a` → high loop 222 → one square (bit 32 = 0) → low loop 32 over `0xFFFFFC2D`. -/
def fieldInvAccum (a : Int) : Int :=
  samLow a 0xFFFFFC2D 32 (fieldMul (samHigh a 222 a) (samHigh a 222 a))

set_option maxRecDepth 4096 in
/-- **THE CRUX — `fieldInvAccum a = fieldInv a`.**  The unrolled square-and-multiply over
the constant exponent `FIELD_P − 2` computes the field inverse.  A GENUINE structural
induction over the loop structure (`samHigh_pow` / `samLow_pow` / `one_high_step` /
`one_sqr_step`) — NOT `native_decide`; the only kernel-`decide` steps are the closed-form
exponent identities for the constant exponent's bit pattern.  `propext`/`Quot.sound`
-clean, no `sorryAx`, no `ofReduceBool`. -/
theorem fieldInvAccum_eq (a : Int) : fieldInvAccum a = fieldInv a := by
  unfold fieldInvAccum
  rw [show (222:Nat) = 221+1 from rfl, samHigh_from_a, one_sqr_step, samLow_pow,
      show (221:Nat)+1 = 222 from rfl, final_exp_eq]
  unfold fieldInv
  rw [fpow_fieldMod]

/-! ### MANDATORY smokes for the `fieldInv` square-and-multiply crux

NOTE: `fieldInv a = fieldPowNat (fieldMod a) (FIELD_P − 2).toNat` is a NAIVE
exponent recursion (≈ 2²⁵⁶ steps), so it CANNOT be reduced numerically by
`native_decide`/`decide` — every smoke is therefore SYMBOLIC (firing the proven
equation) or a closed concrete fact about the loop machinery / exponent. -/

/-- SMOKE (the crux FIRES on a concrete value).  `fieldInvAccum 7 = fieldInv 7`
(symbolic — instantiates the proven equation, no exponent reduction). -/
theorem smoke_fieldInvAccum_eq : fieldInvAccum 7 = fieldInv 7 := fieldInvAccum_eq 7

/-- SMOKE (anti-vacuity of the exponent — the constant exponent is genuinely the FULL
`FIELD_P − 2`, ≈ 2²⁵⁶, not a degenerate small value).  Concrete closed fact. -/
theorem smoke_final_exp_huge : (2 : Nat) ^ 255 < lowExpN 0xFFFFFC2D 32 (2 * highExpN 222 1) := by
  rw [final_exp_eq, fieldPm2_toNat]
  have h : (2:Nat)^255 ≤ 2^256 := Nat.pow_le_pow_right (by omega) (by omega)
  rw [show (2:Nat)^256 = 2 * 2^255 from by rw [Nat.pow_succ, Nat.mul_comm],
      show (2:Nat)^33 = 2 * 2^32 from by rw [Nat.pow_succ, Nat.mul_comm]]
  have h32 : (2:Nat)^32 ≤ 2^255 := Nat.pow_le_pow_right (by omega) (by omega)
  omega

/-- SMOKE (anti-vacuity — the accumulator is one-square-and-multiply chain, not a no-op:
the high loop alone applies a genuine `2e+1` per step).  `highExpN 1 0 = 1`,
`highExpN 2 0 = 3` (square-and-multiply doubles-plus-one). -/
theorem smoke_highExpN_nontrivial : highExpN 1 0 = 1 ∧ highExpN 2 0 = 3 := by
  constructor <;> rfl

/-- SMOKE (loop value firing — one high step on `a = 7` from exp 0 lands `7³`). -/
theorem smoke_samHigh_one : samHigh 7 1 7 = fieldPowNat 7 3 := samHigh_from_a 7 0

end FieldInvSpec

/-! ### `rename` (`set!`) `TrackerSim` transport — the runtime-threading building block

The codegen's `fieldInvHighLoop`/`fieldInvLowLoop` re-`rename` the freshly-produced
`_inv_r2` / `_inv_m` scratch slot back to `_inv_r` each iteration.  Crucially the PRIOR
`_inv_r` is already CONSUMED by the `fieldSqr`/`fieldMul` `rawBlock`s before the rename
fires, so the rename targets the (locally) FRESH top slot — `Tracker.rename` is
`nm.set! (nm.size - 1)`, a top-slot relabel with the runtime stack UNCHANGED.  Part 13
shipped `roll`/`pick` (`toTop`/`copyToTop`) `TrackerSim` preservation but no `set!`
(rename) peer; these three lemmas fill that gap and are the first concrete step of the
`fieldInv_runOps_sim` runtime transport (the remaining gap, documented below). -/

/-- `(nm.push x).set! (size-1) y = nm.push y` — relabel the top slot. -/
theorem push_set_top (nm : Array (Option String)) (x y : Option String) :
    (nm.push x).set! ((nm.push x).size - 1) y = nm.push y := by
  unfold Array.set!
  apply Array.ext
  · rw [Array.size_setIfInBounds, Array.size_push, Array.size_push]
  · intro i h1 h2
    rw [Array.size_setIfInBounds, Array.size_push] at h1
    have hib : i < (nm.push x).size := by rw [Array.size_push]; omega
    rw [Array.getElem_setIfInBounds hib]
    by_cases ht : i = nm.size
    · subst ht
      have he : (nm.push x).size - 1 = nm.size := by rw [Array.size_push]; omega
      simp only [he, ite_true]
      rw [Array.getElem_push_eq]
    · have hlt : i < nm.size := by omega
      have hne : ((nm.push x).size - 1 = i) = False := by
        rw [Array.size_push]; simp; omega
      simp only [hne, ite_false]
      rw [Array.getElem_push_lt hlt, Array.getElem_push_lt hlt]

/-- **`TrackerSim` drops a top slot.**  A push-then-`TrackerSim` reduces to a
`TrackerSim` on the base name array + the popped runtime stack. -/
theorem TrackerSim_pop (nm : Array (Option String)) (σ : String → Value)
    (stk : List Value) (top : Value) (old : String)
    (hSim : TrackerSim (nm.push (some old)) σ (top :: stk)) :
    TrackerSim nm σ stk := by
  obtain ⟨hlen, hslot⟩ := hSim
  rw [Array.size_push] at hlen
  refine ⟨by simp at hlen ⊢; omega, ?_⟩
  intro i hi
  have hi' : i < (nm.push (some old)).size := by rw [Array.size_push]; omega
  have hag := hslot i hi'
  rw [Array.getElem_push_lt hi] at hag
  have hsz : (nm.push (some old)).size = nm.size + 1 := Array.size_push ..
  rw [hsz] at hag
  have hcons : nm.size + 1 - 1 - i = (nm.size - 1 - i) + 1 := by omega
  rw [hcons, List.getElem!_cons_succ] at hag
  exact hag

/-- **`rename` `TrackerSim` transport (the missing `set!` peer).**  `Tracker.rename n`
relabels the top slot to `n` (fresh in the base array) and emits NO runtime op, so the
stack is unchanged; the model `σ` is updated at `n` to the top value.  Reduces to
`TrackerSim_pop` + `TrackerSim_push` via `push_set_top`. -/
theorem TrackerSim_rename (nm : Array (Option String)) (σ : String → Value)
    (stk : List Value) (top : Value) (old n : String)
    (hSim : TrackerSim (nm.push (some old)) σ (top :: stk))
    (hfresh : some n ∉ nm.toList) :
    TrackerSim ((nm.push (some old)).set! ((nm.push (some old)).size - 1) (some n))
      (fun u => if u = n then top else σ u) (top :: stk) := by
  rw [push_set_top]
  exact TrackerSim_push nm σ stk n top (TrackerSim_pop nm σ stk top old hSim) hfresh

/-! ### MANDATORY smokes for the `rename` transport -/

/-- Concrete base valuation for the rename smoke: `"a" ↦ 10`, `"b" ↦ 20`. -/
private def rnσ : String → Value
  | "a" => .vBigint 10
  | "b" => .vBigint 20
  | _   => .vBigint 0

/-- The pre-rename `TrackerSim`: nm `#[a, b]`, runtime `[20, 10]` (top = b = 20). -/
theorem smoke_rnSim_pre :
    TrackerSim (#[some "a"].push (some "b")) rnσ [.vBigint 20, .vBigint 10] := by
  refine ⟨rfl, ?_⟩
  intro i hi
  have hsz : (#[some "a"].push (some "b")).size = 2 := rfl
  rw [hsz] at hi
  match i, hi with
  | 0, _ =>
    show slotAgrees rnσ (some "a") (Value.vBigint 10)
    unfold slotAgrees rnσ; rfl
  | 1, _ =>
    show slotAgrees rnσ (some "b") (Value.vBigint 20)
    unfold slotAgrees rnσ; rfl

/-- SMOKE (rename transport FIRES).  Relabel the top `"b"` to fresh `"c"`: the model
`σ' "c" = 20` (the top value), `σ'` unchanged on `"a"`; runtime stack unchanged. -/
theorem smoke_TrackerSim_rename :
    TrackerSim ((#[some "a"].push (some "b")).set! ((#[some "a"].push (some "b")).size - 1) (some "c"))
      (fun u => if u = "c" then (.vBigint 20) else rnσ u) [.vBigint 20, .vBigint 10] :=
  TrackerSim_rename #[some "a"] rnσ [.vBigint 10] (.vBigint 20) "b" "c" smoke_rnSim_pre (by decide)

/-- SMOKE (`push_set_top` value anti-vacuity).  Relabel really replaces the top name. -/
theorem smoke_push_set_top :
    (#[some "a"].push (some "b")).set! ((#[some "a"].push (some "b")).size - 1) (some "c")
      = #[some "a", some "c"] := by rw [push_set_top]; rfl

/-! ### `fieldInv` LOOP runtime inductions (deliverable 1 — the 254-iter crux, LANDED)

The `emitEcAdd` discharge's hardest piece — the documented blocking sub-goal — was the
"254-iteration deep-depth `TrackerSimT` induction" for the unrolled `fieldInv`.  The
earlier hand-off feared the `copyToTop aName` inside each loop iteration resolved to a
DEEP, ITERATION-DEPENDENT `findDepthList` depth (the `aName` slot sinking as scratch
churns).  **That fear was WRONG, and discovering so is what unblocks the crux:** the
codegen's per-iteration `rename "_inv_r"` collapses each freshly-produced scratch slot
(`_inv_r2`/`_inv_m`) back onto the TOP slot, and the `fieldSqr`/`fieldMul` `rawBlock`s
CONSUME their scratch inputs, so the tracker `nm` is a genuine **FIXED POINT** across every
iteration — `_inv_r` stays at depth 0 and `aName` at depth 1 for all 254 iterations
(verified: `(fieldInvHighLoop n tInv0 aName).nm = tInv0.nm`).  The per-iteration runtime
op-list is therefore a CONSTANT determined increment, NOT depth-varying.

Consequently the runtime side reduces to two clean STRUCTURAL inductions on the loop
count — the genuine 222-iter (high) + 32-iter (low) square-and-multiply runtime threading,
landing the spec accumulators `FieldInvSpec.samHigh`/`samLow` (whose composition is
`fieldInvAccum a = fieldInv a`, the proven crux).  Each per-iteration increment is the
SAME `fieldSqrYInc`(+`over`+`fieldMulSwap2Inc`) chunk discharged for `emitEcOnCurve`. -/

/-- Non-`ifOp` guards for the `fieldInv` increment ops. -/
private theorem niSwapInv : ∀ t e, StackOp.swap ≠ .ifOp t e := by intro t e h; cases h
private theorem niOverInv : ∀ t e, StackOp.over ≠ .ifOp t e := by intro t e h; cases h

open Crypto.Secp256k1 (fieldMul) in
/-- `[swap, swap, OP_MUL, push fieldP] ++ fieldModOps` — the per-iteration second
`fieldMul "_inv_r" "_inv_a"` increment (both `toTop`s at depth 1, product depth 0). -/
def fieldMulSwap2Inc : List StackOp :=
  [.swap, .swap, .opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps

open Crypto.Secp256k1 (fieldMul) in
/-- `fieldMulSwap2Inc` on `[a, b] ++ rest` → `fieldMul b a :: rest` (the two `swap`s
cancel; `OP_MUL` then multiplies the top two `a, b` as `fieldMul b a`). -/
theorem fieldMulSwap2_runOps_sim (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = (.vBigint a) :: (.vBigint b) :: rest) :
    runOps fieldMulSwap2Inc s
      = .ok { s with stack := .vBigint (fieldMul b a) :: rest } := by
  unfold fieldMulSwap2Inc
  rw [show ([StackOp.swap, .swap, .opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps)
        = StackOp.swap :: .swap :: ([.opcode "OP_MUL", .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps) from rfl]
  rw [runOps_cons_nonIf_eq _ _ _ niSwapInv, stepNonIf_swap]
  rw [show applySwap s = .ok { s with stack := (.vBigint b) :: (.vBigint a) :: rest } by
        unfold applySwap; rw [hStk]]
  simp only [match_Except_ok_runOps]
  rw [runOps_cons_nonIf_eq _ _ _ niSwapInv, stepNonIf_swap]
  rw [show applySwap { s with stack := (.vBigint b) :: (.vBigint a) :: rest }
        = .ok { s with stack := (.vBigint a) :: (.vBigint b) :: rest } from rfl]
  simp only [match_Except_ok_runOps]
  rw [fieldMul_optail_transport { s with stack := (.vBigint a) :: (.vBigint b) :: rest }
        b a rest rfl]

/-- One high-loop iteration's determined runtime op-list: `fieldSqr` (square `_inv_r`),
`over` (copy `aName`, depth 1), `fieldMul` (multiply `_inv_r·_inv_a`). -/
def oneHighIterInc : List StackOp :=
  fieldSqrYInc ++ [.over] ++ fieldMulSwap2Inc

open Crypto.Secp256k1 (fieldMul) in
/-- **One high iteration's runtime sim.**  On `[r, a] ++ rest`, lands
`[fieldMul (fieldMul r r) a, a] ++ rest` — precisely `samHigh`'s per-step value transform
`r ↦ (r²)·a`, keeping the base `a` at depth 1 for the next iteration's `over`. -/
theorem oneHighIter_runOps_sim (s : StackState) (r a : Int) (rest : List Value)
    (hStk : s.stack = (.vBigint r) :: (.vBigint a) :: rest) :
    runOps oneHighIterInc s
      = .ok { s with stack := .vBigint (fieldMul (fieldMul r r) a) :: (.vBigint a) :: rest } := by
  unfold oneHighIterInc
  simp only [List.append_assoc, List.cons_append, List.nil_append]
  rw [runOps_append, fieldSqr_runOps_sim s r a rest hStk]
  simp only [match_Except_ok_runOps]
  rw [runOps_cons_nonIf_eq _ _ _ niOverInv,
      show stepNonIf .over { s with stack := (.vBigint (fieldMul r r)) :: (.vBigint a) :: rest }
        = applyOver { s with stack := (.vBigint (fieldMul r r)) :: (.vBigint a) :: rest } from rfl]
  rw [show applyOver { s with stack := (.vBigint (fieldMul r r)) :: (.vBigint a) :: rest }
        = .ok { s with stack := (.vBigint a) :: (.vBigint (fieldMul r r)) :: (.vBigint a) :: rest } from rfl]
  simp only [match_Except_ok_runOps]
  rw [fieldMulSwap2_runOps_sim { s with stack := (.vBigint a) :: (.vBigint (fieldMul r r)) :: (.vBigint a) :: rest }
        a (fieldMul r r) ((.vBigint a) :: rest) rfl]

/-- The unrolled high-loop runtime op-list: `n` copies of `oneHighIterInc`. -/
def highLoopInc (n : Nat) : List StackOp := (List.replicate n oneHighIterInc).flatten

open Crypto.Secp256k1 (fieldMul) in
open FieldInvSpec (samHigh) in
/-- **THE 222-ITERATION HIGH-LOOP RUNTIME INDUCTION (deliverable 1, crux high half).**
Running `n` copies of the determined per-iteration increment on `[r, a] ++ rest` lands the
spec accumulator `samHigh a n r` on top, with `a` preserved at depth 1.  A GENUINE
structural induction on `n` — each step `oneHighIter_runOps_sim` + the `samHigh` step
equation.  No `native_decide`, no shortcut: the actual 254-iter loop induction the
hand-off named as the crux. -/
theorem highLoopInc_runOps_sim (n : Nat) (a : Int) :
    ∀ (r : Int) (s : StackState) (rest : List Value),
      s.stack = (.vBigint r) :: (.vBigint a) :: rest →
      runOps (highLoopInc n) s
        = .ok { s with stack := .vBigint (samHigh a n r) :: (.vBigint a) :: rest } := by
  induction n with
  | zero =>
    intro r s rest hStk
    show runOps (highLoopInc 0) s = _
    unfold highLoopInc
    simp only [List.replicate, List.flatten, runOps_nil]
    show Except.ok s = _
    show _ = Except.ok { s with stack := .vBigint (samHigh a 0 r) :: (.vBigint a) :: rest }
    rw [show samHigh a 0 r = r from rfl, ← hStk]
  | succ k ih =>
    intro r s rest hStk
    unfold highLoopInc
    rw [show List.replicate (k+1) oneHighIterInc = oneHighIterInc :: List.replicate k oneHighIterInc from rfl]
    rw [List.flatten_cons]
    rw [runOps_append, oneHighIter_runOps_sim s r a rest hStk]
    simp only [match_Except_ok_runOps]
    have hnext := ih (fieldMul (fieldMul r r) a)
        { s with stack := .vBigint (fieldMul (fieldMul r r) a) :: (.vBigint a) :: rest } rest rfl
    rw [show (highLoopInc k) = (List.replicate k oneHighIterInc).flatten from rfl] at hnext
    rw [hnext, show samHigh a (k+1) r = samHigh a k (fieldMul (fieldMul r r) a) from rfl]

open Crypto.Secp256k1 (fieldMul) in
/-- One low-loop iteration's determined op-list: square always, multiply iff `c` (the
current bit is set).  `c` is a `Prop` so the `if` matches `samLow`'s `if … = 1` exactly. -/
def oneLowIterInc (c : Prop) [Decidable c] : List StackOp :=
  if c then oneHighIterInc else fieldSqrYInc

open Crypto.Secp256k1 (fieldMul) in
/-- Square-only step on `[r, a] ++ rest` → `[fieldMul r r, a] ++ rest`. -/
theorem fieldSqrOnly_runOps_sim (s : StackState) (r a : Int) (rest : List Value)
    (hStk : s.stack = (.vBigint r) :: (.vBigint a) :: rest) :
    runOps fieldSqrYInc s
      = .ok { s with stack := .vBigint (fieldMul r r) :: (.vBigint a) :: rest } :=
  fieldSqr_runOps_sim s r a rest hStk

open Crypto.Secp256k1 (fieldMul) in
/-- One low-loop iteration's runtime sim: `[r, a] ++ rest` →
`[if c then (r²)·a else r², a] ++ rest` — `samLow`'s per-step value transform. -/
theorem oneLowIter_runOps_sim (c : Prop) [Decidable c] (s : StackState) (r a : Int) (rest : List Value)
    (hStk : s.stack = (.vBigint r) :: (.vBigint a) :: rest) :
    runOps (oneLowIterInc c) s
      = .ok { s with stack := Value.vBigint (if c then fieldMul (fieldMul r r) a else fieldMul r r) :: (.vBigint a) :: rest } := by
  unfold oneLowIterInc
  by_cases hc : c
  · rw [if_pos hc, if_pos hc]; exact oneHighIter_runOps_sim s r a rest hStk
  · rw [if_neg hc, if_neg hc]; exact fieldSqrOnly_runOps_sim s r a rest hStk

/-- The unrolled low-loop runtime op-list: MSB-first `steps` iterations over `lowBits`. -/
def lowLoopInc (steps : Nat) (lowBits : Int) : List StackOp :=
  match steps with
  | 0     => []
  | k + 1 => oneLowIterInc (((lowBits / (2 ^ k)) % 2) = 1) ++ lowLoopInc k lowBits

open Crypto.Secp256k1 (fieldMul) in
open FieldInvSpec (samLow) in
/-- **THE 32-ITERATION LOW-LOOP RUNTIME INDUCTION (deliverable 1, crux low half).**
Running the determined per-iteration increments (each squares, conditionally multiplies on
the current bit of `lowBits`) on `[r, a] ++ rest` lands the spec accumulator
`samLow a lowBits steps r`.  A GENUINE structural induction on `steps`, each step a
`by_cases` on the current bit mirroring `samLow`'s recursion. -/
theorem lowLoopInc_runOps_sim (steps : Nat) (a lowBits : Int) :
    ∀ (r : Int) (s : StackState) (rest : List Value),
      s.stack = (.vBigint r) :: (.vBigint a) :: rest →
      runOps (lowLoopInc steps lowBits) s
        = .ok { s with stack := .vBigint (samLow a lowBits steps r) :: (.vBigint a) :: rest } := by
  induction steps with
  | zero =>
    intro r s rest hStk
    show runOps (lowLoopInc 0 lowBits) s = _
    show runOps [] s = _
    rw [runOps_nil]
    show Except.ok s = _
    show _ = Except.ok { s with stack := .vBigint (samLow a lowBits 0 r) :: (.vBigint a) :: rest }
    rw [show samLow a lowBits 0 r = r from rfl, ← hStk]
  | succ k ih =>
    intro r s rest hStk
    show runOps (lowLoopInc (k+1) lowBits) s = _
    show runOps (oneLowIterInc (((lowBits / (2 ^ k)) % 2) = 1) ++ lowLoopInc k lowBits) s = _
    rw [runOps_append, oneLowIter_runOps_sim (((lowBits / (2 ^ k)) % 2) = 1) s r a rest hStk]
    simp only [match_Except_ok_runOps]
    have hnext := ih (if ((lowBits / (2 ^ k)) % 2) = 1 then fieldMul (fieldMul r r) a else fieldMul r r)
        { s with stack := Value.vBigint (if ((lowBits / (2 ^ k)) % 2) = 1 then fieldMul (fieldMul r r) a else fieldMul r r) :: (.vBigint a) :: rest } rest rfl
    rw [hnext]
    show _ = Except.ok { s with stack := .vBigint (samLow a lowBits (k+1) r) :: (.vBigint a) :: rest }
    rw [show samLow a lowBits (k+1) r
          = samLow a lowBits k (if ((lowBits / (2 ^ k)) % 2) = 1 then fieldMul (fieldMul r r) a else fieldMul r r) from rfl]

/-! ### MANDATORY smokes for the `fieldInv` loop runtime inductions (deliverable 1) -/

private def invSmokeRest : List Value := [Value.vBigint 888]

open FieldInvSpec (samHigh) in
/-- SMOKE (high-loop induction FIRES, anti-vacuity).  3 high iters on `[2, 5] ++ rest`
land `samHigh 5 3 2`, with `5` (the base `a`) preserved at depth 1. -/
theorem smoke_highLoopInc_runOps_sim :
    runOps (highLoopInc 3)
        { (default : StackState) with stack := [.vBigint 2, .vBigint 5] ++ invSmokeRest }
      = .ok { (default : StackState) with
              stack := .vBigint (samHigh 5 3 2) :: .vBigint 5 :: invSmokeRest } :=
  highLoopInc_runOps_sim 3 5 2 _ invSmokeRest rfl

open FieldInvSpec (samHigh) in
/-- SMOKE (high-loop value is a genuine square-and-multiply, not a no-op).
`samHigh 5 1 2 = fieldMul (fieldMul 2 2) 5 = 20`. -/
theorem smoke_samHigh_value : samHigh 5 1 2 = 20 := by native_decide

open FieldInvSpec (samLow) in
/-- SMOKE (low-loop induction FIRES).  4 low iters over `lowBits = 0b1010 = 10` on
`[2, 5] ++ rest` land `samLow 5 10 4 2` (squares 4×, multiplies on bits 3 and 1). -/
theorem smoke_lowLoopInc_runOps_sim :
    runOps (lowLoopInc 4 10)
        { (default : StackState) with stack := [.vBigint 2, .vBigint 5] ++ invSmokeRest }
      = .ok { (default : StackState) with
              stack := .vBigint (samLow 5 10 4 2) :: .vBigint 5 :: invSmokeRest } :=
  lowLoopInc_runOps_sim 4 5 10 2 _ invSmokeRest rfl

open FieldInvSpec (samLow) in
/-- SMOKE (low-loop conditional multiply is real).  Bit set → square-and-multiply
(`samLow 5 1 1 2 = 20`); bit clear → square-only (`samLow 5 0 1 2 = 4`). -/
theorem smoke_samLow_cond : samLow 5 1 1 2 = 20 ∧ samLow 5 0 1 2 = 4 := by native_decide

/-! ### Deliverable 1 — `fieldInv` runtime sim (the determined op-list, depth-0 entry)

The codegen `fieldInv` (`Stack/Ec.lean:356`) on a depth-0 input (`aName` at TOS, the
affineAdd entry: `_s_den` was just produced) runs:

* prelude `copyToTop aName "_inv_r"` at depth 0 = `.dup`  →  `[a, a] ++ rest`,
* `fieldInvHighLoop 222`  =  `highLoopInc 222`,
* bit 32: `fieldSqr "_inv_r" "_inv_r2"` (depth 0)  =  `fieldSqrYInc`,
* `fieldInvLowLoop 32 0xFFFFFC2D`  =  `lowLoopInc 32 0xFFFFFC2D`,
* cleanup `toTop aName` (depth 1 = `.swap`) → `.drop` → `toTop "_inv_r"` (depth 0 = nop)
  → `rename` (no op)  =  `[.swap, .drop]`.

The two loop runtime inductions (`highLoopInc_runOps_sim` / `lowLoopInc_runOps_sim`) thread
the spec accumulators `samHigh`/`samLow`, whose composition is `fieldInvAccum a = fieldInv a`
(the proven crux `fieldInvAccum_eq`), reduced to `Crypto.Secp256k1.fieldInv a`. -/

private theorem niDupInv : ∀ t e, StackOp.dup ≠ .ifOp t e := by intro t e h; cases h
private theorem niDropInv : ∀ t e, StackOp.drop ≠ .ifOp t e := by intro t e h; cases h

open Crypto.Secp256k1 (fieldMul) in
open FieldInvSpec (samHigh samLow fieldInvAccum) in
/-- The determined runtime op-list of `Stack.Ec.fieldInv` at a depth-0 input. -/
def fieldInvCoreInc : List StackOp :=
  [.dup] ++ highLoopInc 222 ++ fieldSqrYInc ++ lowLoopInc 32 0xFFFFFC2D ++ [.swap, .drop]

set_option maxRecDepth 4096 in
open Crypto.Secp256k1 (fieldMul fieldInv) in
open FieldInvSpec (samHigh samLow fieldInvAccum fieldInvAccum_eq) in
/-- **`fieldInv` runtime sim (deliverable 1).**  Running the determined depth-0 `fieldInv`
op-list on `[a] ++ rest` lands `Crypto.Secp256k1.fieldInv a :: rest` — the runtime witness
of the modular inverse the affineAdd chain threads.  Composes the prelude `dup`, the
222-iter high loop (`highLoopInc_runOps_sim`), the bit-32 square (`fieldSqr_runOps_sim`),
the 32-iter low loop (`lowLoopInc_runOps_sim`), and the `swap, drop` cleanup, reduced to
`fieldInv a` via the proven crux `fieldInvAccum_eq`.  No `native_decide`; `propext`/
`Quot.sound`-clean. -/
theorem fieldInv_runOps_sim (s : StackState) (a : Int) (rest : List Value)
    (hStk : s.stack = (.vBigint a) :: rest) :
    runOps fieldInvCoreInc s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldInv a) :: rest } := by
  unfold fieldInvCoreInc
  simp only [List.append_assoc, List.cons_append, List.nil_append]
  -- prelude: dup → [a, a] ++ rest
  rw [runOps_cons_nonIf_eq _ _ _ niDupInv, stepNonIf_dup]
  rw [show applyDup s = .ok { s with stack := (.vBigint a) :: (.vBigint a) :: rest } by
        unfold applyDup StackState.push; rw [hStk]]
  simp only [match_Except_ok_runOps]
  -- high loop 222: [a, a] ++ rest → [samHigh a 222 a, a] ++ rest
  rw [runOps_append, highLoopInc_runOps_sim 222 a a
        { s with stack := (.vBigint a) :: (.vBigint a) :: rest } rest rfl]
  simp only [match_Except_ok_runOps]
  -- bit 32 square: [samHigh a 222 a, a] ++ rest → [(samHigh a 222 a)², a] ++ rest
  rw [runOps_append, fieldSqr_runOps_sim
        { s with stack := .vBigint (FieldInvSpec.samHigh a 222 a) :: (.vBigint a) :: rest }
        (FieldInvSpec.samHigh a 222 a) a rest rfl]
  simp only [match_Except_ok_runOps]
  -- low loop 32: [(samHigh a 222 a)², a] ++ rest → [samLow a 0xFFFFFC2D 32 ((samHigh a 222 a)²), a] ++ rest
  rw [runOps_append, lowLoopInc_runOps_sim 32 a 0xFFFFFC2D
        (Crypto.Secp256k1.fieldMul (FieldInvSpec.samHigh a 222 a) (FieldInvSpec.samHigh a 222 a))
        { s with stack := .vBigint (Crypto.Secp256k1.fieldMul (FieldInvSpec.samHigh a 222 a) (FieldInvSpec.samHigh a 222 a)) :: (.vBigint a) :: rest } rest rfl]
  simp only [match_Except_ok_runOps]
  -- cleanup: swap → [a, fieldInvAccum a] ++ rest
  rw [runOps_cons_nonIf_eq _ _ _ niSwap2, stepNonIf_swap]
  rw [show applySwap
        { s with stack := .vBigint (FieldInvSpec.samLow a 0xFFFFFC2D 32 (Crypto.Secp256k1.fieldMul (FieldInvSpec.samHigh a 222 a) (FieldInvSpec.samHigh a 222 a))) :: (.vBigint a) :: rest }
        = .ok { s with stack := (.vBigint a) :: .vBigint (FieldInvSpec.samLow a 0xFFFFFC2D 32 (Crypto.Secp256k1.fieldMul (FieldInvSpec.samHigh a 222 a) (FieldInvSpec.samHigh a 222 a))) :: rest } from rfl]
  simp only [match_Except_ok_runOps]
  -- cleanup: drop → [fieldInvAccum a] ++ rest
  rw [runOps_cons_nonIf_eq _ _ _ niDropInv, stepNonIf_drop]
  rw [show applyDrop
        { s with stack := (.vBigint a) :: .vBigint (FieldInvSpec.samLow a 0xFFFFFC2D 32 (Crypto.Secp256k1.fieldMul (FieldInvSpec.samHigh a 222 a) (FieldInvSpec.samHigh a 222 a))) :: rest }
        = .ok { s with stack := .vBigint (FieldInvSpec.samLow a 0xFFFFFC2D 32 (Crypto.Secp256k1.fieldMul (FieldInvSpec.samHigh a 222 a) (FieldInvSpec.samHigh a 222 a))) :: rest } from rfl]
  simp only [match_Except_ok_runOps, runOps_nil]
  -- the accumulator IS fieldInv a (the proven crux)
  rw [show FieldInvSpec.samLow a 0xFFFFFC2D 32 (Crypto.Secp256k1.fieldMul (FieldInvSpec.samHigh a 222 a) (FieldInvSpec.samHigh a 222 a))
        = FieldInvSpec.fieldInvAccum a from rfl, FieldInvSpec.fieldInvAccum_eq a]

/-! ### MANDATORY smoke for the `fieldInv` runtime sim (deliverable 1) -/

/-- SMOKE (the `fieldInv` runtime sim FIRES, anti-vacuity).  On `[7] ++ rest`, the
determined `fieldInv` op-list lands `fieldInv 7 :: rest`, with `rest` preserved.
Symbolic — the value `fieldInv 7` is a 2²⁵⁶-step exponent recursion, so the headline is
the runtime transport itself, not a numeric reduction. -/
theorem smoke_fieldInv_runOps_sim :
    runOps fieldInvCoreInc { (default : StackState) with stack := [.vBigint 7] ++ invSmokeRest }
      = .ok { (default : StackState) with
              stack := .vBigint (Crypto.Secp256k1.fieldInv 7) :: invSmokeRest } :=
  fieldInv_runOps_sim _ 7 invSmokeRest rfl

/-! ### Deliverable 1 (cont.) — `fieldInv` op-list bridge: per-iteration ops + nm fixed-point

The runtime loop INDUCTIONS (`highLoopInc_runOps_sim` / `lowLoopInc_runOps_sim`) consume the
determined op-lists `highLoopInc n` / `lowLoopInc steps lowBits`.  The codegen loops
`fieldInvHighLoop` / `fieldInvLowLoop` emit those exact lists provided the per-iteration
tracker `nm` is a FIXED POINT — `_inv_r` at depth 0, `aName` at depth 1 for every iteration.
That fixed-point is established here, abstractly, off a `toList` shape hypothesis
`t.nm.toList = baseL ++ [some aName, some "_inv_r"]` with the six scratch names + `aName`
+ `_inv_r` fresh in `baseL`.  Each step's `nm` is tracked at the `toList` level
(`Array.ext'`), so the body returns the entry `nm` and appends exactly `oneHighIterInc`. -/

/-- The six scratch slot names the `fieldInv` body produces/consumes, plus the two
persistent slots `aName`/`"_inv_r"`. -/
def invScratch : List String :=
  ["_inv_r2", "_inv_a", "_inv_m", "_fsqr_copy", "_fmul_prod", "_fmod_p"]

/-- One high-loop iteration as a standalone `Tracker → Tracker` (mirrors the body of
`fieldInvHighLoop (n+1)`). -/
def hiIterBody (t : Ec.Tracker) (aName : String) : Ec.Tracker :=
  let t := Ec.fieldSqr t "_inv_r" "_inv_r2"
  let t := t.rename "_inv_r"
  let t := t.copyToTop aName "_inv_a"
  let t := Ec.fieldMul t "_inv_r" "_inv_a" "_inv_m"
  t.rename "_inv_r"

/-- The shape predicate for a `fieldInv` loop-entry tracker: `_inv_r` on top, `aName`
just below, the six scratch names + `aName` + `_inv_r` pairwise distinct, expressed at
the `toList` level so depth folds are concrete. -/
def InvLoopShape (t : Ec.Tracker) (baseL : List (Option String)) (aName : String) : Prop :=
  t.nm.toList = baseL ++ [some aName, some "_inv_r"]
    ∧ aName ≠ "_inv_r"
    ∧ (∀ s ∈ invScratch, some s ∉ baseL ∧ s ≠ aName ∧ s ≠ "_inv_r")
    ∧ some aName ∉ baseL ∧ some "_inv_r" ∉ baseL

/-! #### `toList`-level nm transforms (push / pop / rename / toTop-depth-0/1 / rawBlock2) -/

/-- `push` at the `toList` level: append the new slot. -/
private theorem nm_push_toList (t : Ec.Tracker) (n : Option String) :
    (t.nm.push n).toList = t.nm.toList ++ [n] := by rw [Array.toList_push]

/-- `findDepth` of the TOP slot is `0` (depth-0 fold off a `toList` ending in `some r`). -/
private theorem findDepth_top0 (t : Ec.Tracker) (L : List (Option String)) (r : String)
    (hnm : t.nm.toList = L ++ [some r]) : t.findDepth r = 0 := by
  rw [findDepth_eq_findDepthList t r
        (by rw [show t.nm.toList.reverse = some r :: L.reverse from by rw [hnm]; simp];
            exact List.mem_cons_self ..)]
  rw [show t.nm.toList.reverse = some r :: L.reverse from by rw [hnm]; simp]
  unfold findDepthList; rw [if_pos rfl]

/-- `findDepth` of the second-from-top slot is `1`, when the top slot differs. -/
private theorem findDepth_second1 (t : Ec.Tracker) (L : List (Option String)) (a r : String)
    (hnm : t.nm.toList = L ++ [some a, some r]) (hne : a ≠ r) : t.findDepth a = 1 := by
  have hrev : t.nm.toList.reverse = some r :: some a :: L.reverse := by
    rw [hnm]; simp
  rw [findDepth_eq_findDepthList t a
        (by rw [hrev]; exact List.mem_cons_of_mem _ (List.mem_cons_self ..))]
  rw [hrev]; unfold findDepthList
  rw [if_neg (by intro h; exact hne (Option.some.inj h).symm)]
  unfold findDepthList
  rw [if_pos rfl]

/-- `toTop` of the TOP slot is a no-op on `nm` (depth 0 = `roll 0`). -/
private theorem toTop_top_nm (t : Ec.Tracker) (L : List (Option String)) (r : String)
    (hnm : t.nm.toList = L ++ [some r]) : (t.toTop r).nm.toList = t.nm.toList := by
  have hsz : 0 < t.nm.size := by
    rw [← Array.length_toList, hnm, List.length_append]; simp
  rw [toTop_nm_canonical t r 0 (findDepth_top0 t L r hnm) hsz]
  rw [Array.toList_push, Array.toList_eraseIdxIfInBounds]
  rw [show t.nm.size - 1 - 0 = t.nm.toList.length - 1 from by rw [Array.length_toList]; omega,
      arr_getElemBang_toList t.nm (t.nm.toList.length - 1) (by rw [Array.length_toList] at *; omega)]
  exact eraseLast_append t.nm.toList (by rw [Array.length_toList]; omega)

/-- `toTop` of the second-from-top slot swaps the top two (depth 1). -/
private theorem toTop_second_nm (t : Ec.Tracker) (L : List (Option String)) (a r : String)
    (hnm : t.nm.toList = L ++ [some a, some r]) (hne : a ≠ r) :
    (t.toTop a).nm.toList = L ++ [some r, some a] := by
  have hsz1 : 1 < t.nm.size := by
    rw [← Array.length_toList, hnm, List.length_append]; simp
  rw [toTop_nm_canonical t a 1 (findDepth_second1 t L a r hnm hne) hsz1]
  rw [Array.toList_push, Array.toList_eraseIdxIfInBounds]
  have hlen : t.nm.toList.length = L.length + 2 := by rw [hnm, List.length_append]; simp
  rw [show t.nm.size - 1 - 1 = t.nm.toList.length - 2 from by rw [Array.length_toList]; omega]
  rw [arr_getElemBang_toList t.nm (t.nm.toList.length - 2) (by rw [Array.length_toList]; omega)]
  rw [hnm]
  rw [show (L ++ [some a, some r]).length - 2 = L.length from by rw [List.length_append]; simp]
  rw [show (L ++ [some a, some r])[L.length]! = some a from by
        rw [getElem!_pos _ L.length (by rw [List.length_append]; simp),
            List.getElem_append_right (by omega)]; simp]
  rw [List.eraseIdx_append_of_length_le (by omega)]
  simp

/-- `rename "_inv_r"` of a top slot relabels the last entry to `some "_inv_r"`. -/
private theorem rename_invr_nm (t : Ec.Tracker) (L : List (Option String)) (x : Option String)
    (hnm : t.nm.toList = L ++ [x]) :
    (t.rename "_inv_r").nm.toList = L ++ [some "_inv_r"] := by
  unfold Ec.Tracker.rename
  have hsz : t.nm.size > 0 := by rw [← Array.length_toList, hnm, List.length_append]; simp
  rw [if_pos hsz]
  rw [Array.set!, Array.toList_setIfInBounds, hnm]
  rw [show t.nm.size - 1 = L.length from by rw [← Array.length_toList, hnm, List.length_append]; simp]
  rw [List.set_append_right (s := L) (t := [x]) L.length (some "_inv_r") (Nat.le_refl _)]; simp

/-- `rawBlock 2 (some n)` at the `toList` level: drop the last two, append `some n`. -/
private theorem rawBlock2_nm_toList (t : Ec.Tracker) (n : String) (e : List StackOp)
    (L : List (Option String)) (x y : Option String) (hnm : t.nm.toList = L ++ [x, y]) :
    (t.rawBlock 2 (some n) e).nm.toList = L ++ [some n] := by
  rw [rawBlock_nm_some2, Array.toList_push, Array.toList_pop, Array.toList_pop, hnm]
  simp

/-- `copyToTop name n'` at the `toList` level (push, depth-uniform). -/
private theorem copyToTop_nm_toList (t : Ec.Tracker) (name n' : String) :
    (t.copyToTop name n').nm.toList = t.nm.toList ++ [some n'] := by
  rw [Ec.Tracker.copyToTop, pick_nm_push, Array.toList_push]

/-- `rename` preserves `ops`. -/
private theorem rename_ops (t : Ec.Tracker) (n : String) :
    (t.rename n).ops = t.ops := by
  unfold Ec.Tracker.rename; dsimp only; split <;> rfl

/-- `copyToTop` preserves `ops` up to the depth-`d` pick increment, folded concretely. -/
private theorem copyToTop_ops_d (t : Ec.Tracker) (name n' : String) (L : List (Option String))
    (hnm : t.nm.toList = L ++ [some name]) :
    (t.copyToTop name n').ops.toList = t.ops.toList ++ pickExtraOps 0 := by
  rw [copyToTop_ops_concrete t name n' 0 (findDepth_top0 t L name hnm)]

/-- `copyToTop` at depth 1 (second-from-top). -/
private theorem copyToTop_ops_d1 (t : Ec.Tracker) (name n' : String) (L : List (Option String))
    (a : String) (hnm : t.nm.toList = L ++ [some name, some a]) (hne : a ≠ name) :
    (t.copyToTop name n').ops.toList = t.ops.toList ++ pickExtraOps 1 := by
  rw [copyToTop_ops_concrete t name n' 1 (findDepth_second1 t L name a hnm (Ne.symm hne))]

/-- **`fieldSqr "_inv_r" "_inv_r2"` nm (loop-shape).**  Off `L ++ [a, "_inv_r"]`, lands
`L ++ [a, "_inv_r2"]` — `aName` stays at depth 1, the result slot replaces `_inv_r`. -/
private theorem invFieldSqr_nm (t : Ec.Tracker) (L : List (Option String)) (a : String)
    (hnm : t.nm.toList = L ++ [some a, some "_inv_r"]) (hne : a ≠ "_inv_r") :
    (Ec.fieldSqr t "_inv_r" "_inv_r2").nm.toList = L ++ [some a, some "_inv_r2"] := by
  unfold Ec.fieldSqr Ec.fieldMul Ec.fieldMod
  -- copyToTop "_inv_r" "_fsqr_copy" (depth 0) → L ++ [a, _inv_r, _fsqr_copy]
  have h1 : (t.copyToTop "_inv_r" "_fsqr_copy").nm.toList
      = (L ++ [some a]) ++ [some "_inv_r", some "_fsqr_copy"] := by
    rw [copyToTop_nm_toList, hnm]; simp
  -- toTop "_inv_r" (depth 1) → L ++ [a, _fsqr_copy, _inv_r]
  have h2 : ((t.copyToTop "_inv_r" "_fsqr_copy").toTop "_inv_r").nm.toList
      = (L ++ [some a]) ++ [some "_fsqr_copy", some "_inv_r"] :=
    toTop_second_nm _ (L ++ [some a]) "_inv_r" "_fsqr_copy" h1 (by decide)
  -- toTop "_fsqr_copy" (depth 1) → L ++ [a, _inv_r, _fsqr_copy]
  have h3 : (((t.copyToTop "_inv_r" "_fsqr_copy").toTop "_inv_r").toTop "_fsqr_copy").nm.toList
      = (L ++ [some a]) ++ [some "_inv_r", some "_fsqr_copy"] :=
    toTop_second_nm _ (L ++ [some a]) "_fsqr_copy" "_inv_r" h2 (by decide)
  -- rawBlock 2 "_fmul_prod" → L ++ [a, _fmul_prod]
  have h4 : ((((t.copyToTop "_inv_r" "_fsqr_copy").toTop "_inv_r").toTop "_fsqr_copy").rawBlock 2
        (some "_fmul_prod") [.opcode "OP_MUL"]).nm.toList = (L ++ [some a]) ++ [some "_fmul_prod"] :=
    rawBlock2_nm_toList _ "_fmul_prod" _ (L ++ [some a]) (some "_inv_r") (some "_fsqr_copy") h3
  -- fieldMod "_fmul_prod" "_inv_r2": toTop "_fmul_prod" (depth 0, noop) → push _fmod_p → rawBlock2
  have h5 : (((((t.copyToTop "_inv_r" "_fsqr_copy").toTop "_inv_r").toTop "_fsqr_copy").rawBlock 2
        (some "_fmul_prod") [.opcode "OP_MUL"]).toTop "_fmul_prod").nm.toList
      = (L ++ [some a]) ++ [some "_fmul_prod"] := by
    rw [toTop_top_nm _ (L ++ [some a]) "_fmul_prod" (by rw [h4]), h4]
  have h6 : (Ec.pushFieldP ((((((t.copyToTop "_inv_r" "_fsqr_copy").toTop "_inv_r").toTop "_fsqr_copy").rawBlock 2
        (some "_fmul_prod") [.opcode "OP_MUL"]).toTop "_fmul_prod")) "_fmod_p").nm.toList
      = (L ++ [some a, some "_fmul_prod"]) ++ [some "_fmod_p"] := by
    rw [Ec.pushFieldP, pushInt_nm, Array.toList_push, h5]; simp
  rw [rawBlock2_nm_toList _ "_inv_r2" _ (L ++ [some a]) (some "_fmul_prod") (some "_fmod_p")
    (by rw [h6]; simp)]
  simp

/-- **`fieldMul "_inv_r" "_inv_a" "_inv_m"` nm (loop-shape).**  Off `L ++ [a, "_inv_r",
"_inv_a"]`, lands `L ++ [a, "_inv_m"]` — both inputs consumed, product slot on top. -/
private theorem invFieldMul_nm (t : Ec.Tracker) (L : List (Option String)) (a : String)
    (hnm : t.nm.toList = L ++ [some a, some "_inv_r", some "_inv_a"]) :
    (Ec.fieldMul t "_inv_r" "_inv_a" "_inv_m").nm.toList = L ++ [some a, some "_inv_m"] := by
  unfold Ec.fieldMul Ec.fieldMod
  -- toTop "_inv_r" (depth 1) → L ++ [a, _inv_a, _inv_r]
  have h1 : (t.toTop "_inv_r").nm.toList = (L ++ [some a]) ++ [some "_inv_a", some "_inv_r"] :=
    toTop_second_nm t (L ++ [some a]) "_inv_r" "_inv_a" (by rw [hnm]; simp) (by decide)
  -- toTop "_inv_a" (depth 1) → L ++ [a, _inv_r, _inv_a]
  have h2 : ((t.toTop "_inv_r").toTop "_inv_a").nm.toList
      = (L ++ [some a]) ++ [some "_inv_r", some "_inv_a"] :=
    toTop_second_nm _ (L ++ [some a]) "_inv_a" "_inv_r" h1 (by decide)
  -- rawBlock 2 "_fmul_prod" → L ++ [a, _fmul_prod]
  have h3 : (((t.toTop "_inv_r").toTop "_inv_a").rawBlock 2 (some "_fmul_prod")
        [.opcode "OP_MUL"]).nm.toList = (L ++ [some a]) ++ [some "_fmul_prod"] :=
    rawBlock2_nm_toList _ "_fmul_prod" _ (L ++ [some a]) (some "_inv_r") (some "_inv_a") h2
  -- fieldMod: toTop "_fmul_prod" (depth 0) → push _fmod_p → rawBlock2
  have h4 : ((((t.toTop "_inv_r").toTop "_inv_a").rawBlock 2 (some "_fmul_prod")
        [.opcode "OP_MUL"]).toTop "_fmul_prod").nm.toList = (L ++ [some a]) ++ [some "_fmul_prod"] := by
    rw [toTop_top_nm _ (L ++ [some a]) "_fmul_prod" (by rw [h3]), h3]
  have h5 : (Ec.pushFieldP (((((t.toTop "_inv_r").toTop "_inv_a").rawBlock 2 (some "_fmul_prod")
        [.opcode "OP_MUL"]).toTop "_fmul_prod")) "_fmod_p").nm.toList
      = (L ++ [some a, some "_fmul_prod"]) ++ [some "_fmod_p"] := by
    rw [Ec.pushFieldP, pushInt_nm, Array.toList_push, h4]; simp
  rw [rawBlock2_nm_toList _ "_inv_m" _ (L ++ [some a]) (some "_fmul_prod") (some "_fmod_p")
    (by rw [h5]; simp)]
  simp

/-- **`fieldSqr "_inv_r" "_inv_r2"` ops (loop-shape) = `t.ops ++ fieldSqrYInc`.**  Depths:
`copyToTop "_inv_r"` 0, `toTop "_inv_r"` 1, `toTop "_fsqr_copy"` 1, prod 0. -/
private theorem invFieldSqr_ops (t : Ec.Tracker) (L : List (Option String)) (a : String)
    (hnm : t.nm.toList = L ++ [some a, some "_inv_r"]) (hne : a ≠ "_inv_r") :
    (Ec.fieldSqr t "_inv_r" "_inv_r2").ops.toList = t.ops.toList ++ fieldSqrYInc := by
  unfold Ec.fieldSqr
  -- copyToTop "_inv_r" "_fsqr_copy" depth 0
  have hc_nm : (t.copyToTop "_inv_r" "_fsqr_copy").nm.toList
      = (L ++ [some a, some "_inv_r"]) ++ [some "_fsqr_copy"] := by
    rw [copyToTop_nm_toList, hnm]
  have hc_ops : (t.copyToTop "_inv_r" "_fsqr_copy").ops.toList = t.ops.toList ++ pickExtraOps 0 :=
    copyToTop_ops_concrete t "_inv_r" "_fsqr_copy" 0 (findDepth_top0 t (L ++ [some a]) "_inv_r" (by rw [hnm]; simp))
  -- toTop "_inv_r" depth 1 (against the copyToTop tracker, nm = L++[a,_inv_r,_fsqr_copy])
  have hm1_nm : ((t.copyToTop "_inv_r" "_fsqr_copy").toTop "_inv_r").nm.toList
      = (L ++ [some a]) ++ [some "_fsqr_copy", some "_inv_r"] :=
    toTop_second_nm _ (L ++ [some a]) "_inv_r" "_fsqr_copy" (by rw [hc_nm]; simp) (by decide)
  -- toTop "_fsqr_copy" depth 1 → then rawBlock prod depth 0
  have hm2_nm : ((((t.copyToTop "_inv_r" "_fsqr_copy").toTop "_inv_r").toTop "_fsqr_copy").rawBlock 2
        (some "_fmul_prod") [.opcode "OP_MUL"]).nm.toList = (L ++ [some a]) ++ [some "_fmul_prod"] :=
    rawBlock2_nm_toList _ "_fmul_prod" _ (L ++ [some a]) (some "_inv_r") (some "_fsqr_copy")
      (toTop_second_nm _ (L ++ [some a]) "_fsqr_copy" "_inv_r" hm1_nm (by decide))
  rw [fieldMul_ops_concrete (t.copyToTop "_inv_r" "_fsqr_copy") "_inv_r" "_fsqr_copy" "_inv_r2" 1 1 0
        (findDepth_second1 _ (L ++ [some a]) "_inv_r" "_fsqr_copy" (by rw [hc_nm]; simp) (by decide))
        (findDepth_second1 _ (L ++ [some a]) "_fsqr_copy" "_inv_r" hm1_nm (by decide))
        (findDepth_top0 _ (L ++ [some a]) "_fmul_prod" hm2_nm)]
  rw [hc_ops]
  simp only [fieldSqrYInc, rollExtraOps, pickExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- **`fieldMul "_inv_r" "_inv_a" "_inv_m"` ops (loop-shape) = `t.ops ++ fieldMulSwap2Inc`.**
Depths: `toTop "_inv_r"` 1, `toTop "_inv_a"` 1, prod 0. -/
private theorem invFieldMul_ops (t : Ec.Tracker) (L : List (Option String)) (a : String)
    (hnm : t.nm.toList = L ++ [some a, some "_inv_r", some "_inv_a"]) :
    (Ec.fieldMul t "_inv_r" "_inv_a" "_inv_m").ops.toList = t.ops.toList ++ fieldMulSwap2Inc := by
  -- toTop "_inv_r" depth 1
  have hm1_nm : (t.toTop "_inv_r").nm.toList = (L ++ [some a]) ++ [some "_inv_a", some "_inv_r"] :=
    toTop_second_nm t (L ++ [some a]) "_inv_r" "_inv_a" (by rw [hnm]; simp) (by decide)
  have hm2_nm : (((t.toTop "_inv_r").toTop "_inv_a").rawBlock 2 (some "_fmul_prod")
        [.opcode "OP_MUL"]).nm.toList = (L ++ [some a]) ++ [some "_fmul_prod"] :=
    rawBlock2_nm_toList _ "_fmul_prod" _ (L ++ [some a]) (some "_inv_r") (some "_inv_a")
      (toTop_second_nm _ (L ++ [some a]) "_inv_a" "_inv_r" hm1_nm (by decide))
  rw [fieldMul_ops_concrete t "_inv_r" "_inv_a" "_inv_m" 1 1 0
        (findDepth_second1 t (L ++ [some a]) "_inv_r" "_inv_a" (by rw [hnm]; simp) (by decide))
        (findDepth_second1 _ (L ++ [some a]) "_inv_a" "_inv_r" hm1_nm (by decide))
        (findDepth_top0 _ (L ++ [some a]) "_fmul_prod" hm2_nm)]
  simp only [fieldMulSwap2Inc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- **One high-loop iteration ops increment = `oneHighIterInc`.**  Threads `invFieldSqr_ops`
→ `rename` (no op) → `copyToTop a` (depth 1 = `.over`) → `invFieldMul_ops` → `rename` (no op),
using `hiIterBody_nm`'s intermediate shapes for the depth folds. -/
private theorem hiIterBody_ops (t : Ec.Tracker) (L : List (Option String)) (a : String)
    (hnm : t.nm.toList = L ++ [some a, some "_inv_r"]) (hne : a ≠ "_inv_r") :
    (hiIterBody t a).ops.toList = t.ops.toList ++ oneHighIterInc := by
  unfold hiIterBody
  -- shapes (mirror hiIterBody_nm)
  have h1nm : (Ec.fieldSqr t "_inv_r" "_inv_r2").nm.toList = L ++ [some a, some "_inv_r2"] :=
    invFieldSqr_nm t L a hnm hne
  have h2nm : ((Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r").nm.toList
      = L ++ [some a, some "_inv_r"] := by
    rw [rename_invr_nm _ (L ++ [some a]) (some "_inv_r2") (by rw [h1nm]; simp)]; simp
  have h3nm : (((Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r").copyToTop a "_inv_a").nm.toList
      = L ++ [some a, some "_inv_r", some "_inv_a"] := by
    rw [copyToTop_nm_toList, h2nm]; simp
  -- ops chain
  -- fieldSqr ops
  have h1ops : (Ec.fieldSqr t "_inv_r" "_inv_r2").ops.toList = t.ops.toList ++ fieldSqrYInc :=
    invFieldSqr_ops t L a hnm hne
  -- rename preserves ops
  have h2ops : ((Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r").ops.toList
      = t.ops.toList ++ fieldSqrYInc := by
    rw [show ((Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r").ops
          = (Ec.fieldSqr t "_inv_r" "_inv_r2").ops from rename_ops _ "_inv_r", h1ops]
  -- copyToTop a "_inv_a" depth 1 = .over
  have h3ops : (((Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r").copyToTop a "_inv_a").ops.toList
      = t.ops.toList ++ fieldSqrYInc ++ [.over] := by
    rw [copyToTop_ops_concrete _ a "_inv_a" 1
          (findDepth_second1 _ L a "_inv_r" h2nm hne), h2ops]
    simp only [pickExtraOps]
  -- fieldMul "_inv_r" "_inv_a" "_inv_m" ops
  have h4ops : (Ec.fieldMul (((Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r").copyToTop a "_inv_a")
        "_inv_r" "_inv_a" "_inv_m").ops.toList
      = t.ops.toList ++ fieldSqrYInc ++ [.over] ++ fieldMulSwap2Inc := by
    rw [invFieldMul_ops _ L a h3nm, h3ops]
  -- final rename preserves ops
  rw [show ((Ec.fieldMul (((Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r").copyToTop a "_inv_a")
        "_inv_r" "_inv_a" "_inv_m").rename "_inv_r").ops
        = (Ec.fieldMul (((Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r").copyToTop a "_inv_a")
            "_inv_r" "_inv_a" "_inv_m").ops from rename_ops _ "_inv_r", h4ops]
  simp only [oneHighIterInc, List.append_assoc]

/-- **One high-loop iteration is an `nm` FIXED POINT.**  `hiIterBody` off `L ++ [a, "_inv_r"]`
returns to `L ++ [a, "_inv_r"]` (the documented loop invariant: `_inv_r` depth 0, `aName`
depth 1 for every iteration).  Threads `invFieldSqr_nm` → `rename` → `copyToTop` →
`invFieldMul_nm` → `rename` at the `toList` level. -/
private theorem hiIterBody_nm (t : Ec.Tracker) (L : List (Option String)) (a : String)
    (hnm : t.nm.toList = L ++ [some a, some "_inv_r"]) (hne : a ≠ "_inv_r") :
    (hiIterBody t a).nm.toList = L ++ [some a, some "_inv_r"] := by
  unfold hiIterBody
  -- fieldSqr "_inv_r" "_inv_r2" → L ++ [a, _inv_r2]
  have h1 : (Ec.fieldSqr t "_inv_r" "_inv_r2").nm.toList = L ++ [some a, some "_inv_r2"] :=
    invFieldSqr_nm t L a hnm hne
  -- rename "_inv_r" → L ++ [a, _inv_r]
  have h2 : ((Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r").nm.toList
      = L ++ [some a, some "_inv_r"] := by
    rw [rename_invr_nm _ (L ++ [some a]) (some "_inv_r2") (by rw [h1]; simp)]; simp
  -- copyToTop a "_inv_a" (depth 1) → L ++ [a, _inv_r, _inv_a]
  have h3 : (((Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r").copyToTop a "_inv_a").nm.toList
      = L ++ [some a, some "_inv_r", some "_inv_a"] := by
    rw [copyToTop_nm_toList, h2]; simp
  -- fieldMul "_inv_r" "_inv_a" "_inv_m" → L ++ [a, _inv_m]
  have h4 : (Ec.fieldMul (((Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r").copyToTop a "_inv_a")
        "_inv_r" "_inv_a" "_inv_m").nm.toList = L ++ [some a, some "_inv_m"] :=
    invFieldMul_nm _ L a h3
  -- rename "_inv_r" → L ++ [a, _inv_r]
  rw [rename_invr_nm _ (L ++ [some a]) (some "_inv_m") (by rw [h4]; simp)]; simp

/-- `fieldInvHighLoop (n+1)` peels one `hiIterBody` then recurses (definitional). -/
private theorem fieldInvHighLoop_succ (n : Nat) (t : Ec.Tracker) (aName : String) :
    Ec.fieldInvHighLoop (n+1) t aName = Ec.fieldInvHighLoop n (hiIterBody t aName) aName := by
  show Ec.fieldInvHighLoop n (hiIterBody t aName) aName = _
  rfl

/-- **THE HIGH-LOOP OP-LIST BRIDGE (deliverable 1).**  `fieldInvHighLoop n` emits exactly
`highLoopInc n` (= `n` copies of `oneHighIterInc`), with the entry `nm` preserved.  A
structural induction on `n`: each step peels one `hiIterBody` (`fieldInvHighLoop_succ`),
appends `oneHighIterInc` (`hiIterBody_ops`) over the FIXED-POINT `nm` (`hiIterBody_nm`),
then recurses on the preserved shape.  This is the op-list the runtime induction
`highLoopInc_runOps_sim` consumes. -/
private theorem fieldInvHighLoop_ops (n : Nat) :
    ∀ (t : Ec.Tracker) (L : List (Option String)) (a : String),
      t.nm.toList = L ++ [some a, some "_inv_r"] → a ≠ "_inv_r" →
      (Ec.fieldInvHighLoop n t a).ops.toList = t.ops.toList ++ highLoopInc n
        ∧ (Ec.fieldInvHighLoop n t a).nm.toList = L ++ [some a, some "_inv_r"] := by
  induction n with
  | zero =>
    intro t L a hnm hne
    refine ⟨?_, ?_⟩
    · show (Ec.fieldInvHighLoop 0 t a).ops.toList = _
      unfold Ec.fieldInvHighLoop highLoopInc
      simp only [List.replicate, List.flatten, List.append_nil]
    · show (Ec.fieldInvHighLoop 0 t a).nm.toList = _
      unfold Ec.fieldInvHighLoop; exact hnm
  | succ k ih =>
    intro t L a hnm hne
    rw [fieldInvHighLoop_succ k t a]
    have hbody_nm : (hiIterBody t a).nm.toList = L ++ [some a, some "_inv_r"] :=
      hiIterBody_nm t L a hnm hne
    have hbody_ops : (hiIterBody t a).ops.toList = t.ops.toList ++ oneHighIterInc :=
      hiIterBody_ops t L a hnm hne
    obtain ⟨hrec_ops, hrec_nm⟩ := ih (hiIterBody t a) L a hbody_nm hne
    refine ⟨?_, hrec_nm⟩
    rw [hrec_ops, hbody_ops]
    show t.ops.toList ++ oneHighIterInc ++ highLoopInc k = t.ops.toList ++ highLoopInc (k+1)
    unfold highLoopInc
    rw [show List.replicate (k+1) oneHighIterInc = oneHighIterInc :: List.replicate k oneHighIterInc from rfl,
        List.flatten_cons]
    simp only [List.append_assoc]

/-- One low-loop iteration as a standalone `Tracker → Tracker` (mirrors the body of
`fieldInvLowLoop (k+1)`): square always, multiply iff the current bit is set. -/
def loIterBody (lowBits : Int) (k : Nat) (t : Ec.Tracker) (aName : String) : Ec.Tracker :=
  let t := Ec.fieldSqr t "_inv_r" "_inv_r2"
  let t := t.rename "_inv_r"
  let bitSet : Bool := ((lowBits / (2 ^ k)) % 2) = 1
  if bitSet then
    let t := t.copyToTop aName "_inv_a"
    let t := Ec.fieldMul t "_inv_r" "_inv_a" "_inv_m"
    t.rename "_inv_r"
  else t

/-- `fieldInvLowLoop (k+1)` peels one `loIterBody` then recurses (definitional). -/
private theorem fieldInvLowLoop_succ (k : Nat) (lowBits : Int) (t : Ec.Tracker) (aName : String) :
    Ec.fieldInvLowLoop (k+1) lowBits t aName
      = Ec.fieldInvLowLoop k lowBits (loIterBody lowBits k t aName) aName := by
  show Ec.fieldInvLowLoop k lowBits (loIterBody lowBits k t aName) aName = _
  rfl

/-- **One low-loop iteration: `nm` FIXED POINT + ops increment = `oneLowIterInc bit`.**
`by_cases` on the bit: set ⇒ `hiIterBody` (square-and-multiply, already proven); clear ⇒
`fieldSqr`+`rename` (square-only). -/
private theorem loIterBody_nm_ops (lowBits : Int) (k : Nat) (t : Ec.Tracker)
    (L : List (Option String)) (a : String)
    (hnm : t.nm.toList = L ++ [some a, some "_inv_r"]) (hne : a ≠ "_inv_r") :
    (loIterBody lowBits k t a).nm.toList = L ++ [some a, some "_inv_r"]
      ∧ (loIterBody lowBits k t a).ops.toList
          = t.ops.toList ++ oneLowIterInc (((lowBits / (2 ^ k)) % 2) = 1) := by
  unfold oneLowIterInc
  by_cases hbit : ((lowBits / (2 ^ k)) % 2) = 1
  · -- set: body = hiIterBody
    rw [show loIterBody lowBits k t a = hiIterBody t a from by
          unfold loIterBody hiIterBody; simp only [hbit, decide_true, if_true]]
    rw [if_pos hbit]
    exact ⟨hiIterBody_nm t L a hnm hne, hiIterBody_ops t L a hnm hne⟩
  · -- clear: body = fieldSqr + rename (square-only)
    rw [show loIterBody lowBits k t a = (Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r" from by
          unfold loIterBody; simp only [hbit, decide_false, Bool.false_eq_true, if_false]]
    rw [if_neg hbit]
    have h1nm : (Ec.fieldSqr t "_inv_r" "_inv_r2").nm.toList = L ++ [some a, some "_inv_r2"] :=
      invFieldSqr_nm t L a hnm hne
    have h1ops : (Ec.fieldSqr t "_inv_r" "_inv_r2").ops.toList = t.ops.toList ++ fieldSqrYInc :=
      invFieldSqr_ops t L a hnm hne
    refine ⟨?_, ?_⟩
    · rw [rename_invr_nm _ (L ++ [some a]) (some "_inv_r2") (by rw [h1nm]; simp)]; simp
    · rw [show ((Ec.fieldSqr t "_inv_r" "_inv_r2").rename "_inv_r").ops
            = (Ec.fieldSqr t "_inv_r" "_inv_r2").ops from rename_ops _ "_inv_r", h1ops]

/-- **THE LOW-LOOP OP-LIST BRIDGE (deliverable 1).**  `fieldInvLowLoop steps lowBits` emits
exactly `lowLoopInc steps lowBits`, `nm` preserved.  Structural induction on `steps`
mirroring `fieldInvHighLoop_ops`, each step `loIterBody_nm_ops` (per-bit `by_cases`). -/
private theorem fieldInvLowLoop_ops (steps : Nat) (lowBits : Int) :
    ∀ (t : Ec.Tracker) (L : List (Option String)) (a : String),
      t.nm.toList = L ++ [some a, some "_inv_r"] → a ≠ "_inv_r" →
      (Ec.fieldInvLowLoop steps lowBits t a).ops.toList = t.ops.toList ++ lowLoopInc steps lowBits
        ∧ (Ec.fieldInvLowLoop steps lowBits t a).nm.toList = L ++ [some a, some "_inv_r"] := by
  induction steps with
  | zero =>
    intro t L a hnm hne
    refine ⟨?_, ?_⟩
    · show (Ec.fieldInvLowLoop 0 lowBits t a).ops.toList = _
      show t.ops.toList = t.ops.toList ++ lowLoopInc 0 lowBits
      show t.ops.toList = t.ops.toList ++ []
      rw [List.append_nil]
    · show (Ec.fieldInvLowLoop 0 lowBits t a).nm.toList = _
      exact hnm
  | succ k ih =>
    intro t L a hnm hne
    rw [fieldInvLowLoop_succ k lowBits t a]
    obtain ⟨hbody_nm, hbody_ops⟩ := loIterBody_nm_ops lowBits k t L a hnm hne
    obtain ⟨hrec_ops, hrec_nm⟩ := ih (loIterBody lowBits k t a) L a hbody_nm hne
    refine ⟨?_, hrec_nm⟩
    rw [hrec_ops, hbody_ops]
    rw [show lowLoopInc (k+1) lowBits
          = oneLowIterInc (((lowBits / (2 ^ k)) % 2) = 1) ++ lowLoopInc k lowBits from rfl]
    simp only [List.append_assoc]

/-- `drop` ops-append. -/
private theorem drop_ops_append (t : Ec.Tracker) :
    (t.drop).ops.toList = t.ops.toList ++ [StackOp.drop] := by
  unfold Ec.Tracker.drop Ec.Tracker.emit; simp

/-- `drop` nm at the `toList` level: pop the last slot. -/
private theorem drop_nm_toList (t : Ec.Tracker) :
    (t.drop).nm.toList = t.nm.toList.dropLast := by
  unfold Ec.Tracker.drop Ec.Tracker.emit; rw [Array.toList_pop]

/-- **THE FULL `fieldInv` OP-LIST BRIDGE (deliverable 1 — depth-0 entry).**  For an entry
tracker with `aName` on TOS (`t.nm.toList = baseL ++ [some aName]`, the affineAdd
`fieldInv "_s_den" …` site), `(Stack.Ec.fieldInv t aName resultName).ops.toList
  = t.ops.toList ++ fieldInvCoreInc` — exactly the op-list the proven runtime sim
`fieldInv_runOps_sim` consumes.  Chains: prelude `copyToTop aName "_inv_r"` (depth 0 =
`.dup`) → high loop (`fieldInvHighLoop_ops`) → bit-32 `fieldSqr` (`invFieldSqr_ops`) →
`rename` → low loop (`fieldInvLowLoop_ops`) → cleanup `toTop aName`(depth 1=`.swap`)/`.drop`/
`toTop "_inv_r"`(depth 0=nop)/`rename` = `[.swap, .drop]`.  All bridges over the `nm`
FIXED POINT. -/
private theorem fieldInv_ops_depth0 (t : Ec.Tracker) (baseL : List (Option String))
    (aName resultName : String)
    (hnm : t.nm.toList = baseL ++ [some aName]) (hne : aName ≠ "_inv_r")
    (hbaseR : some "_inv_r" ∉ baseL) (hbaseA : some aName ∉ baseL) :
    (Ec.fieldInv t aName resultName).ops.toList = t.ops.toList ++ fieldInvCoreInc := by
  -- the explicit composed form (definitional, avoids unfolding the recursive loops to WHNF)
  rw [show Ec.fieldInv t aName resultName
        = (((((Ec.fieldInvLowLoop 32 0xFFFFFC2D
              (((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
                "_inv_r" "_inv_r2").rename "_inv_r")) aName).toTop aName).drop).toTop "_inv_r").rename
              resultName) from rfl]
  -- prelude: copyToTop aName "_inv_r" (depth 0) → baseL ++ [aName, _inv_r]
  have hp_nm : (t.copyToTop aName "_inv_r").nm.toList = baseL ++ [some aName, some "_inv_r"] := by
    rw [copyToTop_nm_toList, hnm]; simp
  have hp_ops : (t.copyToTop aName "_inv_r").ops.toList = t.ops.toList ++ [StackOp.dup] := by
    rw [copyToTop_ops_concrete t aName "_inv_r" 0 (findDepth_top0 t baseL aName hnm)]
    simp only [pickExtraOps]
  -- high loop
  obtain ⟨hhi_ops, hhi_nm⟩ :=
    fieldInvHighLoop_ops 222 (t.copyToTop aName "_inv_r") baseL aName hp_nm hne
  -- bit-32 fieldSqr
  have hbit_ops : (Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
        "_inv_r" "_inv_r2").ops.toList
      = (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName).ops.toList ++ fieldSqrYInc :=
    invFieldSqr_ops _ baseL aName hhi_nm hne
  have hbit_nm : (Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
        "_inv_r" "_inv_r2").nm.toList = baseL ++ [some aName, some "_inv_r2"] :=
    invFieldSqr_nm _ baseL aName hhi_nm hne
  -- rename "_inv_r"
  have hren_ops : ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
        "_inv_r" "_inv_r2").rename "_inv_r").ops
      = (Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
        "_inv_r" "_inv_r2").ops := rename_ops _ "_inv_r"
  have hren_nm : ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
        "_inv_r" "_inv_r2").rename "_inv_r").nm.toList = baseL ++ [some aName, some "_inv_r"] := by
    rw [rename_invr_nm _ (baseL ++ [some aName]) (some "_inv_r2") (by rw [hbit_nm]; simp)]; simp
  -- low loop
  obtain ⟨hlo_ops, hlo_nm⟩ :=
    fieldInvLowLoop_ops 32 0xFFFFFC2D _ baseL aName hren_nm hne
  -- cleanup: toTop aName (depth 1) → swap
  have hcl1_nm : ((Ec.fieldInvLowLoop 32 0xFFFFFC2D
        ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
          "_inv_r" "_inv_r2").rename "_inv_r") aName).toTop aName).nm.toList
      = baseL ++ [some "_inv_r", some aName] :=
    toTop_second_nm _ baseL aName "_inv_r" hlo_nm hne
  have hcl1_ops : ((Ec.fieldInvLowLoop 32 0xFFFFFC2D
        ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
          "_inv_r" "_inv_r2").rename "_inv_r") aName).toTop aName).ops.toList
      = (Ec.fieldInvLowLoop 32 0xFFFFFC2D
          ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
            "_inv_r" "_inv_r2").rename "_inv_r") aName).ops.toList ++ [StackOp.swap] := by
    rw [toTop_ops_concrete _ aName 1 (findDepth_second1 _ baseL aName "_inv_r" hlo_nm hne)]
    simp only [rollExtraOps]
  -- .drop → baseL ++ [_inv_r]
  have hcl2_nm : (((Ec.fieldInvLowLoop 32 0xFFFFFC2D
        ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
          "_inv_r" "_inv_r2").rename "_inv_r") aName).toTop aName).drop).nm.toList
      = baseL ++ [some "_inv_r"] := by
    rw [drop_nm_toList, hcl1_nm]; simp
  -- toTop "_inv_r" (depth 0) → nop
  have hcl3_ops : ((((Ec.fieldInvLowLoop 32 0xFFFFFC2D
        ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
          "_inv_r" "_inv_r2").rename "_inv_r") aName).toTop aName).drop).toTop "_inv_r").ops.toList
      = (((Ec.fieldInvLowLoop 32 0xFFFFFC2D
            ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
              "_inv_r" "_inv_r2").rename "_inv_r") aName).toTop aName).drop).ops.toList := by
    rw [toTop_ops_concrete _ "_inv_r" 0 (findDepth_top0 _ baseL "_inv_r" hcl2_nm)]
    simp only [rollExtraOps, List.append_nil]
  -- assemble the ops chain.  the final `rename resultName` preserves ops.
  rw [show (((((Ec.fieldInvLowLoop 32 0xFFFFFC2D
        ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
          "_inv_r" "_inv_r2").rename "_inv_r") aName).toTop aName).drop).toTop "_inv_r").rename resultName).ops
        = ((((Ec.fieldInvLowLoop 32 0xFFFFFC2D
            ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
              "_inv_r" "_inv_r2").rename "_inv_r") aName).toTop aName).drop).toTop "_inv_r").ops
        from rename_ops _ resultName]
  rw [hcl3_ops, drop_ops_append, hcl1_ops, hlo_ops]
  rw [show ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
          "_inv_r" "_inv_r2").rename "_inv_r").ops.toList
        = (Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
            "_inv_r" "_inv_r2").ops.toList from by rw [hren_ops]]
  rw [hbit_ops, hhi_ops, hp_ops]
  simp only [fieldInvCoreInc, List.append_assoc, List.cons_append, List.nil_append, List.singleton_append]

/-- **General `rename` nm at the `toList` level.**  `Tracker.rename n` rewrites the TOP
slot to `some n` (the `_inv_r` peer `rename_invr_nm` specialised to `"_inv_r"`). -/
private theorem rename_nm_general (t : Ec.Tracker) (L : List (Option String)) (x : Option String)
    (n : String) (hnm : t.nm.toList = L ++ [x]) :
    (t.rename n).nm.toList = L ++ [some n] := by
  unfold Ec.Tracker.rename
  have hsz : t.nm.size > 0 := by rw [← Array.length_toList, hnm, List.length_append]; simp
  rw [if_pos hsz]
  rw [Array.set!, Array.toList_setIfInBounds, hnm]
  rw [show t.nm.size - 1 = L.length from by rw [← Array.length_toList, hnm, List.length_append]; simp]
  rw [List.set_append_right (s := L) (t := [x]) L.length (some n) (Nat.le_refl _)]; simp

/-- **THE `fieldInv` NM BRIDGE (depth-0 entry).**  Peer of `fieldInv_ops_depth0` for `nm`:
for an entry with `aName` on TOS (`t.nm.toList = baseL ++ [some aName]`), running `fieldInv`
lands `nm.toList = baseL ++ [some resultName]` (the input slot consumed, the result on TOS).
Mirrors the nm-flow already computed inside `fieldInv_ops_depth0`. -/
private theorem fieldInv_nm_depth0 (t : Ec.Tracker) (baseL : List (Option String))
    (aName resultName : String)
    (hnm : t.nm.toList = baseL ++ [some aName]) (hne : aName ≠ "_inv_r") :
    (Ec.fieldInv t aName resultName).nm.toList = baseL ++ [some resultName] := by
  rw [show Ec.fieldInv t aName resultName
        = (((((Ec.fieldInvLowLoop 32 0xFFFFFC2D
              (((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
                "_inv_r" "_inv_r2").rename "_inv_r")) aName).toTop aName).drop).toTop "_inv_r").rename
              resultName) from rfl]
  -- prelude
  have hp_nm : (t.copyToTop aName "_inv_r").nm.toList = baseL ++ [some aName, some "_inv_r"] := by
    rw [copyToTop_nm_toList, hnm]; simp
  -- high loop preserves
  obtain ⟨_, hhi_nm⟩ :=
    fieldInvHighLoop_ops 222 (t.copyToTop aName "_inv_r") baseL aName hp_nm hne
  -- bit-32 fieldSqr
  have hbit_nm : (Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
        "_inv_r" "_inv_r2").nm.toList = baseL ++ [some aName, some "_inv_r2"] :=
    invFieldSqr_nm _ baseL aName hhi_nm hne
  -- rename
  have hren_nm : ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
        "_inv_r" "_inv_r2").rename "_inv_r").nm.toList = baseL ++ [some aName, some "_inv_r"] := by
    rw [rename_invr_nm _ (baseL ++ [some aName]) (some "_inv_r2") (by rw [hbit_nm]; simp)]; simp
  -- low loop preserves
  obtain ⟨_, hlo_nm⟩ :=
    fieldInvLowLoop_ops 32 0xFFFFFC2D _ baseL aName hren_nm hne
  -- cleanup: toTop aName (depth 1) → baseL ++ [_inv_r, aName]
  have hcl1_nm : ((Ec.fieldInvLowLoop 32 0xFFFFFC2D
        ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
          "_inv_r" "_inv_r2").rename "_inv_r") aName).toTop aName).nm.toList
      = baseL ++ [some "_inv_r", some aName] :=
    toTop_second_nm _ baseL aName "_inv_r" hlo_nm hne
  -- drop → baseL ++ [_inv_r]
  have hcl2_nm : (((Ec.fieldInvLowLoop 32 0xFFFFFC2D
        ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
          "_inv_r" "_inv_r2").rename "_inv_r") aName).toTop aName).drop).nm.toList
      = baseL ++ [some "_inv_r"] := by
    rw [drop_nm_toList, hcl1_nm]; simp
  -- toTop "_inv_r" (depth 0) preserves nm
  have hcl3_nm : ((((Ec.fieldInvLowLoop 32 0xFFFFFC2D
        ((Ec.fieldSqr (Ec.fieldInvHighLoop 222 (t.copyToTop aName "_inv_r") aName)
          "_inv_r" "_inv_r2").rename "_inv_r") aName).toTop aName).drop).toTop "_inv_r").nm.toList
      = baseL ++ [some "_inv_r"] := by
    rw [toTop_top_nm _ baseL "_inv_r" hcl2_nm, hcl2_nm]
  -- final rename → baseL ++ [resultName]
  rw [rename_nm_general _ baseL (some "_inv_r") resultName hcl3_nm]

/-! ### MANDATORY smokes for the `fieldInv` op-list bridge (deliverable 1) -/

/-- Concrete loop-entry tracker for the bridge smokes: `nm = [_pa, aBase, _inv_r]`. -/
private def invBridgeT0 : Ec.Tracker :=
  { nm := #[some "_pa", some "_inv_a_base", some "_inv_r"], ops := #[] }

/-- SMOKE (per-iteration `nm` FIXED POINT fires).  One `hiIterBody` returns the entry `nm`. -/
theorem smoke_hiIterBody_nm :
    (hiIterBody invBridgeT0 "_inv_a_base").nm.toList
      = [some "_pa", some "_inv_a_base", some "_inv_r"] :=
  hiIterBody_nm invBridgeT0 [some "_pa"] "_inv_a_base" (by decide) (by decide)

/-- SMOKE (per-iteration ops increment fires).  One `hiIterBody` appends `oneHighIterInc`. -/
theorem smoke_hiIterBody_ops :
    (hiIterBody invBridgeT0 "_inv_a_base").ops.toList = invBridgeT0.ops.toList ++ oneHighIterInc :=
  hiIterBody_ops invBridgeT0 [some "_pa"] "_inv_a_base" (by decide) (by decide)

/-- SMOKE (high-loop op-list bridge fires).  3 iterations emit `highLoopInc 3`, `nm` fixed. -/
theorem smoke_fieldInvHighLoop_ops :
    (Ec.fieldInvHighLoop 3 invBridgeT0 "_inv_a_base").ops.toList
        = invBridgeT0.ops.toList ++ highLoopInc 3
      ∧ (Ec.fieldInvHighLoop 3 invBridgeT0 "_inv_a_base").nm.toList
        = [some "_pa", some "_inv_a_base", some "_inv_r"] :=
  fieldInvHighLoop_ops 3 invBridgeT0 [some "_pa"] "_inv_a_base" (by decide) (by decide)

/-- SMOKE (low-loop op-list bridge fires).  4 iters over `lowBits = 10` emit
`lowLoopInc 4 10`, `nm` fixed. -/
theorem smoke_fieldInvLowLoop_ops :
    (Ec.fieldInvLowLoop 4 10 invBridgeT0 "_inv_a_base").ops.toList
        = invBridgeT0.ops.toList ++ lowLoopInc 4 10
      ∧ (Ec.fieldInvLowLoop 4 10 invBridgeT0 "_inv_a_base").nm.toList
        = [some "_pa", some "_inv_a_base", some "_inv_r"] :=
  fieldInvLowLoop_ops 4 10 invBridgeT0 [some "_pa"] "_inv_a_base" (by decide) (by decide)

/-- Concrete DEPTH-0 entry tracker for the full-bridge smoke: `aName` on TOS. -/
private def invBridgeD0 : Ec.Tracker :=
  { nm := #[some "_pa", some "_s_den"], ops := #[] }

/-- SMOKE (the FULL `fieldInv` op-list bridge fires).  Off a depth-0 `_s_den` entry (the
affineAdd site), `fieldInv "_s_den" "_s_den_inv"` emits exactly `fieldInvCoreInc` — the
op-list the proven runtime sim `fieldInv_runOps_sim` consumes.  This is the join point
that connects the codegen `fieldInv` to its runtime correctness. -/
theorem smoke_fieldInv_ops_depth0 :
    (Ec.fieldInv invBridgeD0 "_s_den" "_s_den_inv").ops.toList
      = invBridgeD0.ops.toList ++ fieldInvCoreInc :=
  fieldInv_ops_depth0 invBridgeD0 [some "_pa"] "_s_den" "_s_den_inv"
    (by decide) (by decide) (by decide) (by decide)

/-! ## Part 16 — Depth-general field-binop runtime sims (affineAdd deliverable 1)

The Part-12 per-field-helper sims (`fieldSub_runOps_sim`, `fieldMul_runOps_sim`, …) are
SHALLOW: they assume the operands sit at fixed depths 0/1 and collapse the `toTop`s to
literal `swap`/`dup`/nop.  `affineAdd` keeps `px/py/qx/qy` at DEEP, step-varying depths as
scratch churns above, so its `toTop aName`/`toTop bName` resolve to arbitrary
`findDepthList` depths.  This Part adds the DEPTH-GENERAL form: a single
`fieldBinop_runOps_simT` that runs the determined `fieldSub`/`fieldMul` increment
(`rollExtraOps da ++ rollExtraOps db ++ [binop, push fieldP] ++ fieldModOps`) at the LIVE
depths via the tail-general step transport `runOps_toTop_extraOps_simT` (the same general
transport the proof corpus uses for varying depths), landing the `Crypto.Secp256k1`
field-op result.  Each ships a smoke.  All `propext`/`Quot.sound`-clean (plus inherited
backend opaques on the `runOps` transports), NO new axiom, `native_decide` only in smokes. -/

private theorem niOpBinop : ∀ (c : String) t e, StackOp.opcode c ≠ .ifOp t e := by
  intro c t e h; cases h
private theorem niPushBinop : ∀ (v : PushVal) t e, StackOp.push v ≠ .ifOp t e := by
  intro v t e h; cases h

/-- The determined DEPTH-GENERAL field-binop increment: roll `aName` to top (depth `da`),
roll `bName` to top (depth `db`, resolved in the post-first-roll stack), apply the binop,
push the field prime, reduce mod p.  `da`/`db` are the live roll depths the codegen decides
per affineAdd step. -/
def fieldBinopGenInc (da db : Nat) (binop : String) : List StackOp :=
  rollExtraOps da ++ rollExtraOps db ++ ([.opcode binop, .push (.bigint Ec.fieldP)] ++ Ec.fieldModOps)

/-- **Depth-general field-binop runtime sim (deliverable 1).**  Running the determined
two-roll + opcode-tail increment at arbitrary depths `da`/`db` lands
`Secp256k1.fieldMod (f av bv)` on top.

The runtime model is given DIRECTLY (not via an nm valuation): `da` is the depth at which
`av` sits in `s.stack`, and after rolling it up, `db` is the depth at which `bv` sits in the
post-first-roll stack.  Both rolls use the GENERAL `runOps_rollExtraOps` (NOT the depth-0/1
special cases), so the lemma serves the deep, step-varying affineAdd depths.  `mid`/`out`
are the residual stacks each roll leaves; the codegen's nm bookkeeping (Part 17) supplies
the concrete `da`/`db`/`mid`/`out` per affineAdd step. -/
theorem fieldBinop_runOps_simT
    (binop : String) (f : Int → Int → Int)
    (s : StackState) (av bv : Int) (da db : Nat)
    (mid out : List Value)
    (hda : da < s.stack.length)
    (hRoll1 : applyRoll s da = .ok { s with stack := .vBigint av :: mid })
    (hdb : db < (.vBigint av :: mid).length)
    (hRoll2 : applyRoll { s with stack := .vBigint av :: mid } db
                = .ok { s with stack := .vBigint bv :: .vBigint av :: out })
    (hBinop : ∀ (t : StackState), t.stack = .vBigint bv :: .vBigint av :: out
        → runOpcode binop t = .ok ({ t with stack := out }.push (.vBigint (f av bv)))) :
    runOps (fieldBinopGenInc da db binop) s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldMod (f av bv)) :: out } := by
  unfold fieldBinopGenInc
  simp only [List.append_assoc]
  -- roll 1: brings av to top
  rw [runOps_append, runOps_rollExtraOps s da hda, hRoll1]
  simp only [match_Except_ok_runOps]
  -- roll 2: brings bv to top (over av)
  rw [runOps_append, runOps_rollExtraOps { s with stack := .vBigint av :: mid } db hdb, hRoll2]
  simp only [match_Except_ok_runOps]
  -- opcode tail: f av bv mod p
  rw [fieldBinop_optail_transport binop f { s with stack := .vBigint bv :: .vBigint av :: out }
        av bv out (hBinop _ rfl)]

/-- SMOKE (depth-general field-binop sim FIRES).  With `OP_SUB` at depths 2 then 1 on
`[x, y, av, z] ++ rest` (av at depth 2), then `[av, x, y, z]` (... bv = y at depth 2 in the
post-roll stack), the increment lands `fieldMod (av - bv)` on top.  Here concrete:
`s = [9, 7, 5, 3]`, `da = 2` (rolls 5 up), `db = 2` (rolls 7 up over 5), `out = [9, 3]`,
landing `fieldSub 5 7`. -/
theorem smoke_fieldBinop_runOps_simT :
    runOps (fieldBinopGenInc 2 2 "OP_SUB")
        { (default : StackState) with stack := [.vBigint 9, .vBigint 7, .vBigint 5, .vBigint 3] }
      = .ok { (default : StackState) with
              stack := .vBigint (Crypto.Secp256k1.fieldMod (5 - 7)) :: [.vBigint 9, .vBigint 3] } :=
  fieldBinop_runOps_simT "OP_SUB" (· - ·) _ 5 7 2 2
    [.vBigint 9, .vBigint 7, .vBigint 3] [.vBigint 9, .vBigint 3]
    (by decide) (by rfl) (by decide) (by rfl)
    (fun t ht => runOpcode_SUB_bigint_local t 5 7 [.vBigint 9, .vBigint 3] ht)

/-- The determined DEPTH-GENERAL `fieldSqr` increment: copy `aName` to top (pick depth
`dp`), then square via `fieldMul aName "_fsqr_copy"` — roll the now-deeper `aName` up
(`dm1`), roll the fresh copy up (`dm2`), `OP_MUL`, mod p.  `dp`/`dm1`/`dm2` are the live
depths the codegen decides per affineAdd step. -/
def fieldSqrGenInc (dp dm1 dm2 : Nat) : List StackOp :=
  pickExtraOps dp ++ fieldBinopGenInc dm1 dm2 "OP_MUL"

/-- **Depth-general `fieldSqr` runtime sim (deliverable 1).**  Running the determined
copy-then-multiply increment at arbitrary depths lands `Secp256k1.fieldMul av av` on top.
The `copyToTop` (`runOps_pickExtraOps` at depth `dp`) duplicates `av`; the inner `fieldMul`
then pairs the two copies via the general two-roll transport (`fieldBinop_runOps_simT`).
`mid`/`out` are the residual stacks; the codegen nm bookkeeping (Part 17) supplies the
concrete depths per affineAdd step. -/
theorem fieldSqr_runOps_simT
    (s : StackState) (av : Int) (dp dm1 dm2 : Nat)
    (mid out : List Value)
    (hdp : dp < s.stack.length)
    (hPick : applyPick s dp = .ok (s.push (.vBigint av)))
    (hdm1 : dm1 < (s.push (.vBigint av)).stack.length)
    (hRoll1 : applyRoll (s.push (.vBigint av)) dm1 = .ok { s with stack := .vBigint av :: mid })
    (hdm2 : dm2 < (.vBigint av :: mid).length)
    (hRoll2 : applyRoll { s with stack := .vBigint av :: mid } dm2
                = .ok { s with stack := .vBigint av :: .vBigint av :: out }) :
    runOps (fieldSqrGenInc dp dm1 dm2) s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldMul av av) :: out } := by
  unfold fieldSqrGenInc
  rw [runOps_append, runOps_pickExtraOps s dp hdp, hPick]
  simp only [match_Except_ok_runOps]
  rw [fieldBinop_runOps_simT "OP_MUL" (· * ·) (s.push (.vBigint av)) av av dm1 dm2 mid out
        hdm1 hRoll1 hdm2 hRoll2
        (fun t ht => runOpcode_MUL_bigint_local t av av out ht)]
  show Except.ok { (s.push (.vBigint av)) with stack := .vBigint (Crypto.Secp256k1.fieldMod (av * av)) :: out }
    = Except.ok { s with stack := .vBigint (Crypto.Secp256k1.fieldMul av av) :: out }
  rfl

/-- SMOKE (depth-general `fieldSqr` sim FIRES).  On `[5, 9, 3]`, copy `5` (depth 0) →
`[5, 5, 9, 3]`, then square the two `5`s (rolls at depth 0/1), landing `fieldMul 5 5`
on top with `[9, 3]` beneath. -/
theorem smoke_fieldSqr_runOps_simT :
    runOps (fieldSqrGenInc 0 1 1)
        { (default : StackState) with stack := [.vBigint 5, .vBigint 9, .vBigint 3] }
      = .ok { (default : StackState) with
              stack := .vBigint (Crypto.Secp256k1.fieldMul 5 5) :: [.vBigint 9, .vBigint 3] } :=
  fieldSqr_runOps_simT _ 5 0 1 1
    [.vBigint 5, .vBigint 9, .vBigint 3] [.vBigint 9, .vBigint 3]
    (by decide) (by rfl) (by decide) (by rfl) (by decide) (by rfl)

/-! ## Part 17 — `affineAdd` op-list bridge: entry scaffolding + first steps (deliverable 2)

`affineAdd` runs on the post-decompose tracker `nm = [px, py, qx, qy]` (qy on TOS), a ~18-step
field chain whose persistent base `[px, py, qx, qy]` stays at the BOTTOM throughout (verified
by probe: every step's `nm` begins `[px, py, qx, qy, …]`).  The chain:

  `copyToTop qy/py` → `fieldSub _qy1 _py1 _s_num` → `copyToTop qx/px` →
  `fieldSub _qx1 _px1 _s_den` (lands `_s_den` at DEPTH 0 = TOS, the `fieldInv` entry) →
  `fieldInv _s_den _s_den_inv` (the proven `fieldInv_ops_depth0` splice) →
  `fieldMul _s_num _s_den_inv _s` → `copyToTop _s _s_keep` → `fieldSqr _s _s2` →
  `copyToTop px` → `fieldSub _s2 _px2 _rx1` → `copyToTop qx` → `fieldSub _rx1 _qx2 rx` →
  `copyToTop px/rx` → `fieldSub _px3 _rx2 _px_rx` → `fieldMul _s_keep _px_rx _s_px_rx` →
  `copyToTop py` → `fieldSub _s_px_rx _py2 ry` → 4× cleanup `toTop`/`drop`.

This Part lands the entry scaffolding + the first chain steps' nm + op-list increments
(each composing with the depth-general field sims of Part 16).  The op-list bridge is the
`emitEcNegate_ops` pattern extended to ~18 steps; the runtime threading is the matching
Part-16 sim chain.  See the HONEST BLOCK below for the precise remaining step. -/

/-- The `affineAdd` entry tracker after `decomposePoint ×2`: `nm = [px, py, qx, qy]`. -/
def aaT0 : Ec.Tracker := { nm := #[some "px", some "py", some "qx", some "qy"], ops := #[] }

theorem aaT0_nm : aaT0.nm.toList = [some "px", some "py", some "qx", some "qy"] := rfl

/-- Step 1: `copyToTop "qy" "_qy1"` (depth 0 = `.dup`).  nm appends `_qy1`. -/
def aaT1 : Ec.Tracker := aaT0.copyToTop "qy" "_qy1"

theorem aaT1_nm : aaT1.nm.toList = [some "px", some "py", some "qx", some "qy", some "_qy1"] := by
  rw [aaT1, copyToTop_nm_toList, aaT0_nm]; rfl

theorem aaT1_ops : aaT1.ops.toList = aaT0.ops.toList ++ pickExtraOps 0 :=
  copyToTop_ops_concrete aaT0 "qy" "_qy1" 0 (fd_of_nm aaT0 "qy" 0 _ rfl (by decide) (by decide))

/-- Step 2: `copyToTop "py" "_py1"` (depth `py` = 3 in `[px,py,qx,qy,_qy1]` reversed). -/
def aaT2 : Ec.Tracker := aaT1.copyToTop "py" "_py1"

theorem aaT2_nm :
    aaT2.nm.toList = [some "px", some "py", some "qx", some "qy", some "_qy1", some "_py1"] := by
  rw [aaT2, copyToTop_nm_toList, aaT1_nm]; rfl

theorem aaT1_nm_arr : aaT1.nm = #[some "px", some "py", some "qx", some "qy", some "_qy1"] :=
  Array.ext' (by rw [aaT1_nm])

theorem aaT2_ops : aaT2.ops.toList = aaT1.ops.toList ++ pickExtraOps 3 :=
  copyToTop_ops_concrete aaT1 "py" "_py1" 3 (fd_of_nm aaT1 "py" 3 _ aaT1_nm_arr (by decide) (by decide))

theorem aaT2_nm_arr :
    aaT2.nm = #[some "px", some "py", some "qx", some "qy", some "_qy1", some "_py1"] :=
  Array.ext' (by rw [aaT2_nm])

/-- **`fieldSub t a b r` ops-append at concrete depths.**  The missing peer of
`fieldMul_ops_concrete`/`fieldAdd_ops_concrete` at `OP_SUB` / `_fsub_diff`; the affineAdd
fieldSub steps reuse it.  The increment equals `fieldBinopGenInc da db "OP_SUB"` once the
product depth `dp` folds to 0 (the diff always lands on TOS). -/
theorem fieldSub_ops_concrete (t : Ec.Tracker) (a b r : String) (da db dp : Nat)
    (hda : t.findDepth a = da) (hdb : (t.toTop a).findDepth b = db)
    (hdp : (((t.toTop a).toTop b).rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]).findDepth "_fsub_diff" = dp) :
    (Ec.fieldSub t a b r).ops.toList
      = t.ops.toList ++ rollExtraOps da ++ rollExtraOps db ++ [.opcode "OP_SUB"]
        ++ rollExtraOps dp ++ [.push (.bigint Ec.fieldP)] ++ Ec.fieldModOps := by
  unfold Ec.fieldSub
  rw [fieldBinop_ops_append t a b "_fsub_diff" r (.opcode "OP_SUB"), hda, hdb, hdp]

/-- Step 3: `fieldSub aaT2 "_qy1" "_py1" "_s_num"` — `_qy1` depth 1, `_py1` depth 1, diff
depth 0.  Op-list appends `fieldBinopGenInc 1 1 "OP_SUB"`; nm collapses to
`[px,py,qx,qy,_s_num]` (the two scratch operands consumed). -/
def aaT3 : Ec.Tracker := Ec.fieldSub aaT2 "_qy1" "_py1" "_s_num"

theorem aaT3_nm_arr :
    aaT3.nm = #[some "px", some "py", some "qx", some "qy", some "_s_num"] := by
  rw [aaT3]
  unfold Ec.fieldSub
  have hm1_nm : (aaT2.toTop "_qy1").nm
      = #[some "px", some "py", some "qx", some "qy", some "_py1", some "_qy1"] := by
    rw [toTop_nm_canonical aaT2 "_qy1" 1
          (fd_of_nm aaT2 "_qy1" 1 _ aaT2_nm_arr (by decide) (by decide)) (by rw [aaT2_nm_arr]; decide),
        aaT2_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT2.toTop "_qy1").toTop "_py1").rawBlock 2 (some "_fsub_diff")
        [.opcode "OP_SUB"]).nm = #[some "px", some "py", some "qx", some "qy", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_py1" 1
          (fd_of_nm _ "_py1" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fsub_diff" "_s_num" 0
        (fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide)) (by rw [hm2_nm]; decide), hm2_nm]
  apply Array.ext' <;> simp

theorem aaT3_nm :
    aaT3.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_num"] := by
  rw [aaT3_nm_arr]

theorem aaT3_ops : aaT3.ops.toList = aaT2.ops.toList ++ fieldBinopGenInc 1 1 "OP_SUB" := by
  have hm1_nm : (aaT2.toTop "_qy1").nm
      = #[some "px", some "py", some "qx", some "qy", some "_py1", some "_qy1"] := by
    rw [toTop_nm_canonical aaT2 "_qy1" 1
          (fd_of_nm aaT2 "_qy1" 1 _ aaT2_nm_arr (by decide) (by decide)) (by rw [aaT2_nm_arr]; decide),
        aaT2_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT2.toTop "_qy1").toTop "_py1").rawBlock 2 (some "_fsub_diff")
        [.opcode "OP_SUB"]).nm = #[some "px", some "py", some "qx", some "qy", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_py1" 1
          (fd_of_nm _ "_py1" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [aaT3, fieldSub_ops_concrete aaT2 "_qy1" "_py1" "_s_num" 1 1 0
        (fd_of_nm aaT2 "_qy1" 1 _ aaT2_nm_arr (by decide) (by decide))
        (fd_of_nm _ "_py1" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide))]
  simp only [fieldBinopGenInc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- Step 4: `copyToTop "qx" "_qx1"` (depth 2). -/
def aaT4 : Ec.Tracker := aaT3.copyToTop "qx" "_qx1"

theorem aaT4_nm :
    aaT4.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_num", some "_qx1"] := by
  rw [aaT4, copyToTop_nm_toList, aaT3_nm]; rfl

theorem aaT4_ops : aaT4.ops.toList = aaT3.ops.toList ++ pickExtraOps 2 :=
  copyToTop_ops_concrete aaT3 "qx" "_qx1" 2 (fd_of_nm aaT3 "qx" 2 _ aaT3_nm_arr (by decide) (by decide))

theorem aaT4_nm_arr :
    aaT4.nm = #[some "px", some "py", some "qx", some "qy", some "_s_num", some "_qx1"] :=
  Array.ext' (by rw [aaT4_nm])

/-- Step 5: `copyToTop "px" "_px1"` (depth 5). -/
def aaT5 : Ec.Tracker := aaT4.copyToTop "px" "_px1"

theorem aaT5_nm :
    aaT5.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_num", some "_qx1", some "_px1"] := by
  rw [aaT5, copyToTop_nm_toList, aaT4_nm]; rfl

theorem aaT5_ops : aaT5.ops.toList = aaT4.ops.toList ++ pickExtraOps 5 :=
  copyToTop_ops_concrete aaT4 "px" "_px1" 5 (fd_of_nm aaT4 "px" 5 _ aaT4_nm_arr (by decide) (by decide))

theorem aaT5_nm_arr :
    aaT5.nm = #[some "px", some "py", some "qx", some "qy", some "_s_num", some "_qx1", some "_px1"] :=
  Array.ext' (by rw [aaT5_nm])

/-- Step 6: `fieldSub aaT5 "_qx1" "_px1" "_s_den"` — `_qx1` depth 1, `_px1` depth 1, diff
depth 0.  CRUCIAL: lands `_s_den` at depth 0 (TOS) — the exact depth-0 entry the proven
`fieldInv_ops_depth0` / `fieldInv_runOps_sim` bridge requires for the next step. -/
def aaT6 : Ec.Tracker := Ec.fieldSub aaT5 "_qx1" "_px1" "_s_den"

theorem aaT6_nm_arr :
    aaT6.nm = #[some "px", some "py", some "qx", some "qy", some "_s_num", some "_s_den"] := by
  rw [aaT6]
  unfold Ec.fieldSub
  have hm1_nm : (aaT5.toTop "_qx1").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_num", some "_px1", some "_qx1"] := by
    rw [toTop_nm_canonical aaT5 "_qx1" 1
          (fd_of_nm aaT5 "_qx1" 1 _ aaT5_nm_arr (by decide) (by decide)) (by rw [aaT5_nm_arr]; decide),
        aaT5_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT5.toTop "_qx1").toTop "_px1").rawBlock 2 (some "_fsub_diff")
        [.opcode "OP_SUB"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_num", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_px1" 1
          (fd_of_nm _ "_px1" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fsub_diff" "_s_den" 0
        (fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide)) (by rw [hm2_nm]; decide), hm2_nm]
  apply Array.ext' <;> simp

theorem aaT6_nm :
    aaT6.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_num", some "_s_den"] := by
  rw [aaT6_nm_arr]

theorem aaT6_ops : aaT6.ops.toList = aaT5.ops.toList ++ fieldBinopGenInc 1 1 "OP_SUB" := by
  have hm1_nm : (aaT5.toTop "_qx1").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_num", some "_px1", some "_qx1"] := by
    rw [toTop_nm_canonical aaT5 "_qx1" 1
          (fd_of_nm aaT5 "_qx1" 1 _ aaT5_nm_arr (by decide) (by decide)) (by rw [aaT5_nm_arr]; decide),
        aaT5_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT5.toTop "_qx1").toTop "_px1").rawBlock 2 (some "_fsub_diff")
        [.opcode "OP_SUB"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_num", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_px1" 1
          (fd_of_nm _ "_px1" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [aaT6, fieldSub_ops_concrete aaT5 "_qx1" "_px1" "_s_den" 1 1 0
        (fd_of_nm aaT5 "_qx1" 1 _ aaT5_nm_arr (by decide) (by decide))
        (fd_of_nm _ "_px1" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide))]
  simp only [fieldBinopGenInc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- **The `fieldInv` splice (step 7) fires at the depth-0 `_s_den` entry.**  `aaT6` lands
`_s_den` on TOS (`aaT6_nm` ends `…, some "_s_den"`), so `fieldInv aaT6 "_s_den" "_s_den_inv"`
appends EXACTLY `fieldInvCoreInc` (the op-list the proven runtime sim `fieldInv_runOps_sim`
consumes) — the proven `fieldInv_ops_depth0` bridge applies directly.  This is the join point
the affineAdd op-list bridge needs at the modular-inverse step. -/
theorem aaT7_ops :
    (Ec.fieldInv aaT6 "_s_den" "_s_den_inv").ops.toList = aaT6.ops.toList ++ fieldInvCoreInc :=
  fieldInv_ops_depth0 aaT6 [some "px", some "py", some "qx", some "qy", some "_s_num"]
    "_s_den" "_s_den_inv"
    (by rw [aaT6_nm]; rfl) (by decide) (by decide) (by decide)

/-- Step 7 (the fieldInv splice) as a named tracker: `aaT7 = fieldInv aaT6 _s_den _s_den_inv`.
nm collapses to `[px, py, qx, qy, _s_num, _s_den_inv]` (input `_s_den` consumed, inverse on TOS). -/
def aaT7 : Ec.Tracker := Ec.fieldInv aaT6 "_s_den" "_s_den_inv"

theorem aaT7_nm :
    aaT7.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_num", some "_s_den_inv"] :=
  fieldInv_nm_depth0 aaT6 [some "px", some "py", some "qx", some "qy", some "_s_num"]
    "_s_den" "_s_den_inv" (by rw [aaT6_nm]; rfl) (by decide)

theorem aaT7_nm_arr :
    aaT7.nm = #[some "px", some "py", some "qx", some "qy", some "_s_num", some "_s_den_inv"] :=
  Array.ext' (by rw [aaT7_nm])

/-- Step 8: `fieldMul aaT7 "_s_num" "_s_den_inv" "_s"` — `_s_num` depth 1, `_s_den_inv` depth 1
(after `toTop _s_num`), product depth 0.  Op-list appends `fieldBinopGenInc 1 1 "OP_MUL"`;
nm collapses to `[px,py,qx,qy,_s]`. -/
def aaT8 : Ec.Tracker := Ec.fieldMul aaT7 "_s_num" "_s_den_inv" "_s"

theorem aaT8_nm_arr :
    aaT8.nm = #[some "px", some "py", some "qx", some "qy", some "_s"] := by
  rw [aaT8]
  unfold Ec.fieldMul
  have hm1_nm : (aaT7.toTop "_s_num").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_den_inv", some "_s_num"] := by
    rw [toTop_nm_canonical aaT7 "_s_num" 1
          (fd_of_nm aaT7 "_s_num" 1 _ aaT7_nm_arr (by decide) (by decide)) (by rw [aaT7_nm_arr]; decide),
        aaT7_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT7.toTop "_s_num").toTop "_s_den_inv").rawBlock 2 (some "_fmul_prod")
        [.opcode "OP_MUL"]).nm = #[some "px", some "py", some "qx", some "qy", some "_fmul_prod"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_s_den_inv" 1
          (fd_of_nm _ "_s_den_inv" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fmul_prod" "_s" 0
        (fd_of_nm _ "_fmul_prod" 0 _ hm2_nm (by decide) (by decide)) (by rw [hm2_nm]; decide), hm2_nm]
  apply Array.ext' <;> simp

theorem aaT8_nm :
    aaT8.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s"] := by
  rw [aaT8_nm_arr]

theorem aaT8_ops : aaT8.ops.toList = aaT7.ops.toList ++ fieldBinopGenInc 1 1 "OP_MUL" := by
  have hm1_nm : (aaT7.toTop "_s_num").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_den_inv", some "_s_num"] := by
    rw [toTop_nm_canonical aaT7 "_s_num" 1
          (fd_of_nm aaT7 "_s_num" 1 _ aaT7_nm_arr (by decide) (by decide)) (by rw [aaT7_nm_arr]; decide),
        aaT7_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT7.toTop "_s_num").toTop "_s_den_inv").rawBlock 2 (some "_fmul_prod")
        [.opcode "OP_MUL"]).nm = #[some "px", some "py", some "qx", some "qy", some "_fmul_prod"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_s_den_inv" 1
          (fd_of_nm _ "_s_den_inv" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [aaT8, fieldMul_ops_concrete aaT7 "_s_num" "_s_den_inv" "_s" 1 1 0
        (fd_of_nm aaT7 "_s_num" 1 _ aaT7_nm_arr (by decide) (by decide))
        (fd_of_nm _ "_s_den_inv" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fmul_prod" 0 _ hm2_nm (by decide) (by decide))]
  simp only [fieldBinopGenInc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- Step 9: `copyToTop "_s" "_s_keep"` (depth 0 = `.dup`). nm appends `_s_keep`. -/
def aaT9 : Ec.Tracker := aaT8.copyToTop "_s" "_s_keep"

theorem aaT9_nm :
    aaT9.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s", some "_s_keep"] := by
  rw [aaT9, copyToTop_nm_toList, aaT8_nm]; rfl

theorem aaT9_nm_arr :
    aaT9.nm = #[some "px", some "py", some "qx", some "qy", some "_s", some "_s_keep"] :=
  Array.ext' (by rw [aaT9_nm])

theorem aaT9_ops : aaT9.ops.toList = aaT8.ops.toList ++ pickExtraOps 0 :=
  copyToTop_ops_concrete aaT8 "_s" "_s_keep" 0 (fd_of_nm aaT8 "_s" 0 _ aaT8_nm_arr (by decide) (by decide))

/-- Step 10: `fieldSqr aaT9 "_s" "_s2"` = `copyToTop "_s" "_fsqr_copy"` then
`fieldMul "_s" "_fsqr_copy" "_s2"`.  `_s` is at depth 1 (under `_s_keep`).  After the copy,
the inner fieldMul squares the two `_s` copies.  nm collapses to `[px,py,qx,qy,_s_keep,_s2]`. -/
def aaT10 : Ec.Tracker := Ec.fieldSqr aaT9 "_s" "_s2"

theorem aaT10_nm_arr :
    aaT10.nm = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_s2"] := by
  rw [aaT10]
  unfold Ec.fieldSqr Ec.fieldMul
  -- copyToTop "_s" "_fsqr_copy": _s at depth 1 → push _fsqr_copy
  have hc_nm : (aaT9.copyToTop "_s" "_fsqr_copy").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s", some "_s_keep", some "_fsqr_copy"] := by
    rw [Ec.Tracker.copyToTop, pick_nm_push, aaT9_nm_arr]; apply Array.ext' <;> simp
  -- toTop "_s" (depth 2) → bring _s up
  have hm1_nm : ((aaT9.copyToTop "_s" "_fsqr_copy").toTop "_s").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_fsqr_copy", some "_s"] := by
    rw [toTop_nm_canonical _ "_s" 2
          (fd_of_nm _ "_s" 2 _ hc_nm (by decide) (by decide)) (by rw [hc_nm]; decide), hc_nm]
    apply Array.ext' <;> simp
  -- toTop "_fsqr_copy" (depth 1) → bring copy up over _s
  have hm2_nm : (((aaT9.copyToTop "_s" "_fsqr_copy").toTop "_s").toTop "_fsqr_copy").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_s", some "_fsqr_copy"] := by
    rw [toTop_nm_canonical _ "_fsqr_copy" 1
          (fd_of_nm _ "_fsqr_copy" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  -- rawBlock 2 _fmul_prod → consume two, append _fmul_prod
  have hm3_nm : ((((aaT9.copyToTop "_s" "_fsqr_copy").toTop "_s").toTop "_fsqr_copy").rawBlock 2
        (some "_fmul_prod") [.opcode "OP_MUL"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_fmul_prod"] := by
    rw [rawBlock_nm_some2, hm2_nm]; apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fmul_prod" "_s2" 0
        (fd_of_nm _ "_fmul_prod" 0 _ hm3_nm (by decide) (by decide)) (by rw [hm3_nm]; decide), hm3_nm]
  apply Array.ext' <;> simp

theorem aaT10_nm :
    aaT10.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_keep", some "_s2"] := by
  rw [aaT10_nm_arr]

theorem aaT10_ops : aaT10.ops.toList = aaT9.ops.toList ++ fieldSqrGenInc 1 2 1 := by
  rw [aaT10]
  unfold Ec.fieldSqr
  have hc_nm : (aaT9.copyToTop "_s" "_fsqr_copy").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s", some "_s_keep", some "_fsqr_copy"] := by
    rw [Ec.Tracker.copyToTop, pick_nm_push, aaT9_nm_arr]; apply Array.ext' <;> simp
  have hc_ops : (aaT9.copyToTop "_s" "_fsqr_copy").ops.toList = aaT9.ops.toList ++ pickExtraOps 1 :=
    copyToTop_ops_concrete aaT9 "_s" "_fsqr_copy" 1
      (fd_of_nm aaT9 "_s" 1 _ aaT9_nm_arr (by decide) (by decide))
  have hm1_nm : ((aaT9.copyToTop "_s" "_fsqr_copy").toTop "_s").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_fsqr_copy", some "_s"] := by
    rw [toTop_nm_canonical _ "_s" 2
          (fd_of_nm _ "_s" 2 _ hc_nm (by decide) (by decide)) (by rw [hc_nm]; decide), hc_nm]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT9.copyToTop "_s" "_fsqr_copy").toTop "_s").toTop "_fsqr_copy").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_s", some "_fsqr_copy"] := by
    rw [toTop_nm_canonical _ "_fsqr_copy" 1
          (fd_of_nm _ "_fsqr_copy" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldMul_ops_concrete (aaT9.copyToTop "_s" "_fsqr_copy") "_s" "_fsqr_copy" "_s2" 2 1 0
        (fd_of_nm _ "_s" 2 _ hc_nm (by decide) (by decide))
        (fd_of_nm _ "_fsqr_copy" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fmul_prod" 0 _
          (by rw [rawBlock_nm_some2, hm2_nm]) (by decide) (by decide))]
  rw [hc_ops]
  simp only [fieldSqrGenInc, fieldBinopGenInc, rollExtraOps, pickExtraOps,
    List.append_assoc, List.nil_append, List.cons_append]

/-- Step 11: `copyToTop "px" "_px2"` (depth 5). -/
def aaT11 : Ec.Tracker := aaT10.copyToTop "px" "_px2"

theorem aaT11_nm :
    aaT11.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_keep", some "_s2", some "_px2"] := by
  rw [aaT11, copyToTop_nm_toList, aaT10_nm]; rfl

theorem aaT11_nm_arr :
    aaT11.nm = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_s2", some "_px2"] :=
  Array.ext' (by rw [aaT11_nm])

theorem aaT11_ops : aaT11.ops.toList = aaT10.ops.toList ++ pickExtraOps 5 :=
  copyToTop_ops_concrete aaT10 "px" "_px2" 5 (fd_of_nm aaT10 "px" 5 _ aaT10_nm_arr (by decide) (by decide))

/-- Step 12: `fieldSub aaT11 "_s2" "_px2" "_rx1"` — `_s2` depth 1, `_px2` depth 1, diff depth 0. -/
def aaT12 : Ec.Tracker := Ec.fieldSub aaT11 "_s2" "_px2" "_rx1"

theorem aaT12_nm_arr :
    aaT12.nm = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_rx1"] := by
  rw [aaT12]; unfold Ec.fieldSub
  have hm1_nm : (aaT11.toTop "_s2").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_px2", some "_s2"] := by
    rw [toTop_nm_canonical aaT11 "_s2" 1
          (fd_of_nm aaT11 "_s2" 1 _ aaT11_nm_arr (by decide) (by decide)) (by rw [aaT11_nm_arr]; decide),
        aaT11_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT11.toTop "_s2").toTop "_px2").rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_px2" 1
          (fd_of_nm _ "_px2" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fsub_diff" "_rx1" 0
        (fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide)) (by rw [hm2_nm]; decide), hm2_nm]
  apply Array.ext' <;> simp

theorem aaT12_nm :
    aaT12.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_keep", some "_rx1"] := by
  rw [aaT12_nm_arr]

theorem aaT12_ops : aaT12.ops.toList = aaT11.ops.toList ++ fieldBinopGenInc 1 1 "OP_SUB" := by
  have hm1_nm : (aaT11.toTop "_s2").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_px2", some "_s2"] := by
    rw [toTop_nm_canonical aaT11 "_s2" 1
          (fd_of_nm aaT11 "_s2" 1 _ aaT11_nm_arr (by decide) (by decide)) (by rw [aaT11_nm_arr]; decide),
        aaT11_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT11.toTop "_s2").toTop "_px2").rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_px2" 1
          (fd_of_nm _ "_px2" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [aaT12, fieldSub_ops_concrete aaT11 "_s2" "_px2" "_rx1" 1 1 0
        (fd_of_nm aaT11 "_s2" 1 _ aaT11_nm_arr (by decide) (by decide))
        (fd_of_nm _ "_px2" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide))]
  simp only [fieldBinopGenInc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- Step 13: `copyToTop "qx" "_qx2"` (depth 3). -/
def aaT13 : Ec.Tracker := aaT12.copyToTop "qx" "_qx2"

theorem aaT13_nm :
    aaT13.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_keep", some "_rx1", some "_qx2"] := by
  rw [aaT13, copyToTop_nm_toList, aaT12_nm]; rfl

theorem aaT13_nm_arr :
    aaT13.nm = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_rx1", some "_qx2"] :=
  Array.ext' (by rw [aaT13_nm])

theorem aaT13_ops : aaT13.ops.toList = aaT12.ops.toList ++ pickExtraOps 3 :=
  copyToTop_ops_concrete aaT12 "qx" "_qx2" 3 (fd_of_nm aaT12 "qx" 3 _ aaT12_nm_arr (by decide) (by decide))

/-- Step 14: `fieldSub aaT13 "_rx1" "_qx2" "rx"` — `_rx1` depth 1, `_qx2` depth 1, diff depth 0. -/
def aaT14 : Ec.Tracker := Ec.fieldSub aaT13 "_rx1" "_qx2" "rx"

theorem aaT14_nm_arr :
    aaT14.nm = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "rx"] := by
  rw [aaT14]; unfold Ec.fieldSub
  have hm1_nm : (aaT13.toTop "_rx1").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_qx2", some "_rx1"] := by
    rw [toTop_nm_canonical aaT13 "_rx1" 1
          (fd_of_nm aaT13 "_rx1" 1 _ aaT13_nm_arr (by decide) (by decide)) (by rw [aaT13_nm_arr]; decide),
        aaT13_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT13.toTop "_rx1").toTop "_qx2").rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_qx2" 1
          (fd_of_nm _ "_qx2" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fsub_diff" "rx" 0
        (fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide)) (by rw [hm2_nm]; decide), hm2_nm]
  apply Array.ext' <;> simp

theorem aaT14_nm :
    aaT14.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_keep", some "rx"] := by
  rw [aaT14_nm_arr]

theorem aaT14_ops : aaT14.ops.toList = aaT13.ops.toList ++ fieldBinopGenInc 1 1 "OP_SUB" := by
  have hm1_nm : (aaT13.toTop "_rx1").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_qx2", some "_rx1"] := by
    rw [toTop_nm_canonical aaT13 "_rx1" 1
          (fd_of_nm aaT13 "_rx1" 1 _ aaT13_nm_arr (by decide) (by decide)) (by rw [aaT13_nm_arr]; decide),
        aaT13_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT13.toTop "_rx1").toTop "_qx2").rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_qx2" 1
          (fd_of_nm _ "_qx2" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [aaT14, fieldSub_ops_concrete aaT13 "_rx1" "_qx2" "rx" 1 1 0
        (fd_of_nm aaT13 "_rx1" 1 _ aaT13_nm_arr (by decide) (by decide))
        (fd_of_nm _ "_qx2" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide))]
  simp only [fieldBinopGenInc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- Step 15: `copyToTop "px" "_px3"` (depth 5). -/
def aaT15 : Ec.Tracker := aaT14.copyToTop "px" "_px3"

theorem aaT15_nm :
    aaT15.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_keep", some "rx", some "_px3"] := by
  rw [aaT15, copyToTop_nm_toList, aaT14_nm]; rfl

theorem aaT15_nm_arr :
    aaT15.nm = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "rx", some "_px3"] :=
  Array.ext' (by rw [aaT15_nm])

theorem aaT15_ops : aaT15.ops.toList = aaT14.ops.toList ++ pickExtraOps 5 :=
  copyToTop_ops_concrete aaT14 "px" "_px3" 5 (fd_of_nm aaT14 "px" 5 _ aaT14_nm_arr (by decide) (by decide))

/-- Step 16: `copyToTop "rx" "_rx2"` (depth 1). -/
def aaT16 : Ec.Tracker := aaT15.copyToTop "rx" "_rx2"

theorem aaT16_nm :
    aaT16.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_keep", some "rx", some "_px3", some "_rx2"] := by
  rw [aaT16, copyToTop_nm_toList, aaT15_nm]; rfl

theorem aaT16_nm_arr :
    aaT16.nm = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "rx", some "_px3", some "_rx2"] :=
  Array.ext' (by rw [aaT16_nm])

theorem aaT16_ops : aaT16.ops.toList = aaT15.ops.toList ++ pickExtraOps 1 :=
  copyToTop_ops_concrete aaT15 "rx" "_rx2" 1 (fd_of_nm aaT15 "rx" 1 _ aaT15_nm_arr (by decide) (by decide))

/-- Step 17: `fieldSub aaT16 "_px3" "_rx2" "_px_rx"` — `_px3` depth 1, `_rx2` depth 1, diff depth 0. -/
def aaT17 : Ec.Tracker := Ec.fieldSub aaT16 "_px3" "_rx2" "_px_rx"

theorem aaT17_nm_arr :
    aaT17.nm = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "rx", some "_px_rx"] := by
  rw [aaT17]; unfold Ec.fieldSub
  have hm1_nm : (aaT16.toTop "_px3").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "rx", some "_rx2", some "_px3"] := by
    rw [toTop_nm_canonical aaT16 "_px3" 1
          (fd_of_nm aaT16 "_px3" 1 _ aaT16_nm_arr (by decide) (by decide)) (by rw [aaT16_nm_arr]; decide),
        aaT16_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT16.toTop "_px3").toTop "_rx2").rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "rx", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_rx2" 1
          (fd_of_nm _ "_rx2" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fsub_diff" "_px_rx" 0
        (fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide)) (by rw [hm2_nm]; decide), hm2_nm]
  apply Array.ext' <;> simp

theorem aaT17_nm :
    aaT17.nm.toList = [some "px", some "py", some "qx", some "qy", some "_s_keep", some "rx", some "_px_rx"] := by
  rw [aaT17_nm_arr]

theorem aaT17_ops : aaT17.ops.toList = aaT16.ops.toList ++ fieldBinopGenInc 1 1 "OP_SUB" := by
  have hm1_nm : (aaT16.toTop "_px3").nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "rx", some "_rx2", some "_px3"] := by
    rw [toTop_nm_canonical aaT16 "_px3" 1
          (fd_of_nm aaT16 "_px3" 1 _ aaT16_nm_arr (by decide) (by decide)) (by rw [aaT16_nm_arr]; decide),
        aaT16_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT16.toTop "_px3").toTop "_rx2").rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "_s_keep", some "rx", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_rx2" 1
          (fd_of_nm _ "_rx2" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [aaT17, fieldSub_ops_concrete aaT16 "_px3" "_rx2" "_px_rx" 1 1 0
        (fd_of_nm aaT16 "_px3" 1 _ aaT16_nm_arr (by decide) (by decide))
        (fd_of_nm _ "_rx2" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide))]
  simp only [fieldBinopGenInc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- Step 18: `fieldMul aaT17 "_s_keep" "_px_rx" "_s_px_rx"` — `_s_keep` depth 2, `_px_rx` depth 1
(after `toTop _s_keep`), product depth 0. -/
def aaT18 : Ec.Tracker := Ec.fieldMul aaT17 "_s_keep" "_px_rx" "_s_px_rx"

theorem aaT18_nm_arr :
    aaT18.nm = #[some "px", some "py", some "qx", some "qy", some "rx", some "_s_px_rx"] := by
  rw [aaT18]; unfold Ec.fieldMul
  have hm1_nm : (aaT17.toTop "_s_keep").nm
      = #[some "px", some "py", some "qx", some "qy", some "rx", some "_px_rx", some "_s_keep"] := by
    rw [toTop_nm_canonical aaT17 "_s_keep" 2
          (fd_of_nm aaT17 "_s_keep" 2 _ aaT17_nm_arr (by decide) (by decide)) (by rw [aaT17_nm_arr]; decide),
        aaT17_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT17.toTop "_s_keep").toTop "_px_rx").rawBlock 2 (some "_fmul_prod") [.opcode "OP_MUL"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "rx", some "_fmul_prod"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_px_rx" 1
          (fd_of_nm _ "_px_rx" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fmul_prod" "_s_px_rx" 0
        (fd_of_nm _ "_fmul_prod" 0 _ hm2_nm (by decide) (by decide)) (by rw [hm2_nm]; decide), hm2_nm]
  apply Array.ext' <;> simp

theorem aaT18_nm :
    aaT18.nm.toList = [some "px", some "py", some "qx", some "qy", some "rx", some "_s_px_rx"] := by
  rw [aaT18_nm_arr]

theorem aaT18_ops : aaT18.ops.toList = aaT17.ops.toList ++ fieldBinopGenInc 2 1 "OP_MUL" := by
  have hm1_nm : (aaT17.toTop "_s_keep").nm
      = #[some "px", some "py", some "qx", some "qy", some "rx", some "_px_rx", some "_s_keep"] := by
    rw [toTop_nm_canonical aaT17 "_s_keep" 2
          (fd_of_nm aaT17 "_s_keep" 2 _ aaT17_nm_arr (by decide) (by decide)) (by rw [aaT17_nm_arr]; decide),
        aaT17_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT17.toTop "_s_keep").toTop "_px_rx").rawBlock 2 (some "_fmul_prod") [.opcode "OP_MUL"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "rx", some "_fmul_prod"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_px_rx" 1
          (fd_of_nm _ "_px_rx" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [aaT18, fieldMul_ops_concrete aaT17 "_s_keep" "_px_rx" "_s_px_rx" 2 1 0
        (fd_of_nm aaT17 "_s_keep" 2 _ aaT17_nm_arr (by decide) (by decide))
        (fd_of_nm _ "_px_rx" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fmul_prod" 0 _ hm2_nm (by decide) (by decide))]
  simp only [fieldBinopGenInc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-- Step 19: `copyToTop "py" "_py2"` (depth 4). -/
def aaT19 : Ec.Tracker := aaT18.copyToTop "py" "_py2"

theorem aaT19_nm :
    aaT19.nm.toList = [some "px", some "py", some "qx", some "qy", some "rx", some "_s_px_rx", some "_py2"] := by
  rw [aaT19, copyToTop_nm_toList, aaT18_nm]; rfl

theorem aaT19_nm_arr :
    aaT19.nm = #[some "px", some "py", some "qx", some "qy", some "rx", some "_s_px_rx", some "_py2"] :=
  Array.ext' (by rw [aaT19_nm])

theorem aaT19_ops : aaT19.ops.toList = aaT18.ops.toList ++ pickExtraOps 4 :=
  copyToTop_ops_concrete aaT18 "py" "_py2" 4 (fd_of_nm aaT18 "py" 4 _ aaT18_nm_arr (by decide) (by decide))

/-- Step 20: `fieldSub aaT19 "_s_px_rx" "_py2" "ry"` — `_s_px_rx` depth 1, `_py2` depth 1, diff depth 0. -/
def aaT20 : Ec.Tracker := Ec.fieldSub aaT19 "_s_px_rx" "_py2" "ry"

theorem aaT20_nm_arr :
    aaT20.nm = #[some "px", some "py", some "qx", some "qy", some "rx", some "ry"] := by
  rw [aaT20]; unfold Ec.fieldSub
  have hm1_nm : (aaT19.toTop "_s_px_rx").nm
      = #[some "px", some "py", some "qx", some "qy", some "rx", some "_py2", some "_s_px_rx"] := by
    rw [toTop_nm_canonical aaT19 "_s_px_rx" 1
          (fd_of_nm aaT19 "_s_px_rx" 1 _ aaT19_nm_arr (by decide) (by decide)) (by rw [aaT19_nm_arr]; decide),
        aaT19_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT19.toTop "_s_px_rx").toTop "_py2").rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "rx", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_py2" 1
          (fd_of_nm _ "_py2" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [fieldMod_nm _ "_fsub_diff" "ry" 0
        (fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide)) (by rw [hm2_nm]; decide), hm2_nm]
  apply Array.ext' <;> simp

theorem aaT20_nm :
    aaT20.nm.toList = [some "px", some "py", some "qx", some "qy", some "rx", some "ry"] := by
  rw [aaT20_nm_arr]

theorem aaT20_ops : aaT20.ops.toList = aaT19.ops.toList ++ fieldBinopGenInc 1 1 "OP_SUB" := by
  have hm1_nm : (aaT19.toTop "_s_px_rx").nm
      = #[some "px", some "py", some "qx", some "qy", some "rx", some "_py2", some "_s_px_rx"] := by
    rw [toTop_nm_canonical aaT19 "_s_px_rx" 1
          (fd_of_nm aaT19 "_s_px_rx" 1 _ aaT19_nm_arr (by decide) (by decide)) (by rw [aaT19_nm_arr]; decide),
        aaT19_nm_arr]
    apply Array.ext' <;> simp
  have hm2_nm : (((aaT19.toTop "_s_px_rx").toTop "_py2").rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]).nm
      = #[some "px", some "py", some "qx", some "qy", some "rx", some "_fsub_diff"] := by
    rw [rawBlock_nm_some2,
        toTop_nm_canonical _ "_py2" 1
          (fd_of_nm _ "_py2" 1 _ hm1_nm (by decide) (by decide)) (by rw [hm1_nm]; decide), hm1_nm]
    apply Array.ext' <;> simp
  rw [aaT20, fieldSub_ops_concrete aaT19 "_s_px_rx" "_py2" "ry" 1 1 0
        (fd_of_nm aaT19 "_s_px_rx" 1 _ aaT19_nm_arr (by decide) (by decide))
        (fd_of_nm _ "_py2" 1 _ hm1_nm (by decide) (by decide))
        (fd_of_nm _ "_fsub_diff" 0 _ hm2_nm (by decide) (by decide))]
  simp only [fieldBinopGenInc, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append]

/-! ### Cleanup steps 21-24: drop the four original input coords.  `toTop X |>.drop` for
`X ∈ {px, py, qx, qy}` (each at the live depth), leaving `nm = [rx, ry]`. -/

/-- Step 21: `toTop "px" |>.drop` — px at depth 5 → drop → `[py,qx,qy,rx,ry]`. -/
def aaT21 : Ec.Tracker := (aaT20.toTop "px").drop

theorem aaT21_nm_arr :
    aaT21.nm = #[some "py", some "qx", some "qy", some "rx", some "ry"] := by
  rw [aaT21]
  have hup : (aaT20.toTop "px").nm = #[some "py", some "qx", some "qy", some "rx", some "ry", some "px"] := by
    rw [toTop_nm_canonical aaT20 "px" 5
          (fd_of_nm aaT20 "px" 5 _ aaT20_nm_arr (by decide) (by decide)) (by rw [aaT20_nm_arr]; decide),
        aaT20_nm_arr]
    apply Array.ext' <;> simp
  apply Array.ext'
  rw [drop_nm_toList, hup]; rfl

theorem aaT21_nm :
    aaT21.nm.toList = [some "py", some "qx", some "qy", some "rx", some "ry"] := by
  rw [aaT21_nm_arr]

theorem aaT21_ops : aaT21.ops.toList = aaT20.ops.toList ++ rollExtraOps 5 ++ [StackOp.drop] := by
  rw [aaT21, drop_ops_append, toTop_ops_concrete aaT20 "px" 5
        (fd_of_nm aaT20 "px" 5 _ aaT20_nm_arr (by decide) (by decide))]

/-- Step 22: `toTop "py" |>.drop` — py at depth 4 → drop → `[qx,qy,rx,ry]`. -/
def aaT22 : Ec.Tracker := (aaT21.toTop "py").drop

theorem aaT22_nm_arr :
    aaT22.nm = #[some "qx", some "qy", some "rx", some "ry"] := by
  rw [aaT22]
  have hup : (aaT21.toTop "py").nm = #[some "qx", some "qy", some "rx", some "ry", some "py"] := by
    rw [toTop_nm_canonical aaT21 "py" 4
          (fd_of_nm aaT21 "py" 4 _ aaT21_nm_arr (by decide) (by decide)) (by rw [aaT21_nm_arr]; decide),
        aaT21_nm_arr]
    apply Array.ext' <;> simp
  apply Array.ext'
  rw [drop_nm_toList, hup]; rfl

theorem aaT22_nm :
    aaT22.nm.toList = [some "qx", some "qy", some "rx", some "ry"] := by
  rw [aaT22_nm_arr]

theorem aaT22_ops : aaT22.ops.toList = aaT21.ops.toList ++ rollExtraOps 4 ++ [StackOp.drop] := by
  rw [aaT22, drop_ops_append, toTop_ops_concrete aaT21 "py" 4
        (fd_of_nm aaT21 "py" 4 _ aaT21_nm_arr (by decide) (by decide))]

/-- Step 23: `toTop "qx" |>.drop` — qx at depth 3 → drop → `[qy,rx,ry]`. -/
def aaT23 : Ec.Tracker := (aaT22.toTop "qx").drop

theorem aaT23_nm_arr :
    aaT23.nm = #[some "qy", some "rx", some "ry"] := by
  rw [aaT23]
  have hup : (aaT22.toTop "qx").nm = #[some "qy", some "rx", some "ry", some "qx"] := by
    rw [toTop_nm_canonical aaT22 "qx" 3
          (fd_of_nm aaT22 "qx" 3 _ aaT22_nm_arr (by decide) (by decide)) (by rw [aaT22_nm_arr]; decide),
        aaT22_nm_arr]
    apply Array.ext' <;> simp
  apply Array.ext'
  rw [drop_nm_toList, hup]; rfl

theorem aaT23_nm :
    aaT23.nm.toList = [some "qy", some "rx", some "ry"] := by
  rw [aaT23_nm_arr]

theorem aaT23_ops : aaT23.ops.toList = aaT22.ops.toList ++ rollExtraOps 3 ++ [StackOp.drop] := by
  rw [aaT23, drop_ops_append, toTop_ops_concrete aaT22 "qx" 3
        (fd_of_nm aaT22 "qx" 3 _ aaT22_nm_arr (by decide) (by decide))]

/-- Step 24: `toTop "qy" |>.drop` — qy at depth 2 → drop → `[rx,ry]` (the affineAdd result). -/
def aaT24 : Ec.Tracker := (aaT23.toTop "qy").drop

theorem aaT24_nm_arr :
    aaT24.nm = #[some "rx", some "ry"] := by
  rw [aaT24]
  have hup : (aaT23.toTop "qy").nm = #[some "rx", some "ry", some "qy"] := by
    rw [toTop_nm_canonical aaT23 "qy" 2
          (fd_of_nm aaT23 "qy" 2 _ aaT23_nm_arr (by decide) (by decide)) (by rw [aaT23_nm_arr]; decide),
        aaT23_nm_arr]
    apply Array.ext' <;> simp
  apply Array.ext'
  rw [drop_nm_toList, hup]; rfl

theorem aaT24_nm :
    aaT24.nm.toList = [some "rx", some "ry"] := by
  rw [aaT24_nm_arr]

theorem aaT24_ops : aaT24.ops.toList = aaT23.ops.toList ++ rollExtraOps 2 ++ [StackOp.drop] := by
  rw [aaT24, drop_ops_append, toTop_ops_concrete aaT23 "qy" 2
        (fd_of_nm aaT23 "qy" 2 _ aaT23_nm_arr (by decide) (by decide))]

/-- **`Ec.affineAdd t = aaT24` when `t` is the entry tracker `aaT0`.**  The codegen
`affineAdd` is exactly the chained 24-step tracker — definitional unfolding establishes
`Ec.affineAdd aaT0 = aaT24`. -/
theorem affineAdd_eq_aaT24 : Ec.affineAdd aaT0 = aaT24 := by
  show Ec.affineAdd aaT0 = _
  rfl

/-- **The determined `affineAdd` op-list increment** (= `aaT24.ops.toList`, since `aaT0.ops = []`).
The 24-step concat: scratch copies (`pickExtraOps`), field ops (`fieldBinopGenInc`/`fieldSqrGenInc`),
the `fieldInv` core (`fieldInvCoreInc`, step 7), and the four cleanup drops. -/
def affineAddInc : List StackOp :=
  pickExtraOps 0 ++ pickExtraOps 3 ++ fieldBinopGenInc 1 1 "OP_SUB"
    ++ pickExtraOps 2 ++ pickExtraOps 5 ++ fieldBinopGenInc 1 1 "OP_SUB"
    ++ fieldInvCoreInc
    ++ fieldBinopGenInc 1 1 "OP_MUL" ++ pickExtraOps 0 ++ fieldSqrGenInc 1 2 1
    ++ pickExtraOps 5 ++ fieldBinopGenInc 1 1 "OP_SUB"
    ++ pickExtraOps 3 ++ fieldBinopGenInc 1 1 "OP_SUB"
    ++ pickExtraOps 5 ++ pickExtraOps 1 ++ fieldBinopGenInc 1 1 "OP_SUB"
    ++ fieldBinopGenInc 2 1 "OP_MUL" ++ pickExtraOps 4 ++ fieldBinopGenInc 1 1 "OP_SUB"
    ++ (rollExtraOps 5 ++ [StackOp.drop]) ++ (rollExtraOps 4 ++ [StackOp.drop])
    ++ (rollExtraOps 3 ++ [StackOp.drop]) ++ (rollExtraOps 2 ++ [StackOp.drop])

/-- **`aaT24.ops.toList = affineAddInc`** — the concrete 24-step op-list increment off the
empty-ops entry `aaT0`.  Chains the 24 per-step ops lemmas. -/
theorem aaT24_ops_full : aaT24.ops.toList = affineAddInc := by
  have aaT7_ops' : aaT7.ops.toList = aaT6.ops.toList ++ fieldInvCoreInc := by
    rw [aaT7]; exact aaT7_ops
  rw [aaT24_ops, aaT23_ops, aaT22_ops, aaT21_ops, aaT20_ops, aaT19_ops, aaT18_ops, aaT17_ops,
      aaT16_ops, aaT15_ops, aaT14_ops, aaT13_ops, aaT12_ops, aaT11_ops, aaT10_ops, aaT9_ops,
      aaT8_ops, aaT7_ops', aaT6_ops, aaT5_ops, aaT4_ops, aaT3_ops, aaT2_ops, aaT1_ops]
  show ([] ++ _ : List StackOp) = _
  simp only [aaT0, List.nil_append]
  unfold affineAddInc
  simp only [List.append_assoc, List.append_eq, List.nil_append, List.append_nil,
    List.cons_append, List.singleton_append,
    fieldSqrGenInc, fieldBinopGenInc, pickExtraOps, rollExtraOps]

/-! ### MANDATORY smokes for the affineAdd op-list deliverable -/

/-- SMOKE (the affineAdd result tracker FIRES).  Running the codegen `affineAdd` off the entry
`aaT0` (`nm = [px,py,qx,qy]`) lands the result `nm = [rx, ry]` — the two output coords, all four
inputs and scratch consumed.  Anti-vacuity: the result is exactly the two named result slots. -/
theorem smoke_affineAdd_result_nm :
    (Ec.affineAdd aaT0).nm.toList = [some "rx", some "ry"] := by
  rw [affineAdd_eq_aaT24, aaT24_nm]

/-- SMOKE (the affineAdd op-list is NON-EMPTY and determined).  The 24-step increment
`affineAddInc` is a genuine non-trivial Bitcoin-Script op-list (anti-vacuity: it begins with the
step-1 `copyToTop qy` = `.dup`). -/
theorem smoke_affineAddInc_head :
    (Ec.affineAdd aaT0).ops.toList.head? = some StackOp.dup := by
  rw [affineAdd_eq_aaT24, aaT24_ops_full]
  unfold affineAddInc
  simp only [pickExtraOps, List.append_assoc, List.cons_append, List.nil_append, List.head?_cons]

/-! ## Part 18 — affineAdd RUNTIME threading (deliverable 1)

Off the post-decompose entry runtime stack `[qy, qx, py, px] ++ rest` (nm bottom→top
`px,py,qx,qy`), thread the 24 determined `affineAddInc` steps to land the affine-add result
`[ry, rx] ++ rest` (nm `[rx, ry]`, `ry` on TOS).  Each `copyToTop`/`toTop` step uses the
depth-general `runOps_pickExtraOps` / `runOps_rollExtraOps` transports; each field-arith step
uses the Part-16 depth-general sims (`fieldBinop_runOps_simT` / `fieldSqr_runOps_simT`) at the
per-step `da`/`db` read off the matching `aaT{i}_ops` fact; the modular-inverse step uses the
proven `fieldInv_runOps_sim`.  The result coordinates equal the non-degenerate (`pxm ≠ qxm`)
branch of `Crypto.Secp256k1.affineAdd`.  All `propext`/`Quot.sound`(/`Classical.choice`)-clean
+ inherited backend opaques; NO new axiom, NO `native_decide` (smokes only). -/

private theorem niDropAA : ∀ t e, StackOp.drop ≠ .ifOp t e := by intro t e h; cases h

/-- **Pick step on an explicit `tracked ++ rest` stack.**  Running `pickExtraOps d`
(`d < tracked.length`) copies `tracked[d]!` to the top, keeping all of `tracked ++ rest`. -/
private theorem aaPickStep (s : StackState) (tracked rest : List Value) (d : Nat)
    (hStk : s.stack = tracked ++ rest) (hd : d < tracked.length) :
    runOps (pickExtraOps d) s = .ok { s with stack := tracked[d]! :: (tracked ++ rest) } := by
  rw [runOps_pickExtraOps s d (by rw [hStk, List.length_append]; omega),
      applyPick_append s tracked rest d hStk hd]
  rw [show s.push tracked[d]! = { s with stack := tracked[d]! :: (tracked ++ rest) } by
        unfold StackState.push; rw [hStk]]

/-- **Field-binop step on an explicit `tracked ++ rest` stack.**  Running
`fieldBinopGenInc da db binop` where the first operand `av` sits at depth `da` of `tracked`,
and (after rolling it up so the stack becomes `av :: mid'`) the second operand `bv` sits at
depth `db` of `av :: mid'` over the residual `av :: out`, lands `fieldMod (f av bv)` on top,
over `out ++ rest`.  The two roll witnesses are discharged by `applyRoll_append` off the
explicit prefixes `tracked` / `av :: mid'`. -/
private theorem aaBinopStep (binop : String) (f : Int → Int → Int)
    (s : StackState) (tracked rest mid' : List Value) (av bv : Int) (da db : Nat)
    (out : List Value)
    (hStk : s.stack = tracked ++ rest)
    (hda : da < tracked.length)
    (havDepth : tracked[da]! = Value.vBigint av)
    (hmid : tracked.eraseIdx da = mid')
    (hdb : db < (Value.vBigint av :: mid').length)
    (hbvDepth : (Value.vBigint av :: mid')[db]! = Value.vBigint bv)
    (hout : (Value.vBigint av :: mid').eraseIdx db = Value.vBigint av :: out)
    (hBinop : ∀ (t : StackState), t.stack = .vBigint bv :: .vBigint av :: (out ++ rest)
        → runOpcode binop t = .ok ({ t with stack := out ++ rest }.push (.vBigint (f av bv)))) :
    runOps (fieldBinopGenInc da db binop) s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldMod (f av bv)) :: (out ++ rest) } := by
  have hRoll1 : applyRoll s da = .ok { s with stack := .vBigint av :: (mid' ++ rest) } := by
    rw [applyRoll_append s tracked rest da hStk hda, havDepth, hmid]
  have hRoll2 : applyRoll { s with stack := .vBigint av :: (mid' ++ rest) } db
      = .ok { s with stack := .vBigint bv :: .vBigint av :: (out ++ rest) } := by
    rw [applyRoll_append { s with stack := .vBigint av :: (mid' ++ rest) }
          (.vBigint av :: mid') rest db (by rfl) hdb]
    rw [hbvDepth]
    congr 1
    rw [hout]
    simp only [List.cons_append]
  exact fieldBinop_runOps_simT binop f s av bv da db (mid' ++ rest) (out ++ rest)
    (by rw [hStk, List.length_append]; omega) hRoll1
    (by simp only [List.length_cons, List.length_append] at hdb ⊢; omega) hRoll2 hBinop

/-- **Field-square step on an explicit `tracked ++ rest` stack.**  Running
`fieldSqrGenInc dp dm1 dm2` where the value `av` sits at depth `dp` of `tracked`: the pick
copies `av`, then the inner mul squares the two copies.  After the copy push the stack prefix
is `av :: tracked`; `dm1` rolls one `av` up (lands `av :: mid'`), `dm2` rolls the second `av`
over it (lands `av :: av :: out`).  Both roll witnesses are discharged by `applyRoll_append`
off the explicit prefixes `av :: tracked` / `av :: mid'`. -/
private theorem aaSqrStep (s : StackState) (tracked rest : List Value) (av : Int)
    (dp dm1 dm2 : Nat) (mid' out : List Value)
    (hStk : s.stack = tracked ++ rest)
    (hdp : dp < tracked.length)
    (havDepth : tracked[dp]! = Value.vBigint av)
    (hdm1 : dm1 < (Value.vBigint av :: tracked).length)
    (hav1 : (Value.vBigint av :: tracked)[dm1]! = Value.vBigint av)
    (hmid : (Value.vBigint av :: tracked).eraseIdx dm1 = mid')
    (hdm2 : dm2 < (Value.vBigint av :: mid').length)
    (hav2 : (Value.vBigint av :: mid')[dm2]! = Value.vBigint av)
    (hout : (Value.vBigint av :: mid').eraseIdx dm2 = Value.vBigint av :: out) :
    runOps (fieldSqrGenInc dp dm1 dm2) s
      = .ok { s with stack := .vBigint (Crypto.Secp256k1.fieldMul av av) :: (out ++ rest) } := by
  have hPick : applyPick s dp = .ok (s.push (Value.vBigint av)) := by
    rw [applyPick_append s tracked rest dp hStk hdp, havDepth]
  have hPushStk : (s.push (Value.vBigint av)).stack = (Value.vBigint av :: tracked) ++ rest := by
    unfold StackState.push; rw [hStk]; rfl
  have hRoll1 : applyRoll (s.push (Value.vBigint av)) dm1
      = .ok { s with stack := .vBigint av :: (mid' ++ rest) } := by
    rw [applyRoll_append (s.push (Value.vBigint av)) (Value.vBigint av :: tracked) rest dm1
          hPushStk hdm1, hav1, hmid]
    rfl
  have hRoll2 : applyRoll { s with stack := .vBigint av :: (mid' ++ rest) } dm2
      = .ok { s with stack := .vBigint av :: .vBigint av :: (out ++ rest) } := by
    rw [applyRoll_append { s with stack := .vBigint av :: (mid' ++ rest) }
          (Value.vBigint av :: mid') rest dm2 (by rfl) hdm2, hav2]
    congr 1
    rw [hout]; simp only [List.cons_append]
  exact fieldSqr_runOps_simT s av dp dm1 dm2 (mid' ++ rest) (out ++ rest)
    (by rw [hStk, List.length_append]; omega) hPick
    (by rw [hPushStk, List.length_append] at *; simp only [List.length_cons] at hdm1 ⊢; omega)
    hRoll1
    (by simp only [List.length_cons, List.length_append] at hdm2 ⊢; omega) hRoll2

/-- **Cleanup step transport (roll-then-drop) on a right-associated `(rollExtraOps d ++
[.drop]) ++ tail` op-list.**  Rolls the depth-`d` element to the top, drops it, then continues
with `tail` from the residual stack.  `tail`-general so it threads the four right-associated
affineAdd cleanup drops without re-grouping. -/
private theorem aaRollDropStepT (s : StackState) (tracked rest : List Value) (d : Nat)
    (tail : List StackOp)
    (hStk : s.stack = tracked ++ rest) (hd : d < tracked.length) :
    runOps (rollExtraOps d ++ ([StackOp.drop] ++ tail)) s
      = runOps tail { s with stack := tracked.eraseIdx d ++ rest } := by
  rw [runOps_append, runOps_rollExtraOps s d (by rw [hStk, List.length_append]; omega),
      applyRoll_append s tracked rest d hStk hd]
  simp only [match_Except_ok_runOps, List.singleton_append]
  rw [runOps_cons_nonIf_eq _ _ _ niDropAA, stepNonIf_drop]
  rw [show applyDrop { s with stack := tracked[d]! :: (tracked.eraseIdx d ++ rest) }
        = .ok { s with stack := tracked.eraseIdx d ++ rest } from rfl]

open Crypto.Secp256k1 (fieldSub fieldMul fieldInv) in
/-- The codegen affine-add `s` slope: `num · den⁻¹` with `num = qy − py`, `den = qx − px`. -/
def aaSlope (px py qx qy : Int) : Int :=
  fieldMul (fieldSub qy py) (fieldInv (fieldSub qx px))

open Crypto.Secp256k1 (fieldSub fieldMul) in
/-- The codegen affine-add `rx` result: `s² − px − qx`. -/
def aaRx (px py qx qy : Int) : Int :=
  fieldSub (fieldSub (fieldMul (aaSlope px py qx qy) (aaSlope px py qx qy)) px) qx

open Crypto.Secp256k1 (fieldSub fieldMul) in
/-- The codegen affine-add `ry` result: `s · (px − rx) − py`. -/
def aaRy (px py qx qy : Int) : Int :=
  fieldSub (fieldMul (aaSlope px py qx qy) (fieldSub px (aaRx px py qx qy))) py

set_option maxRecDepth 4096 in
/-- **affineAdd runtime threading (deliverable 1).**  Running the determined 24-step
`affineAddInc` increment on the post-decompose entry `[qy, qx, py, px] ++ rest` lands
`[ry, rx] ++ rest` (`ry` on TOS, matching nm `[rx, ry]`), where `aaRx`/`aaRy` are the codegen
affine-add result coordinates.  Threads each step via the depth-general sims
(`fieldBinop_runOps_simT` / `fieldSqr_runOps_simT`) + the `fieldInv` sim + the four cleanup
roll-then-drops.  These coords coincide with `Crypto.Secp256k1.affineAdd`'s non-degenerate
branch (see `aaRx_aaRy_eq_affineAdd`). -/
theorem affineAddInc_runOps (s : StackState) (px py qx qy : Int) (rest : List Value)
    (hStk : s.stack = Value.vBigint qy :: Value.vBigint qx :: Value.vBigint py :: Value.vBigint px :: rest) :
    runOps affineAddInc s
      = .ok { s with stack :=
          Value.vBigint (aaRy px py qx qy) :: Value.vBigint (aaRx px py qx qy) :: rest } := by
  -- the codegen field-chain values, written as the `fieldMod (binop)` forms the sims land.
  -- num = qy − py
  have hn : Crypto.Secp256k1.fieldMod (qy - py) = Crypto.Secp256k1.fieldSub qy py := rfl
  -- den = qx − px
  have hd : Crypto.Secp256k1.fieldMod (qx - px) = Crypto.Secp256k1.fieldSub qx px := rfl
  unfold affineAddInc
  simp only [List.append_assoc]
  have subOp : ∀ (bv av : Int) (o : List Value) (t : StackState),
      t.stack = Value.vBigint bv :: Value.vBigint av :: o
        → runOpcode "OP_SUB" t = .ok ({ t with stack := o }.push (Value.vBigint (av - bv))) :=
    fun bv av o t ht => runOpcode_SUB_bigint_local t av bv o ht
  have mulOp : ∀ (bv av : Int) (o : List Value) (t : StackState),
      t.stack = Value.vBigint bv :: Value.vBigint av :: o
        → runOpcode "OP_MUL" t = .ok ({ t with stack := o }.push (Value.vBigint (av * bv))) :=
    fun bv av o t ht => runOpcode_MUL_bigint_local t av bv o ht
  -- step 1: copyToTop qy (pick 0) → [qy, qy, qx, py, px] ++ rest
  rw [runOps_append, aaPickStep s [Value.vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest 0
        hStk (by simp)]
  simp only [List.getElem!_cons_zero, match_Except_ok_runOps]
  -- step 2: copyToTop py (pick 3) → [py, qy, qy, qx, py, px] ++ rest
  rw [runOps_append, aaPickStep _ [Value.vBigint qy, .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest 3
        rfl (by simp)]
  simp only [show ([Value.vBigint qy, .vBigint qy, .vBigint qx, .vBigint py, .vBigint px][3]!) = Value.vBigint py from rfl,
    match_Except_ok_runOps]
  -- step 3: fieldSub _qy1 _py1 → num=fieldSub qy py.  da=1, db=1.
  rw [runOps_append,
      aaBinopStep "OP_SUB" (fun a b => a - b) _
        [Value.vBigint py, .vBigint qy, .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest
        [Value.vBigint py, .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        qy py 1 1 [Value.vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        rfl (by simp) rfl rfl (by simp) rfl rfl
        (fun t ht => subOp py qy _ t ht)]
  simp only [hn, match_Except_ok_runOps]
  -- step 4: copyToTop qx (pick 2) → [qx, N, qy, qx, py, px] ++ rest
  rw [runOps_append, aaPickStep _
        [Value.vBigint (Crypto.Secp256k1.fieldSub qy py), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest 2
        rfl (by simp)]
  simp only [show ([Value.vBigint (Crypto.Secp256k1.fieldSub qy py), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px][2]!) = Value.vBigint qx from rfl,
    match_Except_ok_runOps]
  -- step 5: copyToTop px (pick 5) → [px, qx, N, qy, qx, py, px] ++ rest
  rw [runOps_append, aaPickStep _
        [Value.vBigint qx, .vBigint (Crypto.Secp256k1.fieldSub qy py), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest 5
        rfl (by simp)]
  simp only [show ([Value.vBigint qx, .vBigint (Crypto.Secp256k1.fieldSub qy py), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px][5]!) = Value.vBigint px from rfl,
    match_Except_ok_runOps]
  -- step 6: fieldSub _qx1 _px1 → D=fieldSub qx px.  da=1, db=1.
  rw [runOps_append,
      aaBinopStep "OP_SUB" (fun a b => a - b) _
        [Value.vBigint px, .vBigint qx, .vBigint (Crypto.Secp256k1.fieldSub qy py), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest
        [Value.vBigint px, .vBigint (Crypto.Secp256k1.fieldSub qy py), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        qx px 1 1 [Value.vBigint (Crypto.Secp256k1.fieldSub qy py), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        rfl (by simp) rfl rfl (by simp) rfl rfl
        (fun t ht => subOp px qx _ t ht)]
  simp only [hd, match_Except_ok_runOps]
  -- step 7: fieldInv _s_den (depth 0, TOS) → DI=fieldInv D
  rw [runOps_append, fieldInv_runOps_sim _ (Crypto.Secp256k1.fieldSub qx px)
        (Value.vBigint (Crypto.Secp256k1.fieldSub qy py) :: .vBigint qy :: .vBigint qx :: .vBigint py :: .vBigint px :: rest) rfl]
  simp only [match_Except_ok_runOps]
  -- step 8: fieldMul _s_num _s_den_inv → SL=fieldMul N DI.  da=1, db=1.
  rw [runOps_append,
      aaBinopStep "OP_MUL" (fun a b => a * b) _
        [Value.vBigint (Crypto.Secp256k1.fieldInv (Crypto.Secp256k1.fieldSub qx px)),
          .vBigint (Crypto.Secp256k1.fieldSub qy py), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest
        [Value.vBigint (Crypto.Secp256k1.fieldInv (Crypto.Secp256k1.fieldSub qx px)),
          .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        (Crypto.Secp256k1.fieldSub qy py) (Crypto.Secp256k1.fieldInv (Crypto.Secp256k1.fieldSub qx px)) 1 1
        [Value.vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        rfl (by simp) rfl rfl (by simp) rfl rfl
        (fun t ht => mulOp (Crypto.Secp256k1.fieldInv (Crypto.Secp256k1.fieldSub qx px)) (Crypto.Secp256k1.fieldSub qy py) _ t ht)]
  simp only [show Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.fieldSub qy py * Crypto.Secp256k1.fieldInv (Crypto.Secp256k1.fieldSub qx px))
        = Crypto.Secp256k1.fieldMul (Crypto.Secp256k1.fieldSub qy py) (Crypto.Secp256k1.fieldInv (Crypto.Secp256k1.fieldSub qx px)) from rfl,
    match_Except_ok_runOps]
  -- abbreviate the slope SL = aaSlope (the result of step 8 on TOS)
  -- step 9: copyToTop _s (pick 0, dup) → [SL, SL, qy, qx, py, px] ++ rest
  rw [runOps_append, aaPickStep _
        [Value.vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest 0
        rfl (by simp)]
  simp only [List.getElem!_cons_zero, match_Except_ok_runOps]
  -- step 10: fieldSqr _s (dp=1, dm1=2, dm2=1) → SQ = fieldMul SL SL
  rw [runOps_append,
      aaSqrStep _
        [Value.vBigint (aaSlope px py qx qy), .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest
        (aaSlope px py qx qy) 1 2 1
        [Value.vBigint (aaSlope px py qx qy), .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        [Value.vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        rfl (by simp) rfl (by simp) rfl rfl (by simp) rfl rfl]
  simp only [match_Except_ok_runOps]
  -- step 11: copyToTop px (pick 5) → [px, SQ, SL, qy, qx, py, px] ++ rest
  rw [runOps_append, aaPickStep _
        [Value.vBigint (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (aaSlope px py qx qy)),
          .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest 5
        rfl (by simp)]
  simp only [show ([Value.vBigint (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (aaSlope px py qx qy)),
          .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px][5]!) = Value.vBigint px from rfl,
    match_Except_ok_runOps]
  -- step 12: fieldSub _s2 _px2 → R1 = fieldSub SQ px.  da=1, db=1.
  rw [runOps_append,
      aaBinopStep "OP_SUB" (fun a b => a - b) _
        [Value.vBigint px, .vBigint (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (aaSlope px py qx qy)),
          .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest
        [Value.vBigint px, .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (aaSlope px py qx qy)) px 1 1
        [Value.vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        rfl (by simp) rfl rfl (by simp) rfl rfl
        (fun t ht => subOp px (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (aaSlope px py qx qy)) _ t ht)]
  simp only [match_Except_ok_runOps]
  -- step 13: copyToTop qx (pick 3) → [qx, R1, SL, qy, qx, py, px] ++ rest
  rw [runOps_append, aaPickStep _
        [Value.vBigint (Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (aaSlope px py qx qy) - px)),
          .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest 3
        rfl (by simp)]
  simp only [show ([Value.vBigint (Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (aaSlope px py qx qy) - px)),
          .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px][3]!) = Value.vBigint qx from rfl,
    match_Except_ok_runOps]
  -- step 14: fieldSub _rx1 _qx2 → RX = fieldSub R1 qx = aaRx.  da=1, db=1.
  rw [runOps_append,
      aaBinopStep "OP_SUB" (fun a b => a - b) _
        [Value.vBigint qx,
          .vBigint (Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (aaSlope px py qx qy) - px)),
          .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest
        [Value.vBigint qx, .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        (Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (aaSlope px py qx qy) - px)) qx 1 1
        [Value.vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        rfl (by simp) rfl rfl (by simp) rfl rfl
        (fun t ht => subOp qx (Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (aaSlope px py qx qy) - px)) _ t ht)]
  simp only [match_Except_ok_runOps]
  -- fold the step-14 result to `aaRx`
  rw [show Crypto.Secp256k1.fieldMod
        (Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (aaSlope px py qx qy) - px) - qx)
        = aaRx px py qx qy from rfl]
  -- step 15: copyToTop px (pick 5) → [px, RX, SL, qy, qx, py, px] ++ rest
  rw [runOps_append, aaPickStep _
        [Value.vBigint (aaRx px py qx qy), .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest 5
        rfl (by simp)]
  simp only [show ([Value.vBigint (aaRx px py qx qy), .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px][5]!) = Value.vBigint px from rfl,
    match_Except_ok_runOps]
  -- step 16: copyToTop rx (pick 1) → [RX, px, RX, SL, qy, qx, py, px] ++ rest
  rw [runOps_append, aaPickStep _
        [Value.vBigint px, .vBigint (aaRx px py qx qy), .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest 1
        rfl (by simp)]
  simp only [show ([Value.vBigint px, .vBigint (aaRx px py qx qy), .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px][1]!) = Value.vBigint (aaRx px py qx qy) from rfl,
    match_Except_ok_runOps]
  -- step 17: fieldSub _px3 _rx2 → PR = fieldSub px RX.  da=1, db=1.
  rw [runOps_append,
      aaBinopStep "OP_SUB" (fun a b => a - b) _
        [Value.vBigint (aaRx px py qx qy), .vBigint px, .vBigint (aaRx px py qx qy), .vBigint (aaSlope px py qx qy),
          .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest
        [Value.vBigint (aaRx px py qx qy), .vBigint (aaRx px py qx qy), .vBigint (aaSlope px py qx qy),
          .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        px (aaRx px py qx qy) 1 1
        [Value.vBigint (aaRx px py qx qy), .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        rfl (by simp) rfl rfl (by simp) rfl rfl
        (fun t ht => subOp (aaRx px py qx qy) px _ t ht)]
  simp only [show Crypto.Secp256k1.fieldMod (px - aaRx px py qx qy) = Crypto.Secp256k1.fieldSub px (aaRx px py qx qy) from rfl,
    match_Except_ok_runOps]
  -- step 18: fieldMul _s_keep _px_rx → SP = fieldMul SL PR.  da=2, db=1.
  rw [runOps_append,
      aaBinopStep "OP_MUL" (fun a b => a * b) _
        [Value.vBigint (Crypto.Secp256k1.fieldSub px (aaRx px py qx qy)), .vBigint (aaRx px py qx qy),
          .vBigint (aaSlope px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest
        [Value.vBigint (Crypto.Secp256k1.fieldSub px (aaRx px py qx qy)), .vBigint (aaRx px py qx qy),
          .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        (aaSlope px py qx qy) (Crypto.Secp256k1.fieldSub px (aaRx px py qx qy)) 2 1
        [Value.vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        rfl (by simp) rfl rfl (by simp) rfl rfl
        (fun t ht => mulOp (Crypto.Secp256k1.fieldSub px (aaRx px py qx qy)) (aaSlope px py qx qy) _ t ht)]
  simp only [show Crypto.Secp256k1.fieldMod (aaSlope px py qx qy * Crypto.Secp256k1.fieldSub px (aaRx px py qx qy))
        = Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (Crypto.Secp256k1.fieldSub px (aaRx px py qx qy)) from rfl,
    match_Except_ok_runOps]
  -- step 19: copyToTop py (pick 4) → [py, SP, RX, qy, qx, py, px] ++ rest
  rw [runOps_append, aaPickStep _
        [Value.vBigint (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (Crypto.Secp256k1.fieldSub px (aaRx px py qx qy))),
          .vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest 4
        rfl (by simp)]
  simp only [show ([Value.vBigint (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (Crypto.Secp256k1.fieldSub px (aaRx px py qx qy))),
          .vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px][4]!) = Value.vBigint py from rfl,
    match_Except_ok_runOps]
  -- step 20: fieldSub _s_px_rx _py2 → RY = fieldSub SP py = aaRy.  da=1, db=1.
  rw [runOps_append,
      aaBinopStep "OP_SUB" (fun a b => a - b) _
        [Value.vBigint py,
          .vBigint (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (Crypto.Secp256k1.fieldSub px (aaRx px py qx qy))),
          .vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest
        [Value.vBigint py, .vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (Crypto.Secp256k1.fieldSub px (aaRx px py qx qy))) py 1 1
        [Value.vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px]
        rfl (by simp) rfl rfl (by simp) rfl rfl
        (fun t ht => subOp py (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (Crypto.Secp256k1.fieldSub px (aaRx px py qx qy))) _ t ht)]
  simp only [show Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.fieldMul (aaSlope px py qx qy) (Crypto.Secp256k1.fieldSub px (aaRx px py qx qy)) - py)
        = aaRy px py qx qy from rfl,
    match_Except_ok_runOps]
  -- cleanup steps 21-24: drop px, py, qx, qy → [RY, RX] ++ rest (right-associated drops).
  -- step 21: drop px (roll 5, drop)
  rw [aaRollDropStepT _
        [Value.vBigint (aaRy px py qx qy), .vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px] rest 5 _
        rfl (by simp)]
  simp only [show ([Value.vBigint (aaRy px py qx qy), .vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx, .vBigint py, .vBigint px].eraseIdx 5)
        = [Value.vBigint (aaRy px py qx qy), .vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx, .vBigint py] from rfl]
  -- step 22: drop py (roll 4, drop)
  rw [aaRollDropStepT _
        [Value.vBigint (aaRy px py qx qy), .vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx, .vBigint py] rest 4 _
        rfl (by simp)]
  simp only [show ([Value.vBigint (aaRy px py qx qy), .vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx, .vBigint py].eraseIdx 4)
        = [Value.vBigint (aaRy px py qx qy), .vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx] from rfl]
  -- step 23: drop qx (roll 3, drop)
  rw [aaRollDropStepT _
        [Value.vBigint (aaRy px py qx qy), .vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx] rest 3 _
        rfl (by simp)]
  simp only [show ([Value.vBigint (aaRy px py qx qy), .vBigint (aaRx px py qx qy), .vBigint qy, .vBigint qx].eraseIdx 3)
        = [Value.vBigint (aaRy px py qx qy), .vBigint (aaRx px py qx qy), .vBigint qy] from rfl]
  -- step 24: drop qy (rot, drop) → [RY, RX] ++ rest
  rw [show (rollExtraOps 2 ++ [StackOp.drop] : List StackOp)
        = rollExtraOps 2 ++ ([StackOp.drop] ++ []) from by simp]
  rw [aaRollDropStepT _
        [Value.vBigint (aaRy px py qx qy), .vBigint (aaRx px py qx qy), .vBigint qy] rest 2 []
        rfl (by simp)]
  rw [runOps_nil,
      show ([Value.vBigint (aaRy px py qx qy), .vBigint (aaRx px py qx qy), .vBigint qy].eraseIdx 2)
        = [Value.vBigint (aaRy px py qx qy), .vBigint (aaRx px py qx qy)] from rfl]
  simp only [List.cons_append, List.nil_append]

/-- **The codegen affine-add coords equal `Crypto.Secp256k1.affineAdd`'s non-degenerate branch.**
Under the non-degenerate hypotheses — neither input is the sentinel zero-point and
`fieldMod px ≠ fieldMod qx` (so the affine formula takes the `pxm ≠ qxm` branch, NOT the
`affineDouble` fallback) — `affineAdd px py qx qy = (aaRx px py qx qy, aaRy px py qx qy)`.
The codegen names mirror the spec's `num`/`den`/`s`/`rx`/`ry` exactly (definitional). -/
theorem aaRx_aaRy_eq_affineAdd (px py qx qy : Int)
    (hp : ¬ (px = 0 ∧ py = 0)) (hq : ¬ (qx = 0 ∧ qy = 0))
    (hne : Crypto.Secp256k1.fieldMod px ≠ Crypto.Secp256k1.fieldMod qx) :
    Crypto.Secp256k1.affineAdd px py qx qy = (aaRx px py qx qy, aaRy px py qx qy) := by
  unfold Crypto.Secp256k1.affineAdd
  rw [if_neg hp, if_neg hq, if_neg hne]
  rfl

/-! ### MANDATORY smokes for the affineAdd runtime threading (deliverable 1) -/

/-- Concrete entry stack for the affineAdd-threading smoke: `[qy, qx, py, px]` = `[44, 33, 22, 11]`
with a passive tail `[999]` beneath. -/
private def smokeAAStk : StackState :=
  { (default : StackState) with
    stack := [.vBigint 44, .vBigint 33, .vBigint 22, .vBigint 11, .vBigint 999] }

/-- SMOKE (the affineAdd runtime threading FIRES, anti-vacuity).  Running `affineAddInc` on the
concrete post-decompose entry `[44, 33, 22, 11] ++ [999]` lands `[aaRy, aaRx] ++ [999]` (`aaRy`
on TOS), with the passive tail `[999]` preserved beneath — the whole 24-step chain reduces. -/
theorem smoke_affineAddInc_runOps :
    runOps affineAddInc smokeAAStk
      = .ok { smokeAAStk with
          stack := .vBigint (aaRy 11 22 33 44) :: .vBigint (aaRx 11 22 33 44) :: [.vBigint 999] } :=
  affineAddInc_runOps smokeAAStk 11 22 33 44 [.vBigint 999] rfl

/-- SMOKE (the affineAdd↔spec bridge FIRES, anti-vacuity).  On two distinct concrete
non-sentinel coords with `fieldMod 11 ≠ fieldMod 33`, the spec `affineAdd` equals the codegen
`(aaRx, aaRy)` pair — the non-degenerate branch is genuinely taken. -/
theorem smoke_aaRx_aaRy_eq_affineAdd :
    Crypto.Secp256k1.affineAdd 11 22 33 44 = (aaRx 11 22 33 44, aaRy 11 22 33 44) :=
  aaRx_aaRy_eq_affineAdd 11 22 33 44 (by decide) (by decide) (by decide)

/-- SMOKE (`fieldInv_nm_depth0` FIRES).  On a concrete depth-0 entry (`nm = [_pa, a]`, `a` on
TOS), `fieldInv` lands `nm = [_pa, r]` — input consumed, inverse on TOS. -/
theorem smoke_fieldInv_nm_depth0 :
    (Ec.fieldInv ⟨#[some "_pa", some "_s_den"], #[]⟩ "_s_den" "_s_den_inv").nm.toList
      = [some "_pa", some "_s_den_inv"] :=
  fieldInv_nm_depth0 ⟨#[some "_pa", some "_s_den"], #[]⟩ [some "_pa"] "_s_den" "_s_den_inv"
    (by decide) (by decide)

/-! ### Ops-rebasing meta-lemma (entry-ops irrelevance for nm; append-only for ops).

Every Tracker primitive reads only `t.nm` for its nm transform and appends to `t.ops`.  So any
composite `f` "factors through" the empty-ops entry: `(f t).nm = (f (clearOps t)).nm` and
`(f t).ops = t.ops ++ (f (clearOps t)).ops`.  This is exactly what transports the concrete
`affineAdd_eq_aaT24` (anchored on `aaT0`, ops `#[]`) to a GENERAL entry tracker. -/

/-- Reset a tracker's ops to empty (nm preserved). -/
def clearOps (t : Ec.Tracker) : Ec.Tracker := { t with ops := #[] }

/-- A tracker transform `f` is **ops-rebasable**: nm output is entry-ops-independent and ops is
extended by append from the entry. -/
def Rebasable (f : Ec.Tracker → Ec.Tracker) : Prop :=
  ∀ t, (f t).nm = (f (clearOps t)).nm
    ∧ (f t).ops.toList = t.ops.toList ++ (f (clearOps t)).ops.toList

/-- `clearOps` of trackers with equal nm are equal (ops both `#[]`). -/
private theorem clearOps_eq_of_nm {t₁ t₂ : Ec.Tracker} (h : t₁.nm = t₂.nm) :
    clearOps t₁ = clearOps t₂ := by
  unfold clearOps; rw [h]

/-- `clearOps t` has empty ops. -/
private theorem clearOps_ops (t : Ec.Tracker) : (clearOps t).ops.toList = [] := by
  unfold clearOps; simp

/-- `findDepth` is ops-independent. -/
private theorem findDepth_clearOps (t : Ec.Tracker) (name : String) :
    (clearOps t).findDepth name = t.findDepth name := rfl

/-- `findDepth` depends only on `nm`. -/
private theorem findDepth_of_nm_eq {t₁ t₂ : Ec.Tracker} (h : t₁.nm = t₂.nm) (name : String) :
    t₁.findDepth name = t₂.findDepth name := by
  unfold Ec.Tracker.findDepth; rw [h]

theorem rebasable_id : Rebasable id := by
  intro t; exact ⟨rfl, by simp [clearOps]⟩

/-- Rebasable is closed under (diagrammatic) composition `g ∘ f` (apply `f`, then `g`). -/
theorem rebasable_comp {f g : Ec.Tracker → Ec.Tracker} (hf : Rebasable f) (hg : Rebasable g) :
    Rebasable (fun t => g (f t)) := by
  intro t
  obtain ⟨hf_nm, hf_ops⟩ := hf t
  obtain ⟨hg_nm1, hg_ops1⟩ := hg (f t)
  obtain ⟨hg_nm0, hg_ops0⟩ := hg (f (clearOps t))
  have hcl_eq : clearOps (f t) = clearOps (f (clearOps t)) := clearOps_eq_of_nm hf_nm
  refine ⟨?_, ?_⟩
  · rw [hg_nm1, hcl_eq, ← hg_nm0]
  · rw [hg_ops1, hf_ops, hcl_eq, hg_ops0]
    simp only [List.append_assoc]

/-- `roll`'s nm output is entry-ops-independent (case on the depth `d`; each branch's nm
transform reads only `t.nm`).  These `op_nm_clearOps_*` lemmas establish that every primitive's
nm transform reads only `t.nm`, so `(op t).nm = (op (clearOps t)).nm`. -/
private theorem roll_nm_clearOps (nm : Array (Option String)) (o₁ o₂ : Array StackOp) (d : Nat) :
    (Ec.Tracker.roll ⟨nm, o₁⟩ d).nm = (Ec.Tracker.roll ⟨nm, o₂⟩ d).nm := by
  unfold Ec.Tracker.roll
  match d with
  | 0 => rfl
  | 1 => unfold Ec.Tracker.swap Ec.Tracker.emit; dsimp only; split <;> rfl
  | 2 => unfold Ec.Tracker.rot Ec.Tracker.emit; dsimp only; split <;> rfl
  | n + 3 => unfold Ec.Tracker.emit; dsimp only; split <;> rfl

private theorem pick_nm_clearOps (nm : Array (Option String)) (o₁ o₂ : Array StackOp)
    (d : Nat) (n : String) :
    (Ec.Tracker.pick ⟨nm, o₁⟩ d n).nm = (Ec.Tracker.pick ⟨nm, o₂⟩ d n).nm := by
  unfold Ec.Tracker.pick
  match d with
  | 0 => unfold Ec.Tracker.dup Ec.Tracker.emit; rfl
  | 1 => unfold Ec.Tracker.over Ec.Tracker.emit; rfl
  | k + 2 => unfold Ec.Tracker.emit; rfl

private theorem op_nm_clearOps_toTop (t : Ec.Tracker) (name : String) :
    (t.toTop name).nm = ((clearOps t).toTop name).nm := by
  obtain ⟨nm, ops⟩ := t
  show (Ec.Tracker.roll ⟨nm, ops⟩ (Ec.Tracker.findDepth ⟨nm, ops⟩ name)).nm
      = (Ec.Tracker.roll ⟨nm, #[]⟩ (Ec.Tracker.findDepth ⟨nm, #[]⟩ name)).nm
  rw [show Ec.Tracker.findDepth ⟨nm, #[]⟩ name = Ec.Tracker.findDepth ⟨nm, ops⟩ name from rfl]
  exact roll_nm_clearOps nm ops #[] _

private theorem op_nm_clearOps_copyToTop (t : Ec.Tracker) (name newName : String) :
    (t.copyToTop name newName).nm = ((clearOps t).copyToTop name newName).nm := by
  obtain ⟨nm, ops⟩ := t
  show (Ec.Tracker.pick ⟨nm, ops⟩ (Ec.Tracker.findDepth ⟨nm, ops⟩ name) newName).nm
      = (Ec.Tracker.pick ⟨nm, #[]⟩ (Ec.Tracker.findDepth ⟨nm, #[]⟩ name) newName).nm
  rw [show Ec.Tracker.findDepth ⟨nm, #[]⟩ name = Ec.Tracker.findDepth ⟨nm, ops⟩ name from rfl]
  exact pick_nm_clearOps nm ops #[] _ newName

private theorem op_nm_clearOps_drop (t : Ec.Tracker) :
    (t.drop).nm = ((clearOps t).drop).nm := by
  obtain ⟨nm, ops⟩ := t; simp only [clearOps]; rfl

/-- The pop-loop inside `rawBlock` (over `[0:cnt]`) reads only `nm` — captured as a helper so the
ops-independence of `rawBlock.nm` follows.  Proven by induction on `cnt`. -/
private theorem rawBlock_popLoop_eq (nm : Array (Option String)) (o₁ o₂ : Array StackOp)
    (cnt : Nat) (prod : Option String) (e : List StackOp) :
    (Ec.Tracker.rawBlock ⟨nm, o₁⟩ cnt prod e).nm = (Ec.Tracker.rawBlock ⟨nm, o₂⟩ cnt prod e).nm := by
  unfold Ec.Tracker.rawBlock
  simp only [Id.run]
  -- the nm-output is the `[0:cnt]` pop-fold over `nm`, then optional push; ops-fold is irrelevant
  cases prod <;> rfl

private theorem op_nm_clearOps_rawBlock (t : Ec.Tracker) (cnt : Nat) (prod : Option String)
    (e : List StackOp) :
    (t.rawBlock cnt prod e).nm = ((clearOps t).rawBlock cnt prod e).nm := by
  obtain ⟨nm, ops⟩ := t
  show (Ec.Tracker.rawBlock ⟨nm, ops⟩ cnt prod e).nm = (Ec.Tracker.rawBlock ⟨nm, #[]⟩ cnt prod e).nm
  exact rawBlock_popLoop_eq nm ops #[] cnt prod e

private theorem op_nm_clearOps_pushInt (t : Ec.Tracker) (name : String) (v : Int) :
    (t.pushInt name v).nm = ((clearOps t).pushInt name v).nm := by
  obtain ⟨nm, ops⟩ := t; simp only [clearOps]; rfl

private theorem op_nm_clearOps_rename (t : Ec.Tracker) (name : String) :
    (t.rename name).nm = ((clearOps t).rename name).nm := by
  obtain ⟨nm, ops⟩ := t; simp only [clearOps]
  unfold Ec.Tracker.rename; dsimp only; split <;> rfl

/-- `findDepth` after `toTop` is ops-independent (nm-independence of `toTop` + findDepth-of-nm). -/
private theorem op_findDepth_clearOps_toTop (t : Ec.Tracker) (a b : String) :
    ((clearOps t).toTop a).findDepth b = (t.toTop a).findDepth b :=
  findDepth_of_nm_eq (op_nm_clearOps_toTop t a).symm b

/-- nm after `toTop a` then `toTop b` is ops-independent. -/
private theorem op_nm_clearOps_toTop2 (t : Ec.Tracker) (a b : String) :
    (((clearOps t).toTop a).toTop b).nm = ((t.toTop a).toTop b).nm := by
  have h1 : ((clearOps t).toTop a).nm = (t.toTop a).nm := (op_nm_clearOps_toTop t a).symm
  -- bring the inner toTop nm into agreement, then toTop b is nm-determined
  have key : ∀ (s₁ s₂ : Ec.Tracker), s₁.nm = s₂.nm → (s₁.toTop b).nm = (s₂.toTop b).nm := by
    intro s₁ s₂ hs
    rw [op_nm_clearOps_toTop s₁ b, op_nm_clearOps_toTop s₂ b, clearOps_eq_of_nm hs]
  exact key _ _ h1

/-- `findDepth` after the binop `rawBlock 2` is ops-independent. -/
private theorem op_findDepth_clearOps_rawBlock2 (t : Ec.Tracker) (a b prod r : String)
    (binop : StackOp) :
    ((((clearOps t).toTop a).toTop b).rawBlock 2 (some prod) [binop]).findDepth r
      = (((t.toTop a).toTop b).rawBlock 2 (some prod) [binop]).findDepth r := by
  apply findDepth_of_nm_eq
  have key : ∀ (s₁ s₂ : Ec.Tracker), s₁.nm = s₂.nm →
      (s₁.rawBlock 2 (some prod) [binop]).nm = (s₂.rawBlock 2 (some prod) [binop]).nm := by
    intro s₁ s₂ hs
    rw [op_nm_clearOps_rawBlock s₁, op_nm_clearOps_rawBlock s₂, clearOps_eq_of_nm hs]
  exact key _ _ (op_nm_clearOps_toTop2 t a b)

/-! nm-congruence of the primitives: equal entry nm ⟹ equal output nm. -/

private theorem toTop_nmCongr {t₁ t₂ : Ec.Tracker} (h : t₁.nm = t₂.nm) (name : String) :
    (t₁.toTop name).nm = (t₂.toTop name).nm := by
  obtain ⟨nm₁, o₁⟩ := t₁; obtain ⟨nm₂, o₂⟩ := t₂
  simp only [Ec.Tracker.mk.injEq] at h; subst h
  show (Ec.Tracker.roll ⟨nm₁, o₁⟩ _).nm = (Ec.Tracker.roll ⟨nm₁, o₂⟩ _).nm
  rw [show Ec.Tracker.findDepth ⟨nm₁, o₂⟩ name = Ec.Tracker.findDepth ⟨nm₁, o₁⟩ name from rfl]
  exact roll_nm_clearOps nm₁ o₁ o₂ _

private theorem copyToTop_nmCongr {t₁ t₂ : Ec.Tracker} (h : t₁.nm = t₂.nm) (name newName : String) :
    (t₁.copyToTop name newName).nm = (t₂.copyToTop name newName).nm := by
  obtain ⟨nm₁, o₁⟩ := t₁; obtain ⟨nm₂, o₂⟩ := t₂
  simp only [Ec.Tracker.mk.injEq] at h; subst h
  show (Ec.Tracker.pick ⟨nm₁, o₁⟩ _ newName).nm = (Ec.Tracker.pick ⟨nm₁, o₂⟩ _ newName).nm
  rw [show Ec.Tracker.findDepth ⟨nm₁, o₂⟩ name = Ec.Tracker.findDepth ⟨nm₁, o₁⟩ name from rfl]
  exact pick_nm_clearOps nm₁ o₁ o₂ _ newName

private theorem rawBlock_nmCongr {t₁ t₂ : Ec.Tracker} (h : t₁.nm = t₂.nm)
    (cnt : Nat) (prod : Option String) (e : List StackOp) :
    (t₁.rawBlock cnt prod e).nm = (t₂.rawBlock cnt prod e).nm := by
  obtain ⟨nm₁, o₁⟩ := t₁; obtain ⟨nm₂, o₂⟩ := t₂
  simp only [Ec.Tracker.mk.injEq] at h; subst h
  exact rawBlock_popLoop_eq nm₁ o₁ o₂ cnt prod e

private theorem pushInt_nmCongr {t₁ t₂ : Ec.Tracker} (h : t₁.nm = t₂.nm) (name : String) (v : Int) :
    (t₁.pushInt name v).nm = (t₂.pushInt name v).nm := by
  obtain ⟨nm₁, o₁⟩ := t₁; obtain ⟨nm₂, o₂⟩ := t₂
  simp only [Ec.Tracker.mk.injEq] at h; subst h; rfl

private theorem fieldMod_nmCongr {t₁ t₂ : Ec.Tracker} (h : t₁.nm = t₂.nm) (a r : String) :
    (Ec.fieldMod t₁ a r).nm = (Ec.fieldMod t₂ a r).nm := by
  show (Ec.Tracker.rawBlock (Ec.pushFieldP (t₁.toTop a) "_fmod_p") 2 (some r) Ec.fieldModOps).nm
      = (Ec.Tracker.rawBlock (Ec.pushFieldP (t₂.toTop a) "_fmod_p") 2 (some r) Ec.fieldModOps).nm
  apply rawBlock_nmCongr
  show (Ec.Tracker.pushInt (t₁.toTop a) "_fmod_p" Ec.fieldP).nm
      = (Ec.Tracker.pushInt (t₂.toTop a) "_fmod_p" Ec.fieldP).nm
  exact pushInt_nmCongr (toTop_nmCongr h a) "_fmod_p" Ec.fieldP

private theorem fieldBinop_nmCongr {t₁ t₂ : Ec.Tracker} (h : t₁.nm = t₂.nm)
    (a b prod r : String) (binop : StackOp) :
    (Ec.fieldMod (((t₁.toTop a).toTop b).rawBlock 2 (some prod) [binop]) prod r).nm
      = (Ec.fieldMod (((t₂.toTop a).toTop b).rawBlock 2 (some prod) [binop]) prod r).nm := by
  apply fieldMod_nmCongr
  apply rawBlock_nmCongr
  exact toTop_nmCongr (toTop_nmCongr h a) b

theorem rebasable_toTop (name : String) : Rebasable (fun t => t.toTop name) := by
  intro t
  refine ⟨op_nm_clearOps_toTop t name, ?_⟩
  rw [toTop_ops_concrete t name (t.findDepth name) rfl,
      toTop_ops_concrete (clearOps t) name ((clearOps t).findDepth name) rfl,
      findDepth_clearOps, clearOps_ops]
  simp

theorem rebasable_copyToTop (name newName : String) :
    Rebasable (fun t => t.copyToTop name newName) := by
  intro t
  refine ⟨op_nm_clearOps_copyToTop t name newName, ?_⟩
  rw [copyToTop_ops_concrete t name newName (t.findDepth name) rfl,
      copyToTop_ops_concrete (clearOps t) name newName ((clearOps t).findDepth name) rfl,
      findDepth_clearOps, clearOps_ops]
  simp

theorem rebasable_drop : Rebasable (fun t => t.drop) := by
  intro t
  refine ⟨op_nm_clearOps_drop t, ?_⟩
  rw [drop_ops_append t, drop_ops_append (clearOps t), clearOps_ops]; simp

theorem rebasable_rawBlock (cnt : Nat) (prod : Option String) (e : List StackOp) :
    Rebasable (fun t => t.rawBlock cnt prod e) := by
  intro t
  refine ⟨op_nm_clearOps_rawBlock t cnt prod e, ?_⟩
  rw [rawBlock_ops_append, rawBlock_ops_append, clearOps_ops]; simp

theorem rebasable_pushInt (name : String) (v : Int) :
    Rebasable (fun t => t.pushInt name v) := by
  intro t
  refine ⟨op_nm_clearOps_pushInt t name v, ?_⟩
  unfold Ec.Tracker.pushInt Ec.Tracker.emit clearOps; simp

theorem rebasable_rename (name : String) : Rebasable (fun t => t.rename name) := by
  intro t
  refine ⟨op_nm_clearOps_rename t name, ?_⟩
  rw [show (t.rename name).ops = t.ops from rename_ops t name,
      show ((clearOps t).rename name).ops = (clearOps t).ops from rename_ops (clearOps t) name,
      clearOps_ops]
  simp

/-- Rebasable transports along function equality. -/
theorem rebasable_congr {f g : Ec.Tracker → Ec.Tracker} (h : ∀ t, f t = g t)
    (hg : Rebasable g) : Rebasable f := by
  intro t
  obtain ⟨hnm, hops⟩ := hg t
  refine ⟨?_, ?_⟩
  · rw [h t, hnm, h (clearOps t)]
  · rw [h t, hops, h (clearOps t)]

/-- `pushFieldP` is Rebasable (it IS `pushInt _ fieldP`). -/
theorem rebasable_pushFieldP (name : String) : Rebasable (fun t => Ec.pushFieldP t name) :=
  rebasable_pushInt name Ec.fieldP

/-- `fieldMod` is Rebasable (toTop ∘ pushFieldP ∘ rawBlock).  Proved via the per-conjunct
direct route (nm ops-independence by destructure; ops via `fieldMod_ops_append`) to dodge the
`@[inline]` reduction battle that `rebasable_comp`'s unifier hits on `pushInt`/`rawBlock`. -/
theorem rebasable_fieldMod (a r : String) : Rebasable (fun t => Ec.fieldMod t a r) := by
  intro t
  simp only []
  refine ⟨fieldMod_nmCongr (t₁ := t) (t₂ := clearOps t) rfl a r, ?_⟩
  rw [fieldMod_ops_append t a r, fieldMod_ops_append (clearOps t) a r, clearOps_ops,
      findDepth_clearOps]
  simp

theorem rebasable_fieldSub (a b r : String) : Rebasable (fun t => Ec.fieldSub t a b r) := by
  intro t
  simp only []
  refine ⟨fieldBinop_nmCongr (t₁ := t) (t₂ := clearOps t) rfl a b "_fsub_diff" r (.opcode "OP_SUB"), ?_⟩
  rw [show Ec.fieldSub t a b r
          = Ec.fieldMod (((t.toTop a).toTop b).rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]) "_fsub_diff" r
        from rfl,
      show Ec.fieldSub (clearOps t) a b r
          = Ec.fieldMod ((((clearOps t).toTop a).toTop b).rawBlock 2 (some "_fsub_diff") [.opcode "OP_SUB"]) "_fsub_diff" r
        from rfl,
      fieldBinop_ops_append t a b "_fsub_diff" r (.opcode "OP_SUB"),
      fieldBinop_ops_append (clearOps t) a b "_fsub_diff" r (.opcode "OP_SUB"),
      show (clearOps t).findDepth a = t.findDepth a from rfl,
      op_findDepth_clearOps_toTop t a b,
      op_findDepth_clearOps_rawBlock2 t a b "_fsub_diff" "_fsub_diff" (.opcode "OP_SUB"),
      clearOps_ops]
  simp

theorem rebasable_fieldMul (a b r : String) : Rebasable (fun t => Ec.fieldMul t a b r) := by
  intro t
  simp only []
  refine ⟨fieldBinop_nmCongr (t₁ := t) (t₂ := clearOps t) rfl a b "_fmul_prod" r (.opcode "OP_MUL"), ?_⟩
  rw [show Ec.fieldMul t a b r
          = Ec.fieldMod (((t.toTop a).toTop b).rawBlock 2 (some "_fmul_prod") [.opcode "OP_MUL"]) "_fmul_prod" r
        from rfl,
      show Ec.fieldMul (clearOps t) a b r
          = Ec.fieldMod ((((clearOps t).toTop a).toTop b).rawBlock 2 (some "_fmul_prod") [.opcode "OP_MUL"]) "_fmul_prod" r
        from rfl,
      fieldBinop_ops_append t a b "_fmul_prod" r (.opcode "OP_MUL"),
      fieldBinop_ops_append (clearOps t) a b "_fmul_prod" r (.opcode "OP_MUL"),
      show (clearOps t).findDepth a = t.findDepth a from rfl,
      op_findDepth_clearOps_toTop t a b,
      op_findDepth_clearOps_rawBlock2 t a b "_fmul_prod" "_fmul_prod" (.opcode "OP_MUL"),
      clearOps_ops]
  simp

theorem rebasable_fieldSqr (a r : String) : Rebasable (fun t => Ec.fieldSqr t a r) :=
  rebasable_congr (f := fun t => Ec.fieldSqr t a r)
    (g := fun t => Ec.fieldMul (t.copyToTop a "_fsqr_copy") a "_fsqr_copy" r)
    (fun t => by unfold Ec.fieldSqr; rfl)
    (rebasable_comp (rebasable_copyToTop a "_fsqr_copy") (rebasable_fieldMul a "_fsqr_copy" r))

/-- `hiIterBody · aName` is Rebasable (fieldSqr; rename; copyToTop; fieldMul; rename). -/
theorem rebasable_hiIterBody (aName : String) : Rebasable (fun t => hiIterBody t aName) := by
  refine rebasable_congr
    (g := fun t => Ec.Tracker.rename (Ec.fieldMul (Ec.Tracker.copyToTop
            (Ec.Tracker.rename (Ec.fieldSqr t "_inv_r" "_inv_r2") "_inv_r") aName "_inv_a")
            "_inv_r" "_inv_a" "_inv_m") "_inv_r")
    (fun t => by unfold hiIterBody; rfl) ?_
  exact rebasable_comp
    (rebasable_comp
      (rebasable_comp
        (rebasable_comp (rebasable_fieldSqr "_inv_r" "_inv_r2") (rebasable_rename "_inv_r"))
        (rebasable_copyToTop aName "_inv_a"))
      (rebasable_fieldMul "_inv_r" "_inv_a" "_inv_m"))
    (rebasable_rename "_inv_r")

/-- `fieldInvHighLoop n · aName` is Rebasable (induction on `n`; each step is a fixed
square-and-multiply composition of Rebasable primitives). -/
theorem rebasable_fieldInvHighLoop (n : Nat) (aName : String) :
    Rebasable (fun t => Ec.fieldInvHighLoop n t aName) := by
  induction n with
  | zero =>
    have h : (fun t => Ec.fieldInvHighLoop 0 t aName) = id := by funext t; rfl
    rw [h]; exact rebasable_id
  | succ k ih =>
    have h : (fun t => Ec.fieldInvHighLoop (k+1) t aName)
        = (fun t => Ec.fieldInvHighLoop k (hiIterBody t aName) aName) := by
      funext t; exact fieldInvHighLoop_succ k t aName
    rw [h]
    exact rebasable_comp (rebasable_hiIterBody aName) ih

/-- `fieldInvLowLoop steps lowBits · aName` is Rebasable (induction on `steps`; each step is a
`by_cases` on the bit — both branches Rebasable). -/
theorem rebasable_fieldInvLowLoop (steps : Nat) (lowBits : Int) (aName : String) :
    Rebasable (fun t => Ec.fieldInvLowLoop steps lowBits t aName) := by
  induction steps with
  | zero =>
    have h : (fun t => Ec.fieldInvLowLoop 0 lowBits t aName) = id := by funext t; rfl
    rw [h]; exact rebasable_id
  | succ k ih =>
    have h : (fun t => Ec.fieldInvLowLoop (k+1) lowBits t aName)
        = (fun t => Ec.fieldInvLowLoop k lowBits (loIterBody lowBits k t aName) aName) := by
      funext t; exact fieldInvLowLoop_succ k lowBits t aName
    rw [h]
    have hbody : Rebasable (fun t => loIterBody lowBits k t aName) := by
      by_cases hbit : ((lowBits / (2 ^ k)) % 2) = 1
      · refine rebasable_congr (g := fun t => hiIterBody t aName)
          (fun t => by unfold loIterBody hiIterBody; simp only [hbit, decide_true, if_true]) ?_
        exact rebasable_hiIterBody aName
      · refine rebasable_congr (g := fun t => Ec.Tracker.rename (Ec.fieldSqr t "_inv_r" "_inv_r2") "_inv_r")
          (fun t => by unfold loIterBody; simp only [hbit, decide_false, Bool.false_eq_true, if_false]) ?_
        exact rebasable_comp (rebasable_fieldSqr "_inv_r" "_inv_r2") (rebasable_rename "_inv_r")
    exact rebasable_comp hbody ih

/-- SMOKE (the ops-rebasing substrate FIRES, anti-vacuity).  `fieldSub` is Rebasable: on a
concrete entry with extra entry-ops, the nm output is entry-ops-independent and the ops output is
the entry ops with the determined `fieldSub` increment appended.  Probes a tracker carrying a
non-empty entry-ops list, so the `++ entry.ops` factorization is genuinely exercised. -/
theorem smoke_rebasable_fieldSub :
    let t : Ec.Tracker := ⟨#[some "x", some "y"], #[StackOp.opcode "OP_NOP"]⟩
    (Ec.fieldSub t "x" "y" "z").nm = (Ec.fieldSub (clearOps t) "x" "y" "z").nm
      ∧ (Ec.fieldSub t "x" "y" "z").ops.toList
          = t.ops.toList ++ (Ec.fieldSub (clearOps t) "x" "y" "z").ops.toList :=
  rebasable_fieldSub "x" "y" "z" ⟨#[some "x", some "y"], #[StackOp.opcode "OP_NOP"]⟩

/-! ### WALL CLEARED — general-entry affineAdd transport + `emitEcAdd` op-list now LANDED.

The wave-88 elaboration wall (the `whnf`/`@[inline]` blowup folding the 222/32 `fieldInv` loops
during the `rebasable_fieldInv` congr unfold) is CLEARED via FIX ROUTE 1: `attribute [local
irreducible] Ec.fieldInvHighLoop Ec.fieldInvLowLoop` inside the proof section keeps the loops opaque
to the unifier (their `Rebasable`-ness was already proven by induction via the `*_succ` unfolders
that fired BEFORE the section).  A second wrinkle — the 24-deep `rebasable_comp` chain for
`rebasable_affineAdd` whnf-blew-up on the inlined field-ops even with loops opaque — is dodged by
CHUNKING the composition (`aaChunk1..4`, the 24 steps split 1..6 / 7..8 / 9..20 / 21..24), keeping
each `rebasable_comp` unification small.

LANDED below (all `propext`/`Quot.sound`(/`Classical.choice`)-clean, NO `sorryAx`, NO new axiom, NO
`native_decide`/`ofReduceBool`; each with an anti-vacuity smoke):
* `rebasable_fieldInv` — the final loop-composition (route 1).
* `rebasable_affineAdd` + `affineAdd_nm_ops` — the general-entry transport: `(Ec.affineAdd t).ops =
  t.ops ++ affineAddInc` and `nm = [rx,ry]` for the post-decompose entry (nm = [px,py,qx,qy]).
* `rebasable_decomposePoint` / `rebasable_composePoint` — the point (de)compose stages as Rebasable.
* `emitEcAdd_ops` — `Ec.emitEcAdd = expectedEcAdd` (= `ecaDp2.ops ++ affineAddInc ++ composeRxRyInc`,
  the determined decompose×2 → affineAdd → compose concat), with the two-decompose nm chain
  (`daT1..daT6` / `dbT1..dbT6`, the proven `dpT*` pattern) folding `ecaDp2.nm = [px,py,qx,qy]`.

REMAINING for the full `emitEcAdd_runOps_eq` discharge (the hand-off's sub-goal 4 — RUNTIME
threading, NOT cleared this wave): off the entry runtime stack `[qy,qx,py,px] ++ rest`, thread each
of the 24 determined affineAdd-step increments via the Part-16 depth-general sims
(`fieldBinop_runOps_simT` / `fieldSqr_runOps_simT`, with the per-step concrete `applyRoll` depths
computed from each step's nm) + the proven `fieldInv_runOps_sim` at the `_s_den` site, plus the two
`decomposePoint_runOps` bases and the `composePoint_runOps_sim` build-back, reduced to the
non-degenerate (`pxm ≠ qxm`) branch of `Crypto.Secp256k1.affineAdd` → `Crypto.Secp256k1.ecAdd`.  The
OP-LIST half (`emitEcAdd_ops`) and the affineAdd transport are now WIRED; the runtime per-step
threading (24 sequential `runOps` reductions at probed depths) is LANDED in Part 18-19
(`affineAddInc_runOps` / `ecaDp2_runOps` / `emitEcAdd_runOps_eq`).  The
`Crypto.Spec.emitEcAdd_runOps_eq` axiom is therefore DISCHARGED (drift 74 → 73). -/


/-! ## Part 15 (cont.) — `fieldInv` op-list bridge + affineAdd + `emitEcAdd` discharge: HONEST BLOCK

The spec-level square-and-multiply crux (`FieldInvSpec.fieldInvAccum_eq`) is PROVEN, AND
the RUNTIME loop inductions (`highLoopInc_runOps_sim` / `lowLoopInc_runOps_sim`, the 254-iter
crux the hand-off flagged) are now LANDED above — landing `samHigh`/`samLow` on the
Script-VM stack by genuine structural induction on the loop count.  What REMAINS for the
`emitEcAdd_runOps_eq` discharge:

1. **`fieldInv` op-list bridge — FULLY LANDED (this wave), axiom-clean.**  The runtime loop
   INDUCTIONS were proven (`highLoopInc_runOps_sim` / `lowLoopInc_runOps_sim`); what they
   consume is the determined op-lists `highLoopInc 222` / `lowLoopInc 32 0xFFFFFC2D`.  This
   wave closes the codegen-op-list ↔ inductions gap COMPLETELY:
   * `InvLoopShape` + the `toList`-level nm transforms (`toTop_top_nm`/`toTop_second_nm`/
     `rename_invr_nm`/`rawBlock2_nm_toList`/`copyToTop_nm_toList` + depth folds
     `findDepth_top0`/`findDepth_second1`).
   * `invFieldSqr_nm`/`_ops`, `invFieldMul_nm`/`_ops` — the loop-body field helpers.
   * `hiIterBody_nm`/`_ops` — one high iteration is an `nm` FIXED POINT + appends
     `oneHighIterInc`; `loIterBody_nm_ops` — one low iteration (`by_cases` on the bit)
     appends `oneLowIterInc bit`, nm fixed.
   * `fieldInvHighLoop_ops` / `fieldInvLowLoop_ops` — structural inductions:
     `(fieldInvHighLoop n …).ops = …  ++ highLoopInc n` (resp. low), nm preserved.
   * **`fieldInv_ops_depth0`** — THE FULL BRIDGE: for a DEPTH-0 entry (`aName` on TOS, the
     affineAdd `fieldInv "_s_den" …` site) `(Stack.Ec.fieldInv t aName r).ops.toList
       = t.ops.toList ++ fieldInvCoreInc`, EXACTLY the op-list `fieldInv_runOps_sim` consumes.
     Chains prelude `dup` → high loop → bit-32 `fieldSqr` → `rename` → low loop → cleanup
     `[.swap, .drop]`.  (Uses `show … = <explicit composed form> from rfl` instead of
     `unfold Ec.fieldInv` — the latter triggers KERNEL deep-recursion by forcing the 222/32
     recursive loops to WHNF; the `show` keeps the loop applications opaque on both sides.)
   Smokes: `smoke_hiIterBody_nm`/`_ops`, `smoke_fieldInvHighLoop_ops`,
   `smoke_fieldInvLowLoop_ops`, `smoke_fieldInv_ops_depth0` — all `propext`/`Classical.choice`/
   `Quot.sound`-clean (NO `sorryAx`, NO new axiom, NO `native_decide`).

2. **Depth-general field sims — LANDED (this wave, Part 16, axiom-clean).**  The shallow
   Part-12 sims (`fieldSub_runOps_sim` etc.) assume operands at fixed depth 0/1; affineAdd
   keeps `px/py/qx/qy` at deep VARYING depths.  Part 16 adds the DEPTH-GENERAL form:
   * `fieldBinop_runOps_simT binop f s av bv da db mid out …` — runs the determined
     `fieldBinopGenInc da db binop` (`rollExtraOps da ++ rollExtraOps db ++ [binop, push fieldP]
     ++ fieldModOps`) at ARBITRARY roll depths via the GENERAL `runOps_rollExtraOps` (NOT the
     depth-0/1 special cases), landing `Secp256k1.fieldMod (f av bv)`.  The runtime model is
     given directly as `applyRoll` hypotheses (`hRoll1`/`hRoll2`) so the codegen nm bookkeeping
     supplies the concrete depths per affineAdd step.  Smoke `smoke_fieldBinop_runOps_simT`.
   * `fieldSqr_runOps_simT s av dp dm1 dm2 mid out …` — copy-then-multiply at general depths
     (`fieldSqrGenInc dp dm1 dm2`), landing `Secp256k1.fieldMul av av`.  Smoke
     `smoke_fieldSqr_runOps_simT`.
   Both `propext`/`Quot.sound` + inherited-backend clean, `native_decide`-free (`decide`/`rfl`
   smokes).

3. **affineAdd op-list bridge — STARTED (this wave, Part 17): entry → fieldInv splice LANDED.**
   The entry scaffolding + first SEVEN steps of the ~18-step `affineAdd_ops` determined-concat
   are LANDED and verified, INCLUDING the `fieldInv` splice:
   * `aaT0`…`aaT6` (entry `nm = [px,py,qx,qy]` → `copyToTop qy`/`py` → `fieldSub → _s_num` →
     `copyToTop qx`/`px` → `fieldSub → _s_den`), each with its `_nm`/`_nm_arr` + ops-increment
     theorem (`aaT{1,2,4,5}_ops` = `pickExtraOps {0,3,2,5}`; `aaT{3,6}_ops` =
     `…ops ++ fieldBinopGenInc 1 1 "OP_SUB"`).  `aaT6` lands `_s_den` at depth 0 = TOS (proven).
   * `aaT7_ops` — THE `fieldInv` SPLICE: `(Ec.fieldInv aaT6 "_s_den" "_s_den_inv").ops.toList
     = aaT6.ops.toList ++ fieldInvCoreInc`, via the proven depth-0 bridge `fieldInv_ops_depth0`.
     This JOINS the affineAdd assembly to the END-TO-END-verified `fieldInv` (op-list ⟷ runtime
     ⟷ spec) — the architecturally hardest junction of the whole discharge.
   * `fieldSub_ops_concrete` — the missing peer of `fieldMul_ops_concrete`/`fieldAdd_ops_concrete`
     at `OP_SUB`/`_fsub_diff`, reused by every affineAdd fieldSub step.
   THE PRECISE REMAINING SUB-GOAL (steps 8-20, STRAIGHT-LINE continuation of the aaT6 pattern):
   `fieldMul _s_num _s_den_inv _s` → `copyToTop _s _s_keep` → `fieldSqr _s _s2` →
   `copyToTop px` → `fieldSub _s2 _px2 _rx1` → `copyToTop qx` → `fieldSub _rx1 _qx2 rx` →
   `copyToTop px`/`copyToTop rx` → `fieldSub _px3 _rx2 _px_rx` → `fieldMul _s_keep _px_rx
   _s_px_rx` → `copyToTop py` → `fieldSub _s_px_rx _py2 ry` → 4× cleanup `toTop`/`.drop`.  Each
   step's depths are CONCRETE (every nm begins `[px,py,qx,qy,…]`, base persists at bottom —
   probed), so each is one `fieldSub_ops_concrete`/`fieldMul_ops_concrete`/`fieldSqr` +
   `copyToTop_ops_concrete` application with its inline `nm`-shape lemma (the aaT6 pattern).
   Then `affineAdd_ops` = the determined concat (the ~18 increments + `fieldInvCoreInc` spliced
   at step 7).

4. **affineAdd runtime threading + `emitEcAdd_runOps_eq` discharge (REMAINS).**  Off the entry
   runtime stack `[qy, qx, py, px] ++ rest` (nm bottom→top `px,py,qx,qy`), thread each step's
   determined increment via the Part-16 depth-general sims (the `applyRoll` hypotheses computed
   from the concrete per-step nm) + the proven `fieldInv_runOps_sim` at the `_s_den` site, then
   `composePoint_runOps_sim` (Part 14) to build the result point, reduced to the non-degenerate
   branch of `Crypto.Secp256k1.affineAdd`.  `emitEcAdd_ops` (determined concat:
   `decomposePoint` ×2 → `affineAdd_ops` → `composePoint`, via the intermediate-nm chain) +
   that threading → `Crypto.Secp256k1.ecAdd`.  Honest INPUT-side wf hyps: both points 64-byte
   + on-curve + `FIELD_P ≠ 0`, PLUS the non-degenerate case split `pointX p ≢ pointX q (mod p)`
   (the affine formula's `pxm ≠ qxm` branch — the `P = ±Q` / doubling cases route through
   `affineDouble`, a SEPARATE codegen path NOT exercised by `emitEcAdd`'s straight-line
   affine-add, so excluded by hypothesis).

The `Crypto.Spec.emitEcAdd_runOps_eq` axiom is now DISCHARGED (drift 74 → 73): Part 18 lands the
full 24-step affineAdd runtime threading (`affineAddInc_runOps`) via the Part-16 depth-general
sims + the proven `fieldInv_runOps_sim`, and Part 19 lands the two-decompose runtime
(`ecaDp2_runOps`) + the `composePoint_runOps_sim` build-back, composed into
`emitEcAdd_runOps_eq` and reduced to `Crypto.Secp256k1.ecAdd`'s non-degenerate branch via
`aaRx_aaRy_eq_affineAdd`.  The `fieldInv` END-TO-END verification (op-list ⟷ runtime ⟷ spec) from
the prior wave is WIRED into the affineAdd chain at the `_s_den` modular-inverse step. -/

/-! ### General-entry affineAdd transport — `rebasable_fieldInv` (route 1: local-irreducible loops).

The wave-88 wall: the unifier inside `rebasable_comp` tried to fold the 222/32 `fieldInv` loops to
WHNF during the congr unfold, timing out.  FIX (route 1): mark `Ec.fieldInvHighLoop`/`fieldInvLowLoop`
`@[local irreducible]` inside this section so the unifier keeps them OPAQUE.  Their `Rebasable`-ness is
ALREADY proven (`rebasable_fieldInvHighLoop` / `rebasable_fieldInvLowLoop`, by induction via the
`*_succ` unfolders that fired BEFORE this section).  So composing them is pure plumbing, no folding. -/

section RebasableFieldInv
attribute [local irreducible] Ec.fieldInvHighLoop Ec.fieldInvLowLoop

/-- `Ec.fieldInv` as the explicit diagrammatic composition of its 9 Rebasable steps, with the two
loops kept opaque (`local irreducible`).  Proven by `unfold Ec.fieldInv; rfl` — the loops never WHNF. -/
private theorem fieldInv_eq_comp (aName resultName : String) (t : Ec.Tracker) :
    Ec.fieldInv t aName resultName
      = (fun t =>
          Ec.Tracker.rename
            (Ec.Tracker.toTop
              (Ec.Tracker.drop
                (Ec.Tracker.toTop
                  (Ec.fieldInvLowLoop 32 0xFFFFFC2D
                    (Ec.Tracker.rename
                      (Ec.fieldSqr
                        (Ec.fieldInvHighLoop 222 (Ec.Tracker.copyToTop t aName "_inv_r") aName)
                        "_inv_r" "_inv_r2")
                      "_inv_r")
                    aName)
                  aName)) "_inv_r") resultName) t := by
  unfold Ec.fieldInv
  rfl

/-- **`Ec.fieldInv · aName resultName` is Rebasable.**  Composes the nine already-Rebasable steps
(copyToTop → highLoop 222 → fieldSqr → rename → lowLoop 32 → toTop → drop → toTop → rename) via
`rebasable_comp`, transported onto `Ec.fieldInv` by `rebasable_congr` + `fieldInv_eq_comp`.  The two
loops stay opaque, so no WHNF blowup. -/
theorem rebasable_fieldInv (aName resultName : String) :
    Rebasable (fun t => Ec.fieldInv t aName resultName) := by
  refine rebasable_congr (g := fun t =>
      Ec.Tracker.rename
        (Ec.Tracker.toTop
          (Ec.Tracker.drop
            (Ec.Tracker.toTop
              (Ec.fieldInvLowLoop 32 0xFFFFFC2D
                (Ec.Tracker.rename
                  (Ec.fieldSqr
                    (Ec.fieldInvHighLoop 222 (Ec.Tracker.copyToTop t aName "_inv_r") aName)
                    "_inv_r" "_inv_r2")
                  "_inv_r")
                aName)
              aName)) "_inv_r") resultName)
    (fun t => fieldInv_eq_comp aName resultName t) ?_
  exact
    rebasable_comp
      (rebasable_comp
        (rebasable_comp
          (rebasable_comp
            (rebasable_comp
              (rebasable_comp
                (rebasable_comp
                  (rebasable_comp
                    (rebasable_copyToTop aName "_inv_r")
                    (rebasable_fieldInvHighLoop 222 aName))
                  (rebasable_fieldSqr "_inv_r" "_inv_r2"))
                (rebasable_rename "_inv_r"))
              (rebasable_fieldInvLowLoop 32 0xFFFFFC2D aName))
            (rebasable_toTop aName))
          rebasable_drop)
        (rebasable_toTop "_inv_r"))
      (rebasable_rename resultName)

/-- SMOKE (`rebasable_fieldInv` FIRES, anti-vacuity).  `fieldInv · "_s_den" "_s_den_inv"` satisfies
the `Rebasable` predicate — the meta-substrate genuinely produces the entry-ops-independence +
append-only-ops witness for the 222/32-loop transform.  Stated against the OPAQUE `Rebasable`
predicate (not the unfolded `Ec.fieldInv <conc>` body) so the kernel never folds the loops, while
still DEPENDING on `rebasable_fieldInv`.  Anti-vacuity: `Rebasable` is the real conjunction
(`∀ t, (f t).nm = (f (clearOps t)).nm ∧ (f t).ops = t.ops ++ (f (clearOps t)).ops`), no `True`. -/
theorem smoke_rebasable_fieldInv : Rebasable (fun t => Ec.fieldInv t "_s_den" "_s_den_inv") :=
  rebasable_fieldInv "_s_den" "_s_den_inv"

/-! ### General-entry affineAdd transport — `rebasable_affineAdd` + `affineAdd_nm_ops`.

`Ec.affineAdd` is the 24-step composition (steps 1..6 fieldSub scaffolding, step 7 `fieldInv`, steps
8..20 the slope/rx/ry chain, steps 21..24 the four cleanup `drop ∘ toTop`).  Each step is Rebasable
(`rebasable_copyToTop`/`fieldSub`/`fieldInv`/`fieldMul`/`fieldSqr`/`toTop`/`drop`), so the whole is
Rebasable by chained `rebasable_comp` transported via `rebasable_congr`.  Loops stay opaque (the
`fieldInv` step uses the section-local irreducible). -/

/-- Chunk 1 (steps 1..6): the two fieldSub scaffolds producing `_s_num` and `_s_den`. -/
private def aaChunk1 (t : Ec.Tracker) : Ec.Tracker :=
  Ec.fieldSub
    (Ec.Tracker.copyToTop
      (Ec.Tracker.copyToTop
        (Ec.fieldSub
          (Ec.Tracker.copyToTop
            (Ec.Tracker.copyToTop t "qy" "_qy1")
            "py" "_py1")
          "_qy1" "_py1" "_s_num")
        "qx" "_qx1")
      "px" "_px1")
    "_qx1" "_px1" "_s_den"

/-- Chunk 2 (steps 7..8): `fieldInv` of `_s_den`, then `fieldMul` to the slope `_s`. -/
private def aaChunk2 (t : Ec.Tracker) : Ec.Tracker :=
  Ec.fieldMul (Ec.fieldInv t "_s_den" "_s_den_inv") "_s_num" "_s_den_inv" "_s"

/-- Chunk 3 (steps 9..20): the rx then ry slope chain. -/
private def aaChunk3 (t : Ec.Tracker) : Ec.Tracker :=
  Ec.fieldSub
    (Ec.Tracker.copyToTop
      (Ec.fieldMul
        (Ec.fieldSub
          (Ec.Tracker.copyToTop
            (Ec.Tracker.copyToTop
              (Ec.fieldSub
                (Ec.Tracker.copyToTop
                  (Ec.fieldSub
                    (Ec.Tracker.copyToTop
                      (Ec.fieldSqr
                        (Ec.Tracker.copyToTop t "_s" "_s_keep")
                        "_s" "_s2")
                      "px" "_px2")
                    "_s2" "_px2" "_rx1")
                  "qx" "_qx2")
                "_rx1" "_qx2" "rx")
              "px" "_px3")
            "rx" "_rx2")
          "_px3" "_rx2" "_px_rx")
        "_s_keep" "_px_rx" "_s_px_rx")
      "py" "_py2")
    "_s_px_rx" "_py2" "ry"

/-- Chunk 4 (steps 21..24): the four cleanup `drop ∘ toTop`. -/
private def aaChunk4 (t : Ec.Tracker) : Ec.Tracker :=
  Ec.Tracker.drop (Ec.Tracker.toTop
    (Ec.Tracker.drop (Ec.Tracker.toTop
      (Ec.Tracker.drop (Ec.Tracker.toTop
        (Ec.Tracker.drop (Ec.Tracker.toTop t "px")) "py")) "qx")) "qy")

/-- `Ec.affineAdd` factors as `aaChunk4 ∘ aaChunk3 ∘ aaChunk2 ∘ aaChunk1` (loops kept opaque). -/
private theorem affineAdd_eq_comp (t : Ec.Tracker) :
    Ec.affineAdd t = aaChunk4 (aaChunk3 (aaChunk2 (aaChunk1 t))) := by
  unfold Ec.affineAdd aaChunk1 aaChunk2 aaChunk3 aaChunk4
  rfl

private theorem rebasable_aaChunk1 : Rebasable aaChunk1 := by
  refine rebasable_congr (g := fun t =>
      Ec.fieldSub (Ec.Tracker.copyToTop (Ec.Tracker.copyToTop
        (Ec.fieldSub (Ec.Tracker.copyToTop (Ec.Tracker.copyToTop t "qy" "_qy1") "py" "_py1")
          "_qy1" "_py1" "_s_num") "qx" "_qx1") "px" "_px1") "_qx1" "_px1" "_s_den")
    (fun t => by unfold aaChunk1; rfl) ?_
  exact rebasable_comp (rebasable_comp (rebasable_comp (rebasable_comp (rebasable_comp
    (rebasable_copyToTop "qy" "_qy1") (rebasable_copyToTop "py" "_py1"))
    (rebasable_fieldSub "_qy1" "_py1" "_s_num")) (rebasable_copyToTop "qx" "_qx1"))
    (rebasable_copyToTop "px" "_px1")) (rebasable_fieldSub "_qx1" "_px1" "_s_den")

private theorem rebasable_aaChunk2 : Rebasable aaChunk2 := by
  refine rebasable_congr (g := fun t =>
      Ec.fieldMul (Ec.fieldInv t "_s_den" "_s_den_inv") "_s_num" "_s_den_inv" "_s")
    (fun t => by unfold aaChunk2; rfl) ?_
  exact rebasable_comp (rebasable_fieldInv "_s_den" "_s_den_inv")
    (rebasable_fieldMul "_s_num" "_s_den_inv" "_s")

private theorem rebasable_aaChunk3 : Rebasable aaChunk3 := by
  refine rebasable_congr (g := fun t =>
      Ec.fieldSub (Ec.Tracker.copyToTop (Ec.fieldMul (Ec.fieldSub
        (Ec.Tracker.copyToTop (Ec.Tracker.copyToTop (Ec.fieldSub (Ec.Tracker.copyToTop
          (Ec.fieldSub (Ec.Tracker.copyToTop (Ec.fieldSqr (Ec.Tracker.copyToTop t "_s" "_s_keep")
            "_s" "_s2") "px" "_px2") "_s2" "_px2" "_rx1") "qx" "_qx2") "_rx1" "_qx2" "rx")
          "px" "_px3") "rx" "_rx2") "_px3" "_rx2" "_px_rx") "_s_keep" "_px_rx" "_s_px_rx")
        "py" "_py2") "_s_px_rx" "_py2" "ry")
    (fun t => by unfold aaChunk3; rfl) ?_
  exact rebasable_comp (rebasable_comp (rebasable_comp (rebasable_comp (rebasable_comp
    (rebasable_comp (rebasable_comp (rebasable_comp (rebasable_comp (rebasable_comp
    (rebasable_comp
      (rebasable_copyToTop "_s" "_s_keep")
      (rebasable_fieldSqr "_s" "_s2"))
      (rebasable_copyToTop "px" "_px2"))
      (rebasable_fieldSub "_s2" "_px2" "_rx1"))
      (rebasable_copyToTop "qx" "_qx2"))
      (rebasable_fieldSub "_rx1" "_qx2" "rx"))
      (rebasable_copyToTop "px" "_px3"))
      (rebasable_copyToTop "rx" "_rx2"))
      (rebasable_fieldSub "_px3" "_rx2" "_px_rx"))
      (rebasable_fieldMul "_s_keep" "_px_rx" "_s_px_rx"))
      (rebasable_copyToTop "py" "_py2"))
      (rebasable_fieldSub "_s_px_rx" "_py2" "ry")

/-- One cleanup step `drop ∘ toTop name` is Rebasable. -/
private theorem rebasable_dropToTop (name : String) :
    Rebasable (fun t => Ec.Tracker.drop (Ec.Tracker.toTop t name)) :=
  rebasable_comp (rebasable_toTop name) rebasable_drop

private theorem rebasable_aaChunk4 : Rebasable aaChunk4 := by
  have h1 := rebasable_dropToTop "px"
  have h2 := rebasable_comp h1 (rebasable_dropToTop "py")
  have h3 := rebasable_comp h2 (rebasable_dropToTop "qx")
  have h4 := rebasable_comp h3 (rebasable_dropToTop "qy")
  exact rebasable_congr (g := fun t => Ec.Tracker.drop (Ec.Tracker.toTop
      (Ec.Tracker.drop (Ec.Tracker.toTop
        (Ec.Tracker.drop (Ec.Tracker.toTop
          (Ec.Tracker.drop (Ec.Tracker.toTop t "px")) "py")) "qx")) "qy"))
    (fun t => by unfold aaChunk4; rfl) h4

/-- **`Ec.affineAdd` is Rebasable.**  Composes the four already-Rebasable chunks (the 24 steps split
1..6 / 7..8 / 9..20 / 21..24), transported onto `Ec.affineAdd` by `rebasable_congr` +
`affineAdd_eq_comp`.  Chunking keeps each `rebasable_comp` unification small (the wave-88 wall was a
single 24-deep `rebasable_comp` whose unifier whnf-blew-up on the inlined field-ops).  Loops opaque. -/
theorem rebasable_affineAdd : Rebasable Ec.affineAdd :=
  rebasable_congr (g := fun t => aaChunk4 (aaChunk3 (aaChunk2 (aaChunk1 t))))
    affineAdd_eq_comp
    (rebasable_comp (rebasable_comp (rebasable_comp rebasable_aaChunk1 rebasable_aaChunk2)
      rebasable_aaChunk3) rebasable_aaChunk4)

end RebasableFieldInv

/-- SMOKE (`rebasable_affineAdd` FIRES, anti-vacuity).  `Ec.affineAdd` satisfies the `Rebasable`
predicate (entry-ops-independence + append-only-ops across the full 24-step chain, including the
embedded 222/32-iteration `fieldInv`).  Stated against the opaque `Rebasable` predicate. -/
theorem smoke_rebasable_affineAdd : Rebasable Ec.affineAdd := rebasable_affineAdd

/-- **General-entry `affineAdd` transport.**  For ANY entry tracker `t` whose `nm` is the
post-decompose `[px,py,qx,qy]` (with arbitrary, non-empty entry-ops), the codegen `affineAdd`
appends EXACTLY the determined `affineAddInc` and lands `nm = [rx, ry]`.  Proven by
`rebasable_affineAdd` (transport the empty-ops anchor `aaT0`'s result `aaT24`).  `clearOps t = aaT0`
because `clearOps` zeroes ops and `t.nm` is fixed to the `aaT0` shape. -/
theorem affineAdd_nm_ops (t : Ec.Tracker)
    (hnm : t.nm = #[some "px", some "py", some "qx", some "qy"]) :
    (Ec.affineAdd t).ops.toList = t.ops.toList ++ affineAddInc
      ∧ (Ec.affineAdd t).nm.toList = [some "rx", some "ry"] := by
  have hcl : clearOps t = aaT0 := by
    unfold clearOps aaT0; rw [hnm]
  obtain ⟨hnm', hops'⟩ := rebasable_affineAdd t
  refine ⟨?_, ?_⟩
  · rw [hops', hcl, affineAdd_eq_aaT24, aaT24_ops_full]
  · rw [hnm', hcl, affineAdd_eq_aaT24, aaT24_nm]

/-- SMOKE (`affineAdd_nm_ops` FIRES, anti-vacuity).  On a concrete post-decompose entry carrying a
non-empty entry-ops list (`[OP_NOP]`), the general-entry transport lands the determined op-list
(entry ops ++ `affineAddInc`) and `nm = [rx, ry]` — exercising the `++ t.ops` factorization across
the full 24-step chain (including the 222/32-iteration `fieldInv`). -/
theorem smoke_affineAdd_nm_ops :
    (Ec.affineAdd ⟨#[some "px", some "py", some "qx", some "qy"], #[StackOp.opcode "OP_NOP"]⟩).ops.toList
        = [StackOp.opcode "OP_NOP"] ++ affineAddInc
      ∧ (Ec.affineAdd ⟨#[some "px", some "py", some "qx", some "qy"], #[StackOp.opcode "OP_NOP"]⟩).nm.toList
        = [some "rx", some "ry"] :=
  affineAdd_nm_ops ⟨#[some "px", some "py", some "qx", some "qy"], #[StackOp.opcode "OP_NOP"]⟩ rfl

/-! ### `emitEcAdd` op-list — `rebasable_decomposePoint` / `rebasable_composePoint` + `emitEcAdd_ops`.

`emitEcAdd` = `init [_pa,_pb]` → `decomposePoint _pa` → `decomposePoint _pb` → `affineAdd` →
`composePoint rx ry _result`.  Each stage is a `Tracker → Tracker` built from Rebasable primitives;
proving each Rebasable and composing them gives `emitEcAdd`'s op-list as a single determined concat
off the empty-ops `init` anchor. -/

/-- `swap` reads only `nm` (ops appended); its nm output is entry-ops-independent. -/
private theorem op_nm_clearOps_swap (t : Ec.Tracker) :
    (Ec.Tracker.swap t).nm = (Ec.Tracker.swap (clearOps t)).nm := by
  obtain ⟨nm, ops⟩ := t
  unfold Ec.Tracker.swap Ec.Tracker.emit clearOps
  dsimp only
  split <;> rfl

/-- `swap` ops-append. -/
private theorem swap_ops_append_loc (t : Ec.Tracker) :
    (Ec.Tracker.swap t).ops.toList = t.ops.toList ++ [StackOp.swap] := by
  obtain ⟨nm, ops⟩ := t
  unfold Ec.Tracker.swap Ec.Tracker.emit
  dsimp only
  split <;> simp

theorem rebasable_swap : Rebasable (fun t => Ec.Tracker.swap t) := by
  intro t
  refine ⟨op_nm_clearOps_swap t, ?_⟩
  rw [swap_ops_append_loc t, swap_ops_append_loc (clearOps t), clearOps_ops]; simp

/-- The raw two-element nm-push used inside `decomposePoint` (`{ t with nm := (nm.push a).push b }`)
is Rebasable: nm reads only `t.nm`, ops untouched. -/
theorem rebasable_nmPush2 (a b : Option String) :
    Rebasable (fun t => ({ t with nm := (t.nm.push a).push b } : Ec.Tracker)) := by
  intro t
  obtain ⟨nm, ops⟩ := t
  refine ⟨rfl, ?_⟩
  simp [clearOps]

/-- **`decomposePoint · pointName xName yName` is Rebasable.**  Composes toTop → rawBlock → the raw
2-element nm-push → rawBlock → toTop → rawBlock → swap (all Rebasable).  Built bottom-up. -/
theorem rebasable_decomposePoint (pointName xName yName : String) :
    Rebasable (fun t => Ec.decomposePoint t pointName xName yName) := by
  have hbase := rebasable_comp (rebasable_toTop pointName)
      (rebasable_rawBlock 1 none [.push (.bigint 32), .opcode "OP_SPLIT"])
  have hpush := rebasable_comp hbase (rebasable_nmPush2 (some "_dp_xb") (some "_dp_yb"))
  have hy := rebasable_comp hpush (rebasable_rawBlock 1 (some yName)
      (Ec.emitReverse32Ops ++ [.push (.bytes (ByteArray.mk #[0x00])), .opcode "OP_CAT", .opcode "OP_BIN2NUM"]))
  have htx := rebasable_comp hy (rebasable_toTop "_dp_xb")
  have hx := rebasable_comp htx (rebasable_rawBlock 1 (some xName)
      (Ec.emitReverse32Ops ++ [.push (.bytes (ByteArray.mk #[0x00])), .opcode "OP_CAT", .opcode "OP_BIN2NUM"]))
  have hfull := rebasable_comp hx rebasable_swap
  exact rebasable_congr (fun t => by unfold Ec.decomposePoint; rfl) hfull

/-- **`composePoint · xName yName resultName` is Rebasable.**  toTop → rawBlock → toTop → rawBlock →
toTop → toTop → rawBlock (all Rebasable).  Built bottom-up so each `rebasable_comp` infers its `f`
from the prior `have` (no explicit `g`, dodging the rawBlock-unfold mismatch). -/
theorem rebasable_composePoint (xName yName resultName : String) :
    Rebasable (fun t => Ec.composePoint t xName yName resultName) := by
  have hx := rebasable_comp (rebasable_toTop xName)
      (rebasable_rawBlock 1 (some "_cp_xb")
        ([.push (.bigint 33), .opcode "OP_NUM2BIN", .push (.bigint 32), .opcode "OP_SPLIT", .drop]
          ++ Ec.emitReverse32Ops))
  have hty := rebasable_comp hx (rebasable_toTop yName)
  have hy := rebasable_comp hty (rebasable_rawBlock 1 (some "_cp_yb")
        ([.push (.bigint 33), .opcode "OP_NUM2BIN", .push (.bigint 32), .opcode "OP_SPLIT", .drop]
          ++ Ec.emitReverse32Ops))
  have hcx := rebasable_comp hy (rebasable_toTop "_cp_xb")
  have hcy := rebasable_comp hcx (rebasable_toTop "_cp_yb")
  have hfull := rebasable_comp hcy (rebasable_rawBlock 2 (some resultName) [.opcode "OP_CAT"])
  exact rebasable_congr (fun t => by unfold Ec.composePoint; rfl) hfull

/-- SMOKE (`rebasable_decomposePoint` / `rebasable_composePoint` FIRE). -/
theorem smoke_rebasable_decomposePoint :
    Rebasable (fun t => Ec.decomposePoint t "_pa" "px" "py") :=
  rebasable_decomposePoint "_pa" "px" "py"

theorem smoke_rebasable_composePoint :
    Rebasable (fun t => Ec.composePoint t "rx" "ry" "_result") :=
  rebasable_composePoint "rx" "ry" "_result"

/-! ### `emitEcAdd_ops` — the determined op-list = decompose ++ decompose ++ affineAdd ++ compose. -/

/-- The `emitEcAdd` entry after `init` then `decompose _pa`. -/
private def ecaDp1 : Ec.Tracker :=
  Ec.decomposePoint (Ec.Tracker.init [some "_pa", some "_pb"]) "_pa" "px" "py"

/-- The `emitEcAdd` entry after both decomposes (`nm = [px,py,qx,qy]`). -/
private def ecaDp2 : Ec.Tracker := Ec.decomposePoint ecaDp1 "_pb" "qx" "qy"

/-! Step trackers for the FIRST `emitEcAdd` decompose (`init [_pa,_pb]` → decompose `_pa`), mirroring
the proven `dpT1..dpT6` chain. -/
private def daT1 : Ec.Tracker := (Ec.Tracker.init [some "_pa", some "_pb"]).toTop "_pa"
private def daT2 : Ec.Tracker := daT1.rawBlock 1 none [.push (.bigint 32), .opcode "OP_SPLIT"]
private def daT3 : Ec.Tracker := { daT2 with nm := (daT2.nm.push (some "_dp_xb")).push (some "_dp_yb") }
private def daT4 : Ec.Tracker := daT3.rawBlock 1 (some "py")
  (Ec.emitReverse32Ops ++ [.push (.bytes (ByteArray.mk #[0x00])), .opcode "OP_CAT", .opcode "OP_BIN2NUM"])
private def daT5 : Ec.Tracker := daT4.toTop "_dp_xb"
private def daT6 : Ec.Tracker := daT5.rawBlock 1 (some "px")
  (Ec.emitReverse32Ops ++ [.push (.bytes (ByteArray.mk #[0x00])), .opcode "OP_CAT", .opcode "OP_BIN2NUM"])

private theorem daT1_nm : daT1.nm = #[some "_pb", some "_pa"] := by
  unfold daT1 Ec.Tracker.toTop
  rw [show (Ec.Tracker.init [some "_pa", some "_pb"]).findDepth "_pa" = 1 from by
    rw [findDepth_eq_findDepthList _ _ (by unfold Ec.Tracker.init; decide)]
    unfold Ec.Tracker.init; decide]
  rfl

private theorem daT2_nm : daT2.nm = #[some "_pb"] := by rw [daT2, rawBlock_nm_none1, daT1_nm]; rfl

private theorem daT4_nm : daT4.nm = #[some "_pb", some "_dp_xb", some "py"] := by
  rw [daT4, rawBlock_nm_some1]
  show (daT3.nm.pop.push (some "py")) = _
  rw [daT3]
  show ((((daT2.nm.push (some "_dp_xb")).push (some "_dp_yb")).pop).push (some "py")) = _
  rw [daT2_nm]; rfl

private theorem daT4_fd1 : daT4.findDepth "_dp_xb" = 1 := by
  rw [findDepth_eq_findDepthList _ _ (by rw [daT4_nm]; decide)]; rw [daT4_nm]; decide

private theorem daT6_nm : daT6.nm = #[some "_pb", some "py", some "px"] := by
  rw [daT6, rawBlock_nm_some1]
  show (daT5.nm.pop.push (some "px")) = _
  unfold daT5 Ec.Tracker.toTop
  rw [daT4_fd1]
  show ((daT4.swap).nm.pop.push (some "px")) = _
  rw [swap_nm_ge2 daT4 (by rw [daT4_nm]; decide), daT4_nm]; rfl

private theorem ecaDp1_nm : ecaDp1.nm = #[some "_pb", some "px", some "py"] := by
  show (daT6.swap).nm = _
  rw [swap_nm_ge2 daT6 (by rw [daT6_nm]; decide), daT6_nm]; rfl

/-! Step trackers for the SECOND `emitEcAdd` decompose (decompose `_pb` of `ecaDp1`). -/
private def dbT1 : Ec.Tracker := ecaDp1.toTop "_pb"
private def dbT2 : Ec.Tracker := dbT1.rawBlock 1 none [.push (.bigint 32), .opcode "OP_SPLIT"]
private def dbT3 : Ec.Tracker := { dbT2 with nm := (dbT2.nm.push (some "_dp_xb")).push (some "_dp_yb") }
private def dbT4 : Ec.Tracker := dbT3.rawBlock 1 (some "qy")
  (Ec.emitReverse32Ops ++ [.push (.bytes (ByteArray.mk #[0x00])), .opcode "OP_CAT", .opcode "OP_BIN2NUM"])
private def dbT5 : Ec.Tracker := dbT4.toTop "_dp_xb"
private def dbT6 : Ec.Tracker := dbT5.rawBlock 1 (some "qx")
  (Ec.emitReverse32Ops ++ [.push (.bytes (ByteArray.mk #[0x00])), .opcode "OP_CAT", .opcode "OP_BIN2NUM"])

private theorem dbT1_nm : dbT1.nm = #[some "px", some "py", some "_pb"] := by
  unfold dbT1 Ec.Tracker.toTop
  rw [show ecaDp1.findDepth "_pb" = 2 from by
    rw [findDepth_eq_findDepthList _ _ (by rw [ecaDp1_nm]; decide)]; rw [ecaDp1_nm]; decide]
  show (ecaDp1.roll 2).nm = _
  rw [roll_nm_canonical ecaDp1 2 (by rw [ecaDp1_nm]; decide), ecaDp1_nm]
  simp [Array.eraseIdxIfInBounds]

private theorem dbT2_nm : dbT2.nm = #[some "px", some "py"] := by rw [dbT2, rawBlock_nm_none1, dbT1_nm]; rfl

private theorem dbT4_nm : dbT4.nm = #[some "px", some "py", some "_dp_xb", some "qy"] := by
  rw [dbT4, rawBlock_nm_some1]
  show (dbT3.nm.pop.push (some "qy")) = _
  rw [dbT3]
  show ((((dbT2.nm.push (some "_dp_xb")).push (some "_dp_yb")).pop).push (some "qy")) = _
  rw [dbT2_nm]; rfl

private theorem dbT4_fd1 : dbT4.findDepth "_dp_xb" = 1 := by
  rw [findDepth_eq_findDepthList _ _ (by rw [dbT4_nm]; decide)]; rw [dbT4_nm]; decide

private theorem dbT6_nm : dbT6.nm = #[some "px", some "py", some "qy", some "qx"] := by
  rw [dbT6, rawBlock_nm_some1]
  show (dbT5.nm.pop.push (some "qx")) = _
  unfold dbT5 Ec.Tracker.toTop
  rw [dbT4_fd1]
  show ((dbT4.swap).nm.pop.push (some "qx")) = _
  rw [swap_nm_ge2 dbT4 (by rw [dbT4_nm]; decide), dbT4_nm]; rfl

private theorem ecaDp2_nm : ecaDp2.nm = #[some "px", some "py", some "qx", some "qy"] := by
  show (dbT6.swap).nm = _
  rw [swap_nm_ge2 dbT6 (by rw [dbT6_nm]; decide), dbT6_nm]; rfl

/-- The determined `composePoint "rx" "ry" "_result"` increment off a `[rx,ry]`-nm anchor. -/
def composeRxRyInc : List StackOp :=
  (Ec.composePoint ⟨#[some "rx", some "ry"], #[]⟩ "rx" "ry" "_result").ops.toList

/-- The determined `emitEcAdd` op-list: the two decompose increments, the affineAdd increment, and
the composePoint increment, concatenated.  `dp1Inc`/`dp2Inc` are the per-decompose increments off
their respective empty-ops anchors. -/
def expectedEcAdd : List StackOp :=
  ecaDp2.ops.toList ++ affineAddInc ++ composeRxRyInc

/-- **`emitEcAdd` op-list = `expectedEcAdd`.**  `composePoint` Rebasable splits the build-back off
`affineAdd`'s output (`clearOps` to the `[rx,ry]` anchor → `composeRxRyInc`); `affineAdd_nm_ops`
folds the affineAdd contribution to `affineAddInc` (entry nm = `[px,py,qx,qy]` via `ecaDp2_nm`). -/
theorem emitEcAdd_ops : Ec.emitEcAdd = expectedEcAdd := by
  show (Ec.composePoint (Ec.affineAdd ecaDp2) "rx" "ry" "_result").ops.toList = _
  obtain ⟨hcnm, hcops⟩ := rebasable_composePoint "rx" "ry" "_result" (Ec.affineAdd ecaDp2)
  obtain ⟨haops, hanm⟩ := affineAdd_nm_ops ecaDp2 ecaDp2_nm
  rw [hcops, haops]
  have hnmArr : (Ec.affineAdd ecaDp2).nm = #[some "rx", some "ry"] := by
    apply Array.ext'
    rw [hanm]
  have hcl : clearOps (Ec.affineAdd ecaDp2) = ⟨#[some "rx", some "ry"], #[]⟩ := by
    unfold clearOps; rw [hnmArr]
  rw [hcl]
  show ecaDp2.ops.toList ++ affineAddInc ++ composeRxRyInc = expectedEcAdd
  unfold expectedEcAdd composeRxRyInc
  simp only [List.append_assoc]

/-- SMOKE (`emitEcAdd_ops` FIRES, anti-vacuity — the op-list is non-empty and determined).  The
determined `emitEcAdd` op-list's head is the first `decomposePoint` op (`OP_SPLIT`-prep `push 32`). -/
theorem smoke_emitEcAdd_ops_head :
    Ec.emitEcAdd.head? = (expectedEcAdd).head? := by rw [emitEcAdd_ops]

/-! ## Part 19 — `emitEcAdd` two-decompose runtime + the `emitEcAdd_runOps_eq` discharge

The op-list is `expectedEcAdd = ecaDp2.ops.toList ++ affineAddInc ++ composeRxRyInc`.  This Part
threads the runtime: the two decomposes (off the entry `[pb, pa] ++ rest`) land
`[qy, qx, py, px] ++ rest` (= `[pointY pb, pointX pb, pointY pa, pointX pa] ++ rest`), the proven
`affineAddInc_runOps` (Part 18) lands `[ry, rx] ++ rest`, and `composePoint_runOps_sim` (Part 14)
builds back `[makePoint rx ry] ++ rest = [ecAdd pa pb] ++ rest`. -/

set_option maxRecDepth 8192 in
/-- **`ecaDp1` op-list** = the leading `toTop _pa` roll (`[.swap]`, depth 1) ++ the determined
single-decompose body `expectedDecomposePoint` (name-free).  Mirrors `decomposePoint_ops` with the
first `findDepth` folding to 1 (`_pa` at depth 1 in `[_pa, _pb]`). -/
theorem ecaDp1_ops : ecaDp1.ops.toList = rollExtraOps 1 ++ expectedDecomposePoint := by
  show (daT4.toTop "_dp_xb" |>.rawBlock 1 (some "px")
        (Ec.emitReverse32Ops ++ dpConvTail) |>.swap).ops.toList = _
  rw [swap_ops_append, rawBlock_ops_append, toTop_ops_append, daT4_fd1]
  show (daT4.ops.toList ++ rollExtraOps 1 ++ (Ec.emitReverse32Ops ++ dpConvTail)
        ++ [StackOp.swap]) = _
  rw [daT4, rawBlock_ops_append]
  show ((daT3.ops.toList ++ (Ec.emitReverse32Ops ++ dpConvTail)) ++ rollExtraOps 1
        ++ (Ec.emitReverse32Ops ++ dpConvTail) ++ [StackOp.swap]) = _
  rw [daT3]
  show ((daT2.ops.toList ++ (Ec.emitReverse32Ops ++ dpConvTail)) ++ rollExtraOps 1
        ++ (Ec.emitReverse32Ops ++ dpConvTail) ++ [StackOp.swap]) = _
  rw [daT2, rawBlock_ops_append, daT1, toTop_ops_append]
  rw [show (Ec.Tracker.init [some "_pa", some "_pb"]).findDepth "_pa" = 1 from by
    rw [findDepth_eq_findDepthList _ _ (by unfold Ec.Tracker.init; decide)]
    unfold Ec.Tracker.init; decide]
  simp only [rollExtraOps, Ec.Tracker.init, dpConvTail, expectedDecomposePoint]
  rfl

set_option maxRecDepth 8192 in
/-- **`ecaDp2` op-list** = `ecaDp1.ops ++ ([.rot] ++ expectedDecomposePoint)`.  The second
decompose's leading `toTop _pb` rolls from depth 2 (`rollExtraOps 2 = [.rot]`), then the same
determined body. -/
theorem ecaDp2_ops :
    ecaDp2.ops.toList = ecaDp1.ops.toList ++ (rollExtraOps 2 ++ expectedDecomposePoint) := by
  show (dbT4.toTop "_dp_xb" |>.rawBlock 1 (some "qx")
        (Ec.emitReverse32Ops ++ dpConvTail) |>.swap).ops.toList = _
  rw [swap_ops_append, rawBlock_ops_append, toTop_ops_append, dbT4_fd1]
  show (dbT4.ops.toList ++ rollExtraOps 1 ++ (Ec.emitReverse32Ops ++ dpConvTail)
        ++ [StackOp.swap]) = _
  rw [dbT4, rawBlock_ops_append]
  show ((dbT3.ops.toList ++ (Ec.emitReverse32Ops ++ dpConvTail)) ++ rollExtraOps 1
        ++ (Ec.emitReverse32Ops ++ dpConvTail) ++ [StackOp.swap]) = _
  rw [dbT3]
  show ((dbT2.ops.toList ++ (Ec.emitReverse32Ops ++ dpConvTail)) ++ rollExtraOps 1
        ++ (Ec.emitReverse32Ops ++ dpConvTail) ++ [StackOp.swap]) = _
  rw [dbT2, rawBlock_ops_append, dbT1, toTop_ops_append]
  rw [show ecaDp1.findDepth "_pb" = 2 from by
    rw [findDepth_eq_findDepthList _ _ (by rw [ecaDp1_nm]; decide)]; rw [ecaDp1_nm]; decide]
  simp only [rollExtraOps, dpConvTail, expectedDecomposePoint, List.append_assoc]

set_option maxRecDepth 8192 in
/-- **Roll-prefixed decompose runtime transport.**  Running `rollExtraOps d ++ expectedDecomposePoint`
on `tracked ++ rest` where the depth-`d` element is the point blob `vBytes p` (`64 ≤ p.size`):
the roll brings the blob to the top, then `decomposePoint_op_transport` decodes it, landing
`[pointY p, pointX p] ++ (tracked.eraseIdx d ++ rest)`.  The two `emitEcAdd` decomposes use this. -/
private theorem rollDecompose_runOps (s : StackState) (tracked rest : List Value) (d : Nat) (p : ByteArray)
    (hStk : s.stack = tracked ++ rest) (hd : d < tracked.length)
    (hBlob : tracked[d]! = Value.vBytes p) (hSize : 64 ≤ p.size)
    (hDecX : decodeMinimalLE (reverseAcc 32 (p.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointX p)
    (hDecY : decodeMinimalLE (reverseAcc 32 (p.extract 32 p.size) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointY p) :
    runOps (rollExtraOps d ++ expectedDecomposePoint) s
      = .ok { s with stack := Value.vBigint (Crypto.Secp256k1.pointY p) :: Value.vBigint (Crypto.Secp256k1.pointX p)
                :: (tracked.eraseIdx d ++ rest) } := by
  rw [runOps_append, runOps_rollExtraOps s d (by rw [hStk, List.length_append]; omega),
      applyRoll_append s tracked rest d hStk hd, hBlob]
  simp only [match_Except_ok_runOps]
  rw [decomposePoint_op_transport
        { s with stack := .vBytes p :: (tracked.eraseIdx d ++ rest) } p (tracked.eraseIdx d ++ rest) rfl hSize,
      hDecX, hDecY]

set_option maxRecDepth 8192 in
/-- **`emitEcAdd` two-decompose runtime.**  Running `ecaDp2.ops.toList` on the entry
`[pb, pa] ++ rest` lands `[pointY pb, pointX pb, pointY pa, pointX pa] ++ rest` — the affineAdd
entry stack.  Threads the two `rollDecompose_runOps` (depth-1 `_pa`, then depth-2 `_pb`). -/
theorem ecaDp2_runOps (s : StackState) (pa pb : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes pb :: .vBytes pa :: rest)
    (hSizeA : 64 ≤ pa.size) (hSizeB : 64 ≤ pb.size)
    (hDecXa : decodeMinimalLE (reverseAcc 32 (pa.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointX pa)
    (hDecYa : decodeMinimalLE (reverseAcc 32 (pa.extract 32 pa.size) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointY pa)
    (hDecXb : decodeMinimalLE (reverseAcc 32 (pb.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointX pb)
    (hDecYb : decodeMinimalLE (reverseAcc 32 (pb.extract 32 pb.size) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointY pb) :
    runOps ecaDp2.ops.toList s
      = .ok { s with stack :=
          Value.vBigint (Crypto.Secp256k1.pointY pb) :: Value.vBigint (Crypto.Secp256k1.pointX pb)
            :: Value.vBigint (Crypto.Secp256k1.pointY pa) :: Value.vBigint (Crypto.Secp256k1.pointX pa) :: rest } := by
  rw [ecaDp2_ops, ecaDp1_ops]
  -- decompose 1: roll _pa (depth 1, swap) → decode pa → [pointY pa, pointX pa, pb] ++ rest
  rw [runOps_append,
      rollDecompose_runOps s [Value.vBytes pb, .vBytes pa] rest 1 pa hStk (by simp) rfl
        hSizeA hDecXa hDecYa]
  simp only [show ([Value.vBytes pb, .vBytes pa].eraseIdx 1) = [Value.vBytes pb] from rfl,
    List.cons_append, List.nil_append, match_Except_ok_runOps]
  -- decompose 2: roll _pb (depth 2, rot) → decode pb → [pointY pb, pointX pb, pointY pa, pointX pa] ++ rest
  rw [rollDecompose_runOps _
        [Value.vBigint (Crypto.Secp256k1.pointY pa), .vBigint (Crypto.Secp256k1.pointX pa), .vBytes pb] rest 2 pb
        rfl (by simp) rfl hSizeB hDecXb hDecYb]
  simp only [show ([Value.vBigint (Crypto.Secp256k1.pointY pa), .vBigint (Crypto.Secp256k1.pointX pa), .vBytes pb].eraseIdx 2)
        = [Value.vBigint (Crypto.Secp256k1.pointY pa), .vBigint (Crypto.Secp256k1.pointX pa)] from rfl,
    List.cons_append, List.nil_append]

/-- **`composeRxRyInc = composeInc`.**  The determined `composePoint "rx" "ry" "_result"` increment
off the `[rx, ry]`-nm anchor is the same name-free build-back op-list `composePoint_runOps_sim`
consumes (mirrors `enComposePoint_ops` for the `[_nx, _neg_y]` anchor). -/
theorem composeRxRyInc_eq : composeRxRyInc = composeInc := by
  unfold composeRxRyInc
  rw [show Ec.composePoint ⟨#[some "rx", some "ry"], #[]⟩ "rx" "ry" "_result"
        = ((((((((⟨#[some "rx", some "ry"], #[]⟩ : Ec.Tracker).toTop "rx").rawBlock 1 (some "_cp_xb") coordEncodeOps).toTop "ry").rawBlock
            1 (some "_cp_yb") coordEncodeOps).toTop "_cp_xb").toTop "_cp_yb").rawBlock 2 (some "_result")
            [.opcode "OP_CAT"]) from rfl]
  have hc1_nm : ((⟨#[some "rx", some "ry"], #[]⟩ : Ec.Tracker).toTop "rx").nm = #[some "ry", some "rx"] := by
    rw [toTop_nm_canonical ⟨#[some "rx", some "ry"], #[]⟩ "rx" 1
          (fd_of_nm ⟨#[some "rx", some "ry"], #[]⟩ "rx" 1 _ rfl (by decide) (by decide)) (by decide)]
    apply Array.ext' <;> simp
  have hc2_nm : (((⟨#[some "rx", some "ry"], #[]⟩ : Ec.Tracker).toTop "rx").rawBlock 1 (some "_cp_xb") coordEncodeOps).nm
      = #[some "ry", some "_cp_xb"] := by
    rw [rawBlock_nm_some1, hc1_nm]; rfl
  have hc3_nm : ((((⟨#[some "rx", some "ry"], #[]⟩ : Ec.Tracker).toTop "rx").rawBlock 1 (some "_cp_xb") coordEncodeOps).toTop "ry").nm
      = #[some "_cp_xb", some "ry"] := by
    rw [toTop_nm_canonical _ "ry" 1
          (fd_of_nm _ "ry" 1 _ hc2_nm (by decide) (by decide)) (by rw [hc2_nm]; decide), hc2_nm]
    apply Array.ext' <;> simp
  have hc4_nm : (((((⟨#[some "rx", some "ry"], #[]⟩ : Ec.Tracker).toTop "rx").rawBlock 1 (some "_cp_xb") coordEncodeOps).toTop "ry").rawBlock
        1 (some "_cp_yb") coordEncodeOps).nm = #[some "_cp_xb", some "_cp_yb"] := by
    rw [rawBlock_nm_some1, hc3_nm]; rfl
  have hc5_nm : ((((((⟨#[some "rx", some "ry"], #[]⟩ : Ec.Tracker).toTop "rx").rawBlock 1 (some "_cp_xb") coordEncodeOps).toTop "ry").rawBlock
        1 (some "_cp_yb") coordEncodeOps).toTop "_cp_xb").nm = #[some "_cp_yb", some "_cp_xb"] := by
    rw [toTop_nm_canonical _ "_cp_xb" 1
          (fd_of_nm _ "_cp_xb" 1 _ hc4_nm (by decide) (by decide)) (by rw [hc4_nm]; decide), hc4_nm]
    apply Array.ext' <;> simp
  rw [rawBlock_ops_append, toTop_ops_append, toTop_ops_append, rawBlock_ops_append,
      toTop_ops_append, rawBlock_ops_append, toTop_ops_append]
  rw [fd_of_nm ⟨#[some "rx", some "ry"], #[]⟩ "rx" 1 _ rfl (by decide) (by decide),
      fd_of_nm _ "ry" 1 _ hc2_nm (by decide) (by decide),
      fd_of_nm _ "_cp_xb" 1 _ hc4_nm (by decide) (by decide),
      fd_of_nm _ "_cp_yb" 1 _ hc5_nm (by decide) (by decide)]
  simp only [composeInc, coordEncodeOps, rollExtraOps, List.append_assoc, List.nil_append, List.cons_append,
    List.singleton_append]

set_option maxRecDepth 8192 in
/-- **DISCHARGED — `emitEcAdd` agrees with `Crypto.Secp256k1.ecAdd` (non-degenerate branch).**
Running the determined op-list on `[pb, pa] ++ rest` threads the two `decomposePoint` bases
(`ecaDp2_runOps`) → the 24-step `affineAddInc` field chain (`affineAddInc_runOps`) →
`composePoint_runOps_sim` build-back, landing `vBytes (ecAdd pa pb) :: rest`.

INPUT-side wf hypotheses (the honest hypotheses the bare axiom lacked):
* both points 64 bytes + the four `decomposePoint` canonical-decode bridges (the
  `emitEcPointX/Y` carry, here for `pa` and `pb`);
* the two `composePoint` `OP_NUM2BIN`-encode + BE bridges at the result coords `aaRx`/`aaRy`;
* **non-degeneracy**: neither input is the sentinel zero-point and `pointX pa ≢ pointX pb (mod p)`
  — so the affine formula takes the `pxm ≠ qxm` branch.  The `P = ±Q` / doubling case routes
  through `Crypto.Secp256k1.affineDouble`, a SEPARATE codegen path NOT exercised by `emitEcAdd`'s
  straight-line affine-add, hence excluded by hypothesis.

`propext`/`Quot.sound`(/`Classical.choice`)-clean + inherited backend opaques, NO new axiom,
NO `sorryAx`, NO `native_decide`.  Replaces the `Crypto.Spec.emitEcAdd_runOps_eq` axiom. -/
theorem emitEcAdd_runOps_eq (stkSt : StackState) (pa pb : ByteArray) (rest : List Value)
    (hStk : stkSt.stack = .vBytes pb :: .vBytes pa :: rest)
    (hSizeA : 64 ≤ pa.size) (hSizeB : 64 ≤ pb.size)
    (hDecXa : decodeMinimalLE (reverseAcc 32 (pa.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointX pa)
    (hDecYa : decodeMinimalLE (reverseAcc 32 (pa.extract 32 pa.size) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointY pa)
    (hDecXb : decodeMinimalLE (reverseAcc 32 (pb.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointX pb)
    (hDecYb : decodeMinimalLE (reverseAcc 32 (pb.extract 32 pb.size) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointY pb)
    (encRx encRy : ByteArray)
    (hEncRx : num2binEncode? (aaRx (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa)
                (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb)) 33 = some encRx)
    (hEncRy : num2binEncode? (aaRy (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa)
                (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb)) 33 = some encRy)
    (hSzRx : (32 : Nat) ≤ encRx.size) (hSzRy : (32 : Nat) ≤ encRy.size)
    (hBeRx : reverseAcc 32 (encRx.extract 0 32) ByteArray.empty
              = Crypto.Secp256k1.intToBE32 (aaRx (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa)
                  (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb)))
    (hBeRy : reverseAcc 32 (encRy.extract 0 32) ByteArray.empty
              = Crypto.Secp256k1.intToBE32 (aaRy (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa)
                  (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb)))
    (hPa : ¬ (Crypto.Secp256k1.pointX pa = 0 ∧ Crypto.Secp256k1.pointY pa = 0))
    (hPb : ¬ (Crypto.Secp256k1.pointX pb = 0 ∧ Crypto.Secp256k1.pointY pb = 0))
    (hNonDeg : Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.pointX pa)
                ≠ Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.pointX pb)) :
    runOps Ec.emitEcAdd stkSt
      = .ok { stkSt with stack := .vBytes (Crypto.Secp256k1.ecAdd pa pb) :: rest } := by
  rw [emitEcAdd_ops]
  unfold expectedEcAdd
  simp only [List.append_assoc]
  -- two decomposes → [qy, qx, py, px] ++ rest (q = pb, p = pa)
  rw [runOps_append, ecaDp2_runOps stkSt pa pb rest hStk hSizeA hSizeB hDecXa hDecYa hDecXb hDecYb]
  simp only [match_Except_ok_runOps]
  -- affineAdd field chain → [aaRy, aaRx] ++ rest
  rw [runOps_append,
      affineAddInc_runOps _ (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa)
        (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb) rest rfl]
  simp only [match_Except_ok_runOps]
  -- composePoint build-back → [makePoint aaRx aaRy] ++ rest
  rw [composeRxRyInc_eq,
      composePoint_runOps_sim _
        (aaRx (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa) (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb))
        (aaRy (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa) (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb))
        encRx encRy rest rfl hEncRx hEncRy hSzRx hSzRy hBeRx hBeRy]
  -- makePoint aaRx aaRy = ecAdd pa pb (non-degenerate affineAdd branch)
  rw [show Crypto.Secp256k1.ecAdd pa pb
        = Crypto.Secp256k1.makePoint
            (aaRx (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa) (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb))
            (aaRy (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa) (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb)) from by
      unfold Crypto.Secp256k1.ecAdd
      rw [aaRx_aaRy_eq_affineAdd (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa)
            (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb) hPa hPb hNonDeg]]

/-! ### MANDATORY smokes for the `emitEcAdd` discharge (deliverable 2)

NOTE ON `native_decide`: the result coords `aaRx`/`aaRy` contain `Crypto.Secp256k1.fieldInv`,
which is `fieldPowNat _ (FIELD_P − 2).toNat` — a ~2²⁵⁶-iteration Fermat-exponent recursion that
is NOT machine-computable (it crashes the compiler).  So the two `num2binEncode?` / BE encode
bridges (which evaluate `aaRx`/`aaRy`) cannot be discharged by `native_decide` for a concrete
input; they are the SAME `num2binEncode?`-totality bridges the discharged `emitEcNegate` carries
(satisfiable for any in-range coord).  The anti-vacuity smoke below therefore exercises the
`fieldInv`-FREE wf hypotheses on two genuine, distinct on-curve points — the load-bearing
non-vacuity (real on-curve inputs, the four decode bridges, the non-sentinel guards, and the
non-degenerate `pointX G ≠ pointX 2G (mod p)` case split). -/

/-- Two distinct concrete on-curve secp256k1 points for the discharge smoke: `pa = G`
(the generator) and `pb = 2G` (its double).  Their x-coords differ mod p (non-degenerate). -/
private def smokeEcAddPa : ByteArray :=
  Crypto.Secp256k1.makePoint Crypto.Secp256k1.GEN_X Crypto.Secp256k1.GEN_Y
private def smokeEcAddPb : ByteArray :=
  Crypto.Secp256k1.makePoint
    0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
    0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a

/-- SMOKE (wf anti-vacuity, `fieldInv`-free hypotheses).  The discharge's INPUT-side hypotheses
that do NOT depend on `fieldInv` are SATISFIABLE for two distinct on-curve points `G` and `2G`:
both are 64-byte, the four `decomposePoint` canonical-decode bridges hold, neither is the sentinel
zero-point, and `pointX G ≠ pointX 2G (mod p)` — so the non-degenerate (`pxm ≠ qxm`) branch is
genuinely taken.  Rules out a vacuous discharge on the input side. -/
theorem smoke_emitEcAdd_wf_satisfiable :
    (64 : Nat) ≤ smokeEcAddPa.size ∧ (64 : Nat) ≤ smokeEcAddPb.size
      ∧ decodeMinimalLE (reverseAcc 32 (smokeEcAddPa.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
          = Crypto.Secp256k1.pointX smokeEcAddPa
      ∧ decodeMinimalLE (reverseAcc 32 (smokeEcAddPa.extract 32 smokeEcAddPa.size) ByteArray.empty ++ ByteArray.mk #[0x00])
          = Crypto.Secp256k1.pointY smokeEcAddPa
      ∧ decodeMinimalLE (reverseAcc 32 (smokeEcAddPb.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
          = Crypto.Secp256k1.pointX smokeEcAddPb
      ∧ decodeMinimalLE (reverseAcc 32 (smokeEcAddPb.extract 32 smokeEcAddPb.size) ByteArray.empty ++ ByteArray.mk #[0x00])
          = Crypto.Secp256k1.pointY smokeEcAddPb
      ∧ ¬ (Crypto.Secp256k1.pointX smokeEcAddPa = 0 ∧ Crypto.Secp256k1.pointY smokeEcAddPa = 0)
      ∧ ¬ (Crypto.Secp256k1.pointX smokeEcAddPb = 0 ∧ Crypto.Secp256k1.pointY smokeEcAddPb = 0)
      ∧ Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.pointX smokeEcAddPa)
          ≠ Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.pointX smokeEcAddPb) := by
  native_decide

/-- SMOKE (the discharge FIRES symbolically, anti-vacuity).  Specialising `emitEcAdd_runOps_eq`
to two symbolic 64-byte points whose decode/encode/non-degeneracy bridges are taken as hypotheses
yields the headline equation `runOps emitEcAdd = ecAdd pa pb` — confirming the discharge is a
genuine, applicable theorem (not vacuously typed).  The `fieldInv`-bearing encode bridges are
passed as hypotheses (not `native_decide`d, per the note above). -/
theorem smoke_emitEcAdd_runOps_eq_applies (stkSt : StackState) (pa pb : ByteArray) (rest : List Value)
    (hStk : stkSt.stack = .vBytes pb :: .vBytes pa :: rest)
    (hSizeA : 64 ≤ pa.size) (hSizeB : 64 ≤ pb.size)
    (hDecXa : decodeMinimalLE (reverseAcc 32 (pa.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointX pa)
    (hDecYa : decodeMinimalLE (reverseAcc 32 (pa.extract 32 pa.size) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointY pa)
    (hDecXb : decodeMinimalLE (reverseAcc 32 (pb.extract 0 32) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointX pb)
    (hDecYb : decodeMinimalLE (reverseAcc 32 (pb.extract 32 pb.size) ByteArray.empty ++ ByteArray.mk #[0x00])
              = Crypto.Secp256k1.pointY pb)
    (encRx encRy : ByteArray)
    (hEncRx : num2binEncode? (aaRx (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa)
                (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb)) 33 = some encRx)
    (hEncRy : num2binEncode? (aaRy (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa)
                (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb)) 33 = some encRy)
    (hSzRx : (32 : Nat) ≤ encRx.size) (hSzRy : (32 : Nat) ≤ encRy.size)
    (hBeRx : reverseAcc 32 (encRx.extract 0 32) ByteArray.empty
              = Crypto.Secp256k1.intToBE32 (aaRx (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa)
                  (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb)))
    (hBeRy : reverseAcc 32 (encRy.extract 0 32) ByteArray.empty
              = Crypto.Secp256k1.intToBE32 (aaRy (Crypto.Secp256k1.pointX pa) (Crypto.Secp256k1.pointY pa)
                  (Crypto.Secp256k1.pointX pb) (Crypto.Secp256k1.pointY pb)))
    (hPa : ¬ (Crypto.Secp256k1.pointX pa = 0 ∧ Crypto.Secp256k1.pointY pa = 0))
    (hPb : ¬ (Crypto.Secp256k1.pointX pb = 0 ∧ Crypto.Secp256k1.pointY pb = 0))
    (hNonDeg : Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.pointX pa)
                ≠ Crypto.Secp256k1.fieldMod (Crypto.Secp256k1.pointX pb)) :
    runOps Ec.emitEcAdd stkSt = .ok { stkSt with stack := .vBytes (Crypto.Secp256k1.ecAdd pa pb) :: rest } :=
  emitEcAdd_runOps_eq stkSt pa pb rest hStk hSizeA hSizeB hDecXa hDecYa hDecXb hDecYb
    encRx encRy hEncRx hEncRy hSzRx hSzRy hBeRx hBeRy hPa hPb hNonDeg

end RunarVerification.Stack.AgreesEC
