import RunarVerification.Stack.Eval

/-!
# `AgreesD1` — runtime selection substrate for the multi-method dispatch family

This module is the first dedicated substrate file for the Phase-D **D1
multi-method Merkle dispatch** retirement (axiom
`merkle_dispatch_selection_correct` / sub-omnibus
`compileSafe_observational_correct_modulo_dispatch_codegen` in
`Pipeline.lean`). It is intentionally standalone: it imports only
`RunarVerification.Stack.Eval` and is NOT wired into any existing
file's import graph. Integration is the orchestrator's job.

## What the compiler does (the lowering map this file targets)

For a program with `n ≥ 2` public methods, `Script/Emit.lean`
(`emitDispatch` / `emitDispatchChain`, lines 351-360) emits, for each
public method body `body_i`:

```
[OP_DUP push(0) OP_NUMEQUAL OP_IF OP_DROP <body0> OP_ELSE]
[OP_DUP push(1) OP_NUMEQUAL OP_IF OP_DROP <body1> OP_ELSE]
…
[push(n-1) OP_NUMEQUALVERIFY <body_{n-1}>]
[OP_ENDIF * (n-1)]
```

`Script/Parse.lean` (`parseScriptFrame`, lines 459-474) matches the
`OP_IF` / `OP_ELSE` / `OP_ENDIF` brackets and reconstructs each
non-last branch as a nested `.ifOp thn (some els)` op (see
`Stack/Eval.lean#runOps`, lines 813-830, for the runtime IF
semantics). So `runParsedBytes` of an `n = 2` dispatch chain runs the
flat op-list:

```
[.dup, .push (.bigint 0), .opcode "OP_NUMEQUAL",
 .ifOp (.opcode "OP_DROP" :: body0)
       (some (.push (.bigint 1) :: .opcode "OP_NUMEQUALVERIFY" :: body1))]
```

## What this file proves

The runtime *selection step* of the `n = 2` dispatch head. With the
caller's method-index witness `i = 0` on top of stack
(`stack = vBigint 0 :: rest`), the head opcodes
`OP_DUP push(0) OP_NUMEQUAL OP_IF OP_DROP` consume the witness and the
duplicated copy, and `runOps` of the whole parsed op-list collapses to
`runOps body0 { stack := rest }`. That is exactly the
`merkle_dispatch_selection_correct` conclusion shape for the `i = 0`
branch — the post-dispatch stack is `rest`.

This is the substrate the D1 axiom currently stands in for: the
selection rewrite itself, proven from the `runOps` / `stepNonIf`
definitions. The single-public consume theorems then handle
`runOps body0` unchanged (they are body-level, witness-agnostic), so
the capstone `compileSafe_multi_public_observational_correct` (which
already takes `hDispatchToOps` as a hypothesis) can consume this
directly.
-/

namespace RunarVerification
namespace Stack
namespace AgreesD1

open RunarVerification.ANF.Eval (Value)
open RunarVerification.Stack.Eval

/-- The runtime shape of the parsed `n = 2` dispatch head body that the
recursive-descent parser reconstructs for two public methods. The
caller supplies the two branch bodies `body0` / `body1`; this is the
*entire* op-list `runParsedBytes` runs (head + nested IF). -/
def dispatch2Ops (body0 body1 : List StackOp) : List StackOp :=
  [ .dup,
    .push (.bigint 0),
    .opcode "OP_NUMEQUAL",
    .ifOp (.opcode "OP_DROP" :: body0)
      (some (.push (.bigint 1) :: .opcode "OP_NUMEQUALVERIFY" :: body1)) ]

/-- `OP_DUP` is not an `.ifOp` (discharges `runOps_cons_nonIf_eq`). -/
private theorem dup_not_if :
    ∀ thn els, (StackOp.dup) ≠ .ifOp thn els := by
  intro _ _ h; exact StackOp.noConfusion h

/-- `OP_DROP` (as a named opcode) is not an `.ifOp`. -/
private theorem dropOp_not_if :
    ∀ thn els, (StackOp.opcode "OP_DROP") ≠ .ifOp thn els := by
  intro _ _ h; exact StackOp.noConfusion h

/-! ## Branch-0 selection

The core selection lemma. With method-index witness `0` on top of
stack, the dispatch head selects branch 0 and discards both the
witness and its duplicate, leaving the body to run on `rest`. -/

set_option maxHeartbeats 800000 in
/-- **D1 branch-0 selection (substrate).**

When the unlocking caller pushed dispatch index `0`
(`initial.stack = vBigint 0 :: rest`), running the parsed 2-method
dispatch op-list equals running `body0` on the post-dispatch stack
`{ initial with stack := rest }`.

This is the `i = 0` instance of the `merkle_dispatch_selection_correct`
conclusion, proven directly from the `runOps` / `stepNonIf` / `applyDup`
/ `liftIntBin` definitions. The `OP_NUMEQUAL` of `0 = 0` reduces to
`vBool true`, the reconstructed `.ifOp` takes its `thn` branch, and
`OP_DROP` removes the witness copy the leading `OP_DUP` created. -/
theorem dispatch2_select_branch0
    (body0 body1 : List StackOp)
    (initial : StackState)
    (rest : List Value)
    (hWitness : initial.stack = Value.vBigint (Int.ofNat 0) :: rest) :
    runOps (dispatch2Ops body0 body1) initial
      = runOps body0 { initial with stack := rest } := by
  -- The intermediate states, written inline (no `set` — this project
  -- has no Mathlib). Each opcode step is discharged as a closed `rfl`-
  -- backed equation, then rewritten into the goal.
  unfold dispatch2Ops
  -- OP_DUP: duplicate the witness `0`.
  rw [runOps_cons_nonIf_eq StackOp.dup _ initial dup_not_if]
  have hDup : stepNonIf StackOp.dup initial
      = .ok { initial with stack :=
          (Value.vBigint (Int.ofNat 0) :: Value.vBigint (Int.ofNat 0) :: rest) } := by
    rw [stepNonIf_dup]; unfold applyDup
    rw [hWitness]; simp only [StackState.push, hWitness]
  rw [hDup]
  simp only []
  -- push 0.
  rw [runOps_cons_nonIf_eq (.push (.bigint 0)) _ _
    (by intro _ _ h; exact StackOp.noConfusion h)]
  have hPush : stepNonIf (.push (.bigint 0))
      { initial with stack :=
          (Value.vBigint (Int.ofNat 0) :: Value.vBigint (Int.ofNat 0) :: rest) }
      = .ok { initial with stack :=
          (Value.vBigint (Int.ofNat 0)
            :: Value.vBigint (Int.ofNat 0)
            :: Value.vBigint (Int.ofNat 0) :: rest) } := by
    rw [stepNonIf_push_bigint]; rfl
  rw [hPush]
  simp only []
  -- OP_NUMEQUAL: pop two `0`s → vBool (0 = 0) = true.
  rw [runOps_cons_nonIf_eq (.opcode "OP_NUMEQUAL") _ _
    (by intro _ _ h; exact StackOp.noConfusion h)]
  have hNumEq : stepNonIf (.opcode "OP_NUMEQUAL")
      { initial with stack :=
          (Value.vBigint (Int.ofNat 0)
            :: Value.vBigint (Int.ofNat 0)
            :: Value.vBigint (Int.ofNat 0) :: rest) }
      = .ok { initial with stack :=
          (Value.vBool true :: Value.vBigint (Int.ofNat 0) :: rest) } := by
    rw [stepNonIf_opcode]; rfl
  rw [hNumEq]
  simp only []
  -- The reconstructed `.ifOp`: pop `vBool true`, take the thn branch.
  have hIf :
      runOps
        [.ifOp (.opcode "OP_DROP" :: body0)
          (some (.push (.bigint 1) :: .opcode "OP_NUMEQUALVERIFY" :: body1))]
        { initial with stack :=
            (Value.vBool true :: Value.vBigint (Int.ofNat 0) :: rest) }
      = runOps (.opcode "OP_DROP" :: body0)
          { initial with stack := (Value.vBigint (Int.ofNat 0) :: rest) } := by
    -- Expose the outer `.ifOp` step (one layer), pop the `vBool true`
    -- condition, take the thn branch. The true-branch runs `thn` then
    -- the empty trailing `rest`; the `runOps []` is identity, collapsed
    -- by case-splitting on the thn run.
    rw [runOps]
    unfold StackState.pop?
    simp only [asBool?]
    cases hT : runOps (.opcode "OP_DROP" :: body0)
        { initial with stack := (Value.vBigint (Int.ofNat 0) :: rest) } with
    | error e => rfl
    | ok s'' => simp only [runOps_nil]
  rw [hIf]
  -- OP_DROP removes the witness copy → { initial with stack := rest }.
  rw [runOps_cons_nonIf_eq (.opcode "OP_DROP") _ _ dropOp_not_if]
  have hDrop : stepNonIf (.opcode "OP_DROP")
      { initial with stack := (Value.vBigint (Int.ofNat 0) :: rest) }
      = .ok { initial with stack := rest } := by
    rw [stepNonIf_opcode]; unfold runOpcode applyDrop; rfl
  rw [hDrop]

/-! ## Smoke

Concrete instantiation. The branch-0 selection fires on a real
2-method dispatch op-list: witness `0`, `body0 = [OP_1ADD]`,
`body1 = [OP_2MUL]`, post-witness stack `[7]`. Running the parsed
dispatch leaves `[8]` (= `runOps [OP_1ADD]` on `[7]`). Proven by the
general lemma plus single-step evaluation of `OP_1ADD` — no axiom. -/

/-- Single-step evaluation of `OP_1ADD` on `[7]` yields `[8]`. -/
private theorem run_1add_on_7 :
    runOps [.opcode "OP_1ADD"]
        ({ stack := [Value.vBigint 7] } : StackState)
      = .ok ({ stack := [Value.vBigint 8] } : StackState) := by
  rw [runOps_cons_nonIf_eq (.opcode "OP_1ADD") _ _
    (by intro _ _ h; exact StackOp.noConfusion h)]
  have hStep : stepNonIf (.opcode "OP_1ADD")
      ({ stack := [Value.vBigint 7] } : StackState)
      = .ok ({ stack := [Value.vBigint 8] } : StackState) := by
    rw [stepNonIf_opcode]; rfl
  rw [hStep]
  simp only [runOps_nil]

/-- Concrete branch-0 selection: the parsed 2-method dispatch with
witness `0` on `[0, 7]` reduces to `[8]` (branch 0 = `OP_1ADD`).
Confirms `dispatch2_select_branch0` is not vacuous. -/
theorem dispatch2_select_branch0_smoke :
    runOps
        (dispatch2Ops [.opcode "OP_1ADD"] [.opcode "OP_2MUL"])
        ({ stack := [Value.vBigint (Int.ofNat 0), Value.vBigint 7] } : StackState)
      = .ok ({ stack := [Value.vBigint 8] } : StackState) := by
  rw [dispatch2_select_branch0 [.opcode "OP_1ADD"] [.opcode "OP_2MUL"]
    ({ stack := [Value.vBigint (Int.ofNat 0), Value.vBigint 7] } : StackState)
    [Value.vBigint 7] rfl]
  exact run_1add_on_7

/-! ## Deliverable 1 — branch-`i` selection, `n` methods

`dispatch2_select_branch0` is the `i = 0`, `n = 2` proof-of-concept. We
now generalise to the parsed reconstruction of an arbitrary `n`-method
dispatch chain, selecting any branch `k`.

### The reconstructed op-list

`Script/Emit.lean#emitDispatchChain i ms` emits, for method index `i`:

* non-last method → `OP_DUP push(i) OP_NUMEQUAL OP_IF OP_DROP body OP_ELSE`,
* last method     → `push(i) OP_NUMEQUALVERIFY body`,

with `(ms.length - 1)` trailing `OP_ENDIF`s appended by `emitDispatch`.
`Script/Parse.lean#parseStackOpFuel` reconstructs the `OP_IF … OP_ELSE …
OP_ENDIF` brackets as a right-nested `.ifOp thn (some els)` tree: each
non-last head becomes `[.dup, .push (.bigint i), .opcode "OP_NUMEQUAL",
.ifOp (.opcode "OP_DROP" :: body) (some <rest-of-chain>)]`, and the last
head becomes `.push (.bigint i) :: .opcode "OP_NUMEQUALVERIFY" :: body`.

`dispatchChainOps` below is exactly that reconstruction, parameterised
by the starting method index `i` and the list of branch bodies. For two
bodies starting at index `0` it is definitionally `dispatch2Ops`. -/

/-- The right-nested op-list `runParsedBytes` runs for the dispatch chain
of method-bodies `bodies`, with the first body at index `i`. Mirrors
`Emit.emitDispatchChain` / the parser's `.ifOp` reconstruction. -/
def dispatchChainOps (i : Nat) : List (List StackOp) → List StackOp
  | []        => []
  | [body]    =>
      .push (.bigint (Int.ofNat i))
        :: .opcode "OP_NUMEQUALVERIFY"
        :: body
  | body :: rest =>
      [ .dup,
        .push (.bigint (Int.ofNat i)),
        .opcode "OP_NUMEQUAL",
        .ifOp (.opcode "OP_DROP" :: body)
          (some (dispatchChainOps (i + 1) rest)) ]

/-- `dispatchChainOps 0 [body0, body1]` is the wave-65 `dispatch2Ops`. -/
theorem dispatchChainOps_two_eq_dispatch2Ops (body0 body1 : List StackOp) :
    dispatchChainOps 0 [body0, body1] = dispatch2Ops body0 body1 := rfl

/-! ### Non-matching head step

When the witness `w` does not equal the head index `i`, the dispatch
head `OP_DUP push(i) OP_NUMEQUAL OP_IF` evaluates the `OP_NUMEQUAL` to
`false`, takes the `.ifOp` ELSE arm, and the witness `w` is still on
top of the (otherwise unchanged) stack for the recursive chain. -/

set_option maxHeartbeats 800000 in
/-- Non-matching dispatch head: with witness `w ≠ i` on top of stack,
running the non-last dispatch head (and its nested `.ifOp`) for index
`i` reduces to running the ELSE chain `els` on the *same* witness stack.
The witness copy made by `OP_DUP` is consumed by `OP_NUMEQUAL`; the
original witness `w` survives into the ELSE arm. -/
theorem dispatch_head_skip
    (i : Nat) (w : Int) (body : List StackOp) (els : List StackOp)
    (initial : StackState) (rest : List Value)
    (hWitness : initial.stack = Value.vBigint w :: rest)
    (hNe : w ≠ Int.ofNat i) :
    runOps
        [ .dup,
          .push (.bigint (Int.ofNat i)),
          .opcode "OP_NUMEQUAL",
          .ifOp (.opcode "OP_DROP" :: body) (some els) ]
        initial
      = runOps els { initial with stack := Value.vBigint w :: rest } := by
  -- OP_DUP: duplicate the witness.
  rw [runOps_cons_nonIf_eq StackOp.dup _ initial dup_not_if]
  have hDup : stepNonIf StackOp.dup initial
      = .ok { initial with stack :=
          (Value.vBigint w :: Value.vBigint w :: rest) } := by
    rw [stepNonIf_dup]; unfold applyDup
    rw [hWitness]; simp only [StackState.push, hWitness]
  rw [hDup]
  simp only []
  -- push i.
  rw [runOps_cons_nonIf_eq (.push (.bigint (Int.ofNat i))) _ _
    (by intro _ _ h; exact StackOp.noConfusion h)]
  have hPush : stepNonIf (.push (.bigint (Int.ofNat i)))
      { initial with stack :=
          (Value.vBigint w :: Value.vBigint w :: rest) }
      = .ok { initial with stack :=
          (Value.vBigint (Int.ofNat i)
            :: Value.vBigint w :: Value.vBigint w :: rest) } := by
    rw [stepNonIf_push_bigint]; rfl
  rw [hPush]
  simp only []
  -- OP_NUMEQUAL: pop [i, w] → vBool (decide (w = i)); `w ≠ i` so false.
  rw [runOps_cons_nonIf_eq (.opcode "OP_NUMEQUAL") _ _
    (by intro _ _ h; exact StackOp.noConfusion h)]
  have hNumEq : stepNonIf (.opcode "OP_NUMEQUAL")
      { initial with stack :=
          (Value.vBigint (Int.ofNat i)
            :: Value.vBigint w :: Value.vBigint w :: rest) }
      = .ok { initial with stack :=
          (Value.vBool false :: Value.vBigint w :: rest) } := by
    rw [stepNonIf_opcode]
    show liftIntBin
        { initial with stack :=
            (Value.vBigint (Int.ofNat i)
              :: Value.vBigint w :: Value.vBigint w :: rest) }
        (fun a b => .vBool (decide (a = b)))
      = _
    simp only [liftIntBin, popN, StackState.pop?, asInt?]
    have hDec : decide (w = Int.ofNat i) = false := decide_eq_false hNe
    rw [hDec]
    simp only [StackState.push]
  rw [hNumEq]
  simp only []
  -- The reconstructed `.ifOp`: pop `vBool false`, take the ELSE arm.
  rw [runOps]
  unfold StackState.pop?
  simp only [asBool?]
  cases hE : runOps els
      { initial with stack := (Value.vBigint w :: rest) } with
  | error e => rfl
  | ok s'' => simp only [runOps_nil]

/-! ### Matching last-method head

The last method in the chain is reconstructed as
`push(i) OP_NUMEQUALVERIFY body`. With matching witness `w = i`, the
`OP_NUMEQUALVERIFY` verifies and pops both the pushed index and the
witness, leaving `body` to run on `rest`. -/

set_option maxHeartbeats 800000 in
/-- Matching last-method head: with witness `w = i` on top, the
`push(i) OP_NUMEQUALVERIFY body` tail runs `body` on the post-dispatch
stack `rest` (both the pushed index and the witness are consumed). -/
theorem dispatch_head_last_match
    (i : Nat) (body : List StackOp)
    (initial : StackState) (rest : List Value)
    (hWitness : initial.stack = Value.vBigint (Int.ofNat i) :: rest) :
    runOps
        (.push (.bigint (Int.ofNat i))
          :: .opcode "OP_NUMEQUALVERIFY" :: body)
        initial
      = runOps body { initial with stack := rest } := by
  -- push i.
  rw [runOps_cons_nonIf_eq (.push (.bigint (Int.ofNat i))) _ _
    (by intro _ _ h; exact StackOp.noConfusion h)]
  have hPush : stepNonIf (.push (.bigint (Int.ofNat i))) initial
      = .ok { initial with stack :=
          (Value.vBigint (Int.ofNat i)
            :: Value.vBigint (Int.ofNat i) :: rest) } := by
    rw [stepNonIf_push_bigint]
    simp only [StackState.push]; rw [hWitness]
  rw [hPush]
  simp only []
  -- OP_NUMEQUALVERIFY: pop [i, i], i = i → ok (drop both).
  rw [runOps_cons_nonIf_eq (.opcode "OP_NUMEQUALVERIFY") _ _
    (by intro _ _ h; exact StackOp.noConfusion h)]
  have hVerify : stepNonIf (.opcode "OP_NUMEQUALVERIFY")
      { initial with stack :=
          (Value.vBigint (Int.ofNat i)
            :: Value.vBigint (Int.ofNat i) :: rest) }
      = .ok { initial with stack := rest } := by
    rw [stepNonIf_opcode]
    simp only [runOpcode, popN, StackState.pop?, asInt?]
    rfl
  rw [hVerify]

/-! ### Branch-`i` selection (the general lemma)

The induction key: for a witness `w = i + k` (the caller pushed dispatch
index for the `k`-th body of the chain that starts at method index `i`),
`runOps (dispatchChainOps i bodies)` selects `bodies[k]` and discards the
witness. The base case `k = 0` (matching head) splits on whether the
chain is a singleton (last method → `dispatch_head_last_match`) or not
(matching non-last head → the branch-0 reduction reused inline). The
step case `k = k'+1` uses `dispatch_head_skip` to advance one chain link
(witness `w ≠ i` because `w = i + k' + 1 > i`) and recurses on the ELSE
chain `dispatchChainOps (i+1) rest`. -/

set_option maxHeartbeats 1000000 in
/-- **D1 branch-`k` selection (substrate, general `n`).**

For a chain of `bodies` starting at method index `i`, witness
`w = i + k` with `k < bodies.length`, running the parsed dispatch chain
equals running the selected `bodies[k]` on the post-dispatch stack
`{ initial with stack := rest }` (the witness is discarded). -/
theorem dispatchN_select_branch
    (bodies : List (List StackOp)) :
    ∀ (i k : Nat) (body : List StackOp)
      (initial : StackState) (rest : List Value),
      bodies[k]? = some body →
      initial.stack = Value.vBigint (Int.ofNat (i + k)) :: rest →
      runOps (dispatchChainOps i bodies) initial
        = runOps body { initial with stack := rest } := by
  induction bodies with
  | nil =>
      intro i k body initial rest hIdx _
      exact absurd hIdx (by simp)
  | cons headBody restBodies ih =>
      intro i k body initial rest hIdx hWitness
      cases k with
      | zero =>
          -- Matching head: witness w = i.
          simp only [Nat.add_zero] at hWitness
          -- bodies[0]? = some headBody, so body = headBody.
          have hBody : body = headBody := by
            simp only [List.getElem?_cons_zero, Option.some.injEq] at hIdx
            exact hIdx.symm
          subst hBody
          cases restBodies with
          | nil =>
              -- Singleton chain (last method).
              show runOps (dispatchChainOps i [body]) initial = _
              unfold dispatchChainOps
              exact dispatch_head_last_match i body initial rest hWitness
          | cons headBody' restBodies' =>
              -- Non-last matching head. Reuse the branch-0 reduction
              -- shape: OP_DUP push(i) OP_NUMEQUAL → vBool true → thn arm
              -- → OP_DROP removes witness copy → body on rest.
              show runOps (dispatchChainOps i (body :: headBody' :: restBodies'))
                  initial = _
              unfold dispatchChainOps
              -- OP_DUP.
              rw [runOps_cons_nonIf_eq StackOp.dup _ initial dup_not_if]
              have hDup : stepNonIf StackOp.dup initial
                  = .ok { initial with stack :=
                      (Value.vBigint (Int.ofNat i)
                        :: Value.vBigint (Int.ofNat i) :: rest) } := by
                rw [stepNonIf_dup]; unfold applyDup
                rw [hWitness]; simp only [StackState.push, hWitness]
              rw [hDup]
              simp only []
              -- push i.
              rw [runOps_cons_nonIf_eq (.push (.bigint (Int.ofNat i))) _ _
                (by intro _ _ h; exact StackOp.noConfusion h)]
              have hPush : stepNonIf (.push (.bigint (Int.ofNat i)))
                  { initial with stack :=
                      (Value.vBigint (Int.ofNat i)
                        :: Value.vBigint (Int.ofNat i) :: rest) }
                  = .ok { initial with stack :=
                      (Value.vBigint (Int.ofNat i)
                        :: Value.vBigint (Int.ofNat i)
                        :: Value.vBigint (Int.ofNat i) :: rest) } := by
                rw [stepNonIf_push_bigint]; rfl
              rw [hPush]
              simp only []
              -- OP_NUMEQUAL: i = i → vBool true.
              rw [runOps_cons_nonIf_eq (.opcode "OP_NUMEQUAL") _ _
                (by intro _ _ h; exact StackOp.noConfusion h)]
              have hNumEq : stepNonIf (.opcode "OP_NUMEQUAL")
                  { initial with stack :=
                      (Value.vBigint (Int.ofNat i)
                        :: Value.vBigint (Int.ofNat i)
                        :: Value.vBigint (Int.ofNat i) :: rest) }
                  = .ok { initial with stack :=
                      (Value.vBool true
                        :: Value.vBigint (Int.ofNat i) :: rest) } := by
                rw [stepNonIf_opcode]
                show liftIntBin
                    { initial with stack :=
                        (Value.vBigint (Int.ofNat i)
                          :: Value.vBigint (Int.ofNat i)
                          :: Value.vBigint (Int.ofNat i) :: rest) }
                    (fun a b => .vBool (decide (a = b)))
                  = _
                simp only [liftIntBin, popN, StackState.pop?, asInt?,
                  StackState.push]
                rfl
              rw [hNumEq]
              simp only []
              -- .ifOp: pop vBool true, take thn = OP_DROP :: body.
              have hIf :
                  runOps
                    [.ifOp (.opcode "OP_DROP" :: body)
                      (some (dispatchChainOps (i + 1)
                        (headBody' :: restBodies')))]
                    { initial with stack :=
                        (Value.vBool true
                          :: Value.vBigint (Int.ofNat i) :: rest) }
                  = runOps (.opcode "OP_DROP" :: body)
                      { initial with stack :=
                          (Value.vBigint (Int.ofNat i) :: rest) } := by
                rw [runOps]
                unfold StackState.pop?
                simp only [asBool?]
                cases hT : runOps (.opcode "OP_DROP" :: body)
                    { initial with stack :=
                        (Value.vBigint (Int.ofNat i) :: rest) } with
                | error e => rfl
                | ok s'' => simp only [runOps_nil]
              rw [hIf]
              -- OP_DROP removes witness copy → body on rest.
              rw [runOps_cons_nonIf_eq (.opcode "OP_DROP") _ _ dropOp_not_if]
              have hDrop : stepNonIf (.opcode "OP_DROP")
                  { initial with stack :=
                      (Value.vBigint (Int.ofNat i) :: rest) }
                  = .ok { initial with stack := rest } := by
                rw [stepNonIf_opcode]; unfold runOpcode applyDrop; rfl
              rw [hDrop]
      | succ k' =>
          -- Non-matching head: witness w = i + (k'+1) ≠ i.
          cases restBodies with
          | nil =>
              -- Singleton chain but k = k'+1 ≥ 1 — out of range.
              exact absurd hIdx (by simp)
          | cons headBody' restBodies' =>
              show runOps (dispatchChainOps i (headBody :: headBody' :: restBodies'))
                  initial = _
              -- `dispatchChainOps i (a :: b :: rest)` unfolds to the
              -- non-last head whose ELSE arm is `dispatchChainOps (i+1) (b :: rest)`.
              have hUnfold :
                  dispatchChainOps i (headBody :: headBody' :: restBodies')
                  = [ .dup,
                      .push (.bigint (Int.ofNat i)),
                      .opcode "OP_NUMEQUAL",
                      .ifOp (.opcode "OP_DROP" :: headBody)
                        (some (dispatchChainOps (i + 1)
                          (headBody' :: restBodies'))) ] := rfl
              rw [hUnfold]
              have hNe : Int.ofNat (i + (k' + 1)) ≠ Int.ofNat i := by
                intro hEq
                have : i + (k' + 1) = i := Int.ofNat.inj hEq
                omega
              rw [dispatch_head_skip i (Int.ofNat (i + (k' + 1)))
                    headBody
                    (dispatchChainOps (i + 1) (headBody' :: restBodies'))
                    initial rest hWitness hNe]
              -- Recurse on the ELSE chain at index i+1, witness now at k'.
              have hIdx' : (headBody' :: restBodies')[k']? = some body := by
                simpa using hIdx
              have hWitness' :
                  ({ initial with stack :=
                      Value.vBigint (Int.ofNat (i + (k' + 1))) :: rest }
                    : StackState).stack
                  = Value.vBigint (Int.ofNat ((i + 1) + k')) :: rest := by
                simp only []
                rw [show (i + 1) + k' = i + (k' + 1) by omega]
              exact ih (i + 1) k' body
                { initial with stack :=
                    Value.vBigint (Int.ofNat (i + (k' + 1))) :: rest }
                rest hIdx' hWitness'

/-! ### Smoke for deliverable 1

Concrete 3-method dispatch. Bodies `[OP_1ADD]`, `[OP_NEGATE]`,
`[OP_2MUL]` at indices `0, 1, 2`. Branch 2 (witness `2`) selected on
`[2, 5]` runs `OP_2MUL` → `[10]`. Confirms `dispatchN_select_branch`
fires for a non-zero, last-method branch (`k = 2`, exercises one
`dispatch_head_skip` step and the last-method `OP_NUMEQUALVERIFY`
match). -/

/-- Single-step evaluation of `OP_2MUL` on `[5]` yields `[10]`. -/
private theorem run_2mul_on_5 :
    runOps [.opcode "OP_2MUL"]
        ({ stack := [Value.vBigint 5] } : StackState)
      = .ok ({ stack := [Value.vBigint 10] } : StackState) := by
  rw [runOps_cons_nonIf_eq (.opcode "OP_2MUL") _ _
    (by intro _ _ h; exact StackOp.noConfusion h)]
  have hStep : stepNonIf (.opcode "OP_2MUL")
      ({ stack := [Value.vBigint 5] } : StackState)
      = .ok ({ stack := [Value.vBigint 10] } : StackState) := by
    rw [stepNonIf_opcode]; rfl
  rw [hStep]
  simp only [runOps_nil]

/-- Concrete 3-method branch-2 selection: the parsed dispatch chain with
witness `2` on `[2, 5]` selects the last body `OP_2MUL` → `[10]`.
Exercises a non-matching head skip (index 0) plus the last-method
verify match (index 2). Confirms `dispatchN_select_branch` is not
vacuous for `k ≠ 0`. -/
theorem dispatchN_select_branch2_smoke :
    runOps
        (dispatchChainOps 0
          [[.opcode "OP_1ADD"], [.opcode "OP_NEGATE"], [.opcode "OP_2MUL"]])
        ({ stack := [Value.vBigint (Int.ofNat 2), Value.vBigint 5] } : StackState)
      = .ok ({ stack := [Value.vBigint 10] } : StackState) := by
  rw [dispatchN_select_branch
        [[.opcode "OP_1ADD"], [.opcode "OP_NEGATE"], [.opcode "OP_2MUL"]]
        0 2 [.opcode "OP_2MUL"]
        ({ stack := [Value.vBigint (Int.ofNat 2), Value.vBigint 5] } : StackState)
        [Value.vBigint 5] rfl (by simp)]
  exact run_2mul_on_5

/-- Concrete 3-method branch-0 selection: witness `0` on `[0, 5]` selects
the first body `OP_1ADD` → `[6]`. Exercises the matching non-last head
(`k = 0` with a non-empty ELSE chain). -/
theorem dispatchN_select_branch0_n3_smoke :
    runOps
        (dispatchChainOps 0
          [[.opcode "OP_1ADD"], [.opcode "OP_NEGATE"], [.opcode "OP_2MUL"]])
        ({ stack := [Value.vBigint (Int.ofNat 0), Value.vBigint 5] } : StackState)
      = .ok ({ stack := [Value.vBigint 6] } : StackState) := by
  rw [dispatchN_select_branch
        [[.opcode "OP_1ADD"], [.opcode "OP_NEGATE"], [.opcode "OP_2MUL"]]
        0 0 [.opcode "OP_1ADD"]
        ({ stack := [Value.vBigint (Int.ofNat 0), Value.vBigint 5] } : StackState)
        [Value.vBigint 5] rfl rfl]
  rw [runOps_cons_nonIf_eq (.opcode "OP_1ADD") _ _
    (by intro _ _ h; exact StackOp.noConfusion h)]
  have hStep : stepNonIf (.opcode "OP_1ADD")
      ({ stack := [Value.vBigint 5] } : StackState)
      = .ok ({ stack := [Value.vBigint 6] } : StackState) := by
    rw [stepNonIf_opcode]; rfl
  rw [hStep]
  simp only [runOps_nil]

/-! ## Deliverable 3 — selection for the *parser-output* op shape

`Script.Parse.dispatchReconL` (the exact op-list the real `parseScript`
reconstructs) is byte-for-byte the same cascade as `dispatchChainOps`
EXCEPT the IF-then body uses the short-form `.drop` (parser byte `0x75`)
instead of `.opcode "OP_DROP"`. Both run `applyDrop` under `runOps`, so
the two op-lists are *operationally equal*.

`dispatchReconOps` below mirrors `dispatchReconL` exactly (it is defeq to
it — same constructor shape — so a Pipeline-level wave that sees both
files can bridge them by `rfl`). We prove its branch-`k` selection here
by reducing to `dispatchN_select_branch` through the `.drop`/`OP_DROP`
congruence. This is the `runOps`-side of the
`hDispatchToOps` obligation the capstone needs; the only remaining step
(BLOCKED here — needs a file importing both `Parse` and `AgreesD1`) is
`dispatchReconL = dispatchReconOps` (`rfl`) glued to Deliverable 2's
`parseScript … = .ok (dispatchReconL …)`. -/

/-- Parser-output mirror of `dispatchChainOps`: identical cascade but with
the short-form `.drop` in the IF-then body (matching
`Script.Parse.dispatchReconL`). -/
def dispatchReconOps (i : Nat) : List (List StackOp) → List StackOp
  | []        => []
  | [body]    =>
      .push (.bigint (Int.ofNat i))
        :: .opcode "OP_NUMEQUALVERIFY"
        :: body
  | body :: rest =>
      [ .dup,
        .push (.bigint (Int.ofNat i)),
        .opcode "OP_NUMEQUAL",
        .ifOp (.drop :: body)
          (some (dispatchReconOps (i + 1) rest)) ]

/-- `OP_DROP` (opcode form) and `.drop` (short form) step identically:
both run `applyDrop`, so `runOps` of the two thn-bodies agrees. -/
private theorem runOps_drop_cons_eq_OP_DROP_cons
    (body : List StackOp) (s : StackState) :
    runOps (.drop :: body) s = runOps (.opcode "OP_DROP" :: body) s := by
  rw [runOps_cons_nonIf_eq .drop _ _ (by intro _ _ h; exact StackOp.noConfusion h)]
  rw [runOps_cons_nonIf_eq (.opcode "OP_DROP") _ _ dropOp_not_if]
  rw [stepNonIf_drop]
  have hOpcode : stepNonIf (.opcode "OP_DROP") s = applyDrop s := by
    rw [stepNonIf_opcode]; rfl
  rw [hOpcode]

/-- IF-frame congruence: if two then-bodies and two else-bodies agree
under `runOps` (pointwise), the single-`.ifOp` op-lists agree. -/
private theorem runOps_ifOp_some_cong
    (thn1 thn2 els1 els2 : List StackOp) (s : StackState)
    (hThn : ∀ t, runOps thn1 t = runOps thn2 t)
    (hEls : ∀ t, runOps els1 t = runOps els2 t) :
    runOps [.ifOp thn1 (some els1)] s = runOps [.ifOp thn2 (some els2)] s := by
  rw [runOps, runOps]
  cases hp : s.pop? with
  | none => simp only [hp]
  | some vs =>
      obtain ⟨v, s'⟩ := vs
      simp only [hp]
      cases hb : asBool? v with
      | none => simp only [hb]
      | some b =>
          cases b with
          | true =>
              simp only [hb]
              rw [hThn s']
          | false =>
              simp only [hb]
              rw [hEls s']

/-- **Congruence: the parser-output cascade runs exactly like
`dispatchChainOps`.** Induction on `bodies`; the singleton case is
definitionally identical, the cons-cons case differs only in the IF
then-body (`.drop` vs `OP_DROP`, equal by
`runOps_drop_cons_eq_OP_DROP_cons`) and recurses on the ELSE chain. -/
theorem runOps_dispatchReconOps_eq_dispatchChainOps :
    ∀ (bodies : List (List StackOp)) (i : Nat) (s : StackState),
      runOps (dispatchReconOps i bodies) s = runOps (dispatchChainOps i bodies) s := by
  intro bodies
  induction bodies with
  | nil => intro i s; rfl
  | cons body rest ih =>
      intro i s
      cases rest with
      | nil => rfl
      | cons body' rest' =>
          show runOps [StackOp.dup, .push (.bigint (Int.ofNat i)), .opcode "OP_NUMEQUAL",
              .ifOp (.drop :: body) (some (dispatchReconOps (i + 1) (body' :: rest')))] s
            = runOps [StackOp.dup, .push (.bigint (Int.ofNat i)), .opcode "OP_NUMEQUAL",
                .ifOp (.opcode "OP_DROP" :: body)
                  (some (dispatchChainOps (i + 1) (body' :: rest')))] s
          rw [show [StackOp.dup, .push (.bigint (Int.ofNat i)), .opcode "OP_NUMEQUAL",
                .ifOp (.drop :: body)
                  (some (dispatchReconOps (i + 1) (body' :: rest')))]
                = [StackOp.dup, .push (.bigint (Int.ofNat i)), .opcode "OP_NUMEQUAL"]
                    ++ [.ifOp (.drop :: body)
                        (some (dispatchReconOps (i + 1) (body' :: rest')))] from rfl]
          rw [show [StackOp.dup, .push (.bigint (Int.ofNat i)), .opcode "OP_NUMEQUAL",
                .ifOp (.opcode "OP_DROP" :: body)
                  (some (dispatchChainOps (i + 1) (body' :: rest')))]
                = [StackOp.dup, .push (.bigint (Int.ofNat i)), .opcode "OP_NUMEQUAL"]
                    ++ [.ifOp (.opcode "OP_DROP" :: body)
                        (some (dispatchChainOps (i + 1) (body' :: rest')))] from rfl]
          rw [runOps_append, runOps_append]
          cases runOps [StackOp.dup, .push (.bigint (Int.ofNat i)),
              .opcode "OP_NUMEQUAL"] s with
          | error e => rfl
          | ok s' =>
              simp only []
              exact runOps_ifOp_some_cong _ _ _ _ s'
                (fun t => runOps_drop_cons_eq_OP_DROP_cons body t)
                (fun t => ih (i + 1) t)

/-- **Deliverable 3 (substrate) — branch-`k` selection for the parser
output.** For the `dispatchReconOps` cascade (the exact op shape
`Script.Parse.dispatchReconL` produces), witness `w = i + k` selects
`bodies[k]` and discards the witness. Proven from the congruence above
plus `dispatchN_select_branch`. -/
theorem dispatchReconOps_select_branch
    (bodies : List (List StackOp)) (i k : Nat) (body : List StackOp)
    (initial : StackState) (rest : List Value)
    (hIdx : bodies[k]? = some body)
    (hWitness : initial.stack = Value.vBigint (Int.ofNat (i + k)) :: rest) :
    runOps (dispatchReconOps i bodies) initial
      = runOps body { initial with stack := rest } := by
  rw [runOps_dispatchReconOps_eq_dispatchChainOps bodies i initial]
  exact dispatchN_select_branch bodies i k body initial rest hIdx hWitness

/-! ### Deliverable 3 smokes — selection on the parser-output cascade -/

/-- n=3 branch-2 selection on `dispatchReconOps` (the `.drop`-form
cascade): witness `2` on `[2, 5]` selects `OP_2MUL` → `[10]`. Mirrors the
`dispatchChainOps` smoke; confirms the parser-output selection is not
vacuous. -/
theorem dispatchReconOps_select_branch2_smoke :
    runOps
        (dispatchReconOps 0
          [[.opcode "OP_1ADD"], [.opcode "OP_NEGATE"], [.opcode "OP_2MUL"]])
        ({ stack := [Value.vBigint (Int.ofNat 2), Value.vBigint 5] } : StackState)
      = .ok ({ stack := [Value.vBigint 10] } : StackState) := by
  rw [dispatchReconOps_select_branch
        [[.opcode "OP_1ADD"], [.opcode "OP_NEGATE"], [.opcode "OP_2MUL"]]
        0 2 [.opcode "OP_2MUL"]
        ({ stack := [Value.vBigint (Int.ofNat 2), Value.vBigint 5] } : StackState)
        [Value.vBigint 5] rfl (by simp)]
  exact run_2mul_on_5

/-- n=2 branch-0 selection on `dispatchReconOps`: witness `0` on `[0, 5]`
selects the first body `OP_1ADD` → `[6]`. Exercises the matching non-last
head whose thn uses the short-form `.drop`. -/
theorem dispatchReconOps_select_branch0_n2_smoke :
    runOps
        (dispatchReconOps 0 [[.opcode "OP_1ADD"], [.opcode "OP_2MUL"]])
        ({ stack := [Value.vBigint (Int.ofNat 0), Value.vBigint 5] } : StackState)
      = .ok ({ stack := [Value.vBigint 6] } : StackState) := by
  rw [dispatchReconOps_select_branch
        [[.opcode "OP_1ADD"], [.opcode "OP_2MUL"]]
        0 0 [.opcode "OP_1ADD"]
        ({ stack := [Value.vBigint (Int.ofNat 0), Value.vBigint 5] } : StackState)
        [Value.vBigint 5] rfl rfl]
  rw [runOps_cons_nonIf_eq (.opcode "OP_1ADD") _ _
    (by intro _ _ h; exact StackOp.noConfusion h)]
  have hStep : stepNonIf (.opcode "OP_1ADD")
      ({ stack := [Value.vBigint 5] } : StackState)
      = .ok ({ stack := [Value.vBigint 6] } : StackState) := by
    rw [stepNonIf_opcode]; rfl
  rw [hStep]
  simp only [runOps_nil]

end AgreesD1
end Stack
end RunarVerification
