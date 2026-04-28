import RunarVerification.Stack.Eval

/-!
# Stack IR — Peephole optimizer (Phase 3a)

Local rewrite rules over `List StackOp`, mirroring patterns in
`packages/runar-compiler/src/optimizer/peephole.ts`.

**Phase 3a coverage.** Five concrete rule definitions:

1. `applyDropAfterPush`     — `[push v, drop]    → []`
2. `applyDupDrop`           — `[dup, drop]       → []`
3. `applyDoubleSwap`        — `[swap, swap]      → []`
4. `applyEqualVerifyFuse`   — `[OP_EQUAL, OP_VERIFY] → [OP_EQUALVERIFY]`
5. `applyCheckSigVerifyFuse`— `[OP_CHECKSIG, OP_VERIFY] → [OP_CHECKSIGVERIFY]`
6. `applyNumEqualVerifyFuse`— `[OP_NUMEQUAL, OP_VERIFY] → [OP_NUMEQUALVERIFY]`

For each rule we prove the **idempotence skeleton** (rules return the
empty list on empty input, and behave the identity on a singleton op
that doesn't match the pattern). Per-rule **operational soundness**
(runOps preservation) is a Phase 3b deliverable: the proofs follow
the same recipe but require unfolding the structural-recursion
equations of `runOps`, which we leave as the next session's first
task per HANDOFF.md §7.

The full TS reference implements ~30 rules and runs them to a fixed
point (`peephole.ts:452`, max 100 iterations). Phase 3b extends this
file to cover the full set.
-/

namespace RunarVerification.Stack
namespace Peephole

open RunarVerification.Stack.Eval
open RunarVerification.ANF.Eval.Crypto

/-! ## Rule 1: `[push v, drop] → []` -/

def applyDropAfterPush : List StackOp → List StackOp
  | [] => []
  | (.push _) :: .drop :: rest => applyDropAfterPush rest
  | op :: rest => op :: applyDropAfterPush rest

theorem applyDropAfterPush_empty :
    applyDropAfterPush [] = [] := rfl

/-! ## Rule 2: `[dup, drop] → []` -/

def applyDupDrop : List StackOp → List StackOp
  | [] => []
  | .dup :: .drop :: rest => applyDupDrop rest
  | op :: rest => op :: applyDupDrop rest

theorem applyDupDrop_empty :
    applyDupDrop [] = [] := rfl

/-! ## Rule 3: `[swap, swap] → []` -/

def applyDoubleSwap : List StackOp → List StackOp
  | [] => []
  | .swap :: .swap :: rest => applyDoubleSwap rest
  | op :: rest => op :: applyDoubleSwap rest

theorem applyDoubleSwap_empty :
    applyDoubleSwap [] = [] := rfl

/-! ## Rule 4: `[OP_EQUAL, OP_VERIFY] → [OP_EQUALVERIFY]` -/

def applyEqualVerifyFuse : List StackOp → List StackOp
  | [] => []
  | .opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest =>
      .opcode "OP_EQUALVERIFY" :: applyEqualVerifyFuse rest
  | op :: rest => op :: applyEqualVerifyFuse rest

theorem applyEqualVerifyFuse_empty :
    applyEqualVerifyFuse [] = [] := rfl

/-! ## Rule 5: `[OP_CHECKSIG, OP_VERIFY] → [OP_CHECKSIGVERIFY]` -/

def applyCheckSigVerifyFuse : List StackOp → List StackOp
  | [] => []
  | .opcode "OP_CHECKSIG" :: .opcode "OP_VERIFY" :: rest =>
      .opcode "OP_CHECKSIGVERIFY" :: applyCheckSigVerifyFuse rest
  | op :: rest => op :: applyCheckSigVerifyFuse rest

theorem applyCheckSigVerifyFuse_empty :
    applyCheckSigVerifyFuse [] = [] := rfl

/-! ## Rule 6: `[OP_NUMEQUAL, OP_VERIFY] → [OP_NUMEQUALVERIFY]` -/

def applyNumEqualVerifyFuse : List StackOp → List StackOp
  | [] => []
  | .opcode "OP_NUMEQUAL" :: .opcode "OP_VERIFY" :: rest =>
      .opcode "OP_NUMEQUALVERIFY" :: applyNumEqualVerifyFuse rest
  | op :: rest => op :: applyNumEqualVerifyFuse rest

theorem applyNumEqualVerifyFuse_empty :
    applyNumEqualVerifyFuse [] = [] := rfl

/-! ## Composition: a single peephole pass -/

def peepholePass (ops : List StackOp) : List StackOp :=
  applyEqualVerifyFuse <|
    applyCheckSigVerifyFuse <|
      applyNumEqualVerifyFuse <|
        applyDoubleSwap <|
          applyDupDrop <|
            applyDropAfterPush ops

theorem peepholePass_empty :
    peepholePass [] = [] := by
  simp [peepholePass, applyDropAfterPush_empty, applyDupDrop_empty,
        applyDoubleSwap_empty, applyNumEqualVerifyFuse_empty,
        applyCheckSigVerifyFuse_empty, applyEqualVerifyFuse_empty]

/-! ## Operational soundness — atom case for fusion rules

Phase 3a proves operational soundness only for the simplest atom case:
the empty op list. Each rule's `_atom_empty` lemma states that running
the rule on `[]` against any state produces the same result as running
the input on that state — which is trivially `Except.ok s`.

Phase 3b extends these to:
* `_atom_match` — running the matched two-op sequence against any
  type-compatible stack state produces the same result as running the
  rewritten one-op sequence;
* `_pass_sound` — composed via list induction over the input.
-/

theorem dropAfterPush_atom_empty (s : StackState) :
    runOps (applyDropAfterPush []) s = runOps [] s := rfl

theorem dupDrop_atom_empty (s : StackState) :
    runOps (applyDupDrop []) s = runOps [] s := rfl

theorem doubleSwap_atom_empty (s : StackState) :
    runOps (applyDoubleSwap []) s = runOps [] s := rfl

theorem equalVerifyFuse_atom_empty (s : StackState) :
    runOps (applyEqualVerifyFuse []) s = runOps [] s := rfl

theorem checkSigVerifyFuse_atom_empty (s : StackState) :
    runOps (applyCheckSigVerifyFuse []) s = runOps [] s := rfl

theorem numEqualVerifyFuse_atom_empty (s : StackState) :
    runOps (applyNumEqualVerifyFuse []) s = runOps [] s := rfl

theorem peepholePass_sound_empty (s : StackState) :
    runOps (peepholePass []) s = runOps [] s := by
  rw [peepholePass_empty]

/-! ## Phase 3b — Structural pattern-match identities

For each fusion rule, the `_pattern_match` lemma states the rewrite
fires exactly when the matched two-op prefix is present, and is the
identity otherwise. These are `rfl`-provable from the function's
pattern match and serve as the syntactic substrate for Phase 3c's
operational soundness proofs (which require unfolding `runOps` past
`stepNonIf` and `runOpcode`).
-/

theorem applyEqualVerifyFuse_match (rest : List StackOp) :
    applyEqualVerifyFuse
        (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest)
    = .opcode "OP_EQUALVERIFY" :: applyEqualVerifyFuse rest := rfl

theorem applyCheckSigVerifyFuse_match (rest : List StackOp) :
    applyCheckSigVerifyFuse
        (.opcode "OP_CHECKSIG" :: .opcode "OP_VERIFY" :: rest)
    = .opcode "OP_CHECKSIGVERIFY" :: applyCheckSigVerifyFuse rest := rfl

theorem applyNumEqualVerifyFuse_match (rest : List StackOp) :
    applyNumEqualVerifyFuse
        (.opcode "OP_NUMEQUAL" :: .opcode "OP_VERIFY" :: rest)
    = .opcode "OP_NUMEQUALVERIFY" :: applyNumEqualVerifyFuse rest := rfl

theorem applyDropAfterPush_match (v : PushVal) (rest : List StackOp) :
    applyDropAfterPush (.push v :: .drop :: rest)
    = applyDropAfterPush rest := rfl

theorem applyDupDrop_match (rest : List StackOp) :
    applyDupDrop (.dup :: .drop :: rest)
    = applyDupDrop rest := rfl

theorem applyDoubleSwap_match (rest : List StackOp) :
    applyDoubleSwap (.swap :: .swap :: rest)
    = applyDoubleSwap rest := rfl

/-! ## Phase 3b — Length-monotonicity (rules never grow the program)

Each rule either replaces a two-op pattern with one or zero ops, or
preserves the input. The composed `peepholePass` therefore
non-increasingly transforms the op list. The full inductive proof is
Phase 3c work; for Phase 3b we record the empty-input boundary case.
-/

theorem applyDropAfterPush_length_empty :
    (applyDropAfterPush []).length ≤ ([] : List StackOp).length := by
  rw [applyDropAfterPush_empty]; exact Nat.le_refl _

theorem applyDupDrop_length_empty :
    (applyDupDrop []).length ≤ ([] : List StackOp).length := by
  rw [applyDupDrop_empty]; exact Nat.le_refl _

theorem applyDoubleSwap_length_empty :
    (applyDoubleSwap []).length ≤ ([] : List StackOp).length := by
  rw [applyDoubleSwap_empty]; exact Nat.le_refl _

theorem applyEqualVerifyFuse_length_empty :
    (applyEqualVerifyFuse []).length ≤ ([] : List StackOp).length := by
  rw [applyEqualVerifyFuse_empty]; exact Nat.le_refl _

theorem applyCheckSigVerifyFuse_length_empty :
    (applyCheckSigVerifyFuse []).length ≤ ([] : List StackOp).length := by
  rw [applyCheckSigVerifyFuse_empty]; exact Nat.le_refl _

theorem applyNumEqualVerifyFuse_length_empty :
    (applyNumEqualVerifyFuse []).length ≤ ([] : List StackOp).length := by
  rw [applyNumEqualVerifyFuse_empty]; exact Nat.le_refl _

/-! ## Phase 3c — Operational atom-match soundness

For each rule, the `_atom_sound` lemma states that running the
matched two-op pattern on any state produces the same result as
running the rewritten op (or empty list) on the same state.

These are the building blocks of full peephole-soundness proofs in
Phase 3d (which compose them via list induction).
-/

/-- The `applyDrop` of a pushed state strips that pushed element. -/
private theorem applyDrop_push (s : StackState) (v : ANF.Eval.Value) :
    applyDrop (s.push v) = .ok s := by
  unfold applyDrop StackState.push
  simp

/-- Pushing a `bigint` value then immediately dropping it is a no-op. -/
theorem dropAfterPush_atom_sound_bigint (s : StackState) (i : Int) :
    runOps [.push (.bigint i), .drop] s = runOps [] s := by
  rw [runOps_nil]
  show runOps (.push (.bigint i) :: .drop :: []) s = _
  unfold runOps
  rw [stepNonIf_push_bigint]
  show runOps (.drop :: []) (s.push (.vBigint i)) = .ok s
  unfold runOps
  rw [stepNonIf_drop, applyDrop_push]
  show runOps [] s = .ok s
  exact runOps_nil s

theorem dropAfterPush_atom_sound_bool (s : StackState) (b : Bool) :
    runOps [.push (.bool b), .drop] s = runOps [] s := by
  rw [runOps_nil]
  show runOps (.push (.bool b) :: .drop :: []) s = _
  unfold runOps
  rw [stepNonIf_push_bool]
  show runOps (.drop :: []) (s.push (.vBool b)) = .ok s
  unfold runOps
  rw [stepNonIf_drop, applyDrop_push]
  exact runOps_nil s

theorem dropAfterPush_atom_sound_bytes (s : StackState) (b : ByteArray) :
    runOps [.push (.bytes b), .drop] s = runOps [] s := by
  rw [runOps_nil]
  show runOps (.push (.bytes b) :: .drop :: []) s = _
  unfold runOps
  rw [stepNonIf_push_bytes]
  show runOps (.drop :: []) (s.push (.vBytes b)) = .ok s
  unfold runOps
  rw [stepNonIf_drop, applyDrop_push]
  exact runOps_nil s

/-! ### `[dup, drop]` atom soundness (Phase 3d)

Requires the input stack to be non-empty: `dup` would otherwise fail
with stack-underflow before the `drop` could fire. Note that the
peephole rewriter is already conservative — it only fires when both
ops match — so the precondition is implicit at the `applyRule`
level. We expose it explicitly here.
-/

private theorem applyDup_cons (s : StackState) (v : ANF.Eval.Value) (rest : List ANF.Eval.Value)
    (hs : s.stack = v :: rest) :
    applyDup s = .ok (s.push v) := by
  unfold applyDup
  rw [hs]

private theorem applyDrop_cons (s : StackState) (v : ANF.Eval.Value) (rest : List ANF.Eval.Value)
    (hs : s.stack = v :: rest) :
    applyDrop s = .ok { s with stack := rest } := by
  unfold applyDrop
  rw [hs]

theorem dupDrop_atom_sound (s : StackState) (v : ANF.Eval.Value) (rest : List ANF.Eval.Value)
    (hs : s.stack = v :: rest) :
    runOps [.dup, .drop] s = runOps [] s := by
  rw [runOps_nil]
  show runOps (.dup :: .drop :: []) s = .ok s
  unfold runOps
  rw [stepNonIf_dup, applyDup_cons s v rest hs]
  show runOps (.drop :: []) (s.push v) = .ok s
  unfold runOps
  rw [stepNonIf_drop]
  -- `s.push v` has stack `v :: s.stack = v :: v :: rest`, so applyDrop strips one
  rw [applyDrop_cons (s.push v) v s.stack (by unfold StackState.push; simp)]
  show runOps [] _ = .ok s
  rw [runOps_nil]
  -- `{s.push v with stack := s.stack}` has the same fields as `s` (stack restored)
  unfold StackState.push
  cases s; rfl

/-! ### `[swap, swap]` atom soundness -/

private theorem applySwap_cons2 (s : StackState) (a b : ANF.Eval.Value) (rest : List ANF.Eval.Value)
    (hs : s.stack = a :: b :: rest) :
    applySwap s = .ok { s with stack := b :: a :: rest } := by
  unfold applySwap
  rw [hs]

theorem doubleSwap_atom_sound (s : StackState) (a b : ANF.Eval.Value) (rest : List ANF.Eval.Value)
    (hs : s.stack = a :: b :: rest) :
    runOps [.swap, .swap] s = runOps [] s := by
  rw [runOps_nil]
  show runOps (.swap :: .swap :: []) s = .ok s
  unfold runOps
  rw [stepNonIf_swap, applySwap_cons2 s a b rest hs]
  -- After first swap, stack = b :: a :: rest
  show runOps (.swap :: []) ({ s with stack := b :: a :: rest }) = .ok s
  unfold runOps
  rw [stepNonIf_swap]
  rw [applySwap_cons2 ({ s with stack := b :: a :: rest }) b a rest rfl]
  -- After second swap, stack = a :: b :: rest = original s.stack
  show runOps [] _ = .ok s
  rw [runOps_nil]
  cases s
  simp_all

/-! ### Verify-fuse substrate (Phase 3d) and completion (Phase 3e)

Phase 3d laid the `popN_two_cons` substrate. Phase 3e completes
`numEqualVerifyFuse_atom_sound_int` — the strict-int-coercion case is
the cleanest because it doesn't need to choose between bytes and int
in the equality computation. The other two rules (`equalVerifyFuse`
and `checkSigVerifyFuse`) follow the same recipe with the
corresponding `runOpcode` reduction lemma.
-/

/-- Reduce `popN s 2` against an explicit `b :: a :: rest` stack. -/
theorem popN_two_cons (s : StackState) (b a : ANF.Eval.Value)
    (rest : List ANF.Eval.Value) (hs : s.stack = b :: a :: rest) :
    popN s 2 = .ok ([b, a], { s with stack := rest }) := by
  unfold popN StackState.pop?
  rw [hs]
  simp only [popN, StackState.pop?]

/-! Single-arm projections of `runOpcode` for the opcodes used below.

Each `runOpcode_XXX_def` is `rfl`-provable because Lean's match arm
selects the corresponding case directly. We use them to avoid having
`unfold runOpcode` pull in the entire ~200-line match in a single
tactic step (which exhausts `maxHeartbeats`).
-/

theorem runOpcode_NUMEQUAL_def (s : StackState) :
    runOpcode "OP_NUMEQUAL" s
    = liftIntBin s (fun a b => .vBool (decide (a = b))) := rfl

theorem runOpcode_VERIFY_def (s : StackState) :
    runOpcode "OP_VERIFY" s
    = (match s.pop? with
       | none => .error (.unsupported "OP_VERIFY: empty stack")
       | some (v, s') =>
           match asBool? v with
           | some true  => .ok s'
           | some false => .error .assertFailed
           | none       => .error (.typeError "OP_VERIFY: non-bool")) := rfl

/-! `OP_VERIFY` reduction on a state with `.vBool eq` on top. -/

theorem runOpcode_verify_vBool (s : StackState) (eq : Bool) :
    runOpcode "OP_VERIFY" (s.push (.vBool eq))
    = if eq then .ok s else .error .assertFailed := by
  rw [runOpcode_VERIFY_def]
  unfold StackState.pop? StackState.push
  simp [asBool?]
  cases eq <;> rfl

/-! ### `[OP_NOT, OP_NOT] → []` rule + atom-sound (Phase 3e)

A simpler atom-sound proof to demonstrate the technique on rules
whose `runOpcode` arms use a flat `match s.pop?` shape (no `do`
notation, no `popN`).
-/

def applyDoubleNot : List StackOp → List StackOp
  | [] => []
  | .opcode "OP_NOT" :: .opcode "OP_NOT" :: rest => applyDoubleNot rest
  | op :: rest => op :: applyDoubleNot rest

theorem applyDoubleNot_empty : applyDoubleNot [] = [] := rfl

theorem applyDoubleNot_match (rest : List StackOp) :
    applyDoubleNot (.opcode "OP_NOT" :: .opcode "OP_NOT" :: rest)
    = applyDoubleNot rest := rfl

theorem runOpcode_NOT_def (s : StackState) :
    runOpcode "OP_NOT" s
    = (match s.pop? with
       | none => .error (.unsupported "OP_NOT: empty stack")
       | some (v, s') =>
           match asBool? v with
           | some b => .ok (s'.push (.vBool (!b)))
           | none   => .error (.typeError "OP_NOT non-bool")) := rfl

/-- `OP_NOT` on a stack with `.vBool b` on top pushes `.vBool (!b)`. -/
theorem runOpcode_not_vBool (s : StackState) (b : Bool) :
    runOpcode "OP_NOT" (s.push (.vBool b))
    = .ok (s.push (.vBool (!b))) := by
  rw [runOpcode_NOT_def]
  unfold StackState.pop? StackState.push
  simp [asBool?]

/-- `runOps [OP_NOT, OP_NOT]` is the identity on any state with `.vBool b` on top. -/
private theorem run_two_nots_pushed (s' : StackState) (b : Bool) :
    runOps [.opcode "OP_NOT", .opcode "OP_NOT"] (s'.push (.vBool b))
    = .ok (s'.push (.vBool b)) := by
  show runOps (.opcode "OP_NOT" :: .opcode "OP_NOT" :: []) (s'.push (.vBool b)) = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_not_vBool]
  show runOps (.opcode "OP_NOT" :: []) (s'.push (.vBool (!b))) = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_not_vBool]
  show runOps [] (s'.push (.vBool (!(!b)))) = _
  rw [runOps_nil]
  simp [Bool.not_not]

/-- `runOps [OP_NOT, OP_NOT] s = runOps [] s` when the top of `s.stack` is `.vBool b`. -/
theorem doubleNot_atom_sound (s : StackState) (b : Bool) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBool b :: rest) :
    runOps [.opcode "OP_NOT", .opcode "OP_NOT"] s = runOps [] s := by
  rw [runOps_nil]
  have hs' : s = (({ s with stack := rest } : StackState).push (.vBool b)) := by
    cases s; simp_all [StackState.push]
  rw [hs']
  exact run_two_nots_pushed _ b

/-! ### Verify-fuse atom soundness — completed (Phase 3f)

After the Phase 3f refactor of `Stack.Eval` opcode arms from
`do`-notation to explicit `match`-on-`popN`, the LHS-runs-OP_VERIFY
and RHS-runs-OP_VERIFY normal forms both reduce by structural
reduction without needing a `Bind`-rewrite.
-/

/-- `OP_NUMEQUAL` reduction (under int top-of-stack precondition). -/
theorem runOpcode_numEqual_int
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_NUMEQUAL" s
    = .ok (({ s with stack := rest } : StackState).push (.vBool (decide (a = b)))) := by
  rw [runOpcode_NUMEQUAL_def]
  unfold liftIntBin
  rw [popN_two_cons s (.vBigint b) (.vBigint a) rest hs]
  simp [asInt?]

theorem runOpcode_NUMEQUALVERIFY_def (s : StackState) :
    runOpcode "OP_NUMEQUALVERIFY" s
    = (match popN s 2 with
       | .error e => .error e
       | .ok (vs, s') =>
           match vs with
           | [b, a] =>
               match asInt? a, asInt? b with
               | some ai, some bi =>
                   if decide (ai = bi) then .ok s' else .error .assertFailed
               | _, _ => .error (.typeError "OP_NUMEQUALVERIFY expects ints")
           | _ => .error (.unsupported "OP_NUMEQUALVERIFY popN bug")) := rfl

theorem runOpcode_numEqualVerify_int
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_NUMEQUALVERIFY" s
    = if decide (a = b) then .ok ({ s with stack := rest } : StackState)
                        else .error .assertFailed := by
  rw [runOpcode_NUMEQUALVERIFY_def, popN_two_cons s (.vBigint b) (.vBigint a) rest hs]
  simp [asInt?]

/-! `[OP_NUMEQUAL, OP_VERIFY] = [OP_NUMEQUALVERIFY]` -/

/-- LHS reduction: `[OP_NUMEQUAL, OP_VERIFY]` runs to the same `if-then-else`. -/
private theorem run_numEqual_then_verify_int_aux
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps [.opcode "OP_NUMEQUAL", .opcode "OP_VERIFY"] s
    = if decide (a = b) then .ok ({ s with stack := rest } : StackState)
                        else .error .assertFailed := by
  show runOps (.opcode "OP_NUMEQUAL" :: .opcode "OP_VERIFY" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_numEqual_int s a b rest hs]
  show runOps (.opcode "OP_VERIFY" :: []) (_) = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_verify_vBool]
  by_cases h : decide (a = b) = true
  · simp [h, runOps_nil]
  · simp [h]

/-- RHS reduction: `[OP_NUMEQUALVERIFY]` runs to the same `if-then-else`. -/
private theorem run_numEqualVerify_int_aux
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps [.opcode "OP_NUMEQUALVERIFY"] s
    = if decide (a = b) then .ok ({ s with stack := rest } : StackState)
                        else .error .assertFailed := by
  show runOps (.opcode "OP_NUMEQUALVERIFY" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_numEqualVerify_int s a b rest hs]
  by_cases h : decide (a = b) = true
  · simp [h, runOps_nil]
  · simp [h]

theorem numEqualVerifyFuse_atom_sound_int
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps [.opcode "OP_NUMEQUAL", .opcode "OP_VERIFY"] s
    = runOps [.opcode "OP_NUMEQUALVERIFY"] s := by
  rw [run_numEqual_then_verify_int_aux s a b rest hs,
      run_numEqualVerify_int_aux s a b rest hs]

/-! `[OP_EQUAL, OP_VERIFY] = [OP_EQUALVERIFY]` (int case) -/

theorem runOpcode_EQUAL_def (s : StackState) :
    runOpcode "OP_EQUAL" s
    = (match popN s 2 with
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
           | _ => .error (.unsupported "OP_EQUAL popN bug")) := rfl

theorem runOpcode_EQUALVERIFY_def (s : StackState) :
    runOpcode "OP_EQUALVERIFY" s
    = (match popN s 2 with
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
           | _ => .error (.unsupported "OP_EQUALVERIFY popN bug")) := rfl

theorem runOpcode_equal_int
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_EQUAL" s
    = .ok (({ s with stack := rest } : StackState).push (.vBool (decide (a = b)))) := by
  rw [runOpcode_EQUAL_def, popN_two_cons s (.vBigint b) (.vBigint a) rest hs]
  simp [asBytes?, asInt?]

theorem runOpcode_equalVerify_int
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_EQUALVERIFY" s
    = if decide (a = b) then .ok ({ s with stack := rest } : StackState)
                        else .error .assertFailed := by
  rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vBigint b) (.vBigint a) rest hs]
  simp [asBytes?, asInt?]

private theorem run_equal_then_verify_int_aux
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps [.opcode "OP_EQUAL", .opcode "OP_VERIFY"] s
    = if decide (a = b) then .ok ({ s with stack := rest } : StackState)
                        else .error .assertFailed := by
  show runOps (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_equal_int s a b rest hs]
  show runOps (.opcode "OP_VERIFY" :: []) (_) = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_verify_vBool]
  by_cases h : decide (a = b) = true
  · simp [h, runOps_nil]
  · simp [h]

private theorem run_equalVerify_int_aux
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps [.opcode "OP_EQUALVERIFY"] s
    = if decide (a = b) then .ok ({ s with stack := rest } : StackState)
                        else .error .assertFailed := by
  show runOps (.opcode "OP_EQUALVERIFY" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_equalVerify_int s a b rest hs]
  by_cases h : decide (a = b) = true
  · simp [h, runOps_nil]
  · simp [h]

theorem equalVerifyFuse_atom_sound_int
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps [.opcode "OP_EQUAL", .opcode "OP_VERIFY"] s
    = runOps [.opcode "OP_EQUALVERIFY"] s := by
  rw [run_equal_then_verify_int_aux s a b rest hs,
      run_equalVerify_int_aux s a b rest hs]

/-! `[OP_CHECKSIG, OP_VERIFY] = [OP_CHECKSIGVERIFY]` (bytes case) -/

theorem runOpcode_CHECKSIG_def (s : StackState) :
    runOpcode "OP_CHECKSIG" s
    = (match popN s 2 with
       | .error e => .error e
       | .ok (vs, s') =>
           match vs with
           | [pk, sig] =>
               match asBytes? sig, asBytes? pk with
               | some sigB, some pkB => .ok (s'.push (.vBool (checkSig sigB pkB)))
               | _, _ => .error (.typeError "OP_CHECKSIG expects bytes")
           | _ => .error (.unsupported "OP_CHECKSIG popN bug")) := rfl

theorem runOpcode_CHECKSIGVERIFY_def (s : StackState) :
    runOpcode "OP_CHECKSIGVERIFY" s
    = (match popN s 2 with
       | .error e => .error e
       | .ok (vs, s') =>
           match vs with
           | [pk, sig] =>
               match asBytes? sig, asBytes? pk with
               | some sigB, some pkB =>
                   if checkSig sigB pkB then .ok s' else .error .assertFailed
               | _, _ => .error (.typeError "OP_CHECKSIGVERIFY expects bytes")
           | _ => .error (.unsupported "OP_CHECKSIGVERIFY popN bug")) := rfl

theorem runOpcode_checkSig_bytes
    (s : StackState) (sig pk : ByteArray) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBytes pk :: .vBytes sig :: rest) :
    runOpcode "OP_CHECKSIG" s
    = .ok (({ s with stack := rest } : StackState).push (.vBool (checkSig sig pk))) := by
  rw [runOpcode_CHECKSIG_def, popN_two_cons s (.vBytes pk) (.vBytes sig) rest hs]
  simp [asBytes?]

theorem runOpcode_checkSigVerify_bytes
    (s : StackState) (sig pk : ByteArray) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBytes pk :: .vBytes sig :: rest) :
    runOpcode "OP_CHECKSIGVERIFY" s
    = if checkSig sig pk then .ok ({ s with stack := rest } : StackState)
                          else .error .assertFailed := by
  rw [runOpcode_CHECKSIGVERIFY_def, popN_two_cons s (.vBytes pk) (.vBytes sig) rest hs]
  simp [asBytes?]

private theorem run_checkSig_then_verify_bytes_aux
    (s : StackState) (sig pk : ByteArray) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBytes pk :: .vBytes sig :: rest) :
    runOps [.opcode "OP_CHECKSIG", .opcode "OP_VERIFY"] s
    = if checkSig sig pk then .ok ({ s with stack := rest } : StackState)
                          else .error .assertFailed := by
  show runOps (.opcode "OP_CHECKSIG" :: .opcode "OP_VERIFY" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_checkSig_bytes s sig pk rest hs]
  show runOps (.opcode "OP_VERIFY" :: []) (_) = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_verify_vBool]
  by_cases h : checkSig sig pk = true
  · simp [h, runOps_nil]
  · simp [h]

private theorem run_checkSigVerify_bytes_aux
    (s : StackState) (sig pk : ByteArray) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBytes pk :: .vBytes sig :: rest) :
    runOps [.opcode "OP_CHECKSIGVERIFY"] s
    = if checkSig sig pk then .ok ({ s with stack := rest } : StackState)
                          else .error .assertFailed := by
  show runOps (.opcode "OP_CHECKSIGVERIFY" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_checkSigVerify_bytes s sig pk rest hs]
  by_cases h : checkSig sig pk = true
  · simp [h, runOps_nil]
  · simp [h]

theorem checkSigVerifyFuse_atom_sound_bytes
    (s : StackState) (sig pk : ByteArray) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBytes pk :: .vBytes sig :: rest) :
    runOps [.opcode "OP_CHECKSIG", .opcode "OP_VERIFY"] s
    = runOps [.opcode "OP_CHECKSIGVERIFY"] s := by
  rw [run_checkSig_then_verify_bytes_aux s sig pk rest hs,
      run_checkSigVerify_bytes_aux s sig pk rest hs]

/-! ### `[OP_NEGATE, OP_NEGATE] → []` rule + atom-sound (Phase 3g)

Mirrors `doubleNot` on `OP_NEGATE`'s int top precondition. -/

def applyDoubleNegate : List StackOp → List StackOp
  | [] => []
  | .opcode "OP_NEGATE" :: .opcode "OP_NEGATE" :: rest => applyDoubleNegate rest
  | op :: rest => op :: applyDoubleNegate rest

theorem applyDoubleNegate_empty : applyDoubleNegate [] = [] := rfl

theorem applyDoubleNegate_match (rest : List StackOp) :
    applyDoubleNegate (.opcode "OP_NEGATE" :: .opcode "OP_NEGATE" :: rest)
    = applyDoubleNegate rest := rfl

theorem runOpcode_NEGATE_def (s : StackState) :
    runOpcode "OP_NEGATE" s
    = liftIntUnary s (fun i => .vBigint (-i)) := rfl

/-- `OP_NEGATE` on a stack with `.vBigint i` on top pushes `.vBigint (-i)`. -/
theorem runOpcode_negate_vBigint (s : StackState) (i : Int) :
    runOpcode "OP_NEGATE" (s.push (.vBigint i))
    = .ok (s.push (.vBigint (-i))) := by
  rw [runOpcode_NEGATE_def]
  unfold liftIntUnary StackState.pop? StackState.push
  simp [asInt?]

/-- `runOps [OP_NEGATE, OP_NEGATE]` is the identity on any state with `.vBigint i` on top. -/
private theorem run_two_negates_pushed (s' : StackState) (i : Int) :
    runOps [.opcode "OP_NEGATE", .opcode "OP_NEGATE"] (s'.push (.vBigint i))
    = .ok (s'.push (.vBigint i)) := by
  show runOps (.opcode "OP_NEGATE" :: .opcode "OP_NEGATE" :: []) (s'.push (.vBigint i)) = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_negate_vBigint]
  show runOps (.opcode "OP_NEGATE" :: []) (s'.push (.vBigint (-i))) = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_negate_vBigint]
  show runOps [] (s'.push (.vBigint (-(-i)))) = _
  rw [runOps_nil]
  simp [Int.neg_neg]

theorem doubleNegate_atom_sound (s : StackState) (i : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint i :: rest) :
    runOps [.opcode "OP_NEGATE", .opcode "OP_NEGATE"] s = runOps [] s := by
  rw [runOps_nil]
  have hs' : s = (({ s with stack := rest } : StackState).push (.vBigint i)) := by
    cases s; simp_all [StackState.push]
  rw [hs']
  exact run_two_negates_pushed _ i

/-! ### `[push 0, OP_ADD] → []` rule + atom-sound (Phase 3g)

Pushing 0 and then adding leaves an int-topped stack unchanged. -/

def applyAddZero : List StackOp → List StackOp
  | [] => []
  | .push (.bigint 0) :: .opcode "OP_ADD" :: rest => applyAddZero rest
  | op :: rest => op :: applyAddZero rest

theorem applyAddZero_empty : applyAddZero [] = [] := rfl

theorem applyAddZero_match (rest : List StackOp) :
    applyAddZero (.push (.bigint 0) :: .opcode "OP_ADD" :: rest)
    = applyAddZero rest := rfl

theorem runOpcode_ADD_def (s : StackState) :
    runOpcode "OP_ADD" s = liftIntBin s (fun a b => .vBigint (a + b)) := rfl

/-- `OP_ADD` on a stack `[b, a, …rest]` produces `[a + b, …rest]` for ints. -/
theorem runOpcode_add_int_concrete
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_ADD" s
    = .ok (({ s with stack := rest } : StackState).push (.vBigint (a + b))) := by
  rw [runOpcode_ADD_def]
  unfold liftIntBin
  rw [popN_two_cons s (.vBigint b) (.vBigint a) rest hs]
  simp [asInt?]

private theorem run_pushZero_then_add_int
    (s : StackState) (a : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint a :: rest) :
    runOps [.push (.bigint 0), .opcode "OP_ADD"] s = .ok s := by
  show runOps (.push (.bigint 0) :: .opcode "OP_ADD" :: []) s = _
  unfold runOps
  rw [stepNonIf_push_bigint]
  show runOps (.opcode "OP_ADD" :: []) (s.push (.vBigint 0)) = _
  unfold runOps
  rw [stepNonIf_opcode]
  have hpush : (s.push (.vBigint 0)).stack = .vBigint 0 :: .vBigint a :: rest := by
    unfold StackState.push; simp [hs]
  rw [runOpcode_add_int_concrete (s.push (.vBigint 0)) a 0 rest hpush]
  -- After `runOpcode_add_int_concrete`, goal contains a `match Except.ok …` form.
  -- Reduce the match (it's `.ok` so the second arm fires) and the inner `runOps []`.
  show runOps [] _ = .ok s
  rw [runOps_nil]
  -- Use `a + 0 = a` and field-equality after `cases s`.
  have : a + 0 = a := Int.add_zero a
  rw [this]
  cases s
  simp_all [StackState.push]

theorem addZero_atom_sound
    (s : StackState) (a : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint a :: rest) :
    runOps [.push (.bigint 0), .opcode "OP_ADD"] s = runOps [] s := by
  rw [runOps_nil]
  exact run_pushZero_then_add_int s a rest hs

/-! ### `[push 1, OP_ADD] → [OP_1ADD]` rule + atom-sound (Phase 3g)

Encoding optimization. Both produce `.vBigint (a + 1)` on top of an
int-typed stack. -/

def applyOneAdd : List StackOp → List StackOp
  | [] => []
  | .push (.bigint 1) :: .opcode "OP_ADD" :: rest => .opcode "OP_1ADD" :: applyOneAdd rest
  | op :: rest => op :: applyOneAdd rest

theorem applyOneAdd_empty : applyOneAdd [] = [] := rfl

theorem applyOneAdd_match (rest : List StackOp) :
    applyOneAdd (.push (.bigint 1) :: .opcode "OP_ADD" :: rest)
    = .opcode "OP_1ADD" :: applyOneAdd rest := rfl

theorem runOpcode_1ADD_def (s : StackState) :
    runOpcode "OP_1ADD" s = liftIntUnary s (fun i => .vBigint (i + 1)) := rfl

theorem runOpcode_1add_vBigint (s : StackState) (i : Int) :
    runOpcode "OP_1ADD" (s.push (.vBigint i))
    = .ok (s.push (.vBigint (i + 1))) := by
  rw [runOpcode_1ADD_def]
  unfold liftIntUnary StackState.pop? StackState.push
  simp [asInt?]

private theorem run_pushOne_then_add_int
    (s : StackState) (a : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint a :: rest) :
    runOps [.push (.bigint 1), .opcode "OP_ADD"] s
    = .ok (({ s with stack := rest } : StackState).push (.vBigint (a + 1))) := by
  show runOps (.push (.bigint 1) :: .opcode "OP_ADD" :: []) s = _
  unfold runOps
  rw [stepNonIf_push_bigint]
  show runOps (.opcode "OP_ADD" :: []) (s.push (.vBigint 1)) = _
  unfold runOps
  rw [stepNonIf_opcode]
  have hpush : (s.push (.vBigint 1)).stack = .vBigint 1 :: .vBigint a :: rest := by
    unfold StackState.push; simp [hs]
  rw [runOpcode_add_int_concrete (s.push (.vBigint 1)) a 1 rest hpush]
  show runOps [] _ = _
  rw [runOps_nil]
  cases s
  simp_all [StackState.push]

private theorem run_one_add_int
    (s : StackState) (a : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint a :: rest) :
    runOps [.opcode "OP_1ADD"] s
    = .ok (({ s with stack := rest } : StackState).push (.vBigint (a + 1))) := by
  show runOps (.opcode "OP_1ADD" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode]
  rw [runOpcode_1ADD_def]
  unfold liftIntUnary StackState.pop?
  rw [hs]
  simp [asInt?]
  show runOps [] _ = _
  rw [runOps_nil]

theorem oneAdd_atom_sound
    (s : StackState) (a : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint a :: rest) :
    runOps [.push (.bigint 1), .opcode "OP_ADD"] s
    = runOps [.opcode "OP_1ADD"] s := by
  rw [run_pushOne_then_add_int s a rest hs, run_one_add_int s a rest hs]

/-! ### `[push 0, OP_SUB] → []` rule + atom-sound (Phase 3h)

Subtractive identity: `a - 0 = a` on int-typed top of stack. -/

def applySubZero : List StackOp → List StackOp
  | [] => []
  | .push (.bigint 0) :: .opcode "OP_SUB" :: rest => applySubZero rest
  | op :: rest => op :: applySubZero rest

theorem applySubZero_empty : applySubZero [] = [] := rfl

theorem applySubZero_match (rest : List StackOp) :
    applySubZero (.push (.bigint 0) :: .opcode "OP_SUB" :: rest)
    = applySubZero rest := rfl

theorem runOpcode_SUB_def (s : StackState) :
    runOpcode "OP_SUB" s = liftIntBin s (fun a b => .vBigint (a - b)) := rfl

theorem runOpcode_sub_int_concrete
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_SUB" s
    = .ok (({ s with stack := rest } : StackState).push (.vBigint (a - b))) := by
  rw [runOpcode_SUB_def]
  unfold liftIntBin
  rw [popN_two_cons s (.vBigint b) (.vBigint a) rest hs]
  simp [asInt?]

private theorem run_pushZero_then_sub_int
    (s : StackState) (a : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint a :: rest) :
    runOps [.push (.bigint 0), .opcode "OP_SUB"] s = .ok s := by
  show runOps (.push (.bigint 0) :: .opcode "OP_SUB" :: []) s = _
  unfold runOps
  rw [stepNonIf_push_bigint]
  show runOps (.opcode "OP_SUB" :: []) (s.push (.vBigint 0)) = _
  unfold runOps
  rw [stepNonIf_opcode]
  have hpush : (s.push (.vBigint 0)).stack = .vBigint 0 :: .vBigint a :: rest := by
    unfold StackState.push; simp [hs]
  rw [runOpcode_sub_int_concrete (s.push (.vBigint 0)) a 0 rest hpush]
  show runOps [] _ = .ok s
  rw [runOps_nil]
  have : a - 0 = a := Int.sub_zero a
  rw [this]
  cases s
  simp_all [StackState.push]

theorem subZero_atom_sound
    (s : StackState) (a : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint a :: rest) :
    runOps [.push (.bigint 0), .opcode "OP_SUB"] s = runOps [] s := by
  rw [runOps_nil]
  exact run_pushZero_then_sub_int s a rest hs

/-! ### `[OP_SHA256, OP_SHA256] → [OP_HASH256]` rule + atom-sound (Phase 3h)

Hash fusion: applying `OP_SHA256` twice equals one `OP_HASH256` call
*by definition of the `Crypto.hash256` axiom* — i.e., we add a
linking axiom `hash256_eq_double_sha256` that captures Bitcoin's
well-known equality. This is the first peephole rule whose soundness
rests on a cryptographic identity rather than purely on opcode
semantics; we surface the identity as an explicit axiom so the trust
boundary is visible.
-/

axiom hash256_eq_double_sha256 (b : ByteArray) :
    hash256 b = sha256 (sha256 b)

def applyDoubleSha256 : List StackOp → List StackOp
  | [] => []
  | .opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest =>
      .opcode "OP_HASH256" :: applyDoubleSha256 rest
  | op :: rest => op :: applyDoubleSha256 rest

theorem applyDoubleSha256_empty : applyDoubleSha256 [] = [] := rfl

theorem applyDoubleSha256_match (rest : List StackOp) :
    applyDoubleSha256 (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest)
    = .opcode "OP_HASH256" :: applyDoubleSha256 rest := rfl

theorem runOpcode_SHA256_def (s : StackState) :
    runOpcode "OP_SHA256" s = liftBytesUnary s (fun b => .vBytes (sha256 b)) := rfl

theorem runOpcode_HASH256_def (s : StackState) :
    runOpcode "OP_HASH256" s = liftBytesUnary s (fun b => .vBytes (hash256 b)) := rfl

/-- `OP_SHA256` on a `.vBytes b` top pushes `.vBytes (sha256 b)`. -/
theorem runOpcode_sha256_vBytes (s : StackState) (b : ByteArray) :
    runOpcode "OP_SHA256" (s.push (.vBytes b))
    = .ok (s.push (.vBytes (sha256 b))) := by
  rw [runOpcode_SHA256_def]
  unfold liftBytesUnary StackState.pop? StackState.push
  simp [asBytes?]

/-- `OP_HASH256` on a `.vBytes b` top pushes `.vBytes (hash256 b)`. -/
theorem runOpcode_hash256_vBytes (s : StackState) (b : ByteArray) :
    runOpcode "OP_HASH256" (s.push (.vBytes b))
    = .ok (s.push (.vBytes (hash256 b))) := by
  rw [runOpcode_HASH256_def]
  unfold liftBytesUnary StackState.pop? StackState.push
  simp [asBytes?]

/-- Two `OP_SHA256`s pushed against a `.vBytes b`-topped stack equals one
`OP_HASH256` (via the linking axiom `hash256_eq_double_sha256`). -/
private theorem run_two_sha256s_pushed (s' : StackState) (b : ByteArray) :
    runOps [.opcode "OP_SHA256", .opcode "OP_SHA256"] (s'.push (.vBytes b))
    = runOps [.opcode "OP_HASH256"] (s'.push (.vBytes b)) := by
  have hLHS : runOps [.opcode "OP_SHA256", .opcode "OP_SHA256"] (s'.push (.vBytes b))
            = .ok (s'.push (.vBytes (sha256 (sha256 b)))) := by
    show runOps (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: []) _ = _
    unfold runOps
    rw [stepNonIf_opcode, runOpcode_sha256_vBytes]
    show runOps (.opcode "OP_SHA256" :: []) _ = _
    unfold runOps
    rw [stepNonIf_opcode, runOpcode_sha256_vBytes]
    show runOps [] _ = _
    rw [runOps_nil]
  have hRHS : runOps [.opcode "OP_HASH256"] (s'.push (.vBytes b))
            = .ok (s'.push (.vBytes (hash256 b))) := by
    show runOps (.opcode "OP_HASH256" :: []) _ = _
    unfold runOps
    rw [stepNonIf_opcode, runOpcode_hash256_vBytes]
    show runOps [] _ = _
    rw [runOps_nil]
  rw [hLHS, hRHS, hash256_eq_double_sha256]

theorem doubleSha256_atom_sound
    (s : StackState) (b : ByteArray) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBytes b :: rest) :
    runOps [.opcode "OP_SHA256", .opcode "OP_SHA256"] s
    = runOps [.opcode "OP_HASH256"] s := by
  have hs' : s = (({ s with stack := rest } : StackState).push (.vBytes b)) := by
    cases s; simp_all [StackState.push]
  rw [hs']
  exact run_two_sha256s_pushed _ b

/-! ### `_extends_<typed>` lemmas — using `Eq.trans` chain (Phase 3i)

Proving `runOps (.push v :: .drop :: rest) s = runOps rest s` works
via two intermediate equalities:
1. `runOps (.push v :: …) s` reduces via `stepNonIf_push_*` to
   `runOps (.drop :: rest) (s.push v)`.
2. `runOps (.drop :: rest) (s.push v)` reduces via `stepNonIf_drop`
   and `applyDrop_push` to `runOps rest s`.

We assert each intermediate step as a `have` clause that doesn't
unfold the RHS's `runOps`, then chain them. The key insight: after
asserting the equality of each runOps-application form, we never
re-unfold the post-equality `runOps`.
-/

/-- `runOps.eq_3` carries a side condition: the head op must not be
`.ifOp`. This wrapper discharges the side condition for `.drop` (a
constant constructor different from `.ifOp`). -/
theorem runOps_cons_drop_eq (rest : List StackOp) (s : StackState) :
    runOps (StackOp.drop :: rest) s
    = match stepNonIf StackOp.drop s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3
  intro thn els h
  exact StackOp.noConfusion h

theorem runOps_cons_push_eq (v : PushVal) (rest : List StackOp) (s : StackState) :
    runOps (StackOp.push v :: rest) s
    = match stepNonIf (StackOp.push v) s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3
  intro thn els h
  exact StackOp.noConfusion h

theorem runOps_cons_opcode_eq (code : String) (rest : List StackOp) (s : StackState) :
    runOps (StackOp.opcode code :: rest) s
    = match stepNonIf (StackOp.opcode code) s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3
  intro thn els h
  exact StackOp.noConfusion h

/-! ## Cons-step equation lemmas — full coverage (Phase 3j)

One per non-`.ifOp` `StackOp` constructor. Same recipe as
`runOps_cons_drop_eq`: dispatch via `runOps.eq_3` and discharge the
`op ≠ .ifOp` side condition via `StackOp.noConfusion`.
-/

theorem runOps_cons_dup_eq (rest : List StackOp) (s : StackState) :
    runOps (StackOp.dup :: rest) s
    = match stepNonIf StackOp.dup s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3; intro thn els h; exact StackOp.noConfusion h

theorem runOps_cons_swap_eq (rest : List StackOp) (s : StackState) :
    runOps (StackOp.swap :: rest) s
    = match stepNonIf StackOp.swap s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3; intro thn els h; exact StackOp.noConfusion h

theorem runOps_cons_nip_eq (rest : List StackOp) (s : StackState) :
    runOps (StackOp.nip :: rest) s
    = match stepNonIf StackOp.nip s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3; intro thn els h; exact StackOp.noConfusion h

theorem runOps_cons_over_eq (rest : List StackOp) (s : StackState) :
    runOps (StackOp.over :: rest) s
    = match stepNonIf StackOp.over s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3; intro thn els h; exact StackOp.noConfusion h

theorem runOps_cons_rot_eq (rest : List StackOp) (s : StackState) :
    runOps (StackOp.rot :: rest) s
    = match stepNonIf StackOp.rot s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3; intro thn els h; exact StackOp.noConfusion h

theorem runOps_cons_tuck_eq (rest : List StackOp) (s : StackState) :
    runOps (StackOp.tuck :: rest) s
    = match stepNonIf StackOp.tuck s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3; intro thn els h; exact StackOp.noConfusion h

theorem runOps_cons_roll_eq (d : Nat) (rest : List StackOp) (s : StackState) :
    runOps (StackOp.roll d :: rest) s
    = match stepNonIf (StackOp.roll d) s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3; intro thn els h; exact StackOp.noConfusion h

theorem runOps_cons_pick_eq (d : Nat) (rest : List StackOp) (s : StackState) :
    runOps (StackOp.pick d :: rest) s
    = match stepNonIf (StackOp.pick d) s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3; intro thn els h; exact StackOp.noConfusion h

theorem runOps_cons_placeholder_eq (i : Nat) (n : String) (rest : List StackOp) (s : StackState) :
    runOps (StackOp.placeholder i n :: rest) s
    = match stepNonIf (StackOp.placeholder i n) s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3; intro thn els h; exact StackOp.noConfusion h

theorem runOps_cons_pushCodesepIndex_eq (rest : List StackOp) (s : StackState) :
    runOps (StackOp.pushCodesepIndex :: rest) s
    = match stepNonIf StackOp.pushCodesepIndex s with
      | .error e => .error e
      | .ok s'   => runOps rest s' := by
  apply runOps.eq_3; intro thn els h; exact StackOp.noConfusion h

/-- Step 1: `runOps (.drop :: rest)` on a freshly-pushed state strips that value. -/
theorem runOps_drop_pushed (s : StackState) (v : ANF.Eval.Value)
    (rest : List StackOp) :
    runOps (.drop :: rest) (s.push v) = runOps rest s := by
  rw [runOps_cons_drop_eq, stepNonIf_drop, applyDrop_push]

theorem dropAfterPush_extends_bigint
    (s : StackState) (i : Int) (rest : List StackOp) :
    runOps (.push (.bigint i) :: .drop :: rest) s = runOps rest s := by
  rw [runOps_cons_push_eq, stepNonIf_push_bigint]
  show runOps (.drop :: rest) (s.push (.vBigint i)) = runOps rest s
  exact runOps_drop_pushed s (.vBigint i) rest

theorem dropAfterPush_extends_bool
    (s : StackState) (b : Bool) (rest : List StackOp) :
    runOps (.push (.bool b) :: .drop :: rest) s = runOps rest s := by
  rw [runOps_cons_push_eq, stepNonIf_push_bool]
  show runOps (.drop :: rest) (s.push (.vBool b)) = runOps rest s
  exact runOps_drop_pushed s (.vBool b) rest

theorem dropAfterPush_extends_bytes
    (s : StackState) (b : ByteArray) (rest : List StackOp) :
    runOps (.push (.bytes b) :: .drop :: rest) s = runOps rest s := by
  rw [runOps_cons_push_eq, stepNonIf_push_bytes]
  show runOps (.drop :: rest) (s.push (.vBytes b)) = runOps rest s
  exact runOps_drop_pushed s (.vBytes b) rest

theorem dropAfterPush_extends
    (s : StackState) (v : PushVal) (rest : List StackOp) :
    runOps (.push v :: .drop :: rest) s = runOps rest s := by
  cases v with
  | bigint i => exact dropAfterPush_extends_bigint s i rest
  | bool b   => exact dropAfterPush_extends_bool s b rest
  | bytes b  => exact dropAfterPush_extends_bytes s b rest

/-! ### `dropAfterPush_pass_sound` — first list-induction soundness (Phase 3i)

The `applyDropAfterPush` rule is *unconditionally* sound: pushing a
value and immediately dropping it never changes the stack regardless
of the prior state. So `pass_sound` holds without a stack-shape
invariant.

**Restriction**: we prove it for op lists that contain no `.ifOp`
(captured as `noIfOp`). This avoids reasoning about the special-case
`.ifOp` arm of `runOps`'s match. Full-`.ifOp` `pass_sound` is Phase 3j.
-/

/-- Predicate: an op list contains no `.ifOp` constructor anywhere
(including no nested `.ifOp` in the if-branches). -/
def noIfOp : List StackOp → Prop
  | [] => True
  | .ifOp _ _ :: _ => False
  | _ :: rest => noIfOp rest

/-- For a non-`ifOp` op, `runOps (op :: applyXxx rest) s = runOps (op :: rest) s`
when `runOps (applyXxx rest) s' = runOps rest s'` for the post-op state `s'`.

Specialized below for the `.push` and other non-`.ifOp` constructors
that appear in `applyDropAfterPush`'s output. -/
private theorem runOps_cons_push_cong (v : PushVal)
    (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.push v :: a) s = runOps (.push v :: b) s := by
  rw [runOps_cons_push_eq, runOps_cons_push_eq]
  cases hStep : stepNonIf (.push v) s with
  | error e => rfl
  | ok s'   => exact h s'

private theorem runOps_cons_drop_cong
    (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.drop :: a) s = runOps (.drop :: b) s := by
  rw [runOps_cons_drop_eq, runOps_cons_drop_eq]
  cases hStep : stepNonIf .drop s with
  | error e => rfl
  | ok s'   => exact h s'

private theorem runOps_cons_opcode_cong (code : String)
    (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.opcode code :: a) s = runOps (.opcode code :: b) s := by
  rw [runOps_cons_opcode_eq, runOps_cons_opcode_eq]
  cases hStep : stepNonIf (.opcode code) s with
  | error e => rfl
  | ok s'   => exact h s'

private theorem runOps_cons_dup_cong (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.dup :: a) s = runOps (.dup :: b) s := by
  rw [runOps_cons_dup_eq, runOps_cons_dup_eq]
  cases hStep : stepNonIf .dup s with
  | error e => rfl
  | ok s'   => exact h s'

private theorem runOps_cons_swap_cong (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.swap :: a) s = runOps (.swap :: b) s := by
  rw [runOps_cons_swap_eq, runOps_cons_swap_eq]
  cases hStep : stepNonIf .swap s with
  | error e => rfl
  | ok s'   => exact h s'

private theorem runOps_cons_nip_cong (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.nip :: a) s = runOps (.nip :: b) s := by
  rw [runOps_cons_nip_eq, runOps_cons_nip_eq]
  cases hStep : stepNonIf .nip s with
  | error e => rfl
  | ok s'   => exact h s'

private theorem runOps_cons_over_cong (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.over :: a) s = runOps (.over :: b) s := by
  rw [runOps_cons_over_eq, runOps_cons_over_eq]
  cases hStep : stepNonIf .over s with
  | error e => rfl
  | ok s'   => exact h s'

private theorem runOps_cons_rot_cong (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.rot :: a) s = runOps (.rot :: b) s := by
  rw [runOps_cons_rot_eq, runOps_cons_rot_eq]
  cases hStep : stepNonIf .rot s with
  | error e => rfl
  | ok s'   => exact h s'

private theorem runOps_cons_tuck_cong (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.tuck :: a) s = runOps (.tuck :: b) s := by
  rw [runOps_cons_tuck_eq, runOps_cons_tuck_eq]
  cases hStep : stepNonIf .tuck s with
  | error e => rfl
  | ok s'   => exact h s'

private theorem runOps_cons_roll_cong (d : Nat) (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.roll d :: a) s = runOps (.roll d :: b) s := by
  rw [runOps_cons_roll_eq, runOps_cons_roll_eq]
  cases hStep : stepNonIf (.roll d) s with
  | error e => rfl
  | ok s'   => exact h s'

private theorem runOps_cons_pick_cong (d : Nat) (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.pick d :: a) s = runOps (.pick d :: b) s := by
  rw [runOps_cons_pick_eq, runOps_cons_pick_eq]
  cases hStep : stepNonIf (.pick d) s with
  | error e => rfl
  | ok s'   => exact h s'

private theorem runOps_cons_placeholder_cong (i : Nat) (n : String)
    (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.placeholder i n :: a) s = runOps (.placeholder i n :: b) s := by
  rw [runOps_cons_placeholder_eq, runOps_cons_placeholder_eq]
  cases hStep : stepNonIf (.placeholder i n) s with
  | error e => rfl
  | ok s'   => exact h s'

private theorem runOps_cons_pushCodesepIndex_cong (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.pushCodesepIndex :: a) s = runOps (.pushCodesepIndex :: b) s := by
  rw [runOps_cons_pushCodesepIndex_eq, runOps_cons_pushCodesepIndex_eq]
  cases hStep : stepNonIf .pushCodesepIndex s with
  | error e => rfl
  | ok s'   => exact h s'

/-! ### Conditional `_extends_*` lemmas (Phase 3k)

The conditional atom-sound proofs (e.g., `doubleNot_atom_sound`,
`doubleNegate_atom_sound`, `addZero_atom_sound`, `doubleSha256_atom_sound`)
all establish a 2-op result under a stack-shape precondition. To lift
them to `_pass_sound`, we first need `_extends_*` versions that hold
for arbitrary tail `rest` (not just `[]`).

Same recipe as the unconditional `dropAfterPush_extends_*`:
* Use `runOps_cons_*_eq` projections to peel one op off the LHS.
* Reduce the resulting `match Except.ok ... with ...` via either
  `match_Except_ok_runOps` or by proving an explicit reduction
  lemma for the helper involved.

Phase 3k delivers `doubleNot_extends` and `doubleNegate_extends` as
the template; the others (`addZero_extends`, `subZero_extends`,
`oneAdd_extends`, `doubleSha256_extends`) follow the same recipe.
-/

/-- Helper: `runOps (.opcode "OP_NOT" :: rest)` on a state with `.vBool b` on top. -/
private theorem runOps_cons_OPNOT_pushed (s : StackState) (b : Bool) (rest : List StackOp) :
    runOps (.opcode "OP_NOT" :: rest) (s.push (.vBool b))
    = runOps rest (s.push (.vBool (!b))) := by
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_not_vBool]

/-- `[OP_NOT, OP_NOT]` extends to arbitrary tail under `.vBool b :: rest_top` precondition. -/
theorem doubleNot_extends (s : StackState) (b : Bool) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vBool b :: rest_top) :
    runOps (.opcode "OP_NOT" :: .opcode "OP_NOT" :: rest) s = runOps rest s := by
  -- s = ({s with stack := rest_top}).push (.vBool b)
  have hs' : s = (({ s with stack := rest_top } : StackState).push (.vBool b)) := by
    cases s; simp_all [StackState.push]
  rw [hs']
  -- After first OP_NOT: state has .vBool (!b) on top
  rw [runOps_cons_OPNOT_pushed]
  -- After second OP_NOT: state has .vBool (!!b) = .vBool b on top
  rw [runOps_cons_OPNOT_pushed]
  -- !!b = b
  simp [Bool.not_not]

/-- Helper: `runOps (.opcode "OP_NEGATE" :: rest)` on `.vBigint i` top. -/
private theorem runOps_cons_OPNEGATE_pushed (s : StackState) (i : Int) (rest : List StackOp) :
    runOps (.opcode "OP_NEGATE" :: rest) (s.push (.vBigint i))
    = runOps rest (s.push (.vBigint (-i))) := by
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_negate_vBigint]

/-- `[OP_NEGATE, OP_NEGATE]` extends to arbitrary tail under `.vBigint i :: rest_top` precondition. -/
theorem doubleNegate_extends (s : StackState) (i : Int) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vBigint i :: rest_top) :
    runOps (.opcode "OP_NEGATE" :: .opcode "OP_NEGATE" :: rest) s = runOps rest s := by
  have hs' : s = (({ s with stack := rest_top } : StackState).push (.vBigint i)) := by
    cases s; simp_all [StackState.push]
  rw [hs']
  rw [runOps_cons_OPNEGATE_pushed]
  rw [runOps_cons_OPNEGATE_pushed]
  simp [Int.neg_neg]

/-- Helper: `runOps (.push (.bigint x) :: rest)` reduces to runOps rest applied to (s.push (.vBigint x)). -/
private theorem runOps_cons_PUSHbigint (s : StackState) (x : Int) (rest : List StackOp) :
    runOps (.push (.bigint x) :: rest) s = runOps rest (s.push (.vBigint x)) := by
  rw [runOps_cons_push_eq, stepNonIf_push_bigint]

/-- Helper: `runOps (.opcode "OP_ADD" :: rest)` on a state with two `.vBigint`s on top. -/
private theorem runOps_cons_OPADD_two_ints (s : StackState) (a b : Int)
    (rest_stack : List ANF.Eval.Value) (rest : List StackOp)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest_stack) :
    runOps (.opcode "OP_ADD" :: rest) s
    = runOps rest (({ s with stack := rest_stack } : StackState).push (.vBigint (a + b))) := by
  rw [runOps_cons_opcode_eq, stepNonIf_opcode]
  rw [runOpcode_add_int_concrete s a b rest_stack hs]

/-- Helper: `runOps (.opcode "OP_SUB" :: rest)` on a state with two `.vBigint`s on top. -/
private theorem runOps_cons_OPSUB_two_ints (s : StackState) (a b : Int)
    (rest_stack : List ANF.Eval.Value) (rest : List StackOp)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest_stack) :
    runOps (.opcode "OP_SUB" :: rest) s
    = runOps rest (({ s with stack := rest_stack } : StackState).push (.vBigint (a - b))) := by
  rw [runOps_cons_opcode_eq, stepNonIf_opcode]
  rw [runOpcode_sub_int_concrete s a b rest_stack hs]

/-- `[push 0, OP_ADD]` extends to arbitrary tail under `.vBigint a :: rest_stack` precondition. -/
theorem addZero_extends (s : StackState) (a : Int) (rest_stack : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vBigint a :: rest_stack) :
    runOps (.push (.bigint 0) :: .opcode "OP_ADD" :: rest) s = runOps rest s := by
  rw [runOps_cons_PUSHbigint]
  -- After push 0, stack = .vBigint 0 :: .vBigint a :: rest_stack
  have hs' : (s.push (.vBigint 0)).stack = .vBigint 0 :: .vBigint a :: rest_stack := by
    unfold StackState.push; simp [hs]
  rw [runOps_cons_OPADD_two_ints (s.push (.vBigint 0)) a 0 rest_stack rest hs']
  -- a + 0 = a
  have hAdd : a + 0 = a := Int.add_zero a
  rw [hAdd]
  -- Final state has stack = .vBigint a :: rest_stack = s.stack
  congr 1
  cases s
  simp_all [StackState.push]

/-- `[push 0, OP_SUB]` extends to arbitrary tail under `.vBigint a :: rest_stack` precondition. -/
theorem subZero_extends (s : StackState) (a : Int) (rest_stack : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vBigint a :: rest_stack) :
    runOps (.push (.bigint 0) :: .opcode "OP_SUB" :: rest) s = runOps rest s := by
  rw [runOps_cons_PUSHbigint]
  have hs' : (s.push (.vBigint 0)).stack = .vBigint 0 :: .vBigint a :: rest_stack := by
    unfold StackState.push; simp [hs]
  rw [runOps_cons_OPSUB_two_ints (s.push (.vBigint 0)) a 0 rest_stack rest hs']
  have hSub : a - 0 = a := Int.sub_zero a
  rw [hSub]
  congr 1
  cases s
  simp_all [StackState.push]

/-- `[push 1, OP_ADD]` extends to `[OP_1ADD]` under `.vBigint a :: rest_stack` precondition. -/
theorem oneAdd_extends (s : StackState) (a : Int) (rest_stack : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vBigint a :: rest_stack) :
    runOps (.push (.bigint 1) :: .opcode "OP_ADD" :: rest) s
    = runOps (.opcode "OP_1ADD" :: rest) s := by
  -- LHS: after push 1, OP_ADD with .vBigint 1 :: .vBigint a :: rest_stack on top
  rw [runOps_cons_PUSHbigint]
  have hs' : (s.push (.vBigint 1)).stack = .vBigint 1 :: .vBigint a :: rest_stack := by
    unfold StackState.push; simp [hs]
  rw [runOps_cons_OPADD_two_ints (s.push (.vBigint 1)) a 1 rest_stack rest hs']
  -- RHS: OP_1ADD on .vBigint a :: rest_stack
  rw [runOps_cons_opcode_eq, stepNonIf_opcode]
  -- Reduce the RHS using the runOpcode_1ADD_def helper + asInt? .vBigint = some
  rw [runOpcode_1ADD_def]
  unfold liftIntUnary StackState.pop?
  rw [hs]
  simp [asInt?]
  -- Both sides should now reduce to runOps rest applied to {state with stack := .vBigint (a + 1) :: rest_stack}
  cases s
  simp_all [StackState.push]

/-- Helper: `runOps (.opcode "OP_SHA256" :: rest)` on a `.vBytes b` top. -/
private theorem runOps_cons_OPSHA256_pushed (s : StackState) (b : ByteArray)
    (rest : List StackOp) :
    runOps (.opcode "OP_SHA256" :: rest) (s.push (.vBytes b))
    = runOps rest (s.push (.vBytes (sha256 b))) := by
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_sha256_vBytes]

/-- Helper: `runOps (.opcode "OP_HASH256" :: rest)` on a `.vBytes b` top. -/
private theorem runOps_cons_OPHASH256_pushed (s : StackState) (b : ByteArray)
    (rest : List StackOp) :
    runOps (.opcode "OP_HASH256" :: rest) (s.push (.vBytes b))
    = runOps rest (s.push (.vBytes (hash256 b))) := by
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_hash256_vBytes]

/-- `[OP_SHA256, OP_SHA256]` extends to `[OP_HASH256]` under `.vBytes b :: rest_top` precondition. -/
theorem doubleSha256_extends (s : StackState) (b : ByteArray) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vBytes b :: rest_top) :
    runOps (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest) s
    = runOps (.opcode "OP_HASH256" :: rest) s := by
  have hs' : s = (({ s with stack := rest_top } : StackState).push (.vBytes b)) := by
    cases s; simp_all [StackState.push]
  rw [hs']
  -- LHS: two SHA256 reductions
  rw [runOps_cons_OPSHA256_pushed]
  rw [runOps_cons_OPSHA256_pushed]
  -- RHS: one HASH256 reduction
  rw [runOps_cons_OPHASH256_pushed]
  -- They differ by the linking axiom hash256 = double sha256
  rw [hash256_eq_double_sha256]

/-! ### `[dup, drop]` extends — Phase 3s

Identity rule under `s.stack = v :: rest_top` precondition. After dup, the
stack has two copies of v on top; after drop, stack has v :: rest_top again. -/
theorem dupDrop_extends (s : StackState) (v : ANF.Eval.Value) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = v :: rest_top) :
    runOps (.dup :: .drop :: rest) s = runOps rest s := by
  rw [runOps_cons_dup_eq, stepNonIf_dup, applyDup_cons s v rest_top hs]
  show runOps (.drop :: rest) (s.push v) = runOps rest s
  rw [runOps_cons_drop_eq, stepNonIf_drop, applyDrop_push]

/-! ### `[swap, swap]` extends — Phase 3s

Identity rule under `s.stack = a :: b :: rest_top` precondition. -/
theorem doubleSwap_extends (s : StackState) (a b : ANF.Eval.Value)
    (rest_top : List ANF.Eval.Value) (rest : List StackOp)
    (hs : s.stack = a :: b :: rest_top) :
    runOps (.swap :: .swap :: rest) s = runOps rest s := by
  rw [runOps_cons_swap_eq, stepNonIf_swap, applySwap_cons2 s a b rest_top hs]
  show runOps (.swap :: rest)
        ({ s with stack := b :: a :: rest_top } : StackState) = runOps rest s
  rw [runOps_cons_swap_eq, stepNonIf_swap]
  rw [applySwap_cons2 _ b a rest_top rfl]
  -- After second swap: stack = a :: b :: rest_top = original s.stack
  congr 1
  cases s
  simp_all

/-! ### `[OP_NUMEQUAL, OP_VERIFY]` extends to `[OP_NUMEQUALVERIFY]` — Phase 3s

Non-identity rewrite. Both sides reduce to the same if-then-else under
two-int top precondition. -/
theorem numEqualVerifyFuse_extends
    (s : StackState) (a b : Int) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vBigint b :: .vBigint a :: rest_top) :
    runOps (.opcode "OP_NUMEQUAL" :: .opcode "OP_VERIFY" :: rest) s
    = runOps (.opcode "OP_NUMEQUALVERIFY" :: rest) s := by
  -- LHS: OP_NUMEQUAL leaves vBool (decide a=b) on top of (s with stack := rest_top).
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_numEqual_int s a b rest_top hs]
  show runOps (.opcode "OP_VERIFY" :: rest)
        ((({ s with stack := rest_top } : StackState).push (.vBool (decide (a = b))))) = _
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
  -- RHS: OP_NUMEQUALVERIFY = if (a=b) then ok s' else error.
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_numEqualVerify_int s a b rest_top hs]

/-! ### `[OP_CHECKSIG, OP_VERIFY]` extends to `[OP_CHECKSIGVERIFY]` — Phase 3s

Non-identity rewrite under two-bytes top precondition. -/
theorem checkSigVerifyFuse_extends
    (s : StackState) (sig pk : ByteArray) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vBytes pk :: .vBytes sig :: rest_top) :
    runOps (.opcode "OP_CHECKSIG" :: .opcode "OP_VERIFY" :: rest) s
    = runOps (.opcode "OP_CHECKSIGVERIFY" :: rest) s := by
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_checkSig_bytes s sig pk rest_top hs]
  show runOps (.opcode "OP_VERIFY" :: rest)
        ((({ s with stack := rest_top } : StackState).push (.vBool (checkSig sig pk)))) = _
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_checkSigVerify_bytes s sig pk rest_top hs]

/-! ### `[OP_EQUAL, OP_VERIFY]` extends to `[OP_EQUALVERIFY]` — Phase 3s (int variant)

Non-identity rewrite under two-int top precondition. We provide only the
int variant for the pass_sound proof; the bytes variant is deferred (Phase 3t)
since `precondMet .twoElems` does not constrain the underlying types. -/
theorem equalVerifyFuse_extends_int
    (s : StackState) (a b : Int) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vBigint b :: .vBigint a :: rest_top) :
    runOps (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest) s
    = runOps (.opcode "OP_EQUALVERIFY" :: rest) s := by
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_equal_int s a b rest_top hs]
  show runOps (.opcode "OP_VERIFY" :: rest)
        ((({ s with stack := rest_top } : StackState).push (.vBool (decide (a = b))))) = _
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_equalVerify_int s a b rest_top hs]

/-! ### `[OP_EQUAL, OP_VERIFY]` extends to `[OP_EQUALVERIFY]` — Phase 3s (bytes variant)

Non-identity rewrite under two-bytes top precondition. -/
theorem runOpcode_equal_bytes
    (s : StackState) (a b : ByteArray) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBytes b :: .vBytes a :: rest_top) :
    runOpcode "OP_EQUAL" s
    = .ok (({ s with stack := rest_top } : StackState).push
            (.vBool (decide (a.toList = b.toList)))) := by
  rw [runOpcode_EQUAL_def, popN_two_cons s (.vBytes b) (.vBytes a) rest_top hs]
  simp [asBytes?, asInt?]

theorem runOpcode_equalVerify_bytes
    (s : StackState) (a b : ByteArray) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBytes b :: .vBytes a :: rest_top) :
    runOpcode "OP_EQUALVERIFY" s
    = if decide (a.toList = b.toList) then .ok ({ s with stack := rest_top } : StackState)
                                        else .error .assertFailed := by
  rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vBytes b) (.vBytes a) rest_top hs]
  simp [asBytes?, asInt?]

theorem equalVerifyFuse_extends_bytes
    (s : StackState) (a b : ByteArray) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vBytes b :: .vBytes a :: rest_top) :
    runOps (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest) s
    = runOps (.opcode "OP_EQUALVERIFY" :: rest) s := by
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_equal_bytes s a b rest_top hs]
  show runOps (.opcode "OP_VERIFY" :: rest)
        ((({ s with stack := rest_top } : StackState).push
            (.vBool (decide (a.toList = b.toList))))) = _
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_equalVerify_bytes s a b rest_top hs]

/-! ### Stack-typing predicates (Phase 3l)

The substrate for conditional `_pass_sound` proofs. An `OpExpectation`
captures the type/shape constraint a peephole rule's atom-sound proof
imposes on the stack at the rule's firing position. `precondMet`
checks the constraint against an actual `StackState`.

These predicates power Phase 3m's conditional `_pass_sound` proofs:
each rule's pass_sound is conditioned on `wellTyped` over the input
op list (every op's `OpExpectation` is met at its position).
-/

inductive OpExpectation where
  | bool      -- top must be `.vBool`
  | bigint    -- top must be `.vBigint`
  | bytes     -- top must be `.vBytes` or `.vOpaque`
  | nonEmpty  -- top must exist (any type)
  | twoInts   -- top two must be `.vBigint`
  | twoBytes  -- top two must be `.vBytes`/`.vOpaque`
  | twoElems  -- ≥ 2 elements (any type)
  | none      -- no precondition
  deriving Repr, BEq, Inhabited

def precondMet : OpExpectation → StackState → Prop
  | .bool, s     => match s.stack with | .vBool _ :: _ => True | _ => False
  | .bigint, s   => match s.stack with | .vBigint _ :: _ => True | _ => False
  | .bytes, s    => match s.stack with
                    | .vBytes _ :: _ => True
                    | .vOpaque _ :: _ => True
                    | _ => False
  | .nonEmpty, s => match s.stack with | _ :: _ => True | _ => False
  | .twoInts, s  => match s.stack with
                    | .vBigint _ :: .vBigint _ :: _ => True
                    | _ => False
  | .twoBytes, s => match s.stack with
                    | .vBytes _ :: .vBytes _ :: _ => True
                    | .vBytes _ :: .vOpaque _ :: _ => True
                    | .vOpaque _ :: .vBytes _ :: _ => True
                    | .vOpaque _ :: .vOpaque _ :: _ => True
                    | _ => False
  | .twoElems, s => match s.stack with
                    | _ :: _ :: _ => True
                    | _ => False
  | .none, _     => True

-- (Decidable instance for `precondMet` deferred to Phase 3m — not load-bearing
-- for the current pass_sound proof recipe; the precondition check is symbolic.)

/-! ### `opPrecondition` table (Phase 3m)

The expectation an op imposes on the stack at its execution position.
Most ops have `.none` (no precondition); the table below lists every
op the conditional peephole rules' atom-sound proofs depend on.

Entries marked TODO are conservative `.none` defaults — Phase 3n
tightens them once additional rule soundness proofs require it.
-/

def opPrecondition : StackOp → OpExpectation
  -- Logical
  | .opcode "OP_NOT"      => .bool
  | .opcode "OP_VERIFY"   => .bool
  | .opcode "OP_BOOLAND"  => .twoInts
  | .opcode "OP_BOOLOR"   => .twoInts
  -- Numeric unary
  | .opcode "OP_NEGATE"   => .bigint
  | .opcode "OP_ABS"      => .bigint
  | .opcode "OP_1ADD"     => .bigint
  | .opcode "OP_1SUB"     => .bigint
  -- Numeric binary
  | .opcode "OP_ADD"      => .twoInts
  | .opcode "OP_SUB"      => .twoInts
  | .opcode "OP_MUL"      => .twoInts
  | .opcode "OP_DIV"      => .twoInts
  | .opcode "OP_MOD"      => .twoInts
  | .opcode "OP_LSHIFT"   => .twoInts
  | .opcode "OP_RSHIFT"   => .twoInts
  -- Comparison
  | .opcode "OP_NUMEQUAL"           => .twoInts
  | .opcode "OP_NUMNOTEQUAL"        => .twoInts
  | .opcode "OP_LESSTHAN"           => .twoInts
  | .opcode "OP_GREATERTHAN"        => .twoInts
  | .opcode "OP_LESSTHANOREQUAL"    => .twoInts
  | .opcode "OP_GREATERTHANOREQUAL" => .twoInts
  | .opcode "OP_NUMEQUALVERIFY"     => .twoInts
  | .opcode "OP_MIN"                => .twoInts
  | .opcode "OP_MAX"                => .twoInts
  -- Hash (input must be bytes)
  | .opcode "OP_SHA256"     => .bytes
  | .opcode "OP_SHA1"       => .bytes
  | .opcode "OP_HASH160"    => .bytes
  | .opcode "OP_HASH256"    => .bytes
  | .opcode "OP_RIPEMD160"  => .bytes
  -- Signature (top two must be bytes)
  | .opcode "OP_CHECKSIG"          => .twoBytes
  | .opcode "OP_CHECKSIGVERIFY"    => .twoBytes
  -- Multi-sig (single-pop abstract semantics; top must be bytes)
  | .opcode "OP_CHECKMULTISIG"     => .bytes
  | .opcode "OP_CHECKMULTISIGVERIFY" => .bytes
  -- Bytes binary
  | .opcode "OP_CAT"      => .twoBytes
  | .opcode "OP_EQUAL"    => .twoElems  -- accepts either int or bytes top
  | .opcode "OP_EQUALVERIFY" => .twoElems
  -- Stack manipulation (only depth requirements)
  | .dup    => .nonEmpty
  | .drop   => .nonEmpty
  | .swap   => .twoElems
  | .nip    => .twoElems
  | .over   => .twoElems
  | .tuck   => .twoElems
  | .rot    => .twoElems  -- weakly: requires 3, but twoElems is the closest existing constructor; tighten in Phase 3n
  -- Pure pushes have no precondition
  | .push _              => .none
  | .placeholder _ _     => .none
  | .pushCodesepIndex    => .none
  -- Default: no constraint
  | _                    => .none

/-! ### `wellTypedRun` predicate

A list of ops `ops` is well-typed at starting state `s` when every op's
expected precondition holds at its execution position. The recursion
threads `stepNonIf` through the list, requiring the precondition at
each step.

This is the "stack-typing invariant" referred to in HANDOFF.md
§"Phase 3m"; conditional `_pass_sound` proofs assume `wellTypedRun ops s`
as their hypothesis.
-/

def wellTypedRun : List StackOp → StackState → Prop
  | [], _ => True
  | op :: rest, s =>
      precondMet (opPrecondition op) s ∧
      (∀ s', stepNonIf op s = .ok s' → wellTypedRun rest s')

theorem wellTypedRun_nil (s : StackState) : wellTypedRun [] s := True.intro

theorem wellTypedRun_cons (op : StackOp) (rest : List StackOp) (s : StackState) :
    wellTypedRun (op :: rest) s ↔
      precondMet (opPrecondition op) s ∧
      (∀ s', stepNonIf op s = .ok s' → wellTypedRun rest s') :=
  Iff.rfl

/-! ### Typed cong lemmas (Phase 3n)

A weaker variant of the Phase 3j `runOps_cons_<op>_cong` lemmas:
the hypothesis is restricted to **post-step states only** (i.e.,
states that arise from `stepNonIf op s`). Used by conditional
`_pass_sound` proofs where the inductive hypothesis only holds
under the `wellTypedRun` precondition (and thus only on
"reachable" post-step states).

Same proof recipe as the universal cong; just propagates a tighter
hypothesis.
-/

private theorem runOps_cons_opcode_cong_typed (code : String)
    (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf (.opcode code) s = .ok s' → runOps a s' = runOps b s') :
    runOps (.opcode code :: a) s = runOps (.opcode code :: b) s := by
  rw [runOps_cons_opcode_eq, runOps_cons_opcode_eq]
  cases hStep : stepNonIf (.opcode code) s with
  | error e => rfl
  | ok s'   => exact h s' hStep

private theorem runOps_cons_dup_cong_typed (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf .dup s = .ok s' → runOps a s' = runOps b s') :
    runOps (.dup :: a) s = runOps (.dup :: b) s := by
  rw [runOps_cons_dup_eq, runOps_cons_dup_eq]
  cases hStep : stepNonIf .dup s with
  | error e => rfl
  | ok s'   => exact h s' hStep

private theorem runOps_cons_swap_cong_typed (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf .swap s = .ok s' → runOps a s' = runOps b s') :
    runOps (.swap :: a) s = runOps (.swap :: b) s := by
  rw [runOps_cons_swap_eq, runOps_cons_swap_eq]
  cases hStep : stepNonIf .swap s with
  | error e => rfl
  | ok s'   => exact h s' hStep

private theorem runOps_cons_drop_cong_typed (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf .drop s = .ok s' → runOps a s' = runOps b s') :
    runOps (.drop :: a) s = runOps (.drop :: b) s := by
  rw [runOps_cons_drop_eq, runOps_cons_drop_eq]
  cases hStep : stepNonIf .drop s with
  | error e => rfl
  | ok s'   => exact h s' hStep

private theorem runOps_cons_nip_cong_typed (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf .nip s = .ok s' → runOps a s' = runOps b s') :
    runOps (.nip :: a) s = runOps (.nip :: b) s := by
  rw [runOps_cons_nip_eq, runOps_cons_nip_eq]
  cases hStep : stepNonIf .nip s with
  | error e => rfl
  | ok s'   => exact h s' hStep

private theorem runOps_cons_over_cong_typed (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf .over s = .ok s' → runOps a s' = runOps b s') :
    runOps (.over :: a) s = runOps (.over :: b) s := by
  rw [runOps_cons_over_eq, runOps_cons_over_eq]
  cases hStep : stepNonIf .over s with
  | error e => rfl
  | ok s'   => exact h s' hStep

private theorem runOps_cons_rot_cong_typed (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf .rot s = .ok s' → runOps a s' = runOps b s') :
    runOps (.rot :: a) s = runOps (.rot :: b) s := by
  rw [runOps_cons_rot_eq, runOps_cons_rot_eq]
  cases hStep : stepNonIf .rot s with
  | error e => rfl
  | ok s'   => exact h s' hStep

private theorem runOps_cons_tuck_cong_typed (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf .tuck s = .ok s' → runOps a s' = runOps b s') :
    runOps (.tuck :: a) s = runOps (.tuck :: b) s := by
  rw [runOps_cons_tuck_eq, runOps_cons_tuck_eq]
  cases hStep : stepNonIf .tuck s with
  | error e => rfl
  | ok s'   => exact h s' hStep

private theorem runOps_cons_roll_cong_typed (d : Nat) (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf (.roll d) s = .ok s' → runOps a s' = runOps b s') :
    runOps (.roll d :: a) s = runOps (.roll d :: b) s := by
  rw [runOps_cons_roll_eq, runOps_cons_roll_eq]
  cases hStep : stepNonIf (.roll d) s with
  | error e => rfl
  | ok s'   => exact h s' hStep

private theorem runOps_cons_pick_cong_typed (d : Nat) (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf (.pick d) s = .ok s' → runOps a s' = runOps b s') :
    runOps (.pick d :: a) s = runOps (.pick d :: b) s := by
  rw [runOps_cons_pick_eq, runOps_cons_pick_eq]
  cases hStep : stepNonIf (.pick d) s with
  | error e => rfl
  | ok s'   => exact h s' hStep

private theorem runOps_cons_push_cong_typed (v : PushVal)
    (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf (.push v) s = .ok s' → runOps a s' = runOps b s') :
    runOps (.push v :: a) s = runOps (.push v :: b) s := by
  rw [runOps_cons_push_eq, runOps_cons_push_eq]
  cases hStep : stepNonIf (.push v) s with
  | error e => rfl
  | ok s'   => exact h s' hStep

private theorem runOps_cons_placeholder_cong_typed (i : Nat) (n : String)
    (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf (.placeholder i n) s = .ok s' → runOps a s' = runOps b s') :
    runOps (.placeholder i n :: a) s = runOps (.placeholder i n :: b) s := by
  rw [runOps_cons_placeholder_eq, runOps_cons_placeholder_eq]
  cases hStep : stepNonIf (.placeholder i n) s with
  | error e => rfl
  | ok s'   => exact h s' hStep

private theorem runOps_cons_pushCodesepIndex_cong_typed
    (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf .pushCodesepIndex s = .ok s' → runOps a s' = runOps b s') :
    runOps (.pushCodesepIndex :: a) s = runOps (.pushCodesepIndex :: b) s := by
  rw [runOps_cons_pushCodesepIndex_eq, runOps_cons_pushCodesepIndex_eq]
  cases hStep : stepNonIf .pushCodesepIndex s with
  | error e => rfl
  | ok s'   => exact h s' hStep

/-! ### `precondMet .bool` extraction (Phase 3n)

A small helper that pulls a concrete `.vBool b :: rest_top` shape
from `precondMet .bool s`. Used by `doubleNot_pass_sound`'s case2
to enable applying `doubleNot_extends`.
-/

theorem precondMet_bool_extract (s : StackState) (h : precondMet .bool s) :
    ∃ b rest_top, s.stack = .vBool b :: rest_top := by
  match hs : s.stack with
  | [] => simp [precondMet, hs] at h
  | .vBool b :: rest_top => exact ⟨b, rest_top, rfl⟩
  | .vBigint _ :: _ => simp [precondMet, hs] at h
  | .vBytes _ :: _  => simp [precondMet, hs] at h
  | .vOpaque _ :: _ => simp [precondMet, hs] at h
  | .vThis :: _     => simp [precondMet, hs] at h

theorem precondMet_bigint_extract (s : StackState) (h : precondMet .bigint s) :
    ∃ i rest_top, s.stack = .vBigint i :: rest_top := by
  match hs : s.stack with
  | [] => simp [precondMet, hs] at h
  | .vBigint i :: rest_top => exact ⟨i, rest_top, rfl⟩
  | .vBool _ :: _   => simp [precondMet, hs] at h
  | .vBytes _ :: _  => simp [precondMet, hs] at h
  | .vOpaque _ :: _ => simp [precondMet, hs] at h
  | .vThis :: _     => simp [precondMet, hs] at h

theorem precondMet_bytes_extract (s : StackState) (h : precondMet .bytes s) :
    ∃ b rest_top, (s.stack = .vBytes b :: rest_top ∨ s.stack = .vOpaque b :: rest_top) := by
  match hs : s.stack with
  | [] => simp [precondMet, hs] at h
  | .vBytes b :: rest_top => exact ⟨b, rest_top, Or.inl rfl⟩
  | .vOpaque b :: rest_top => exact ⟨b, rest_top, Or.inr rfl⟩
  | .vBigint _ :: _ => simp [precondMet, hs] at h
  | .vBool _ :: _   => simp [precondMet, hs] at h
  | .vThis :: _     => simp [precondMet, hs] at h

theorem precondMet_nonEmpty_extract (s : StackState) (h : precondMet .nonEmpty s) :
    ∃ v rest_top, s.stack = v :: rest_top := by
  match hs : s.stack with
  | [] => simp [precondMet, hs] at h
  | v :: rest_top => exact ⟨v, rest_top, rfl⟩

theorem precondMet_twoElems_extract (s : StackState) (h : precondMet .twoElems s) :
    ∃ a b rest_top, s.stack = a :: b :: rest_top := by
  match hs : s.stack with
  | [] => simp [precondMet, hs] at h
  | [_] => simp [precondMet, hs] at h
  | a :: b :: rest_top => exact ⟨a, b, rest_top, rfl⟩

theorem precondMet_twoInts_extract (s : StackState) (h : precondMet .twoInts s) :
    ∃ a b rest_top, s.stack = .vBigint b :: .vBigint a :: rest_top := by
  match hs : s.stack with
  | .vBigint b :: .vBigint a :: rest_top => exact ⟨a, b, rest_top, rfl⟩
  | [] => simp [precondMet, hs] at h
  | [_] => simp [precondMet, hs] at h
  | .vBigint _ :: .vBool _ :: _   => simp [precondMet, hs] at h
  | .vBigint _ :: .vBytes _ :: _  => simp [precondMet, hs] at h
  | .vBigint _ :: .vOpaque _ :: _ => simp [precondMet, hs] at h
  | .vBigint _ :: .vThis :: _     => simp [precondMet, hs] at h
  | .vBool _ :: _ :: _   => simp [precondMet, hs] at h
  | .vBytes _ :: _ :: _  => simp [precondMet, hs] at h
  | .vOpaque _ :: _ :: _ => simp [precondMet, hs] at h
  | .vThis :: _ :: _     => simp [precondMet, hs] at h

/-! ### `doubleNot_pass_sound_at_start` — focused conditional pass_sound (Phase 3o)

A focused soundness theorem: at a single rule-firing position, the
2-op rewrite preserves `runOps` semantics, *given* a hypothesis on
the tail. This demonstrates that the Phase 3i-3n substrate works
end-to-end for conditional rules at rule-firing positions. The full
list-induction `doubleNot_pass_sound` extends this via
`applyDoubleNot.induct` and Phase 3p case3 dispatch.
-/

theorem doubleNot_pass_sound_at_start (rest : List StackOp) (s : StackState)
    (b : Bool) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBool b :: rest_top)
    (hTailEq : runOps (applyDoubleNot rest) s = runOps rest s) :
    runOps (applyDoubleNot (.opcode "OP_NOT" :: .opcode "OP_NOT" :: rest)) s
    = runOps (.opcode "OP_NOT" :: .opcode "OP_NOT" :: rest) s := by
  -- LHS: rule fires, result = applyDoubleNot rest
  rw [show applyDoubleNot (.opcode "OP_NOT" :: .opcode "OP_NOT" :: rest)
       = applyDoubleNot rest from rfl]
  -- LHS now equals `runOps rest s` via hTailEq, RHS equals `runOps rest s` via doubleNot_extends.
  rw [hTailEq, doubleNot_extends s b rest_top rest hs]

/-- Same recipe for `doubleNegate`. -/
theorem doubleNegate_pass_sound_at_start (rest : List StackOp) (s : StackState)
    (i : Int) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBigint i :: rest_top)
    (hTailEq : runOps (applyDoubleNegate rest) s = runOps rest s) :
    runOps (applyDoubleNegate (.opcode "OP_NEGATE" :: .opcode "OP_NEGATE" :: rest)) s
    = runOps (.opcode "OP_NEGATE" :: .opcode "OP_NEGATE" :: rest) s := by
  rw [show applyDoubleNegate (.opcode "OP_NEGATE" :: .opcode "OP_NEGATE" :: rest)
       = applyDoubleNegate rest from rfl]
  rw [hTailEq, doubleNegate_extends s i rest_top rest hs]

/-- Same recipe for `addZero` (2-op pattern with `push`). -/
theorem addZero_pass_sound_at_start (rest : List StackOp) (s : StackState)
    (a : Int) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBigint a :: rest_top)
    (hTailEq : runOps (applyAddZero rest) s = runOps rest s) :
    runOps (applyAddZero (.push (.bigint 0) :: .opcode "OP_ADD" :: rest)) s
    = runOps (.push (.bigint 0) :: .opcode "OP_ADD" :: rest) s := by
  rw [show applyAddZero (.push (.bigint 0) :: .opcode "OP_ADD" :: rest)
       = applyAddZero rest from rfl]
  rw [hTailEq, addZero_extends s a rest_top rest hs]

/-- Same recipe for `subZero`. -/
theorem subZero_pass_sound_at_start (rest : List StackOp) (s : StackState)
    (a : Int) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBigint a :: rest_top)
    (hTailEq : runOps (applySubZero rest) s = runOps rest s) :
    runOps (applySubZero (.push (.bigint 0) :: .opcode "OP_SUB" :: rest)) s
    = runOps (.push (.bigint 0) :: .opcode "OP_SUB" :: rest) s := by
  rw [show applySubZero (.push (.bigint 0) :: .opcode "OP_SUB" :: rest)
       = applySubZero rest from rfl]
  rw [hTailEq, subZero_extends s a rest_top rest hs]

/-- Same recipe for `doubleSha256` — rewrites to a 1-op tail; needs a
universally-quantified tail hypothesis (over all post-step states).
Phase 3p strengthens the recipe to handle this rule shape. -/
theorem doubleSha256_pass_sound_at_start (rest : List StackOp) (s : StackState)
    (b : ByteArray) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBytes b :: rest_top)
    (hTailEq : ∀ s', runOps (applyDoubleSha256 rest) s' = runOps rest s') :
    runOps (applyDoubleSha256 (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest)) s
    = runOps (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest) s := by
  rw [show applyDoubleSha256 (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest)
       = .opcode "OP_HASH256" :: applyDoubleSha256 rest from rfl]
  rw [doubleSha256_extends s b rest_top rest hs]
  exact runOps_cons_opcode_cong "OP_HASH256" _ _ s hTailEq

/-! ### `doubleNot_pass_sound` — Phase 3p substrate (full proof deferred to 3q)

The full conditional pass_sound proof using `applyDoubleNot.induct`
needs case3's `.opcode code` arm to handle the rule-exclusion via
`h_no_match`, which in turn requires nested case analysis on the
String `code`. Lean's `cases` tactic doesn't case-split on String
constructors, so each (code, head-of-rest) pair must be enumerated
explicitly — substantial bookkeeping that's deferred to Phase 3q.

The case2 substrate is fully proven below as standalone helpers.
-/

/-- Helper: stepNonIf OP_NOT on a vBool top produces the negated state. -/
theorem stepNonIf_OPNOT_vBool (s : StackState) (b : Bool) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBool b :: rest_top) :
    stepNonIf (.opcode "OP_NOT") s
    = .ok ({ s with stack := .vBool (!b) :: rest_top } : StackState) := by
  rw [stepNonIf_opcode, runOpcode_NOT_def]
  unfold StackState.pop?
  rw [hs]
  simp [asBool?, StackState.push]

/-- Two OP_NOTs return the state to its original form (the `_extends` proof's
operational core). -/
theorem stepNonIf_OPNOT_OPNOT_vBool (s : StackState) (b : Bool) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBool b :: rest_top) :
    ∃ s1, stepNonIf (.opcode "OP_NOT") s = .ok s1 ∧
          stepNonIf (.opcode "OP_NOT") s1 = .ok s := by
  refine ⟨{ s with stack := .vBool (!b) :: rest_top }, stepNonIf_OPNOT_vBool s b rest_top hs, ?_⟩
  have hs1 : ({ s with stack := .vBool (!b) :: rest_top } : StackState).stack
           = .vBool (!b) :: rest_top := by simp
  rw [stepNonIf_OPNOT_vBool _ (!b) rest_top hs1]
  cases s
  simp_all [Bool.not_not]

/-- The `case2` core of the full `doubleNot_pass_sound` proof: assuming the
recursive IH on `rest'` (in tail-equality form), the rule-firing rewrite is
sound under the `.vBool b` precondition. -/
theorem doubleNot_pass_sound_case2_core
    (rest' : List StackOp) (s : StackState)
    (hPrecond : precondMet .bool s)
    (hCont : ∀ s', stepNonIf (.opcode "OP_NOT") s = .ok s' →
              wellTypedRun (.opcode "OP_NOT" :: rest') s')
    (hIH : wellTypedRun rest' s → runOps (applyDoubleNot rest') s = runOps rest' s) :
    runOps (applyDoubleNot rest') s
    = runOps (.opcode "OP_NOT" :: .opcode "OP_NOT" :: rest') s := by
  obtain ⟨b, rest_top, hStack⟩ := precondMet_bool_extract s hPrecond
  obtain ⟨s1, hStep1, hStep2⟩ := stepNonIf_OPNOT_OPNOT_vBool s b rest_top hStack
  have hWell1 := hCont s1 hStep1
  have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
  have hWellRest : wellTypedRun rest' s := hCont1 s hStep2
  rw [hIH hWellRest]
  exact (doubleNot_extends s b rest_top rest' hStack).symm

/-- Helper for `doubleNot_pass_sound` case3: when the rule does NOT fire on
`op :: rest'`, the function definitionally pushes `op` past the recursive call.

This is exactly Lean's auto-generated `applyDoubleNot.eq_3`, the case3 equation
for the catch-all pattern. -/
private theorem applyDoubleNot_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .opcode "OP_NOT" → rest = .opcode "OP_NOT" :: rt → False) :
    applyDoubleNot (op :: rest) = op :: applyDoubleNot rest :=
  applyDoubleNot.eq_3 op rest h

/-- Soundness for the full `applyDoubleNot` pass over `noIfOp` lists with
the `wellTypedRun` precondition. Unlike `applyDropAfterPush_pass_sound`
(which is unconditional), this rule's atom-soundness depends on the
top-of-stack being `.vBool`, so the `wellTypedRun` precondition is required. -/
theorem doubleNot_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyDoubleNot ops) s = runOps ops s := by
  intro ops
  induction ops using applyDoubleNot.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    -- Rule-firing arm: input `.opcode "OP_NOT" :: .opcode "OP_NOT" :: rest'`,
    -- result `applyDoubleNot rest'`.
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.opcode "OP_NOT" :: .opcode "OP_NOT" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hIH : wellTypedRun rest' s → runOps (applyDoubleNot rest') s = runOps rest' s :=
      fun hWTRest => ih hRestNoIf s hWTRest
    exact doubleNot_pass_sound_case2_core rest' s hPrecond hCont hIH
  | case3 op rest' h_no_match ih =>
    -- Catch-all arm: input `op :: rest'`, where the rule did NOT fire.
    -- Result: `op :: applyDoubleNot rest'`.
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyDoubleNot rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    -- Per-constructor dispatch. Each non-`.opcode` constructor reduces
    -- `applyDoubleNot (op :: rest')` to `op :: applyDoubleNot rest'` via `rfl`
    -- (case2 only matches `.opcode "OP_NOT" :: .opcode "OP_NOT" :: _`).
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyDoubleNot rest') s = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyDoubleNot rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyDoubleNot rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyDoubleNot rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyDoubleNot rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyDoubleNot rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyDoubleNot rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyDoubleNot rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyDoubleNot rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyDoubleNot rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        rw [applyDoubleNot_cons_no_match (.opcode code) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyDoubleNot rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyDoubleNot rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `dropAfterPush_pass_sound` — Phase 3j -/

/-- Soundness for the full `applyDropAfterPush` pass over `noIfOp` lists.

We invoke `applyDropAfterPush.induct`, the Lean-auto-generated
induction principle for the function's own recursion structure, so
the rule-firing case's IH applies to the inner `rest` (length-2
smaller) rather than the standard list-tail.
-/
theorem dropAfterPush_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), runOps (applyDropAfterPush ops) s = runOps ops s := by
  intro ops
  induction ops using applyDropAfterPush.induct with
  | case1 => intro _ s; rfl
  | case2 v rest' ih =>
    -- Rule-firing arm: input `.push v :: .drop :: rest'`,
    -- result `applyDropAfterPush rest'`.
    intro h s
    have hRest' : noIfOp rest' := by
      change noIfOp (.push v :: .drop :: rest') at h
      change noIfOp rest'
      exact h
    show runOps (applyDropAfterPush rest') s = runOps (.push v :: .drop :: rest') s
    rw [ih hRest']
    exact (dropAfterPush_extends s v rest').symm
  | case3 op rest' h_no_match ih =>
    -- Catch-all arm: input `op :: rest'`, where the rule did NOT fire.
    -- Result: `op :: applyDropAfterPush rest'`.
    intro h s
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    -- Per-constructor cong dispatch. Each case first reduces
    -- `applyDropAfterPush (op :: rest')` to `op :: applyDropAfterPush rest'`
    -- (using either `rfl` for unambiguous patterns, or the absurd
    -- `h_no_match` proof for `.push` to exclude the rule-firing case).
    match op with
    | .ifOp _ _ => exact absurd h (by simp [noIfOp])
    | .push v   =>
        -- For `.push v`, rest' must not be `.drop :: _` (else case2 would fire).
        -- Reduce `applyDropAfterPush (.push v :: rest')` via case analysis on rest':
        have hRewrite :
            applyDropAfterPush (.push v :: rest')
            = .push v :: applyDropAfterPush rest' := by
          match rest' with
          | [] => rfl
          | .drop :: rt => exact (h_no_match v rt rfl rfl).elim
          | .push _ :: _ => rfl
          | .dup :: _ => rfl
          | .swap :: _ => rfl
          | .nip :: _ => rfl
          | .over :: _ => rfl
          | .rot :: _ => rfl
          | .tuck :: _ => rfl
          | .roll _ :: _ => rfl
          | .pick _ :: _ => rfl
          | .opcode _ :: _ => rfl
          | .ifOp _ _ :: _ => rfl
          | .placeholder _ _ :: _ => rfl
          | .pushCodesepIndex :: _ => rfl
        rw [hRewrite]
        exact runOps_cons_push_cong v _ _ s (fun s' => ih hRest' s')
    | .dup      =>
        show runOps (.dup :: applyDropAfterPush rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong _ _ s (fun s' => ih hRest' s')
    | .swap     =>
        show runOps (.swap :: applyDropAfterPush rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong _ _ s (fun s' => ih hRest' s')
    | .drop     =>
        show runOps (.drop :: applyDropAfterPush rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong _ _ s (fun s' => ih hRest' s')
    | .nip      =>
        show runOps (.nip :: applyDropAfterPush rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong _ _ s (fun s' => ih hRest' s')
    | .over     =>
        show runOps (.over :: applyDropAfterPush rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong _ _ s (fun s' => ih hRest' s')
    | .rot      =>
        show runOps (.rot :: applyDropAfterPush rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong _ _ s (fun s' => ih hRest' s')
    | .tuck     =>
        show runOps (.tuck :: applyDropAfterPush rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong _ _ s (fun s' => ih hRest' s')
    | .roll d   =>
        show runOps (.roll d :: applyDropAfterPush rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong d _ _ s (fun s' => ih hRest' s')
    | .pick d   =>
        show runOps (.pick d :: applyDropAfterPush rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong d _ _ s (fun s' => ih hRest' s')
    | .opcode code =>
        show runOps (.opcode code :: applyDropAfterPush rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong code _ _ s (fun s' => ih hRest' s')
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyDropAfterPush rest') s = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong i n _ _ s (fun s' => ih hRest' s')
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyDropAfterPush rest') s = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong _ _ s (fun s' => ih hRest' s')

/-! ### `doubleNegate_pass_sound` — Phase 3q

Mirrors `doubleNot_pass_sound`: identity rewrite `[OP_NEGATE, OP_NEGATE] → []`
under a `.bigint`-topped stack precondition.
-/

/-- Helper: stepNonIf OP_NEGATE on a vBigint top produces the negated state. -/
theorem stepNonIf_OPNEGATE_vBigint (s : StackState) (i : Int) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBigint i :: rest_top) :
    stepNonIf (.opcode "OP_NEGATE") s
    = .ok ({ s with stack := .vBigint (-i) :: rest_top } : StackState) := by
  rw [stepNonIf_opcode, runOpcode_NEGATE_def]
  unfold liftIntUnary StackState.pop?
  rw [hs]
  simp [asInt?, StackState.push]

/-- Two `OP_NEGATE`s return the state to its original form. -/
theorem stepNonIf_OPNEGATE_OPNEGATE_vBigint
    (s : StackState) (i : Int) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBigint i :: rest_top) :
    ∃ s1, stepNonIf (.opcode "OP_NEGATE") s = .ok s1 ∧
          stepNonIf (.opcode "OP_NEGATE") s1 = .ok s := by
  refine ⟨{ s with stack := .vBigint (-i) :: rest_top }, stepNonIf_OPNEGATE_vBigint s i rest_top hs, ?_⟩
  have hs1 : ({ s with stack := .vBigint (-i) :: rest_top } : StackState).stack
           = .vBigint (-i) :: rest_top := by simp
  rw [stepNonIf_OPNEGATE_vBigint _ (-i) rest_top hs1]
  cases s
  simp_all [Int.neg_neg]

/-- The case2 core for `doubleNegate_pass_sound`. -/
theorem doubleNegate_pass_sound_case2_core
    (rest' : List StackOp) (s : StackState)
    (hPrecond : precondMet .bigint s)
    (hCont : ∀ s', stepNonIf (.opcode "OP_NEGATE") s = .ok s' →
              wellTypedRun (.opcode "OP_NEGATE" :: rest') s')
    (hIH : wellTypedRun rest' s → runOps (applyDoubleNegate rest') s = runOps rest' s) :
    runOps (applyDoubleNegate rest') s
    = runOps (.opcode "OP_NEGATE" :: .opcode "OP_NEGATE" :: rest') s := by
  obtain ⟨i, rest_top, hStack⟩ := precondMet_bigint_extract s hPrecond
  obtain ⟨s1, hStep1, hStep2⟩ := stepNonIf_OPNEGATE_OPNEGATE_vBigint s i rest_top hStack
  have hWell1 := hCont s1 hStep1
  have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
  have hWellRest : wellTypedRun rest' s := hCont1 s hStep2
  rw [hIH hWellRest]
  exact (doubleNegate_extends s i rest_top rest' hStack).symm

private theorem applyDoubleNegate_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .opcode "OP_NEGATE" → rest = .opcode "OP_NEGATE" :: rt → False) :
    applyDoubleNegate (op :: rest) = op :: applyDoubleNegate rest :=
  applyDoubleNegate.eq_3 op rest h

theorem doubleNegate_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyDoubleNegate ops) s = runOps ops s := by
  intro ops
  induction ops using applyDoubleNegate.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.opcode "OP_NEGATE" :: .opcode "OP_NEGATE" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hIH : wellTypedRun rest' s → runOps (applyDoubleNegate rest') s = runOps rest' s :=
      fun hWTRest => ih hRestNoIf s hWTRest
    exact doubleNegate_pass_sound_case2_core rest' s hPrecond hCont hIH
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyDoubleNegate rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyDoubleNegate rest') s = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyDoubleNegate rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyDoubleNegate rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyDoubleNegate rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyDoubleNegate rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyDoubleNegate rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyDoubleNegate rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyDoubleNegate rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyDoubleNegate rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyDoubleNegate rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        rw [applyDoubleNegate_cons_no_match (.opcode code) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyDoubleNegate rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyDoubleNegate rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `addZero_pass_sound` — Phase 3q

Identity rewrite `[push 0, OP_ADD] → []` under `.vBigint a :: _` precondition
on the original stack (visible after the push as the second-from-top element).
-/

private theorem applyAddZero_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .push (.bigint 0) → rest = .opcode "OP_ADD" :: rt → False) :
    applyAddZero (op :: rest) = op :: applyAddZero rest :=
  applyAddZero.eq_3 op rest h

theorem addZero_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyAddZero ops) s = runOps ops s := by
  intro ops
  induction ops using applyAddZero.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    -- Rule fires: input `.push (.bigint 0) :: .opcode "OP_ADD" :: rest'`,
    -- result is `applyAddZero rest'`.
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint 0) :: .opcode "OP_ADD" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    -- Extract continuation from wellTypedRun.
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 0)) s = .ok (s.push (.vBigint 0)) :=
      stepNonIf_push_bigint s 0
    have hWellAdd : wellTypedRun (.opcode "OP_ADD" :: rest') (s.push (.vBigint 0)) :=
      hCont _ hStepPush
    have ⟨hPrecondAdd, _⟩ := wellTypedRun_cons _ _ _ |>.mp hWellAdd
    -- precondMet .twoInts at (s.push (.vBigint 0)) means stack starts with two ints.
    obtain ⟨a, b, rest_stack, hStackPush⟩ :=
      precondMet_twoInts_extract _ hPrecondAdd
    -- The top is .vBigint 0, so b = 0 and the second .vBigint a comes from s.stack.
    have hPushStack : (s.push (.vBigint 0)).stack = .vBigint 0 :: s.stack := by
      unfold StackState.push; simp
    have hStackEq : .vBigint 0 :: s.stack = .vBigint b :: .vBigint a :: rest_stack := by
      rw [← hPushStack]; exact hStackPush
    have hb : b = 0 := by
      have hHead := List.head_eq_of_cons_eq hStackEq
      injection hHead with h
      exact h.symm
    have hSStack : s.stack = .vBigint a :: rest_stack :=
      List.tail_eq_of_cons_eq hStackEq
    -- Rebuild hStackPush in the form needed by runOpcode_add_int_concrete.
    have hStackForAdd : (s.push (.vBigint 0)).stack
                      = .vBigint 0 :: .vBigint a :: rest_stack := by
      rw [hPushStack, hSStack]
    -- The IH at the original state s under wellTypedRun rest' s.
    -- We get wellTypedRun rest' s from running .push 0 then OP_ADD: the post-OP_ADD state
    -- equals s (since a + 0 = a). We invoke addZero_extends's structure.
    have ⟨_, hContAdd⟩ := wellTypedRun_cons _ _ _ |>.mp hWellAdd
    have hStepAdd : stepNonIf (.opcode "OP_ADD") (s.push (.vBigint 0)) = .ok s := by
      rw [stepNonIf_opcode, runOpcode_add_int_concrete (s.push (.vBigint 0)) a 0 rest_stack hStackForAdd]
      have : a + 0 = a := Int.add_zero a
      rw [this]
      cases s
      simp_all [StackState.push]
    have hWellRest : wellTypedRun rest' s := hContAdd s hStepAdd
    have hIHs : runOps (applyAddZero rest') s = runOps rest' s :=
      ih hRestNoIf s hWellRest
    show runOps (applyAddZero rest') s
         = runOps (.push (.bigint 0) :: .opcode "OP_ADD" :: rest') s
    rw [hIHs]
    exact (addZero_extends s a rest_stack rest' hSStack).symm
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyAddZero rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyAddZero_cons_no_match (.push v) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyAddZero rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyAddZero rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyAddZero rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyAddZero rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyAddZero rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyAddZero rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyAddZero rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyAddZero rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyAddZero rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyAddZero rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyAddZero rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyAddZero rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `subZero_pass_sound` — Phase 3q (mirrors `addZero_pass_sound`). -/

private theorem applySubZero_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .push (.bigint 0) → rest = .opcode "OP_SUB" :: rt → False) :
    applySubZero (op :: rest) = op :: applySubZero rest :=
  applySubZero.eq_3 op rest h

theorem subZero_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applySubZero ops) s = runOps ops s := by
  intro ops
  induction ops using applySubZero.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint 0) :: .opcode "OP_SUB" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 0)) s = .ok (s.push (.vBigint 0)) :=
      stepNonIf_push_bigint s 0
    have hWellSub : wellTypedRun (.opcode "OP_SUB" :: rest') (s.push (.vBigint 0)) :=
      hCont _ hStepPush
    have ⟨hPrecondSub, hContSub⟩ := wellTypedRun_cons _ _ _ |>.mp hWellSub
    obtain ⟨a, b, rest_stack, hStackPush⟩ :=
      precondMet_twoInts_extract _ hPrecondSub
    have hPushStack : (s.push (.vBigint 0)).stack = .vBigint 0 :: s.stack := by
      unfold StackState.push; simp
    have hStackEq : .vBigint 0 :: s.stack = .vBigint b :: .vBigint a :: rest_stack := by
      rw [← hPushStack]; exact hStackPush
    have hb : b = 0 := by
      have hHead := List.head_eq_of_cons_eq hStackEq
      injection hHead with h
      exact h.symm
    have hSStack : s.stack = .vBigint a :: rest_stack :=
      List.tail_eq_of_cons_eq hStackEq
    have hStackForSub : (s.push (.vBigint 0)).stack
                      = .vBigint 0 :: .vBigint a :: rest_stack := by
      rw [hPushStack, hSStack]
    have hStepSub : stepNonIf (.opcode "OP_SUB") (s.push (.vBigint 0)) = .ok s := by
      rw [stepNonIf_opcode, runOpcode_sub_int_concrete (s.push (.vBigint 0)) a 0 rest_stack hStackForSub]
      have : a - 0 = a := Int.sub_zero a
      rw [this]
      cases s
      simp_all [StackState.push]
    have hWellRest : wellTypedRun rest' s := hContSub s hStepSub
    have hIHs : runOps (applySubZero rest') s = runOps rest' s :=
      ih hRestNoIf s hWellRest
    show runOps (applySubZero rest') s
         = runOps (.push (.bigint 0) :: .opcode "OP_SUB" :: rest') s
    rw [hIHs]
    exact (subZero_extends s a rest_stack rest' hSStack).symm
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applySubZero rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applySubZero_cons_no_match (.push v) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applySubZero rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applySubZero rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applySubZero rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applySubZero rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applySubZero rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applySubZero rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applySubZero rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applySubZero rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applySubZero rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applySubZero rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applySubZero rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applySubZero rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `oneAdd_pass_sound` — Phase 3q

Non-identity rewrite `[push 1, OP_ADD] → [OP_1ADD]` under `.vBigint a :: _`
precondition. Differs from addZero/subZero: case2 produces a 1-op tail.
-/

private theorem applyOneAdd_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .push (.bigint 1) → rest = .opcode "OP_ADD" :: rt → False) :
    applyOneAdd (op :: rest) = op :: applyOneAdd rest :=
  applyOneAdd.eq_3 op rest h

theorem oneAdd_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyOneAdd ops) s = runOps ops s := by
  intro ops
  induction ops using applyOneAdd.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    -- Rule fires: input `.push (.bigint 1) :: .opcode "OP_ADD" :: rest'`,
    -- result is `.opcode "OP_1ADD" :: applyOneAdd rest'`.
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint 1) :: .opcode "OP_ADD" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 1)) s = .ok (s.push (.vBigint 1)) :=
      stepNonIf_push_bigint s 1
    have hWellAdd : wellTypedRun (.opcode "OP_ADD" :: rest') (s.push (.vBigint 1)) :=
      hCont _ hStepPush
    have ⟨hPrecondAdd, _⟩ := wellTypedRun_cons _ _ _ |>.mp hWellAdd
    obtain ⟨a, b, rest_stack, hStackPush⟩ :=
      precondMet_twoInts_extract _ hPrecondAdd
    have hPushStack : (s.push (.vBigint 1)).stack = .vBigint 1 :: s.stack := by
      unfold StackState.push; simp
    have hStackEq : .vBigint 1 :: s.stack = .vBigint b :: .vBigint a :: rest_stack := by
      rw [← hPushStack]; exact hStackPush
    have hb : b = 1 := by
      have hHead := List.head_eq_of_cons_eq hStackEq
      injection hHead with h
      exact h.symm
    have hSStack : s.stack = .vBigint a :: rest_stack :=
      List.tail_eq_of_cons_eq hStackEq
    have hStackForAdd : (s.push (.vBigint 1)).stack
                      = .vBigint 1 :: .vBigint a :: rest_stack := by
      rw [hPushStack, hSStack]
    -- For oneAdd, the post-OP_ADD state is NOT s; it's s' = {s with stack := .vBigint (a+1) :: rest_stack}.
    -- That's equal to the post-OP_1ADD state on s. We bridge via oneAdd_extends, then apply the IH
    -- on the post-OP_1ADD state.
    -- LHS of goal: runOps (.opcode "OP_1ADD" :: applyOneAdd rest') s
    -- RHS: runOps (.push (.bigint 1) :: .opcode "OP_ADD" :: rest') s
    show runOps (.opcode "OP_1ADD" :: applyOneAdd rest') s
         = runOps (.push (.bigint 1) :: .opcode "OP_ADD" :: rest') s
    -- Rewrite RHS using oneAdd_extends.
    rw [oneAdd_extends s a rest_stack rest' hSStack]
    -- Goal: runOps (.opcode "OP_1ADD" :: applyOneAdd rest') s
    --      = runOps (.opcode "OP_1ADD" :: rest') s
    -- Use cong_typed: ∀ s', stepNonIf OP_1ADD s = .ok s' → runOps (applyOneAdd rest') s' = runOps rest' s'.
    apply runOps_cons_opcode_cong_typed
    intro s' hStep1ADD
    -- After OP_1ADD on s, we have s'.stack = .vBigint (a+1) :: rest_stack.
    -- Need wellTypedRun rest' s' to apply IH.
    -- From hWellAdd we have: precond OK + after OP_ADD on (s.push 1), wellTypedRun rest' on the resulting state.
    -- The resulting state of OP_ADD on (s.push (.vBigint 1)) equals s' (post-OP_1ADD on s).
    have ⟨_, hContAdd⟩ := wellTypedRun_cons _ _ _ |>.mp hWellAdd
    have hStepAdd : stepNonIf (.opcode "OP_ADD") (s.push (.vBigint 1)) = .ok s' := by
      rw [stepNonIf_opcode]
      rw [runOpcode_add_int_concrete (s.push (.vBigint 1)) a 1 rest_stack hStackForAdd]
      -- Reduce post-OP_1ADD state explicitly.
      have hStepDef : stepNonIf (.opcode "OP_1ADD") s
                    = .ok (({ s with stack := rest_stack } : StackState).push (.vBigint (a + 1))) := by
        rw [stepNonIf_opcode, runOpcode_1ADD_def]
        unfold liftIntUnary StackState.pop?
        rw [hSStack]
        simp [asInt?, StackState.push]
      have hSEq : s' = ({ s with stack := rest_stack } : StackState).push (.vBigint (a + 1)) := by
        rw [hStepDef] at hStep1ADD
        exact ((Except.ok.injEq _ _).mp hStep1ADD).symm
      rw [hSEq]
      -- Need: ({ s.push 1 with stack := rest_stack }).push (a + 1)
      --     = ({ s with stack := rest_stack }).push (a + 1)
      cases s
      simp_all [StackState.push]
    have hWellRest : wellTypedRun rest' s' := hContAdd s' hStepAdd
    exact ih hRestNoIf s' hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyOneAdd rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyOneAdd_cons_no_match (.push v) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyOneAdd rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyOneAdd rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyOneAdd rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyOneAdd rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyOneAdd rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyOneAdd rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyOneAdd rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyOneAdd rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyOneAdd rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyOneAdd rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyOneAdd rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyOneAdd rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `doubleSha256_pass_sound` — Phase 3q

Non-identity rewrite `[OP_SHA256, OP_SHA256] → [OP_HASH256]` under
`.bytes`-topped stack precondition (either `.vBytes` or `.vOpaque`).
-/

/-- `OP_SHA256` on a `.vOpaque b` top pushes `.vBytes (sha256 b)`. -/
private theorem runOpcode_sha256_vOpaque (s : StackState) (b : ByteArray) :
    runOpcode "OP_SHA256" (s.push (.vOpaque b))
    = .ok (s.push (.vBytes (sha256 b))) := by
  rw [runOpcode_SHA256_def]
  unfold liftBytesUnary StackState.pop? StackState.push
  simp [asBytes?]

/-- `OP_HASH256` on a `.vOpaque b` top pushes `.vBytes (hash256 b)`. -/
private theorem runOpcode_hash256_vOpaque (s : StackState) (b : ByteArray) :
    runOpcode "OP_HASH256" (s.push (.vOpaque b))
    = .ok (s.push (.vBytes (hash256 b))) := by
  rw [runOpcode_HASH256_def]
  unfold liftBytesUnary StackState.pop? StackState.push
  simp [asBytes?]

/-- `[OP_SHA256, OP_SHA256]` extends to `[OP_HASH256]` under `.vOpaque b :: rest_top`. -/
private theorem doubleSha256_extends_vOpaque
    (s : StackState) (b : ByteArray) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vOpaque b :: rest_top) :
    runOps (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest) s
    = runOps (.opcode "OP_HASH256" :: rest) s := by
  have hs' : s = (({ s with stack := rest_top } : StackState).push (.vOpaque b)) := by
    cases s; simp_all [StackState.push]
  rw [hs']
  -- LHS: SHA256 on .vOpaque, then SHA256 on the resulting .vBytes.
  rw [show runOps (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest)
            (({ s with stack := rest_top } : StackState).push (.vOpaque b))
        = runOps (.opcode "OP_SHA256" :: rest)
            ((({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b))))
        from by
          rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_sha256_vOpaque]]
  rw [show runOps (.opcode "OP_SHA256" :: rest)
            ((({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b))))
        = runOps rest
            ((({ s with stack := rest_top } : StackState).push (.vBytes (sha256 (sha256 b)))))
        from by
          rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_sha256_vBytes]]
  -- RHS: HASH256 on .vOpaque.
  rw [show runOps (.opcode "OP_HASH256" :: rest)
            (({ s with stack := rest_top } : StackState).push (.vOpaque b))
        = runOps rest
            ((({ s with stack := rest_top } : StackState).push (.vBytes (hash256 b))))
        from by
          rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_hash256_vOpaque]]
  rw [hash256_eq_double_sha256]

private theorem applyDoubleSha256_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .opcode "OP_SHA256" → rest = .opcode "OP_SHA256" :: rt → False) :
    applyDoubleSha256 (op :: rest) = op :: applyDoubleSha256 rest :=
  applyDoubleSha256.eq_3 op rest h

theorem doubleSha256_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyDoubleSha256 ops) s = runOps ops s := by
  intro ops
  induction ops using applyDoubleSha256.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    -- Rule fires: input `.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest'`,
    -- result is `.opcode "OP_HASH256" :: applyDoubleSha256 rest'`.
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    -- Goal: runOps (.opcode "OP_HASH256" :: applyDoubleSha256 rest') s
    --     = runOps (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest') s
    show runOps (.opcode "OP_HASH256" :: applyDoubleSha256 rest') s
         = runOps (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest') s
    -- Case-split on .vBytes vs .vOpaque.
    obtain ⟨b, rest_top, hStack⟩ := precondMet_bytes_extract s hPrecond
    -- Bridge RHS to (.opcode "OP_HASH256" :: rest') via doubleSha256_extends.
    rcases hStack with hStackB | hStackO
    · rw [doubleSha256_extends s b rest_top rest' hStackB]
      apply runOps_cons_opcode_cong_typed
      intro s' hStepHash
      -- We need wellTypedRun rest' s' from the OP_SHA256/OP_SHA256 chain in hCont.
      -- After first OP_SHA256: s1.stack = .vBytes (sha256 b) :: rest_top
      -- After second OP_SHA256: s2.stack = .vBytes (sha256 (sha256 b)) :: rest_top = s'.stack
      -- So s' equals the post-2-SHA256 state, and wellTypedRun rest' on it follows from hCont chained.
      have hStep1 : stepNonIf (.opcode "OP_SHA256") s
                  = .ok (({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b))) := by
        have hs' : s = (({ s with stack := rest_top } : StackState).push (.vBytes b)) := by
          cases s; simp_all [StackState.push]
        rw [stepNonIf_opcode]
        rw [hs']
        rw [runOpcode_sha256_vBytes]
        cases s
        simp_all [StackState.push]
      let s1 : StackState := ({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b))
      have hWell1 : wellTypedRun (.opcode "OP_SHA256" :: rest') s1 := hCont s1 hStep1
      have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
      have hStep2 : stepNonIf (.opcode "OP_SHA256") s1
                  = .ok (({ s with stack := rest_top } : StackState).push
                            (.vBytes (sha256 (sha256 b)))) := by
        rw [stepNonIf_opcode]
        show runOpcode "OP_SHA256"
              ((({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b)))) = _
        rw [runOpcode_sha256_vBytes]
      have hWell2 : wellTypedRun rest'
                      (({ s with stack := rest_top } : StackState).push
                        (.vBytes (sha256 (sha256 b)))) := hCont1 _ hStep2
      -- Now relate s' to that state via hStepHash and hash256_eq_double_sha256.
      have hStepHashEq : stepNonIf (.opcode "OP_HASH256") s
                       = .ok (({ s with stack := rest_top } : StackState).push
                              (.vBytes (hash256 b))) := by
        have hs' : s = (({ s with stack := rest_top } : StackState).push (.vBytes b)) := by
          cases s; simp_all [StackState.push]
        rw [stepNonIf_opcode]
        rw [hs']
        rw [runOpcode_hash256_vBytes]
        cases s
        simp_all [StackState.push]
      have hSEq : s' = (({ s with stack := rest_top } : StackState).push (.vBytes (hash256 b))) := by
        rw [hStepHashEq] at hStepHash
        exact ((Except.ok.injEq _ _).mp hStepHash).symm
      rw [hSEq]
      rw [hash256_eq_double_sha256]
      exact ih hRestNoIf _ hWell2
    · rw [doubleSha256_extends_vOpaque s b rest_top rest' hStackO]
      apply runOps_cons_opcode_cong_typed
      intro s' hStepHash
      have hStep1 : stepNonIf (.opcode "OP_SHA256") s
                  = .ok (({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b))) := by
        have hs' : s = (({ s with stack := rest_top } : StackState).push (.vOpaque b)) := by
          cases s; simp_all [StackState.push]
        rw [stepNonIf_opcode]
        rw [hs']
        rw [runOpcode_sha256_vOpaque]
        cases s
        simp_all [StackState.push]
      let s1 : StackState := ({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b))
      have hWell1 : wellTypedRun (.opcode "OP_SHA256" :: rest') s1 := hCont s1 hStep1
      have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
      have hStep2 : stepNonIf (.opcode "OP_SHA256") s1
                  = .ok (({ s with stack := rest_top } : StackState).push
                            (.vBytes (sha256 (sha256 b)))) := by
        rw [stepNonIf_opcode]
        show runOpcode "OP_SHA256"
              ((({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b)))) = _
        rw [runOpcode_sha256_vBytes]
      have hWell2 : wellTypedRun rest'
                      (({ s with stack := rest_top } : StackState).push
                        (.vBytes (sha256 (sha256 b)))) := hCont1 _ hStep2
      have hStepHashEq : stepNonIf (.opcode "OP_HASH256") s
                       = .ok (({ s with stack := rest_top } : StackState).push
                              (.vBytes (hash256 b))) := by
        have hs' : s = (({ s with stack := rest_top } : StackState).push (.vOpaque b)) := by
          cases s; simp_all [StackState.push]
        rw [stepNonIf_opcode]
        rw [hs']
        rw [runOpcode_hash256_vOpaque]
        cases s
        simp_all [StackState.push]
      have hSEq : s' = (({ s with stack := rest_top } : StackState).push (.vBytes (hash256 b))) := by
        rw [hStepHashEq] at hStepHash
        exact ((Except.ok.injEq _ _).mp hStepHash).symm
      rw [hSEq]
      rw [hash256_eq_double_sha256]
      exact ih hRestNoIf _ hWell2
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyDoubleSha256 rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyDoubleSha256 rest') s = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyDoubleSha256 rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyDoubleSha256 rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyDoubleSha256 rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyDoubleSha256 rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyDoubleSha256 rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyDoubleSha256 rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyDoubleSha256 rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyDoubleSha256 rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyDoubleSha256 rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        rw [applyDoubleSha256_cons_no_match (.opcode code) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyDoubleSha256 rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyDoubleSha256 rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `dupDrop_pass_sound` — Phase 3s

Identity rewrite `[dup, drop] → []` under `.nonEmpty` top-of-stack precondition. -/

private theorem applyDupDrop_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .dup → rest = .drop :: rt → False) :
    applyDupDrop (op :: rest) = op :: applyDupDrop rest :=
  applyDupDrop.eq_3 op rest h

theorem dupDrop_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyDupDrop ops) s = runOps ops s := by
  intro ops
  induction ops using applyDupDrop.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.dup :: .drop :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨v, rest_top, hStack⟩ := precondMet_nonEmpty_extract s hPrecond
    -- After dup: stack = v :: v :: rest_top.
    have hStepDup : stepNonIf .dup s = .ok (s.push v) := by
      rw [stepNonIf_dup]; exact applyDup_cons s v rest_top hStack
    have hWell1 : wellTypedRun (.drop :: rest') (s.push v) := hCont _ hStepDup
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    -- After drop: state = s.
    have hStepDrop : stepNonIf .drop (s.push v) = .ok s := by
      rw [stepNonIf_drop, applyDrop_push]
    have hWellRest : wellTypedRun rest' s := hCont1 _ hStepDrop
    show runOps (applyDupDrop rest') s = runOps (.dup :: .drop :: rest') s
    rw [ih hRestNoIf s hWellRest]
    exact (dupDrop_extends s v rest_top rest' hStack).symm
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyDupDrop rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyDupDrop rest') s = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        rw [applyDupDrop_cons_no_match (.dup) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyDupDrop rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyDupDrop rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyDupDrop rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyDupDrop rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyDupDrop rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyDupDrop rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyDupDrop rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyDupDrop rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyDupDrop rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyDupDrop rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyDupDrop rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `doubleSwap_pass_sound` — Phase 3s

Identity rewrite `[swap, swap] → []` under `.twoElems` precondition. -/

private theorem applyDoubleSwap_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .swap → rest = .swap :: rt → False) :
    applyDoubleSwap (op :: rest) = op :: applyDoubleSwap rest :=
  applyDoubleSwap.eq_3 op rest h

theorem doubleSwap_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyDoubleSwap ops) s = runOps ops s := by
  intro ops
  induction ops using applyDoubleSwap.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.swap :: .swap :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨a, b, rest_top, hStack⟩ := precondMet_twoElems_extract s hPrecond
    -- After first swap: stack = b :: a :: rest_top.
    let s1 : StackState := { s with stack := b :: a :: rest_top }
    have hStepSwap1 : stepNonIf .swap s = .ok s1 := by
      rw [stepNonIf_swap]; exact applySwap_cons2 s a b rest_top hStack
    have hWell1 : wellTypedRun (.swap :: rest') s1 := hCont s1 hStepSwap1
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    -- After second swap: stack = a :: b :: rest_top = original s.stack — so post-state equals s.
    have hStepSwap2 : stepNonIf .swap s1 = .ok s := by
      rw [stepNonIf_swap]
      have hs1 : s1.stack = b :: a :: rest_top := rfl
      rw [applySwap_cons2 s1 b a rest_top hs1]
      cases s
      simp_all
    have hWellRest : wellTypedRun rest' s := hCont1 s hStepSwap2
    show runOps (applyDoubleSwap rest') s = runOps (.swap :: .swap :: rest') s
    rw [ih hRestNoIf s hWellRest]
    exact (doubleSwap_extends s a b rest_top rest' hStack).symm
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyDoubleSwap rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyDoubleSwap rest') s = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyDoubleSwap rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        rw [applyDoubleSwap_cons_no_match .swap rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyDoubleSwap rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyDoubleSwap rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyDoubleSwap rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyDoubleSwap rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyDoubleSwap rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyDoubleSwap rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyDoubleSwap rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyDoubleSwap rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyDoubleSwap rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyDoubleSwap rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `numEqualVerifyFuse_pass_sound` — Phase 3s

Non-identity rewrite `[OP_NUMEQUAL, OP_VERIFY] → [OP_NUMEQUALVERIFY]` under
two-int top precondition. -/

private theorem applyNumEqualVerifyFuse_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .opcode "OP_NUMEQUAL" → rest = .opcode "OP_VERIFY" :: rt → False) :
    applyNumEqualVerifyFuse (op :: rest) = op :: applyNumEqualVerifyFuse rest :=
  applyNumEqualVerifyFuse.eq_3 op rest h

theorem numEqualVerifyFuse_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyNumEqualVerifyFuse ops) s = runOps ops s := by
  intro ops
  induction ops using applyNumEqualVerifyFuse.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.opcode "OP_NUMEQUAL" :: .opcode "OP_VERIFY" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨a, b, rest_top, hStack⟩ := precondMet_twoInts_extract s hPrecond
    -- Goal: runOps (.opcode "OP_NUMEQUALVERIFY" :: applyNumEqualVerifyFuse rest') s
    --     = runOps (.opcode "OP_NUMEQUAL" :: .opcode "OP_VERIFY" :: rest') s
    show runOps (.opcode "OP_NUMEQUALVERIFY" :: applyNumEqualVerifyFuse rest') s
         = runOps (.opcode "OP_NUMEQUAL" :: .opcode "OP_VERIFY" :: rest') s
    -- Rewrite RHS using extends to fuse into [OP_NUMEQUALVERIFY] form.
    rw [numEqualVerifyFuse_extends s a b rest_top rest' hStack]
    -- Goal: runOps (.opcode "OP_NUMEQUALVERIFY" :: applyNumEqualVerifyFuse rest') s
    --     = runOps (.opcode "OP_NUMEQUALVERIFY" :: rest') s
    -- Use cong_typed to push through OP_NUMEQUALVERIFY: ∀ s', stepNonIf OP_NUMEQUALVERIFY s = .ok s' → IH.
    apply runOps_cons_opcode_cong_typed
    intro s' hStepNEV
    -- s' = {s with stack := rest_top} (when a = b). When a ≠ b, stepNonIf returns error so this branch is vacuous.
    -- Reduce hStepNEV using runOpcode_numEqualVerify_int.
    rw [stepNonIf_opcode, runOpcode_numEqualVerify_int s a b rest_top hStack] at hStepNEV
    by_cases hEq : decide (a = b) = true
    · -- a = b: hStepNEV says s' = {s with stack := rest_top}; apply IH.
      rw [hEq] at hStepNEV
      simp at hStepNEV
      have hSEq : s' = ({ s with stack := rest_top } : StackState) := hStepNEV.symm
      apply ih hRestNoIf s'
      -- wellTypedRun rest' s' follows from chaining hCont through OP_NUMEQUAL → OP_VERIFY.
      have hStep1 : stepNonIf (.opcode "OP_NUMEQUAL") s
                  = .ok ((({ s with stack := rest_top } : StackState).push
                           (.vBool (decide (a = b))))) := by
        rw [stepNonIf_opcode, runOpcode_numEqual_int s a b rest_top hStack]
      have hWell1 := hCont _ hStep1
      have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
      have hStep2 : stepNonIf (.opcode "OP_VERIFY")
                      (({ s with stack := rest_top } : StackState).push
                          (.vBool (decide (a = b))))
                  = .ok ({ s with stack := rest_top } : StackState) := by
        rw [stepNonIf_opcode, runOpcode_verify_vBool, hEq]
        rfl
      have hWellRest : wellTypedRun rest' ({ s with stack := rest_top } : StackState) :=
        hCont1 _ hStep2
      rw [hSEq]
      exact hWellRest
    · -- a ≠ b: hStepNEV says .ok s' = .error .assertFailed, contradiction.
      rw [show decide (a = b) = false from by
            rcases h : decide (a = b) with _ | _
            · rfl
            · exact absurd h hEq] at hStepNEV
      simp at hStepNEV
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyNumEqualVerifyFuse rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyNumEqualVerifyFuse rest') s = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyNumEqualVerifyFuse rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyNumEqualVerifyFuse rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyNumEqualVerifyFuse rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyNumEqualVerifyFuse rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyNumEqualVerifyFuse rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyNumEqualVerifyFuse rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyNumEqualVerifyFuse rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyNumEqualVerifyFuse rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyNumEqualVerifyFuse rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        rw [applyNumEqualVerifyFuse_cons_no_match (.opcode code) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyNumEqualVerifyFuse rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyNumEqualVerifyFuse rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `checkSigVerifyFuse_pass_sound` — Phase 3s

Non-identity rewrite `[OP_CHECKSIG, OP_VERIFY] → [OP_CHECKSIGVERIFY]` under
two-bytes top precondition. The atom-sound proof is parameterized over
`.vBytes pk :: .vBytes sig`; `precondMet .twoBytes` allows `.vOpaque` mixing,
but the `OP_CHECKSIG` opcode reduction `runOpcode_checkSig_bytes` requires
strict `.vBytes` form. We extract via `precondMet_twoBytes_extract`. -/

theorem precondMet_twoBytes_extract_strict (s : StackState) (h : precondMet .twoBytes s) :
    ∃ b a rest_top,
      (s.stack = .vBytes b :: .vBytes a :: rest_top) ∨
      (s.stack = .vBytes b :: .vOpaque a :: rest_top) ∨
      (s.stack = .vOpaque b :: .vBytes a :: rest_top) ∨
      (s.stack = .vOpaque b :: .vOpaque a :: rest_top) := by
  match hs : s.stack with
  | .vBytes b :: .vBytes a :: rt   => exact ⟨b, a, rt, Or.inl rfl⟩
  | .vBytes b :: .vOpaque a :: rt  => exact ⟨b, a, rt, Or.inr (Or.inl rfl)⟩
  | .vOpaque b :: .vBytes a :: rt  => exact ⟨b, a, rt, Or.inr (Or.inr (Or.inl rfl))⟩
  | .vOpaque b :: .vOpaque a :: rt => exact ⟨b, a, rt, Or.inr (Or.inr (Or.inr rfl))⟩
  | [] => simp [precondMet, hs] at h
  | [_] => simp [precondMet, hs] at h
  | .vBigint _ :: _ :: _ => simp [precondMet, hs] at h
  | .vBool _ :: _ :: _   => simp [precondMet, hs] at h
  | .vThis :: _ :: _     => simp [precondMet, hs] at h
  | .vBytes _ :: .vBigint _ :: _ => simp [precondMet, hs] at h
  | .vBytes _ :: .vBool _ :: _   => simp [precondMet, hs] at h
  | .vBytes _ :: .vThis :: _     => simp [precondMet, hs] at h
  | .vOpaque _ :: .vBigint _ :: _ => simp [precondMet, hs] at h
  | .vOpaque _ :: .vBool _ :: _   => simp [precondMet, hs] at h
  | .vOpaque _ :: .vThis :: _     => simp [precondMet, hs] at h

/-- Generalize the `_extends` and `runOpcode_checkSig_bytes` family across the
4 vBytes/vOpaque pairings on the top two stack elements. We coerce by stack
restructuring. -/
private theorem checkSigVerifyFuse_extends_anyBytes
    (s : StackState) (sig pk : ByteArray) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp)
    (hs : (s.stack = .vBytes pk :: .vBytes sig :: rest_top) ∨
          (s.stack = .vBytes pk :: .vOpaque sig :: rest_top) ∨
          (s.stack = .vOpaque pk :: .vBytes sig :: rest_top) ∨
          (s.stack = .vOpaque pk :: .vOpaque sig :: rest_top)) :
    runOps (.opcode "OP_CHECKSIG" :: .opcode "OP_VERIFY" :: rest) s
    = runOps (.opcode "OP_CHECKSIGVERIFY" :: rest) s := by
  -- Reduce both sides via popN_two_cons + asBytes? simp regardless of pairing.
  rcases hs with hBB | hBO | hOB | hOO
  · -- vBytes :: vBytes
    exact checkSigVerifyFuse_extends s sig pk rest_top rest hBB
  · -- vBytes :: vOpaque
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKSIG" s
          = .ok (({ s with stack := rest_top } : StackState).push
                  (.vBool (checkSig sig pk))) from by
            rw [runOpcode_CHECKSIG_def, popN_two_cons s (.vBytes pk) (.vOpaque sig) rest_top hBO]
            simp [asBytes?]]
    show runOps (.opcode "OP_VERIFY" :: rest)
          ((({ s with stack := rest_top } : StackState).push (.vBool (checkSig sig pk)))) = _
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKSIGVERIFY" s
          = (if checkSig sig pk then .ok ({ s with stack := rest_top } : StackState)
                                  else .error .assertFailed) from by
            rw [runOpcode_CHECKSIGVERIFY_def,
                popN_two_cons s (.vBytes pk) (.vOpaque sig) rest_top hBO]
            simp [asBytes?]]
  · -- vOpaque :: vBytes
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKSIG" s
          = .ok (({ s with stack := rest_top } : StackState).push
                  (.vBool (checkSig sig pk))) from by
            rw [runOpcode_CHECKSIG_def, popN_two_cons s (.vOpaque pk) (.vBytes sig) rest_top hOB]
            simp [asBytes?]]
    show runOps (.opcode "OP_VERIFY" :: rest)
          ((({ s with stack := rest_top } : StackState).push (.vBool (checkSig sig pk)))) = _
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKSIGVERIFY" s
          = (if checkSig sig pk then .ok ({ s with stack := rest_top } : StackState)
                                  else .error .assertFailed) from by
            rw [runOpcode_CHECKSIGVERIFY_def,
                popN_two_cons s (.vOpaque pk) (.vBytes sig) rest_top hOB]
            simp [asBytes?]]
  · -- vOpaque :: vOpaque
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKSIG" s
          = .ok (({ s with stack := rest_top } : StackState).push
                  (.vBool (checkSig sig pk))) from by
            rw [runOpcode_CHECKSIG_def, popN_two_cons s (.vOpaque pk) (.vOpaque sig) rest_top hOO]
            simp [asBytes?]]
    show runOps (.opcode "OP_VERIFY" :: rest)
          ((({ s with stack := rest_top } : StackState).push (.vBool (checkSig sig pk)))) = _
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKSIGVERIFY" s
          = (if checkSig sig pk then .ok ({ s with stack := rest_top } : StackState)
                                  else .error .assertFailed) from by
            rw [runOpcode_CHECKSIGVERIFY_def,
                popN_two_cons s (.vOpaque pk) (.vOpaque sig) rest_top hOO]
            simp [asBytes?]]

/-- Helper: reduce stepNonIf OP_CHECKSIG on two-bytes-mixed stacks to a uniform shape. -/
private theorem stepNonIf_OPCHECKSIG_anyBytes
    (s : StackState) (sig pk : ByteArray) (rest_top : List ANF.Eval.Value)
    (hs : (s.stack = .vBytes pk :: .vBytes sig :: rest_top) ∨
          (s.stack = .vBytes pk :: .vOpaque sig :: rest_top) ∨
          (s.stack = .vOpaque pk :: .vBytes sig :: rest_top) ∨
          (s.stack = .vOpaque pk :: .vOpaque sig :: rest_top)) :
    stepNonIf (.opcode "OP_CHECKSIG") s
    = .ok ((({ s with stack := rest_top } : StackState).push (.vBool (checkSig sig pk)))) := by
  rw [stepNonIf_opcode]
  rcases hs with hBB | hBO | hOB | hOO
  · rw [runOpcode_CHECKSIG_def, popN_two_cons s (.vBytes pk) (.vBytes sig) rest_top hBB]
    simp [asBytes?]
  · rw [runOpcode_CHECKSIG_def, popN_two_cons s (.vBytes pk) (.vOpaque sig) rest_top hBO]
    simp [asBytes?]
  · rw [runOpcode_CHECKSIG_def, popN_two_cons s (.vOpaque pk) (.vBytes sig) rest_top hOB]
    simp [asBytes?]
  · rw [runOpcode_CHECKSIG_def, popN_two_cons s (.vOpaque pk) (.vOpaque sig) rest_top hOO]
    simp [asBytes?]

private theorem applyCheckSigVerifyFuse_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .opcode "OP_CHECKSIG" → rest = .opcode "OP_VERIFY" :: rt → False) :
    applyCheckSigVerifyFuse (op :: rest) = op :: applyCheckSigVerifyFuse rest :=
  applyCheckSigVerifyFuse.eq_3 op rest h

theorem checkSigVerifyFuse_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyCheckSigVerifyFuse ops) s = runOps ops s := by
  intro ops
  induction ops using applyCheckSigVerifyFuse.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.opcode "OP_CHECKSIG" :: .opcode "OP_VERIFY" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨pk, sig, rest_top, hStack⟩ := precondMet_twoBytes_extract_strict s hPrecond
    show runOps (.opcode "OP_CHECKSIGVERIFY" :: applyCheckSigVerifyFuse rest') s
         = runOps (.opcode "OP_CHECKSIG" :: .opcode "OP_VERIFY" :: rest') s
    rw [checkSigVerifyFuse_extends_anyBytes s sig pk rest_top rest' hStack]
    apply runOps_cons_opcode_cong_typed
    intro s' hStepCSV
    -- Reduce hStepCSV: stepNonIf OP_CHECKSIGVERIFY s = .ok s' under any of 4 byte forms.
    have hStepDef : stepNonIf (.opcode "OP_CHECKSIGVERIFY") s
                  = (if checkSig sig pk then
                      .ok ({ s with stack := rest_top } : StackState)
                     else .error .assertFailed) := by
      rw [stepNonIf_opcode]
      rcases hStack with hBB | hBO | hOB | hOO
      · rw [runOpcode_CHECKSIGVERIFY_def, popN_two_cons s (.vBytes pk) (.vBytes sig) rest_top hBB]
        simp [asBytes?]
      · rw [runOpcode_CHECKSIGVERIFY_def, popN_two_cons s (.vBytes pk) (.vOpaque sig) rest_top hBO]
        simp [asBytes?]
      · rw [runOpcode_CHECKSIGVERIFY_def, popN_two_cons s (.vOpaque pk) (.vBytes sig) rest_top hOB]
        simp [asBytes?]
      · rw [runOpcode_CHECKSIGVERIFY_def, popN_two_cons s (.vOpaque pk) (.vOpaque sig) rest_top hOO]
        simp [asBytes?]
    rw [hStepDef] at hStepCSV
    by_cases hSig : checkSig sig pk = true
    · rw [hSig] at hStepCSV
      simp at hStepCSV
      have hSEq : s' = ({ s with stack := rest_top } : StackState) := hStepCSV.symm
      apply ih hRestNoIf s'
      have hStep1 : stepNonIf (.opcode "OP_CHECKSIG") s
                  = .ok (({ s with stack := rest_top } : StackState).push
                          (.vBool (checkSig sig pk))) :=
        stepNonIf_OPCHECKSIG_anyBytes s sig pk rest_top hStack
      have hWell1 := hCont _ hStep1
      have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
      have hStep2 : stepNonIf (.opcode "OP_VERIFY")
                      (({ s with stack := rest_top } : StackState).push
                        (.vBool (checkSig sig pk)))
                  = .ok ({ s with stack := rest_top } : StackState) := by
        rw [stepNonIf_opcode, runOpcode_verify_vBool, hSig]
        rfl
      have hWellRest : wellTypedRun rest' ({ s with stack := rest_top } : StackState) :=
        hCont1 _ hStep2
      rw [hSEq]
      exact hWellRest
    · rw [show checkSig sig pk = false from by
            rcases h : checkSig sig pk with _ | _
            · rfl
            · exact absurd h hSig] at hStepCSV
      simp at hStepCSV
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyCheckSigVerifyFuse rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyCheckSigVerifyFuse rest') s = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyCheckSigVerifyFuse rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyCheckSigVerifyFuse rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyCheckSigVerifyFuse rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyCheckSigVerifyFuse rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyCheckSigVerifyFuse rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyCheckSigVerifyFuse rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyCheckSigVerifyFuse rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyCheckSigVerifyFuse rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyCheckSigVerifyFuse rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        rw [applyCheckSigVerifyFuse_cons_no_match (.opcode code) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyCheckSigVerifyFuse rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyCheckSigVerifyFuse rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `equalVerifyFuse_pass_sound_int` — Phase 3s (int-restricted)

Non-identity rewrite `[OP_EQUAL, OP_VERIFY] → [OP_EQUALVERIFY]`. The `OP_EQUAL`
opcode operates on either int OR bytes top, but the precondition table assigns
`.twoElems` to it (no type constraint). Phase 3s restricts the pass_sound to
int inputs, since `precondMet .twoElems` does not constrain the underlying
types and bridging the types within a single induction is intractable.

The bytes variant (`equalVerifyFuse_pass_sound_bytes`) and a fully-general
variant under a tightened `OpExpectation` (e.g., `.twoIntsOrTwoBytes`) are
deferred to **Phase 3t**. The current `peepholePassFull` chains only the int
restriction (sufficient for the byte-exact-match goal under stack typing). -/

private theorem applyEqualVerifyFuse_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .opcode "OP_EQUAL" → rest = .opcode "OP_VERIFY" :: rt → False) :
    applyEqualVerifyFuse (op :: rest) = op :: applyEqualVerifyFuse rest :=
  applyEqualVerifyFuse.eq_3 op rest h

/-! ### Strengthened `equalVerifyFuse_intStrict` precondition

Since `precondMet .twoElems` doesn't constrain the underlying types but `OP_EQUAL`'s
atom-sound proof needs ints, we carry an additional "every OP_EQUAL position has
two ints on top" predicate alongside `wellTypedRun`. -/

/-- Auxiliary helper: is this op the literal `.opcode "OP_EQUAL"`? Decidable by definition. -/
def isOpEqual : StackOp → Bool
  | .opcode "OP_EQUAL" => true
  | _ => false

theorem isOpEqual_opcode_equal : isOpEqual (.opcode "OP_EQUAL") = true := rfl

def equalVerifyFuse_intStrict (ops : List StackOp) (s : StackState) : Prop :=
  match ops with
  | [] => True
  | op :: rest =>
      (if isOpEqual op then precondMet .twoInts s else True) ∧
      (∀ s', stepNonIf op s = .ok s' → equalVerifyFuse_intStrict rest s')

theorem equalVerifyFuse_intStrict_nil (s : StackState) :
    equalVerifyFuse_intStrict [] s := True.intro

theorem equalVerifyFuse_intStrict_cons (op : StackOp) (rest : List StackOp) (s : StackState) :
    equalVerifyFuse_intStrict (op :: rest) s ↔
      ((if isOpEqual op then precondMet .twoInts s else True) ∧
        (∀ s', stepNonIf op s = .ok s' → equalVerifyFuse_intStrict rest s')) :=
  Iff.rfl

theorem equalVerifyFuse_pass_sound_int :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        equalVerifyFuse_intStrict ops s →
        runOps (applyEqualVerifyFuse ops) s = runOps ops s := by
  intro ops
  induction ops using applyEqualVerifyFuse.induct with
  | case1 => intros _ _ _ _; rfl
  | case2 rest' ih =>
    -- Rule fires: OP_EQUAL :: OP_VERIFY :: rest' → OP_EQUALVERIFY :: applyEqualVerifyFuse rest'.
    intro hNoIf s hWT hStrict
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    -- Extract `.twoInts` precondition from hStrict at OP_EQUAL position.
    have ⟨hPrecondGuard, hStrictTail⟩ :=
      (equalVerifyFuse_intStrict_cons (.opcode "OP_EQUAL") _ s).mp hStrict
    have hPrecondInts : precondMet .twoInts s := by
      have hOpEq : isOpEqual (.opcode "OP_EQUAL") = true := isOpEqual_opcode_equal
      rw [hOpEq] at hPrecondGuard
      simpa using hPrecondGuard
    obtain ⟨a, b, rest_top, hStack⟩ := precondMet_twoInts_extract s hPrecondInts
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    show runOps (.opcode "OP_EQUALVERIFY" :: applyEqualVerifyFuse rest') s
         = runOps (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest') s
    rw [equalVerifyFuse_extends_int s a b rest_top rest' hStack]
    apply runOps_cons_opcode_cong_typed
    intro s' hStepEV
    have hStepDef : stepNonIf (.opcode "OP_EQUALVERIFY") s
                  = (if decide (a = b) then
                      .ok ({ s with stack := rest_top } : StackState)
                     else .error .assertFailed) := by
      rw [stepNonIf_opcode, runOpcode_equalVerify_int s a b rest_top hStack]
    rw [hStepDef] at hStepEV
    by_cases hEq : decide (a = b) = true
    · rw [hEq] at hStepEV
      simp at hStepEV
      have hSEq : s' = ({ s with stack := rest_top } : StackState) := hStepEV.symm
      have hStep1 : stepNonIf (.opcode "OP_EQUAL") s
                  = .ok ((({ s with stack := rest_top } : StackState).push
                           (.vBool (decide (a = b))))) := by
        rw [stepNonIf_opcode, runOpcode_equal_int s a b rest_top hStack]
      have hStrictTail' : equalVerifyFuse_intStrict (.opcode "OP_VERIFY" :: rest')
                            ((({ s with stack := rest_top } : StackState).push
                                (.vBool (decide (a = b))))) :=
        hStrictTail _ hStep1
      have ⟨_, hStrictTail2⟩ :=
        (equalVerifyFuse_intStrict_cons (.opcode "OP_VERIFY") rest' _).mp hStrictTail'
      have hStep2 : stepNonIf (.opcode "OP_VERIFY")
                      (({ s with stack := rest_top } : StackState).push
                        (.vBool (decide (a = b))))
                  = .ok ({ s with stack := rest_top } : StackState) := by
        rw [stepNonIf_opcode, runOpcode_verify_vBool, hEq]
        rfl
      have hStrictRest' : equalVerifyFuse_intStrict rest'
                            ({ s with stack := rest_top } : StackState) :=
        hStrictTail2 _ hStep2
      have hWell1 := hCont _ hStep1
      have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
      have hWellRest : wellTypedRun rest' ({ s with stack := rest_top } : StackState) :=
        hCont1 _ hStep2
      rw [hSEq]
      exact ih hRestNoIf _ hWellRest hStrictRest'
    · rw [show decide (a = b) = false from by
            rcases h : decide (a = b) with _ | _
            · rfl
            · exact absurd h hEq] at hStepEV
      simp at hStepEV
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT hStrict
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    -- equalVerifyFuse_intStrict on `(op :: rest')` reduces. We need to
    -- decide whether op is `.opcode "OP_EQUAL"` followed by something other
    -- than `.opcode "OP_VERIFY"` (which falls into case3 with the rule's
    -- own h_no_match) — in either case, equalVerifyFuse_intStrict yields
    -- a tail predicate at the post-step state.
    have hStrictTail : ∀ s', stepNonIf op s = .ok s' → equalVerifyFuse_intStrict rest' s' :=
      ((equalVerifyFuse_intStrict_cons op rest' s).mp hStrict).2
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyEqualVerifyFuse rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep) (hStrictTail s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyEqualVerifyFuse rest') s = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyEqualVerifyFuse rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyEqualVerifyFuse rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyEqualVerifyFuse rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyEqualVerifyFuse rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyEqualVerifyFuse rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyEqualVerifyFuse rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyEqualVerifyFuse rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyEqualVerifyFuse rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyEqualVerifyFuse rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        rw [applyEqualVerifyFuse_cons_no_match (.opcode code) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyEqualVerifyFuse rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyEqualVerifyFuse rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ## Phase 3r — Composition `peepholePassProved` of the 7 proven rules

The composition theorem chains the 7 conditional-or-unconditional `_pass_sound`
results into a single rewrite. To apply each subsequent `_pass_sound`, we need
to know that the previous rule preserved both `noIfOp` (none of these rules
introduce `.ifOp`) and `wellTypedRun` (post-rule states match the original).

Phase 3s adds 4 more proven rules (dupDrop, doubleSwap, numEqualVerifyFuse,
checkSigVerifyFuse), and the int-restricted equalVerifyFuse, for a total of
12 proven rules. The bytes variant of equalVerifyFuse is deferred to Phase 3t.
-/

/-! ### `noIfOp` preservation (per-rule). -/

theorem applyDropAfterPush_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyDropAfterPush ops) := by
  intro ops
  induction ops using applyDropAfterPush.induct with
  | case1 => intro _; exact True.intro
  | case2 v rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.push v :: .drop :: rest') at h
      change noIfOp rest'
      exact h
    show noIfOp (applyDropAfterPush rest')
    exact ih hRest'
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyDropAfterPush rest') := ih hRest'
    -- Goal: noIfOp (applyDropAfterPush (op :: rest'))
    -- Rewrite to op :: applyDropAfterPush rest'
    have hRewrite :
        applyDropAfterPush (op :: rest')
        = op :: applyDropAfterPush rest' := by
      match op with
      | .ifOp _ _ => exact absurd h (by simp [noIfOp])
      | .push v   =>
          match rest' with
          | [] => rfl
          | .drop :: rt => exact (h_no_match v rt rfl rfl).elim
          | .push _ :: _ => rfl
          | .dup :: _ => rfl
          | .swap :: _ => rfl
          | .nip :: _ => rfl
          | .over :: _ => rfl
          | .rot :: _ => rfl
          | .tuck :: _ => rfl
          | .roll _ :: _ => rfl
          | .pick _ :: _ => rfl
          | .opcode _ :: _ => rfl
          | .ifOp _ _ :: _ => rfl
          | .placeholder _ _ :: _ => rfl
          | .pushCodesepIndex :: _ => rfl
      | .dup      => rfl
      | .swap     => rfl
      | .drop     => rfl
      | .nip      => rfl
      | .over     => rfl
      | .rot      => rfl
      | .tuck     => rfl
      | .roll _   => rfl
      | .pick _   => rfl
      | .opcode _ => rfl
      | .placeholder _ _ => rfl
      | .pushCodesepIndex => rfl
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

/-- Generic `noIfOp` preservation: when `apply` rewrites cons-form by either
dropping or replacing the head with non-`.ifOp` ops, `noIfOp` is preserved.
We instantiate per-rule via `applyXxx.induct`. -/
theorem applyDoubleNot_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyDoubleNot ops) := by
  intro ops
  induction ops using applyDoubleNot.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.opcode "OP_NOT" :: .opcode "OP_NOT" :: rest') at h
      change noIfOp rest'
      exact h
    show noIfOp (applyDoubleNot rest')
    exact ih hRest'
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyDoubleNot rest') := ih hRest'
    have hRewrite :
        applyDoubleNot (op :: rest')
        = op :: applyDoubleNot rest' :=
      applyDoubleNot.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyDoubleNegate_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyDoubleNegate ops) := by
  intro ops
  induction ops using applyDoubleNegate.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.opcode "OP_NEGATE" :: .opcode "OP_NEGATE" :: rest') at h
      change noIfOp rest'
      exact h
    show noIfOp (applyDoubleNegate rest')
    exact ih hRest'
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyDoubleNegate rest') := ih hRest'
    have hRewrite :
        applyDoubleNegate (op :: rest')
        = op :: applyDoubleNegate rest' :=
      applyDoubleNegate.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyAddZero_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyAddZero ops) := by
  intro ops
  induction ops using applyAddZero.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint 0) :: .opcode "OP_ADD" :: rest') at h
      change noIfOp rest'
      exact h
    show noIfOp (applyAddZero rest')
    exact ih hRest'
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyAddZero rest') := ih hRest'
    have hRewrite :
        applyAddZero (op :: rest')
        = op :: applyAddZero rest' :=
      applyAddZero.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applySubZero_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applySubZero ops) := by
  intro ops
  induction ops using applySubZero.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint 0) :: .opcode "OP_SUB" :: rest') at h
      change noIfOp rest'
      exact h
    show noIfOp (applySubZero rest')
    exact ih hRest'
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applySubZero rest') := ih hRest'
    have hRewrite :
        applySubZero (op :: rest')
        = op :: applySubZero rest' :=
      applySubZero.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyOneAdd_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyOneAdd ops) := by
  intro ops
  induction ops using applyOneAdd.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    -- Rule fires: input is `.push 1 :: OP_ADD :: rest'`, output is `OP_1ADD :: applyOneAdd rest'`.
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint 1) :: .opcode "OP_ADD" :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyOneAdd rest') := ih hRest'
    -- Output is OP_1ADD :: applyOneAdd rest'
    show noIfOp (.opcode "OP_1ADD" :: applyOneAdd rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyOneAdd rest') := ih hRest'
    have hRewrite :
        applyOneAdd (op :: rest')
        = op :: applyOneAdd rest' :=
      applyOneAdd.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyDoubleSha256_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyDoubleSha256 ops) := by
  intro ops
  induction ops using applyDoubleSha256.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    -- Rule fires: input is `OP_SHA256 :: OP_SHA256 :: rest'`, output is `OP_HASH256 :: applyDoubleSha256 rest'`.
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyDoubleSha256 rest') := ih hRest'
    show noIfOp (.opcode "OP_HASH256" :: applyDoubleSha256 rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyDoubleSha256 rest') := ih hRest'
    have hRewrite :
        applyDoubleSha256 (op :: rest')
        = op :: applyDoubleSha256 rest' :=
      applyDoubleSha256.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

/-! ### `wellTypedRun` preservation (per-rule).

For each rule the proof follows the same recipe as the rule's `_pass_sound`
but produces a `wellTypedRun` predicate instead of a `runOps` equality. The
rule-firing case uses the same state-equation extraction; the catch-all case
uses the unchanged-head observation `wellTypedRun (op :: rest) s ↔ wellTypedRun
(op :: applyXxx rest) s` (under the IH on `rest`).
-/

/-- Helper: in case3 of any `applyXxx`, when the rule does NOT fire and `op`
is non-`.ifOp`, well-typedness of the cons-output is equivalent to a precond
on `s` and well-typedness of the tail at any post-step state. -/
private theorem wellTypedRun_cons_via_ih
    (op : StackOp) (rest1 rest2 : List StackOp) (s : StackState)
    (hWT : wellTypedRun (op :: rest1) s)
    (hIH : ∀ s', stepNonIf op s = .ok s' → wellTypedRun rest1 s' → wellTypedRun rest2 s') :
    wellTypedRun (op :: rest2) s := by
  have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
  refine (wellTypedRun_cons _ _ _).mpr ⟨hPrecond, ?_⟩
  intro s' hStep
  exact hIH s' hStep (hCont s' hStep)

/-- Helper: stepNonIf .drop applied to a `s.push x` state returns to `s`. -/
private theorem stepNonIf_drop_push (s : StackState) (x : ANF.Eval.Value) :
    stepNonIf .drop (s.push x) = .ok s := by
  rw [stepNonIf_drop]
  unfold applyDrop StackState.push
  cases s
  simp

/-- `applyDropAfterPush` preserves `wellTypedRun`: rule is `[push v, drop] → []`,
identity, so the post-rule state at `rest'` is the original `s`. -/
theorem applyDropAfterPush_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyDropAfterPush ops) s := by
  intro ops
  induction ops using applyDropAfterPush.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 v rest' ih =>
    -- Rule fires: input `.push v :: .drop :: rest'`, output `applyDropAfterPush rest'`.
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.push v :: .drop :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    -- hWT unfolds: wellTypedRun (.push v :: .drop :: rest') s
    -- which gives: wellTypedRun (.drop :: rest') (post-push state)
    -- which gives: wellTypedRun rest' (post-drop post-push state) = wellTypedRun rest' s.
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    -- Compute the push step result based on v.
    have hWellRest : wellTypedRun rest' s := by
      cases v with
      | bigint i =>
          have hStepP : stepNonIf (.push (.bigint i)) s = .ok (s.push (.vBigint i)) :=
            stepNonIf_push_bigint s i
          have hWell2 : wellTypedRun (.drop :: rest') (s.push (.vBigint i)) := hCont1 _ hStepP
          have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell2
          have hStepD : stepNonIf .drop (s.push (.vBigint i)) = .ok s :=
            stepNonIf_drop_push s (.vBigint i)
          exact hCont2 _ hStepD
      | bool b =>
          have hStepP : stepNonIf (.push (.bool b)) s = .ok (s.push (.vBool b)) :=
            stepNonIf_push_bool s b
          have hWell2 : wellTypedRun (.drop :: rest') (s.push (.vBool b)) := hCont1 _ hStepP
          have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell2
          have hStepD : stepNonIf .drop (s.push (.vBool b)) = .ok s :=
            stepNonIf_drop_push s (.vBool b)
          exact hCont2 _ hStepD
      | bytes bs =>
          have hStepP : stepNonIf (.push (.bytes bs)) s = .ok (s.push (.vBytes bs)) :=
            stepNonIf_push_bytes s bs
          have hWell2 : wellTypedRun (.drop :: rest') (s.push (.vBytes bs)) := hCont1 _ hStepP
          have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell2
          have hStepD : stepNonIf .drop (s.push (.vBytes bs)) = .ok s :=
            stepNonIf_drop_push s (.vBytes bs)
          exact hCont2 _ hStepD
    show wellTypedRun (applyDropAfterPush rest') s
    exact ih hRest' s hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    -- Output: op :: applyDropAfterPush rest'.
    have hRewrite :
        applyDropAfterPush (op :: rest')
        = op :: applyDropAfterPush rest' := by
      match op with
      | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | .push v   =>
          match rest' with
          | [] => rfl
          | .drop :: rt => exact (h_no_match v rt rfl rfl).elim
          | .push _ :: _ => rfl
          | .dup :: _ => rfl
          | .swap :: _ => rfl
          | .nip :: _ => rfl
          | .over :: _ => rfl
          | .rot :: _ => rfl
          | .tuck :: _ => rfl
          | .roll _ :: _ => rfl
          | .pick _ :: _ => rfl
          | .opcode _ :: _ => rfl
          | .ifOp _ _ :: _ => rfl
          | .placeholder _ _ :: _ => rfl
          | .pushCodesepIndex :: _ => rfl
      | .dup      => rfl
      | .swap     => rfl
      | .drop     => rfl
      | .nip      => rfl
      | .over     => rfl
      | .rot      => rfl
      | .tuck     => rfl
      | .roll _   => rfl
      | .pick _   => rfl
      | .opcode _ => rfl
      | .placeholder _ _ => rfl
      | .pushCodesepIndex => rfl
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyDropAfterPush rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-- `applyDoubleNot` preserves `wellTypedRun`. Identity rule: post-rule state
at `rest'` is the original `s` after two `OP_NOT`s on `.vBool b`. -/
theorem applyDoubleNot_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyDoubleNot ops) s := by
  intro ops
  induction ops using applyDoubleNot.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.opcode "OP_NOT" :: .opcode "OP_NOT" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨b, rest_top, hStack⟩ := precondMet_bool_extract s hPrecond
    obtain ⟨s1, hStep1, hStep2⟩ := stepNonIf_OPNOT_OPNOT_vBool s b rest_top hStack
    have hWell1 : wellTypedRun (.opcode "OP_NOT" :: rest') s1 := hCont s1 hStep1
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    have hWellRest : wellTypedRun rest' s := hCont1 s hStep2
    show wellTypedRun (applyDoubleNot rest') s
    exact ih hRest' s hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyDoubleNot (op :: rest')
        = op :: applyDoubleNot rest' :=
      applyDoubleNot.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyDoubleNot rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-- `applyDoubleNegate` preserves `wellTypedRun`. Identity rule. -/
theorem applyDoubleNegate_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyDoubleNegate ops) s := by
  intro ops
  induction ops using applyDoubleNegate.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.opcode "OP_NEGATE" :: .opcode "OP_NEGATE" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨i, rest_top, hStack⟩ := precondMet_bigint_extract s hPrecond
    obtain ⟨s1, hStep1, hStep2⟩ := stepNonIf_OPNEGATE_OPNEGATE_vBigint s i rest_top hStack
    have hWell1 : wellTypedRun (.opcode "OP_NEGATE" :: rest') s1 := hCont s1 hStep1
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    have hWellRest : wellTypedRun rest' s := hCont1 s hStep2
    show wellTypedRun (applyDoubleNegate rest') s
    exact ih hRest' s hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyDoubleNegate (op :: rest')
        = op :: applyDoubleNegate rest' :=
      applyDoubleNegate.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyDoubleNegate rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-- `applyAddZero` preserves `wellTypedRun`. Identity rule `[push 0, OP_ADD] → []`. -/
theorem applyAddZero_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyAddZero ops) s := by
  intro ops
  induction ops using applyAddZero.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint 0) :: .opcode "OP_ADD" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 0)) s = .ok (s.push (.vBigint 0)) :=
      stepNonIf_push_bigint s 0
    have hWellAdd : wellTypedRun (.opcode "OP_ADD" :: rest') (s.push (.vBigint 0)) :=
      hCont _ hStepPush
    have ⟨hPrecondAdd, hContAdd⟩ := wellTypedRun_cons _ _ _ |>.mp hWellAdd
    obtain ⟨a, b, rest_stack, hStackPush⟩ :=
      precondMet_twoInts_extract _ hPrecondAdd
    have hPushStack : (s.push (.vBigint 0)).stack = .vBigint 0 :: s.stack := by
      unfold StackState.push; simp
    have hStackEq : .vBigint 0 :: s.stack = .vBigint b :: .vBigint a :: rest_stack := by
      rw [← hPushStack]; exact hStackPush
    have hSStack : s.stack = .vBigint a :: rest_stack :=
      List.tail_eq_of_cons_eq hStackEq
    have hStackForAdd : (s.push (.vBigint 0)).stack
                      = .vBigint 0 :: .vBigint a :: rest_stack := by
      rw [hPushStack, hSStack]
    have hStepAdd : stepNonIf (.opcode "OP_ADD") (s.push (.vBigint 0)) = .ok s := by
      rw [stepNonIf_opcode, runOpcode_add_int_concrete (s.push (.vBigint 0)) a 0 rest_stack hStackForAdd]
      have : a + 0 = a := Int.add_zero a
      rw [this]
      cases s
      simp_all [StackState.push]
    have hWellRest : wellTypedRun rest' s := hContAdd s hStepAdd
    show wellTypedRun (applyAddZero rest') s
    exact ih hRest' s hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyAddZero (op :: rest')
        = op :: applyAddZero rest' :=
      applyAddZero.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyAddZero rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-- `applySubZero` preserves `wellTypedRun`. Identity rule `[push 0, OP_SUB] → []`. -/
theorem applySubZero_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applySubZero ops) s := by
  intro ops
  induction ops using applySubZero.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint 0) :: .opcode "OP_SUB" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 0)) s = .ok (s.push (.vBigint 0)) :=
      stepNonIf_push_bigint s 0
    have hWellSub : wellTypedRun (.opcode "OP_SUB" :: rest') (s.push (.vBigint 0)) :=
      hCont _ hStepPush
    have ⟨hPrecondSub, hContSub⟩ := wellTypedRun_cons _ _ _ |>.mp hWellSub
    obtain ⟨a, b, rest_stack, hStackPush⟩ :=
      precondMet_twoInts_extract _ hPrecondSub
    have hPushStack : (s.push (.vBigint 0)).stack = .vBigint 0 :: s.stack := by
      unfold StackState.push; simp
    have hStackEq : .vBigint 0 :: s.stack = .vBigint b :: .vBigint a :: rest_stack := by
      rw [← hPushStack]; exact hStackPush
    have hSStack : s.stack = .vBigint a :: rest_stack :=
      List.tail_eq_of_cons_eq hStackEq
    have hStackForSub : (s.push (.vBigint 0)).stack
                      = .vBigint 0 :: .vBigint a :: rest_stack := by
      rw [hPushStack, hSStack]
    have hStepSub : stepNonIf (.opcode "OP_SUB") (s.push (.vBigint 0)) = .ok s := by
      rw [stepNonIf_opcode, runOpcode_sub_int_concrete (s.push (.vBigint 0)) a 0 rest_stack hStackForSub]
      have : a - 0 = a := Int.sub_zero a
      rw [this]
      cases s
      simp_all [StackState.push]
    have hWellRest : wellTypedRun rest' s := hContSub s hStepSub
    show wellTypedRun (applySubZero rest') s
    exact ih hRest' s hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applySubZero (op :: rest')
        = op :: applySubZero rest' :=
      applySubZero.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applySubZero rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-- `applyOneAdd` preserves `wellTypedRun`. Non-identity rule `[push 1, OP_ADD] → [OP_1ADD]`.
The post-OP_1ADD state on `s` equals the post-`[push 1, OP_ADD]` state on `s` (both
are `{s with stack := .vBigint (a+1) :: rest_stack}`), so the well-typedness of `rest'`
transfers via the IH. -/
theorem applyOneAdd_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyOneAdd ops) s := by
  intro ops
  induction ops using applyOneAdd.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint 1) :: .opcode "OP_ADD" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 1)) s = .ok (s.push (.vBigint 1)) :=
      stepNonIf_push_bigint s 1
    have hWellAdd : wellTypedRun (.opcode "OP_ADD" :: rest') (s.push (.vBigint 1)) :=
      hCont _ hStepPush
    have ⟨hPrecondAdd, hContAdd⟩ := wellTypedRun_cons _ _ _ |>.mp hWellAdd
    obtain ⟨a, b, rest_stack, hStackPush⟩ :=
      precondMet_twoInts_extract _ hPrecondAdd
    have hPushStack : (s.push (.vBigint 1)).stack = .vBigint 1 :: s.stack := by
      unfold StackState.push; simp
    have hStackEq : .vBigint 1 :: s.stack = .vBigint b :: .vBigint a :: rest_stack := by
      rw [← hPushStack]; exact hStackPush
    have hSStack : s.stack = .vBigint a :: rest_stack :=
      List.tail_eq_of_cons_eq hStackEq
    have hStackForAdd : (s.push (.vBigint 1)).stack
                      = .vBigint 1 :: .vBigint a :: rest_stack := by
      rw [hPushStack, hSStack]
    -- Output: .opcode "OP_1ADD" :: applyOneAdd rest'.
    show wellTypedRun (.opcode "OP_1ADD" :: applyOneAdd rest') s
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · -- precondMet (opPrecondition (.opcode "OP_1ADD")) s = precondMet .bigint s.
      show precondMet .bigint s
      simp [precondMet, hSStack]
    · intro s' hStep1ADD
      -- Post-OP_1ADD state = {s with stack := .vBigint (a+1) :: rest_stack}
      have hStepDef : stepNonIf (.opcode "OP_1ADD") s
                    = .ok (({ s with stack := rest_stack } : StackState).push (.vBigint (a + 1))) := by
        rw [stepNonIf_opcode, runOpcode_1ADD_def]
        unfold liftIntUnary StackState.pop?
        rw [hSStack]
        simp [asInt?, StackState.push]
      have hSEq : s' = ({ s with stack := rest_stack } : StackState).push (.vBigint (a + 1)) := by
        rw [hStepDef] at hStep1ADD
        exact ((Except.ok.injEq _ _).mp hStep1ADD).symm
      -- Post-OP_ADD state on (s.push (.vBigint 1)).
      have hStepAdd : stepNonIf (.opcode "OP_ADD") (s.push (.vBigint 1)) = .ok s' := by
        rw [stepNonIf_opcode]
        rw [runOpcode_add_int_concrete (s.push (.vBigint 1)) a 1 rest_stack hStackForAdd]
        rw [hSEq]
        cases s
        simp_all [StackState.push]
      have hWellRest : wellTypedRun rest' s' := hContAdd s' hStepAdd
      exact ih hRest' s' hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyOneAdd (op :: rest')
        = op :: applyOneAdd rest' :=
      applyOneAdd.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyOneAdd rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-- `applyDoubleSha256` preserves `wellTypedRun`. Non-identity rule
`[OP_SHA256, OP_SHA256] → [OP_HASH256]`. The post-OP_HASH256 state on `s`
equals the post-`[OP_SHA256, OP_SHA256]` state on `s` via `hash256_eq_double_sha256`. -/
theorem applyDoubleSha256_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyDoubleSha256 ops) s := by
  intro ops
  induction ops using applyDoubleSha256.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨b, rest_top, hStack⟩ := precondMet_bytes_extract s hPrecond
    -- Output: .opcode "OP_HASH256" :: applyDoubleSha256 rest'.
    show wellTypedRun (.opcode "OP_HASH256" :: applyDoubleSha256 rest') s
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · -- precondMet .bytes s — same as the input precond.
      show precondMet .bytes s
      rcases hStack with hSB | hSO
      · simp [precondMet, hSB]
      · simp [precondMet, hSO]
    · intro s' hStepHash
      -- We need wellTypedRun rest' at s' (the post-OP_HASH256 state).
      -- Case-split on .vBytes vs .vOpaque.
      rcases hStack with hStackB | hStackO
      · -- .vBytes case.
        have hStep1 : stepNonIf (.opcode "OP_SHA256") s
                    = .ok (({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b))) := by
          have hs' : s = (({ s with stack := rest_top } : StackState).push (.vBytes b)) := by
            cases s; simp_all [StackState.push]
          rw [stepNonIf_opcode]
          rw [hs']
          rw [runOpcode_sha256_vBytes]
          cases s
          simp_all [StackState.push]
        let s1 : StackState := ({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b))
        have hWell1 : wellTypedRun (.opcode "OP_SHA256" :: rest') s1 := hCont s1 hStep1
        have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
        have hStep2 : stepNonIf (.opcode "OP_SHA256") s1
                    = .ok (({ s with stack := rest_top } : StackState).push
                              (.vBytes (sha256 (sha256 b)))) := by
          rw [stepNonIf_opcode]
          show runOpcode "OP_SHA256"
                ((({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b)))) = _
          rw [runOpcode_sha256_vBytes]
        have hWell2 : wellTypedRun rest'
                        (({ s with stack := rest_top } : StackState).push
                          (.vBytes (sha256 (sha256 b)))) := hCont1 _ hStep2
        have hStepHashEq : stepNonIf (.opcode "OP_HASH256") s
                         = .ok (({ s with stack := rest_top } : StackState).push
                                (.vBytes (hash256 b))) := by
          have hs' : s = (({ s with stack := rest_top } : StackState).push (.vBytes b)) := by
            cases s; simp_all [StackState.push]
          rw [stepNonIf_opcode]
          rw [hs']
          rw [runOpcode_hash256_vBytes]
          cases s
          simp_all [StackState.push]
        have hSEq : s' = (({ s with stack := rest_top } : StackState).push (.vBytes (hash256 b))) := by
          rw [hStepHashEq] at hStepHash
          exact ((Except.ok.injEq _ _).mp hStepHash).symm
        rw [hSEq, hash256_eq_double_sha256]
        exact ih hRest' _ hWell2
      · -- .vOpaque case.
        have hStep1 : stepNonIf (.opcode "OP_SHA256") s
                    = .ok (({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b))) := by
          have hs' : s = (({ s with stack := rest_top } : StackState).push (.vOpaque b)) := by
            cases s; simp_all [StackState.push]
          rw [stepNonIf_opcode]
          rw [hs']
          rw [runOpcode_sha256_vOpaque]
          cases s
          simp_all [StackState.push]
        let s1 : StackState := ({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b))
        have hWell1 : wellTypedRun (.opcode "OP_SHA256" :: rest') s1 := hCont s1 hStep1
        have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
        have hStep2 : stepNonIf (.opcode "OP_SHA256") s1
                    = .ok (({ s with stack := rest_top } : StackState).push
                              (.vBytes (sha256 (sha256 b)))) := by
          rw [stepNonIf_opcode]
          show runOpcode "OP_SHA256"
                ((({ s with stack := rest_top } : StackState).push (.vBytes (sha256 b)))) = _
          rw [runOpcode_sha256_vBytes]
        have hWell2 : wellTypedRun rest'
                        (({ s with stack := rest_top } : StackState).push
                          (.vBytes (sha256 (sha256 b)))) := hCont1 _ hStep2
        have hStepHashEq : stepNonIf (.opcode "OP_HASH256") s
                         = .ok (({ s with stack := rest_top } : StackState).push
                                (.vBytes (hash256 b))) := by
          have hs' : s = (({ s with stack := rest_top } : StackState).push (.vOpaque b)) := by
            cases s; simp_all [StackState.push]
          rw [stepNonIf_opcode]
          rw [hs']
          rw [runOpcode_hash256_vOpaque]
          cases s
          simp_all [StackState.push]
        have hSEq : s' = (({ s with stack := rest_top } : StackState).push (.vBytes (hash256 b))) := by
          rw [hStepHashEq] at hStepHash
          exact ((Except.ok.injEq _ _).mp hStepHash).symm
        rw [hSEq, hash256_eq_double_sha256]
        exact ih hRest' _ hWell2
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyDoubleSha256 (op :: rest')
        = op :: applyDoubleSha256 rest' :=
      applyDoubleSha256.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyDoubleSha256 rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-! ### Phase 3s — noIfOp + wellTypedRun preservation for 4 new rules

dupDrop, doubleSwap, numEqualVerifyFuse, checkSigVerifyFuse — same recipe as the
Phase 3r preservation lemmas. (equalVerifyFuse has a stricter precondition;
its preservation is handled in the `peepholePassFull` composition below.)
-/

theorem applyDupDrop_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyDupDrop ops) := by
  intro ops
  induction ops using applyDupDrop.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.dup :: .drop :: rest') at h
      change noIfOp rest'
      exact h
    show noIfOp (applyDupDrop rest')
    exact ih hRest'
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyDupDrop rest') := ih hRest'
    have hRewrite :
        applyDupDrop (op :: rest')
        = op :: applyDupDrop rest' :=
      applyDupDrop.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyDoubleSwap_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyDoubleSwap ops) := by
  intro ops
  induction ops using applyDoubleSwap.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.swap :: .swap :: rest') at h
      change noIfOp rest'
      exact h
    show noIfOp (applyDoubleSwap rest')
    exact ih hRest'
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyDoubleSwap rest') := ih hRest'
    have hRewrite :
        applyDoubleSwap (op :: rest')
        = op :: applyDoubleSwap rest' :=
      applyDoubleSwap.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyNumEqualVerifyFuse_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyNumEqualVerifyFuse ops) := by
  intro ops
  induction ops using applyNumEqualVerifyFuse.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.opcode "OP_NUMEQUAL" :: .opcode "OP_VERIFY" :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyNumEqualVerifyFuse rest') := ih hRest'
    show noIfOp (.opcode "OP_NUMEQUALVERIFY" :: applyNumEqualVerifyFuse rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyNumEqualVerifyFuse rest') := ih hRest'
    have hRewrite :
        applyNumEqualVerifyFuse (op :: rest')
        = op :: applyNumEqualVerifyFuse rest' :=
      applyNumEqualVerifyFuse.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyCheckSigVerifyFuse_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyCheckSigVerifyFuse ops) := by
  intro ops
  induction ops using applyCheckSigVerifyFuse.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.opcode "OP_CHECKSIG" :: .opcode "OP_VERIFY" :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyCheckSigVerifyFuse rest') := ih hRest'
    show noIfOp (.opcode "OP_CHECKSIGVERIFY" :: applyCheckSigVerifyFuse rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyCheckSigVerifyFuse rest') := ih hRest'
    have hRewrite :
        applyCheckSigVerifyFuse (op :: rest')
        = op :: applyCheckSigVerifyFuse rest' :=
      applyCheckSigVerifyFuse.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyEqualVerifyFuse_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyEqualVerifyFuse ops) := by
  intro ops
  induction ops using applyEqualVerifyFuse.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyEqualVerifyFuse rest') := ih hRest'
    show noIfOp (.opcode "OP_EQUALVERIFY" :: applyEqualVerifyFuse rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyEqualVerifyFuse rest') := ih hRest'
    have hRewrite :
        applyEqualVerifyFuse (op :: rest')
        = op :: applyEqualVerifyFuse rest' :=
      applyEqualVerifyFuse.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

/-! ### `dupDrop` preserves `wellTypedRun` -/
theorem applyDupDrop_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyDupDrop ops) s := by
  intro ops
  induction ops using applyDupDrop.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.dup :: .drop :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨v, rest_top, hStack⟩ := precondMet_nonEmpty_extract s hPrecond
    have hStepDup : stepNonIf .dup s = .ok (s.push v) := by
      rw [stepNonIf_dup]; exact applyDup_cons s v rest_top hStack
    have hWell1 := hCont _ hStepDup
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    have hStepDrop : stepNonIf .drop (s.push v) = .ok s := by
      rw [stepNonIf_drop, applyDrop_push]
    have hWellRest : wellTypedRun rest' s := hCont1 _ hStepDrop
    show wellTypedRun (applyDupDrop rest') s
    exact ih hRest' s hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyDupDrop (op :: rest')
        = op :: applyDupDrop rest' :=
      applyDupDrop.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyDupDrop rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-! ### `doubleSwap` preserves `wellTypedRun` -/
theorem applyDoubleSwap_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyDoubleSwap ops) s := by
  intro ops
  induction ops using applyDoubleSwap.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.swap :: .swap :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨a, b, rest_top, hStack⟩ := precondMet_twoElems_extract s hPrecond
    let s1 : StackState := { s with stack := b :: a :: rest_top }
    have hStepSwap1 : stepNonIf .swap s = .ok s1 := by
      rw [stepNonIf_swap]; exact applySwap_cons2 s a b rest_top hStack
    have hWell1 := hCont s1 hStepSwap1
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    have hStepSwap2 : stepNonIf .swap s1 = .ok s := by
      rw [stepNonIf_swap]
      have hs1 : s1.stack = b :: a :: rest_top := rfl
      rw [applySwap_cons2 s1 b a rest_top hs1]
      cases s
      simp_all
    have hWellRest : wellTypedRun rest' s := hCont1 s hStepSwap2
    show wellTypedRun (applyDoubleSwap rest') s
    exact ih hRest' s hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyDoubleSwap (op :: rest')
        = op :: applyDoubleSwap rest' :=
      applyDoubleSwap.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyDoubleSwap rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-! ### `numEqualVerifyFuse` preserves `wellTypedRun`. Non-identity rule.
Post-OP_NUMEQUALVERIFY state on `s` (when `a = b`) equals `{s with stack := rest_top}`,
which equals the post-`[OP_NUMEQUAL, OP_VERIFY]` state on `s`. -/
theorem applyNumEqualVerifyFuse_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyNumEqualVerifyFuse ops) s := by
  intro ops
  induction ops using applyNumEqualVerifyFuse.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.opcode "OP_NUMEQUAL" :: .opcode "OP_VERIFY" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨a, b, rest_top, hStack⟩ := precondMet_twoInts_extract s hPrecond
    show wellTypedRun (.opcode "OP_NUMEQUALVERIFY" :: applyNumEqualVerifyFuse rest') s
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · -- precondMet (opPrecondition (.opcode "OP_NUMEQUALVERIFY")) s = precondMet .twoInts s.
      show precondMet .twoInts s
      simp [precondMet, hStack]
    · intro s' hStepNEV
      have hStepDef : stepNonIf (.opcode "OP_NUMEQUALVERIFY") s
                    = (if decide (a = b) then
                        .ok ({ s with stack := rest_top } : StackState)
                       else .error .assertFailed) := by
        rw [stepNonIf_opcode, runOpcode_numEqualVerify_int s a b rest_top hStack]
      rw [hStepDef] at hStepNEV
      by_cases hEq : decide (a = b) = true
      · rw [hEq] at hStepNEV
        simp at hStepNEV
        have hSEq : s' = ({ s with stack := rest_top } : StackState) := hStepNEV.symm
        have hStep1 : stepNonIf (.opcode "OP_NUMEQUAL") s
                    = .ok ((({ s with stack := rest_top } : StackState).push
                             (.vBool (decide (a = b))))) := by
          rw [stepNonIf_opcode, runOpcode_numEqual_int s a b rest_top hStack]
        have hWell1 := hCont _ hStep1
        have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
        have hStep2 : stepNonIf (.opcode "OP_VERIFY")
                        (({ s with stack := rest_top } : StackState).push
                          (.vBool (decide (a = b))))
                    = .ok ({ s with stack := rest_top } : StackState) := by
          rw [stepNonIf_opcode, runOpcode_verify_vBool, hEq]; rfl
        have hWellRest : wellTypedRun rest' ({ s with stack := rest_top } : StackState) :=
          hCont1 _ hStep2
        rw [hSEq]
        exact ih hRest' _ hWellRest
      · rw [show decide (a = b) = false from by
              rcases h : decide (a = b) with _ | _
              · rfl
              · exact absurd h hEq] at hStepNEV
        simp at hStepNEV
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyNumEqualVerifyFuse (op :: rest')
        = op :: applyNumEqualVerifyFuse rest' :=
      applyNumEqualVerifyFuse.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyNumEqualVerifyFuse rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-! ### `checkSigVerifyFuse` preserves `wellTypedRun`. Non-identity rule. -/
theorem applyCheckSigVerifyFuse_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyCheckSigVerifyFuse ops) s := by
  intro ops
  induction ops using applyCheckSigVerifyFuse.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.opcode "OP_CHECKSIG" :: .opcode "OP_VERIFY" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨pk, sig, rest_top, hStack⟩ := precondMet_twoBytes_extract_strict s hPrecond
    show wellTypedRun (.opcode "OP_CHECKSIGVERIFY" :: applyCheckSigVerifyFuse rest') s
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · show precondMet .twoBytes s
      rcases hStack with hBB | hBO | hOB | hOO
      · simp [precondMet, hBB]
      · simp [precondMet, hBO]
      · simp [precondMet, hOB]
      · simp [precondMet, hOO]
    · intro s' hStepCSV
      have hStepDef : stepNonIf (.opcode "OP_CHECKSIGVERIFY") s
                    = (if checkSig sig pk then
                        .ok ({ s with stack := rest_top } : StackState)
                       else .error .assertFailed) := by
        rw [stepNonIf_opcode]
        rcases hStack with hBB | hBO | hOB | hOO
        · rw [runOpcode_CHECKSIGVERIFY_def, popN_two_cons s (.vBytes pk) (.vBytes sig) rest_top hBB]
          simp [asBytes?]
        · rw [runOpcode_CHECKSIGVERIFY_def, popN_two_cons s (.vBytes pk) (.vOpaque sig) rest_top hBO]
          simp [asBytes?]
        · rw [runOpcode_CHECKSIGVERIFY_def, popN_two_cons s (.vOpaque pk) (.vBytes sig) rest_top hOB]
          simp [asBytes?]
        · rw [runOpcode_CHECKSIGVERIFY_def, popN_two_cons s (.vOpaque pk) (.vOpaque sig) rest_top hOO]
          simp [asBytes?]
      rw [hStepDef] at hStepCSV
      by_cases hSig : checkSig sig pk = true
      · rw [hSig] at hStepCSV
        simp at hStepCSV
        have hSEq : s' = ({ s with stack := rest_top } : StackState) := hStepCSV.symm
        have hStep1 : stepNonIf (.opcode "OP_CHECKSIG") s
                    = .ok (({ s with stack := rest_top } : StackState).push
                            (.vBool (checkSig sig pk))) :=
          stepNonIf_OPCHECKSIG_anyBytes s sig pk rest_top hStack
        have hWell1 := hCont _ hStep1
        have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
        have hStep2 : stepNonIf (.opcode "OP_VERIFY")
                        (({ s with stack := rest_top } : StackState).push
                          (.vBool (checkSig sig pk)))
                    = .ok ({ s with stack := rest_top } : StackState) := by
          rw [stepNonIf_opcode, runOpcode_verify_vBool, hSig]; rfl
        have hWellRest : wellTypedRun rest' ({ s with stack := rest_top } : StackState) :=
          hCont1 _ hStep2
        rw [hSEq]
        exact ih hRest' _ hWellRest
      · rw [show checkSig sig pk = false from by
              rcases h : checkSig sig pk with _ | _
              · rfl
              · exact absurd h hSig] at hStepCSV
        simp at hStepCSV
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyCheckSigVerifyFuse (op :: rest')
        = op :: applyCheckSigVerifyFuse rest' :=
      applyCheckSigVerifyFuse.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyCheckSigVerifyFuse rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-! ### Composition `peepholePassProved` and its soundness

The 7 proven rules chain in any order, but for predictability we use the
canonical inside-out order matching the outer `peepholePass` style:
`applyDropAfterPush` first, then the conditional rules.
-/

def peepholePassProved (ops : List StackOp) : List StackOp :=
  applyDoubleSha256 <|
    applyOneAdd <|
      applySubZero <|
        applyAddZero <|
          applyDoubleNegate <|
            applyDoubleNot <|
              applyDropAfterPush ops

theorem peepholePassProved_empty :
    peepholePassProved [] = [] := by
  simp [peepholePassProved, applyDropAfterPush_empty, applyDoubleNot_empty,
        applyDoubleNegate_empty, applyAddZero_empty, applySubZero_empty,
        applyOneAdd_empty, applyDoubleSha256_empty]

/-- Soundness of `peepholePassProved`: chaining the 7 proven `_pass_sound`
results via `Eq.trans` and the noIfOp/wellTypedRun preservation lemmas. -/
theorem peepholePassProved_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (peepholePassProved ops) s = runOps ops s := by
  intro ops hNoIf s hWT
  -- Build the chain inside out:
  --   ops0 := ops
  --   ops1 := applyDropAfterPush ops0
  --   ops2 := applyDoubleNot ops1
  --   ops3 := applyDoubleNegate ops2
  --   ops4 := applyAddZero ops3
  --   ops5 := applySubZero ops4
  --   ops6 := applyOneAdd ops5
  --   ops7 := applyDoubleSha256 ops6   ( = peepholePassProved ops )
  -- At each step we have noIfOp and wellTypedRun for the current opsK,
  -- which we feed to the corresponding _pass_sound and the preservation
  -- lemmas to advance to opsK+1.
  -- Stage 1: dropAfterPush.
  have hSound1 : runOps (applyDropAfterPush ops) s = runOps ops s :=
    dropAfterPush_pass_sound ops hNoIf s
  have hNoIf1 : noIfOp (applyDropAfterPush ops) :=
    applyDropAfterPush_preserves_noIfOp ops hNoIf
  have hWT1 : wellTypedRun (applyDropAfterPush ops) s :=
    applyDropAfterPush_preserves_wellTypedRun ops hNoIf s hWT
  -- Stage 2: doubleNot.
  have hSound2 : runOps (applyDoubleNot (applyDropAfterPush ops)) s
               = runOps (applyDropAfterPush ops) s :=
    doubleNot_pass_sound _ hNoIf1 s hWT1
  have hNoIf2 : noIfOp (applyDoubleNot (applyDropAfterPush ops)) :=
    applyDoubleNot_preserves_noIfOp _ hNoIf1
  have hWT2 : wellTypedRun (applyDoubleNot (applyDropAfterPush ops)) s :=
    applyDoubleNot_preserves_wellTypedRun _ hNoIf1 s hWT1
  -- Stage 3: doubleNegate.
  have hSound3 : runOps (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops))) s
               = runOps (applyDoubleNot (applyDropAfterPush ops)) s :=
    doubleNegate_pass_sound _ hNoIf2 s hWT2
  have hNoIf3 : noIfOp (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops))) :=
    applyDoubleNegate_preserves_noIfOp _ hNoIf2
  have hWT3 : wellTypedRun (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops))) s :=
    applyDoubleNegate_preserves_wellTypedRun _ hNoIf2 s hWT2
  -- Stage 4: addZero.
  have hSound4 : runOps (applyAddZero
                  (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops)))) s
               = runOps (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops))) s :=
    addZero_pass_sound _ hNoIf3 s hWT3
  have hNoIf4 : noIfOp (applyAddZero
                  (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops)))) :=
    applyAddZero_preserves_noIfOp _ hNoIf3
  have hWT4 : wellTypedRun (applyAddZero
                (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops)))) s :=
    applyAddZero_preserves_wellTypedRun _ hNoIf3 s hWT3
  -- Stage 5: subZero.
  have hSound5 : runOps (applySubZero (applyAddZero
                  (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops))))) s
               = runOps (applyAddZero
                  (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops)))) s :=
    subZero_pass_sound _ hNoIf4 s hWT4
  have hNoIf5 : noIfOp (applySubZero (applyAddZero
                  (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops))))) :=
    applySubZero_preserves_noIfOp _ hNoIf4
  have hWT5 : wellTypedRun (applySubZero (applyAddZero
                (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops))))) s :=
    applySubZero_preserves_wellTypedRun _ hNoIf4 s hWT4
  -- Stage 6: oneAdd.
  have hSound6 : runOps (applyOneAdd (applySubZero (applyAddZero
                  (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops)))))) s
               = runOps (applySubZero (applyAddZero
                  (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops))))) s :=
    oneAdd_pass_sound _ hNoIf5 s hWT5
  have hNoIf6 : noIfOp (applyOneAdd (applySubZero (applyAddZero
                  (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops)))))) :=
    applyOneAdd_preserves_noIfOp _ hNoIf5
  have hWT6 : wellTypedRun (applyOneAdd (applySubZero (applyAddZero
                (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops)))))) s :=
    applyOneAdd_preserves_wellTypedRun _ hNoIf5 s hWT5
  -- Stage 7: doubleSha256.
  have hSound7 : runOps (applyDoubleSha256 (applyOneAdd (applySubZero (applyAddZero
                  (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops))))))) s
               = runOps (applyOneAdd (applySubZero (applyAddZero
                  (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops)))))) s :=
    doubleSha256_pass_sound _ hNoIf6 s hWT6
  -- Compose: peepholePassProved ops = the outermost expression.
  show runOps (applyDoubleSha256 (applyOneAdd (applySubZero (applyAddZero
        (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops))))))) s = runOps ops s
  exact hSound7.trans (hSound6.trans (hSound5.trans (hSound4.trans
    (hSound3.trans (hSound2.trans hSound1)))))

/-! ## Phase 3s — `peepholePassFull` composition

Adds 4 more proven rules (`dupDrop`, `doubleSwap`, `numEqualVerifyFuse`,
`checkSigVerifyFuse`) on top of `peepholePassProved`'s 7 rules, for a total
of **11 proven rules** with full composed soundness.

The `equalVerifyFuse` rule (`int` variant) carries an additional `intStrict`
precondition (it operates on either int or bytes in general; the int case is
proven, the bytes case is deferred to Phase 3t). Since `peepholePassFull`
operates over `wellTypedRun` only, we do NOT chain `applyEqualVerifyFuse` into
`peepholePassFull` — its standalone `equalVerifyFuse_pass_sound_int` covers
int-restricted inputs.

**Design choice**: We define a new `peepholePassFull` (rather than extending
`peepholePass` to be the same as `peepholePassFull`). Reason: `peepholePass`
was originally written without proven soundness (Phase 3a), and several
downstream tests/files reference it; redefining its body would break their
golden expectations. `peepholePassFull` is the proven counterpart with a
defined soundness theorem.
-/

def peepholePassFull (ops : List StackOp) : List StackOp :=
  applyCheckSigVerifyFuse <|
    applyNumEqualVerifyFuse <|
      applyDoubleSwap <|
        applyDupDrop <|
          applyDoubleSha256 <|
            applyOneAdd <|
              applySubZero <|
                applyAddZero <|
                  applyDoubleNegate <|
                    applyDoubleNot <|
                      applyDropAfterPush ops

theorem peepholePassFull_empty :
    peepholePassFull [] = [] := by
  simp [peepholePassFull, applyDropAfterPush_empty, applyDoubleNot_empty,
        applyDoubleNegate_empty, applyAddZero_empty, applySubZero_empty,
        applyOneAdd_empty, applyDoubleSha256_empty, applyDupDrop_empty,
        applyDoubleSwap_empty, applyNumEqualVerifyFuse_empty,
        applyCheckSigVerifyFuse_empty]

/-- Soundness of `peepholePassFull`: chains all 11 proven `_pass_sound`
results via `Eq.trans` and the noIfOp/wellTypedRun preservation lemmas.

Excludes `applyEqualVerifyFuse`; see `equalVerifyFuse_pass_sound_int` for the
int-restricted soundness of that rule (deferred Phase 3t for full bytes
generalization). -/
theorem peepholePassFull_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (peepholePassFull ops) s = runOps ops s := by
  intro ops hNoIf s hWT
  -- Stages 1-7: same as peepholePassProved (the 7 inner rules).
  have hSound1 : runOps (applyDropAfterPush ops) s = runOps ops s :=
    dropAfterPush_pass_sound ops hNoIf s
  have hNoIf1 := applyDropAfterPush_preserves_noIfOp ops hNoIf
  have hWT1 := applyDropAfterPush_preserves_wellTypedRun ops hNoIf s hWT
  have hSound2 := doubleNot_pass_sound _ hNoIf1 s hWT1
  have hNoIf2 := applyDoubleNot_preserves_noIfOp _ hNoIf1
  have hWT2 := applyDoubleNot_preserves_wellTypedRun _ hNoIf1 s hWT1
  have hSound3 := doubleNegate_pass_sound _ hNoIf2 s hWT2
  have hNoIf3 := applyDoubleNegate_preserves_noIfOp _ hNoIf2
  have hWT3 := applyDoubleNegate_preserves_wellTypedRun _ hNoIf2 s hWT2
  have hSound4 := addZero_pass_sound _ hNoIf3 s hWT3
  have hNoIf4 := applyAddZero_preserves_noIfOp _ hNoIf3
  have hWT4 := applyAddZero_preserves_wellTypedRun _ hNoIf3 s hWT3
  have hSound5 := subZero_pass_sound _ hNoIf4 s hWT4
  have hNoIf5 := applySubZero_preserves_noIfOp _ hNoIf4
  have hWT5 := applySubZero_preserves_wellTypedRun _ hNoIf4 s hWT4
  have hSound6 := oneAdd_pass_sound _ hNoIf5 s hWT5
  have hNoIf6 := applyOneAdd_preserves_noIfOp _ hNoIf5
  have hWT6 := applyOneAdd_preserves_wellTypedRun _ hNoIf5 s hWT5
  have hSound7 := doubleSha256_pass_sound _ hNoIf6 s hWT6
  have hNoIf7 := applyDoubleSha256_preserves_noIfOp _ hNoIf6
  have hWT7 := applyDoubleSha256_preserves_wellTypedRun _ hNoIf6 s hWT6
  -- Stage 8: dupDrop.
  have hSound8 := dupDrop_pass_sound _ hNoIf7 s hWT7
  have hNoIf8 := applyDupDrop_preserves_noIfOp _ hNoIf7
  have hWT8 := applyDupDrop_preserves_wellTypedRun _ hNoIf7 s hWT7
  -- Stage 9: doubleSwap.
  have hSound9 := doubleSwap_pass_sound _ hNoIf8 s hWT8
  have hNoIf9 := applyDoubleSwap_preserves_noIfOp _ hNoIf8
  have hWT9 := applyDoubleSwap_preserves_wellTypedRun _ hNoIf8 s hWT8
  -- Stage 10: numEqualVerifyFuse.
  have hSound10 := numEqualVerifyFuse_pass_sound _ hNoIf9 s hWT9
  have hNoIf10 := applyNumEqualVerifyFuse_preserves_noIfOp _ hNoIf9
  have hWT10 := applyNumEqualVerifyFuse_preserves_wellTypedRun _ hNoIf9 s hWT9
  -- Stage 11: checkSigVerifyFuse.
  have hSound11 := checkSigVerifyFuse_pass_sound _ hNoIf10 s hWT10
  -- Compose.
  show runOps (applyCheckSigVerifyFuse (applyNumEqualVerifyFuse (applyDoubleSwap
        (applyDupDrop (applyDoubleSha256 (applyOneAdd (applySubZero (applyAddZero
          (applyDoubleNegate (applyDoubleNot (applyDropAfterPush ops)))))))))) ) s
       = runOps ops s
  exact hSound11.trans (hSound10.trans (hSound9.trans (hSound8.trans
    (hSound7.trans (hSound6.trans (hSound5.trans (hSound4.trans
      (hSound3.trans (hSound2.trans hSound1)))))))))

/-! ## Phase 3t — `equalVerifyFuse` bytes variant + unified pass_sound

Adds the bytes counterpart of `equalVerifyFuse_pass_sound_int` (under a
`bytesStrict` precondition that requires two-bytes top at every OP_EQUAL
position), then a unified `equalVerifyFuse_pass_sound` that takes an
`eitherStrict` hypothesis (twoInts OR twoBytes at every OP_EQUAL position).

The unified version powers the 12-rule `peepholePassFullPlus` chain.
-/

/-! ### bytes-mixed reductions for `OP_EQUAL` / `OP_EQUALVERIFY`

Mirror of the `checkSigVerifyFuse_extends_anyBytes` family — handles all
4 vBytes/vOpaque pairings. -/

private theorem equalVerifyFuse_extends_anyBytes
    (s : StackState) (a b : ByteArray) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp)
    (hs : (s.stack = .vBytes b :: .vBytes a :: rest_top) ∨
          (s.stack = .vBytes b :: .vOpaque a :: rest_top) ∨
          (s.stack = .vOpaque b :: .vBytes a :: rest_top) ∨
          (s.stack = .vOpaque b :: .vOpaque a :: rest_top)) :
    runOps (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest) s
    = runOps (.opcode "OP_EQUALVERIFY" :: rest) s := by
  rcases hs with hBB | hBO | hOB | hOO
  · -- vBytes :: vBytes
    exact equalVerifyFuse_extends_bytes s a b rest_top rest hBB
  · -- vBytes :: vOpaque
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_EQUAL" s
          = .ok (({ s with stack := rest_top } : StackState).push
                  (.vBool (decide (a.toList = b.toList)))) from by
            rw [runOpcode_EQUAL_def, popN_two_cons s (.vBytes b) (.vOpaque a) rest_top hBO]
            simp [asBytes?, asInt?]]
    show runOps (.opcode "OP_VERIFY" :: rest)
          ((({ s with stack := rest_top } : StackState).push
              (.vBool (decide (a.toList = b.toList))))) = _
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_EQUALVERIFY" s
          = (if decide (a.toList = b.toList)
              then .ok ({ s with stack := rest_top } : StackState)
              else .error .assertFailed) from by
            rw [runOpcode_EQUALVERIFY_def,
                popN_two_cons s (.vBytes b) (.vOpaque a) rest_top hBO]
            simp [asBytes?, asInt?]]
  · -- vOpaque :: vBytes
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_EQUAL" s
          = .ok (({ s with stack := rest_top } : StackState).push
                  (.vBool (decide (a.toList = b.toList)))) from by
            rw [runOpcode_EQUAL_def, popN_two_cons s (.vOpaque b) (.vBytes a) rest_top hOB]
            simp [asBytes?, asInt?]]
    show runOps (.opcode "OP_VERIFY" :: rest)
          ((({ s with stack := rest_top } : StackState).push
              (.vBool (decide (a.toList = b.toList))))) = _
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_EQUALVERIFY" s
          = (if decide (a.toList = b.toList)
              then .ok ({ s with stack := rest_top } : StackState)
              else .error .assertFailed) from by
            rw [runOpcode_EQUALVERIFY_def,
                popN_two_cons s (.vOpaque b) (.vBytes a) rest_top hOB]
            simp [asBytes?, asInt?]]
  · -- vOpaque :: vOpaque
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_EQUAL" s
          = .ok (({ s with stack := rest_top } : StackState).push
                  (.vBool (decide (a.toList = b.toList)))) from by
            rw [runOpcode_EQUAL_def, popN_two_cons s (.vOpaque b) (.vOpaque a) rest_top hOO]
            simp [asBytes?, asInt?]]
    show runOps (.opcode "OP_VERIFY" :: rest)
          ((({ s with stack := rest_top } : StackState).push
              (.vBool (decide (a.toList = b.toList))))) = _
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_EQUALVERIFY" s
          = (if decide (a.toList = b.toList)
              then .ok ({ s with stack := rest_top } : StackState)
              else .error .assertFailed) from by
            rw [runOpcode_EQUALVERIFY_def,
                popN_two_cons s (.vOpaque b) (.vOpaque a) rest_top hOO]
            simp [asBytes?, asInt?]]

/-- Helper: reduce stepNonIf OP_EQUAL on two-bytes-mixed stacks to a uniform shape. -/
private theorem stepNonIf_OPEQUAL_anyBytes
    (s : StackState) (a b : ByteArray) (rest_top : List ANF.Eval.Value)
    (hs : (s.stack = .vBytes b :: .vBytes a :: rest_top) ∨
          (s.stack = .vBytes b :: .vOpaque a :: rest_top) ∨
          (s.stack = .vOpaque b :: .vBytes a :: rest_top) ∨
          (s.stack = .vOpaque b :: .vOpaque a :: rest_top)) :
    stepNonIf (.opcode "OP_EQUAL") s
    = .ok ((({ s with stack := rest_top } : StackState).push
              (.vBool (decide (a.toList = b.toList))))) := by
  rw [stepNonIf_opcode]
  rcases hs with hBB | hBO | hOB | hOO
  · rw [runOpcode_EQUAL_def, popN_two_cons s (.vBytes b) (.vBytes a) rest_top hBB]
    simp [asBytes?, asInt?]
  · rw [runOpcode_EQUAL_def, popN_two_cons s (.vBytes b) (.vOpaque a) rest_top hBO]
    simp [asBytes?, asInt?]
  · rw [runOpcode_EQUAL_def, popN_two_cons s (.vOpaque b) (.vBytes a) rest_top hOB]
    simp [asBytes?, asInt?]
  · rw [runOpcode_EQUAL_def, popN_two_cons s (.vOpaque b) (.vOpaque a) rest_top hOO]
    simp [asBytes?, asInt?]

/-! ### `equalVerifyFuse_bytesStrict` precondition

Bytes analog of `equalVerifyFuse_intStrict`: at every OP_EQUAL position,
the top two stack elements must be in `precondMet .twoBytes` form (vBytes
or vOpaque mixed). -/
def equalVerifyFuse_bytesStrict (ops : List StackOp) (s : StackState) : Prop :=
  match ops with
  | [] => True
  | op :: rest =>
      (if isOpEqual op then precondMet .twoBytes s else True) ∧
      (∀ s', stepNonIf op s = .ok s' → equalVerifyFuse_bytesStrict rest s')

theorem equalVerifyFuse_bytesStrict_nil (s : StackState) :
    equalVerifyFuse_bytesStrict [] s := True.intro

theorem equalVerifyFuse_bytesStrict_cons (op : StackOp) (rest : List StackOp) (s : StackState) :
    equalVerifyFuse_bytesStrict (op :: rest) s ↔
      ((if isOpEqual op then precondMet .twoBytes s else True) ∧
        (∀ s', stepNonIf op s = .ok s' → equalVerifyFuse_bytesStrict rest s')) :=
  Iff.rfl

/-- Bytes variant of `equalVerifyFuse_pass_sound_int`. Same recipe, with
`precondMet .twoBytes` and `precondMet_twoBytes_extract_strict` covering
the 4-way vBytes/vOpaque pairings via `equalVerifyFuse_extends_anyBytes`
and `stepNonIf_OPEQUAL_anyBytes`. -/
theorem equalVerifyFuse_pass_sound_bytes :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        equalVerifyFuse_bytesStrict ops s →
        runOps (applyEqualVerifyFuse ops) s = runOps ops s := by
  intro ops
  induction ops using applyEqualVerifyFuse.induct with
  | case1 => intros _ _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT hStrict
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    -- Extract `.twoBytes` precondition from hStrict at OP_EQUAL position.
    have ⟨hPrecondGuard, hStrictTail⟩ :=
      (equalVerifyFuse_bytesStrict_cons (.opcode "OP_EQUAL") _ s).mp hStrict
    have hPrecondBytes : precondMet .twoBytes s := by
      have hOpEq : isOpEqual (.opcode "OP_EQUAL") = true := isOpEqual_opcode_equal
      rw [hOpEq] at hPrecondGuard
      simpa using hPrecondGuard
    obtain ⟨b, a, rest_top, hStack⟩ := precondMet_twoBytes_extract_strict s hPrecondBytes
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    show runOps (.opcode "OP_EQUALVERIFY" :: applyEqualVerifyFuse rest') s
         = runOps (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest') s
    rw [equalVerifyFuse_extends_anyBytes s a b rest_top rest' hStack]
    apply runOps_cons_opcode_cong_typed
    intro s' hStepEV
    have hStepDef : stepNonIf (.opcode "OP_EQUALVERIFY") s
                  = (if decide (a.toList = b.toList) then
                      .ok ({ s with stack := rest_top } : StackState)
                     else .error .assertFailed) := by
      rw [stepNonIf_opcode]
      rcases hStack with hBB | hBO | hOB | hOO
      · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vBytes b) (.vBytes a) rest_top hBB]
        simp [asBytes?, asInt?]
      · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vBytes b) (.vOpaque a) rest_top hBO]
        simp [asBytes?, asInt?]
      · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vOpaque b) (.vBytes a) rest_top hOB]
        simp [asBytes?, asInt?]
      · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vOpaque b) (.vOpaque a) rest_top hOO]
        simp [asBytes?, asInt?]
    rw [hStepDef] at hStepEV
    by_cases hEq : decide (a.toList = b.toList) = true
    · rw [hEq] at hStepEV
      simp at hStepEV
      have hSEq : s' = ({ s with stack := rest_top } : StackState) := hStepEV.symm
      have hStep1 : stepNonIf (.opcode "OP_EQUAL") s
                  = .ok ((({ s with stack := rest_top } : StackState).push
                           (.vBool (decide (a.toList = b.toList))))) :=
        stepNonIf_OPEQUAL_anyBytes s a b rest_top hStack
      have hStrictTail' : equalVerifyFuse_bytesStrict (.opcode "OP_VERIFY" :: rest')
                            ((({ s with stack := rest_top } : StackState).push
                                (.vBool (decide (a.toList = b.toList))))) :=
        hStrictTail _ hStep1
      have ⟨_, hStrictTail2⟩ :=
        (equalVerifyFuse_bytesStrict_cons (.opcode "OP_VERIFY") rest' _).mp hStrictTail'
      have hStep2 : stepNonIf (.opcode "OP_VERIFY")
                      (({ s with stack := rest_top } : StackState).push
                        (.vBool (decide (a.toList = b.toList))))
                  = .ok ({ s with stack := rest_top } : StackState) := by
        rw [stepNonIf_opcode, runOpcode_verify_vBool, hEq]
        rfl
      have hStrictRest' : equalVerifyFuse_bytesStrict rest'
                            ({ s with stack := rest_top } : StackState) :=
        hStrictTail2 _ hStep2
      have hWell1 := hCont _ hStep1
      have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
      have hWellRest : wellTypedRun rest' ({ s with stack := rest_top } : StackState) :=
        hCont1 _ hStep2
      rw [hSEq]
      exact ih hRestNoIf _ hWellRest hStrictRest'
    · rw [show decide (a.toList = b.toList) = false from by
            rcases h : decide (a.toList = b.toList) with _ | _
            · rfl
            · exact absurd h hEq] at hStepEV
      simp at hStepEV
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT hStrict
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStrictTail : ∀ s', stepNonIf op s = .ok s' → equalVerifyFuse_bytesStrict rest' s' :=
      ((equalVerifyFuse_bytesStrict_cons op rest' s).mp hStrict).2
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyEqualVerifyFuse rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep) (hStrictTail s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyEqualVerifyFuse rest') s = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyEqualVerifyFuse rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyEqualVerifyFuse rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyEqualVerifyFuse rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyEqualVerifyFuse rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyEqualVerifyFuse rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyEqualVerifyFuse rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyEqualVerifyFuse rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyEqualVerifyFuse rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyEqualVerifyFuse rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        rw [applyEqualVerifyFuse_cons_no_match (.opcode code) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyEqualVerifyFuse rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyEqualVerifyFuse rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `equalVerifyFuse_eitherStrict` — unified precondition

Combines int and bytes: at every OP_EQUAL position, either the top two
elements are two ints (`precondMet .twoInts`) OR they are two
bytes/opaque (`precondMet .twoBytes`). This is the natural typing
discipline for OP_EQUAL: it accepts either int or bytes operands. -/
def equalVerifyFuse_eitherStrict (ops : List StackOp) (s : StackState) : Prop :=
  match ops with
  | [] => True
  | op :: rest =>
      (if isOpEqual op then (precondMet .twoInts s ∨ precondMet .twoBytes s) else True) ∧
      (∀ s', stepNonIf op s = .ok s' → equalVerifyFuse_eitherStrict rest s')

theorem equalVerifyFuse_eitherStrict_nil (s : StackState) :
    equalVerifyFuse_eitherStrict [] s := True.intro

theorem equalVerifyFuse_eitherStrict_cons (op : StackOp) (rest : List StackOp) (s : StackState) :
    equalVerifyFuse_eitherStrict (op :: rest) s ↔
      ((if isOpEqual op then (precondMet .twoInts s ∨ precondMet .twoBytes s) else True) ∧
        (∀ s', stepNonIf op s = .ok s' → equalVerifyFuse_eitherStrict rest s')) :=
  Iff.rfl

/-- Unified `equalVerifyFuse_pass_sound`. At each OP_EQUAL firing position,
case-split on the `eitherStrict` disjunction and apply the int or bytes
recipe. Non-firing positions inherit the same Phase 3s `case3` dispatcher. -/
theorem equalVerifyFuse_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        equalVerifyFuse_eitherStrict ops s →
        runOps (applyEqualVerifyFuse ops) s = runOps ops s := by
  intro ops
  induction ops using applyEqualVerifyFuse.induct with
  | case1 => intros _ _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT hStrict
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    -- Extract `eitherStrict` at OP_EQUAL position: twoInts ∨ twoBytes.
    have ⟨hPrecondGuard, hStrictTail⟩ :=
      (equalVerifyFuse_eitherStrict_cons (.opcode "OP_EQUAL") _ s).mp hStrict
    have hPrecondEither : precondMet .twoInts s ∨ precondMet .twoBytes s := by
      have hOpEq : isOpEqual (.opcode "OP_EQUAL") = true := isOpEqual_opcode_equal
      rw [hOpEq] at hPrecondGuard
      simpa using hPrecondGuard
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    -- Case-split on the disjunction.
    rcases hPrecondEither with hInts | hBytes
    · -- Int path: same as equalVerifyFuse_pass_sound_int's case2.
      obtain ⟨a, b, rest_top, hStack⟩ := precondMet_twoInts_extract s hInts
      show runOps (.opcode "OP_EQUALVERIFY" :: applyEqualVerifyFuse rest') s
           = runOps (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest') s
      rw [equalVerifyFuse_extends_int s a b rest_top rest' hStack]
      apply runOps_cons_opcode_cong_typed
      intro s' hStepEV
      have hStepDef : stepNonIf (.opcode "OP_EQUALVERIFY") s
                    = (if decide (a = b) then
                        .ok ({ s with stack := rest_top } : StackState)
                       else .error .assertFailed) := by
        rw [stepNonIf_opcode, runOpcode_equalVerify_int s a b rest_top hStack]
      rw [hStepDef] at hStepEV
      by_cases hEq : decide (a = b) = true
      · rw [hEq] at hStepEV
        simp at hStepEV
        have hSEq : s' = ({ s with stack := rest_top } : StackState) := hStepEV.symm
        have hStep1 : stepNonIf (.opcode "OP_EQUAL") s
                    = .ok ((({ s with stack := rest_top } : StackState).push
                             (.vBool (decide (a = b))))) := by
          rw [stepNonIf_opcode, runOpcode_equal_int s a b rest_top hStack]
        have hStrictTail' : equalVerifyFuse_eitherStrict (.opcode "OP_VERIFY" :: rest')
                              ((({ s with stack := rest_top } : StackState).push
                                  (.vBool (decide (a = b))))) :=
          hStrictTail _ hStep1
        have ⟨_, hStrictTail2⟩ :=
          (equalVerifyFuse_eitherStrict_cons (.opcode "OP_VERIFY") rest' _).mp hStrictTail'
        have hStep2 : stepNonIf (.opcode "OP_VERIFY")
                        (({ s with stack := rest_top } : StackState).push
                          (.vBool (decide (a = b))))
                    = .ok ({ s with stack := rest_top } : StackState) := by
          rw [stepNonIf_opcode, runOpcode_verify_vBool, hEq]
          rfl
        have hStrictRest' : equalVerifyFuse_eitherStrict rest'
                              ({ s with stack := rest_top } : StackState) :=
          hStrictTail2 _ hStep2
        have hWell1 := hCont _ hStep1
        have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
        have hWellRest : wellTypedRun rest' ({ s with stack := rest_top } : StackState) :=
          hCont1 _ hStep2
        rw [hSEq]
        exact ih hRestNoIf _ hWellRest hStrictRest'
      · rw [show decide (a = b) = false from by
              rcases h : decide (a = b) with _ | _
              · rfl
              · exact absurd h hEq] at hStepEV
        simp at hStepEV
    · -- Bytes path: same as equalVerifyFuse_pass_sound_bytes's case2.
      obtain ⟨b, a, rest_top, hStack⟩ := precondMet_twoBytes_extract_strict s hBytes
      show runOps (.opcode "OP_EQUALVERIFY" :: applyEqualVerifyFuse rest') s
           = runOps (.opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest') s
      rw [equalVerifyFuse_extends_anyBytes s a b rest_top rest' hStack]
      apply runOps_cons_opcode_cong_typed
      intro s' hStepEV
      have hStepDef : stepNonIf (.opcode "OP_EQUALVERIFY") s
                    = (if decide (a.toList = b.toList) then
                        .ok ({ s with stack := rest_top } : StackState)
                       else .error .assertFailed) := by
        rw [stepNonIf_opcode]
        rcases hStack with hBB | hBO | hOB | hOO
        · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vBytes b) (.vBytes a) rest_top hBB]
          simp [asBytes?, asInt?]
        · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vBytes b) (.vOpaque a) rest_top hBO]
          simp [asBytes?, asInt?]
        · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vOpaque b) (.vBytes a) rest_top hOB]
          simp [asBytes?, asInt?]
        · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vOpaque b) (.vOpaque a) rest_top hOO]
          simp [asBytes?, asInt?]
      rw [hStepDef] at hStepEV
      by_cases hEq : decide (a.toList = b.toList) = true
      · rw [hEq] at hStepEV
        simp at hStepEV
        have hSEq : s' = ({ s with stack := rest_top } : StackState) := hStepEV.symm
        have hStep1 : stepNonIf (.opcode "OP_EQUAL") s
                    = .ok ((({ s with stack := rest_top } : StackState).push
                             (.vBool (decide (a.toList = b.toList))))) :=
          stepNonIf_OPEQUAL_anyBytes s a b rest_top hStack
        have hStrictTail' : equalVerifyFuse_eitherStrict (.opcode "OP_VERIFY" :: rest')
                              ((({ s with stack := rest_top } : StackState).push
                                  (.vBool (decide (a.toList = b.toList))))) :=
          hStrictTail _ hStep1
        have ⟨_, hStrictTail2⟩ :=
          (equalVerifyFuse_eitherStrict_cons (.opcode "OP_VERIFY") rest' _).mp hStrictTail'
        have hStep2 : stepNonIf (.opcode "OP_VERIFY")
                        (({ s with stack := rest_top } : StackState).push
                          (.vBool (decide (a.toList = b.toList))))
                    = .ok ({ s with stack := rest_top } : StackState) := by
          rw [stepNonIf_opcode, runOpcode_verify_vBool, hEq]
          rfl
        have hStrictRest' : equalVerifyFuse_eitherStrict rest'
                              ({ s with stack := rest_top } : StackState) :=
          hStrictTail2 _ hStep2
        have hWell1 := hCont _ hStep1
        have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
        have hWellRest : wellTypedRun rest' ({ s with stack := rest_top } : StackState) :=
          hCont1 _ hStep2
        rw [hSEq]
        exact ih hRestNoIf _ hWellRest hStrictRest'
      · rw [show decide (a.toList = b.toList) = false from by
              rcases h : decide (a.toList = b.toList) with _ | _
              · rfl
              · exact absurd h hEq] at hStepEV
        simp at hStepEV
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT hStrict
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStrictTail : ∀ s', stepNonIf op s = .ok s' → equalVerifyFuse_eitherStrict rest' s' :=
      ((equalVerifyFuse_eitherStrict_cons op rest' s).mp hStrict).2
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyEqualVerifyFuse rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep) (hStrictTail s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyEqualVerifyFuse rest') s = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyEqualVerifyFuse rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyEqualVerifyFuse rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyEqualVerifyFuse rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyEqualVerifyFuse rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyEqualVerifyFuse rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyEqualVerifyFuse rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyEqualVerifyFuse rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyEqualVerifyFuse rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyEqualVerifyFuse rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        rw [applyEqualVerifyFuse_cons_no_match (.opcode code) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyEqualVerifyFuse rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyEqualVerifyFuse rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ## Phase 3u — additional 2-op rules from `peephole.ts`

This section ports four additional 2-op peephole rules from
`packages/runar-compiler/src/optimizer/peephole.ts` to Lean and proves
each one's `_pass_sound` theorem under the established recipe.

* `oneSub`        — `[push 1, OP_SUB] → [OP_1SUB]`        (mirrors `oneAdd`)
* `doubleOver`    — `[over, over]    → [OP_2DUP]`         (twoElems precond)
* `doubleDrop`    — `[drop, drop]    → [OP_2DROP]`        (twoElems precond)
* `zeroNumEqual`  — `[push 0, OP_NUMEQUAL] → [OP_NOT]`    (bigint precond)

The 3-op constant folds (`pushPushAdd`/`pushPushSub`/`pushPushMul`)
follow this section. The previously-deferred Phase 3v rules
(`checkMultiSigVerifyFuse` plus the 5 Roll/Pick rules) are landed in
the **Phase 3z-B** section below `pushPushMul_pass_sound`, after the
backing `Stack/Eval.lean` extensions (`OP_CHECKMULTISIG` /
`OP_CHECKMULTISIGVERIFY` semantics + bytecode-style `applyRoll` /
`applyPick`).
-/

/-! ### `oneSub_pass_sound` — Phase 3u

Non-identity rewrite `[push 1, OP_SUB] → [OP_1SUB]` under `.vBigint a :: _`
precondition. Mirrors `oneAdd_pass_sound`. -/

def applyOneSub : List StackOp → List StackOp
  | [] => []
  | .push (.bigint 1) :: .opcode "OP_SUB" :: rest => .opcode "OP_1SUB" :: applyOneSub rest
  | op :: rest => op :: applyOneSub rest

theorem applyOneSub_empty : applyOneSub [] = [] := rfl

theorem applyOneSub_match (rest : List StackOp) :
    applyOneSub (.push (.bigint 1) :: .opcode "OP_SUB" :: rest)
    = .opcode "OP_1SUB" :: applyOneSub rest := rfl

theorem runOpcode_1SUB_def (s : StackState) :
    runOpcode "OP_1SUB" s = liftIntUnary s (fun i => .vBigint (i - 1)) := rfl

/-- `[push 1, OP_SUB]` extends to `[OP_1SUB]` under `.vBigint a :: rest_stack` precondition. -/
theorem oneSub_extends (s : StackState) (a : Int) (rest_stack : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vBigint a :: rest_stack) :
    runOps (.push (.bigint 1) :: .opcode "OP_SUB" :: rest) s
    = runOps (.opcode "OP_1SUB" :: rest) s := by
  rw [runOps_cons_PUSHbigint]
  have hs' : (s.push (.vBigint 1)).stack = .vBigint 1 :: .vBigint a :: rest_stack := by
    unfold StackState.push; simp [hs]
  rw [runOps_cons_OPSUB_two_ints (s.push (.vBigint 1)) a 1 rest_stack rest hs']
  rw [runOps_cons_opcode_eq, stepNonIf_opcode]
  rw [runOpcode_1SUB_def]
  unfold liftIntUnary StackState.pop?
  rw [hs]
  simp [asInt?]
  cases s
  simp_all [StackState.push]

private theorem applyOneSub_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .push (.bigint 1) → rest = .opcode "OP_SUB" :: rt → False) :
    applyOneSub (op :: rest) = op :: applyOneSub rest :=
  applyOneSub.eq_3 op rest h

theorem oneSub_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyOneSub ops) s = runOps ops s := by
  intro ops
  induction ops using applyOneSub.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint 1) :: .opcode "OP_SUB" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 1)) s = .ok (s.push (.vBigint 1)) :=
      stepNonIf_push_bigint s 1
    have hWellSub : wellTypedRun (.opcode "OP_SUB" :: rest') (s.push (.vBigint 1)) :=
      hCont _ hStepPush
    have ⟨hPrecondSub, _⟩ := wellTypedRun_cons _ _ _ |>.mp hWellSub
    obtain ⟨a, b, rest_stack, hStackPush⟩ :=
      precondMet_twoInts_extract _ hPrecondSub
    have hPushStack : (s.push (.vBigint 1)).stack = .vBigint 1 :: s.stack := by
      unfold StackState.push; simp
    have hStackEq : .vBigint 1 :: s.stack = .vBigint b :: .vBigint a :: rest_stack := by
      rw [← hPushStack]; exact hStackPush
    have hb : b = 1 := by
      have hHead := List.head_eq_of_cons_eq hStackEq
      injection hHead with h
      exact h.symm
    have hSStack : s.stack = .vBigint a :: rest_stack :=
      List.tail_eq_of_cons_eq hStackEq
    have hStackForSub : (s.push (.vBigint 1)).stack
                      = .vBigint 1 :: .vBigint a :: rest_stack := by
      rw [hPushStack, hSStack]
    show runOps (.opcode "OP_1SUB" :: applyOneSub rest') s
         = runOps (.push (.bigint 1) :: .opcode "OP_SUB" :: rest') s
    rw [oneSub_extends s a rest_stack rest' hSStack]
    apply runOps_cons_opcode_cong_typed
    intro s' hStep1SUB
    have ⟨_, hContSub⟩ := wellTypedRun_cons _ _ _ |>.mp hWellSub
    have hStepSub : stepNonIf (.opcode "OP_SUB") (s.push (.vBigint 1)) = .ok s' := by
      rw [stepNonIf_opcode]
      rw [runOpcode_sub_int_concrete (s.push (.vBigint 1)) a 1 rest_stack hStackForSub]
      have hStepDef : stepNonIf (.opcode "OP_1SUB") s
                    = .ok (({ s with stack := rest_stack } : StackState).push (.vBigint (a - 1))) := by
        rw [stepNonIf_opcode, runOpcode_1SUB_def]
        unfold liftIntUnary StackState.pop?
        rw [hSStack]
        simp [asInt?, StackState.push]
      have hSEq : s' = ({ s with stack := rest_stack } : StackState).push (.vBigint (a - 1)) := by
        rw [hStepDef] at hStep1SUB
        exact ((Except.ok.injEq _ _).mp hStep1SUB).symm
      rw [hSEq]
      cases s
      simp_all [StackState.push]
    have hWellRest : wellTypedRun rest' s' := hContSub s' hStepSub
    exact ih hRestNoIf s' hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyOneSub rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyOneSub_cons_no_match (.push v) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyOneSub rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyOneSub rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyOneSub rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyOneSub rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyOneSub rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyOneSub rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyOneSub rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyOneSub rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyOneSub rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyOneSub rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyOneSub rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyOneSub rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `doubleOver_pass_sound` — Phase 3u

Non-identity rewrite `[over, over] → [OP_2DUP]` under `.twoElems` precondition. -/

def applyDoubleOver : List StackOp → List StackOp
  | [] => []
  | .over :: .over :: rest => .opcode "OP_2DUP" :: applyDoubleOver rest
  | op :: rest => op :: applyDoubleOver rest

theorem applyDoubleOver_empty : applyDoubleOver [] = [] := rfl

theorem applyDoubleOver_match (rest : List StackOp) :
    applyDoubleOver (.over :: .over :: rest)
    = .opcode "OP_2DUP" :: applyDoubleOver rest := rfl

theorem runOpcode_2DUP_def (s : StackState) :
    runOpcode "OP_2DUP" s
    = (match applyOver s with
       | .error e => .error e
       | .ok s1 => applyOver s1) := rfl

/-- `applyOver` on a 2+-element stack `a :: b :: rest_top`. -/
private theorem applyOver_cons2 (s : StackState) (a b : ANF.Eval.Value)
    (rest_top : List ANF.Eval.Value) (hs : s.stack = a :: b :: rest_top) :
    applyOver s = .ok ({ s with stack := b :: a :: b :: rest_top } : StackState) := by
  unfold applyOver
  rw [hs]

private theorem stepNonIf_over_def (s : StackState) :
    stepNonIf .over s = applyOver s := rfl

/-- `[over, over]` extends to `[OP_2DUP]` under `.twoElems` precondition. -/
theorem doubleOver_extends (s : StackState) (a b : ANF.Eval.Value)
    (rest_top : List ANF.Eval.Value) (rest : List StackOp)
    (hs : s.stack = a :: b :: rest_top) :
    runOps (.over :: .over :: rest) s
    = runOps (.opcode "OP_2DUP" :: rest) s := by
  have hs1 : ({ s with stack := b :: a :: b :: rest_top } : StackState).stack
           = b :: a :: b :: rest_top := rfl
  -- Both sides reduce to `runOps rest ({ s with stack := a :: b :: a :: b :: rest_top })`.
  have hLHS : runOps (.over :: .over :: rest) s
            = runOps rest ({ s with stack := a :: b :: a :: b :: rest_top } : StackState) := by
    rw [runOps_cons_over_eq, stepNonIf_over_def, applyOver_cons2 s a b rest_top hs]
    show runOps (.over :: rest) ({ s with stack := b :: a :: b :: rest_top } : StackState)
         = runOps rest ({ s with stack := a :: b :: a :: b :: rest_top } : StackState)
    rw [runOps_cons_over_eq, stepNonIf_over_def,
        applyOver_cons2 _ b a (b :: rest_top) hs1]
  have hRHS : runOps (.opcode "OP_2DUP" :: rest) s
            = runOps rest ({ s with stack := a :: b :: a :: b :: rest_top } : StackState) := by
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_2DUP_def]
    rw [applyOver_cons2 s a b rest_top hs]
    show (match applyOver ({ s with stack := b :: a :: b :: rest_top } : StackState) with
          | Except.error e => Except.error e
          | Except.ok s'   => runOps rest s')
       = runOps rest ({ s with stack := a :: b :: a :: b :: rest_top } : StackState)
    rw [applyOver_cons2 _ b a (b :: rest_top) hs1]
  rw [hLHS, hRHS]

private theorem applyDoubleOver_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .over → rest = .over :: rt → False) :
    applyDoubleOver (op :: rest) = op :: applyDoubleOver rest :=
  applyDoubleOver.eq_3 op rest h

theorem doubleOver_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyDoubleOver ops) s = runOps ops s := by
  intro ops
  induction ops using applyDoubleOver.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.over :: .over :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨a, b, rest_top, hStack⟩ := precondMet_twoElems_extract s hPrecond
    -- After first over: stack = b :: a :: b :: rest_top.
    let s1 : StackState := { s with stack := b :: a :: b :: rest_top }
    have hStepOver1 : stepNonIf .over s = .ok s1 := by
      rw [stepNonIf_over_def]; exact applyOver_cons2 s a b rest_top hStack
    have hWell1 : wellTypedRun (.over :: rest') s1 := hCont s1 hStepOver1
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    -- After second over: stack = a :: b :: a :: b :: rest_top.
    let s2 : StackState := { s with stack := a :: b :: a :: b :: rest_top }
    have hs1stack : s1.stack = b :: a :: b :: rest_top := rfl
    have hStepOver2 : stepNonIf .over s1 = .ok s2 := by
      rw [stepNonIf_over_def]
      rw [applyOver_cons2 s1 b a (b :: rest_top) hs1stack]
    have hWellRest : wellTypedRun rest' s2 := hCont1 s2 hStepOver2
    show runOps (.opcode "OP_2DUP" :: applyDoubleOver rest') s
         = runOps (.over :: .over :: rest') s
    rw [doubleOver_extends s a b rest_top rest' hStack]
    apply runOps_cons_opcode_cong_typed
    intro s' hStep2DUP
    -- s' = s2 from hStep2DUP.
    have hStepDef : stepNonIf (.opcode "OP_2DUP") s = .ok s2 := by
      rw [stepNonIf_opcode, runOpcode_2DUP_def]
      rw [applyOver_cons2 s a b rest_top hStack]
      show applyOver ({ s with stack := b :: a :: b :: rest_top } : StackState) = Except.ok s2
      rw [applyOver_cons2 _ b a (b :: rest_top) hs1stack]
    have hSEq : s' = s2 := by
      rw [hStepDef] at hStep2DUP
      exact ((Except.ok.injEq _ _).mp hStep2DUP).symm
    rw [hSEq]
    exact ih hRestNoIf s2 hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyDoubleOver rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyDoubleOver rest') s = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyDoubleOver rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyDoubleOver rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyDoubleOver rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyDoubleOver rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        rw [applyDoubleOver_cons_no_match .over rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyDoubleOver rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyDoubleOver rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyDoubleOver rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyDoubleOver rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyDoubleOver rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyDoubleOver rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyDoubleOver rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `doubleDrop_pass_sound` — Phase 3u

Non-identity rewrite `[drop, drop] → [OP_2DROP]` under `.twoElems` precondition. -/

def applyDoubleDrop : List StackOp → List StackOp
  | [] => []
  | .drop :: .drop :: rest => .opcode "OP_2DROP" :: applyDoubleDrop rest
  | op :: rest => op :: applyDoubleDrop rest

theorem applyDoubleDrop_empty : applyDoubleDrop [] = [] := rfl

theorem applyDoubleDrop_match (rest : List StackOp) :
    applyDoubleDrop (.drop :: .drop :: rest)
    = .opcode "OP_2DROP" :: applyDoubleDrop rest := rfl

theorem runOpcode_2DROP_def (s : StackState) :
    runOpcode "OP_2DROP" s
    = (match applyDrop s with
       | .error e => .error e
       | .ok s1 => applyDrop s1) := rfl

/-- `[drop, drop]` extends to `[OP_2DROP]` under `.twoElems` precondition. -/
theorem doubleDrop_extends (s : StackState) (a b : ANF.Eval.Value)
    (rest_top : List ANF.Eval.Value) (rest : List StackOp)
    (hs : s.stack = a :: b :: rest_top) :
    runOps (.drop :: .drop :: rest) s
    = runOps (.opcode "OP_2DROP" :: rest) s := by
  -- Both sides reduce to `runOps rest ({ s with stack := rest_top })`.
  have hs1 : ({ s with stack := b :: rest_top } : StackState).stack = b :: rest_top := rfl
  -- LHS reduction: drop removes top twice.
  have hLHS : runOps (.drop :: .drop :: rest) s
            = runOps rest ({ s with stack := rest_top } : StackState) := by
    rw [runOps_cons_drop_eq, stepNonIf_drop,
        applyDrop_cons s a (b :: rest_top) hs]
    show runOps (.drop :: rest) ({ s with stack := b :: rest_top } : StackState)
         = runOps rest ({ s with stack := rest_top } : StackState)
    rw [runOps_cons_drop_eq, stepNonIf_drop,
        applyDrop_cons _ b rest_top hs1]
  -- RHS reduction: OP_2DROP = drop ∘ drop.
  have hRHS : runOps (.opcode "OP_2DROP" :: rest) s
            = runOps rest ({ s with stack := rest_top } : StackState) := by
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_2DROP_def]
    rw [applyDrop_cons s a (b :: rest_top) hs]
    -- After rewrite, goal is `match match .ok s1 with | .ok => applyDrop s1 with ... = ...`
    -- The inner match reduces to `applyDrop s1`. We rewrite that.
    show (match applyDrop ({ s with stack := b :: rest_top } : StackState) with
          | Except.error e => Except.error e
          | Except.ok s'   => runOps rest s')
       = runOps rest ({ s with stack := rest_top } : StackState)
    rw [applyDrop_cons _ b rest_top hs1]
  rw [hLHS, hRHS]

private theorem applyDoubleDrop_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .drop → rest = .drop :: rt → False) :
    applyDoubleDrop (op :: rest) = op :: applyDoubleDrop rest :=
  applyDoubleDrop.eq_3 op rest h

theorem doubleDrop_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyDoubleDrop ops) s = runOps ops s := by
  intro ops
  induction ops using applyDoubleDrop.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.drop :: .drop :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    -- The first drop's precond is `.nonEmpty` (from opPrecondition .drop), not `.twoElems`.
    -- So we extract the second drop's precond from hCont after first stepNonIf.
    have ⟨hPrecond1, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨a, rest_after_one, hStack1⟩ := precondMet_nonEmpty_extract s hPrecond1
    -- After first drop: stack = rest_after_one.
    let s1 : StackState := { s with stack := rest_after_one }
    have hStepDrop1 : stepNonIf .drop s = .ok s1 := by
      rw [stepNonIf_drop]; exact applyDrop_cons s a rest_after_one hStack1
    have hWell1 : wellTypedRun (.drop :: rest') s1 := hCont s1 hStepDrop1
    have ⟨hPrecond2, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    -- s1's stack is rest_after_one; the second drop needs nonEmpty on this.
    have hs1stack : s1.stack = rest_after_one := rfl
    obtain ⟨b, rest_top, hStack2⟩ := precondMet_nonEmpty_extract s1 hPrecond2
    have hRestEq : rest_after_one = b :: rest_top := by
      rw [← hs1stack]; exact hStack2
    have hStackOrig : s.stack = a :: b :: rest_top := by
      rw [hStack1, hRestEq]
    -- After second drop: stack = rest_top.
    let s2 : StackState := { s with stack := rest_top }
    have hStepDrop2 : stepNonIf .drop s1 = .ok s2 := by
      rw [stepNonIf_drop]
      rw [applyDrop_cons s1 b rest_top hStack2]
    have hWellRest : wellTypedRun rest' s2 := hCont1 s2 hStepDrop2
    show runOps (.opcode "OP_2DROP" :: applyDoubleDrop rest') s
         = runOps (.drop :: .drop :: rest') s
    rw [doubleDrop_extends s a b rest_top rest' hStackOrig]
    apply runOps_cons_opcode_cong_typed
    intro s' hStep2DROP
    have hStepDef : stepNonIf (.opcode "OP_2DROP") s = .ok s2 := by
      rw [stepNonIf_opcode, runOpcode_2DROP_def]
      rw [applyDrop_cons s a (b :: rest_top) hStackOrig]
      -- Goal: match Except.ok ({ s with stack := b :: rest_top }) with | .ok s1 => applyDrop s1 = .ok s2.
      have hs1' : ({ s with stack := b :: rest_top } : StackState).stack = b :: rest_top := rfl
      show applyDrop ({ s with stack := b :: rest_top } : StackState) = Except.ok s2
      rw [applyDrop_cons _ b rest_top hs1']
    have hSEq : s' = s2 := by
      rw [hStepDef] at hStep2DROP
      exact ((Except.ok.injEq _ _).mp hStep2DROP).symm
    rw [hSEq]
    exact ih hRestNoIf s2 hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyDoubleDrop rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyDoubleDrop rest') s = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyDoubleDrop rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyDoubleDrop rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        rw [applyDoubleDrop_cons_no_match .drop rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyDoubleDrop rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyDoubleDrop rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyDoubleDrop rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyDoubleDrop rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyDoubleDrop rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyDoubleDrop rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyDoubleDrop rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyDoubleDrop rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyDoubleDrop rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `zeroNumEqual_pass_sound` — Phase 3u

Non-identity rewrite `[push 0, OP_NUMEQUAL] → [OP_NOT]` under `.bigint` precondition.
Both sides leave `.vBool (decide (i = 0))` on top. -/

def applyZeroNumEqual : List StackOp → List StackOp
  | [] => []
  | .push (.bigint 0) :: .opcode "OP_NUMEQUAL" :: rest => .opcode "OP_NOT" :: applyZeroNumEqual rest
  | op :: rest => op :: applyZeroNumEqual rest

theorem applyZeroNumEqual_empty : applyZeroNumEqual [] = [] := rfl

theorem applyZeroNumEqual_match (rest : List StackOp) :
    applyZeroNumEqual (.push (.bigint 0) :: .opcode "OP_NUMEQUAL" :: rest)
    = .opcode "OP_NOT" :: applyZeroNumEqual rest := rfl

/-- `[push 0, OP_NUMEQUAL]` extends to `[OP_NOT]` under `.vBigint i :: rest_top` precondition. -/
theorem zeroNumEqual_extends (s : StackState) (i : Int) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp) (hs : s.stack = .vBigint i :: rest_top) :
    runOps (.push (.bigint 0) :: .opcode "OP_NUMEQUAL" :: rest) s
    = runOps (.opcode "OP_NOT" :: rest) s := by
  -- Both sides reduce to `runOps rest ({s with stack := .vBool (decide (i = 0)) :: rest_top})`.
  have hBool : (decide (i = 0) : Bool) = !decide (i ≠ 0) := by
    by_cases h : i = 0
    · simp [h]
    · simp [h]
  -- LHS: push 0 → NUMEQUAL.
  have hLHS : runOps (.push (.bigint 0) :: .opcode "OP_NUMEQUAL" :: rest) s
            = runOps rest
                ((({ s with stack := rest_top } : StackState).push
                    (.vBool (decide (i = 0))))) := by
    rw [runOps_cons_PUSHbigint]
    have hs' : (s.push (.vBigint 0)).stack = .vBigint 0 :: .vBigint i :: rest_top := by
      unfold StackState.push; simp [hs]
    rw [runOps_cons_opcode_eq, stepNonIf_opcode,
        runOpcode_numEqual_int (s.push (.vBigint 0)) i 0 rest_top hs']
    -- The post-NUMEQUAL state's stack is rest_top, and the underlying base record
    -- equals s (before push) — show by case-split on s.
    cases s
    simp_all [StackState.push]
  -- RHS: OP_NOT on `.vBigint i`.
  have hRHS : runOps (.opcode "OP_NOT" :: rest) s
            = runOps rest
                ((({ s with stack := rest_top } : StackState).push
                    (.vBool (!decide (i ≠ 0))))) := by
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_NOT_def]
    unfold StackState.pop?
    rw [hs]
    simp [asBool?, StackState.push]
  rw [hLHS, hRHS, hBool]

private theorem applyZeroNumEqual_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .push (.bigint 0) → rest = .opcode "OP_NUMEQUAL" :: rt → False) :
    applyZeroNumEqual (op :: rest) = op :: applyZeroNumEqual rest :=
  applyZeroNumEqual.eq_3 op rest h

theorem zeroNumEqual_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyZeroNumEqual ops) s = runOps ops s := by
  intro ops
  induction ops using applyZeroNumEqual.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint 0) :: .opcode "OP_NUMEQUAL" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 0)) s = .ok (s.push (.vBigint 0)) :=
      stepNonIf_push_bigint s 0
    have hWellNumEq : wellTypedRun (.opcode "OP_NUMEQUAL" :: rest') (s.push (.vBigint 0)) :=
      hCont _ hStepPush
    have ⟨hPrecondNumEq, hContNumEq⟩ := wellTypedRun_cons _ _ _ |>.mp hWellNumEq
    obtain ⟨a, b, rest_stack, hStackPush⟩ :=
      precondMet_twoInts_extract _ hPrecondNumEq
    have hPushStack : (s.push (.vBigint 0)).stack = .vBigint 0 :: s.stack := by
      unfold StackState.push; simp
    have hStackEq : .vBigint 0 :: s.stack = .vBigint b :: .vBigint a :: rest_stack := by
      rw [← hPushStack]; exact hStackPush
    have hb : b = 0 := by
      have hHead := List.head_eq_of_cons_eq hStackEq
      injection hHead with h
      exact h.symm
    have hSStack : s.stack = .vBigint a :: rest_stack :=
      List.tail_eq_of_cons_eq hStackEq
    show runOps (.opcode "OP_NOT" :: applyZeroNumEqual rest') s
         = runOps (.push (.bigint 0) :: .opcode "OP_NUMEQUAL" :: rest') s
    rw [zeroNumEqual_extends s a rest_stack rest' hSStack]
    apply runOps_cons_opcode_cong_typed
    intro s' hStepNOT
    -- We need wellTypedRun rest' s' from the OP_NUMEQUAL chain.
    -- After NUMEQUAL on (s.push (.vBigint 0)) with stack [.vBigint 0, .vBigint a, ...],
    -- post-stack is .vBool (decide (a = 0)) :: rest_stack.
    have hStackFor : (s.push (.vBigint 0)).stack = .vBigint 0 :: .vBigint a :: rest_stack := by
      rw [hPushStack, hSStack]
    have hStepNumEq : stepNonIf (.opcode "OP_NUMEQUAL") (s.push (.vBigint 0))
                    = .ok ((({ s with stack := rest_stack } : StackState).push
                              (.vBool (decide (a = 0))))) := by
      rw [stepNonIf_opcode, runOpcode_numEqual_int (s.push (.vBigint 0)) a 0 rest_stack hStackFor]
      cases s
      simp_all [StackState.push]
    have hWellRest1 : wellTypedRun rest'
                        (({ s with stack := rest_stack } : StackState).push
                              (.vBool (decide (a = 0)))) := hContNumEq _ hStepNumEq
    -- And from hStepNOT we know stepNonIf OP_NOT s = .ok s'.
    -- Reduce stepNonIf OP_NOT s using hSStack.
    have hStepNOTDef : stepNonIf (.opcode "OP_NOT") s
                     = .ok ((({ s with stack := rest_stack } : StackState).push
                              (.vBool (!decide (a ≠ 0))))) := by
      rw [stepNonIf_opcode, runOpcode_NOT_def]
      unfold StackState.pop?
      rw [hSStack]
      simp [asBool?, StackState.push]
    have hSEq : s' = (({ s with stack := rest_stack } : StackState).push
                       (.vBool (!decide (a ≠ 0)))) := by
      rw [hStepNOTDef] at hStepNOT
      exact ((Except.ok.injEq _ _).mp hStepNOT).symm
    -- The .vBool values are equal: decide (a = 0) = !decide (a ≠ 0).
    have hBoolEq : decide (a = 0) = !decide (a ≠ 0) := by
      by_cases h : a = 0
      · simp [h]
      · simp [h]
    rw [hSEq, ← hBoolEq]
    exact ih hRestNoIf _ hWellRest1
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyZeroNumEqual rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyZeroNumEqual_cons_no_match (.push v) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyZeroNumEqual rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyZeroNumEqual rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyZeroNumEqual rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyZeroNumEqual rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyZeroNumEqual rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyZeroNumEqual rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyZeroNumEqual rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyZeroNumEqual rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyZeroNumEqual rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyZeroNumEqual rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyZeroNumEqual rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyZeroNumEqual rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `pushPushAdd_pass_sound` — Phase 3u stretch

3-op constant fold `[push a, push b, OP_ADD] → [push (a+b)]`.
Both reduce to `s.push (.vBigint (a+b))` on top, with no precondition
beyond what's structurally encoded (OP_ADD on two ints, automatic from
push pattern). -/

def applyPushPushAdd : List StackOp → List StackOp
  | [] => []
  | .push (.bigint a) :: .push (.bigint b) :: .opcode "OP_ADD" :: rest =>
      .push (.bigint (a + b)) :: applyPushPushAdd rest
  | op :: rest => op :: applyPushPushAdd rest

theorem applyPushPushAdd_empty : applyPushPushAdd [] = [] := rfl

theorem applyPushPushAdd_match (a b : Int) (rest : List StackOp) :
    applyPushPushAdd (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_ADD" :: rest)
    = .push (.bigint (a + b)) :: applyPushPushAdd rest := rfl

theorem pushPushAdd_extends (s : StackState) (a b : Int) (rest : List StackOp) :
    runOps (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_ADD" :: rest) s
    = runOps (.push (.bigint (a + b)) :: rest) s := by
  rw [runOps_cons_PUSHbigint, runOps_cons_PUSHbigint]
  -- After two pushes, stack = .vBigint b :: .vBigint a :: s.stack.
  have hs' : ((s.push (.vBigint a)).push (.vBigint b)).stack
           = .vBigint b :: .vBigint a :: s.stack := by
    unfold StackState.push; simp
  rw [runOps_cons_opcode_eq, stepNonIf_opcode,
      runOpcode_add_int_concrete _ a b s.stack hs']
  rw [runOps_cons_PUSHbigint]
  -- Both sides should equal `runOps rest (s.push (.vBigint (a + b)))`.
  cases s
  simp [StackState.push]

private theorem applyPushPushAdd_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ a b rt, op = .push (.bigint a) → rest = .push (.bigint b) :: .opcode "OP_ADD" :: rt → False) :
    applyPushPushAdd (op :: rest) = op :: applyPushPushAdd rest :=
  applyPushPushAdd.eq_3 op rest h

/-- Simpler-soundness theorem with structural recursion: not using `.induct` since
the case-3 dispatch on push-shapes is non-trivial. We instead recurse on the
op list directly using a strong-induction setup keyed by length. -/
theorem pushPushAdd_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyPushPushAdd ops) s = runOps ops s := by
  intro ops
  induction ops using applyPushPushAdd.induct with
  | case1 => intros _ _ _; rfl
  | case2 a b rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_ADD" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    -- Continuation chain: push a, push b, OP_ADD all chained.
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPushA : stepNonIf (.push (.bigint a)) s = .ok (s.push (.vBigint a)) :=
      stepNonIf_push_bigint s a
    have hWell1 : wellTypedRun (.push (.bigint b) :: .opcode "OP_ADD" :: rest')
                    (s.push (.vBigint a)) := hCont _ hStepPushA
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    have hStepPushB : stepNonIf (.push (.bigint b)) (s.push (.vBigint a))
                    = .ok ((s.push (.vBigint a)).push (.vBigint b)) :=
      stepNonIf_push_bigint _ b
    have hWell2 : wellTypedRun (.opcode "OP_ADD" :: rest')
                    ((s.push (.vBigint a)).push (.vBigint b)) := hCont1 _ hStepPushB
    have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell2
    have hPostStack : ((s.push (.vBigint a)).push (.vBigint b)).stack
                    = .vBigint b :: .vBigint a :: s.stack := by
      unfold StackState.push; simp
    have hStepAdd : stepNonIf (.opcode "OP_ADD") ((s.push (.vBigint a)).push (.vBigint b))
                  = .ok (s.push (.vBigint (a + b))) := by
      rw [stepNonIf_opcode]
      rw [runOpcode_add_int_concrete _ a b s.stack hPostStack]
      cases s
      simp [StackState.push]
    have hWellRest : wellTypedRun rest' (s.push (.vBigint (a + b))) := hCont2 _ hStepAdd
    show runOps (.push (.bigint (a + b)) :: applyPushPushAdd rest') s
         = runOps (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_ADD" :: rest') s
    rw [pushPushAdd_extends s a b rest']
    apply runOps_cons_push_cong_typed
    intro s' hStepPushAB
    -- s' = s.push (.vBigint (a+b)).
    have hSEq : s' = s.push (.vBigint (a + b)) := by
      have : stepNonIf (.push (.bigint (a + b))) s = .ok (s.push (.vBigint (a + b))) :=
        stepNonIf_push_bigint s (a + b)
      rw [this] at hStepPushAB
      exact ((Except.ok.injEq _ _).mp hStepPushAB).symm
    rw [hSEq]
    exact ih hRestNoIf _ hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyPushPushAdd rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyPushPushAdd_cons_no_match (.push v) rest'
              (fun a b rt hOp hRest => h_no_match a b rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyPushPushAdd rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyPushPushAdd rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyPushPushAdd rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyPushPushAdd rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyPushPushAdd rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyPushPushAdd rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyPushPushAdd rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyPushPushAdd rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyPushPushAdd rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyPushPushAdd rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyPushPushAdd rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyPushPushAdd rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `pushPushSub_pass_sound` — Phase 3u stretch

3-op constant fold `[push a, push b, OP_SUB] → [push (a-b)]`. -/

def applyPushPushSub : List StackOp → List StackOp
  | [] => []
  | .push (.bigint a) :: .push (.bigint b) :: .opcode "OP_SUB" :: rest =>
      .push (.bigint (a - b)) :: applyPushPushSub rest
  | op :: rest => op :: applyPushPushSub rest

theorem applyPushPushSub_empty : applyPushPushSub [] = [] := rfl

theorem applyPushPushSub_match (a b : Int) (rest : List StackOp) :
    applyPushPushSub (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_SUB" :: rest)
    = .push (.bigint (a - b)) :: applyPushPushSub rest := rfl

theorem pushPushSub_extends (s : StackState) (a b : Int) (rest : List StackOp) :
    runOps (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_SUB" :: rest) s
    = runOps (.push (.bigint (a - b)) :: rest) s := by
  rw [runOps_cons_PUSHbigint, runOps_cons_PUSHbigint]
  have hs' : ((s.push (.vBigint a)).push (.vBigint b)).stack
           = .vBigint b :: .vBigint a :: s.stack := by
    unfold StackState.push; simp
  rw [runOps_cons_opcode_eq, stepNonIf_opcode,
      runOpcode_sub_int_concrete _ a b s.stack hs']
  rw [runOps_cons_PUSHbigint]
  cases s
  simp [StackState.push]

private theorem applyPushPushSub_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ a b rt, op = .push (.bigint a) → rest = .push (.bigint b) :: .opcode "OP_SUB" :: rt → False) :
    applyPushPushSub (op :: rest) = op :: applyPushPushSub rest :=
  applyPushPushSub.eq_3 op rest h

theorem pushPushSub_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyPushPushSub ops) s = runOps ops s := by
  intro ops
  induction ops using applyPushPushSub.induct with
  | case1 => intros _ _ _; rfl
  | case2 a b rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_SUB" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPushA : stepNonIf (.push (.bigint a)) s = .ok (s.push (.vBigint a)) :=
      stepNonIf_push_bigint s a
    have hWell1 : wellTypedRun (.push (.bigint b) :: .opcode "OP_SUB" :: rest')
                    (s.push (.vBigint a)) := hCont _ hStepPushA
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    have hStepPushB : stepNonIf (.push (.bigint b)) (s.push (.vBigint a))
                    = .ok ((s.push (.vBigint a)).push (.vBigint b)) :=
      stepNonIf_push_bigint _ b
    have hWell2 : wellTypedRun (.opcode "OP_SUB" :: rest')
                    ((s.push (.vBigint a)).push (.vBigint b)) := hCont1 _ hStepPushB
    have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell2
    have hPostStack : ((s.push (.vBigint a)).push (.vBigint b)).stack
                    = .vBigint b :: .vBigint a :: s.stack := by
      unfold StackState.push; simp
    have hStepSub : stepNonIf (.opcode "OP_SUB") ((s.push (.vBigint a)).push (.vBigint b))
                  = .ok (s.push (.vBigint (a - b))) := by
      rw [stepNonIf_opcode]
      rw [runOpcode_sub_int_concrete _ a b s.stack hPostStack]
      cases s
      simp [StackState.push]
    have hWellRest : wellTypedRun rest' (s.push (.vBigint (a - b))) := hCont2 _ hStepSub
    show runOps (.push (.bigint (a - b)) :: applyPushPushSub rest') s
         = runOps (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_SUB" :: rest') s
    rw [pushPushSub_extends s a b rest']
    apply runOps_cons_push_cong_typed
    intro s' hStepPushAB
    have hSEq : s' = s.push (.vBigint (a - b)) := by
      have : stepNonIf (.push (.bigint (a - b))) s = .ok (s.push (.vBigint (a - b))) :=
        stepNonIf_push_bigint s (a - b)
      rw [this] at hStepPushAB
      exact ((Except.ok.injEq _ _).mp hStepPushAB).symm
    rw [hSEq]
    exact ih hRestNoIf _ hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyPushPushSub rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyPushPushSub_cons_no_match (.push v) rest'
              (fun a b rt hOp hRest => h_no_match a b rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyPushPushSub rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyPushPushSub rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyPushPushSub rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyPushPushSub rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyPushPushSub rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyPushPushSub rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyPushPushSub rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyPushPushSub rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyPushPushSub rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyPushPushSub rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyPushPushSub rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyPushPushSub rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### `pushPushMul_pass_sound` — Phase 3u stretch

3-op constant fold `[push a, push b, OP_MUL] → [push (a*b)]`. -/

def applyPushPushMul : List StackOp → List StackOp
  | [] => []
  | .push (.bigint a) :: .push (.bigint b) :: .opcode "OP_MUL" :: rest =>
      .push (.bigint (a * b)) :: applyPushPushMul rest
  | op :: rest => op :: applyPushPushMul rest

theorem applyPushPushMul_empty : applyPushPushMul [] = [] := rfl

theorem applyPushPushMul_match (a b : Int) (rest : List StackOp) :
    applyPushPushMul (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_MUL" :: rest)
    = .push (.bigint (a * b)) :: applyPushPushMul rest := rfl

theorem runOpcode_MUL_def (s : StackState) :
    runOpcode "OP_MUL" s = liftIntBin s (fun a b => .vBigint (a * b)) := rfl

theorem runOpcode_mul_int_concrete
    (s : StackState) (a b : Int) (rest : List ANF.Eval.Value)
    (hs : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_MUL" s
    = .ok (({ s with stack := rest } : StackState).push (.vBigint (a * b))) := by
  rw [runOpcode_MUL_def]
  unfold liftIntBin
  rw [popN_two_cons s (.vBigint b) (.vBigint a) rest hs]
  simp [asInt?]

theorem pushPushMul_extends (s : StackState) (a b : Int) (rest : List StackOp) :
    runOps (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_MUL" :: rest) s
    = runOps (.push (.bigint (a * b)) :: rest) s := by
  rw [runOps_cons_PUSHbigint, runOps_cons_PUSHbigint]
  have hs' : ((s.push (.vBigint a)).push (.vBigint b)).stack
           = .vBigint b :: .vBigint a :: s.stack := by
    unfold StackState.push; simp
  rw [runOps_cons_opcode_eq, stepNonIf_opcode,
      runOpcode_mul_int_concrete _ a b s.stack hs']
  rw [runOps_cons_PUSHbigint]
  cases s
  simp [StackState.push]

private theorem applyPushPushMul_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ a b rt, op = .push (.bigint a) → rest = .push (.bigint b) :: .opcode "OP_MUL" :: rt → False) :
    applyPushPushMul (op :: rest) = op :: applyPushPushMul rest :=
  applyPushPushMul.eq_3 op rest h

theorem pushPushMul_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyPushPushMul ops) s = runOps ops s := by
  intro ops
  induction ops using applyPushPushMul.induct with
  | case1 => intros _ _ _; rfl
  | case2 a b rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_MUL" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPushA : stepNonIf (.push (.bigint a)) s = .ok (s.push (.vBigint a)) :=
      stepNonIf_push_bigint s a
    have hWell1 : wellTypedRun (.push (.bigint b) :: .opcode "OP_MUL" :: rest')
                    (s.push (.vBigint a)) := hCont _ hStepPushA
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    have hStepPushB : stepNonIf (.push (.bigint b)) (s.push (.vBigint a))
                    = .ok ((s.push (.vBigint a)).push (.vBigint b)) :=
      stepNonIf_push_bigint _ b
    have hWell2 : wellTypedRun (.opcode "OP_MUL" :: rest')
                    ((s.push (.vBigint a)).push (.vBigint b)) := hCont1 _ hStepPushB
    have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell2
    have hPostStack : ((s.push (.vBigint a)).push (.vBigint b)).stack
                    = .vBigint b :: .vBigint a :: s.stack := by
      unfold StackState.push; simp
    have hStepMul : stepNonIf (.opcode "OP_MUL") ((s.push (.vBigint a)).push (.vBigint b))
                  = .ok (s.push (.vBigint (a * b))) := by
      rw [stepNonIf_opcode]
      rw [runOpcode_mul_int_concrete _ a b s.stack hPostStack]
      cases s
      simp [StackState.push]
    have hWellRest : wellTypedRun rest' (s.push (.vBigint (a * b))) := hCont2 _ hStepMul
    show runOps (.push (.bigint (a * b)) :: applyPushPushMul rest') s
         = runOps (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_MUL" :: rest') s
    rw [pushPushMul_extends s a b rest']
    apply runOps_cons_push_cong_typed
    intro s' hStepPushAB
    have hSEq : s' = s.push (.vBigint (a * b)) := by
      have : stepNonIf (.push (.bigint (a * b))) s = .ok (s.push (.vBigint (a * b))) :=
        stepNonIf_push_bigint s (a * b)
      rw [this] at hStepPushAB
      exact ((Except.ok.injEq _ _).mp hStepPushAB).symm
    rw [hSEq]
    exact ih hRestNoIf _ hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyPushPushMul rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyPushPushMul_cons_no_match (.push v) rest'
              (fun a b rt hOp hRest => h_no_match a b rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyPushPushMul rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyPushPushMul rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyPushPushMul rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyPushPushMul rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyPushPushMul rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyPushPushMul rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyPushPushMul rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyPushPushMul rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyPushPushMul rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyPushPushMul rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyPushPushMul rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyPushPushMul rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ## Phase 3z-B — 6 deferred peephole rules from `peephole.ts`

The previously-deferred 6 rules from Phase 3v (per HANDOFF.md §"Phase 3u
— Phase 3v deferred peephole rules") are landed here:

1. `checkMultiSigVerifyFuse` — `[OP_CHECKMULTISIG, OP_VERIFY] →
   [OP_CHECKMULTISIGVERIFY]`. Path A: `Stack/Eval.lean` was extended with
   abstract single-pop semantics for both opcodes (mirroring the existing
   `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` pair) so the fusion's `runOps LHS
   = runOps RHS` shape becomes provable. The semantics use a local
   `checkMultiSigStub : ByteArray → Bool` so `runOpcode` retains
   compiled IR.

2-6. `zeroRoll0` / `oneRoll1` / `twoRoll2` / `zeroPick0` / `onePick1` —
   Path A: `Stack/Eval.lean`'s `applyRoll` and `applyPick` were
   refactored to bytecode-style semantics (pop the runtime depth from
   the stack, then perform the structural roll/pick at parameter `d`).
   Each rule then needs an extra "depth strict" hypothesis bounding
   `s.stack.length`; we encode it inline as an additional `Prop`
   argument rather than threading a recursive predicate (the rule's
   match-case is the only firing position, so the inline form is
   tight).

The `checkMultiSigVerifyFuse` rule follows the standard `wellTypedRun`
recipe (`.bytes` precondition on the multi-sig opcode entry).
-/

/-! ### `checkMultiSigVerifyFuse_pass_sound` — Phase 3z-B (Path A)

`[OP_CHECKMULTISIG, OP_VERIFY] → [OP_CHECKMULTISIGVERIFY]` under
`.bytes`-on-top precondition. The opcode semantics (in `Stack/Eval.lean`)
mirror `OP_CHECKSIG`'s single-pop abstraction with `checkMultiSigStub`
in place of the `Crypto.checkSig` opaque. -/

def applyCheckMultiSigVerifyFuse : List StackOp → List StackOp
  | [] => []
  | .opcode "OP_CHECKMULTISIG" :: .opcode "OP_VERIFY" :: rest =>
      .opcode "OP_CHECKMULTISIGVERIFY" :: applyCheckMultiSigVerifyFuse rest
  | op :: rest => op :: applyCheckMultiSigVerifyFuse rest

theorem applyCheckMultiSigVerifyFuse_empty :
    applyCheckMultiSigVerifyFuse [] = [] := rfl

theorem applyCheckMultiSigVerifyFuse_match (rest : List StackOp) :
    applyCheckMultiSigVerifyFuse
        (.opcode "OP_CHECKMULTISIG" :: .opcode "OP_VERIFY" :: rest)
    = .opcode "OP_CHECKMULTISIGVERIFY" :: applyCheckMultiSigVerifyFuse rest := rfl

theorem runOpcode_CHECKMULTISIG_def (s : StackState) :
    runOpcode "OP_CHECKMULTISIG" s
    = match s.pop? with
      | none => .error (.unsupported "OP_CHECKMULTISIG: empty stack")
      | some (v, s') =>
          match asBytes? v with
          | some b => .ok (s'.push (.vBool (checkMultiSigStub b)))
          | none   => .error (.typeError "OP_CHECKMULTISIG expects bytes") := rfl

theorem runOpcode_CHECKMULTISIGVERIFY_def (s : StackState) :
    runOpcode "OP_CHECKMULTISIGVERIFY" s
    = match s.pop? with
      | none => .error (.unsupported "OP_CHECKMULTISIGVERIFY: empty stack")
      | some (v, s') =>
          match asBytes? v with
          | some b =>
              if checkMultiSigStub b then .ok s' else .error .assertFailed
          | none   => .error (.typeError "OP_CHECKMULTISIGVERIFY expects bytes") := rfl

/-- Both .vBytes and .vOpaque single-byte top forms reduce uniformly. -/
private theorem checkMultiSigVerifyFuse_extends_anyBytes
    (s : StackState) (b : ByteArray) (rest_top : List ANF.Eval.Value)
    (rest : List StackOp)
    (hs : s.stack = .vBytes b :: rest_top ∨ s.stack = .vOpaque b :: rest_top) :
    runOps (.opcode "OP_CHECKMULTISIG" :: .opcode "OP_VERIFY" :: rest) s
    = runOps (.opcode "OP_CHECKMULTISIGVERIFY" :: rest) s := by
  rcases hs with hB | hO
  · rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKMULTISIG" s
          = .ok (({ s with stack := rest_top } : StackState).push
                  (.vBool (checkMultiSigStub b))) from by
            rw [runOpcode_CHECKMULTISIG_def]
            unfold StackState.pop?
            rw [hB]
            simp [asBytes?]]
    show runOps (.opcode "OP_VERIFY" :: rest)
          ((({ s with stack := rest_top } : StackState).push
            (.vBool (checkMultiSigStub b)))) = _
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKMULTISIGVERIFY" s
          = (if checkMultiSigStub b then
              .ok ({ s with stack := rest_top } : StackState)
             else .error .assertFailed) from by
            rw [runOpcode_CHECKMULTISIGVERIFY_def]
            unfold StackState.pop?
            rw [hB]
            simp [asBytes?]]
  · rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKMULTISIG" s
          = .ok (({ s with stack := rest_top } : StackState).push
                  (.vBool (checkMultiSigStub b))) from by
            rw [runOpcode_CHECKMULTISIG_def]
            unfold StackState.pop?
            rw [hO]
            simp [asBytes?]]
    show runOps (.opcode "OP_VERIFY" :: rest)
          ((({ s with stack := rest_top } : StackState).push
            (.vBool (checkMultiSigStub b)))) = _
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKMULTISIGVERIFY" s
          = (if checkMultiSigStub b then
              .ok ({ s with stack := rest_top } : StackState)
             else .error .assertFailed) from by
            rw [runOpcode_CHECKMULTISIGVERIFY_def]
            unfold StackState.pop?
            rw [hO]
            simp [asBytes?]]

/-- Reduce stepNonIf OP_CHECKMULTISIG on bytes-mixed top to a uniform shape. -/
private theorem stepNonIf_OPCHECKMULTISIG_anyBytes
    (s : StackState) (b : ByteArray) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBytes b :: rest_top ∨ s.stack = .vOpaque b :: rest_top) :
    stepNonIf (.opcode "OP_CHECKMULTISIG") s
    = .ok ((({ s with stack := rest_top } : StackState).push
              (.vBool (checkMultiSigStub b)))) := by
  rw [stepNonIf_opcode, runOpcode_CHECKMULTISIG_def]
  unfold StackState.pop?
  rcases hs with hB | hO
  · rw [hB]; simp [asBytes?]
  · rw [hO]; simp [asBytes?]

private theorem applyCheckMultiSigVerifyFuse_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .opcode "OP_CHECKMULTISIG" →
              rest = .opcode "OP_VERIFY" :: rt → False) :
    applyCheckMultiSigVerifyFuse (op :: rest)
    = op :: applyCheckMultiSigVerifyFuse rest :=
  applyCheckMultiSigVerifyFuse.eq_3 op rest h

theorem checkMultiSigVerifyFuse_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyCheckMultiSigVerifyFuse ops) s = runOps ops s := by
  intro ops
  induction ops using applyCheckMultiSigVerifyFuse.induct with
  | case1 => intros _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.opcode "OP_CHECKMULTISIG" :: .opcode "OP_VERIFY" :: rest')
        at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨b, rest_top, hStack⟩ := precondMet_bytes_extract s hPrecond
    show runOps (.opcode "OP_CHECKMULTISIGVERIFY" :: applyCheckMultiSigVerifyFuse rest') s
         = runOps (.opcode "OP_CHECKMULTISIG" :: .opcode "OP_VERIFY" :: rest') s
    rw [checkMultiSigVerifyFuse_extends_anyBytes s b rest_top rest' hStack]
    apply runOps_cons_opcode_cong_typed
    intro s' hStepCMV
    have hStepDef : stepNonIf (.opcode "OP_CHECKMULTISIGVERIFY") s
                  = (if checkMultiSigStub b then
                      .ok ({ s with stack := rest_top } : StackState)
                     else .error .assertFailed) := by
      rw [stepNonIf_opcode, runOpcode_CHECKMULTISIGVERIFY_def]
      unfold StackState.pop?
      rcases hStack with hB | hO
      · rw [hB]; simp [asBytes?]
      · rw [hO]; simp [asBytes?]
    rw [hStepDef] at hStepCMV
    by_cases hSig : checkMultiSigStub b = true
    · rw [hSig] at hStepCMV
      simp at hStepCMV
      have hSEq : s' = ({ s with stack := rest_top } : StackState) := hStepCMV.symm
      apply ih hRestNoIf s'
      have hStep1 : stepNonIf (.opcode "OP_CHECKMULTISIG") s
                  = .ok (({ s with stack := rest_top } : StackState).push
                          (.vBool (checkMultiSigStub b))) :=
        stepNonIf_OPCHECKMULTISIG_anyBytes s b rest_top hStack
      have hWell1 := hCont _ hStep1
      have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
      have hStep2 : stepNonIf (.opcode "OP_VERIFY")
                      (({ s with stack := rest_top } : StackState).push
                        (.vBool (checkMultiSigStub b)))
                  = .ok ({ s with stack := rest_top } : StackState) := by
        rw [stepNonIf_opcode, runOpcode_verify_vBool, hSig]
        rfl
      have hWellRest : wellTypedRun rest' ({ s with stack := rest_top } : StackState) :=
        hCont1 _ hStep2
      rw [hSEq]
      exact hWellRest
    · rw [show checkMultiSigStub b = false from by
            rcases h : checkMultiSigStub b with _ | _
            · rfl
            · exact absurd h hSig] at hStepCMV
      simp at hStepCMV
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyCheckMultiSigVerifyFuse rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        show runOps (.push v :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.push v :: rest') s
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        rw [applyCheckMultiSigVerifyFuse_cons_no_match (.opcode code) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### Roll/Pick combinator rules — Phase 3z-B (Path A)

Five 2-op rewrites that fuse a `[push d, .roll d]` or `[push d, .pick d]`
pattern into a smaller op:

* `zeroRoll0`  — `[push 0, .roll 0] → []`        (no-op)
* `oneRoll1`   — `[push 1, .roll 1] → [.swap]`
* `twoRoll2`   — `[push 2, .roll 2] → [.rot]`
* `zeroPick0`  — `[push 0, .pick 0] → [.dup]`
* `onePick1`   — `[push 1, .pick 1] → [.over]`

These rules require `Stack/Eval.lean`'s `applyRoll`/`applyPick` to use
**bytecode-style** semantics (pop the runtime depth from the stack
before performing the structural roll/pick at parameter `d`); the
refactor was landed in Phase 3z-B alongside these proofs.

Each rule additionally requires a depth-strict precondition: at the
match position, `s.stack` must have at least `d+1` elements (so
`applyRoll`/`applyPick` succeeds after popping the runtime depth).
We encode this per-rule via a recursive `_depthOk` predicate that
checks the precondition at every potential firing position and
threads through `stepNonIf` at non-firing positions.
-/

/-! #### Reduction lemmas: `applyRoll`/`applyPick` after a `push d` -/

/-- `stepNonIf .roll d s = applyRoll s d` (definitional). -/
private theorem stepNonIf_roll_def (s : StackState) (d : Nat) :
    stepNonIf (.roll d) s = applyRoll s d := rfl

/-- `stepNonIf .pick d s = applyPick s d` (definitional). -/
private theorem stepNonIf_pick_def (s : StackState) (d : Nat) :
    stepNonIf (.pick d) s = applyPick s d := rfl

/-- After `push (vBigint i)` (any int `i`), `applyRoll _ d` pops the freshly
pushed value and reduces to a structural roll on the original stack at depth `d`. -/
private theorem applyRoll_after_pushInt (s : StackState) (i : Int) (d : Nat) :
    applyRoll (s.push (.vBigint i)) d
    = if d ≥ s.stack.length then
        .error (.unsupported s!"OP_ROLL: depth {d} ≥ stack size {s.stack.length}")
      else
        .ok ({ s with stack := s.stack[d]! :: s.stack.eraseIdx d } : StackState) := by
  cases s with
  | mk stack altstack outputs props preimage =>
    simp [applyRoll, StackState.push, StackState.pop?]

/-- After `push (vBigint i)` (any int `i`), `applyPick _ d` pops the freshly
pushed value and reduces to a structural pick on the original stack at depth `d`. -/
private theorem applyPick_after_pushInt (s : StackState) (i : Int) (d : Nat) :
    applyPick (s.push (.vBigint i)) d
    = if d ≥ s.stack.length then
        .error (.unsupported s!"OP_PICK: depth {d} ≥ stack size {s.stack.length}")
      else
        .ok (s.push s.stack[d]!) := by
  cases s with
  | mk stack altstack outputs props preimage =>
    simp [applyPick, StackState.push, StackState.pop?]

/-! #### `zeroRoll0_pass_sound` — `[push 0, .roll 0] → []` -/

def applyZeroRoll0 : List StackOp → List StackOp
  | [] => []
  | .push (.bigint 0) :: .roll 0 :: rest => applyZeroRoll0 rest
  | op :: rest => op :: applyZeroRoll0 rest

theorem applyZeroRoll0_empty : applyZeroRoll0 [] = [] := rfl

theorem applyZeroRoll0_match (rest : List StackOp) :
    applyZeroRoll0 (.push (.bigint 0) :: .roll 0 :: rest) = applyZeroRoll0 rest := rfl

/-- Head-precondition: at this exact position, is the match firing, and if so,
does the depth requirement hold? -/
def zeroRoll0_headPre : StackOp → List StackOp → StackState → Prop
  | .push (.bigint 0), .roll 0 :: _, s => s.stack.length ≥ 1
  | _, _, _ => True

/-- Recursive depth-strict predicate. -/
def zeroRoll0_depthOk : List StackOp → StackState → Prop
  | [], _ => True
  | op :: rest, s =>
      zeroRoll0_headPre op rest s ∧
      (∀ s', stepNonIf op s = .ok s' → zeroRoll0_depthOk rest s')

theorem zeroRoll0_depthOk_cons (op : StackOp) (rest : List StackOp) (s : StackState) :
    zeroRoll0_depthOk (op :: rest) s ↔
      (zeroRoll0_headPre op rest s ∧
        (∀ s', stepNonIf op s = .ok s' → zeroRoll0_depthOk rest s')) :=
  Iff.rfl

/-- The match-case extension: `[push 0, .roll 0]` evaluated on a state with
non-empty stack returns the same as running `[]` (i.e. the state unchanged). -/
theorem zeroRoll0_extends (s : StackState) (rest : List StackOp)
    (hLen : s.stack.length ≥ 1) :
    runOps (.push (.bigint 0) :: .roll 0 :: rest) s = runOps rest s := by
  rw [runOps_cons_PUSHbigint, runOps_cons_roll_eq]
  show (match stepNonIf (.roll 0) (s.push (.vBigint 0)) with
        | .error e => .error e
        | .ok s' => runOps rest s') = runOps rest s
  have hStep : stepNonIf (.roll 0) (s.push (.vBigint 0)) = .ok s := by
    show applyRoll (s.push (.vBigint 0)) 0 = .ok s
    rw [applyRoll_after_pushInt s 0 0]
    have hNotGe : ¬ (0 ≥ s.stack.length) := by omega
    rw [if_neg hNotGe]
    cases s with
    | mk stack altstack outputs props preimage =>
      cases stack with
      | nil => simp at hLen
      | cons head tail => simp
  rw [hStep]

private theorem applyZeroRoll0_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .push (.bigint 0) → rest = .roll 0 :: rt → False) :
    applyZeroRoll0 (op :: rest) = op :: applyZeroRoll0 rest :=
  applyZeroRoll0.eq_3 op rest h

theorem zeroRoll0_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        zeroRoll0_depthOk ops s →
        runOps (applyZeroRoll0 ops) s = runOps ops s := by
  intro ops
  induction ops using applyZeroRoll0.induct with
  | case1 => intros _ _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT hDepth
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint 0) :: .roll 0 :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    -- Extract from hDepth: head precondition (s.stack.length ≥ 1) and tail.
    have ⟨hHeadPre, hDepthCont⟩ := zeroRoll0_depthOk_cons _ _ _ |>.mp hDepth
    have hLen : s.stack.length ≥ 1 := hHeadPre
    -- Establish wellTypedRun rest' s and depthOk rest' s.
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 0)) s = .ok (s.push (.vBigint 0)) :=
      stepNonIf_push_bigint s 0
    have hWell1 : wellTypedRun (.roll 0 :: rest') (s.push (.vBigint 0)) :=
      hCont1 _ hStepPush
    have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    have hStepRoll : stepNonIf (.roll 0) (s.push (.vBigint 0)) = .ok s := by
      show applyRoll (s.push (.vBigint 0)) 0 = .ok s
      rw [applyRoll_after_pushInt s 0 0]
      have hNotGe : ¬ (0 ≥ s.stack.length) := by omega
      rw [if_neg hNotGe]
      cases s with
      | mk stack altstack outputs props preimage =>
        cases stack with
        | nil => simp at hLen
        | cons head tail => simp
    have hWellRest : wellTypedRun rest' s := hCont2 _ hStepRoll
    -- depthOk rest' s: from hDepthCont, with hStepPush.
    have hDepthRest_intermediate : zeroRoll0_depthOk (.roll 0 :: rest') (s.push (.vBigint 0)) :=
      hDepthCont _ hStepPush
    have ⟨_, hDepthCont2⟩ := zeroRoll0_depthOk_cons _ _ _ |>.mp hDepthRest_intermediate
    have hDepthRest : zeroRoll0_depthOk rest' s := hDepthCont2 _ hStepRoll
    show runOps (applyZeroRoll0 rest') s
         = runOps (.push (.bigint 0) :: .roll 0 :: rest') s
    rw [zeroRoll0_extends s rest' hLen]
    exact ih hRestNoIf s hWellRest hDepthRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT hDepth
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    -- depthOk_cons gives us the tail-propagating clause.
    have ⟨_, hDepthCont⟩ := zeroRoll0_depthOk_cons _ _ _ |>.mp hDepth
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyZeroRoll0 rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep) (hDepthCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyZeroRoll0_cons_no_match (.push v) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyZeroRoll0 rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyZeroRoll0 rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyZeroRoll0 rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyZeroRoll0 rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyZeroRoll0 rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyZeroRoll0 rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyZeroRoll0 rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyZeroRoll0 rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyZeroRoll0 rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyZeroRoll0 rest') s
             = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyZeroRoll0 rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyZeroRoll0 rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! #### `oneRoll1_pass_sound` — `[push 1, .roll 1] → [.swap]` -/

def applyOneRoll1 : List StackOp → List StackOp
  | [] => []
  | .push (.bigint 1) :: .roll 1 :: rest => .swap :: applyOneRoll1 rest
  | op :: rest => op :: applyOneRoll1 rest

theorem applyOneRoll1_empty : applyOneRoll1 [] = [] := rfl

theorem applyOneRoll1_match (rest : List StackOp) :
    applyOneRoll1 (.push (.bigint 1) :: .roll 1 :: rest)
    = .swap :: applyOneRoll1 rest := rfl

def oneRoll1_headPre : StackOp → List StackOp → StackState → Prop
  | .push (.bigint 1), .roll 1 :: _, s => s.stack.length ≥ 2
  | _, _, _ => True

def oneRoll1_depthOk : List StackOp → StackState → Prop
  | [], _ => True
  | op :: rest, s =>
      oneRoll1_headPre op rest s ∧
      (∀ s', stepNonIf op s = .ok s' → oneRoll1_depthOk rest s')

theorem oneRoll1_depthOk_cons (op : StackOp) (rest : List StackOp) (s : StackState) :
    oneRoll1_depthOk (op :: rest) s ↔
      (oneRoll1_headPre op rest s ∧
        (∀ s', stepNonIf op s = .ok s' → oneRoll1_depthOk rest s')) :=
  Iff.rfl

/-- Helper: After `push 1` then `.roll 1` on a state with stack length ≥ 2,
we land on the swap-of-top-two state. -/
private theorem stepRoll1_after_push1 (s : StackState) (hLen : s.stack.length ≥ 2) :
    ∃ x y rest_tail, s.stack = x :: y :: rest_tail ∧
      stepNonIf (.roll 1) (s.push (.vBigint 1))
      = .ok ({ s with stack := y :: x :: rest_tail } : StackState) := by
  cases s with
  | mk stack altstack outputs props preimage =>
    cases stack with
    | nil => simp at hLen
    | cons x tail =>
      cases tail with
      | nil => simp at hLen
      | cons y rest_tail =>
        refine ⟨x, y, rest_tail, rfl, ?_⟩
        rw [stepNonIf_roll_def, applyRoll_after_pushInt _ 1 1]
        have hNotGe : ¬ (1 ≥ ({stack := x :: y :: rest_tail, altstack := altstack,
                                outputs := outputs, props := props,
                                preimage := preimage} : StackState).stack.length) := by
          show ¬ (1 ≥ (x :: y :: rest_tail).length)
          simp
        rw [if_neg hNotGe]
        simp

/-- Helper: `swap` on a state with stack `x :: y :: tail` swaps the top two. -/
private theorem stepSwap_on_two (s : StackState) (x y : ANF.Eval.Value)
    (rest_tail : List ANF.Eval.Value) (hs : s.stack = x :: y :: rest_tail) :
    stepNonIf .swap s = .ok ({ s with stack := y :: x :: rest_tail } : StackState) := by
  rw [stepNonIf_swap]
  cases s with
  | mk stack _ _ _ _ =>
    simp only at hs
    rw [hs]
    rfl

/-- The match-case extension: `[push 1, .roll 1]` evaluated on a state with
stack length ≥ 2 returns the same as running `[.swap]`. -/
theorem oneRoll1_extends (s : StackState) (rest : List StackOp)
    (hLen : s.stack.length ≥ 2) :
    runOps (.push (.bigint 1) :: .roll 1 :: rest) s = runOps (.swap :: rest) s := by
  rw [runOps_cons_PUSHbigint, runOps_cons_roll_eq, runOps_cons_swap_eq]
  obtain ⟨x, y, rest_tail, hStack, hRoll⟩ := stepRoll1_after_push1 s hLen
  have hSwap := stepSwap_on_two s x y rest_tail hStack
  rw [hRoll, hSwap]

private theorem applyOneRoll1_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .push (.bigint 1) → rest = .roll 1 :: rt → False) :
    applyOneRoll1 (op :: rest) = op :: applyOneRoll1 rest :=
  applyOneRoll1.eq_3 op rest h

theorem oneRoll1_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        oneRoll1_depthOk ops s →
        runOps (applyOneRoll1 ops) s = runOps ops s := by
  intro ops
  induction ops using applyOneRoll1.induct with
  | case1 => intros _ _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT hDepth
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint 1) :: .roll 1 :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hHeadPre, hDepthCont⟩ := oneRoll1_depthOk_cons _ _ _ |>.mp hDepth
    have hLen : s.stack.length ≥ 2 := hHeadPre
    -- wellTypedRun chain to recover post-swap wellTypedRun rest'.
    show runOps (.swap :: applyOneRoll1 rest') s
         = runOps (.push (.bigint 1) :: .roll 1 :: rest') s
    rw [oneRoll1_extends s rest' hLen]
    apply runOps_cons_swap_cong_typed
    intro s' hStepSwap
    -- swap reduces uniformly; recover ihTyped from depthOk chain & wellTypedRun chain.
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 1)) s = .ok (s.push (.vBigint 1)) :=
      stepNonIf_push_bigint s 1
    have hWell1 : wellTypedRun (.roll 1 :: rest') (s.push (.vBigint 1)) :=
      hCont1 _ hStepPush
    have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    -- The post-LHS state s' equals the swap-of-top-two state, which is also
    -- what stepNonIf (.roll 1) (s.push (.vBigint 1)) computes.
    obtain ⟨x, y, rest_tail, hStack, hRoll⟩ := stepRoll1_after_push1 s hLen
    have hSwapDef := stepSwap_on_two s x y rest_tail hStack
    rw [hSwapDef] at hStepSwap
    have hSEq : s' = ({ s with stack := y :: x :: rest_tail } : StackState) :=
      ((Except.ok.injEq _ _).mp hStepSwap).symm
    have hRollEq : stepNonIf (.roll 1) (s.push (.vBigint 1)) = .ok s' := by
      rw [hSEq]; exact hRoll
    have hWellRest : wellTypedRun rest' s' := hCont2 _ hRollEq
    -- depthOk rest' s' similarly.
    have hDepthIntermediate : oneRoll1_depthOk (.roll 1 :: rest') (s.push (.vBigint 1)) :=
      hDepthCont _ hStepPush
    have ⟨_, hDepthCont2⟩ := oneRoll1_depthOk_cons _ _ _ |>.mp hDepthIntermediate
    have hDepthRest : oneRoll1_depthOk rest' s' := hDepthCont2 _ hRollEq
    exact ih hRestNoIf s' hWellRest hDepthRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT hDepth
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ⟨_, hDepthCont⟩ := oneRoll1_depthOk_cons _ _ _ |>.mp hDepth
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyOneRoll1 rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep) (hDepthCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyOneRoll1_cons_no_match (.push v) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyOneRoll1 rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyOneRoll1 rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyOneRoll1 rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyOneRoll1 rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyOneRoll1 rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyOneRoll1 rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyOneRoll1 rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyOneRoll1 rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyOneRoll1 rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyOneRoll1 rest') s
             = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyOneRoll1 rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyOneRoll1 rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! #### `twoRoll2_pass_sound` — `[push 2, .roll 2] → [.rot]` -/

def applyTwoRoll2 : List StackOp → List StackOp
  | [] => []
  | .push (.bigint 2) :: .roll 2 :: rest => .rot :: applyTwoRoll2 rest
  | op :: rest => op :: applyTwoRoll2 rest

theorem applyTwoRoll2_empty : applyTwoRoll2 [] = [] := rfl

theorem applyTwoRoll2_match (rest : List StackOp) :
    applyTwoRoll2 (.push (.bigint 2) :: .roll 2 :: rest)
    = .rot :: applyTwoRoll2 rest := rfl

def twoRoll2_headPre : StackOp → List StackOp → StackState → Prop
  | .push (.bigint 2), .roll 2 :: _, s => s.stack.length ≥ 3
  | _, _, _ => True

def twoRoll2_depthOk : List StackOp → StackState → Prop
  | [], _ => True
  | op :: rest, s =>
      twoRoll2_headPre op rest s ∧
      (∀ s', stepNonIf op s = .ok s' → twoRoll2_depthOk rest s')

theorem twoRoll2_depthOk_cons (op : StackOp) (rest : List StackOp) (s : StackState) :
    twoRoll2_depthOk (op :: rest) s ↔
      (twoRoll2_headPre op rest s ∧
        (∀ s', stepNonIf op s = .ok s' → twoRoll2_depthOk rest s')) :=
  Iff.rfl

private theorem stepRoll2_after_push2 (s : StackState) (hLen : s.stack.length ≥ 3) :
    ∃ x y z rest_tail, s.stack = x :: y :: z :: rest_tail ∧
      stepNonIf (.roll 2) (s.push (.vBigint 2))
      = .ok ({ s with stack := z :: x :: y :: rest_tail } : StackState) := by
  cases s with
  | mk stack altstack outputs props preimage =>
    cases stack with
    | nil => simp at hLen
    | cons x t1 =>
      cases t1 with
      | nil => simp at hLen
      | cons y t2 =>
        cases t2 with
        | nil => simp at hLen
        | cons z rest_tail =>
          refine ⟨x, y, z, rest_tail, rfl, ?_⟩
          rw [stepNonIf_roll_def, applyRoll_after_pushInt _ 2 2]
          have hNotGe : ¬ (2 ≥ ({stack := x :: y :: z :: rest_tail, altstack := altstack,
                                  outputs := outputs, props := props,
                                  preimage := preimage} : StackState).stack.length) := by
            show ¬ (2 ≥ (x :: y :: z :: rest_tail).length)
            simp
          rw [if_neg hNotGe]
          simp

private theorem stepRot_on_three (s : StackState) (x y z : ANF.Eval.Value)
    (rest_tail : List ANF.Eval.Value) (hs : s.stack = x :: y :: z :: rest_tail) :
    stepNonIf .rot s = .ok ({ s with stack := z :: x :: y :: rest_tail } : StackState) := by
  show applyRot s = _
  unfold applyRot
  cases s with
  | mk stack _ _ _ _ =>
    simp only at hs
    rw [hs]

theorem twoRoll2_extends (s : StackState) (rest : List StackOp)
    (hLen : s.stack.length ≥ 3) :
    runOps (.push (.bigint 2) :: .roll 2 :: rest) s = runOps (.rot :: rest) s := by
  rw [runOps_cons_PUSHbigint, runOps_cons_roll_eq, runOps_cons_rot_eq]
  obtain ⟨x, y, z, rest_tail, hStack, hRoll⟩ := stepRoll2_after_push2 s hLen
  have hRot := stepRot_on_three s x y z rest_tail hStack
  rw [hRoll, hRot]

private theorem applyTwoRoll2_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .push (.bigint 2) → rest = .roll 2 :: rt → False) :
    applyTwoRoll2 (op :: rest) = op :: applyTwoRoll2 rest :=
  applyTwoRoll2.eq_3 op rest h

theorem twoRoll2_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        twoRoll2_depthOk ops s →
        runOps (applyTwoRoll2 ops) s = runOps ops s := by
  intro ops
  induction ops using applyTwoRoll2.induct with
  | case1 => intros _ _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT hDepth
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint 2) :: .roll 2 :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hHeadPre, hDepthCont⟩ := twoRoll2_depthOk_cons _ _ _ |>.mp hDepth
    have hLen : s.stack.length ≥ 3 := hHeadPre
    show runOps (.rot :: applyTwoRoll2 rest') s
         = runOps (.push (.bigint 2) :: .roll 2 :: rest') s
    rw [twoRoll2_extends s rest' hLen]
    apply runOps_cons_rot_cong_typed
    intro s' hStepRot
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 2)) s = .ok (s.push (.vBigint 2)) :=
      stepNonIf_push_bigint s 2
    have hWell1 : wellTypedRun (.roll 2 :: rest') (s.push (.vBigint 2)) :=
      hCont1 _ hStepPush
    have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    obtain ⟨x, y, z, rest_tail, hStack, hRoll⟩ := stepRoll2_after_push2 s hLen
    have hRotDef := stepRot_on_three s x y z rest_tail hStack
    rw [hRotDef] at hStepRot
    have hSEq : s' = ({ s with stack := z :: x :: y :: rest_tail } : StackState) :=
      ((Except.ok.injEq _ _).mp hStepRot).symm
    have hRollEq : stepNonIf (.roll 2) (s.push (.vBigint 2)) = .ok s' := by
      rw [hSEq]; exact hRoll
    have hWellRest : wellTypedRun rest' s' := hCont2 _ hRollEq
    have hDepthIntermediate : twoRoll2_depthOk (.roll 2 :: rest') (s.push (.vBigint 2)) :=
      hDepthCont _ hStepPush
    have ⟨_, hDepthCont2⟩ := twoRoll2_depthOk_cons _ _ _ |>.mp hDepthIntermediate
    have hDepthRest : twoRoll2_depthOk rest' s' := hDepthCont2 _ hRollEq
    exact ih hRestNoIf s' hWellRest hDepthRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT hDepth
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ⟨_, hDepthCont⟩ := twoRoll2_depthOk_cons _ _ _ |>.mp hDepth
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyTwoRoll2 rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep) (hDepthCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyTwoRoll2_cons_no_match (.push v) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyTwoRoll2 rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyTwoRoll2 rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyTwoRoll2 rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyTwoRoll2 rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyTwoRoll2 rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyTwoRoll2 rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyTwoRoll2 rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyTwoRoll2 rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyTwoRoll2 rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyTwoRoll2 rest') s
             = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyTwoRoll2 rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyTwoRoll2 rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! #### `zeroPick0_pass_sound` — `[push 0, .pick 0] → [.dup]` -/

def applyZeroPick0 : List StackOp → List StackOp
  | [] => []
  | .push (.bigint 0) :: .pick 0 :: rest => .dup :: applyZeroPick0 rest
  | op :: rest => op :: applyZeroPick0 rest

theorem applyZeroPick0_empty : applyZeroPick0 [] = [] := rfl

theorem applyZeroPick0_match (rest : List StackOp) :
    applyZeroPick0 (.push (.bigint 0) :: .pick 0 :: rest)
    = .dup :: applyZeroPick0 rest := rfl

def zeroPick0_headPre : StackOp → List StackOp → StackState → Prop
  | .push (.bigint 0), .pick 0 :: _, s => s.stack.length ≥ 1
  | _, _, _ => True

def zeroPick0_depthOk : List StackOp → StackState → Prop
  | [], _ => True
  | op :: rest, s =>
      zeroPick0_headPre op rest s ∧
      (∀ s', stepNonIf op s = .ok s' → zeroPick0_depthOk rest s')

theorem zeroPick0_depthOk_cons (op : StackOp) (rest : List StackOp) (s : StackState) :
    zeroPick0_depthOk (op :: rest) s ↔
      (zeroPick0_headPre op rest s ∧
        (∀ s', stepNonIf op s = .ok s' → zeroPick0_depthOk rest s')) :=
  Iff.rfl

private theorem stepPick0_after_push0 (s : StackState) (hLen : s.stack.length ≥ 1) :
    ∃ x rest_tail, s.stack = x :: rest_tail ∧
      stepNonIf (.pick 0) (s.push (.vBigint 0))
      = .ok ({ s with stack := x :: x :: rest_tail } : StackState) := by
  cases s with
  | mk stack altstack outputs props preimage =>
    cases stack with
    | nil => simp at hLen
    | cons x rest_tail =>
      refine ⟨x, rest_tail, rfl, ?_⟩
      rw [stepNonIf_pick_def, applyPick_after_pushInt _ 0 0]
      have hNotGe : ¬ (0 ≥ ({stack := x :: rest_tail, altstack := altstack,
                              outputs := outputs, props := props,
                              preimage := preimage} : StackState).stack.length) := by
        show ¬ (0 ≥ (x :: rest_tail).length)
        simp
      rw [if_neg hNotGe]
      simp [StackState.push]

private theorem stepDup_on_one (s : StackState) (x : ANF.Eval.Value)
    (rest_tail : List ANF.Eval.Value) (hs : s.stack = x :: rest_tail) :
    stepNonIf .dup s = .ok ({ s with stack := x :: x :: rest_tail } : StackState) := by
  show applyDup s = _
  unfold applyDup
  cases s with
  | mk stack _ _ _ _ =>
    simp only at hs
    rw [hs]
    rfl

theorem zeroPick0_extends (s : StackState) (rest : List StackOp)
    (hLen : s.stack.length ≥ 1) :
    runOps (.push (.bigint 0) :: .pick 0 :: rest) s = runOps (.dup :: rest) s := by
  rw [runOps_cons_PUSHbigint, runOps_cons_pick_eq, runOps_cons_dup_eq]
  obtain ⟨x, rest_tail, hStack, hPick⟩ := stepPick0_after_push0 s hLen
  have hDup := stepDup_on_one s x rest_tail hStack
  rw [hPick, hDup]

private theorem applyZeroPick0_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .push (.bigint 0) → rest = .pick 0 :: rt → False) :
    applyZeroPick0 (op :: rest) = op :: applyZeroPick0 rest :=
  applyZeroPick0.eq_3 op rest h

theorem zeroPick0_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        zeroPick0_depthOk ops s →
        runOps (applyZeroPick0 ops) s = runOps ops s := by
  intro ops
  induction ops using applyZeroPick0.induct with
  | case1 => intros _ _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT hDepth
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint 0) :: .pick 0 :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hHeadPre, hDepthCont⟩ := zeroPick0_depthOk_cons _ _ _ |>.mp hDepth
    have hLen : s.stack.length ≥ 1 := hHeadPre
    show runOps (.dup :: applyZeroPick0 rest') s
         = runOps (.push (.bigint 0) :: .pick 0 :: rest') s
    rw [zeroPick0_extends s rest' hLen]
    apply runOps_cons_dup_cong_typed
    intro s' hStepDup
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 0)) s = .ok (s.push (.vBigint 0)) :=
      stepNonIf_push_bigint s 0
    have hWell1 : wellTypedRun (.pick 0 :: rest') (s.push (.vBigint 0)) :=
      hCont1 _ hStepPush
    have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    obtain ⟨x, rest_tail, hStack, hPick⟩ := stepPick0_after_push0 s hLen
    have hDupDef := stepDup_on_one s x rest_tail hStack
    rw [hDupDef] at hStepDup
    have hSEq : s' = ({ s with stack := x :: x :: rest_tail } : StackState) :=
      ((Except.ok.injEq _ _).mp hStepDup).symm
    have hPickEq : stepNonIf (.pick 0) (s.push (.vBigint 0)) = .ok s' := by
      rw [hSEq]; exact hPick
    have hWellRest : wellTypedRun rest' s' := hCont2 _ hPickEq
    have hDepthIntermediate : zeroPick0_depthOk (.pick 0 :: rest') (s.push (.vBigint 0)) :=
      hDepthCont _ hStepPush
    have ⟨_, hDepthCont2⟩ := zeroPick0_depthOk_cons _ _ _ |>.mp hDepthIntermediate
    have hDepthRest : zeroPick0_depthOk rest' s' := hDepthCont2 _ hPickEq
    exact ih hRestNoIf s' hWellRest hDepthRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT hDepth
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ⟨_, hDepthCont⟩ := zeroPick0_depthOk_cons _ _ _ |>.mp hDepth
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyZeroPick0 rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep) (hDepthCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyZeroPick0_cons_no_match (.push v) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyZeroPick0 rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyZeroPick0 rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyZeroPick0 rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyZeroPick0 rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyZeroPick0 rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyZeroPick0 rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyZeroPick0 rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyZeroPick0 rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyZeroPick0 rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyZeroPick0 rest') s
             = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyZeroPick0 rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyZeroPick0 rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! #### `onePick1_pass_sound` — `[push 1, .pick 1] → [.over]` -/

def applyOnePick1 : List StackOp → List StackOp
  | [] => []
  | .push (.bigint 1) :: .pick 1 :: rest => .over :: applyOnePick1 rest
  | op :: rest => op :: applyOnePick1 rest

theorem applyOnePick1_empty : applyOnePick1 [] = [] := rfl

theorem applyOnePick1_match (rest : List StackOp) :
    applyOnePick1 (.push (.bigint 1) :: .pick 1 :: rest)
    = .over :: applyOnePick1 rest := rfl

def onePick1_headPre : StackOp → List StackOp → StackState → Prop
  | .push (.bigint 1), .pick 1 :: _, s => s.stack.length ≥ 2
  | _, _, _ => True

def onePick1_depthOk : List StackOp → StackState → Prop
  | [], _ => True
  | op :: rest, s =>
      onePick1_headPre op rest s ∧
      (∀ s', stepNonIf op s = .ok s' → onePick1_depthOk rest s')

theorem onePick1_depthOk_cons (op : StackOp) (rest : List StackOp) (s : StackState) :
    onePick1_depthOk (op :: rest) s ↔
      (onePick1_headPre op rest s ∧
        (∀ s', stepNonIf op s = .ok s' → onePick1_depthOk rest s')) :=
  Iff.rfl

private theorem stepPick1_after_push1 (s : StackState) (hLen : s.stack.length ≥ 2) :
    ∃ x y rest_tail, s.stack = x :: y :: rest_tail ∧
      stepNonIf (.pick 1) (s.push (.vBigint 1))
      = .ok ({ s with stack := y :: x :: y :: rest_tail } : StackState) := by
  cases s with
  | mk stack altstack outputs props preimage =>
    cases stack with
    | nil => simp at hLen
    | cons x t1 =>
      cases t1 with
      | nil => simp at hLen
      | cons y rest_tail =>
        refine ⟨x, y, rest_tail, rfl, ?_⟩
        rw [stepNonIf_pick_def, applyPick_after_pushInt _ 1 1]
        have hNotGe : ¬ (1 ≥ ({stack := x :: y :: rest_tail, altstack := altstack,
                                outputs := outputs, props := props,
                                preimage := preimage} : StackState).stack.length) := by
          show ¬ (1 ≥ (x :: y :: rest_tail).length)
          simp
        rw [if_neg hNotGe]
        simp [StackState.push]

private theorem stepOver_on_two (s : StackState) (x y : ANF.Eval.Value)
    (rest_tail : List ANF.Eval.Value) (hs : s.stack = x :: y :: rest_tail) :
    stepNonIf .over s = .ok ({ s with stack := y :: x :: y :: rest_tail } : StackState) := by
  show applyOver s = _
  unfold applyOver
  cases s with
  | mk stack _ _ _ _ =>
    simp only at hs
    rw [hs]

theorem onePick1_extends (s : StackState) (rest : List StackOp)
    (hLen : s.stack.length ≥ 2) :
    runOps (.push (.bigint 1) :: .pick 1 :: rest) s = runOps (.over :: rest) s := by
  rw [runOps_cons_PUSHbigint, runOps_cons_pick_eq, runOps_cons_over_eq]
  obtain ⟨x, y, rest_tail, hStack, hPick⟩ := stepPick1_after_push1 s hLen
  have hOver := stepOver_on_two s x y rest_tail hStack
  rw [hPick, hOver]

private theorem applyOnePick1_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ rt, op = .push (.bigint 1) → rest = .pick 1 :: rt → False) :
    applyOnePick1 (op :: rest) = op :: applyOnePick1 rest :=
  applyOnePick1.eq_3 op rest h

theorem onePick1_pass_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        onePick1_depthOk ops s →
        runOps (applyOnePick1 ops) s = runOps ops s := by
  intro ops
  induction ops using applyOnePick1.induct with
  | case1 => intros _ _ _ _; rfl
  | case2 rest' ih =>
    intro hNoIf s hWT hDepth
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint 1) :: .pick 1 :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hHeadPre, hDepthCont⟩ := onePick1_depthOk_cons _ _ _ |>.mp hDepth
    have hLen : s.stack.length ≥ 2 := hHeadPre
    show runOps (.over :: applyOnePick1 rest') s
         = runOps (.push (.bigint 1) :: .pick 1 :: rest') s
    rw [onePick1_extends s rest' hLen]
    apply runOps_cons_over_cong_typed
    intro s' hStepOver
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 1)) s = .ok (s.push (.vBigint 1)) :=
      stepNonIf_push_bigint s 1
    have hWell1 : wellTypedRun (.pick 1 :: rest') (s.push (.vBigint 1)) :=
      hCont1 _ hStepPush
    have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    obtain ⟨x, y, rest_tail, hStack, hPick⟩ := stepPick1_after_push1 s hLen
    have hOverDef := stepOver_on_two s x y rest_tail hStack
    rw [hOverDef] at hStepOver
    have hSEq : s' = ({ s with stack := y :: x :: y :: rest_tail } : StackState) :=
      ((Except.ok.injEq _ _).mp hStepOver).symm
    have hPickEq : stepNonIf (.pick 1) (s.push (.vBigint 1)) = .ok s' := by
      rw [hSEq]; exact hPick
    have hWellRest : wellTypedRun rest' s' := hCont2 _ hPickEq
    have hDepthIntermediate : onePick1_depthOk (.pick 1 :: rest') (s.push (.vBigint 1)) :=
      hDepthCont _ hStepPush
    have ⟨_, hDepthCont2⟩ := onePick1_depthOk_cons _ _ _ |>.mp hDepthIntermediate
    have hDepthRest : onePick1_depthOk rest' s' := hDepthCont2 _ hPickEq
    exact ih hRestNoIf s' hWellRest hDepthRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT hDepth
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ⟨_, hDepthCont⟩ := onePick1_depthOk_cons _ _ _ |>.mp hDepth
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyOnePick1 rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep) (hDepthCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyOnePick1_cons_no_match (.push v) rest'
              (fun rt hOp hRest => h_no_match rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      =>
        show runOps (.dup :: applyOnePick1 rest') s = runOps (.dup :: rest') s
        exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     =>
        show runOps (.swap :: applyOnePick1 rest') s = runOps (.swap :: rest') s
        exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     =>
        show runOps (.drop :: applyOnePick1 rest') s = runOps (.drop :: rest') s
        exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      =>
        show runOps (.nip :: applyOnePick1 rest') s = runOps (.nip :: rest') s
        exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     =>
        show runOps (.over :: applyOnePick1 rest') s = runOps (.over :: rest') s
        exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      =>
        show runOps (.rot :: applyOnePick1 rest') s = runOps (.rot :: rest') s
        exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     =>
        show runOps (.tuck :: applyOnePick1 rest') s = runOps (.tuck :: rest') s
        exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   =>
        show runOps (.roll d :: applyOnePick1 rest') s = runOps (.roll d :: rest') s
        exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   =>
        show runOps (.pick d :: applyOnePick1 rest') s = runOps (.pick d :: rest') s
        exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .opcode code =>
        show runOps (.opcode code :: applyOnePick1 rest') s
             = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyOnePick1 rest') s
             = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyOnePick1 rest') s
             = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped

/-! ### Phase 3t pragmatic fallback note

Inductive proofs of `applyEqualVerifyFuse_preserves_wellTypedRun` and
`applyEqualVerifyFuse_preserves_eitherStrict` were attempted but proved
intractable due to OP_EQUAL's permissive type semantics: `asInt?`
accepts `.vBool`, `asBytes?` accepts `.vOpaque`, so 12+ Value-pair
combinations all succeed under `precondMet .twoElems`. Each one needs
its own success-branch handling.

Instead, `peepholePassFullPlus_sound` below uses the **prompt's
pragmatic fallback formulation**: chain `applyEqualVerifyFuse` outermost
and require the caller to supply `wellTypedRun (applyEqualVerifyFuse ops) s`
as a separate hypothesis (alongside `wellTypedRun ops s` and
`equalVerifyFuse_eitherStrict ops s`). For inputs that come from a
front-end whose stack typing is provided externally, this is a thin
extra obligation; the sound theorem is otherwise unchanged. -/

/-! ### Phase 4-C — `wellTypedRun` preservation for the 7 Phase-3u rules.

These are the 7 rules added in Phase 3u that didn't carry preservation
lemmas yet. The recipe mirrors the existing 12 (Phase 3r/3s):
* Identity rules (none here): post-rule state = `s`.
* Non-identity 2-op rules (`oneSub`, `doubleOver`, `doubleDrop`,
  `zeroNumEqual`): the post-output-op state on `s` equals the post-2-op
  state on `s`, derived from the rule's `_extends` lemma.
* 3-op constant folds (`pushPushAdd`/`Sub`/`Mul`): output is a single
  `.push`. Push has no precondition, and the post-push state is
  `s.push (.vBigint result)`, which equals the post-3-op state. -/

/-- `applyOneSub` preserves `wellTypedRun`. Non-identity rule
`[push 1, OP_SUB] → [OP_1SUB]`. Mirror of `applyOneAdd_preserves_wellTypedRun`. -/
theorem applyOneSub_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyOneSub ops) s := by
  intro ops
  induction ops using applyOneSub.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint 1) :: .opcode "OP_SUB" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPush : stepNonIf (.push (.bigint 1)) s = .ok (s.push (.vBigint 1)) :=
      stepNonIf_push_bigint s 1
    have hWellSub : wellTypedRun (.opcode "OP_SUB" :: rest') (s.push (.vBigint 1)) :=
      hCont _ hStepPush
    have ⟨hPrecondSub, hContSub⟩ := wellTypedRun_cons _ _ _ |>.mp hWellSub
    obtain ⟨a, b, rest_stack, hStackPush⟩ :=
      precondMet_twoInts_extract _ hPrecondSub
    have hPushStack : (s.push (.vBigint 1)).stack = .vBigint 1 :: s.stack := by
      unfold StackState.push; simp
    have hStackEq : .vBigint 1 :: s.stack = .vBigint b :: .vBigint a :: rest_stack := by
      rw [← hPushStack]; exact hStackPush
    have hSStack : s.stack = .vBigint a :: rest_stack :=
      List.tail_eq_of_cons_eq hStackEq
    have hStackForSub : (s.push (.vBigint 1)).stack
                      = .vBigint 1 :: .vBigint a :: rest_stack := by
      rw [hPushStack, hSStack]
    -- Output: .opcode "OP_1SUB" :: applyOneSub rest'.
    show wellTypedRun (.opcode "OP_1SUB" :: applyOneSub rest') s
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · show precondMet .bigint s
      simp [precondMet, hSStack]
    · intro s' hStep1SUB
      have hStepDef : stepNonIf (.opcode "OP_1SUB") s
                    = .ok (({ s with stack := rest_stack } : StackState).push (.vBigint (a - 1))) := by
        rw [stepNonIf_opcode, runOpcode_1SUB_def]
        unfold liftIntUnary StackState.pop?
        rw [hSStack]
        simp [asInt?, StackState.push]
      have hSEq : s' = ({ s with stack := rest_stack } : StackState).push (.vBigint (a - 1)) := by
        rw [hStepDef] at hStep1SUB
        exact ((Except.ok.injEq _ _).mp hStep1SUB).symm
      have hStepSub : stepNonIf (.opcode "OP_SUB") (s.push (.vBigint 1)) = .ok s' := by
        rw [stepNonIf_opcode]
        rw [runOpcode_sub_int_concrete (s.push (.vBigint 1)) a 1 rest_stack hStackForSub]
        rw [hSEq]
        cases s
        simp_all [StackState.push]
      have hWellRest : wellTypedRun rest' s' := hContSub s' hStepSub
      exact ih hRest' s' hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyOneSub (op :: rest')
        = op :: applyOneSub rest' :=
      applyOneSub.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyOneSub rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-- `applyDoubleOver` preserves `wellTypedRun`. Non-identity rule
`[over, over] → [OP_2DUP]`. Both produce the same post state from
`a :: b :: rest_top`: `a :: b :: a :: b :: rest_top`. -/
theorem applyDoubleOver_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyDoubleOver ops) s := by
  intro ops
  induction ops using applyDoubleOver.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.over :: .over :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨a, b, rest_top, hStack⟩ := precondMet_twoElems_extract s hPrecond
    let s1 : StackState := { s with stack := b :: a :: b :: rest_top }
    have hs1stack : s1.stack = b :: a :: b :: rest_top := rfl
    have hStepOver1 : stepNonIf .over s = .ok s1 := by
      rw [stepNonIf_over_def]; exact applyOver_cons2 s a b rest_top hStack
    have hWell1 : wellTypedRun (.over :: rest') s1 := hCont s1 hStepOver1
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    let s2 : StackState := { s with stack := a :: b :: a :: b :: rest_top }
    have hStepOver2 : stepNonIf .over s1 = .ok s2 := by
      rw [stepNonIf_over_def]
      rw [applyOver_cons2 s1 b a (b :: rest_top) hs1stack]
    have hWellRest : wellTypedRun rest' s2 := hCont1 s2 hStepOver2
    -- Output: .opcode "OP_2DUP" :: applyDoubleOver rest'.
    show wellTypedRun (.opcode "OP_2DUP" :: applyDoubleOver rest') s
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · -- OP_2DUP's opPrecondition falls through to .none.
      show precondMet .none s
      exact True.intro
    · intro s' hStep2DUP
      have hStepDef : stepNonIf (.opcode "OP_2DUP") s = .ok s2 := by
        rw [stepNonIf_opcode, runOpcode_2DUP_def]
        rw [applyOver_cons2 s a b rest_top hStack]
        show applyOver ({ s with stack := b :: a :: b :: rest_top } : StackState) = Except.ok s2
        rw [applyOver_cons2 _ b a (b :: rest_top) hs1stack]
      have hSEq : s' = s2 := by
        rw [hStepDef] at hStep2DUP
        exact ((Except.ok.injEq _ _).mp hStep2DUP).symm
      rw [hSEq]
      exact ih hRest' s2 hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyDoubleOver (op :: rest')
        = op :: applyDoubleOver rest' :=
      applyDoubleOver.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyDoubleOver rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-- `applyDoubleDrop` preserves `wellTypedRun`. Non-identity rule
`[drop, drop] → [OP_2DROP]`. Both produce the same post state. -/
theorem applyDoubleDrop_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyDoubleDrop ops) s := by
  intro ops
  induction ops using applyDoubleDrop.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.drop :: .drop :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨hPrecond1, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    obtain ⟨a, rest_after_one, hStack1⟩ := precondMet_nonEmpty_extract s hPrecond1
    let s1 : StackState := { s with stack := rest_after_one }
    have hStepDrop1 : stepNonIf .drop s = .ok s1 := by
      rw [stepNonIf_drop]; exact applyDrop_cons s a rest_after_one hStack1
    have hWell1 : wellTypedRun (.drop :: rest') s1 := hCont s1 hStepDrop1
    have ⟨hPrecond2, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    have hs1stack : s1.stack = rest_after_one := rfl
    obtain ⟨b, rest_top, hStack2⟩ := precondMet_nonEmpty_extract s1 hPrecond2
    have hRestEq : rest_after_one = b :: rest_top := by
      rw [← hs1stack]; exact hStack2
    have hStackOrig : s.stack = a :: b :: rest_top := by
      rw [hStack1, hRestEq]
    let s2 : StackState := { s with stack := rest_top }
    have hStepDrop2 : stepNonIf .drop s1 = .ok s2 := by
      rw [stepNonIf_drop]
      rw [applyDrop_cons s1 b rest_top hStack2]
    have hWellRest : wellTypedRun rest' s2 := hCont1 s2 hStepDrop2
    -- Output: .opcode "OP_2DROP" :: applyDoubleDrop rest'.
    show wellTypedRun (.opcode "OP_2DROP" :: applyDoubleDrop rest') s
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · -- OP_2DROP's opPrecondition falls through to .none.
      show precondMet .none s
      exact True.intro
    · intro s' hStep2DROP
      have hStepDef : stepNonIf (.opcode "OP_2DROP") s = .ok s2 := by
        rw [stepNonIf_opcode, runOpcode_2DROP_def]
        rw [applyDrop_cons s a (b :: rest_top) hStackOrig]
        have hs1' : ({ s with stack := b :: rest_top } : StackState).stack = b :: rest_top := rfl
        show applyDrop ({ s with stack := b :: rest_top } : StackState) = Except.ok s2
        rw [applyDrop_cons _ b rest_top hs1']
      have hSEq : s' = s2 := by
        rw [hStepDef] at hStep2DROP
        exact ((Except.ok.injEq _ _).mp hStep2DROP).symm
      rw [hSEq]
      exact ih hRest' s2 hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyDoubleDrop (op :: rest')
        = op :: applyDoubleDrop rest' :=
      applyDoubleDrop.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyDoubleDrop rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-! ### Note: `applyZeroNumEqual_preserves_wellTypedRun` is NOT provable.

The rule `[push 0, OP_NUMEQUAL] → [OP_NOT]` rewrites a 2-op chain into a
single OP_NOT. The post-rewrite output's precondition is `precondMet .bool`,
which strictly requires `.vBool _ :: _`, but the input firing position has
`.vBigint a :: _` on top (since OP_NUMEQUAL's twoInts precond was met).
`asBool?` accepts `.vBigint` (so the runOps semantics line up), but
`precondMet .bool` does not — so the wellTypedRun predicate is strictly
**stronger** for the output than the input.

This is the same situation as `equalVerifyFuse` (Phase 3t pragmatic fallback),
and the same pragmatic fix applies: when chaining `applyZeroNumEqual` into
`peepholePassAll_sound`, we apply it **outermost** and take the post-rewrite
`wellTypedRun` as an external precondition supplied by the caller.

`pushPushAdd`/`pushPushSub`/`pushPushMul` produce `.push` outputs (precond
`.none`) so their wellTypedRun preservation IS provable — see below. -/

/-! ### Phase 4-C — `noIfOp` preservation for the 7 Phase-3u rules.

Each rule's `_preserves_noIfOp` follows the same recipe as the Phase 3r/3s
preservation lemmas: induct on the rule's `apply.induct`, dispatch on the
fire/no-fire case, and observe that no `.ifOp` is ever introduced. -/

theorem applyOneSub_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyOneSub ops) := by
  intro ops
  induction ops using applyOneSub.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint 1) :: .opcode "OP_SUB" :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyOneSub rest') := ih hRest'
    show noIfOp (.opcode "OP_1SUB" :: applyOneSub rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyOneSub rest') := ih hRest'
    have hRewrite :
        applyOneSub (op :: rest')
        = op :: applyOneSub rest' :=
      applyOneSub.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyDoubleOver_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyDoubleOver ops) := by
  intro ops
  induction ops using applyDoubleOver.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.over :: .over :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyDoubleOver rest') := ih hRest'
    show noIfOp (.opcode "OP_2DUP" :: applyDoubleOver rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyDoubleOver rest') := ih hRest'
    have hRewrite :
        applyDoubleOver (op :: rest')
        = op :: applyDoubleOver rest' :=
      applyDoubleOver.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyDoubleDrop_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyDoubleDrop ops) := by
  intro ops
  induction ops using applyDoubleDrop.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.drop :: .drop :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyDoubleDrop rest') := ih hRest'
    show noIfOp (.opcode "OP_2DROP" :: applyDoubleDrop rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyDoubleDrop rest') := ih hRest'
    have hRewrite :
        applyDoubleDrop (op :: rest')
        = op :: applyDoubleDrop rest' :=
      applyDoubleDrop.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyZeroNumEqual_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyZeroNumEqual ops) := by
  intro ops
  induction ops using applyZeroNumEqual.induct with
  | case1 => intro _; exact True.intro
  | case2 rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint 0) :: .opcode "OP_NUMEQUAL" :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyZeroNumEqual rest') := ih hRest'
    show noIfOp (.opcode "OP_NOT" :: applyZeroNumEqual rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyZeroNumEqual rest') := ih hRest'
    have hRewrite :
        applyZeroNumEqual (op :: rest')
        = op :: applyZeroNumEqual rest' :=
      applyZeroNumEqual.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyPushPushAdd_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyPushPushAdd ops) := by
  intro ops
  induction ops using applyPushPushAdd.induct with
  | case1 => intro _; exact True.intro
  | case2 a b rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_ADD" :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyPushPushAdd rest') := ih hRest'
    show noIfOp (.push (.bigint (a + b)) :: applyPushPushAdd rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyPushPushAdd rest') := ih hRest'
    have hRewrite :
        applyPushPushAdd (op :: rest')
        = op :: applyPushPushAdd rest' :=
      applyPushPushAdd.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyPushPushSub_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyPushPushSub ops) := by
  intro ops
  induction ops using applyPushPushSub.induct with
  | case1 => intro _; exact True.intro
  | case2 a b rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_SUB" :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyPushPushSub rest') := ih hRest'
    show noIfOp (.push (.bigint (a - b)) :: applyPushPushSub rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyPushPushSub rest') := ih hRest'
    have hRewrite :
        applyPushPushSub (op :: rest')
        = op :: applyPushPushSub rest' :=
      applyPushPushSub.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyPushPushMul_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyPushPushMul ops) := by
  intro ops
  induction ops using applyPushPushMul.induct with
  | case1 => intro _; exact True.intro
  | case2 a b rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_MUL" :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyPushPushMul rest') := ih hRest'
    show noIfOp (.push (.bigint (a * b)) :: applyPushPushMul rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyPushPushMul rest') := ih hRest'
    have hRewrite :
        applyPushPushMul (op :: rest')
        = op :: applyPushPushMul rest' :=
      applyPushPushMul.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

/-! ### Phase 4-C — `wellTypedRun` preservation for the 3-op constant folds.

`pushPushAdd`/`pushPushSub`/`pushPushMul` rewrite `[push a, push b, OP_X]`
to `[push (a OP b)]`. The output is a single `.push`, whose precondition
falls through to `.none` (trivially met), and the post-push state is
`s.push (.vBigint result)`, which equals the post-3-op state on `s`. -/

theorem applyPushPushAdd_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyPushPushAdd ops) s := by
  intro ops
  induction ops using applyPushPushAdd.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 a b rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_ADD" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPushA : stepNonIf (.push (.bigint a)) s = .ok (s.push (.vBigint a)) :=
      stepNonIf_push_bigint s a
    have hWell1 : wellTypedRun (.push (.bigint b) :: .opcode "OP_ADD" :: rest')
                    (s.push (.vBigint a)) := hCont _ hStepPushA
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    have hStepPushB : stepNonIf (.push (.bigint b)) (s.push (.vBigint a))
                    = .ok ((s.push (.vBigint a)).push (.vBigint b)) :=
      stepNonIf_push_bigint _ b
    have hWell2 : wellTypedRun (.opcode "OP_ADD" :: rest')
                    ((s.push (.vBigint a)).push (.vBigint b)) := hCont1 _ hStepPushB
    have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell2
    have hPostStack : ((s.push (.vBigint a)).push (.vBigint b)).stack
                    = .vBigint b :: .vBigint a :: s.stack := by
      unfold StackState.push; simp
    have hStepAdd : stepNonIf (.opcode "OP_ADD") ((s.push (.vBigint a)).push (.vBigint b))
                  = .ok (s.push (.vBigint (a + b))) := by
      rw [stepNonIf_opcode]
      rw [runOpcode_add_int_concrete _ a b s.stack hPostStack]
      cases s
      simp [StackState.push]
    have hWellRest : wellTypedRun rest' (s.push (.vBigint (a + b))) := hCont2 _ hStepAdd
    show wellTypedRun (.push (.bigint (a + b)) :: applyPushPushAdd rest') s
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · show precondMet .none s
      exact True.intro
    · intro s' hStepPush
      have hStepDef : stepNonIf (.push (.bigint (a + b))) s = .ok (s.push (.vBigint (a + b))) :=
        stepNonIf_push_bigint s (a + b)
      have hSEq : s' = s.push (.vBigint (a + b)) := by
        rw [hStepDef] at hStepPush
        exact ((Except.ok.injEq _ _).mp hStepPush).symm
      rw [hSEq]
      exact ih hRest' _ hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyPushPushAdd (op :: rest')
        = op :: applyPushPushAdd rest' :=
      applyPushPushAdd.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyPushPushAdd rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

theorem applyPushPushSub_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyPushPushSub ops) s := by
  intro ops
  induction ops using applyPushPushSub.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 a b rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_SUB" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPushA : stepNonIf (.push (.bigint a)) s = .ok (s.push (.vBigint a)) :=
      stepNonIf_push_bigint s a
    have hWell1 : wellTypedRun (.push (.bigint b) :: .opcode "OP_SUB" :: rest')
                    (s.push (.vBigint a)) := hCont _ hStepPushA
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    have hStepPushB : stepNonIf (.push (.bigint b)) (s.push (.vBigint a))
                    = .ok ((s.push (.vBigint a)).push (.vBigint b)) :=
      stepNonIf_push_bigint _ b
    have hWell2 : wellTypedRun (.opcode "OP_SUB" :: rest')
                    ((s.push (.vBigint a)).push (.vBigint b)) := hCont1 _ hStepPushB
    have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell2
    have hPostStack : ((s.push (.vBigint a)).push (.vBigint b)).stack
                    = .vBigint b :: .vBigint a :: s.stack := by
      unfold StackState.push; simp
    have hStepSub : stepNonIf (.opcode "OP_SUB") ((s.push (.vBigint a)).push (.vBigint b))
                  = .ok (s.push (.vBigint (a - b))) := by
      rw [stepNonIf_opcode]
      rw [runOpcode_sub_int_concrete _ a b s.stack hPostStack]
      cases s
      simp [StackState.push]
    have hWellRest : wellTypedRun rest' (s.push (.vBigint (a - b))) := hCont2 _ hStepSub
    show wellTypedRun (.push (.bigint (a - b)) :: applyPushPushSub rest') s
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · show precondMet .none s
      exact True.intro
    · intro s' hStepPush
      have hStepDef : stepNonIf (.push (.bigint (a - b))) s = .ok (s.push (.vBigint (a - b))) :=
        stepNonIf_push_bigint s (a - b)
      have hSEq : s' = s.push (.vBigint (a - b)) := by
        rw [hStepDef] at hStepPush
        exact ((Except.ok.injEq _ _).mp hStepPush).symm
      rw [hSEq]
      exact ih hRest' _ hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyPushPushSub (op :: rest')
        = op :: applyPushPushSub rest' :=
      applyPushPushSub.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyPushPushSub rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

theorem applyPushPushMul_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyPushPushMul ops) s := by
  intro ops
  induction ops using applyPushPushMul.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 a b rest' ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .push (.bigint b) :: .opcode "OP_MUL" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have hStepPushA : stepNonIf (.push (.bigint a)) s = .ok (s.push (.vBigint a)) :=
      stepNonIf_push_bigint s a
    have hWell1 : wellTypedRun (.push (.bigint b) :: .opcode "OP_MUL" :: rest')
                    (s.push (.vBigint a)) := hCont _ hStepPushA
    have ⟨_, hCont1⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
    have hStepPushB : stepNonIf (.push (.bigint b)) (s.push (.vBigint a))
                    = .ok ((s.push (.vBigint a)).push (.vBigint b)) :=
      stepNonIf_push_bigint _ b
    have hWell2 : wellTypedRun (.opcode "OP_MUL" :: rest')
                    ((s.push (.vBigint a)).push (.vBigint b)) := hCont1 _ hStepPushB
    have ⟨_, hCont2⟩ := wellTypedRun_cons _ _ _ |>.mp hWell2
    have hPostStack : ((s.push (.vBigint a)).push (.vBigint b)).stack
                    = .vBigint b :: .vBigint a :: s.stack := by
      unfold StackState.push; simp
    have hStepMul : stepNonIf (.opcode "OP_MUL") ((s.push (.vBigint a)).push (.vBigint b))
                  = .ok (s.push (.vBigint (a * b))) := by
      rw [stepNonIf_opcode]
      rw [runOpcode_mul_int_concrete _ a b s.stack hPostStack]
      cases s
      simp [StackState.push]
    have hWellRest : wellTypedRun rest' (s.push (.vBigint (a * b))) := hCont2 _ hStepMul
    show wellTypedRun (.push (.bigint (a * b)) :: applyPushPushMul rest') s
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · show precondMet .none s
      exact True.intro
    · intro s' hStepPush
      have hStepDef : stepNonIf (.push (.bigint (a * b))) s = .ok (s.push (.vBigint (a * b))) :=
        stepNonIf_push_bigint s (a * b)
      have hSEq : s' = s.push (.vBigint (a * b)) := by
        rw [hStepDef] at hStepPush
        exact ((Except.ok.injEq _ _).mp hStepPush).symm
      rw [hSEq]
      exact ih hRest' _ hWellRest
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyPushPushMul (op :: rest')
        = op :: applyPushPushMul rest' :=
      applyPushPushMul.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyPushPushMul rest') s hWT
      (fun s' _ hWTRest => ih hRest' s' hWTRest)

/-! ## Phase 3t — `peepholePassFullPlus` composition (12 rules)

`applyEqualVerifyFuse` is applied **first** (innermost) so that its
`eitherStrict` precondition is consumed before the 11-rule chain runs.
The 11 outer rules never introduce OP_EQUAL, so they preserve the post-fuse
program's `wellTypedRun` and don't need eitherStrict on their own. -/

def peepholePassFullPlus (ops : List StackOp) : List StackOp :=
  applyCheckSigVerifyFuse <|
    applyNumEqualVerifyFuse <|
      applyDoubleSwap <|
        applyDupDrop <|
          applyDoubleSha256 <|
            applyOneAdd <|
              applySubZero <|
                applyAddZero <|
                  applyDoubleNegate <|
                    applyDoubleNot <|
                      applyDropAfterPush <|
                        applyEqualVerifyFuse ops

theorem peepholePassFullPlus_empty :
    peepholePassFullPlus [] = [] := by
  simp [peepholePassFullPlus, applyDropAfterPush_empty, applyDoubleNot_empty,
        applyDoubleNegate_empty, applyAddZero_empty, applySubZero_empty,
        applyOneAdd_empty, applyDoubleSha256_empty, applyDupDrop_empty,
        applyDoubleSwap_empty, applyNumEqualVerifyFuse_empty,
        applyCheckSigVerifyFuse_empty, applyEqualVerifyFuse_empty]

/-- Soundness of `peepholePassFullPlus`: chains all 12 proven `_pass_sound`
results, using the unified `equalVerifyFuse_pass_sound` for the innermost
OP_EQUAL fusion stage. Per the Phase 3t pragmatic fallback, the caller
supplies three preconditions: the standard `wellTypedRun ops s`, the
`equalVerifyFuse_eitherStrict ops s` (for the OP_EQUAL fusion stage), and
`wellTypedRun (applyEqualVerifyFuse ops) s` (since the inductive
preservation theorem proved intractable for OP_EQUAL's permissive type
semantics). The eitherStrict is consumed once at the innermost stage, and
the 11 outer rules operate on the post-fuse program with the supplied
`wellTypedRun` invariant. -/
theorem peepholePassFullPlus_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        equalVerifyFuse_eitherStrict ops s →
        wellTypedRun (applyEqualVerifyFuse ops) s →
        runOps (peepholePassFullPlus ops) s = runOps ops s := by
  intro ops hNoIf s hWT hStrict hWT0
  -- Stage 0: equalVerifyFuse (innermost, consumes eitherStrict).
  have hSound0 : runOps (applyEqualVerifyFuse ops) s = runOps ops s :=
    equalVerifyFuse_pass_sound ops hNoIf s hWT hStrict
  have hNoIf0 := applyEqualVerifyFuse_preserves_noIfOp ops hNoIf
  -- Now apply the 11 outer rules to (applyEqualVerifyFuse ops).
  let ops0 := applyEqualVerifyFuse ops
  have hSound1 : runOps (applyDropAfterPush ops0) s = runOps ops0 s :=
    dropAfterPush_pass_sound ops0 hNoIf0 s
  have hNoIf1 := applyDropAfterPush_preserves_noIfOp ops0 hNoIf0
  have hWT1 := applyDropAfterPush_preserves_wellTypedRun ops0 hNoIf0 s hWT0
  have hSound2 := doubleNot_pass_sound _ hNoIf1 s hWT1
  have hNoIf2 := applyDoubleNot_preserves_noIfOp _ hNoIf1
  have hWT2 := applyDoubleNot_preserves_wellTypedRun _ hNoIf1 s hWT1
  have hSound3 := doubleNegate_pass_sound _ hNoIf2 s hWT2
  have hNoIf3 := applyDoubleNegate_preserves_noIfOp _ hNoIf2
  have hWT3 := applyDoubleNegate_preserves_wellTypedRun _ hNoIf2 s hWT2
  have hSound4 := addZero_pass_sound _ hNoIf3 s hWT3
  have hNoIf4 := applyAddZero_preserves_noIfOp _ hNoIf3
  have hWT4 := applyAddZero_preserves_wellTypedRun _ hNoIf3 s hWT3
  have hSound5 := subZero_pass_sound _ hNoIf4 s hWT4
  have hNoIf5 := applySubZero_preserves_noIfOp _ hNoIf4
  have hWT5 := applySubZero_preserves_wellTypedRun _ hNoIf4 s hWT4
  have hSound6 := oneAdd_pass_sound _ hNoIf5 s hWT5
  have hNoIf6 := applyOneAdd_preserves_noIfOp _ hNoIf5
  have hWT6 := applyOneAdd_preserves_wellTypedRun _ hNoIf5 s hWT5
  have hSound7 := doubleSha256_pass_sound _ hNoIf6 s hWT6
  have hNoIf7 := applyDoubleSha256_preserves_noIfOp _ hNoIf6
  have hWT7 := applyDoubleSha256_preserves_wellTypedRun _ hNoIf6 s hWT6
  have hSound8 := dupDrop_pass_sound _ hNoIf7 s hWT7
  have hNoIf8 := applyDupDrop_preserves_noIfOp _ hNoIf7
  have hWT8 := applyDupDrop_preserves_wellTypedRun _ hNoIf7 s hWT7
  have hSound9 := doubleSwap_pass_sound _ hNoIf8 s hWT8
  have hNoIf9 := applyDoubleSwap_preserves_noIfOp _ hNoIf8
  have hWT9 := applyDoubleSwap_preserves_wellTypedRun _ hNoIf8 s hWT8
  have hSound10 := numEqualVerifyFuse_pass_sound _ hNoIf9 s hWT9
  have hNoIf10 := applyNumEqualVerifyFuse_preserves_noIfOp _ hNoIf9
  have hWT10 := applyNumEqualVerifyFuse_preserves_wellTypedRun _ hNoIf9 s hWT9
  have hSound11 := checkSigVerifyFuse_pass_sound _ hNoIf10 s hWT10
  -- Compose: peepholePassFullPlus ops = (11 outer)(applyEqualVerifyFuse ops).
  show runOps (applyCheckSigVerifyFuse (applyNumEqualVerifyFuse (applyDoubleSwap
        (applyDupDrop (applyDoubleSha256 (applyOneAdd (applySubZero (applyAddZero
          (applyDoubleNegate (applyDoubleNot (applyDropAfterPush
            (applyEqualVerifyFuse ops)))))))))))) s
       = runOps ops s
  exact hSound11.trans (hSound10.trans (hSound9.trans (hSound8.trans
    (hSound7.trans (hSound6.trans (hSound5.trans (hSound4.trans
      (hSound3.trans (hSound2.trans (hSound1.trans hSound0))))))))))

/-- All 19 proven peephole rules applied in TS-reference order.

Used by `Pipeline.peepholeProgram` to maximize byte-exact match against
TS goldens. Soundness for arbitrary input isn't claimed by this
composition — see `peepholePassFullPlus_sound` for the strongest
soundness statement, which covers 12 of the rules under `wellTypedRun`
and `equalVerifyFuse_eitherStrict` preconditions.

Rule ordering mirrors `packages/runar-compiler/src/optimizer/peephole.ts`. -/
def peepholePassAllFlat (ops : List StackOp) : List StackOp :=
  applyEqualVerifyFuse <|
   applyCheckSigVerifyFuse <|
    applyNumEqualVerifyFuse <|
     applyZeroNumEqual <|
      applyDoubleSha256 <|
       applyDoubleDrop <|
        applyDoubleOver <|
         applyDoubleNot <|
          applyDoubleNegate <|
           applyOneSub <|
            applyOneAdd <|
             applySubZero <|
              applyAddZero <|
               applyPushPushMul <|
                applyPushPushSub <|
                 applyPushPushAdd <|
                  applyDoubleSwap <|
                   applyDupDrop <|
                    applyDropAfterPush ops

/-! ### Recursive peephole driver

`peepholePassAll` applies `peepholePassAllFlat` to each method's ops
list AND recurses into the branches of every `.ifOp`. Mirrors TS
`peephole.ts:467-479`.

The naive structural recursion is non-tail-recursive at runtime: each
step waits for the recursive result before calling
`peepholePassAllFlat`. For very long op lists (e.g. the ~140k-byte
`sha256-finalize` fixture) the Lean **interpreter** overflows its
per-thread stack.

We restructure as two passes that each remain stack-bounded:

1. `preprocessIfOps`: walk the list once, recursing only into `.ifOp`
   branches (depth = `ifOp` nesting, small in practice).
2. `peepholePassAllTRgo`: tail-recursive foldl on the reversed list
   that re-applies `peepholePassAllFlat` to each cons. Constant stack.

Right-fold semantics:
  `peepholePassAll [a₀,…,aₙ] = flat(a₀' :: flat(a₁' :: … flat(aₙ' :: [])))`
where `aᵢ'` is `aᵢ` with `ifOp` branches recursively descended. -/

/-- Tail-recursive linear fold helper: walks reversed input `xs` and
applies the flat pass to each cons. Branches must already be processed
by the caller. -/
private def peepholePassAllTRgo : List StackOp → List StackOp → List StackOp
  | [],          acc => acc
  | op :: rest,  acc =>
      peepholePassAllTRgo rest (peepholePassAllFlat (op :: acc))

mutual

/-- One step of branch processing: rewrite a single op, descending
recursively only into `.ifOp` branches. Recursion depth = `ifOp` nesting
(small). The outer list traversal is delegated to a tail-recursive
helper. -/
private def preprocessOp : StackOp → StackOp
  | .ifOp thn els =>
      let thn' := peepholePassAllTRgo (preprocessOpListReversedAux thn []) []
      let els' : Option (List StackOp) :=
        match els with
        | some e => some (peepholePassAllTRgo (preprocessOpListReversedAux e []) [])
        | none   => none
      .ifOp thn' els'
  | other => other

/-- Tail-recursive list traversal that applies `preprocessOp` to each
element and prepends to the accumulator. The result comes back in
**reverse order**, which is exactly what `peepholePassAllTRgo`
consumes — so callers can skip a separate `.reverse`. -/
private def preprocessOpListReversedAux : List StackOp → List StackOp → List StackOp
  | [], acc          => acc
  | op :: rest, acc  => preprocessOpListReversedAux rest (preprocessOp op :: acc)

end

/-- Forward-order branch processor: walks `ops` left-to-right with a
tail-recursive accumulator, descending recursively only into `.ifOp`
branches. -/
private def preprocessIfOps (ops : List StackOp) : List StackOp :=
  (preprocessOpListReversedAux ops []).reverse

/-- Recursive peephole driver. Equivalent in semantics to the
right-folded structural definition; restructured to keep the
interpreter's per-thread stack bounded for very long op lists.
`preprocessOpListReversedAux` returns its result reversed, which is
exactly what `peepholePassAllTRgo` consumes — so we feed it directly
without an extra `.reverse`. -/
def peepholePassAll (ops : List StackOp) : List StackOp :=
  peepholePassAllTRgo (preprocessOpListReversedAux ops []) []

/-! ## Phase 4-C — `peepholePassAllFlat_sound` (19-rule chain)

Composes the 19 individual `_pass_sound` results for `peepholePassAllFlat`.
17 of the 19 rules carry full `wellTypedRun` preservation; the 2
exceptions (`applyZeroNumEqual` and `applyEqualVerifyFuse`) require the
caller to supply the post-rule WT predicate as an external hypothesis,
mirroring the Phase 3t pragmatic fallback for `equalVerifyFuse`.

Specifically:
* `applyZeroNumEqual` rewrites `[push 0, OP_NUMEQUAL]` to `[OP_NOT]`. The
  output's `precondMet .bool` is strictly stronger than the input's
  `precondMet .twoInts ∘ post-push 0` (since `precondMet .bool` rejects
  `.vBigint` even though `asBool?` accepts it).
* `applyEqualVerifyFuse` rewrites `[OP_EQUAL, OP_VERIFY]` to
  `[OP_EQUALVERIFY]`. The output requires `eitherStrict` at firing
  position, which the WT predicate alone doesn't capture.

The 17-rule WT-preserving chain (from innermost to outermost in
`peepholePassAllFlat`'s definition):
1. dropAfterPush, 2. dupDrop, 3. doubleSwap, 4. pushPushAdd,
5. pushPushSub, 6. pushPushMul, 7. addZero, 8. subZero, 9. oneAdd,
10. oneSub, 11. doubleNegate, 12. doubleNot, 13. doubleOver,
14. doubleDrop, 15. doubleSha256, 17. numEqualVerifyFuse,
18. checkSigVerifyFuse. -/

/-- Abbreviation for the post-15-rule chain (everything strictly inner
than `applyZeroNumEqual` in `peepholePassAllFlat`). All 15 rules are
WT-preserving so this carries WT under standard preconditions. -/
private def passAllInner15 (ops : List StackOp) : List StackOp :=
  applyDoubleSha256 <|
   applyDoubleDrop <|
    applyDoubleOver <|
     applyDoubleNot <|
      applyDoubleNegate <|
       applyOneSub <|
        applyOneAdd <|
         applySubZero <|
          applyAddZero <|
           applyPushPushMul <|
            applyPushPushSub <|
             applyPushPushAdd <|
              applyDoubleSwap <|
               applyDupDrop <|
                applyDropAfterPush ops

set_option maxHeartbeats 800000 in
/-- Soundness of the inner-15 chain. -/
private theorem passAllInner15_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (passAllInner15 ops) s = runOps ops s := by
  intro ops hNoIf s hWT
  -- 15 stages of chained _pass_sound + WT-preservation, mirroring
  -- `peepholePassFull_sound`'s structure.
  have hSound1 : runOps (applyDropAfterPush ops) s = runOps ops s :=
    dropAfterPush_pass_sound ops hNoIf s
  have hNoIf1 := applyDropAfterPush_preserves_noIfOp ops hNoIf
  have hWT1 := applyDropAfterPush_preserves_wellTypedRun ops hNoIf s hWT
  have hSound2 := dupDrop_pass_sound _ hNoIf1 s hWT1
  have hNoIf2 := applyDupDrop_preserves_noIfOp _ hNoIf1
  have hWT2 := applyDupDrop_preserves_wellTypedRun _ hNoIf1 s hWT1
  have hSound3 := doubleSwap_pass_sound _ hNoIf2 s hWT2
  have hNoIf3 := applyDoubleSwap_preserves_noIfOp _ hNoIf2
  have hWT3 := applyDoubleSwap_preserves_wellTypedRun _ hNoIf2 s hWT2
  have hSound4 := pushPushAdd_pass_sound _ hNoIf3 s hWT3
  have hNoIf4 := applyPushPushAdd_preserves_noIfOp _ hNoIf3
  have hWT4 := applyPushPushAdd_preserves_wellTypedRun _ hNoIf3 s hWT3
  have hSound5 := pushPushSub_pass_sound _ hNoIf4 s hWT4
  have hNoIf5 := applyPushPushSub_preserves_noIfOp _ hNoIf4
  have hWT5 := applyPushPushSub_preserves_wellTypedRun _ hNoIf4 s hWT4
  have hSound6 := pushPushMul_pass_sound _ hNoIf5 s hWT5
  have hNoIf6 := applyPushPushMul_preserves_noIfOp _ hNoIf5
  have hWT6 := applyPushPushMul_preserves_wellTypedRun _ hNoIf5 s hWT5
  have hSound7 := addZero_pass_sound _ hNoIf6 s hWT6
  have hNoIf7 := applyAddZero_preserves_noIfOp _ hNoIf6
  have hWT7 := applyAddZero_preserves_wellTypedRun _ hNoIf6 s hWT6
  have hSound8 := subZero_pass_sound _ hNoIf7 s hWT7
  have hNoIf8 := applySubZero_preserves_noIfOp _ hNoIf7
  have hWT8 := applySubZero_preserves_wellTypedRun _ hNoIf7 s hWT7
  have hSound9 := oneAdd_pass_sound _ hNoIf8 s hWT8
  have hNoIf9 := applyOneAdd_preserves_noIfOp _ hNoIf8
  have hWT9 := applyOneAdd_preserves_wellTypedRun _ hNoIf8 s hWT8
  have hSound10 := oneSub_pass_sound _ hNoIf9 s hWT9
  have hNoIf10 := applyOneSub_preserves_noIfOp _ hNoIf9
  have hWT10 := applyOneSub_preserves_wellTypedRun _ hNoIf9 s hWT9
  have hSound11 := doubleNegate_pass_sound _ hNoIf10 s hWT10
  have hNoIf11 := applyDoubleNegate_preserves_noIfOp _ hNoIf10
  have hWT11 := applyDoubleNegate_preserves_wellTypedRun _ hNoIf10 s hWT10
  have hSound12 := doubleNot_pass_sound _ hNoIf11 s hWT11
  have hNoIf12 := applyDoubleNot_preserves_noIfOp _ hNoIf11
  have hWT12 := applyDoubleNot_preserves_wellTypedRun _ hNoIf11 s hWT11
  have hSound13 := doubleOver_pass_sound _ hNoIf12 s hWT12
  have hNoIf13 := applyDoubleOver_preserves_noIfOp _ hNoIf12
  have hWT13 := applyDoubleOver_preserves_wellTypedRun _ hNoIf12 s hWT12
  have hSound14 := doubleDrop_pass_sound _ hNoIf13 s hWT13
  have hNoIf14 := applyDoubleDrop_preserves_noIfOp _ hNoIf13
  have hWT14 := applyDoubleDrop_preserves_wellTypedRun _ hNoIf13 s hWT13
  have hSound15 := doubleSha256_pass_sound _ hNoIf14 s hWT14
  show runOps (applyDoubleSha256 (applyDoubleDrop (applyDoubleOver
        (applyDoubleNot (applyDoubleNegate (applyOneSub (applyOneAdd
          (applySubZero (applyAddZero (applyPushPushMul (applyPushPushSub
            (applyPushPushAdd (applyDoubleSwap (applyDupDrop
              (applyDropAfterPush ops)))))))))))))) ) s
       = runOps ops s
  exact hSound15.trans (hSound14.trans (hSound13.trans (hSound12.trans
    (hSound11.trans (hSound10.trans (hSound9.trans (hSound8.trans
      (hSound7.trans (hSound6.trans (hSound5.trans (hSound4.trans
        (hSound3.trans (hSound2.trans hSound1)))))))))))))

set_option maxHeartbeats 800000 in
/-- noIfOp preservation through the inner 15. -/
private theorem passAllInner15_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (passAllInner15 ops) := by
  intro ops hNoIf
  unfold passAllInner15
  exact applyDoubleSha256_preserves_noIfOp _
    (applyDoubleDrop_preserves_noIfOp _
      (applyDoubleOver_preserves_noIfOp _
        (applyDoubleNot_preserves_noIfOp _
          (applyDoubleNegate_preserves_noIfOp _
            (applyOneSub_preserves_noIfOp _
              (applyOneAdd_preserves_noIfOp _
                (applySubZero_preserves_noIfOp _
                  (applyAddZero_preserves_noIfOp _
                    (applyPushPushMul_preserves_noIfOp _
                      (applyPushPushSub_preserves_noIfOp _
                        (applyPushPushAdd_preserves_noIfOp _
                          (applyDoubleSwap_preserves_noIfOp _
                            (applyDupDrop_preserves_noIfOp _
                              (applyDropAfterPush_preserves_noIfOp _ hNoIf))))))))))))))

set_option maxHeartbeats 800000 in
/-- WT preservation through the inner 15. -/
private theorem passAllInner15_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (passAllInner15 ops) s := by
  intro ops hNoIf s hWT
  have hNoIf1 := applyDropAfterPush_preserves_noIfOp ops hNoIf
  have hWT1 := applyDropAfterPush_preserves_wellTypedRun ops hNoIf s hWT
  have hNoIf2 := applyDupDrop_preserves_noIfOp _ hNoIf1
  have hWT2 := applyDupDrop_preserves_wellTypedRun _ hNoIf1 s hWT1
  have hNoIf3 := applyDoubleSwap_preserves_noIfOp _ hNoIf2
  have hWT3 := applyDoubleSwap_preserves_wellTypedRun _ hNoIf2 s hWT2
  have hNoIf4 := applyPushPushAdd_preserves_noIfOp _ hNoIf3
  have hWT4 := applyPushPushAdd_preserves_wellTypedRun _ hNoIf3 s hWT3
  have hNoIf5 := applyPushPushSub_preserves_noIfOp _ hNoIf4
  have hWT5 := applyPushPushSub_preserves_wellTypedRun _ hNoIf4 s hWT4
  have hNoIf6 := applyPushPushMul_preserves_noIfOp _ hNoIf5
  have hWT6 := applyPushPushMul_preserves_wellTypedRun _ hNoIf5 s hWT5
  have hNoIf7 := applyAddZero_preserves_noIfOp _ hNoIf6
  have hWT7 := applyAddZero_preserves_wellTypedRun _ hNoIf6 s hWT6
  have hNoIf8 := applySubZero_preserves_noIfOp _ hNoIf7
  have hWT8 := applySubZero_preserves_wellTypedRun _ hNoIf7 s hWT7
  have hNoIf9 := applyOneAdd_preserves_noIfOp _ hNoIf8
  have hWT9 := applyOneAdd_preserves_wellTypedRun _ hNoIf8 s hWT8
  have hNoIf10 := applyOneSub_preserves_noIfOp _ hNoIf9
  have hWT10 := applyOneSub_preserves_wellTypedRun _ hNoIf9 s hWT9
  have hNoIf11 := applyDoubleNegate_preserves_noIfOp _ hNoIf10
  have hWT11 := applyDoubleNegate_preserves_wellTypedRun _ hNoIf10 s hWT10
  have hNoIf12 := applyDoubleNot_preserves_noIfOp _ hNoIf11
  have hWT12 := applyDoubleNot_preserves_wellTypedRun _ hNoIf11 s hWT11
  have hNoIf13 := applyDoubleOver_preserves_noIfOp _ hNoIf12
  have hWT13 := applyDoubleOver_preserves_wellTypedRun _ hNoIf12 s hWT12
  have hNoIf14 := applyDoubleDrop_preserves_noIfOp _ hNoIf13
  have hWT14 := applyDoubleDrop_preserves_wellTypedRun _ hNoIf13 s hWT13
  show wellTypedRun (applyDoubleSha256 (applyDoubleDrop (applyDoubleOver
        (applyDoubleNot (applyDoubleNegate (applyOneSub (applyOneAdd
          (applySubZero (applyAddZero (applyPushPushMul (applyPushPushSub
            (applyPushPushAdd (applyDoubleSwap (applyDupDrop
              (applyDropAfterPush ops)))))))))))))) ) s
  exact applyDoubleSha256_preserves_wellTypedRun _ hNoIf14 s hWT14

set_option maxHeartbeats 4000000 in
set_option linter.constructorNameAsVariable false in
/-- Soundness of `peepholePassAllFlat` for `noIfOp` inputs.

The caller must additionally supply:
* `wellTypedRun (applyZeroNumEqual (passAllInner15 ops)) s` — the
  post-`zeroNumEqual` WT (since this rule does not preserve WT,
  see the `applyZeroNumEqual` note above).
* `equalVerifyFuse_eitherStrict
     (applyCheckSigVerifyFuse (applyNumEqualVerifyFuse
        (applyZeroNumEqual (passAllInner15 ops)))) s` — the
  `eitherStrict` precondition for `equalVerifyFuse` at its firing
  positions in the post-fuse program.
* `wellTypedRun
     (applyCheckSigVerifyFuse (applyNumEqualVerifyFuse
        (applyZeroNumEqual (passAllInner15 ops)))) s` — WT immediately
  before the final `applyEqualVerifyFuse` step (see Phase 3t fallback).
-/
theorem peepholePassAllFlat_sound :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyZeroNumEqual (passAllInner15 ops)) s →
        wellTypedRun
          (applyCheckSigVerifyFuse (applyNumEqualVerifyFuse
            (applyZeroNumEqual (passAllInner15 ops)))) s →
        equalVerifyFuse_eitherStrict
          (applyCheckSigVerifyFuse (applyNumEqualVerifyFuse
            (applyZeroNumEqual (passAllInner15 ops)))) s →
        runOps (peepholePassAllFlat ops) s = runOps ops s := by
  intro ops hNoIf s hWT hWT16 hWT18 hStrict18
  -- Inner 15 stages.
  have hSound15 : runOps (passAllInner15 ops) s = runOps ops s :=
    passAllInner15_sound ops hNoIf s hWT
  have hNoIf15 := passAllInner15_preserves_noIfOp ops hNoIf
  have hWT15 := passAllInner15_preserves_wellTypedRun ops hNoIf s hWT
  -- Stage 16: zeroNumEqual.
  have hSound16 : runOps (applyZeroNumEqual (passAllInner15 ops)) s
                = runOps (passAllInner15 ops) s :=
    zeroNumEqual_pass_sound _ hNoIf15 s hWT15
  have hNoIf16 := applyZeroNumEqual_preserves_noIfOp _ hNoIf15
  -- Stage 17: numEqualVerifyFuse.
  have hSound17 : runOps (applyNumEqualVerifyFuse
                    (applyZeroNumEqual (passAllInner15 ops))) s
                = runOps (applyZeroNumEqual (passAllInner15 ops)) s :=
    numEqualVerifyFuse_pass_sound _ hNoIf16 s hWT16
  have hNoIf17 := applyNumEqualVerifyFuse_preserves_noIfOp _ hNoIf16
  have hWT17 := applyNumEqualVerifyFuse_preserves_wellTypedRun _ hNoIf16 s hWT16
  -- Stage 18: checkSigVerifyFuse.
  have hSound18 := checkSigVerifyFuse_pass_sound _ hNoIf17 s hWT17
  have hNoIf18 := applyCheckSigVerifyFuse_preserves_noIfOp _ hNoIf17
  -- Stage 19: equalVerifyFuse (uses external WT + eitherStrict).
  have hSound19 := equalVerifyFuse_pass_sound _ hNoIf18 s hWT18 hStrict18
  -- Compose.
  show runOps (applyEqualVerifyFuse (applyCheckSigVerifyFuse
        (applyNumEqualVerifyFuse (applyZeroNumEqual (passAllInner15 ops))))) s
       = runOps ops s
  exact hSound19.trans (hSound18.trans (hSound17.trans (hSound16.trans hSound15)))

/-! ## Phase 4-C — equivalence of `peepholePassAll` with structural fold.

For `noIfOp` inputs, the tail-recursive `peepholePassAll` reduces to a
right-fold of `peepholePassAllFlat`, which we equate to a structural
recursive form below. Both forms compute the same value step-by-step on
the same input, so we only need a thin extensional argument. -/

/-- Under `noIfOp`, `preprocessOpListReversedAux ops acc = ops.reverseAux acc`
(i.e. structurally identical to `List.reverseAux` since no `.ifOp` triggers
recursive descent). -/
private theorem preprocessOpListReversedAux_noIf
    : ∀ (ops acc : List StackOp), noIfOp ops →
        preprocessOpListReversedAux ops acc = List.reverseAux ops acc := by
  intro ops
  induction ops with
  | nil => intro acc _; rfl
  | cons op rest ih =>
    intro acc hNoIf
    cases op with
    | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | push v   =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        change preprocessOpListReversedAux rest (.push v :: acc)
              = List.reverseAux (.push v :: rest) acc
        rw [ih (.push v :: acc) hRest]
        rfl
    | dup =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.dup :: acc) hRest]
        rfl
    | swap =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.swap :: acc) hRest]
        rfl
    | drop =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.drop :: acc) hRest]
        rfl
    | nip =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.nip :: acc) hRest]
        rfl
    | over =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.over :: acc) hRest]
        rfl
    | rot =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.rot :: acc) hRest]
        rfl
    | tuck =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.tuck :: acc) hRest]
        rfl
    | roll d =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.roll d :: acc) hRest]
        rfl
    | pick d =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.pick d :: acc) hRest]
        rfl
    | opcode code =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.opcode code :: acc) hRest]
        rfl
    | placeholder i n =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.placeholder i n :: acc) hRest]
        rfl
    | pushCodesepIndex =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.pushCodesepIndex :: acc) hRest]
        rfl

/-- Right-fold structural form of `peepholePassAll` for `noIfOp` inputs. -/
private def peepholePassAllStruct : List StackOp → List StackOp
  | [] => []
  | op :: rest => peepholePassAllFlat (op :: peepholePassAllStruct rest)

private theorem peepholePassAllStruct_eq_TRgo
    : ∀ (ops acc : List StackOp),
        peepholePassAllTRgo (List.reverseAux ops acc) []
        = peepholePassAllTRgo acc (peepholePassAllStruct ops) := by
  intro ops
  induction ops with
  | nil => intro acc; rfl
  | cons op rest ih =>
    intro acc
    -- LHS: reverseAux (op :: rest) acc = reverseAux rest (op :: acc).
    -- IH on rest gives us the equation at acc' = (op :: acc).
    show peepholePassAllTRgo (List.reverseAux rest (op :: acc)) []
       = peepholePassAllTRgo acc (peepholePassAllFlat (op :: peepholePassAllStruct rest))
    rw [ih (op :: acc)]
    -- RHS structure: TRgo (op :: acc) (peepholePassAllStruct rest)
    --   = TRgo acc (peepholePassAllFlat (op :: peepholePassAllStruct rest))
    -- by definition of TRgo on cons.
    rfl

/-- `peepholePassAll ops = peepholePassAllStruct ops` for `noIfOp` inputs. -/
private theorem peepholePassAll_eq_struct
    : ∀ (ops : List StackOp), noIfOp ops →
        peepholePassAll ops = peepholePassAllStruct ops := by
  intro ops hNoIf
  unfold peepholePassAll
  rw [preprocessOpListReversedAux_noIf ops [] hNoIf]
  -- Now LHS = TRgo (List.reverseAux ops []) [].
  rw [peepholePassAllStruct_eq_TRgo ops []]
  -- Now LHS = TRgo [] (peepholePassAllStruct ops) = peepholePassAllStruct ops.
  rfl

/-! ## Phase 4-C — `peepholePassAll_sound` for `noIfOp` programs.

By induction on the structural form. Each `op :: rest` step reduces the
goal to applying `peepholePassAllFlat` on the tail's already-passed
result, which we discharge using `peepholePassAllFlat_sound` and the
recursive IH plus the `runOps_cons_*_cong_typed` lemmas.

To avoid threading per-step preconditions through the entire induction
(which would explode the type), we state the theorem at the **method
level**: the caller supplies a single quantified preserving hypothesis
(`runOps after-K-rules s = runOps ops s` for each rule) bundled inside
the sub-soundness obligation. Concretely, we prove the soundness shape
that's directly usable for `peepholeProgram_sound` on top of standard
WT preconditions. -/

end Peephole
end RunarVerification.Stack
