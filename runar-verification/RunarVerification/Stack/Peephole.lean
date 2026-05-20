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

Each `runOpcode_<OP>_def` is `rfl`-provable because Lean's match arm
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
                     | _, _ =>
                         match asInt? a, asBytes? b with
                         | some ai, some bb =>
                             decide ((encodeMinimalLE ai).toList = bb.toList)
                         | _, _ =>
                             match asBytes? a, asInt? b with
                             | some ab, some bi =>
                                 decide (ab.toList = (encodeMinimalLE bi).toList)
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

/-! ### `[push N, OP_1ADD] → [push (N+1)]` rule (Phase 7.1 follow-up)

In streaming mode, `applyOneAdd` may fold `[push 1, OP_ADD]` to
`[OP_1ADD]` before the upcoming preceding `push N` has streamed
in, blocking `applyPushPushAdd`'s 3-op fold. This rule
consolidates the resulting `[push N, OP_1ADD]` into `[push (N+1)]`,
producing the same minimal byte sequence the TS reference emits.

Closes the `if-without-else-multi-temp` fixture's byte-74
divergence (`push 8, OP_1ADD` → `push 9`). -/

def applyPushOneAdd : List StackOp → List StackOp
  | [] => []
  | .push (.bigint a) :: .opcode "OP_1ADD" :: rest =>
      .push (.bigint (a + 1)) :: applyPushOneAdd rest
  | op :: rest => op :: applyPushOneAdd rest

theorem applyPushOneAdd_empty : applyPushOneAdd [] = [] := rfl

/-! ### `[push N, OP_1SUB] → [push (N-1)]` rule (symmetric to PushOneAdd) -/

def applyPushOneSub : List StackOp → List StackOp
  | [] => []
  | .push (.bigint a) :: .opcode "OP_1SUB" :: rest =>
      .push (.bigint (a - 1)) :: applyPushOneSub rest
  | op :: rest => op :: applyPushOneSub rest

theorem applyPushOneSub_empty : applyPushOneSub [] = [] := rfl

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
*by definition of `Crypto.hash256`*. As of Tier 5.3 (2026-05-10)
`Crypto.hash256` is a concrete `def` over the backend-parametric
`Crypto.sha256`, so the linking identity is now provable by `rfl` and
contributes no separate axiom to the TCB.
-/

theorem hash256_eq_double_sha256 (b : ByteArray) :
    hash256 b = sha256 (sha256 b) := rfl

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

theorem runOps_cons_pickStruct_eq (d : Nat) (rest : List StackOp) (s : StackState) :
    runOps (StackOp.pickStruct d :: rest) s
    = match stepNonIf (StackOp.pickStruct d) s with
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

theorem runOps_cons_rawBytes_eq (b : ByteArray) (rest : List StackOp) (s : StackState) :
    runOps (StackOp.rawBytes b :: rest) s
    = match stepNonIf (StackOp.rawBytes b) s with
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

/-- Boolean checker for `noIfOp`. Returns `true` iff no element of `ops`
is an `.ifOp` constructor. -/
def noIfOpBool : List StackOp → Bool
  | [] => true
  | .ifOp _ _ :: _ => false
  | _ :: rest => noIfOpBool rest

/-- `noIfOpBool` reflects `noIfOp`. -/
theorem noIfOpBool_iff (ops : List StackOp) :
    noIfOpBool ops = true ↔ noIfOp ops := by
  induction ops with
  | nil => simp [noIfOpBool, noIfOp]
  | cons op rest ih =>
      cases op with
      | ifOp _ _ => simp [noIfOpBool, noIfOp]
      | _ => simp [noIfOpBool, noIfOp, ih]

/-- `noIfOp` is decidable via the Boolean checker. -/
instance (ops : List StackOp) : Decidable (noIfOp ops) :=
  if h : noIfOpBool ops = true
  then isTrue ((noIfOpBool_iff ops).mp h)
  else isFalse (fun hNo => h ((noIfOpBool_iff ops).mpr hNo))

/-- Predicate: an op list contains no `.push` constructor at the top
level. Mirrors `noIfOp`. The chain-fold post-pass
(`applyPushAddPushAdd` / `applyPushAddPushSub`) only rewrites windows
that begin with `.push (.bigint _)`, so a `pushFree` list is a fixpoint
of the chain-fold. Used by `peepholeChainFold_eq_self_of_noIfOp_pushFree`
to discharge the pure-syntactic identity for the arith consume fragment,
which lowers to `[.swap, .opcode …]` (no `.push`). -/
def pushFree : List StackOp → Prop
  | [] => True
  | .push _ :: _ => False
  | _ :: rest => pushFree rest

/-- Boolean checker for `pushFree`. Returns `true` iff no element of
`ops` is a `.push` constructor. -/
def pushFreeBool : List StackOp → Bool
  | [] => true
  | .push _ :: _ => false
  | _ :: rest => pushFreeBool rest

/-- `pushFreeBool` reflects `pushFree`. -/
theorem pushFreeBool_iff (ops : List StackOp) :
    pushFreeBool ops = true ↔ pushFree ops := by
  induction ops with
  | nil => simp [pushFreeBool, pushFree]
  | cons op rest ih =>
      cases op with
      | push _ => simp [pushFreeBool, pushFree]
      | _ => simp [pushFreeBool, pushFree, ih]

/-- `pushFree` is decidable via the Boolean checker. -/
instance (ops : List StackOp) : Decidable (pushFree ops) :=
  if h : pushFreeBool ops = true
  then isTrue ((pushFreeBool_iff ops).mp h)
  else isFalse (fun hNo => h ((pushFreeBool_iff ops).mpr hNo))

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

private theorem runOps_cons_pickStruct_cong (d : Nat) (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.pickStruct d :: a) s = runOps (.pickStruct d :: b) s := by
  rw [runOps_cons_pickStruct_eq, runOps_cons_pickStruct_eq]
  cases hStep : stepNonIf (.pickStruct d) s with
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

private theorem runOps_cons_rawBytes_cong (bs : ByteArray)
    (a b : List StackOp) (s : StackState)
    (h : ∀ s', runOps a s' = runOps b s') :
    runOps (.rawBytes bs :: a) s = runOps (.rawBytes bs :: b) s := by
  rw [runOps_cons_rawBytes_eq, runOps_cons_rawBytes_eq]
  cases hStep : stepNonIf (.rawBytes bs) s with
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
  simp [asBytes?]

theorem runOpcode_equalVerify_bytes
    (s : StackState) (a b : ByteArray) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBytes b :: .vBytes a :: rest_top) :
    runOpcode "OP_EQUALVERIFY" s
    = if decide (a.toList = b.toList) then .ok ({ s with stack := rest_top } : StackState)
                                        else .error .assertFailed := by
  rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vBytes b) (.vBytes a) rest_top hs]
  simp [asBytes?]

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

/-- F1 decidability: `precondMet` is a pattern-match returning `True`
or `False`. Each arm is decidable by `decide` on the underlying
`match` expression. Required transitively by `wellTypedRun` /
`peepholePassAllFlat_preconditions`'s Decidable instances. -/
instance precondMet_decidable (e : OpExpectation) (s : StackState) :
    Decidable (precondMet e s) := by
  cases e <;> simp [precondMet] <;> (first | (split <;> infer_instance) | infer_instance)

/-! ### `opPrecondition` table (Phase 3m)

The expectation an op imposes on the stack at its execution position.
Most ops have `.none` (no precondition); the table below lists every
op the conditional peephole rules' atom-sound proofs depend on.

Entries not yet classified are conservative `.none` defaults — Phase 3n
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

/-! ### F1 decidability for `wellTypedRun`

`wellTypedRun` is `Prop`-valued and uses `∀ s', stepNonIf op s = .ok s' → …`
to thread the post-step state. `stepNonIf op s` is a *functional* expression
returning a `Stack.Eval.Result StackState` (either `.ok` of a unique
witness or `.error`). The universal quantifier is therefore vacuous on
`.error` and collapses to a single check on `.ok`'s payload. We
formalise this via the equivalent `wellTypedRunBool` checker and then
transport its `Decidable` instance back to the `Prop` form.

Pattern: `def wellTypedRunBool` mirrors `wellTypedRun` but consumes
`stepNonIf`'s result eagerly; `wellTypedRunBool_iff_wellTypedRun`
proves the two are propositionally equal, and the `Decidable` instance
falls out via `inferInstanceAs ∘ decidable_of_iff`. -/

def wellTypedRunBool : List StackOp → StackState → Bool
  | [], _ => true
  | op :: rest, s =>
      (decide (precondMet (opPrecondition op) s)) &&
      (match stepNonIf op s with
       | .ok s' => wellTypedRunBool rest s'
       | .error _ => true)

theorem wellTypedRunBool_iff_wellTypedRun :
    ∀ (ops : List StackOp) (s : StackState),
      wellTypedRunBool ops s = true ↔ wellTypedRun ops s
  | [], _ => by simp [wellTypedRunBool, wellTypedRun]
  | op :: rest, s => by
    unfold wellTypedRunBool wellTypedRun
    constructor
    · intro h
      rw [Bool.and_eq_true] at h
      obtain ⟨hPre, hRest⟩ := h
      refine ⟨of_decide_eq_true hPre, ?_⟩
      intro s' hStep
      have : wellTypedRunBool rest s' = true := by
        rw [hStep] at hRest; exact hRest
      exact (wellTypedRunBool_iff_wellTypedRun rest s').mp this
    · intro ⟨hPre, hStep⟩
      rw [Bool.and_eq_true]
      refine ⟨decide_eq_true hPre, ?_⟩
      cases hRes : stepNonIf op s with
      | error _ => rfl
      | ok s' =>
          have := hStep s' hRes
          exact (wellTypedRunBool_iff_wellTypedRun rest s').mpr this

instance wellTypedRun_decidable (ops : List StackOp) (s : StackState) :
    Decidable (wellTypedRun ops s) :=
  decidable_of_iff (wellTypedRunBool ops s = true)
    (wellTypedRunBool_iff_wellTypedRun ops s)

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

private theorem runOps_cons_pickStruct_cong_typed (d : Nat) (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf (.pickStruct d) s = .ok s' → runOps a s' = runOps b s') :
    runOps (.pickStruct d :: a) s = runOps (.pickStruct d :: b) s := by
  rw [runOps_cons_pickStruct_eq, runOps_cons_pickStruct_eq]
  cases hStep : stepNonIf (.pickStruct d) s with
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

private theorem runOps_cons_rawBytes_cong_typed (bs : ByteArray)
    (a b : List StackOp) (s : StackState)
    (h : ∀ s', stepNonIf (.rawBytes bs) s = .ok s' → runOps a s' = runOps b s') :
    runOps (.rawBytes bs :: a) s = runOps (.rawBytes bs :: b) s := by
  rw [runOps_cons_rawBytes_eq, runOps_cons_rawBytes_eq]
  cases hStep : stepNonIf (.rawBytes bs) s with
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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyDoubleNot rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyDoubleNot rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
          | .pickStruct _ :: _ => rfl
          | .opcode _ :: _ => rfl
          | .ifOp _ _ :: _ => rfl
          | .placeholder _ _ :: _ => rfl
          | .pushCodesepIndex :: _ => rfl
          | .rawBytes _ :: _ => rfl
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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyDropAfterPush rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong d _ _ s (fun s' => ih hRest' s')
    | .opcode code =>
        show runOps (.opcode code :: applyDropAfterPush rest') s = runOps (.opcode code :: rest') s
        exact runOps_cons_opcode_cong code _ _ s (fun s' => ih hRest' s')
    | .placeholder i n =>
        show runOps (.placeholder i n :: applyDropAfterPush rest') s = runOps (.placeholder i n :: rest') s
        exact runOps_cons_placeholder_cong i n _ _ s (fun s' => ih hRest' s')
    | .pushCodesepIndex =>
        show runOps (.pushCodesepIndex :: applyDropAfterPush rest') s = runOps (.pushCodesepIndex :: rest') s
        exact runOps_cons_pushCodesepIndex_cong _ _ s (fun s' => ih hRest' s')
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyDropAfterPush rest') s = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong b _ _ s (fun s' => ih hRest' s')

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyDoubleNegate rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyDoubleNegate rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyAddZero rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyAddZero rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applySubZero rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applySubZero rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyOneAdd rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyOneAdd rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyDoubleSha256 rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyDoubleSha256 rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyDupDrop rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyDupDrop rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
      -- In Lean ≥ v4.29 the `let s1` projection no longer reduces under
      -- `simp_all` automatically; unfold it explicitly first.
      simp only [s1]
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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyDoubleSwap rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyDoubleSwap rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyNumEqualVerifyFuse rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyNumEqualVerifyFuse rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyCheckSigVerifyFuse rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyCheckSigVerifyFuse rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyEqualVerifyFuse rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyEqualVerifyFuse rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
          | .pickStruct _ :: _ => rfl
          | .opcode _ :: _ => rfl
          | .ifOp _ _ :: _ => rfl
          | .placeholder _ _ :: _ => rfl
          | .pushCodesepIndex :: _ => rfl
          | .rawBytes _ :: _ => rfl
      | .dup      => rfl
      | .swap     => rfl
      | .drop     => rfl
      | .nip      => rfl
      | .over     => rfl
      | .rot      => rfl
      | .tuck     => rfl
      | .roll _   => rfl
      | .pick _   => rfl
      | .pickStruct _ => rfl
      | .opcode _ => rfl
      | .placeholder _ _ => rfl
      | .pushCodesepIndex => rfl
      | .rawBytes _ => rfl
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
          | .pickStruct _ :: _ => rfl
          | .opcode _ :: _ => rfl
          | .ifOp _ _ :: _ => rfl
          | .placeholder _ _ :: _ => rfl
          | .pushCodesepIndex :: _ => rfl
          | .rawBytes _ :: _ => rfl
      | .dup      => rfl
      | .swap     => rfl
      | .drop     => rfl
      | .nip      => rfl
      | .over     => rfl
      | .rot      => rfl
      | .tuck     => rfl
      | .roll _   => rfl
      | .pick _   => rfl
      | .pickStruct _ => rfl
      | .opcode _ => rfl
      | .placeholder _ _ => rfl
      | .pushCodesepIndex => rfl
      | .rawBytes _ => rfl
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
      -- In Lean ≥ v4.29 the `let s1` projection no longer reduces under
      -- `simp_all` automatically; unfold it explicitly first.
      simp only [s1]
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
            simp [asBytes?]]
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
            simp [asBytes?]]
  · -- vOpaque :: vBytes
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_EQUAL" s
          = .ok (({ s with stack := rest_top } : StackState).push
                  (.vBool (decide (a.toList = b.toList)))) from by
            rw [runOpcode_EQUAL_def, popN_two_cons s (.vOpaque b) (.vBytes a) rest_top hOB]
            simp [asBytes?]]
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
            simp [asBytes?]]
  · -- vOpaque :: vOpaque
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_EQUAL" s
          = .ok (({ s with stack := rest_top } : StackState).push
                  (.vBool (decide (a.toList = b.toList)))) from by
            rw [runOpcode_EQUAL_def, popN_two_cons s (.vOpaque b) (.vOpaque a) rest_top hOO]
            simp [asBytes?]]
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
            simp [asBytes?]]

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
    simp [asBytes?]
  · rw [runOpcode_EQUAL_def, popN_two_cons s (.vBytes b) (.vOpaque a) rest_top hBO]
    simp [asBytes?]
  · rw [runOpcode_EQUAL_def, popN_two_cons s (.vOpaque b) (.vBytes a) rest_top hOB]
    simp [asBytes?]
  · rw [runOpcode_EQUAL_def, popN_two_cons s (.vOpaque b) (.vOpaque a) rest_top hOO]
    simp [asBytes?]

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
        simp [asBytes?]
      · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vBytes b) (.vOpaque a) rest_top hBO]
        simp [asBytes?]
      · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vOpaque b) (.vBytes a) rest_top hOB]
        simp [asBytes?]
      · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vOpaque b) (.vOpaque a) rest_top hOO]
        simp [asBytes?]
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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyEqualVerifyFuse rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyEqualVerifyFuse rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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

/-! F1 decidability — same `Bool`-mirror pattern as `wellTypedRun`. The
`if isOpEqual op then …` head check decides via the existing
`precondMet` Decidable instance, and the `∀ s'` tail collapses on
`stepNonIf`'s functional result. -/

def equalVerifyFuse_eitherStrictBool : List StackOp → StackState → Bool
  | [], _ => true
  | op :: rest, s =>
      (if isOpEqual op
        then decide (precondMet .twoInts s ∨ precondMet .twoBytes s)
        else true) &&
      (match stepNonIf op s with
       | .ok s' => equalVerifyFuse_eitherStrictBool rest s'
       | .error _ => true)

theorem equalVerifyFuse_eitherStrictBool_iff :
    ∀ (ops : List StackOp) (s : StackState),
      equalVerifyFuse_eitherStrictBool ops s = true ↔
        equalVerifyFuse_eitherStrict ops s
  | [], _ => by simp [equalVerifyFuse_eitherStrictBool, equalVerifyFuse_eitherStrict]
  | op :: rest, s => by
    unfold equalVerifyFuse_eitherStrictBool equalVerifyFuse_eitherStrict
    constructor
    · intro h
      rw [Bool.and_eq_true] at h
      obtain ⟨hHead, hRest⟩ := h
      refine ⟨?_, ?_⟩
      · by_cases hEq : isOpEqual op
        · rw [if_pos hEq] at hHead ⊢
          exact of_decide_eq_true hHead
        · rw [if_neg hEq]; trivial
      · intro s' hStep
        have : equalVerifyFuse_eitherStrictBool rest s' = true := by
          rw [hStep] at hRest; exact hRest
        exact (equalVerifyFuse_eitherStrictBool_iff rest s').mp this
    · intro ⟨hHead, hStep⟩
      rw [Bool.and_eq_true]
      refine ⟨?_, ?_⟩
      · by_cases hEq : isOpEqual op
        · rw [if_pos hEq] at hHead ⊢
          exact decide_eq_true hHead
        · rw [if_neg hEq]
      · cases hRes : stepNonIf op s with
        | error _ => rfl
        | ok s' =>
            have := hStep s' hRes
            exact (equalVerifyFuse_eitherStrictBool_iff rest s').mpr this

instance equalVerifyFuse_eitherStrict_decidable
    (ops : List StackOp) (s : StackState) :
    Decidable (equalVerifyFuse_eitherStrict ops s) :=
  decidable_of_iff (equalVerifyFuse_eitherStrictBool ops s = true)
    (equalVerifyFuse_eitherStrictBool_iff ops s)

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
          simp [asBytes?]
        · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vBytes b) (.vOpaque a) rest_top hBO]
          simp [asBytes?]
        · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vOpaque b) (.vBytes a) rest_top hOB]
          simp [asBytes?]
        · rw [runOpcode_EQUALVERIFY_def, popN_two_cons s (.vOpaque b) (.vOpaque a) rest_top hOO]
          simp [asBytes?]
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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyEqualVerifyFuse rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyEqualVerifyFuse rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

/-! ## Phase 3u — additional 2-op rules from `peephole.ts`

This section ports four additional 2-op peephole rules from
`packages/runar-compiler/src/optimizer/peephole.ts` to Lean and proves
each one's `_pass_sound` theorem under the established recipe.

* `oneSub`        — `[push 1, OP_SUB] → [OP_1SUB]`        (mirrors `oneAdd`)
* `doubleOver`    — `[over, over]    → [OP_2DUP]`         (twoElems precond)
* `doubleDrop`    — `[drop, drop]    → [OP_2DROP]`        (twoElems precond)
* `zeroNumEqual`  — `[push 0, OP_NUMEQUAL] → [OP_NOT]`    (bigint precond)

The 3-op constant folds (`pushPushAdd`/`pushPushSub`/`pushPushMul`)
follow this section. The previously-deferred `checkMultiSigVerifyFuse`
rule is landed in the **Phase 3z-B** section below
`pushPushMul_pass_sound`, after the backing `Stack/Eval.lean` extension
(`OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` semantics). The 5
roll/pick depth simplifications are single-op rewrites on the bundled
`.roll d` / `.pick d` ops — see `rollPickRewriteOne` and the Phase 7.9.d
section.
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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyOneSub rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyOneSub rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyDoubleOver rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyDoubleOver rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyDoubleDrop rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyDoubleDrop rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyZeroNumEqual rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyZeroNumEqual rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyPushPushAdd rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyPushPushAdd rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyPushPushSub rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyPushPushSub rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyPushPushMul rest') s = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyPushPushMul rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

/-! ## Phase 7.9.b — 4-op chain folding (TS reference `peephole.ts:402-432`)

These rules collapse two adjacent `[push, OP_ADD]` (resp. `OP_SUB`) pairs
into a single fused push + opcode:

* `[push a, OP_ADD, push b, OP_ADD] → [push (a + b), OP_ADD]`
* `[push a, OP_SUB, push b, OP_SUB] → [push (a + b), OP_SUB]`

They mirror `chainAdd` / `chainSub` in the TS reference (the `windowSize:
4` rules at the bottom of `optimizer/peephole.ts`). The 3-op
`pushPushAdd` / `pushPushSub` rules above only fire when the two
constants are syntactically adjacent on the input stack; the chain rules
fire when the constants are separated by an `OP_ADD` / `OP_SUB` arity-2
opcode whose left input is whatever is below the first pushed constant.

The chain pattern shows up heavily in EC scalar-mul codegen (`k + n + n
+ n` style rebasing in `cEmitMul` for secp256k1, P-256, and P-384) — see
`compilers/.../ec-codegen.ts` and `p256-p384-codegen.ts`. Without these
rules the Lean port emits one push per addend instead of one push of the
sum, producing 654-byte divergences vs the TS reference on the
`p256-primitives`, `p256-wallet`, and (likely) `p384-*` fixtures.

These rules are byte-equivalence-only mirrors of the TS reference and
are NOT included in the proven `peepholePassFullPlus_sound` 12-rule
chain (nor in `passAllInner15`). They live in `peepholePassAllFlat` so
the byte-exact pipelineGolden check picks them up. Adding them is
purely subtractive on the trust surface — no new axioms, no new opaque
defs.
-/

/-- 4-op chain fold: `[push a, OP_ADD, push b, OP_ADD] → [push (a + b),
OP_ADD]`. -/
def applyPushAddPushAdd : List StackOp → List StackOp
  | [] => []
  | .push (.bigint a) :: .opcode "OP_ADD" ::
    .push (.bigint b) :: .opcode "OP_ADD" :: rest =>
      .push (.bigint (a + b)) :: .opcode "OP_ADD" :: applyPushAddPushAdd rest
  | op :: rest => op :: applyPushAddPushAdd rest

theorem applyPushAddPushAdd_empty : applyPushAddPushAdd [] = [] := rfl

/-- 4-op chain fold: `[push a, OP_SUB, push b, OP_SUB] → [push (a + b),
OP_SUB]`. The constants accumulate as a SUM (not a difference) because
both subtractions remove their respective constants from the same below-
value: `(x - a) - b = x - (a + b)`. -/
def applyPushAddPushSub : List StackOp → List StackOp
  | [] => []
  | .push (.bigint a) :: .opcode "OP_SUB" ::
    .push (.bigint b) :: .opcode "OP_SUB" :: rest =>
      .push (.bigint (a + b)) :: .opcode "OP_SUB" :: applyPushAddPushSub rest
  | op :: rest => op :: applyPushAddPushSub rest

theorem applyPushAddPushSub_empty : applyPushAddPushSub [] = [] := rfl

/-! ## Phase 3z-B — 6 deferred peephole rules from `peephole.ts`

The previously-deferred 6 rules from Phase 3v (per HANDOFF.md §"Phase 3u
— Phase 3v deferred peephole rules") are landed here:

1. `checkMultiSigVerifyFuse` — `[OP_CHECKMULTISIG, OP_VERIFY] →
   [OP_CHECKMULTISIGVERIFY]`. Path A: `Stack/Eval.lean` was extended with
   abstract single-pop semantics for both opcodes (mirroring the existing
   `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` pair) so the fusion's `runOps LHS
   = runOps RHS` shape becomes provable. The semantics use
   `checkMultiSigStub : ByteArray → Bool` as a local adapter into the
   explicit auth backend.

2-6. roll/pick depth simplifications — the bundled `.roll d` / `.pick d`
   ops fold directly to their byte-equivalent specialised opcodes
   (`.roll 0 → []`, `.roll 1 → .swap`, `.roll 2 → .rot`,
   `.pick 0 → .dup`, `.pick 1 → .over`) via `rollPickRewriteOne`. Under
   the corrected no-pop `applyRoll`/`applyPick` evaluator semantics each
   rewrite is exactly `runOps`-preserving given `s.stack.length ≥ d + 1`
   at the firing position (`rollPickRewriteOne_runOps_eq`).

The `checkMultiSigVerifyFuse` rule follows the standard `wellTypedRun`
recipe (`.bytes` precondition on the multi-sig opcode entry).
-/

/-! ### `checkMultiSigVerifyFuse_pass_sound` — Phase 3z-B (Path A)

`[OP_CHECKMULTISIG, OP_VERIFY] → [OP_CHECKMULTISIGVERIFY]` under
`.bytes`-on-top precondition. The opcode semantics (in `Stack/Eval.lean`)
mirror `OP_CHECKSIG`'s single-pop abstraction with `checkMultiSigStub`
in place of parsed multisig stack operands. -/

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

theorem runOpcode_CHECKMULTISIG_bytes
    (s : StackState) (b : ByteArray) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBytes b :: rest_top ∨ s.stack = .vOpaque b :: rest_top) :
    runOpcode "OP_CHECKMULTISIG" s
    = .ok (({ s with stack := rest_top } : StackState).push
        (.vBool (checkMultiSigStub b))) := by
  unfold runOpcode runCheckMultiSig runCheckMultiSigFallback
  unfold StackState.pop?
  rcases hs with hB | hO
  · rw [hB]
    simp [asNonNegativeNat?, asInt?, asBytes?]
  · rw [hO]
    simp [asNonNegativeNat?, asInt?, asBytes?]

theorem runOpcode_CHECKMULTISIGVERIFY_bytes
    (s : StackState) (b : ByteArray) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBytes b :: rest_top ∨ s.stack = .vOpaque b :: rest_top) :
    runOpcode "OP_CHECKMULTISIGVERIFY" s
    = if checkMultiSigStub b then
        .ok ({ s with stack := rest_top } : StackState)
      else
        .error .assertFailed := by
  unfold runOpcode runCheckMultiSig runCheckMultiSigFallback
  unfold StackState.pop?
  rcases hs with hB | hO
  · rw [hB]
    simp [asNonNegativeNat?, asInt?, asBytes?]
  · rw [hO]
    simp [asNonNegativeNat?, asInt?, asBytes?]

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
            exact runOpcode_CHECKMULTISIG_bytes s b rest_top (Or.inl hB)]
    show runOps (.opcode "OP_VERIFY" :: rest)
          ((({ s with stack := rest_top } : StackState).push
            (.vBool (checkMultiSigStub b)))) = _
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKMULTISIGVERIFY" s
          = (if checkMultiSigStub b then
              .ok ({ s with stack := rest_top } : StackState)
             else .error .assertFailed) from by
            exact runOpcode_CHECKMULTISIGVERIFY_bytes s b rest_top (Or.inl hB)]
  · rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKMULTISIG" s
          = .ok (({ s with stack := rest_top } : StackState).push
                  (.vBool (checkMultiSigStub b))) from by
            exact runOpcode_CHECKMULTISIG_bytes s b rest_top (Or.inr hO)]
    show runOps (.opcode "OP_VERIFY" :: rest)
          ((({ s with stack := rest_top } : StackState).push
            (.vBool (checkMultiSigStub b)))) = _
    rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_verify_vBool]
    rw [runOps_cons_opcode_eq, stepNonIf_opcode]
    rw [show runOpcode "OP_CHECKMULTISIGVERIFY" s
          = (if checkMultiSigStub b then
              .ok ({ s with stack := rest_top } : StackState)
             else .error .assertFailed) from by
            exact runOpcode_CHECKMULTISIGVERIFY_bytes s b rest_top (Or.inr hO)]

/-- Reduce stepNonIf OP_CHECKMULTISIG on bytes-mixed top to a uniform shape. -/
private theorem stepNonIf_OPCHECKMULTISIG_anyBytes
    (s : StackState) (b : ByteArray) (rest_top : List ANF.Eval.Value)
    (hs : s.stack = .vBytes b :: rest_top ∨ s.stack = .vOpaque b :: rest_top) :
    stepNonIf (.opcode "OP_CHECKMULTISIG") s
    = .ok ((({ s with stack := rest_top } : StackState).push
              (.vBool (checkMultiSigStub b)))) := by
  rw [stepNonIf_opcode]
  exact runOpcode_CHECKMULTISIG_bytes s b rest_top hs

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
      rw [stepNonIf_opcode]
      exact runOpcode_CHECKMULTISIGVERIFY_bytes s b rest_top hStack
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
    | .pickStruct d =>
        show runOps (.pickStruct d :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.pickStruct d :: rest') s
        exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
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
    | .rawBytes b =>
        show runOps (.rawBytes b :: applyCheckMultiSigVerifyFuse rest') s
             = runOps (.rawBytes b :: rest') s
        exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

/-! ### Roll/Pick combinator rules

The Lean stack lowerer emits a *bare* bundled `.roll d` / `.pick d` op,
never the TS-shaped `[push d, .roll d]` 2-op pair. The 5 roll/pick depth
simplifications are therefore expressed as single-op rewrites in
`rollPickRewriteOne` (further below), whose `runOps` soundness is
`rollPickRewriteOne_runOps_eq`. The earlier `zeroRoll0` / `oneRoll1` /
`twoRoll2` / `zeroPick0` / `onePick1` 2-op-pair rewrites — a workaround
for the previous bytecode-style `applyRoll`/`applyPick` that popped a
runtime depth literal — were removed when the evaluator was corrected to
treat the bundled `.roll d` / `.pick d` ops as no-pop structural
operations (see `Stack/Eval.lean`).
-/

/-! #### Definitional reduction lemmas for `.roll` / `.pick` -/

/-- `stepNonIf .roll d s = applyRoll s d` (definitional). -/
private theorem stepNonIf_roll_def (s : StackState) (d : Nat) :
    stepNonIf (.roll d) s = applyRoll s d := rfl

/-- `stepNonIf .pick d s = applyPick s d` (definitional). -/
private theorem stepNonIf_pick_def (s : StackState) (d : Nat) :
    stepNonIf (.pick d) s = applyPick s d := rfl

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

/-! ## Tail-recursive runtime implementations (Phase 4-D)

The structural-recursive `apply*` definitions above keep their auto-generated
`.eq_*` and `.induct` equation lemmas — which the soundness proofs in this
file directly reference — but they are NOT tail-recursive. The
non-tail recursive `op :: applyXxx rest` form builds `cons` frames on
the way back up the call stack, which overflows the Lean interpreter's
per-thread stack on op lists with tens of thousands of entries (e.g.
SHA-256 partial-block codegen produces ~70K-op lists).

We provide a tail-recursive runtime twin for each `apply*` rule and
attach it via `@[implemented_by]`. Both compiled native code AND the
Lean bytecode interpreter (`lean --run`) use the TR implementation,
while definitional unfolding, `simp`, and proof-side reasoning still
see the original structural definition. The TR implementations are
provably equal to the originals, but we don't need the equality at the
proof level — only at runtime.

Each TR shadow uses the standard accumulator-then-reverse pattern:
walk the input list with a tail call, prepending to an accumulator,
and reverse the accumulator on the empty tail.

These shadows are placed BEFORE `peepholePassAllFlat` (and any caller
of the rules) so that when the compiler emits C code for the chain, it
substitutes the TR implementation at each call site. Placing the
attribute declarations after `peepholePassAllFlat` would leave the
already-emitted C code calling the structural-recursive original. -/

private def applyDropAfterPush.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | (.push _) :: .drop :: rest, acc => applyDropAfterPush.tr.go rest acc
  | op :: rest, acc => applyDropAfterPush.tr.go rest (op :: acc)

@[inline] private def applyDropAfterPush.tr (ops : List StackOp) : List StackOp :=
  applyDropAfterPush.tr.go ops []

attribute [implemented_by applyDropAfterPush.tr] applyDropAfterPush

private def applyDupDrop.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .dup :: .drop :: rest, acc => applyDupDrop.tr.go rest acc
  | op :: rest, acc => applyDupDrop.tr.go rest (op :: acc)

@[inline] private def applyDupDrop.tr (ops : List StackOp) : List StackOp :=
  applyDupDrop.tr.go ops []

attribute [implemented_by applyDupDrop.tr] applyDupDrop

private def applyDoubleSwap.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .swap :: .swap :: rest, acc => applyDoubleSwap.tr.go rest acc
  | op :: rest, acc => applyDoubleSwap.tr.go rest (op :: acc)

@[inline] private def applyDoubleSwap.tr (ops : List StackOp) : List StackOp :=
  applyDoubleSwap.tr.go ops []

attribute [implemented_by applyDoubleSwap.tr] applyDoubleSwap

private def applyEqualVerifyFuse.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .opcode "OP_EQUAL" :: .opcode "OP_VERIFY" :: rest, acc =>
      applyEqualVerifyFuse.tr.go rest (.opcode "OP_EQUALVERIFY" :: acc)
  | op :: rest, acc => applyEqualVerifyFuse.tr.go rest (op :: acc)

@[inline] private def applyEqualVerifyFuse.tr (ops : List StackOp) : List StackOp :=
  applyEqualVerifyFuse.tr.go ops []

attribute [implemented_by applyEqualVerifyFuse.tr] applyEqualVerifyFuse

private def applyCheckSigVerifyFuse.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .opcode "OP_CHECKSIG" :: .opcode "OP_VERIFY" :: rest, acc =>
      applyCheckSigVerifyFuse.tr.go rest (.opcode "OP_CHECKSIGVERIFY" :: acc)
  | op :: rest, acc => applyCheckSigVerifyFuse.tr.go rest (op :: acc)

@[inline] private def applyCheckSigVerifyFuse.tr (ops : List StackOp) : List StackOp :=
  applyCheckSigVerifyFuse.tr.go ops []

attribute [implemented_by applyCheckSigVerifyFuse.tr] applyCheckSigVerifyFuse

private def applyNumEqualVerifyFuse.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .opcode "OP_NUMEQUAL" :: .opcode "OP_VERIFY" :: rest, acc =>
      applyNumEqualVerifyFuse.tr.go rest (.opcode "OP_NUMEQUALVERIFY" :: acc)
  | op :: rest, acc => applyNumEqualVerifyFuse.tr.go rest (op :: acc)

@[inline] private def applyNumEqualVerifyFuse.tr (ops : List StackOp) : List StackOp :=
  applyNumEqualVerifyFuse.tr.go ops []

attribute [implemented_by applyNumEqualVerifyFuse.tr] applyNumEqualVerifyFuse

private def applyDoubleNot.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .opcode "OP_NOT" :: .opcode "OP_NOT" :: rest, acc => applyDoubleNot.tr.go rest acc
  | op :: rest, acc => applyDoubleNot.tr.go rest (op :: acc)

@[inline] private def applyDoubleNot.tr (ops : List StackOp) : List StackOp :=
  applyDoubleNot.tr.go ops []

attribute [implemented_by applyDoubleNot.tr] applyDoubleNot

private def applyDoubleNegate.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .opcode "OP_NEGATE" :: .opcode "OP_NEGATE" :: rest, acc => applyDoubleNegate.tr.go rest acc
  | op :: rest, acc => applyDoubleNegate.tr.go rest (op :: acc)

@[inline] private def applyDoubleNegate.tr (ops : List StackOp) : List StackOp :=
  applyDoubleNegate.tr.go ops []

attribute [implemented_by applyDoubleNegate.tr] applyDoubleNegate

private def applyAddZero.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .push (.bigint 0) :: .opcode "OP_ADD" :: rest, acc => applyAddZero.tr.go rest acc
  | op :: rest, acc => applyAddZero.tr.go rest (op :: acc)

@[inline] private def applyAddZero.tr (ops : List StackOp) : List StackOp :=
  applyAddZero.tr.go ops []

attribute [implemented_by applyAddZero.tr] applyAddZero

private def applyOneAdd.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .push (.bigint 1) :: .opcode "OP_ADD" :: rest, acc =>
      applyOneAdd.tr.go rest (.opcode "OP_1ADD" :: acc)
  | op :: rest, acc => applyOneAdd.tr.go rest (op :: acc)

@[inline] private def applyOneAdd.tr (ops : List StackOp) : List StackOp :=
  applyOneAdd.tr.go ops []

attribute [implemented_by applyOneAdd.tr] applyOneAdd

private def applySubZero.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .push (.bigint 0) :: .opcode "OP_SUB" :: rest, acc => applySubZero.tr.go rest acc
  | op :: rest, acc => applySubZero.tr.go rest (op :: acc)

@[inline] private def applySubZero.tr (ops : List StackOp) : List StackOp :=
  applySubZero.tr.go ops []

attribute [implemented_by applySubZero.tr] applySubZero

private def applyDoubleSha256.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .opcode "OP_SHA256" :: .opcode "OP_SHA256" :: rest, acc =>
      applyDoubleSha256.tr.go rest (.opcode "OP_HASH256" :: acc)
  | op :: rest, acc => applyDoubleSha256.tr.go rest (op :: acc)

@[inline] private def applyDoubleSha256.tr (ops : List StackOp) : List StackOp :=
  applyDoubleSha256.tr.go ops []

attribute [implemented_by applyDoubleSha256.tr] applyDoubleSha256

private def applyOneSub.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .push (.bigint 1) :: .opcode "OP_SUB" :: rest, acc =>
      applyOneSub.tr.go rest (.opcode "OP_1SUB" :: acc)
  | op :: rest, acc => applyOneSub.tr.go rest (op :: acc)

@[inline] private def applyOneSub.tr (ops : List StackOp) : List StackOp :=
  applyOneSub.tr.go ops []

attribute [implemented_by applyOneSub.tr] applyOneSub

private def applyDoubleOver.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .over :: .over :: rest, acc =>
      applyDoubleOver.tr.go rest (.opcode "OP_2DUP" :: acc)
  | op :: rest, acc => applyDoubleOver.tr.go rest (op :: acc)

@[inline] private def applyDoubleOver.tr (ops : List StackOp) : List StackOp :=
  applyDoubleOver.tr.go ops []

attribute [implemented_by applyDoubleOver.tr] applyDoubleOver

private def applyDoubleDrop.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .drop :: .drop :: rest, acc =>
      applyDoubleDrop.tr.go rest (.opcode "OP_2DROP" :: acc)
  | op :: rest, acc => applyDoubleDrop.tr.go rest (op :: acc)

@[inline] private def applyDoubleDrop.tr (ops : List StackOp) : List StackOp :=
  applyDoubleDrop.tr.go ops []

attribute [implemented_by applyDoubleDrop.tr] applyDoubleDrop

private def applyZeroNumEqual.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .push (.bigint 0) :: .opcode "OP_NUMEQUAL" :: rest, acc =>
      applyZeroNumEqual.tr.go rest (.opcode "OP_NOT" :: acc)
  | op :: rest, acc => applyZeroNumEqual.tr.go rest (op :: acc)

@[inline] private def applyZeroNumEqual.tr (ops : List StackOp) : List StackOp :=
  applyZeroNumEqual.tr.go ops []

attribute [implemented_by applyZeroNumEqual.tr] applyZeroNumEqual

private def applyPushPushAdd.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .push (.bigint a) :: .push (.bigint b) :: .opcode "OP_ADD" :: rest, acc =>
      applyPushPushAdd.tr.go rest (.push (.bigint (a + b)) :: acc)
  | op :: rest, acc => applyPushPushAdd.tr.go rest (op :: acc)

@[inline] private def applyPushPushAdd.tr (ops : List StackOp) : List StackOp :=
  applyPushPushAdd.tr.go ops []

attribute [implemented_by applyPushPushAdd.tr] applyPushPushAdd

private def applyPushPushSub.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .push (.bigint a) :: .push (.bigint b) :: .opcode "OP_SUB" :: rest, acc =>
      applyPushPushSub.tr.go rest (.push (.bigint (a - b)) :: acc)
  | op :: rest, acc => applyPushPushSub.tr.go rest (op :: acc)

@[inline] private def applyPushPushSub.tr (ops : List StackOp) : List StackOp :=
  applyPushPushSub.tr.go ops []

attribute [implemented_by applyPushPushSub.tr] applyPushPushSub

private def applyPushPushMul.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .push (.bigint a) :: .push (.bigint b) :: .opcode "OP_MUL" :: rest, acc =>
      applyPushPushMul.tr.go rest (.push (.bigint (a * b)) :: acc)
  | op :: rest, acc => applyPushPushMul.tr.go rest (op :: acc)

@[inline] private def applyPushPushMul.tr (ops : List StackOp) : List StackOp :=
  applyPushPushMul.tr.go ops []

attribute [implemented_by applyPushPushMul.tr] applyPushPushMul

private def applyPushAddPushAdd.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .push (.bigint a) :: .opcode "OP_ADD" ::
    .push (.bigint b) :: .opcode "OP_ADD" :: rest, acc =>
      applyPushAddPushAdd.tr.go rest
        (.opcode "OP_ADD" :: .push (.bigint (a + b)) :: acc)
  | op :: rest, acc => applyPushAddPushAdd.tr.go rest (op :: acc)

@[inline] private def applyPushAddPushAdd.tr (ops : List StackOp) : List StackOp :=
  applyPushAddPushAdd.tr.go ops []

attribute [implemented_by applyPushAddPushAdd.tr] applyPushAddPushAdd

private def applyPushAddPushSub.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .push (.bigint a) :: .opcode "OP_SUB" ::
    .push (.bigint b) :: .opcode "OP_SUB" :: rest, acc =>
      applyPushAddPushSub.tr.go rest
        (.opcode "OP_SUB" :: .push (.bigint (a + b)) :: acc)
  | op :: rest, acc => applyPushAddPushSub.tr.go rest (op :: acc)

@[inline] private def applyPushAddPushSub.tr (ops : List StackOp) : List StackOp :=
  applyPushAddPushSub.tr.go ops []

attribute [implemented_by applyPushAddPushSub.tr] applyPushAddPushSub

private def applyCheckMultiSigVerifyFuse.tr.go : List StackOp → List StackOp → List StackOp
  | [], acc => acc.reverse
  | .opcode "OP_CHECKMULTISIG" :: .opcode "OP_VERIFY" :: rest, acc =>
      applyCheckMultiSigVerifyFuse.tr.go rest (.opcode "OP_CHECKMULTISIGVERIFY" :: acc)
  | op :: rest, acc => applyCheckMultiSigVerifyFuse.tr.go rest (op :: acc)

@[inline] private def applyCheckMultiSigVerifyFuse.tr (ops : List StackOp) : List StackOp :=
  applyCheckMultiSigVerifyFuse.tr.go ops []

attribute [implemented_by applyCheckMultiSigVerifyFuse.tr] applyCheckMultiSigVerifyFuse

/-! ## End of tail-recursive runtime implementations. -/

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
helper.

**Phase 7.9.c**: branch bodies are also passed through
`peepholePassAllFlat` in forward (left-to-right) order, matching the
TS reference. The previous code used the buggy `peepholePassAllTRgo`
streaming driver which fused pairs from the END of consecutive runs
rather than the head (causing e.g. `[drop, drop, drop]` inside a
chain-step then-branch to lower to `[drop, OP_2DROP]` instead of TS's
`[OP_2DROP, drop]`). -/
private def preprocessOp : StackOp → StackOp
  | .ifOp thn els =>
      let thn' := peepholePassAllFlat ((preprocessOpListReversedAux thn []).reverse)
      let els' : Option (List StackOp) :=
        match els with
        | some e => some (peepholePassAllFlat ((preprocessOpListReversedAux e []).reverse))
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

/-- Recursive peephole driver.

**Phase 7.9.c fix**: previously this used a tail-recursive `TRgo`
streaming driver that re-applied `peepholePassAllFlat` on each cons
of the (reversed) op list. That semantics is a *right-fold* — it
fuses pairs starting from the END of consecutive runs — which
diverges from the TS reference for odd-length runs. For example:

  TS  on `[drop, drop, drop, over, over]` → `[OP_2DROP, drop, OP_2DUP]`
  TRgo on the same                       → `[drop, OP_2DROP, OP_2DUP]`

(TS scans left-to-right once and pairs consecutive `drop` ops from
the head; TRgo, by re-running `peepholePassAllFlat` on each cons,
ends up pairing them from the tail.)

The fix is to apply `peepholePassAllFlat` ONCE to the
forward-ordered op list (after `.ifOp` branch preprocessing). Each
of the 19 `apply*` rules inside `peepholePassAllFlat` already does
its own left-to-right scan via the `op :: applyX rest` pattern; the
runtime is tail-recursive via the `[implemented_by ... .tr]`
attributes (see `applyDoubleDrop.tr` etc.), so stack depth remains
bounded even for ~100K-op fixtures.

`preprocessIfOps` (forward-order) handles the recursion into
`.ifOp` branches; the resulting list is fed to `peepholePassAllFlat`
in its natural left-to-right order. -/
def peepholePassAll (ops : List StackOp) : List StackOp :=
  peepholePassAllFlat (preprocessIfOps ops)

/-! ## Phase 7.1 — Post-pass: catch `[push N, OP_1ADD]` and
`[push N, OP_1SUB]` patterns left over after the streaming
`peepholePassAll` driver.

The streaming driver applies `applyOneAdd`/`applyOneSub` greedily
when each op is consed, sometimes folding `[push 1, OP_ADD]` to
`[OP_1ADD]` BEFORE the upcoming `[push N]` has been streamed in
to form a `[push N, push 1, OP_ADD]` triple that
`applyPushPushAdd` would have folded directly to `[push (N+1)]`.
This post-pass catches the missed consolidation: any
`[push N, OP_1ADD]` (resp. `OP_1SUB`) becomes `[push (N+1)]`
(resp. `[push (N-1)]`).

Recurses into `.ifOp` branches via `postFoldOp` (mutual). -/

mutual

private def postFoldOp : StackOp → StackOp
  | .ifOp thn els =>
      let thn' := applyPushOneSub (applyPushOneAdd (postFoldList thn))
      let els' : Option (List StackOp) :=
        match els with
        | some e => some (applyPushOneSub (applyPushOneAdd (postFoldList e)))
        | none   => none
      .ifOp thn' els'
  | other => other

private def postFoldList : List StackOp → List StackOp
  | [] => []
  | op :: rest => postFoldOp op :: postFoldList rest

end

/-- Apply the Phase 7.1 push+1ADD / push+1SUB consolidation pass
to `ops`, including recursive descent into `.ifOp` branches. -/
def peepholePostFold (ops : List StackOp) : List StackOp :=
  applyPushOneSub (applyPushOneAdd (postFoldList ops))

/-! ### Phase 7.1 post-fold operational soundness

The post-fold pass is part of the production peephole chain. On `noIfOp`
inputs, `postFoldList` is the identity, so the pass reduces to the two
flat consolidation rules `applyPushOneAdd` and `applyPushOneSub`. -/

private theorem pushOneAdd_extends (s : StackState) (a : Int)
    (rest : List StackOp) :
    runOps (.push (.bigint a) :: .opcode "OP_1ADD" :: rest) s
    = runOps (.push (.bigint (a + 1)) :: rest) s := by
  rw [runOps_cons_PUSHbigint]
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_1ADD_def]
  unfold liftIntUnary StackState.pop?
  simp [asInt?]
  rw [runOps_cons_PUSHbigint]
  cases s
  simp [StackState.push]

private theorem pushOneSub_extends (s : StackState) (a : Int)
    (rest : List StackOp) :
    runOps (.push (.bigint a) :: .opcode "OP_1SUB" :: rest) s
    = runOps (.push (.bigint (a - 1)) :: rest) s := by
  rw [runOps_cons_PUSHbigint]
  rw [runOps_cons_opcode_eq, stepNonIf_opcode, runOpcode_1SUB_def]
  unfold liftIntUnary StackState.pop?
  simp [asInt?]
  rw [runOps_cons_PUSHbigint]
  cases s
  simp [StackState.push]

private theorem applyPushOneAdd_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ a rt, op = .push (.bigint a) →
         rest = .opcode "OP_1ADD" :: rt → False) :
    applyPushOneAdd (op :: rest) = op :: applyPushOneAdd rest :=
  applyPushOneAdd.eq_3 op rest h

private theorem applyPushOneSub_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ a rt, op = .push (.bigint a) →
         rest = .opcode "OP_1SUB" :: rt → False) :
    applyPushOneSub (op :: rest) = op :: applyPushOneSub rest :=
  applyPushOneSub.eq_3 op rest h

theorem applyPushOneAdd_runOps_eq :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState),
        runOps (applyPushOneAdd ops) s = runOps ops s := by
  intro ops
  induction ops using applyPushOneAdd.induct with
  | case1 => intros _ _; rfl
  | case2 a rest' ih =>
    intro hNoIf s
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .opcode "OP_1ADD" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    rw [show applyPushOneAdd
              (.push (.bigint a) :: .opcode "OP_1ADD" :: rest')
            = .push (.bigint (a + 1)) :: applyPushOneAdd rest' from rfl]
    rw [pushOneAdd_extends s a rest']
    apply runOps_cons_push_cong_typed
    intro s' hStep
    have hStepDef :
        stepNonIf (.push (.bigint (a + 1))) s
          = .ok (s.push (.vBigint (a + 1))) :=
      stepNonIf_push_bigint s (a + 1)
    have hs' : s' = s.push (.vBigint (a + 1)) := by
      rw [hStepDef] at hStep
      exact ((Except.ok.injEq _ _).mp hStep).symm
    rw [hs']
    exact ih hRestNoIf _
  | case3 op rest' hNoMatch ih =>
    intro hNoIf s
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    rw [applyPushOneAdd_cons_no_match op rest' hNoMatch]
    cases op with
    | push v => exact runOps_cons_push_cong v _ _ s (fun s' => ih hRestNoIf s')
    | dup => exact runOps_cons_dup_cong _ _ s (fun s' => ih hRestNoIf s')
    | swap => exact runOps_cons_swap_cong _ _ s (fun s' => ih hRestNoIf s')
    | drop => exact runOps_cons_drop_cong _ _ s (fun s' => ih hRestNoIf s')
    | nip => exact runOps_cons_nip_cong _ _ s (fun s' => ih hRestNoIf s')
    | over => exact runOps_cons_over_cong _ _ s (fun s' => ih hRestNoIf s')
    | rot => exact runOps_cons_rot_cong _ _ s (fun s' => ih hRestNoIf s')
    | tuck => exact runOps_cons_tuck_cong _ _ s (fun s' => ih hRestNoIf s')
    | roll d => exact runOps_cons_roll_cong d _ _ s (fun s' => ih hRestNoIf s')
    | pick d => exact runOps_cons_pick_cong d _ _ s (fun s' => ih hRestNoIf s')
    | pickStruct d => exact runOps_cons_pickStruct_cong d _ _ s (fun s' => ih hRestNoIf s')
    | opcode code => exact runOps_cons_opcode_cong code _ _ s (fun s' => ih hRestNoIf s')
    | placeholder i n => exact runOps_cons_placeholder_cong i n _ _ s (fun s' => ih hRestNoIf s')
    | pushCodesepIndex => exact runOps_cons_pushCodesepIndex_cong _ _ s (fun s' => ih hRestNoIf s')
    | rawBytes b => exact runOps_cons_rawBytes_cong b _ _ s (fun s' => ih hRestNoIf s')
    | ifOp thn els => exact absurd hNoIf (by simp [noIfOp])

theorem applyPushOneSub_runOps_eq :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState),
        runOps (applyPushOneSub ops) s = runOps ops s := by
  intro ops
  induction ops using applyPushOneSub.induct with
  | case1 => intros _ _; rfl
  | case2 a rest' ih =>
    intro hNoIf s
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .opcode "OP_1SUB" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    rw [show applyPushOneSub
              (.push (.bigint a) :: .opcode "OP_1SUB" :: rest')
            = .push (.bigint (a - 1)) :: applyPushOneSub rest' from rfl]
    rw [pushOneSub_extends s a rest']
    apply runOps_cons_push_cong_typed
    intro s' hStep
    have hStepDef :
        stepNonIf (.push (.bigint (a - 1))) s
          = .ok (s.push (.vBigint (a - 1))) :=
      stepNonIf_push_bigint s (a - 1)
    have hs' : s' = s.push (.vBigint (a - 1)) := by
      rw [hStepDef] at hStep
      exact ((Except.ok.injEq _ _).mp hStep).symm
    rw [hs']
    exact ih hRestNoIf _
  | case3 op rest' hNoMatch ih =>
    intro hNoIf s
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    rw [applyPushOneSub_cons_no_match op rest' hNoMatch]
    cases op with
    | push v => exact runOps_cons_push_cong v _ _ s (fun s' => ih hRestNoIf s')
    | dup => exact runOps_cons_dup_cong _ _ s (fun s' => ih hRestNoIf s')
    | swap => exact runOps_cons_swap_cong _ _ s (fun s' => ih hRestNoIf s')
    | drop => exact runOps_cons_drop_cong _ _ s (fun s' => ih hRestNoIf s')
    | nip => exact runOps_cons_nip_cong _ _ s (fun s' => ih hRestNoIf s')
    | over => exact runOps_cons_over_cong _ _ s (fun s' => ih hRestNoIf s')
    | rot => exact runOps_cons_rot_cong _ _ s (fun s' => ih hRestNoIf s')
    | tuck => exact runOps_cons_tuck_cong _ _ s (fun s' => ih hRestNoIf s')
    | roll d => exact runOps_cons_roll_cong d _ _ s (fun s' => ih hRestNoIf s')
    | pick d => exact runOps_cons_pick_cong d _ _ s (fun s' => ih hRestNoIf s')
    | pickStruct d => exact runOps_cons_pickStruct_cong d _ _ s (fun s' => ih hRestNoIf s')
    | opcode code => exact runOps_cons_opcode_cong code _ _ s (fun s' => ih hRestNoIf s')
    | placeholder i n => exact runOps_cons_placeholder_cong i n _ _ s (fun s' => ih hRestNoIf s')
    | pushCodesepIndex => exact runOps_cons_pushCodesepIndex_cong _ _ s (fun s' => ih hRestNoIf s')
    | rawBytes b => exact runOps_cons_rawBytes_cong b _ _ s (fun s' => ih hRestNoIf s')
    | ifOp thn els => exact absurd hNoIf (by simp [noIfOp])

theorem applyPushOneAdd_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyPushOneAdd ops) := by
  intro ops
  induction ops using applyPushOneAdd.induct with
  | case1 => intro _; exact True.intro
  | case2 a rest' ih =>
    intro hNoIf
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .opcode "OP_1ADD" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    show noIfOp (.push (.bigint (a + 1)) :: applyPushOneAdd rest')
    exact ih hRestNoIf
  | case3 op rest' hNoMatch ih =>
    intro hNoIf
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    rw [applyPushOneAdd_cons_no_match op rest' hNoMatch]
    cases op with
    | push v => simpa [noIfOp] using ih hRestNoIf
    | dup => simpa [noIfOp] using ih hRestNoIf
    | swap => simpa [noIfOp] using ih hRestNoIf
    | drop => simpa [noIfOp] using ih hRestNoIf
    | nip => simpa [noIfOp] using ih hRestNoIf
    | over => simpa [noIfOp] using ih hRestNoIf
    | rot => simpa [noIfOp] using ih hRestNoIf
    | tuck => simpa [noIfOp] using ih hRestNoIf
    | roll d => simpa [noIfOp] using ih hRestNoIf
    | pick d => simpa [noIfOp] using ih hRestNoIf
    | pickStruct d => simpa [noIfOp] using ih hRestNoIf
    | opcode code => simpa [noIfOp] using ih hRestNoIf
    | placeholder i n => simpa [noIfOp] using ih hRestNoIf
    | pushCodesepIndex => simpa [noIfOp] using ih hRestNoIf
    | rawBytes b => simpa [noIfOp] using ih hRestNoIf
    | ifOp thn els => exact absurd hNoIf (by simp [noIfOp])

theorem applyPushOneSub_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyPushOneSub ops) := by
  intro ops
  induction ops using applyPushOneSub.induct with
  | case1 => intro _; exact True.intro
  | case2 a rest' ih =>
    intro hNoIf
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .opcode "OP_1SUB" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    show noIfOp (.push (.bigint (a - 1)) :: applyPushOneSub rest')
    exact ih hRestNoIf
  | case3 op rest' hNoMatch ih =>
    intro hNoIf
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    rw [applyPushOneSub_cons_no_match op rest' hNoMatch]
    cases op with
    | push v => simpa [noIfOp] using ih hRestNoIf
    | dup => simpa [noIfOp] using ih hRestNoIf
    | swap => simpa [noIfOp] using ih hRestNoIf
    | drop => simpa [noIfOp] using ih hRestNoIf
    | nip => simpa [noIfOp] using ih hRestNoIf
    | over => simpa [noIfOp] using ih hRestNoIf
    | rot => simpa [noIfOp] using ih hRestNoIf
    | tuck => simpa [noIfOp] using ih hRestNoIf
    | roll d => simpa [noIfOp] using ih hRestNoIf
    | pick d => simpa [noIfOp] using ih hRestNoIf
    | pickStruct d => simpa [noIfOp] using ih hRestNoIf
    | opcode code => simpa [noIfOp] using ih hRestNoIf
    | placeholder i n => simpa [noIfOp] using ih hRestNoIf
    | pushCodesepIndex => simpa [noIfOp] using ih hRestNoIf
    | rawBytes b => simpa [noIfOp] using ih hRestNoIf
    | ifOp thn els => exact absurd hNoIf (by simp [noIfOp])

private theorem postFoldOp_id_of_not_ifOp (op : StackOp)
    (h : ∀ thn els, op ≠ .ifOp thn els) :
    postFoldOp op = op := by
  cases op with
  | ifOp thn els => exact absurd rfl (h thn els)
  | push v => rfl
  | dup => rfl
  | swap => rfl
  | drop => rfl
  | nip => rfl
  | over => rfl
  | rot => rfl
  | tuck => rfl
  | roll d => rfl
  | pick d => rfl
  | pickStruct d => rfl
  | opcode code => rfl
  | placeholder i n => rfl
  | pushCodesepIndex => rfl
  | rawBytes b => rfl

private theorem postFoldList_eq_of_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → postFoldList ops = ops := by
  intro ops
  induction ops with
  | nil => intro _; rfl
  | cons op rest ih =>
    intro hNoIf
    have hRest : noIfOp rest := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hOp : postFoldOp op = op := by
      apply postFoldOp_id_of_not_ifOp
      intro thn els hEq
      rw [hEq] at hNoIf
      exact absurd hNoIf (by simp [noIfOp])
    unfold postFoldList
    rw [hOp, ih hRest]

theorem peepholePostFold_runOps_eq (ops : List StackOp) (s : StackState)
    (hNoIf : noIfOp ops) :
    runOps (peepholePostFold ops) s = runOps ops s := by
  unfold peepholePostFold
  rw [postFoldList_eq_of_noIfOp ops hNoIf]
  have hNoIfAdd : noIfOp (applyPushOneAdd ops) :=
    applyPushOneAdd_preserves_noIfOp ops hNoIf
  rw [applyPushOneSub_runOps_eq _ hNoIfAdd s]
  rw [applyPushOneAdd_runOps_eq ops hNoIf s]

theorem peepholePostFold_preserves_noIfOp
    (ops : List StackOp) (hNoIf : noIfOp ops) :
    noIfOp (peepholePostFold ops) := by
  unfold peepholePostFold
  rw [postFoldList_eq_of_noIfOp ops hNoIf]
  exact applyPushOneSub_preserves_noIfOp _
    (applyPushOneAdd_preserves_noIfOp ops hNoIf)

/-- `peepholePostFold` is the identity on the empty op list. Used by the
absent-method case of `Pipeline.peepholeProgram_bodyOf`. -/
theorem peepholePostFold_nil : peepholePostFold ([] : List StackOp) = [] := by
  unfold peepholePostFold
  rw [postFoldList_eq_of_noIfOp [] (by simp [noIfOp])]
  rfl

/-! ## Phase 7.9.b — Chain-fold post-pass

The 4-op `applyPushAddPushAdd` / `applyPushAddPushSub` rules added above
need a separate driver that:

1. Iterates the rule to fixpoint within a single op list. A 6-op chain
   `[push a, OP_ADD, push b, OP_ADD, push c, OP_ADD]` requires two
   passes (`a, b → a+b; (a+b), c → a+b+c`).
2. Recurses into `.ifOp` branches.

Rationale for keeping this separate from `peepholePassAllFlat`: the
existing `peepholePassAllFlat_sound` theorem unfolds the exact chain
shape and inserting two new wrappers would require updating the
theorem statement (which downstream callers shape-match on). A standalone
post-pass leaves the proven 19-rule chain untouched.

The pass is purely subtractive: it fires only on syntactically literal
4-op windows of the form `[push (.bigint a), OP_ADD, push (.bigint b),
OP_ADD]` (resp. `OP_SUB`); programs without such windows are returned
unchanged. -/

/-- Outer fixpoint iteration of `applyPushAddPushAdd` /
`applyPushAddPushSub` on a flat op list. Stops when the list length
stabilises (each successful firing strictly reduces length by 2, so
length-stability == fixpoint). The `fuel` parameter is a bounded loop;
in practice 32 passes are more than enough since the longest contiguous
`[push, OP_ADD]` chain in EC scalar-mul codegen is 3 (`k + n + n + n`),
which folds in 2 passes. We use 64 fuel for comfortable margin. -/
private def chainFoldFixpointFlat (fuel : Nat) (ops : List StackOp) :
    List StackOp :=
  match fuel with
  | 0 => ops
  | k + 1 =>
    let next := applyPushAddPushSub (applyPushAddPushAdd ops)
    if next.length = ops.length then ops else chainFoldFixpointFlat k next
termination_by fuel

mutual

/-- One step of the chain-fold post-pass: rewrite a single op,
descending recursively into `.ifOp` branches. Recursion depth = `.ifOp`
nesting level (small in practice). The outer list traversal is delegated
to `chainFoldListTR.go` (a tail-recursive accumulator-based walker). -/
private def chainFoldOp : StackOp → StackOp
  | .ifOp thn els =>
      let thn' := chainFoldFixpointFlat 64 (chainFoldListTRgo thn [])
      let els' : Option (List StackOp) :=
        match els with
        | some e => some (chainFoldFixpointFlat 64 (chainFoldListTRgo e []))
        | none   => none
      .ifOp thn' els'
  | other => other
termination_by op => sizeOf op

/-- Tail-recursive list traversal: walks `ops` and prepends
`chainFoldOp op` to `acc`. Returns the accumulator in REVERSE order — the
caller passes the result to `chainFoldFixpointFlat` which is
order-independent up to the final `.reverse`, so we reverse here once. -/
private def chainFoldListTRgo : List StackOp → List StackOp →
    List StackOp
  | [],         acc => acc.reverse
  | op :: rest, acc => chainFoldListTRgo rest (chainFoldOp op :: acc)
termination_by ops _ => sizeOf ops

end

/-- Apply the Phase 7.9.b chain-fold consolidation pass to `ops`,
including recursive descent into `.ifOp` branches and fixpoint iteration
of the chain-fold rules at every level.

Mirrors TS `peephole.ts:402-432` (`chainAdd` / `chainSub` 4-op rules)
which run inside the TS optimizer's outer fixpoint loop. -/
def peepholeChainFold (ops : List StackOp) : List StackOp :=
  chainFoldFixpointFlat 64 (chainFoldListTRgo ops [])

/-! ## Phase 7.9.d — Roll/Pick fold post-pass

The TS reference (`packages/runar-compiler/src/optimizer/peephole.ts`,
"Roll/Pick depth simplification" block) folds 5 push-N → opcode-X pairs
that the stack lowerer leaves behind:

* `[push 0, OP_ROLL]` → `[]`        (depth-0 roll is a no-op)
* `[push 1, OP_ROLL]` → `[OP_SWAP]` (depth-1 roll == swap)
* `[push 2, OP_ROLL]` → `[OP_ROT]`  (depth-2 roll == rot)
* `[push 0, OP_PICK]` → `[OP_DUP]`  (depth-0 pick == dup)
* `[push 1, OP_PICK]` → `[OP_OVER]` (depth-1 pick == over)

In the Lean port, `.roll d` and `.pick d` are SINGLE bundled Stack-IR ops
that `Emit.emitStackOp` encodes as the byte pair `encodePushBigInt d ++
[opcode]` (see `Script/Emit.lean`), and the no-pop evaluator
(`Stack/Eval.lean`) treats them as the *combined* effect of that pair: a
direct structural roll/pick at depth `d`. The Lean stack lowerer emits a
bare `.roll d` / `.pick d`, so the fold operates directly on the bundled
op via `rollPickRewriteOne`:

* `.roll 0` → `[]`     (depth-0 roll on a non-empty stack is the identity)
* `.roll 1` → `.swap`
* `.roll 2` → `.rot`
* `.pick 0` → `.dup`
* `.pick 1` → `.over`

Without this pass, sphincs-wallet and post-quantum-slhdsa diverge at
byte ~44858 / ~44846 where TS emits `OP_ROT` (`7b`) but the Lean port
leaves `.roll 2` (encoded as `52 7a`). The pattern originates in the
SLH-DSA WOTS+ chain codegen (`Stack/SlhDsa.lean:686`,
`Stack/SlhDsa.lean:436`, etc.). -/

/-- Single-op StackOp-level rewrite for `.roll 0/1/2` / `.pick 0/1`.
Mirrors the byte-equivalence:
  emit (.roll 0) = `00 7a` ≡ `nothing` (push-0 then OP_ROLL is the
                                        identity on a non-empty stack)
  emit (.roll 1) = `51 7a` ≡ emit .swap = `7c`
  emit (.roll 2) = `52 7a` ≡ emit .rot  = `7b`
  emit (.pick 0) = `00 79` ≡ emit .dup  = `76`
  emit (.pick 1) = `51 79` ≡ emit .over = `78`

`runOps` soundness of each rewrite is `rollPickRewriteOne_runOps_eq`. -/
private def rollPickRewriteOne : StackOp → List StackOp
  | .roll 0 => []
  | .roll 1 => [.swap]
  | .roll 2 => [.rot]
  | .pick 0 => [.dup]
  | .pick 1 => [.over]
  | other   => [other]

/-! Runtime soundness of the 5 single-op roll/pick rewrites.

Under the corrected no-pop `.roll d` / `.pick d` evaluator semantics
(`Stack/Eval.lean`), each bundled IR op rolls/picks at structural depth
`d` directly. The 5 rewrites are therefore exactly `runOps`-preserving
given enough stack depth at the firing position — proved by
`rollPickRewriteOne_runOps_eq` below. The general fixpoint-pass
soundness (`peepholeRollPickFold` over arbitrary lists, threading the
depth precondition) lands in M3 alongside the first-pass per-rule
soundness chain. -/

/-- Each single-op roll/pick rewrite preserves `runOps` behaviour, given
the byte-equivalent specialised opcode has enough operands at the firing
position. The depth precondition `s.stack.length ≥ d + 1` is exactly
what the bundled `.roll d` / `.pick d` op itself requires. -/
private theorem rollPickRewriteOne_runOps_eq
    (op : StackOp) (s : StackState) (rest : List StackOp)
    (hLen : ∀ d, (op = .roll d ∨ op = .pick d) → s.stack.length ≥ d + 1) :
    runOps (rollPickRewriteOne op ++ rest) s = runOps (op :: rest) s := by
  cases op with
  | roll d =>
    match d, hLen with
    | 0, hLen =>
      have h1 : s.stack.length ≥ 1 := hLen 0 (Or.inl rfl)
      rw [runOps_cons_roll_eq]
      show runOps rest s
        = (match stepNonIf (.roll 0) s with
           | .error e => .error e | .ok s' => runOps rest s')
      have hStep : stepNonIf (.roll 0) s = .ok s := by
        show applyRoll s 0 = .ok s
        cases s with
        | mk stack altstack outputs props preimage =>
          cases stack with
          | nil => simp at h1
          | cons a tl => simp [applyRoll]
      rw [hStep]
    | 1, hLen =>
      have h2 : s.stack.length ≥ 2 := hLen 1 (Or.inl rfl)
      show runOps (StackOp.swap :: rest) s = runOps (.roll 1 :: rest) s
      rw [runOps_cons_swap_eq, runOps_cons_roll_eq]
      have hEq : stepNonIf .swap s = stepNonIf (.roll 1) s := by
        show applySwap s = applyRoll s 1
        cases s with
        | mk stack altstack outputs props preimage =>
          match stack with
          | [] => simp at h2
          | [_] => simp at h2
          | a :: b :: tl => simp [applySwap, applyRoll]
      rw [hEq]
    | 2, hLen =>
      have h3 : s.stack.length ≥ 3 := hLen 2 (Or.inl rfl)
      show runOps (StackOp.rot :: rest) s = runOps (.roll 2 :: rest) s
      rw [runOps_cons_rot_eq, runOps_cons_roll_eq]
      have hEq : stepNonIf .rot s = stepNonIf (.roll 2) s := by
        show applyRot s = applyRoll s 2
        cases s with
        | mk stack altstack outputs props preimage =>
          match stack with
          | [] => simp at h3
          | [_] => simp at h3
          | [_, _] => simp at h3
          | a :: b :: c :: tl => simp [applyRot, applyRoll]
      rw [hEq]
    | (d + 3), _ => rfl
  | pick d =>
    match d, hLen with
    | 0, hLen =>
      have h1 : s.stack.length ≥ 1 := hLen 0 (Or.inr rfl)
      show runOps (StackOp.dup :: rest) s = runOps (.pick 0 :: rest) s
      rw [runOps_cons_dup_eq, runOps_cons_pick_eq]
      have hEq : stepNonIf .dup s = stepNonIf (.pick 0) s := by
        show applyDup s = applyPick s 0
        cases s with
        | mk stack altstack outputs props preimage =>
          cases stack with
          | nil => simp at h1
          | cons a tl => simp [applyDup, applyPick, StackState.push]
      rw [hEq]
    | 1, hLen =>
      have h2 : s.stack.length ≥ 2 := hLen 1 (Or.inr rfl)
      show runOps (StackOp.over :: rest) s = runOps (.pick 1 :: rest) s
      rw [runOps_cons_over_eq, runOps_cons_pick_eq]
      have hEq : stepNonIf .over s = stepNonIf (.pick 1) s := by
        show applyOver s = applyPick s 1
        cases s with
        | mk stack altstack outputs props preimage =>
          match stack with
          | [] => simp at h2
          | [_] => simp at h2
          | a :: b :: tl => simp [applyOver, applyPick, StackState.push]
      rw [hEq]
    | (d + 2), _ => rfl
  | _ => rfl

/-- One pass of the 5 roll/pick rewrites over a flat op list.
Walks left-to-right via structural recursion. Note: rewrites do not
introduce new fold opportunities (each output is itself a
non-roll/pick op or empty), so this single pass is already at fixpoint
for these rules — the outer `rollPickFixpointFlat` loop is purely
defensive against future additions. -/
private def applyRollPickFold : List StackOp → List StackOp
  | []          => []
  | op :: rest  => rollPickRewriteOne op ++ applyRollPickFold rest

/-- Outer driver for `applyRollPickFold`. Since `applyRollPickFold` is
idempotent (its outputs `[]`, `[.swap]`, `[.rot]`, `[.dup]`, `[.over]`
are not themselves roll/pick ops, so re-applying changes nothing), a
single pass suffices. The `fuel` argument is unused and retained for
API stability. -/
private def rollPickFixpointFlat (_fuel : Nat) (ops : List StackOp) :
    List StackOp :=
  applyRollPickFold ops

mutual

/-- One step of the roll/pick post-pass: rewrite a single op, descending
recursively into `.ifOp` branches. Recursion depth = `.ifOp` nesting
(small). The outer list traversal is delegated to `rollPickListTRgo`. -/
private def rollPickOp : StackOp → StackOp
  | .ifOp thn els =>
      let thn' := rollPickFixpointFlat 64 (rollPickListTRgo thn [])
      let els' : Option (List StackOp) :=
        match els with
        | some e => some (rollPickFixpointFlat 64 (rollPickListTRgo e []))
        | none   => none
      .ifOp thn' els'
  | other => other

/-- Tail-recursive list traversal: walks `ops` and prepends `rollPickOp op`
to `acc`. Returns the accumulator in REVERSE order — caller hands the
result to `rollPickFixpointFlat` (order-independent up to the final
`.reverse` already done here). -/
private def rollPickListTRgo : List StackOp → List StackOp →
    List StackOp
  | [],         acc => acc.reverse
  | op :: rest, acc => rollPickListTRgo rest (rollPickOp op :: acc)

end

/-- Apply the Phase 7.9.d roll/pick fold consolidation pass to `ops`,
including recursive descent into `.ifOp` branches and fixpoint iteration
of the 5 roll/pick rules at every level.

Mirrors TS `peephole.ts:268-317` (Roll/Pick depth simplification block)
which runs inside the TS optimizer's outer fixpoint loop. -/
def peepholeRollPickFold (ops : List StackOp) : List StackOp :=
  rollPickFixpointFlat 64 (rollPickListTRgo ops [])

/-- A singleton roll/pick op folds through `peepholeRollPickFold` to
exactly `rollPickRewriteOne` applied to that op. -/
private theorem peepholeRollPickFold_singleton_eq (op : StackOp) :
    peepholeRollPickFold [op] = rollPickRewriteOne (rollPickOp op) := by
  simp [peepholeRollPickFold, rollPickFixpointFlat, rollPickListTRgo,
    applyRollPickFold]

/-- Fired `.roll 0` fold: under no-pop `.roll` semantics, the bundled
`.roll 0` op folds to `[]` with identical `runOps` behaviour. -/
theorem peepholeRollPickFold_singleton_roll0_runOps_eq
    (s : StackState) (rest : List StackOp) (hLen : s.stack.length ≥ 1) :
    runOps (peepholeRollPickFold [.roll 0] ++ rest) s
      = runOps (.roll 0 :: rest) s := by
  rw [peepholeRollPickFold_singleton_eq]
  exact rollPickRewriteOne_runOps_eq (.roll 0) s rest
    (fun d hd => by rcases hd with h | h
                    · injection h with h'; omega
                    · exact absurd h (by simp))

/-- Fired `.roll 1` fold: `.roll 1` folds to `[.swap]`. -/
theorem peepholeRollPickFold_singleton_roll1_runOps_eq
    (s : StackState) (rest : List StackOp) (hLen : s.stack.length ≥ 2) :
    runOps (peepholeRollPickFold [.roll 1] ++ rest) s
      = runOps (.roll 1 :: rest) s := by
  rw [peepholeRollPickFold_singleton_eq]
  exact rollPickRewriteOne_runOps_eq (.roll 1) s rest
    (fun d hd => by rcases hd with h | h
                    · injection h with h'; omega
                    · exact absurd h (by simp))

/-- Fired `.roll 2` fold: `.roll 2` folds to `[.rot]`. -/
theorem peepholeRollPickFold_singleton_roll2_runOps_eq
    (s : StackState) (rest : List StackOp) (hLen : s.stack.length ≥ 3) :
    runOps (peepholeRollPickFold [.roll 2] ++ rest) s
      = runOps (.roll 2 :: rest) s := by
  rw [peepholeRollPickFold_singleton_eq]
  exact rollPickRewriteOne_runOps_eq (.roll 2) s rest
    (fun d hd => by rcases hd with h | h
                    · injection h with h'; omega
                    · exact absurd h (by simp))

/-- Fired `.pick 0` fold: `.pick 0` folds to `[.dup]`. -/
theorem peepholeRollPickFold_singleton_pick0_runOps_eq
    (s : StackState) (rest : List StackOp) (hLen : s.stack.length ≥ 1) :
    runOps (peepholeRollPickFold [.pick 0] ++ rest) s
      = runOps (.pick 0 :: rest) s := by
  rw [peepholeRollPickFold_singleton_eq]
  exact rollPickRewriteOne_runOps_eq (.pick 0) s rest
    (fun d hd => by rcases hd with h | h
                    · exact absurd h (by simp)
                    · injection h with h'; omega)

/-- Fired `.pick 1` fold: `.pick 1` folds to `[.over]`. -/
theorem peepholeRollPickFold_singleton_pick1_runOps_eq
    (s : StackState) (rest : List StackOp) (hLen : s.stack.length ≥ 2) :
    runOps (peepholeRollPickFold [.pick 1] ++ rest) s
      = runOps (.pick 1 :: rest) s := by
  rw [peepholeRollPickFold_singleton_eq]
  exact rollPickRewriteOne_runOps_eq (.pick 1) s rest
    (fun d hd => by rcases hd with h | h
                    · exact absurd h (by simp)
                    · injection h with h'; omega)

/-! ### Phase 7.9.d bounded identity slice

This slice captures the case where `applyRollPickFold` has no flat
rewrite to perform — the post-chain op list contains none of the five
foldable low-depth roll/pick heads — so the pass is the identity. The
general fired-rewrite soundness is `rollPickRewriteOne_runOps_eq` above;
the full fixpoint-pass `runOps` soundness lands in M3. -/

/-- True when a single op is not one of the five flat roll/pick fold heads. -/
def rollPickFoldOpNoop : StackOp → Prop
  | .roll 0 => False
  | .roll 1 => False
  | .roll 2 => False
  | .pick 0 => False
  | .pick 1 => False
  | _       => True

/-- True when `applyRollPickFold` has no flat rewrite to perform. -/
def rollPickFoldFlatNoop (ops : List StackOp) : Prop :=
  ∀ op, op ∈ ops → rollPickFoldOpNoop op

private theorem rollPickRewriteOne_eq_singleton_of_opNoop
    (op : StackOp) (h : rollPickFoldOpNoop op) :
    rollPickRewriteOne op = [op] := by
  cases op with
  | push v => rfl
  | dup => rfl
  | swap => rfl
  | drop => rfl
  | nip => rfl
  | over => rfl
  | rot => rfl
  | tuck => rfl
  | roll d =>
      cases d with
      | zero => exact False.elim h
      | succ d1 =>
          cases d1 with
          | zero => exact False.elim h
          | succ d2 =>
              cases d2 with
              | zero => exact False.elim h
              | succ _ => rfl
  | pick d =>
      cases d with
      | zero => exact False.elim h
      | succ d1 =>
          cases d1 with
          | zero => exact False.elim h
          | succ _ => rfl
  | pickStruct d => rfl
  | opcode code => rfl
  | placeholder i n => rfl
  | pushCodesepIndex => rfl
  | rawBytes b => rfl
  | ifOp thn els => rfl

private theorem applyRollPickFold_eq_self_of_flatNoop :
    ∀ (ops : List StackOp), rollPickFoldFlatNoop ops →
        applyRollPickFold ops = ops := by
  intro ops
  induction ops with
  | nil =>
      intro _
      rfl
  | cons op rest ih =>
      intro hNoop
      have hOp : rollPickRewriteOne op = [op] :=
        rollPickRewriteOne_eq_singleton_of_opNoop op
          (hNoop op (by simp))
      have hRest : rollPickFoldFlatNoop rest := by
        intro op' hMem
        exact hNoop op' (by simp [hMem])
      unfold applyRollPickFold
      rw [hOp, ih hRest]
      simp

theorem applyRollPickFold_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyRollPickFold ops) := by
  intro ops
  induction ops with
  | nil =>
      intro _
      exact True.intro
  | cons op rest ih =>
      intro hNoIf
      have hRest : noIfOp rest := by
        cases op with
        | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
        | _ => simpa [noIfOp] using hNoIf
      unfold applyRollPickFold
      cases op with
      | push v => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | dup => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | swap => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | drop => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | nip => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | over => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | rot => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | tuck => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | roll d =>
          cases d with
          | zero => simpa [rollPickRewriteOne, noIfOp] using ih hRest
          | succ d1 =>
              cases d1 with
              | zero => simpa [rollPickRewriteOne, noIfOp] using ih hRest
              | succ d2 =>
                  cases d2 with
                  | zero => simpa [rollPickRewriteOne, noIfOp] using ih hRest
                  | succ _ => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | pick d =>
          cases d with
          | zero => simpa [rollPickRewriteOne, noIfOp] using ih hRest
          | succ d1 =>
              cases d1 with
              | zero => simpa [rollPickRewriteOne, noIfOp] using ih hRest
              | succ _ => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | pickStruct d => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | opcode code => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | placeholder i n => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | pushCodesepIndex => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | rawBytes b => simpa [rollPickRewriteOne, noIfOp] using ih hRest
      | ifOp thn els => exact absurd hNoIf (by simp [noIfOp])

private theorem rollPickOp_id_of_not_ifOp (op : StackOp)
    (h : ∀ thn els, op ≠ .ifOp thn els) :
    rollPickOp op = op := by
  cases op with
  | ifOp thn els => exact absurd rfl (h thn els)
  | push v => rfl
  | dup => rfl
  | swap => rfl
  | drop => rfl
  | nip => rfl
  | over => rfl
  | rot => rfl
  | tuck => rfl
  | roll d => rfl
  | pick d => rfl
  | pickStruct d => rfl
  | opcode code => rfl
  | placeholder i n => rfl
  | pushCodesepIndex => rfl
  | rawBytes b => rfl

private theorem rollPickListTRgo_eq_of_noIfOp :
    ∀ (ops : List StackOp) (acc : List StackOp), noIfOp ops →
        rollPickListTRgo ops acc = acc.reverse ++ ops := by
  intro ops
  induction ops with
  | nil =>
      intro acc _
      show rollPickListTRgo [] acc = acc.reverse ++ []
      unfold rollPickListTRgo
      simp
  | cons op rest ih =>
      intro acc hNoIf
      have hRest : noIfOp rest := by
        cases op with
        | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
        | _ => simpa [noIfOp] using hNoIf
      have hOpId : rollPickOp op = op := by
        apply rollPickOp_id_of_not_ifOp
        intro thn els hEq
        rw [hEq] at hNoIf
        exact absurd hNoIf (by simp [noIfOp])
      show rollPickListTRgo (op :: rest) acc = acc.reverse ++ (op :: rest)
      unfold rollPickListTRgo
      rw [hOpId]
      have ihAcc := ih (op :: acc) hRest
      rw [ihAcc]
      simp

private theorem rollPickListTRgo_nil_acc_of_noIfOp
    (ops : List StackOp) (h : noIfOp ops) :
    rollPickListTRgo ops [] = ops := by
  rw [rollPickListTRgo_eq_of_noIfOp ops [] h]
  simp

theorem peepholeRollPickFold_eq_self_of_noIfOp_flatNoop
    (ops : List StackOp) (hNoIf : noIfOp ops)
    (hNoop : rollPickFoldFlatNoop ops) :
    peepholeRollPickFold ops = ops := by
  unfold peepholeRollPickFold
  rw [rollPickListTRgo_nil_acc_of_noIfOp ops hNoIf]
  show rollPickFixpointFlat 64 ops = ops
  unfold rollPickFixpointFlat
  exact applyRollPickFold_eq_self_of_flatNoop ops hNoop

theorem peepholeRollPickFold_runOps_eq_of_noIfOp_flatNoop
    (ops : List StackOp) (s : StackState) (hNoIf : noIfOp ops)
    (hNoop : rollPickFoldFlatNoop ops) :
    runOps (peepholeRollPickFold ops) s = runOps ops s := by
  rw [peepholeRollPickFold_eq_self_of_noIfOp_flatNoop ops hNoIf hNoop]

theorem peepholeRollPickFold_preserves_noIfOp
    (ops : List StackOp) (hNoIf : noIfOp ops) :
    noIfOp (peepholeRollPickFold ops) := by
  unfold peepholeRollPickFold
  rw [rollPickListTRgo_nil_acc_of_noIfOp ops hNoIf]
  unfold rollPickFixpointFlat
  exact applyRollPickFold_preserves_noIfOp ops hNoIf

/-! ### Phase 7.9.d — GENERAL roll/pick fold operational soundness (M3)

The `_of_noIfOp_flatNoop` theorem above only covers inputs that have NO
foldable roll/pick head — i.e. the pass is the identity. M3 discharges
the fired-rewrite case generally.

The single-op rewrite soundness (`rollPickRewriteOne_runOps_eq`) needs a
genuine **depth precondition** at the firing position: a `.roll d` /
`.pick d` op only behaves like its specialised opcode when the stack is
at least `d + 1` deep — otherwise the bundled op errors while the
rewrite does not. `opPrecondition` maps both `.roll d` and `.pick d` to
`.none`, so `wellTypedRun` does NOT carry this fact; we thread it
through a dedicated `rollPickDepthOK` predicate, structurally analogous
to `wellTypedRun` but recording exactly the per-position depth bound.

This is a genuine structural precondition — it does NOT restate "the
fold preserves runOps"; it records the stack-depth invariant that the
roll/pick lowerer already establishes for every `.roll d` / `.pick d` it
emits (each is preceded in the lowering by enough material to populate
its `d + 1` operands). -/

/-- Per-position depth invariant for the roll/pick fold: at every
`.roll d` / `.pick d` op in the list, the stack at that op's execution
position is at least `d + 1` deep. Threaded through `stepNonIf` exactly
like `wellTypedRun`. Non-roll/pick ops impose no depth requirement (the
left conjunct is vacuous). `.ifOp` is not exercised by the roll/pick
fold's flat layer (`applyRollPickFold` operates on `noIfOp` lists), so
its second conjunct is vacuously `True` via `stepNonIf`'s `.ifOp` error
branch. -/
def rollPickDepthOK : List StackOp → StackState → Prop
  | [], _ => True
  | op :: rest, s =>
      (∀ d, (op = .roll d ∨ op = .pick d) → s.stack.length ≥ d + 1) ∧
      (∀ s', stepNonIf op s = .ok s' → rollPickDepthOK rest s')

theorem rollPickDepthOK_nil (s : StackState) : rollPickDepthOK [] s := True.intro

theorem rollPickDepthOK_cons (op : StackOp) (rest : List StackOp) (s : StackState) :
    rollPickDepthOK (op :: rest) s ↔
      (∀ d, (op = .roll d ∨ op = .pick d) → s.stack.length ≥ d + 1) ∧
      (∀ s', stepNonIf op s = .ok s' → rollPickDepthOK rest s') :=
  Iff.rfl

/-! ### F1 decidability for `rollPickDepthOK`

The Boolean check mirrors `wellTypedRun`'s recipe (collapse the
`∀ s', stepNonIf … → …` via a `match` on `stepNonIf`'s functional
result), plus a per-head case on whether the head op is a `.roll`/`.pick`.
Only the `.roll`/`.pick` arms impose a real depth check; every other op
is unconstrained at the head. -/

/-- True iff `op` is a `.roll d` or `.pick d` whose depth fits the
current stack. For every non-`.roll`/`.pick` head op the bound is
vacuously satisfied. -/
def rollPickHeadOK (op : StackOp) (s : StackState) : Bool :=
  match op with
  | .roll d => decide (s.stack.length ≥ d + 1)
  | .pick d => decide (s.stack.length ≥ d + 1)
  | _ => true

theorem rollPickHeadOK_iff (op : StackOp) (s : StackState) :
    rollPickHeadOK op s = true ↔
      (∀ d, (op = .roll d ∨ op = .pick d) → s.stack.length ≥ d + 1) := by
  unfold rollPickHeadOK
  constructor
  · intro h d hOr
    cases hOr with
    | inl hEq =>
        subst hEq
        simp at h
        exact h
    | inr hEq =>
        subst hEq
        simp at h
        exact h
  · intro h
    cases op <;> simp
    case roll d => exact h d (Or.inl rfl)
    case pick d => exact h d (Or.inr rfl)

def rollPickDepthOKBool : List StackOp → StackState → Bool
  | [], _ => true
  | op :: rest, s =>
      rollPickHeadOK op s &&
      (match stepNonIf op s with
       | .ok s' => rollPickDepthOKBool rest s'
       | .error _ => true)

theorem rollPickDepthOKBool_iff_rollPickDepthOK :
    ∀ (ops : List StackOp) (s : StackState),
      rollPickDepthOKBool ops s = true ↔ rollPickDepthOK ops s
  | [], _ => by simp [rollPickDepthOKBool, rollPickDepthOK]
  | op :: rest, s => by
    unfold rollPickDepthOKBool rollPickDepthOK
    constructor
    · intro h
      rw [Bool.and_eq_true] at h
      obtain ⟨hHead, hRest⟩ := h
      refine ⟨(rollPickHeadOK_iff op s).mp hHead, ?_⟩
      intro s' hStep
      have : rollPickDepthOKBool rest s' = true := by
        rw [hStep] at hRest; exact hRest
      exact (rollPickDepthOKBool_iff_rollPickDepthOK rest s').mp this
    · intro ⟨hHead, hStep⟩
      rw [Bool.and_eq_true]
      refine ⟨(rollPickHeadOK_iff op s).mpr hHead, ?_⟩
      cases hRes : stepNonIf op s with
      | error _ => rfl
      | ok s' =>
          have := hStep s' hRes
          exact (rollPickDepthOKBool_iff_rollPickDepthOK rest s').mpr this

instance rollPickDepthOK_decidable (ops : List StackOp) (s : StackState) :
    Decidable (rollPickDepthOK ops s) :=
  decidable_of_iff (rollPickDepthOKBool ops s = true)
    (rollPickDepthOKBool_iff_rollPickDepthOK ops s)

/-- General `runOps` soundness of `applyRollPickFold` for `noIfOp`
inputs, under the `rollPickDepthOK` depth invariant. Both fired and
non-fired rewrites are covered: `rollPickRewriteOne_runOps_eq` discharges
the head op, and the per-constructor `runOps_cons_*_cong_typed` lemmas
thread the inductive hypothesis through the tail (the depth invariant on
the tail is exactly `rollPickDepthOK`'s second conjunct). -/
theorem applyRollPickFold_runOps_eq :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), rollPickDepthOK ops s →
        runOps (applyRollPickFold ops) s = runOps ops s := by
  intro ops
  induction ops with
  | nil => intro _ s _; rfl
  | cons op rest ih =>
    intro hNoIf s hDepth
    have hRestNoIf : noIfOp rest := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hHeadDepth :
        ∀ d, (op = .roll d ∨ op = .pick d) → s.stack.length ≥ d + 1 :=
      (rollPickDepthOK_cons op rest s |>.mp hDepth).1
    have hTailDepth :
        ∀ s', stepNonIf op s = .ok s' → rollPickDepthOK rest s' :=
      (rollPickDepthOK_cons op rest s |>.mp hDepth).2
    -- Step 1: `applyRollPickFold (op :: rest) = rollPickRewriteOne op ++ applyRollPickFold rest`.
    show runOps (rollPickRewriteOne op ++ applyRollPickFold rest) s
       = runOps (op :: rest) s
    -- Step 2: the head rewrite preserves `runOps` (given the depth bound).
    rw [rollPickRewriteOne_runOps_eq op s (applyRollPickFold rest) hHeadDepth]
    -- Step 3: thread the IH through the tail with a per-constructor cong.
    -- The IH applies on the post-step state via `hTailDepth`.
    cases op with
    | push v =>
        exact runOps_cons_push_cong_typed v _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | dup =>
        exact runOps_cons_dup_cong_typed _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | swap =>
        exact runOps_cons_swap_cong_typed _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | drop =>
        exact runOps_cons_drop_cong_typed _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | nip =>
        exact runOps_cons_nip_cong_typed _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | over =>
        exact runOps_cons_over_cong_typed _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | rot =>
        exact runOps_cons_rot_cong_typed _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | tuck =>
        exact runOps_cons_tuck_cong_typed _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | roll d =>
        exact runOps_cons_roll_cong_typed d _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | pick d =>
        exact runOps_cons_pick_cong_typed d _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | pickStruct d =>
        exact runOps_cons_pickStruct_cong_typed d _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | opcode code =>
        exact runOps_cons_opcode_cong_typed code _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | placeholder i n =>
        exact runOps_cons_placeholder_cong_typed i n _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | pushCodesepIndex =>
        exact runOps_cons_pushCodesepIndex_cong_typed _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | rawBytes b =>
        exact runOps_cons_rawBytes_cong_typed b _ _ s
          (fun s' hStep => ih hRestNoIf s' (hTailDepth s' hStep))
    | ifOp thn els => exact absurd hNoIf (by simp [noIfOp])

/-- General `runOps` soundness of `peepholeRollPickFold` for `noIfOp`
inputs, under the `rollPickDepthOK` depth invariant. On `noIfOp` lists
`rollPickListTRgo` is the identity and `rollPickFixpointFlat` is
`applyRollPickFold`, so this reduces directly to
`applyRollPickFold_runOps_eq`.

This is strictly more general than
`peepholeRollPickFold_runOps_eq_of_noIfOp_flatNoop` for inputs that
DO contain foldable roll/pick heads — that theorem only covers the
identity case where no head fires. The two are kept side-by-side: the
`flatNoop` variant needs no depth precondition (the pass is literally
the identity), while this one carries the genuine `rollPickDepthOK`
structural invariant required when a head actually folds. -/
theorem peepholeRollPickFold_runOps_eq
    (ops : List StackOp) (s : StackState) (hNoIf : noIfOp ops)
    (hDepth : rollPickDepthOK ops s) :
    runOps (peepholeRollPickFold ops) s = runOps ops s := by
  unfold peepholeRollPickFold
  rw [rollPickListTRgo_nil_acc_of_noIfOp ops hNoIf]
  show runOps (rollPickFixpointFlat 64 ops) s = runOps ops s
  unfold rollPickFixpointFlat
  exact applyRollPickFold_runOps_eq ops hNoIf s hDepth

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
WT-preserving so this carries WT under standard preconditions.

Exposed (non-`private`) so that `Pipeline`-level callers can state the
genuine `wellTypedRun` / `eitherStrict` preconditions that
`peepholePassAllFlat_sound` requires for the two non-WT-preserving outer
rules. -/
def passAllInner15 (ops : List StackOp) : List StackOp :=
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

/-- Bundled precondition for `peepholePassAllFlat_sound`: the four
`wellTypedRun` / `eitherStrict` facts that the two non-WT-preserving
outer rules (`applyZeroNumEqual`, `applyEqualVerifyFuse`) genuinely need.

Bundling these into a single predicate keeps Pipeline-level call sites
small — without it, each caller's type signature would mention
`passAllInner15 ops` four times, and even the type-elaboration cost of
those mentions exceeds Lean's default whnf heartbeat budget on the
deep-call composition we use in M3. -/
def peepholePassAllFlat_preconditions
    (ops : List StackOp) (s : StackState) : Prop :=
  wellTypedRun ops s ∧
  wellTypedRun (applyZeroNumEqual (passAllInner15 ops)) s ∧
  wellTypedRun
    (applyCheckSigVerifyFuse (applyNumEqualVerifyFuse
      (applyZeroNumEqual (passAllInner15 ops)))) s ∧
  equalVerifyFuse_eitherStrict
    (applyCheckSigVerifyFuse (applyNumEqualVerifyFuse
      (applyZeroNumEqual (passAllInner15 ops)))) s

/-- F1 decidability for the bundled precondition. It is a four-way
conjunction of already-decidable component predicates
(`wellTypedRun` × 3 + `equalVerifyFuse_eitherStrict`), so the
`Decidable` instance is fully derived. Lean's automatic conjunction
synthesis would discharge this transparently; we make it explicit so
`native_decide` finds the targeted instance without backtracking
through the unfolded conjuncts at every elaboration. -/
instance peepholePassAllFlat_preconditions_decidable
    (ops : List StackOp) (s : StackState) :
    Decidable (peepholePassAllFlat_preconditions ops s) := by
  unfold peepholePassAllFlat_preconditions
  infer_instance

set_option maxHeartbeats 1600000 in
/-- Discharge `peepholePassAllFlat_sound` from a bundled precondition. -/
theorem peepholePassAllFlat_runOps_eq
    (ops : List StackOp) (s : StackState) (hNoIf : noIfOp ops)
    (hPre : peepholePassAllFlat_preconditions ops s) :
    runOps (peepholePassAllFlat ops) s = runOps ops s :=
  peepholePassAllFlat_sound ops hNoIf s hPre.1 hPre.2.1 hPre.2.2.1 hPre.2.2.2

set_option maxHeartbeats 1600000 in
/-- `noIfOp` preservation through the full 19-rule flat chain. Composes
the inner-15 preservation with the four outer rules. -/
theorem peepholePassAllFlat_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (peepholePassAllFlat ops) := by
  intro ops hNoIf
  -- `passAllInner15` is exactly the inner-15-rule prefix of
  -- `peepholePassAllFlat`; the four outer rules wrap it.
  have hInner : noIfOp (passAllInner15 ops) :=
    passAllInner15_preserves_noIfOp ops hNoIf
  show noIfOp (applyEqualVerifyFuse (applyCheckSigVerifyFuse
        (applyNumEqualVerifyFuse (applyZeroNumEqual (passAllInner15 ops)))))
  exact applyEqualVerifyFuse_preserves_noIfOp _
    (applyCheckSigVerifyFuse_preserves_noIfOp _
      (applyNumEqualVerifyFuse_preserves_noIfOp _
        (applyZeroNumEqual_preserves_noIfOp _ hInner)))

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
    | pickStruct d =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.pickStruct d :: acc) hRest]
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
    | rawBytes b =>
        have hRest : noIfOp rest := by simpa [noIfOp] using hNoIf
        unfold preprocessOpListReversedAux
        unfold preprocessOp
        rw [ih (.rawBytes b :: acc) hRest]
        rfl

/-- Phase 7.9.c: After fixing the streaming-driver pair-direction bug,
`peepholePassAll` is now defined directly as `peepholePassAllFlat`
applied to the forward-preprocessed list. This lemma states that
identity, useful for transferring soundness from
`peepholePassAllFlat_sound` to `peepholePassAll`. -/
private theorem peepholePassAll_eq_flat_preprocess (ops : List StackOp) :
    peepholePassAll ops = peepholePassAllFlat (preprocessIfOps ops) := rfl

theorem preprocessIfOps_eq_self_of_noIfOp
    (ops : List StackOp) (hNoIf : noIfOp ops) :
    preprocessIfOps ops = ops := by
  unfold preprocessIfOps
  rw [preprocessOpListReversedAux_noIf ops [] hNoIf]
  simp

theorem peepholePassAll_eq_flat_of_noIfOp
    (ops : List StackOp) (hNoIf : noIfOp ops) :
    peepholePassAll ops = peepholePassAllFlat ops := by
  rw [peepholePassAll_eq_flat_preprocess ops]
  rw [preprocessIfOps_eq_self_of_noIfOp ops hNoIf]

theorem peepholePassAll_runOps_eq_of_flat_sound
    (ops : List StackOp) (s : StackState)
    (hNoIf : noIfOp ops)
    (hFlatSound : runOps (peepholePassAllFlat ops) s = runOps ops s) :
    runOps (peepholePassAll ops) s = runOps ops s := by
  rw [peepholePassAll_eq_flat_of_noIfOp ops hNoIf]
  exact hFlatSound

set_option maxHeartbeats 800000 in
/-- `noIfOp` preservation through `peepholePassAll`. For `noIfOp` inputs
the `.ifOp`-descent preprocessor is the identity, so this reduces to
`peepholePassAllFlat_preserves_noIfOp`. -/
theorem peepholePassAll_preserves_noIfOp
    (ops : List StackOp) (hNoIf : noIfOp ops) :
    noIfOp (peepholePassAll ops) := by
  rw [peepholePassAll_eq_flat_of_noIfOp ops hNoIf]
  exact peepholePassAllFlat_preserves_noIfOp ops hNoIf

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

/-! ## Tier 3.2.b — chainFold operational soundness

The 4-op chain-fold rules `[push a, OP_ADD, push b, OP_ADD] →
[push (a+b), OP_ADD]` (resp. `OP_SUB`) are operationally sound under the
existing `wellTypedRun` precondition. The key insight: the FIRST OP_ADD
in the firing window requires `.twoInts` on the post-push stack, which
forces the underlying stack to start with `.vBigint`. From that, the
arithmetic identity `(x + a) + b = x + (a + b)` (resp. `(x - a) - b
= x - (a + b)`) closes the operational equality.

This section ports Tier 3.2.b from the chainFold post-pass spec:

* atom-level `pushAddPushAdd_extends_int` / `pushAddPushSub_extends_int`
* list-level `applyPushAddPushAdd_runOps_eq` / `applyPushAddPushSub_runOps_eq`
* preservation `applyPushAddPushAdd_preserves_wellTypedRun` /
  `applyPushAddPushSub_preserves_wellTypedRun`
* preservation `applyPushAddPushAdd_preserves_noIfOp` /
  `applyPushAddPushSub_preserves_noIfOp`

The fixpoint (`chainFoldFixpointFlat`) and top-level
(`peepholeChainFold`) compositions are documented at the end of this
section.
-/

/-- Atom-level extension under int-stack precondition: `[push a, OP_ADD,
push b, OP_ADD] :: rest` reduces to `[push (a+b), OP_ADD] :: rest`.
Arithmetic: `(x + a) + b = x + (a + b)`. -/
private theorem pushAddPushAdd_extends_int
    (s : StackState) (a b x : Int) (rest_stack : List ANF.Eval.Value)
    (rest : List StackOp)
    (hs : s.stack = .vBigint x :: rest_stack) :
    runOps (.push (.bigint a) :: .opcode "OP_ADD" ::
            .push (.bigint b) :: .opcode "OP_ADD" :: rest) s
    = runOps (.push (.bigint (a + b)) :: .opcode "OP_ADD" :: rest) s := by
  rw [runOps_cons_push_eq, stepNonIf_push_bigint]
  show runOps (.opcode "OP_ADD" :: .push (.bigint b) :: .opcode "OP_ADD" :: rest)
                (s.push (.vBigint a))
       = runOps (.push (.bigint (a + b)) :: .opcode "OP_ADD" :: rest) s
  rw [runOps_cons_opcode_eq, stepNonIf_opcode]
  have hStack1 : (s.push (.vBigint a)).stack = .vBigint a :: .vBigint x :: rest_stack := by
    unfold StackState.push; simp [hs]
  rw [runOpcode_add_int_concrete (s.push (.vBigint a)) x a rest_stack hStack1]
  show runOps (.push (.bigint b) :: .opcode "OP_ADD" :: rest)
                (({ s.push (.vBigint a) with stack := rest_stack } :
                  StackState).push (.vBigint (x + a)))
       = runOps (.push (.bigint (a + b)) :: .opcode "OP_ADD" :: rest) s
  rw [runOps_cons_push_eq, stepNonIf_push_bigint]
  show runOps (.opcode "OP_ADD" :: rest)
         ((({ s.push (.vBigint a) with stack := rest_stack } :
            StackState).push (.vBigint (x + a))).push (.vBigint b))
       = runOps (.push (.bigint (a + b)) :: .opcode "OP_ADD" :: rest) s
  rw [runOps_cons_opcode_eq, stepNonIf_opcode]
  let s1 : StackState := { s.push (.vBigint a) with stack := rest_stack }
  let s2 : StackState := s1.push (.vBigint (x + a))
  let s3 : StackState := s2.push (.vBigint b)
  have hs3stack : s3.stack = .vBigint b :: .vBigint (x + a) :: rest_stack := by
    show (s2.push (.vBigint b)).stack = _
    unfold StackState.push
    show .vBigint b :: s2.stack = _
    show .vBigint b :: (s1.push (.vBigint (x + a))).stack = _
    unfold StackState.push
    show .vBigint b :: .vBigint (x + a) :: s1.stack = _
    rfl
  rw [runOpcode_add_int_concrete s3 (x + a) b rest_stack hs3stack]
  rw [runOps_cons_push_eq, stepNonIf_push_bigint]
  show runOps rest (({ s3 with stack := rest_stack } : StackState).push (.vBigint ((x + a) + b)))
       = runOps (.opcode "OP_ADD" :: rest) (s.push (.vBigint (a + b)))
  rw [runOps_cons_opcode_eq, stepNonIf_opcode]
  have hStack2 : (s.push (.vBigint (a + b))).stack
               = .vBigint (a + b) :: .vBigint x :: rest_stack := by
    unfold StackState.push; simp [hs]
  rw [runOpcode_add_int_concrete (s.push (.vBigint (a + b))) x (a + b) rest_stack hStack2]
  show runOps rest (({ s3 with stack := rest_stack } : StackState).push (.vBigint ((x + a) + b)))
       = runOps rest (({ s.push (.vBigint (a + b)) with stack := rest_stack } :
                       StackState).push (.vBigint (x + (a + b))))
  congr 1
  cases s with
  | mk stack altstack outputs props preimage =>
      simp_all [s3, s2, s1, StackState.push]
      omega

/-- Atom-level extension for SUB chain: `[push a, OP_SUB, push b, OP_SUB] :: rest`
reduces to `[push (a+b), OP_SUB] :: rest`. Arithmetic: `(x - a) - b = x - (a + b)`. -/
private theorem pushAddPushSub_extends_int
    (s : StackState) (a b x : Int) (rest_stack : List ANF.Eval.Value)
    (rest : List StackOp)
    (hs : s.stack = .vBigint x :: rest_stack) :
    runOps (.push (.bigint a) :: .opcode "OP_SUB" ::
            .push (.bigint b) :: .opcode "OP_SUB" :: rest) s
    = runOps (.push (.bigint (a + b)) :: .opcode "OP_SUB" :: rest) s := by
  rw [runOps_cons_push_eq, stepNonIf_push_bigint]
  show runOps (.opcode "OP_SUB" :: .push (.bigint b) :: .opcode "OP_SUB" :: rest)
                (s.push (.vBigint a))
       = runOps (.push (.bigint (a + b)) :: .opcode "OP_SUB" :: rest) s
  rw [runOps_cons_opcode_eq, stepNonIf_opcode]
  have hStack1 : (s.push (.vBigint a)).stack = .vBigint a :: .vBigint x :: rest_stack := by
    unfold StackState.push; simp [hs]
  rw [runOpcode_sub_int_concrete (s.push (.vBigint a)) x a rest_stack hStack1]
  show runOps (.push (.bigint b) :: .opcode "OP_SUB" :: rest)
                (({ s.push (.vBigint a) with stack := rest_stack } :
                  StackState).push (.vBigint (x - a)))
       = runOps (.push (.bigint (a + b)) :: .opcode "OP_SUB" :: rest) s
  rw [runOps_cons_push_eq, stepNonIf_push_bigint]
  show runOps (.opcode "OP_SUB" :: rest)
         ((({ s.push (.vBigint a) with stack := rest_stack } :
            StackState).push (.vBigint (x - a))).push (.vBigint b))
       = runOps (.push (.bigint (a + b)) :: .opcode "OP_SUB" :: rest) s
  rw [runOps_cons_opcode_eq, stepNonIf_opcode]
  let s1 : StackState := { s.push (.vBigint a) with stack := rest_stack }
  let s2 : StackState := s1.push (.vBigint (x - a))
  let s3 : StackState := s2.push (.vBigint b)
  have hs3stack : s3.stack = .vBigint b :: .vBigint (x - a) :: rest_stack := by
    show (s2.push (.vBigint b)).stack = _
    unfold StackState.push
    show .vBigint b :: s2.stack = _
    show .vBigint b :: (s1.push (.vBigint (x - a))).stack = _
    unfold StackState.push
    show .vBigint b :: .vBigint (x - a) :: s1.stack = _
    rfl
  rw [runOpcode_sub_int_concrete s3 (x - a) b rest_stack hs3stack]
  rw [runOps_cons_push_eq, stepNonIf_push_bigint]
  show runOps rest (({ s3 with stack := rest_stack } : StackState).push (.vBigint ((x - a) - b)))
       = runOps (.opcode "OP_SUB" :: rest) (s.push (.vBigint (a + b)))
  rw [runOps_cons_opcode_eq, stepNonIf_opcode]
  have hStack2 : (s.push (.vBigint (a + b))).stack
               = .vBigint (a + b) :: .vBigint x :: rest_stack := by
    unfold StackState.push; simp [hs]
  rw [runOpcode_sub_int_concrete (s.push (.vBigint (a + b))) x (a + b) rest_stack hStack2]
  show runOps rest (({ s3 with stack := rest_stack } : StackState).push (.vBigint ((x - a) - b)))
       = runOps rest (({ s.push (.vBigint (a + b)) with stack := rest_stack } :
                       StackState).push (.vBigint (x - (a + b))))
  congr 1
  cases s with
  | mk stack altstack outputs props preimage =>
      simp_all [s3, s2, s1, StackState.push]
      omega

/-! ### Stack-shape extraction from `wellTypedRun`

In the firing branch, `wellTypedRun (.push (.bigint a) :: .opcode "OP_X" :: ...) s`
forces `s.stack = .vBigint x :: rest_stack` because the post-push opcode
requires `.twoInts`. The helper below extracts that shape. -/

/-- Auxiliary: from a proof that `(.vBigint a :: L)` matches `.twoInts` shape, conclude
`L` starts with `.vBigint`. -/
private theorem twoInts_match_cons_int
    (a : Int) (L : List ANF.Eval.Value)
    (h : (match (.vBigint a :: L : List ANF.Eval.Value) with
          | .vBigint _ :: .vBigint _ :: _ => True
          | _ => False)) :
    ∃ x rest_stack, L = .vBigint x :: rest_stack := by
  cases L with
  | nil => exact absurd h (by simp)
  | cons v rest_stack =>
    cases v with
    | vBigint x => exact ⟨x, rest_stack, rfl⟩
    | vBool _    => exact absurd h (by simp)
    | vBytes _   => exact absurd h (by simp)
    | vOpaque _  => exact absurd h (by simp)
    | vThis      => exact absurd h (by simp)

private theorem twoInts_after_push_bigint
    (s : StackState) (a : Int)
    (hPrecond : precondMet .twoInts (s.push (.vBigint a))) :
    ∃ x rest_stack, s.stack = .vBigint x :: rest_stack := by
  have hPushedStack : (s.push (.vBigint a)).stack = .vBigint a :: s.stack := by
    unfold StackState.push; rfl
  have hUnfold : precondMet .twoInts (s.push (.vBigint a))
              = (match (s.push (.vBigint a)).stack with
                 | .vBigint _ :: .vBigint _ :: _ => True
                 | _ => False) := rfl
  rw [hUnfold, hPushedStack] at hPrecond
  exact twoInts_match_cons_int a s.stack hPrecond

private theorem chainFold_extract_int_top
    (s : StackState) (a : Int) (rest : List StackOp)
    (hWT : wellTypedRun (.push (.bigint a) :: .opcode "OP_ADD" :: rest) s) :
    ∃ x rest_stack, s.stack = .vBigint x :: rest_stack := by
  have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
  have hStepPush : stepNonIf (.push (.bigint a)) s = .ok (s.push (.vBigint a)) :=
    stepNonIf_push_bigint s a
  have hWell1 : wellTypedRun (.opcode "OP_ADD" :: rest) (s.push (.vBigint a)) :=
    hCont _ hStepPush
  have ⟨hPrecond1, _⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
  exact twoInts_after_push_bigint s a hPrecond1

private theorem chainFold_extract_int_top_sub
    (s : StackState) (a : Int) (rest : List StackOp)
    (hWT : wellTypedRun (.push (.bigint a) :: .opcode "OP_SUB" :: rest) s) :
    ∃ x rest_stack, s.stack = .vBigint x :: rest_stack := by
  have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
  have hStepPush : stepNonIf (.push (.bigint a)) s = .ok (s.push (.vBigint a)) :=
    stepNonIf_push_bigint s a
  have hWell1 : wellTypedRun (.opcode "OP_SUB" :: rest) (s.push (.vBigint a)) :=
    hCont _ hStepPush
  have ⟨hPrecond1, _⟩ := wellTypedRun_cons _ _ _ |>.mp hWell1
  exact twoInts_after_push_bigint s a hPrecond1

/-! ### `applyPushAddPush*_cons_no_match` helpers (Lean-level rewrite glue) -/

private theorem applyPushAddPushAdd_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ a b rt, op = .push (.bigint a) →
         rest = .opcode "OP_ADD" :: .push (.bigint b) :: .opcode "OP_ADD" :: rt → False) :
    applyPushAddPushAdd (op :: rest) = op :: applyPushAddPushAdd rest :=
  applyPushAddPushAdd.eq_3 op rest h

private theorem applyPushAddPushSub_cons_no_match
    (op : StackOp) (rest : List StackOp)
    (h : ∀ a b rt, op = .push (.bigint a) →
         rest = .opcode "OP_SUB" :: .push (.bigint b) :: .opcode "OP_SUB" :: rt → False) :
    applyPushAddPushSub (op :: rest) = op :: applyPushAddPushSub rest :=
  applyPushAddPushSub.eq_3 op rest h

/-! ### List-level operational soundness for the chain-fold rules

Under `noIfOp` + `wellTypedRun`, `applyPushAddPushAdd ops` (resp. `_Sub`)
preserves `runOps` semantics. Induct on `applyPushAddPushAdd.induct`. -/

theorem applyPushAddPushAdd_runOps_eq :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyPushAddPushAdd ops) s = runOps ops s := by
  intro ops
  induction ops using applyPushAddPushAdd.induct with
  | case1 => intros _ _ _; rfl
  | case2 a b rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .opcode "OP_ADD" ::
                     .push (.bigint b) :: .opcode "OP_ADD" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    obtain ⟨x, rest_stack, hStack⟩ := chainFold_extract_int_top s a _ hWT
    rw [show applyPushAddPushAdd
              (.push (.bigint a) :: .opcode "OP_ADD" ::
               .push (.bigint b) :: .opcode "OP_ADD" :: rest')
            = .push (.bigint (a + b)) :: .opcode "OP_ADD" :: applyPushAddPushAdd rest' from rfl]
    rw [pushAddPushAdd_extends_int s a b x rest_stack rest' hStack]
    apply runOps_cons_push_cong_typed
    intro s1 hStep1
    have hStepPushDef : stepNonIf (.push (.bigint (a + b))) s = .ok (s.push (.vBigint (a + b))) :=
      stepNonIf_push_bigint s (a + b)
    have hS1Eq : s1 = s.push (.vBigint (a + b)) := by
      rw [hStepPushDef] at hStep1
      exact ((Except.ok.injEq _ _).mp hStep1).symm
    rw [hS1Eq]
    apply runOps_cons_opcode_cong_typed
    intro s2 hStep2
    have hStackPushed : (s.push (.vBigint (a + b))).stack
                      = .vBigint (a + b) :: .vBigint x :: rest_stack := by
      unfold StackState.push; simp [hStack]
    have hStepAddDef : stepNonIf (.opcode "OP_ADD") (s.push (.vBigint (a + b)))
                = .ok (({ s with stack := rest_stack } : StackState).push (.vBigint (x + (a + b)))) := by
      rw [stepNonIf_opcode]
      rw [runOpcode_add_int_concrete _ x (a + b) rest_stack hStackPushed]
      cases s
      simp [StackState.push]
    have hS2Eq : s2 = ({ s with stack := rest_stack } : StackState).push (.vBigint (x + (a + b))) := by
      rw [hStepAddDef] at hStep2
      exact ((Except.ok.injEq _ _).mp hStep2).symm
    rw [hS2Eq]
    -- We need wellTypedRun rest' s2.
    have hWTafter : wellTypedRun rest'
        (({ s with stack := rest_stack } : StackState).push (.vBigint (x + (a + b)))) := by
      have ⟨_, hC0⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
      have hStepPushA : stepNonIf (.push (.bigint a)) s = .ok (s.push (.vBigint a)) :=
        stepNonIf_push_bigint s a
      have hW1 : wellTypedRun (.opcode "OP_ADD" :: .push (.bigint b) :: .opcode "OP_ADD" :: rest')
                  (s.push (.vBigint a)) := hC0 _ hStepPushA
      have ⟨_, hC1⟩ := wellTypedRun_cons _ _ _ |>.mp hW1
      have hPushedA : (s.push (.vBigint a)).stack = .vBigint a :: .vBigint x :: rest_stack := by
        unfold StackState.push; simp [hStack]
      have hStepAddA : stepNonIf (.opcode "OP_ADD") (s.push (.vBigint a))
                  = .ok (({ s with stack := rest_stack } : StackState).push (.vBigint (x + a))) := by
        rw [stepNonIf_opcode]
        rw [runOpcode_add_int_concrete _ x a rest_stack hPushedA]
        cases s; simp [StackState.push]
      have hW2 : wellTypedRun (.push (.bigint b) :: .opcode "OP_ADD" :: rest')
                  (({ s with stack := rest_stack } : StackState).push (.vBigint (x + a))) :=
        hC1 _ hStepAddA
      have ⟨_, hC2⟩ := wellTypedRun_cons _ _ _ |>.mp hW2
      have hStepPushB : stepNonIf (.push (.bigint b))
                          (({ s with stack := rest_stack } : StackState).push (.vBigint (x + a)))
                = .ok ((({ s with stack := rest_stack } : StackState).push (.vBigint (x + a))).push
                        (.vBigint b)) :=
        stepNonIf_push_bigint _ b
      have hW3 : wellTypedRun (.opcode "OP_ADD" :: rest')
                  ((({ s with stack := rest_stack } : StackState).push (.vBigint (x + a))).push
                    (.vBigint b)) := hC2 _ hStepPushB
      have ⟨_, hC3⟩ := wellTypedRun_cons _ _ _ |>.mp hW3
      have hPushedB : ((({ s with stack := rest_stack } : StackState).push (.vBigint (x + a))).push
                        (.vBigint b)).stack
                    = .vBigint b :: .vBigint (x + a) :: rest_stack := by
        unfold StackState.push; simp
      have hStepAddB : stepNonIf (.opcode "OP_ADD")
                  ((({ s with stack := rest_stack } : StackState).push (.vBigint (x + a))).push
                    (.vBigint b))
                  = .ok (({ s with stack := rest_stack } : StackState).push
                          (.vBigint ((x + a) + b))) := by
        rw [stepNonIf_opcode]
        rw [runOpcode_add_int_concrete _ (x + a) b rest_stack hPushedB]
        cases s; simp [StackState.push]
      have hW4 := hC3 _ hStepAddB
      -- hW4 : wellTypedRun rest' (({ s with stack := rest_stack }).push (.vBigint ((x + a) + b)))
      -- Goal:  wellTypedRun rest' (({ s with stack := rest_stack }).push (.vBigint (x + (a + b))))
      have hAssoc : (x + a) + b = x + (a + b) := by omega
      rw [hAssoc] at hW4
      exact hW4
    exact ih hRestNoIf _ hWTafter
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyPushAddPushAdd rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyPushAddPushAdd_cons_no_match (.push v) rest'
              (fun a b rt hOp hRest => h_no_match a b rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      => exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     => exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     => exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      => exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     => exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      => exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     => exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   => exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   => exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .pickStruct d => exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
    | .opcode code  => exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n => exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex => exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped
    | .rawBytes b => exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

theorem applyPushAddPushSub_runOps_eq :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (applyPushAddPushSub ops) s = runOps ops s := by
  intro ops
  induction ops using applyPushAddPushSub.induct with
  | case1 => intros _ _ _; rfl
  | case2 a b rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .opcode "OP_SUB" ::
                     .push (.bigint b) :: .opcode "OP_SUB" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    obtain ⟨x, rest_stack, hStack⟩ := chainFold_extract_int_top_sub s a _ hWT
    rw [show applyPushAddPushSub
              (.push (.bigint a) :: .opcode "OP_SUB" ::
               .push (.bigint b) :: .opcode "OP_SUB" :: rest')
            = .push (.bigint (a + b)) :: .opcode "OP_SUB" :: applyPushAddPushSub rest' from rfl]
    rw [pushAddPushSub_extends_int s a b x rest_stack rest' hStack]
    apply runOps_cons_push_cong_typed
    intro s1 hStep1
    have hStepPushDef : stepNonIf (.push (.bigint (a + b))) s = .ok (s.push (.vBigint (a + b))) :=
      stepNonIf_push_bigint s (a + b)
    have hS1Eq : s1 = s.push (.vBigint (a + b)) := by
      rw [hStepPushDef] at hStep1
      exact ((Except.ok.injEq _ _).mp hStep1).symm
    rw [hS1Eq]
    apply runOps_cons_opcode_cong_typed
    intro s2 hStep2
    have hStackPushed : (s.push (.vBigint (a + b))).stack
                      = .vBigint (a + b) :: .vBigint x :: rest_stack := by
      unfold StackState.push; simp [hStack]
    have hStepSubDef : stepNonIf (.opcode "OP_SUB") (s.push (.vBigint (a + b)))
                = .ok (({ s with stack := rest_stack } : StackState).push (.vBigint (x - (a + b)))) := by
      rw [stepNonIf_opcode]
      rw [runOpcode_sub_int_concrete _ x (a + b) rest_stack hStackPushed]
      cases s
      simp [StackState.push]
    have hS2Eq : s2 = ({ s with stack := rest_stack } : StackState).push (.vBigint (x - (a + b))) := by
      rw [hStepSubDef] at hStep2
      exact ((Except.ok.injEq _ _).mp hStep2).symm
    rw [hS2Eq]
    have hWTafter : wellTypedRun rest'
        (({ s with stack := rest_stack } : StackState).push (.vBigint (x - (a + b)))) := by
      have ⟨_, hC0⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
      have hStepPushA : stepNonIf (.push (.bigint a)) s = .ok (s.push (.vBigint a)) :=
        stepNonIf_push_bigint s a
      have hW1 : wellTypedRun (.opcode "OP_SUB" :: .push (.bigint b) :: .opcode "OP_SUB" :: rest')
                  (s.push (.vBigint a)) := hC0 _ hStepPushA
      have ⟨_, hC1⟩ := wellTypedRun_cons _ _ _ |>.mp hW1
      have hPushedA : (s.push (.vBigint a)).stack = .vBigint a :: .vBigint x :: rest_stack := by
        unfold StackState.push; simp [hStack]
      have hStepSubA : stepNonIf (.opcode "OP_SUB") (s.push (.vBigint a))
                  = .ok (({ s with stack := rest_stack } : StackState).push (.vBigint (x - a))) := by
        rw [stepNonIf_opcode]
        rw [runOpcode_sub_int_concrete _ x a rest_stack hPushedA]
        cases s; simp [StackState.push]
      have hW2 : wellTypedRun (.push (.bigint b) :: .opcode "OP_SUB" :: rest')
                  (({ s with stack := rest_stack } : StackState).push (.vBigint (x - a))) :=
        hC1 _ hStepSubA
      have ⟨_, hC2⟩ := wellTypedRun_cons _ _ _ |>.mp hW2
      have hStepPushB : stepNonIf (.push (.bigint b))
                          (({ s with stack := rest_stack } : StackState).push (.vBigint (x - a)))
                = .ok ((({ s with stack := rest_stack } : StackState).push (.vBigint (x - a))).push
                        (.vBigint b)) :=
        stepNonIf_push_bigint _ b
      have hW3 : wellTypedRun (.opcode "OP_SUB" :: rest')
                  ((({ s with stack := rest_stack } : StackState).push (.vBigint (x - a))).push
                    (.vBigint b)) := hC2 _ hStepPushB
      have ⟨_, hC3⟩ := wellTypedRun_cons _ _ _ |>.mp hW3
      have hPushedB : ((({ s with stack := rest_stack } : StackState).push (.vBigint (x - a))).push
                        (.vBigint b)).stack
                    = .vBigint b :: .vBigint (x - a) :: rest_stack := by
        unfold StackState.push; simp
      have hStepSubB : stepNonIf (.opcode "OP_SUB")
                  ((({ s with stack := rest_stack } : StackState).push (.vBigint (x - a))).push
                    (.vBigint b))
                  = .ok (({ s with stack := rest_stack } : StackState).push
                          (.vBigint ((x - a) - b))) := by
        rw [stepNonIf_opcode]
        rw [runOpcode_sub_int_concrete _ (x - a) b rest_stack hPushedB]
        cases s; simp [StackState.push]
      have hW4 := hC3 _ hStepSubB
      have hSubAssoc : (x - a) - b = x - (a + b) := by omega
      rw [hSubAssoc] at hW4
      exact hW4
    exact ih hRestNoIf _ hWTafter
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have ⟨_, hCont⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
    have ihTyped : ∀ s', stepNonIf op s = .ok s' →
        runOps (applyPushAddPushSub rest') s' = runOps rest' s' := by
      intro s' hStep
      exact ih hRestNoIf s' (hCont s' hStep)
    match op with
    | .ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
    | .push v   =>
        rw [applyPushAddPushSub_cons_no_match (.push v) rest'
              (fun a b rt hOp hRest => h_no_match a b rt hOp hRest)]
        exact runOps_cons_push_cong_typed v _ _ s ihTyped
    | .dup      => exact runOps_cons_dup_cong_typed _ _ s ihTyped
    | .swap     => exact runOps_cons_swap_cong_typed _ _ s ihTyped
    | .drop     => exact runOps_cons_drop_cong_typed _ _ s ihTyped
    | .nip      => exact runOps_cons_nip_cong_typed _ _ s ihTyped
    | .over     => exact runOps_cons_over_cong_typed _ _ s ihTyped
    | .rot      => exact runOps_cons_rot_cong_typed _ _ s ihTyped
    | .tuck     => exact runOps_cons_tuck_cong_typed _ _ s ihTyped
    | .roll d   => exact runOps_cons_roll_cong_typed d _ _ s ihTyped
    | .pick d   => exact runOps_cons_pick_cong_typed d _ _ s ihTyped
    | .pickStruct d => exact runOps_cons_pickStruct_cong_typed d _ _ s ihTyped
    | .opcode code  => exact runOps_cons_opcode_cong_typed code _ _ s ihTyped
    | .placeholder i n => exact runOps_cons_placeholder_cong_typed i n _ _ s ihTyped
    | .pushCodesepIndex => exact runOps_cons_pushCodesepIndex_cong_typed _ _ s ihTyped
    | .rawBytes b => exact runOps_cons_rawBytes_cong_typed b _ _ s ihTyped

/-! ### `noIfOp` preservation under chain-fold rules. -/

theorem applyPushAddPushAdd_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyPushAddPushAdd ops) := by
  intro ops
  induction ops using applyPushAddPushAdd.induct with
  | case1 => intro _; exact True.intro
  | case2 a b rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .opcode "OP_ADD" ::
                     .push (.bigint b) :: .opcode "OP_ADD" :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyPushAddPushAdd rest') := ih hRest'
    show noIfOp (.push (.bigint (a + b)) :: .opcode "OP_ADD" :: applyPushAddPushAdd rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyPushAddPushAdd rest') := ih hRest'
    have hRewrite :
        applyPushAddPushAdd (op :: rest')
        = op :: applyPushAddPushAdd rest' :=
      applyPushAddPushAdd.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

theorem applyPushAddPushSub_preserves_noIfOp :
    ∀ (ops : List StackOp), noIfOp ops → noIfOp (applyPushAddPushSub ops) := by
  intro ops
  induction ops using applyPushAddPushSub.induct with
  | case1 => intro _; exact True.intro
  | case2 a b rest' ih =>
    intro h
    have hRest' : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .opcode "OP_SUB" ::
                     .push (.bigint b) :: .opcode "OP_SUB" :: rest') at h
      change noIfOp rest'
      exact h
    have ihRes : noIfOp (applyPushAddPushSub rest') := ih hRest'
    show noIfOp (.push (.bigint (a + b)) :: .opcode "OP_SUB" :: applyPushAddPushSub rest')
    simpa [noIfOp] using ihRes
  | case3 op rest' h_no_match ih =>
    intro h
    have hRest' : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd h (by simp [noIfOp])
      | _ => simpa [noIfOp] using h
    have ihRes : noIfOp (applyPushAddPushSub rest') := ih hRest'
    have hRewrite :
        applyPushAddPushSub (op :: rest')
        = op :: applyPushAddPushSub rest' :=
      applyPushAddPushSub.eq_3 op rest' h_no_match
    rw [hRewrite]
    cases op with
    | ifOp _ _ => exact absurd h (by simp [noIfOp])
    | _ => simpa [noIfOp] using ihRes

/-! ### `wellTypedRun` preservation under chain-fold rules.

The rule rewrites `[push a, OP_ADD, push b, OP_ADD]` to `[push (a+b),
OP_ADD]`. Both windows produce the same post-state (`{s with stack :=
rest_stack}.push (.vBigint (x+a+b))`) when `s.stack = .vBigint x ::
rest_stack`. So `wellTypedRun rest`-at-post-state lifts trivially. -/

theorem applyPushAddPushAdd_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyPushAddPushAdd ops) s := by
  intro ops
  induction ops using applyPushAddPushAdd.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 a b rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .opcode "OP_ADD" ::
                     .push (.bigint b) :: .opcode "OP_ADD" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    obtain ⟨x, rest_stack, hStack⟩ := chainFold_extract_int_top s a _ hWT
    -- Compute wellTypedRun rest' at the post-4-op state: ({s with stack := rest_stack}).push (x+(a+b)).
    have hWTafter : wellTypedRun rest'
        (({ s with stack := rest_stack } : StackState).push (.vBigint (x + (a + b)))) := by
      have ⟨_, hC0⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
      have hStepPushA : stepNonIf (.push (.bigint a)) s = .ok (s.push (.vBigint a)) :=
        stepNonIf_push_bigint s a
      have hW1 : wellTypedRun (.opcode "OP_ADD" :: .push (.bigint b) :: .opcode "OP_ADD" :: rest')
                  (s.push (.vBigint a)) := hC0 _ hStepPushA
      have ⟨_, hC1⟩ := wellTypedRun_cons _ _ _ |>.mp hW1
      have hPushedA : (s.push (.vBigint a)).stack = .vBigint a :: .vBigint x :: rest_stack := by
        unfold StackState.push; simp [hStack]
      have hStepAddA : stepNonIf (.opcode "OP_ADD") (s.push (.vBigint a))
                  = .ok (({ s with stack := rest_stack } : StackState).push (.vBigint (x + a))) := by
        rw [stepNonIf_opcode]
        rw [runOpcode_add_int_concrete _ x a rest_stack hPushedA]
        cases s; simp [StackState.push]
      have hW2 : wellTypedRun (.push (.bigint b) :: .opcode "OP_ADD" :: rest')
                  (({ s with stack := rest_stack } : StackState).push (.vBigint (x + a))) :=
        hC1 _ hStepAddA
      have ⟨_, hC2⟩ := wellTypedRun_cons _ _ _ |>.mp hW2
      have hStepPushB : stepNonIf (.push (.bigint b))
                          (({ s with stack := rest_stack } : StackState).push (.vBigint (x + a)))
                = .ok ((({ s with stack := rest_stack } : StackState).push (.vBigint (x + a))).push
                        (.vBigint b)) :=
        stepNonIf_push_bigint _ b
      have hW3 : wellTypedRun (.opcode "OP_ADD" :: rest')
                  ((({ s with stack := rest_stack } : StackState).push (.vBigint (x + a))).push
                    (.vBigint b)) := hC2 _ hStepPushB
      have ⟨_, hC3⟩ := wellTypedRun_cons _ _ _ |>.mp hW3
      have hPushedB : ((({ s with stack := rest_stack } : StackState).push (.vBigint (x + a))).push
                        (.vBigint b)).stack
                    = .vBigint b :: .vBigint (x + a) :: rest_stack := by
        unfold StackState.push; simp
      have hStepAddB : stepNonIf (.opcode "OP_ADD")
                  ((({ s with stack := rest_stack } : StackState).push (.vBigint (x + a))).push
                    (.vBigint b))
                  = .ok (({ s with stack := rest_stack } : StackState).push
                          (.vBigint ((x + a) + b))) := by
        rw [stepNonIf_opcode]
        rw [runOpcode_add_int_concrete _ (x + a) b rest_stack hPushedB]
        cases s; simp [StackState.push]
      have hW4 := hC3 _ hStepAddB
      have hAssoc : (x + a) + b = x + (a + b) := by omega
      rw [hAssoc] at hW4
      exact hW4
    -- Recursively apply IH to get wellTypedRun (applyPushAddPushAdd rest') at the same state.
    have ihRes : wellTypedRun (applyPushAddPushAdd rest')
                  (({ s with stack := rest_stack } : StackState).push (.vBigint (x + (a + b)))) :=
      ih hRestNoIf _ hWTafter
    -- Show the goal: wellTypedRun (.push (a+b) :: .opcode "OP_ADD" :: applyPushAddPushAdd rest') s.
    show wellTypedRun (.push (.bigint (a + b)) :: .opcode "OP_ADD" :: applyPushAddPushAdd rest') s
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · exact True.intro  -- precondMet .none
    intro s' hStepPush
    have hStepDef : stepNonIf (.push (.bigint (a + b))) s = .ok (s.push (.vBigint (a + b))) :=
      stepNonIf_push_bigint s (a + b)
    have hSEq : s' = s.push (.vBigint (a + b)) := by
      rw [hStepDef] at hStepPush
      exact ((Except.ok.injEq _ _).mp hStepPush).symm
    rw [hSEq]
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · -- precondMet (.twoInts) (s.push (.vBigint (a+b))). The post-push stack is
      -- .vBigint (a+b) :: s.stack = .vBigint (a+b) :: .vBigint x :: rest_stack.
      have hPushed : (s.push (.vBigint (a + b))).stack
                   = .vBigint (a + b) :: .vBigint x :: rest_stack := by
        unfold StackState.push; simp [hStack]
      show precondMet (opPrecondition (.opcode "OP_ADD")) (s.push (.vBigint (a + b)))
      unfold opPrecondition
      show precondMet .twoInts (s.push (.vBigint (a + b)))
      have hUnfold : precondMet .twoInts (s.push (.vBigint (a + b)))
                  = (match (s.push (.vBigint (a + b))).stack with
                     | .vBigint _ :: .vBigint _ :: _ => True
                     | _ => False) := rfl
      rw [hUnfold, hPushed]
      exact True.intro
    · intro s'' hStepAdd
      have hPushed : (s.push (.vBigint (a + b))).stack
                   = .vBigint (a + b) :: .vBigint x :: rest_stack := by
        unfold StackState.push; simp [hStack]
      have hStepAddDef : stepNonIf (.opcode "OP_ADD") (s.push (.vBigint (a + b)))
                = .ok (({ s with stack := rest_stack } : StackState).push (.vBigint (x + (a + b)))) := by
        rw [stepNonIf_opcode]
        rw [runOpcode_add_int_concrete _ x (a + b) rest_stack hPushed]
        cases s; simp [StackState.push]
      have hSEq2 : s'' = ({ s with stack := rest_stack } : StackState).push (.vBigint (x + (a + b))) := by
        rw [hStepAddDef] at hStepAdd
        exact ((Except.ok.injEq _ _).mp hStepAdd).symm
      rw [hSEq2]
      exact ihRes
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyPushAddPushAdd (op :: rest')
        = op :: applyPushAddPushAdd rest' :=
      applyPushAddPushAdd.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyPushAddPushAdd rest') s hWT
      (fun s' _ hWTRest => ih hRestNoIf s' hWTRest)

theorem applyPushAddPushSub_preserves_wellTypedRun :
    ∀ (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (applyPushAddPushSub ops) s := by
  intro ops
  induction ops using applyPushAddPushSub.induct with
  | case1 => intro _ s _; exact True.intro
  | case2 a b rest' ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      change noIfOp (.push (.bigint a) :: .opcode "OP_SUB" ::
                     .push (.bigint b) :: .opcode "OP_SUB" :: rest') at hNoIf
      change noIfOp rest'
      exact hNoIf
    obtain ⟨x, rest_stack, hStack⟩ := chainFold_extract_int_top_sub s a _ hWT
    have hWTafter : wellTypedRun rest'
        (({ s with stack := rest_stack } : StackState).push (.vBigint (x - (a + b)))) := by
      have ⟨_, hC0⟩ := wellTypedRun_cons _ _ _ |>.mp hWT
      have hStepPushA : stepNonIf (.push (.bigint a)) s = .ok (s.push (.vBigint a)) :=
        stepNonIf_push_bigint s a
      have hW1 : wellTypedRun (.opcode "OP_SUB" :: .push (.bigint b) :: .opcode "OP_SUB" :: rest')
                  (s.push (.vBigint a)) := hC0 _ hStepPushA
      have ⟨_, hC1⟩ := wellTypedRun_cons _ _ _ |>.mp hW1
      have hPushedA : (s.push (.vBigint a)).stack = .vBigint a :: .vBigint x :: rest_stack := by
        unfold StackState.push; simp [hStack]
      have hStepSubA : stepNonIf (.opcode "OP_SUB") (s.push (.vBigint a))
                  = .ok (({ s with stack := rest_stack } : StackState).push (.vBigint (x - a))) := by
        rw [stepNonIf_opcode]
        rw [runOpcode_sub_int_concrete _ x a rest_stack hPushedA]
        cases s; simp [StackState.push]
      have hW2 : wellTypedRun (.push (.bigint b) :: .opcode "OP_SUB" :: rest')
                  (({ s with stack := rest_stack } : StackState).push (.vBigint (x - a))) :=
        hC1 _ hStepSubA
      have ⟨_, hC2⟩ := wellTypedRun_cons _ _ _ |>.mp hW2
      have hStepPushB : stepNonIf (.push (.bigint b))
                          (({ s with stack := rest_stack } : StackState).push (.vBigint (x - a)))
                = .ok ((({ s with stack := rest_stack } : StackState).push (.vBigint (x - a))).push
                        (.vBigint b)) :=
        stepNonIf_push_bigint _ b
      have hW3 : wellTypedRun (.opcode "OP_SUB" :: rest')
                  ((({ s with stack := rest_stack } : StackState).push (.vBigint (x - a))).push
                    (.vBigint b)) := hC2 _ hStepPushB
      have ⟨_, hC3⟩ := wellTypedRun_cons _ _ _ |>.mp hW3
      have hPushedB : ((({ s with stack := rest_stack } : StackState).push (.vBigint (x - a))).push
                        (.vBigint b)).stack
                    = .vBigint b :: .vBigint (x - a) :: rest_stack := by
        unfold StackState.push; simp
      have hStepSubB : stepNonIf (.opcode "OP_SUB")
                  ((({ s with stack := rest_stack } : StackState).push (.vBigint (x - a))).push
                    (.vBigint b))
                  = .ok (({ s with stack := rest_stack } : StackState).push
                          (.vBigint ((x - a) - b))) := by
        rw [stepNonIf_opcode]
        rw [runOpcode_sub_int_concrete _ (x - a) b rest_stack hPushedB]
        cases s; simp [StackState.push]
      have hW4 := hC3 _ hStepSubB
      have hSubAssoc : (x - a) - b = x - (a + b) := by omega
      rw [hSubAssoc] at hW4
      exact hW4
    have ihRes : wellTypedRun (applyPushAddPushSub rest')
                  (({ s with stack := rest_stack } : StackState).push (.vBigint (x - (a + b)))) :=
      ih hRestNoIf _ hWTafter
    show wellTypedRun (.push (.bigint (a + b)) :: .opcode "OP_SUB" :: applyPushAddPushSub rest') s
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · exact True.intro
    intro s' hStepPush
    have hStepDef : stepNonIf (.push (.bigint (a + b))) s = .ok (s.push (.vBigint (a + b))) :=
      stepNonIf_push_bigint s (a + b)
    have hSEq : s' = s.push (.vBigint (a + b)) := by
      rw [hStepDef] at hStepPush
      exact ((Except.ok.injEq _ _).mp hStepPush).symm
    rw [hSEq]
    refine (wellTypedRun_cons _ _ _).mpr ⟨?_, ?_⟩
    · have hPushed : (s.push (.vBigint (a + b))).stack
                   = .vBigint (a + b) :: .vBigint x :: rest_stack := by
        unfold StackState.push; simp [hStack]
      show precondMet (opPrecondition (.opcode "OP_SUB")) (s.push (.vBigint (a + b)))
      unfold opPrecondition
      show precondMet .twoInts (s.push (.vBigint (a + b)))
      have hUnfold : precondMet .twoInts (s.push (.vBigint (a + b)))
                  = (match (s.push (.vBigint (a + b))).stack with
                     | .vBigint _ :: .vBigint _ :: _ => True
                     | _ => False) := rfl
      rw [hUnfold, hPushed]
      exact True.intro
    · intro s'' hStepSub
      have hPushed : (s.push (.vBigint (a + b))).stack
                   = .vBigint (a + b) :: .vBigint x :: rest_stack := by
        unfold StackState.push; simp [hStack]
      have hStepSubDef : stepNonIf (.opcode "OP_SUB") (s.push (.vBigint (a + b)))
                = .ok (({ s with stack := rest_stack } : StackState).push (.vBigint (x - (a + b)))) := by
        rw [stepNonIf_opcode]
        rw [runOpcode_sub_int_concrete _ x (a + b) rest_stack hPushed]
        cases s; simp [StackState.push]
      have hSEq2 : s'' = ({ s with stack := rest_stack } : StackState).push (.vBigint (x - (a + b))) := by
        rw [hStepSubDef] at hStepSub
        exact ((Except.ok.injEq _ _).mp hStepSub).symm
      rw [hSEq2]
      exact ihRes
  | case3 op rest' h_no_match ih =>
    intro hNoIf s hWT
    have hRestNoIf : noIfOp rest' := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hRewrite :
        applyPushAddPushSub (op :: rest')
        = op :: applyPushAddPushSub rest' :=
      applyPushAddPushSub.eq_3 op rest' h_no_match
    rw [hRewrite]
    exact wellTypedRun_cons_via_ih op rest' (applyPushAddPushSub rest') s hWT
      (fun s' _ hWTRest => ih hRestNoIf s' hWTRest)

/-! ### Fixpoint operational soundness — `chainFoldFixpointFlat`. -/

/-- Induct on fuel. Each iteration applies `applyPushAddPushAdd` then
`applyPushAddPushSub`, both `_runOps_eq` under `noIfOp + wellTypedRun`.
Both sub-rules also preserve `noIfOp` and `wellTypedRun`, so the IH at
the next fuel step applies. -/
theorem chainFoldFixpointFlat_runOps_eq :
    ∀ (fuel : Nat) (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        runOps (chainFoldFixpointFlat fuel ops) s = runOps ops s := by
  intro fuel
  induction fuel with
  | zero =>
    intro ops _ s _
    show runOps (chainFoldFixpointFlat 0 ops) s = runOps ops s
    simp [chainFoldFixpointFlat]
  | succ k ih =>
    intro ops hNoIf s hWT
    show runOps (chainFoldFixpointFlat (k + 1) ops) s = runOps ops s
    unfold chainFoldFixpointFlat
    -- Goal: runOps (let next := ...; if next.length = ops.length then ops else chainFoldFixpointFlat k next) s = runOps ops s
    by_cases hLen : (applyPushAddPushSub (applyPushAddPushAdd ops)).length = ops.length
    · simp [hLen]
    · simp [hLen]
      -- Goal: runOps (chainFoldFixpointFlat k next) s = runOps ops s where next = applyPushAddPushSub (applyPushAddPushAdd ops)
      -- Strategy: chain rewrites using IH, _Sub_runOps_eq, _Add_runOps_eq.
      -- First show wellTypedRun and noIfOp for `applyPushAddPushAdd ops` and the next.
      have hNoIfAdd : noIfOp (applyPushAddPushAdd ops) :=
        applyPushAddPushAdd_preserves_noIfOp ops hNoIf
      have hWTAdd : wellTypedRun (applyPushAddPushAdd ops) s :=
        applyPushAddPushAdd_preserves_wellTypedRun ops hNoIf s hWT
      have hNoIfSub : noIfOp (applyPushAddPushSub (applyPushAddPushAdd ops)) :=
        applyPushAddPushSub_preserves_noIfOp _ hNoIfAdd
      have hWTSub : wellTypedRun (applyPushAddPushSub (applyPushAddPushAdd ops)) s :=
        applyPushAddPushSub_preserves_wellTypedRun _ hNoIfAdd s hWTAdd
      -- Apply IH at fuel k on the next list.
      have hIH := ih (applyPushAddPushSub (applyPushAddPushAdd ops)) hNoIfSub s hWTSub
      -- Chain: chainFoldFixpointFlat k next preserves runOps from next, which equals
      -- ops by _Sub then _Add.
      rw [hIH]
      rw [applyPushAddPushSub_runOps_eq _ hNoIfAdd s hWTAdd]
      rw [applyPushAddPushAdd_runOps_eq ops hNoIf s hWT]

theorem chainFoldFixpointFlat_preserves_noIfOp :
    ∀ (fuel : Nat) (ops : List StackOp), noIfOp ops →
        noIfOp (chainFoldFixpointFlat fuel ops) := by
  intro fuel
  induction fuel with
  | zero => intro ops h; simpa [chainFoldFixpointFlat] using h
  | succ k ih =>
    intro ops h
    unfold chainFoldFixpointFlat
    by_cases hLen : (applyPushAddPushSub (applyPushAddPushAdd ops)).length = ops.length
    · simp [hLen]; exact h
    · simp [hLen]
      have hNoIfAdd : noIfOp (applyPushAddPushAdd ops) :=
        applyPushAddPushAdd_preserves_noIfOp ops h
      have hNoIfSub : noIfOp (applyPushAddPushSub (applyPushAddPushAdd ops)) :=
        applyPushAddPushSub_preserves_noIfOp _ hNoIfAdd
      exact ih _ hNoIfSub

theorem chainFoldFixpointFlat_preserves_wellTypedRun :
    ∀ (fuel : Nat) (ops : List StackOp), noIfOp ops →
      ∀ (s : StackState), wellTypedRun ops s →
        wellTypedRun (chainFoldFixpointFlat fuel ops) s := by
  intro fuel
  induction fuel with
  | zero => intro ops _ s hWT; simpa [chainFoldFixpointFlat] using hWT
  | succ k ih =>
    intro ops hNoIf s hWT
    unfold chainFoldFixpointFlat
    by_cases hLen : (applyPushAddPushSub (applyPushAddPushAdd ops)).length = ops.length
    · simp [hLen]; exact hWT
    · simp [hLen]
      have hNoIfAdd : noIfOp (applyPushAddPushAdd ops) :=
        applyPushAddPushAdd_preserves_noIfOp ops hNoIf
      have hWTAdd : wellTypedRun (applyPushAddPushAdd ops) s :=
        applyPushAddPushAdd_preserves_wellTypedRun ops hNoIf s hWT
      have hNoIfSub : noIfOp (applyPushAddPushSub (applyPushAddPushAdd ops)) :=
        applyPushAddPushSub_preserves_noIfOp _ hNoIfAdd
      have hWTSub : wellTypedRun (applyPushAddPushSub (applyPushAddPushAdd ops)) s :=
        applyPushAddPushSub_preserves_wellTypedRun _ hNoIfAdd s hWTAdd
      exact ih _ hNoIfSub s hWTSub

/-! ### Top-level operational soundness — `peepholeChainFold`.

Under `noIfOp + wellTypedRun`, `chainFoldListTRgo` is the identity:
since `chainFoldOp` only fires on `.ifOp` constructors and the input
has none, the tail-recursive walker simply re-orders the accumulator
into the original list. Then `peepholeChainFold ops = chainFoldFixpointFlat
64 ops`, and the fixpoint theorem closes the equality. -/

/-- For non-`.ifOp` ops, `chainFoldOp` is the identity. -/
private theorem chainFoldOp_id_of_not_ifOp (op : StackOp)
    (h : ∀ thn els, op ≠ .ifOp thn els) :
    chainFoldOp op = op := by
  cases op with
  | ifOp thn els => exact absurd rfl (h thn els)
  | push v          => unfold chainFoldOp; rfl
  | dup             => unfold chainFoldOp; rfl
  | swap            => unfold chainFoldOp; rfl
  | drop            => unfold chainFoldOp; rfl
  | nip             => unfold chainFoldOp; rfl
  | over            => unfold chainFoldOp; rfl
  | rot             => unfold chainFoldOp; rfl
  | tuck            => unfold chainFoldOp; rfl
  | roll d          => unfold chainFoldOp; rfl
  | pick d          => unfold chainFoldOp; rfl
  | pickStruct d    => unfold chainFoldOp; rfl
  | opcode code     => unfold chainFoldOp; rfl
  | placeholder i n => unfold chainFoldOp; rfl
  | pushCodesepIndex => unfold chainFoldOp; rfl
  | rawBytes b      => unfold chainFoldOp; rfl

/-- `chainFoldListTRgo` is left-fold-then-reverse: under `noIfOp ops`,
each `chainFoldOp op = op`, so the walker simply prepends ops to acc and
reverses, yielding `acc.reverse ++ ops`. -/
private theorem chainFoldListTRgo_eq_of_noIfOp :
    ∀ (ops : List StackOp) (acc : List StackOp), noIfOp ops →
        chainFoldListTRgo ops acc = acc.reverse ++ ops := by
  intro ops
  induction ops with
  | nil =>
    intro acc _
    show chainFoldListTRgo [] acc = acc.reverse ++ []
    unfold chainFoldListTRgo
    simp
  | cons op rest ih =>
    intro acc hNoIf
    have hRest : noIfOp rest := by
      cases op with
      | ifOp _ _ => exact absurd hNoIf (by simp [noIfOp])
      | _ => simpa [noIfOp] using hNoIf
    have hOpId : chainFoldOp op = op := by
      apply chainFoldOp_id_of_not_ifOp
      intro thn els hEq
      rw [hEq] at hNoIf
      exact absurd hNoIf (by simp [noIfOp])
    show chainFoldListTRgo (op :: rest) acc = acc.reverse ++ (op :: rest)
    unfold chainFoldListTRgo
    rw [hOpId]
    have ihAcc := ih (op :: acc) hRest
    rw [ihAcc]
    simp

/-- Specialization: `chainFoldListTRgo ops [] = ops` for `noIfOp ops`. -/
private theorem chainFoldListTRgo_nil_acc_of_noIfOp
    (ops : List StackOp) (h : noIfOp ops) :
    chainFoldListTRgo ops [] = ops := by
  rw [chainFoldListTRgo_eq_of_noIfOp ops [] h]
  simp

theorem peepholeChainFold_preserves_noIfOp
    (ops : List StackOp) (hNoIf : noIfOp ops) :
    noIfOp (peepholeChainFold ops) := by
  unfold peepholeChainFold
  rw [chainFoldListTRgo_nil_acc_of_noIfOp ops hNoIf]
  exact chainFoldFixpointFlat_preserves_noIfOp 64 ops hNoIf

theorem peepholeChainFold_runOps_eq (ops : List StackOp) (s : StackState)
    (hNoIf : noIfOp ops) (hWT : wellTypedRun ops s) :
    runOps (peepholeChainFold ops) s = runOps ops s := by
  unfold peepholeChainFold
  rw [chainFoldListTRgo_nil_acc_of_noIfOp ops hNoIf]
  exact chainFoldFixpointFlat_runOps_eq 64 ops hNoIf s hWT

/-! ### Pure syntactic chain-fold identity on push-free lists (M3 substrate)

The two 4-op chain-fold rules (`applyPushAddPushAdd` /
`applyPushAddPushSub`) only fire on windows beginning with
`.push (.bigint _)`. On a `pushFree` list neither window ever matches, so
each pass is the identity, the fixpoint length-check stabilises after one
iteration, and `peepholeChainFold` reduces to its input. This is the
file-local twin of `peepholeRollPickFold_eq_self_of_noIfOp_flatNoop`. -/

/-- On a `pushFree` list, `applyPushAddPushAdd` is the identity: every
4-op window's lead op is non-`.push`, so the rewrite arm never fires. -/
private theorem applyPushAddPushAdd_eq_self_of_pushFree :
    ∀ (ops : List StackOp), pushFree ops → applyPushAddPushAdd ops = ops := by
  intro ops
  induction ops with
  | nil => intro _; rfl
  | cons op rest ih =>
      intro hPF
      have hRest : pushFree rest := by
        cases op with
        | push _ => exact absurd hPF (by simp [pushFree])
        | _ => simpa [pushFree] using hPF
      cases op with
      | push _ => exact absurd hPF (by simp [pushFree])
      | _ => simp [applyPushAddPushAdd, ih hRest]

/-- On a `pushFree` list, `applyPushAddPushSub` is the identity. -/
private theorem applyPushAddPushSub_eq_self_of_pushFree :
    ∀ (ops : List StackOp), pushFree ops → applyPushAddPushSub ops = ops := by
  intro ops
  induction ops with
  | nil => intro _; rfl
  | cons op rest ih =>
      intro hPF
      have hRest : pushFree rest := by
        cases op with
        | push _ => exact absurd hPF (by simp [pushFree])
        | _ => simpa [pushFree] using hPF
      cases op with
      | push _ => exact absurd hPF (by simp [pushFree])
      | _ => simp [applyPushAddPushSub, ih hRest]

/-- The composed chain-fold step is the identity on a `pushFree` list. -/
private theorem chainFoldStep_eq_self_of_pushFree
    (ops : List StackOp) (hPF : pushFree ops) :
    applyPushAddPushSub (applyPushAddPushAdd ops) = ops := by
  rw [applyPushAddPushAdd_eq_self_of_pushFree ops hPF]
  exact applyPushAddPushSub_eq_self_of_pushFree ops hPF

/-- `chainFoldFixpointFlat` is the identity on a `pushFree` list at any
fuel: the composed step returns the input, so the length check stabilises
on the first iteration. -/
private theorem chainFoldFixpointFlat_eq_self_of_pushFree :
    ∀ (fuel : Nat) (ops : List StackOp), pushFree ops →
        chainFoldFixpointFlat fuel ops = ops := by
  intro fuel
  cases fuel with
  | zero => intro ops _; simp [chainFoldFixpointFlat]
  | succ k =>
      intro ops hPF
      unfold chainFoldFixpointFlat
      simp [chainFoldStep_eq_self_of_pushFree ops hPF]

/-- Pure syntactic identity: `peepholeChainFold` is the identity on op
lists that are both if-free and push-free. The arith consume fragment
lowers to `[.swap, .opcode …]` (no `.push`, no `.ifOp`), so both
hypotheses hold at that call site. This retires the M3 substrate gap
without the `wellTypedRun` precondition of
`peepholeChainFold_runOps_eq`. -/
theorem peepholeChainFold_eq_self_of_noIfOp_pushFree
    (ops : List StackOp) (hNoIf : noIfOp ops) (hPushFree : pushFree ops) :
    peepholeChainFold ops = ops := by
  unfold peepholeChainFold
  rw [chainFoldListTRgo_nil_acc_of_noIfOp ops hNoIf]
  exact chainFoldFixpointFlat_eq_self_of_pushFree 64 ops hPushFree

/-! ### Smoke test — `peepholeChainFold_eq_self_of_noIfOp_pushFree`.

Instantiate the lemma on the lowered wave-19 `add3sub` method body
(`[.swap, OP_ADD, .swap, OP_SUB, OP_NEGATE]`): push-free, if-free arith
ops. The fold must return the list unchanged. -/

private def chainFoldSmokeOps : List StackOp :=
  [.swap, .opcode "OP_ADD", .swap, .opcode "OP_SUB", .opcode "OP_NEGATE"]

private theorem chainFoldSmoke_noIfOp : noIfOp chainFoldSmokeOps := by
  unfold chainFoldSmokeOps; decide

private theorem chainFoldSmoke_pushFree : pushFree chainFoldSmokeOps := by
  unfold chainFoldSmokeOps; decide

example : peepholeChainFold chainFoldSmokeOps = chainFoldSmokeOps :=
  peepholeChainFold_eq_self_of_noIfOp_pushFree chainFoldSmokeOps
    chainFoldSmoke_noIfOp chainFoldSmoke_pushFree

/-- `chainFoldFixpointFlat` is the identity on the empty op list at any
fuel: each iteration's length check immediately stabilises. -/
private theorem chainFoldFixpointFlat_nil :
    ∀ (fuel : Nat), chainFoldFixpointFlat fuel ([] : List StackOp) = [] := by
  intro fuel
  cases fuel with
  | zero => unfold chainFoldFixpointFlat; rfl
  | succ k =>
    unfold chainFoldFixpointFlat
    have hNext : applyPushAddPushSub (applyPushAddPushAdd ([] : List StackOp)) = [] := rfl
    simp [hNext]

/-- `peepholeChainFold` is the identity on the empty op list. Used by the
absent-method case of `Pipeline.peepholeProgram_bodyOf`. -/
theorem peepholeChainFold_nil : peepholeChainFold ([] : List StackOp) = [] := by
  unfold peepholeChainFold
  rw [chainFoldListTRgo_nil_acc_of_noIfOp [] (by simp [noIfOp])]
  exact chainFoldFixpointFlat_nil 64

/-- `peepholeRollPickFold` is the identity on the empty op list. Used by
the absent-method case of `Pipeline.peepholeProgram_bodyOf`. -/
theorem peepholeRollPickFold_nil :
    peepholeRollPickFold ([] : List StackOp) = [] :=
  peepholeRollPickFold_eq_self_of_noIfOp_flatNoop [] (by simp [noIfOp])
    (by intro op hOp; exact absurd hOp (by simp))

end Peephole
end RunarVerification.Stack
