import RunarVerification.ANF.Eval
import RunarVerification.Stack.Eval
import RunarVerification.Stack.Lower

/-!
# Stack IR — Forward simulation lemmas (Phase 3a)

This file holds the **byte-exact lowering identities** for every
constructor in `SimpleANF`. Each lemma is a syntactic equality (`rfl`)
between the result of `lowerValue` and a hand-written op list — they
document the dispatch table in `Lower.lean` and serve as rewrite rules
that Phase 3b's full forward-simulation theorem will compose with the
operational semantics in `Stack.Eval`.

**Phase 3a deliberately stops at the lowering level.** Phase 3b's
operational proof — that `runOps (lowerValue …) ≈ evalValue …` —
requires a `sim` relation across `ANF.Eval.State` and
`Stack.Eval.StackState` and a per-binding induction; both are
substantial enough to merit their own session. The identities below
are the load-bearing input to that proof.
-/

namespace RunarVerification.Stack
namespace Sim

open RunarVerification.ANF
open RunarVerification.Stack.Lower
open RunarVerification.Stack.Eval

/-! ## Per-constructor lowering identities (refl)

For each `simpleValue` constructor, `lowerValue` produces a specific
op list determined entirely by the constructor's payload and the
incoming `StackMap`. These identities pin down the dispatch table.
-/

theorem lower_loadConst_int (sm : StackMap) (bn : String) (i : Int) :
    lowerValue sm bn (.loadConst (.int i)) = ([.push (.bigint i)], sm.push bn) := rfl

theorem lower_loadConst_bool (sm : StackMap) (bn : String) (b : Bool) :
    lowerValue sm bn (.loadConst (.bool b)) = ([.push (.bool b)], sm.push bn) := rfl

theorem lower_loadConst_bytes (sm : StackMap) (bn : String) (b : ByteArray) :
    lowerValue sm bn (.loadConst (.bytes b)) = ([.push (.bytes b)], sm.push bn) := rfl

theorem lower_loadConst_thisRef (sm : StackMap) (bn : String) :
    lowerValue sm bn (.loadConst .thisRef) = ([], sm) := rfl

theorem lower_loadConst_refAlias (sm : StackMap) (bn : String) (n : String) :
    lowerValue sm bn (.loadConst (.refAlias n)) = (loadRef sm n, sm.push bn) := rfl

theorem lower_loadParam (sm : StackMap) (bn : String) (n : String) :
    lowerValue sm bn (.loadParam n) = (loadRef sm n, sm.push bn) := rfl

theorem lower_loadProp (sm : StackMap) (bn : String) (n : String) :
    lowerValue sm bn (.loadProp n) = (loadRef sm n, sm.push bn) := rfl

theorem lower_unaryOp (sm : StackMap) (bn : String) (op operand : String) (rt : Option String) :
    lowerValue sm bn (.unaryOp op operand rt) =
      (loadRef sm operand ++ [.opcode (unaryOpcode op)], sm.push bn) := rfl

theorem lower_assert (sm : StackMap) (bn : String) (ref : String) :
    lowerValue sm bn (.assert ref) = (loadRef sm ref ++ [.opcode "OP_VERIFY"], sm) := rfl

/-- The byte-equality variant of `!==` appends `OP_NOT` for invert. -/
theorem lower_binOp_neq_bytes
    (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "!==" l r (some "bytes")) =
      (loadRef sm l ++ loadRef (sm.push l) r ++
        [.opcode (binopOpcode "!==" (some "bytes"))] ++ [.opcode "OP_NOT"],
       sm.push bn) := rfl

/-- Concrete binop expansions (one lemma per primitive). -/
theorem lower_binOp_add (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "+" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_ADD"], sm.push bn) := rfl

theorem lower_binOp_sub (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "-" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_SUB"], sm.push bn) := rfl

theorem lower_binOp_mul (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "*" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_MUL"], sm.push bn) := rfl

/-! ## `lowerArgs` reduction lemmas (used by `call` lowering identities) -/

theorem lowerArgs_nil (sm : StackMap) :
    lowerArgs sm [] = ([], sm) := rfl

theorem lowerArgs_singleton (sm : StackMap) (x : String) :
    lowerArgs sm [x] = (loadRef sm x, sm.push x) := by
  show (loadRef sm x ++ (lowerArgs (sm.push x) []).fst,
        (lowerArgs (sm.push x) []).snd) = _
  rw [lowerArgs_nil]
  simp

theorem lowerArgs_pair (sm : StackMap) (l r : String) :
    lowerArgs sm [l, r] = (loadRef sm l ++ loadRef (sm.push l) r, (sm.push l).push r) := by
  show (loadRef sm l ++ (lowerArgs (sm.push l) [r]).fst,
        (lowerArgs (sm.push l) [r]).snd) = _
  rw [lowerArgs_singleton]

theorem lowerArgs_singleton_fst (sm : StackMap) (x : String) :
    (lowerArgs sm [x]).fst = loadRef sm x := by
  rw [lowerArgs_singleton]

theorem lowerArgs_pair_fst (sm : StackMap) (l r : String) :
    (lowerArgs sm [l, r]).fst = loadRef sm l ++ loadRef (sm.push l) r := by
  rw [lowerArgs_pair]

theorem lower_call_cat (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.call "cat" [l, r]) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_CAT"], sm.push bn) := by
  unfold lowerValue
  simp only [builtinOpcode, List.map_cons, List.map_nil]
  congr 1
  rw [lowerArgs_pair_fst]

theorem lower_call_sha256 (sm : StackMap) (bn : String) (x : String) :
    lowerValue sm bn (.call "sha256" [x]) =
      (loadRef sm x ++ [.opcode "OP_SHA256"], sm.push bn) := by
  simp [lowerValue, lowerArgs_singleton_fst, builtinOpcode]

/-! ## `loadRef` decision-table identities

The `loadRef` function picks the smallest-byte opcode for the given
stack-map depth: `dup` at depth 0, `over` at depth 1, otherwise
`pick d`. These identities make the choice visible to peephole
soundness proofs.
-/

theorem loadRef_at_top (sm : StackMap) (n : String)
    (h : sm.depth? n = some 0) :
    loadRef sm n = [.dup] := by
  unfold loadRef
  rw [h]

theorem loadRef_at_depth_1 (sm : StackMap) (n : String)
    (h : sm.depth? n = some 1) :
    loadRef sm n = [.over] := by
  unfold loadRef
  rw [h]

theorem loadRef_at_depth_ge_2 (sm : StackMap) (n : String) (d : Nat)
    (hd : d ≥ 2) (h : sm.depth? n = some d) :
    loadRef sm n = [.pick d] := by
  unfold loadRef
  rw [h]
  match d, hd with
  | d + 2, _ => rfl

/-! ## Top-level shape preservation

`lower` preserves the contract name, method count, and per-method
name. These are what `Pipeline.lean`'s top-level theorem composes
with the simulation lemmas above.
-/

theorem lower_preserves_contract_name (p : ANFProgram) :
    (lower p).contractName = p.contractName := rfl

theorem lower_preserves_method_count (p : ANFProgram) :
    (lower p).methods.length = (p.methods.filter (·.isPublic)).length := by
  unfold lower
  simp

theorem lower_method_name_preserved (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod) :
    (lowerMethod progMethods props m).name = m.name := rfl

/-! ## Empty-program lowering -/

theorem lower_empty_program (cn : String) :
    lower { contractName := cn, properties := [], methods := [] } =
      { contractName := cn, methods := [] } := rfl

/-! ## SimpleANF stability under no-op constructors

Constructors that produce no stack ops (e.g., `loadConst .thisRef`) do
not modify the runtime stack. The lemma is the formal statement that
`thisRef` is a metadata-only constructor.
-/

theorem lower_thisRef_emits_nothing (sm : StackMap) (bn : String) :
    (lowerValue sm bn (.loadConst .thisRef)).fst = [] := rfl

/-! ## Operational lemmas

Run-level identities for the building blocks of `lower`'s output.
With Phase 3c's exposure of `Stack.Eval`'s helpers and the
`def`+`termination_by` rewrite, every reduction step is now visible
to `rw` and `simp`.
-/

theorem run_empty (s : StackState) : runOps [] s = .ok s := by
  unfold runOps; rfl

/-! ### Single-op runs -/

theorem run_push_bigint (s : StackState) (i : Int) :
    runOps [.push (.bigint i)] s = .ok (s.push (.vBigint i)) := by
  show runOps (.push (.bigint i) :: []) s = _
  unfold runOps
  rw [stepNonIf_push_bigint]
  simp [run_empty]

theorem run_push_bool (s : StackState) (b : Bool) :
    runOps [.push (.bool b)] s = .ok (s.push (.vBool b)) := by
  show runOps (.push (.bool b) :: []) s = _
  unfold runOps
  rw [stepNonIf_push_bool]
  simp [run_empty]

theorem run_push_bytes (s : StackState) (b : ByteArray) :
    runOps [.push (.bytes b)] s = .ok (s.push (.vBytes b)) := by
  show runOps (.push (.bytes b) :: []) s = _
  unfold runOps
  rw [stepNonIf_push_bytes]
  simp [run_empty]

/-! ### `OP_VERIFY` against `vBool` top-of-stack -/

theorem runOpcode_verify_true (s : StackState) :
    runOpcode "OP_VERIFY" (s.push (.vBool true)) = .ok s := rfl

theorem runOpcode_verify_false (s : StackState) :
    runOpcode "OP_VERIFY" (s.push (.vBool false)) = .error .assertFailed := rfl

theorem run_assert_true (s : StackState) :
    runOps [.opcode "OP_VERIFY"] (s.push (.vBool true)) = .ok s := by
  show runOps (.opcode "OP_VERIFY" :: []) _ = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_verify_true]
  simp [run_empty]

theorem run_assert_false (s : StackState) :
    runOps [.opcode "OP_VERIFY"] (s.push (.vBool false))
    = .error .assertFailed := by
  show runOps (.opcode "OP_VERIFY" :: []) _ = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_verify_false]

end Sim
end RunarVerification.Stack
