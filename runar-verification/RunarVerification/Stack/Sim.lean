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

theorem lower_binOp_div (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "/" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_DIV"], sm.push bn) := rfl

theorem lower_binOp_mod (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "%" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_MOD"], sm.push bn) := rfl

theorem lower_binOp_lt (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "<" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_LESSTHAN"], sm.push bn) := rfl

theorem lower_binOp_lte (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "<=" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_LESSTHANOREQUAL"], sm.push bn) := rfl

theorem lower_binOp_gt (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp ">" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_GREATERTHAN"], sm.push bn) := rfl

theorem lower_binOp_gte (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp ">=" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_GREATERTHANOREQUAL"], sm.push bn) := rfl

theorem lower_binOp_boolAnd (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "&&" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_BOOLAND"], sm.push bn) := rfl

theorem lower_binOp_boolOr (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "||" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_BOOLOR"], sm.push bn) := rfl

theorem lower_binOp_numEq (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "===" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_NUMEQUAL"], sm.push bn) := rfl

theorem lower_binOp_numNeq (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "!==" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_NUMNOTEQUAL"], sm.push bn) := rfl

theorem lower_binOp_bytesEq (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "===" l r (some "bytes")) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_EQUAL"], sm.push bn) := rfl

theorem lower_binOp_andBytes (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "&" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_AND"], sm.push bn) := rfl

theorem lower_binOp_orBytes (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "|" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_OR"], sm.push bn) := rfl

theorem lower_binOp_xorBytes (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "^" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_XOR"], sm.push bn) := rfl

theorem lower_binOp_lshift (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp "<<" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_LSHIFT"], sm.push bn) := rfl

theorem lower_binOp_rshift (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.binOp ">>" l r none) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_RSHIFT"], sm.push bn) := rfl

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

theorem lowerArgs_triple (sm : StackMap) (x y z : String) :
    lowerArgs sm [x, y, z] =
      (loadRef sm x ++ loadRef (sm.push x) y ++ loadRef ((sm.push x).push y) z,
       ((sm.push x).push y).push z) := by
  show (loadRef sm x ++ (lowerArgs (sm.push x) [y, z]).fst,
        (lowerArgs (sm.push x) [y, z]).snd) = _
  rw [lowerArgs_pair]
  simp [List.append_assoc]

theorem lowerArgs_triple_fst (sm : StackMap) (x y z : String) :
    (lowerArgs sm [x, y, z]).fst =
      loadRef sm x ++ loadRef (sm.push x) y ++ loadRef ((sm.push x).push y) z := by
  rw [lowerArgs_triple]

theorem lower_call_cat (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.call "cat" [l, r]) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_CAT"], sm.push bn) := by
  unfold lowerValue
  simp only [builtinOpcode, List.map_cons, List.map_nil]
  congr 1
  rw [lowerArgs_pair_fst]

theorem lower_call_len (sm : StackMap) (bn : String) (x : String) :
    lowerValue sm bn (.call "len" [x]) =
      (loadRef sm x ++ [.opcode "OP_SIZE", .opcode "OP_NIP"], sm.push bn) := by
  simp [lowerValue, lowerArgs_singleton_fst, builtinOpcode]

theorem lower_call_num2bin (sm : StackMap) (bn : String) (n size : String) :
    lowerValue sm bn (.call "num2bin" [n, size]) =
      (loadRef sm n ++ loadRef (sm.push n) size ++ [.opcode "OP_NUM2BIN"], sm.push bn) := by
  unfold lowerValue
  simp only [builtinOpcode, List.map_cons, List.map_nil]
  congr 1
  rw [lowerArgs_pair_fst]

theorem lower_call_split (sm : StackMap) (bn : String) (data index : String) :
    lowerValue sm bn (.call "split" [data, index]) =
      (loadRef sm data ++ loadRef (sm.push data) index ++ [.opcode "OP_SPLIT"], sm.push bn) := by
  unfold lowerValue
  simp only [builtinOpcode, List.map_cons, List.map_nil]
  congr 1
  rw [lowerArgs_pair_fst]

theorem lower_call_bin2num (sm : StackMap) (bn : String) (x : String) :
    lowerValue sm bn (.call "bin2num" [x]) =
      (loadRef sm x ++ [.opcode "OP_BIN2NUM"], sm.push bn) := by
  simp [lowerValue, lowerArgs_singleton_fst, builtinOpcode]

theorem lower_call_toByteString (sm : StackMap) (bn : String) (x : String) :
    lowerValue sm bn (.call "toByteString" [x]) =
      (loadRef sm x, sm.push bn) := by
  simp [lowerValue, lowerArgs_singleton_fst, builtinOpcode]

theorem lower_call_sha256 (sm : StackMap) (bn : String) (x : String) :
    lowerValue sm bn (.call "sha256" [x]) =
      (loadRef sm x ++ [.opcode "OP_SHA256"], sm.push bn) := by
  simp [lowerValue, lowerArgs_singleton_fst, builtinOpcode]

theorem lower_call_abs (sm : StackMap) (bn : String) (x : String) :
    lowerValue sm bn (.call "abs" [x]) =
      (loadRef sm x ++ [.opcode "OP_ABS"], sm.push bn) := by
  simp [lowerValue, lowerArgs_singleton_fst, builtinOpcode]

theorem lower_call_min (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.call "min" [l, r]) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_MIN"], sm.push bn) := by
  unfold lowerValue
  simp only [builtinOpcode, List.map_cons, List.map_nil]
  congr 1
  rw [lowerArgs_pair_fst]

theorem lower_call_max (sm : StackMap) (bn : String) (l r : String) :
    lowerValue sm bn (.call "max" [l, r]) =
      (loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode "OP_MAX"], sm.push bn) := by
  unfold lowerValue
  simp only [builtinOpcode, List.map_cons, List.map_nil]
  congr 1
  rw [lowerArgs_pair_fst]

theorem lower_call_within (sm : StackMap) (bn : String) (x lo hi : String) :
    lowerValue sm bn (.call "within" [x, lo, hi]) =
      (loadRef sm x ++ loadRef (sm.push x) lo ++ loadRef ((sm.push x).push lo) hi ++
        [.opcode "OP_WITHIN"], sm.push bn) := by
  unfold lowerValue
  simp only [builtinOpcode, List.map_cons, List.map_nil]
  congr 1
  rw [lowerArgs_triple_fst]

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
    loadRef sm n = [.pickStruct d] := by
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

/-! ### Phase 6 Step 4 — `loadRef` operational discharge

Each branch of `loadRef`'s 3-case dispatch (depth 0 → `[.dup]`,
depth 1 → `[.over]`, depth ≥ 2 → `[.pickStruct d]`) pushes the
value at the requested structural depth onto the top of the stack,
preserving the rest. These three lemmas give the operational
companion to `agrees_preserved_load{Param,Prop,Const_refAlias}`
in `Stack.Agrees` — combined, they discharge the `hPushed`
hypothesis.

Note `applyDup` is on `Stack.Eval`, accessible as `Stack.Eval.applyDup`.
We use `Stack.Eval.runOps` and the `stepNonIf_*` reduction theorems
already provided by `Eval.lean`. -/

open RunarVerification.ANF.Eval (Value)

/-- Helper: `applyDup` on `s` whose stack starts with `v`. -/
private theorem applyDup_cons_local (s : StackState) (v : Value) (rest : List Value)
    (hs : s.stack = v :: rest) :
    applyDup s = .ok (s.push v) := by
  unfold applyDup
  rw [hs]

/-- Helper: `applyOver` on `s` whose stack starts with `topV :: v :: rest`. -/
private theorem applyOver_cons_local (s : StackState) (topV v : Value)
    (rest : List Value) (hs : s.stack = topV :: v :: rest) :
    applyOver s = .ok (s.push v) := by
  unfold applyOver
  rw [hs]
  show Except.ok ({ s with stack := v :: topV :: v :: rest } : StackState)
       = Except.ok (s.push v)
  unfold StackState.push
  rw [hs]

/-- Helper: `applyPickStruct` at depth `d` when stack length > d
and the value at index `d` equals `v`. -/
private theorem applyPickStruct_at_local (s : StackState) (d : Nat) (v : Value)
    (hLen : d < s.stack.length)
    (hAt  : s.stack[d]! = v) :
    applyPickStruct s d = .ok (s.push v) := by
  unfold applyPickStruct
  rw [if_neg (Nat.not_le_of_lt hLen)]
  rw [hAt]

/-- Single-op run for `.dup` on a non-empty stack: pushes the top. -/
theorem run_dup_nonEmpty (s : StackState) (v : Value) (rest : List Value)
    (hStk : s.stack = v :: rest) :
    runOps [.dup] s = .ok (s.push v) := by
  show runOps (.dup :: []) _ = _
  unfold runOps
  rw [stepNonIf_dup, applyDup_cons_local s v rest hStk]
  simp [run_empty]

/-- Single-op run for `.over` on a stack of length ≥ 2: pushes the
value at depth 1. -/
theorem run_over_deep (s : StackState) (topV v : Value) (rest : List Value)
    (hStk : s.stack = topV :: v :: rest) :
    runOps [.over] s = .ok (s.push v) := by
  show runOps (.over :: []) _ = _
  unfold runOps
  show (match stepNonIf .over s with
        | Except.error e => Except.error e
        | Except.ok s'   => runOps [] s') = _
  have : stepNonIf .over s = applyOver s := rfl
  rw [this, applyOver_cons_local s topV v rest hStk]
  simp [run_empty]

/-- Single-op run for `.pickStruct d` on a stack of length > d:
pushes the value at structural depth `d`. -/
theorem run_pickStruct_at_depth (s : StackState) (d : Nat) (v : Value)
    (hLen : d < s.stack.length)
    (hAt  : s.stack[d]! = v) :
    runOps [.pickStruct d] s = .ok (s.push v) := by
  show runOps (.pickStruct d :: []) _ = _
  unfold runOps
  show (match stepNonIf (.pickStruct d) s with
        | Except.error e => Except.error e
        | Except.ok s'   => runOps [] s') = _
  have : stepNonIf (.pickStruct d) s = applyPickStruct s d := rfl
  rw [this, applyPickStruct_at_local s d v hLen hAt]
  simp [run_empty]

/-! ### Phase 6 Step 6 — `runOps_append` (sequencing)

The fundamental compositional property: running concatenated
op-lists is the same as running the first then sequencing the
result through the second. This is the key prerequisite for the
per-binding induction in `Stack.Agrees` (Stage C).

**Hoist note (2026-05-17).** The proofs were originally implemented
in this file because `Stack.Sim` was the only consumer. Phase B7
(Merkle inductive step) needs the same compositional fact in
`Stack.Merkle`, which is *upstream* of `Stack.Sim` in the import
graph (`Sim` imports `Lower`, which imports `Merkle`). To avoid an
import cycle, both `runOps_append` and the helper
`runOps_cons_nonIf_eq` now live in `Stack.Eval` (next to the other
`runOps_*` reduction lemmas). The names below are re-exports that
preserve every existing call site (`Stack.Sim.runOps_append`,
`Stack.Sim.runOps_cons_nonIf_eq`).
-/

/-- Re-export of `Stack.Eval.runOps_cons_nonIf_eq` to keep
historical `Stack.Sim.runOps_cons_nonIf_eq` references working. -/
theorem runOps_cons_nonIf_eq
    (op : StackOp) (rest : List StackOp) (s : StackState)
    (hNotIf : ∀ thn els, op ≠ .ifOp thn els) :
    runOps (op :: rest) s
    = match stepNonIf op s with
      | .error e => .error e
      | .ok s'   => runOps rest s' :=
  Eval.runOps_cons_nonIf_eq op rest s hNotIf

/-- Re-export of `Stack.Eval.runOps_append` to keep historical
`Stack.Sim.runOps_append` references working. -/
theorem runOps_append : ∀ (ops1 ops2 : List StackOp) (s : StackState),
    runOps (ops1 ++ ops2) s
    = match runOps ops1 s with
      | .error e => .error e
      | .ok s'   => runOps ops2 s' :=
  Eval.runOps_append

/-! ### Phase 6 Step 4 tail — Per-opcode operational reduction

Each lemma below witnesses that `runOpcode` reduces to a specific
`s.push result` form when the stack top has the expected typed
shape. These compose with `runOps_append` to discharge the
`hPushed` hypothesis in Stage B's `agrees_preserved_unaryOp` /
`_binOp` / `_assert` lemmas.

Recipe per lemma:
1. Show `s.stack = [args...] :: rest`.
2. Unfold `runOpcode` for the specific code.
3. Reduce via `liftIntBin`/`liftIntUnary`/`liftBytesBin`/`liftBytesUnary`
   or by direct pattern match.

The lemmas are stated in terms of `s.push v` form for direct
composition with the existing `agreesTagged_loadRef_depth*`
lemmas (which all conclude `... = .ok (s.push v)`). -/

/-! #### `_def` rfl projections — single-arm exposure of `runOpcode`

Each `_def` lemma below is `rfl`-provable because Lean reduces the
literal-string match in `runOpcode` directly to the relevant arm.
We use them to avoid pulling in the entire ~200-line `unfold runOpcode`
match in a single tactic step. -/

theorem runOpcode_ADD_def (s : StackState) :
    runOpcode "OP_ADD" s = liftIntBin s (fun a b => .vBigint (a + b)) := rfl

theorem runOpcode_SUB_def (s : StackState) :
    runOpcode "OP_SUB" s = liftIntBin s (fun a b => .vBigint (a - b)) := rfl

theorem runOpcode_MUL_def (s : StackState) :
    runOpcode "OP_MUL" s = liftIntBin s (fun a b => .vBigint (a * b)) := rfl

theorem runOpcode_DIV_def (s : StackState) :
    runOpcode "OP_DIV" s =
      (match popN s 2 with
       | .error e => .error e
       | .ok (vs, s') =>
           match vs with
           | [b, a] =>
               match asInt? a, asInt? b with
               | some ai, some bi =>
                   if bi == 0 then .error .divByZero else .ok (s'.push (.vBigint (ai / bi)))
               | _, _ => .error (.typeError "OP_DIV expects ints")
           | _ => .error (.unsupported "OP_DIV popN bug")) := rfl

theorem runOpcode_MOD_def (s : StackState) :
    runOpcode "OP_MOD" s =
      (match popN s 2 with
       | .error e => .error e
       | .ok (vs, s') =>
           match vs with
           | [b, a] =>
               match asInt? a, asInt? b with
               | some ai, some bi =>
                   if bi == 0 then .error .divByZero else .ok (s'.push (.vBigint (ai % bi)))
               | _, _ => .error (.typeError "OP_MOD expects ints")
           | _ => .error (.unsupported "OP_MOD popN bug")) := rfl

theorem runOpcode_LSHIFT_def (s : StackState) :
    runOpcode "OP_LSHIFT" s
    = liftIntBin s (fun a b => .vBigint (a * (2 ^ b.toNat))) := rfl

theorem runOpcode_RSHIFT_def (s : StackState) :
    runOpcode "OP_RSHIFT" s
    = liftIntBin s (fun a b => .vBigint (a / (2 ^ b.toNat))) := rfl

theorem runOpcode_MIN_def (s : StackState) :
    runOpcode "OP_MIN" s = liftIntBin s (fun a b => .vBigint (min a b)) := rfl

theorem runOpcode_MAX_def (s : StackState) :
    runOpcode "OP_MAX" s = liftIntBin s (fun a b => .vBigint (max a b)) := rfl

theorem runOpcode_WITHIN_def (s : StackState) :
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

theorem runOpcode_LESSTHAN_def (s : StackState) :
    runOpcode "OP_LESSTHAN" s
    = liftIntBin s (fun a b => .vBool (decide (a < b))) := rfl

theorem runOpcode_GREATERTHAN_def (s : StackState) :
    runOpcode "OP_GREATERTHAN" s
    = liftIntBin s (fun a b => .vBool (decide (a > b))) := rfl

theorem runOpcode_LESSTHANOREQUAL_def (s : StackState) :
    runOpcode "OP_LESSTHANOREQUAL" s
    = liftIntBin s (fun a b => .vBool (decide (a ≤ b))) := rfl

theorem runOpcode_GREATERTHANOREQUAL_def (s : StackState) :
    runOpcode "OP_GREATERTHANOREQUAL" s
    = liftIntBin s (fun a b => .vBool (decide (a ≥ b))) := rfl

theorem runOpcode_NUMEQUAL_def (s : StackState) :
    runOpcode "OP_NUMEQUAL" s
    = liftIntBin s (fun a b => .vBool (decide (a = b))) := rfl

theorem runOpcode_NUMNOTEQUAL_def (s : StackState) :
    runOpcode "OP_NUMNOTEQUAL" s
    = liftIntBin s (fun a b => .vBool (decide (a ≠ b))) := rfl

theorem runOpcode_BOOLAND_def (s : StackState) :
    runOpcode "OP_BOOLAND" s
    = liftIntBin s (fun a b => .vBool (decide (a ≠ 0 ∧ b ≠ 0))) := rfl

theorem runOpcode_BOOLOR_def (s : StackState) :
    runOpcode "OP_BOOLOR" s
    = liftIntBin s (fun a b => .vBool (decide (a ≠ 0 ∨ b ≠ 0))) := rfl

theorem runOpcode_EQUAL_def (s : StackState) :
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

theorem runOpcode_NEGATE_def (s : StackState) :
    runOpcode "OP_NEGATE" s = liftIntUnary s (fun i => .vBigint (-i)) := rfl

theorem runOpcode_ABS_def (s : StackState) :
    runOpcode "OP_ABS" s = liftIntUnary s (fun i => .vBigint i.natAbs) := rfl

theorem runOpcode_1ADD_def (s : StackState) :
    runOpcode "OP_1ADD" s = liftIntUnary s (fun i => .vBigint (i + 1)) := rfl

theorem runOpcode_1SUB_def (s : StackState) :
    runOpcode "OP_1SUB" s = liftIntUnary s (fun i => .vBigint (i - 1)) := rfl

theorem runOpcode_NOT_def (s : StackState) :
    runOpcode "OP_NOT" s
    = (match s.pop? with
       | none => .error (.unsupported "OP_NOT: empty stack")
       | some (v, s') =>
           match asBool? v with
           | some b => .ok (s'.push (.vBool (!b)))
           | none   => .error (.typeError "OP_NOT non-bool")) := rfl

theorem runOpcode_NIP_def (s : StackState) :
    runOpcode "OP_NIP" s = applyNip s := rfl

theorem runOpcode_DROP_def (s : StackState) :
    runOpcode "OP_DROP" s = applyDrop s := rfl

theorem runOpcode_VERIFY_def (s : StackState) :
    runOpcode "OP_VERIFY" s
    = (match s.pop? with
       | none => .error (.unsupported "OP_VERIFY: empty stack")
       | some (v, s') =>
           match asBool? v with
           | some true  => .ok s'
           | some false => .error .assertFailed
           | none       => .error (.typeError "OP_VERIFY: non-bool")) := rfl

theorem runOpcode_CAT_def (s : StackState) :
    runOpcode "OP_CAT" s = liftBytesBin s (fun a b => .vBytes (a ++ b)) := rfl

theorem runOpcode_SPLIT_def (s : StackState) :
    runOpcode "OP_SPLIT" s =
      (match popN s 2 with
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
           | _ => .error (.unsupported "OP_SPLIT popN bug")) := rfl

theorem runOpcode_SIZE_def (s : StackState) :
    runOpcode "OP_SIZE" s =
      (match s.stack with
       | [] => .error (.unsupported "OP_SIZE: empty stack")
       | v :: _ =>
           match asBytes? v with
           | some b => .ok (s.push (.vBigint b.size))
           | none => .error (.typeError "OP_SIZE: not bytes")) := rfl

theorem runOpcode_INVERT_def (s : StackState) :
    runOpcode "OP_INVERT" s = liftBytesUnary s (fun b => .vBytes (invertBytes b)) := rfl

theorem runOpcode_BIN2NUM_def (s : StackState) :
    runOpcode "OP_BIN2NUM" s =
      (match s.pop? with
       | none => .error (.unsupported "OP_BIN2NUM: empty stack")
       | some (v, s') =>
           match asBytes? v with
           | some b => .ok (s'.push (.vBigint (decodeMinimalLE b)))
           | none => .error (.typeError "OP_BIN2NUM: not bytes")) := rfl

theorem runOpcode_NUM2BIN_def (s : StackState) :
    runOpcode "OP_NUM2BIN" s =
      (match popN s 2 with
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
           | _ => .error (.unsupported "OP_NUM2BIN popN bug")) := rfl

theorem runOpcode_AND_def (s : StackState) :
    runOpcode "OP_AND" s = liftBytesBinChecked s (bitwiseBytes "OP_AND" (· &&& ·)) := rfl

theorem runOpcode_OR_def (s : StackState) :
    runOpcode "OP_OR" s = liftBytesBinChecked s (bitwiseBytes "OP_OR" (· ||| ·)) := rfl

theorem runOpcode_XOR_def (s : StackState) :
    runOpcode "OP_XOR" s = liftBytesBinChecked s (bitwiseBytes "OP_XOR" (· ^^^ ·)) := rfl

/-! #### Helper: `popN s 2` on a 2+ stack -/

/-- `popN s 2` when stack starts with two elements `b :: a :: rest`
returns `[b, a]` and the residual state. Mirrors `popN_two_cons` in
Peephole.lean (re-derived here because Sim is upstream of Peephole). -/
private theorem popN_two_local
    (s : StackState) (b a : Value) (rest : List Value)
    (hStk : s.stack = b :: a :: rest) :
    popN s 2 = .ok ([b, a], { s with stack := rest }) := by
  unfold popN StackState.pop?
  rw [hStk]
  simp only [popN, StackState.pop?]

/-- `popN s 3` when stack starts with three elements
`c :: b :: a :: rest` returns `[c, b, a]` and the residual state. -/
private theorem popN_three_local
    (s : StackState) (c b a : Value) (rest : List Value)
    (hStk : s.stack = c :: b :: a :: rest) :
    popN s 3 = .ok ([c, b, a], { s with stack := rest }) := by
  unfold popN StackState.pop?
  rw [hStk]
  simp only [popN, StackState.pop?]

/-- `OP_VERIFY` succeeds on a `vBool true` top, returning the
popped state (no push). -/
theorem runOpcode_verify_pop_vBool_true
    (s : StackState) (rest : List Value)
    (hStk : s.stack = .vBool true :: rest) :
    runOpcode "OP_VERIFY" s = .ok { s with stack := rest } := by
  rw [runOpcode_VERIFY_def]
  unfold StackState.pop?
  rw [hStk]
  simp [asBool?]

/-- `OP_VERIFY` fails on a `vBool false` top. -/
theorem runOpcode_verify_pop_vBool_false
    (s : StackState) (rest : List Value)
    (hStk : s.stack = .vBool false :: rest) :
    runOpcode "OP_VERIFY" s = .error .assertFailed := by
  rw [runOpcode_VERIFY_def]
  unfold StackState.pop?
  rw [hStk]
  simp [asBool?]

/-! #### Binary integer ops (`liftIntBin`-shaped) -/

/-- `OP_ADD` on a 2-int stack: pushes `a + b`. -/
theorem runOpcode_ADD_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_ADD" s = .ok ({ s with stack := rest }.push (.vBigint (a + b))) := by
  rw [runOpcode_ADD_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_SUB_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_SUB" s = .ok ({ s with stack := rest }.push (.vBigint (a - b))) := by
  rw [runOpcode_SUB_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_MUL_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_MUL" s = .ok ({ s with stack := rest }.push (.vBigint (a * b))) := by
  rw [runOpcode_MUL_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_DIV_intInt_nonzero
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest)
    (hNonzero : b ≠ 0) :
    runOpcode "OP_DIV" s = .ok ({ s with stack := rest }.push (.vBigint (a / b))) := by
  rw [runOpcode_DIV_def]
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?, hNonzero]

theorem runOpcode_MOD_intInt_nonzero
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest)
    (hNonzero : b ≠ 0) :
    runOpcode "OP_MOD" s = .ok ({ s with stack := rest }.push (.vBigint (a % b))) := by
  rw [runOpcode_MOD_def]
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?, hNonzero]

theorem runOpcode_LSHIFT_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_LSHIFT" s = .ok ({ s with stack := rest }.push (.vBigint (a * (2 ^ b.toNat)))) := by
  rw [runOpcode_LSHIFT_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_RSHIFT_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_RSHIFT" s = .ok ({ s with stack := rest }.push (.vBigint (a / (2 ^ b.toNat)))) := by
  rw [runOpcode_RSHIFT_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_MIN_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_MIN" s = .ok ({ s with stack := rest }.push (.vBigint (min a b))) := by
  rw [runOpcode_MIN_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_MAX_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_MAX" s = .ok ({ s with stack := rest }.push (.vBigint (max a b))) := by
  rw [runOpcode_MAX_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_WITHIN_intIntInt
    (s : StackState) (x lo hi : Int) (rest : List Value)
    (hStk : s.stack = .vBigint hi :: .vBigint lo :: .vBigint x :: rest) :
    runOpcode "OP_WITHIN" s =
      .ok ({ s with stack := rest }.push (.vBool (decide (lo ≤ x ∧ x < hi)))) := by
  rw [runOpcode_WITHIN_def]
  rw [popN_three_local s _ _ _ rest hStk]
  simp [asInt?]

/-! #### Comparison ops (`liftIntBin`-shaped, return `vBool`) -/

theorem runOpcode_LESSTHAN_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_LESSTHAN" s = .ok ({ s with stack := rest }.push (.vBool (decide (a < b)))) := by
  rw [runOpcode_LESSTHAN_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_GREATERTHAN_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_GREATERTHAN" s = .ok ({ s with stack := rest }.push (.vBool (decide (a > b)))) := by
  rw [runOpcode_GREATERTHAN_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_LESSTHANOREQUAL_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_LESSTHANOREQUAL" s = .ok ({ s with stack := rest }.push (.vBool (decide (a ≤ b)))) := by
  rw [runOpcode_LESSTHANOREQUAL_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_GREATERTHANOREQUAL_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_GREATERTHANOREQUAL" s = .ok ({ s with stack := rest }.push (.vBool (decide (a ≥ b)))) := by
  rw [runOpcode_GREATERTHANOREQUAL_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_NUMEQUAL_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_NUMEQUAL" s = .ok ({ s with stack := rest }.push (.vBool (decide (a = b)))) := by
  rw [runOpcode_NUMEQUAL_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_NUMNOTEQUAL_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_NUMNOTEQUAL" s = .ok ({ s with stack := rest }.push (.vBool (decide (a ≠ b)))) := by
  rw [runOpcode_NUMNOTEQUAL_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_BOOLAND_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_BOOLAND" s = .ok ({ s with stack := rest }.push (.vBool (decide (a ≠ 0 ∧ b ≠ 0)))) := by
  rw [runOpcode_BOOLAND_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

theorem runOpcode_BOOLOR_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_BOOLOR" s = .ok ({ s with stack := rest }.push (.vBool (decide (a ≠ 0 ∨ b ≠ 0)))) := by
  rw [runOpcode_BOOLOR_def]
  unfold liftIntBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?]

/-! #### Unary integer ops (`liftIntUnary`-shaped) -/

theorem runOpcode_NEGATE_int
    (s : StackState) (i : Int) (rest : List Value)
    (hStk : s.stack = .vBigint i :: rest) :
    runOpcode "OP_NEGATE" s = .ok ({ s with stack := rest }.push (.vBigint (-i))) := by
  rw [runOpcode_NEGATE_def]
  unfold liftIntUnary StackState.pop?
  rw [hStk]
  simp [asInt?]

theorem runOpcode_ABS_int
    (s : StackState) (i : Int) (rest : List Value)
    (hStk : s.stack = .vBigint i :: rest) :
    runOpcode "OP_ABS" s = .ok ({ s with stack := rest }.push (.vBigint i.natAbs)) := by
  rw [runOpcode_ABS_def]
  unfold liftIntUnary StackState.pop?
  rw [hStk]
  simp [asInt?]

theorem runOpcode_1ADD_int
    (s : StackState) (i : Int) (rest : List Value)
    (hStk : s.stack = .vBigint i :: rest) :
    runOpcode "OP_1ADD" s = .ok ({ s with stack := rest }.push (.vBigint (i + 1))) := by
  rw [runOpcode_1ADD_def]
  unfold liftIntUnary StackState.pop?
  rw [hStk]
  simp [asInt?]

theorem runOpcode_1SUB_int
    (s : StackState) (i : Int) (rest : List Value)
    (hStk : s.stack = .vBigint i :: rest) :
    runOpcode "OP_1SUB" s = .ok ({ s with stack := rest }.push (.vBigint (i - 1))) := by
  rw [runOpcode_1SUB_def]
  unfold liftIntUnary StackState.pop?
  rw [hStk]
  simp [asInt?]

/-! #### Unary boolean op -/

theorem runOpcode_NOT_bool
    (s : StackState) (b : Bool) (rest : List Value)
    (hStk : s.stack = .vBool b :: rest) :
    runOpcode "OP_NOT" s = .ok ({ s with stack := rest }.push (.vBool (!b))) := by
  rw [runOpcode_NOT_def]
  unfold StackState.pop?
  rw [hStk]
  simp [asBool?]

theorem runOpcode_NIP_deep
    (s : StackState) (top second : Value) (rest : List Value)
    (hStk : s.stack = top :: second :: rest) :
    runOpcode "OP_NIP" s = .ok { s with stack := top :: rest } := by
  rw [runOpcode_NIP_def]
  unfold applyNip
  rw [hStk]

theorem runOpcode_DROP_top
    (s : StackState) (top : Value) (rest : List Value)
    (hStk : s.stack = top :: rest) :
    runOpcode "OP_DROP" s = .ok { s with stack := rest } := by
  rw [runOpcode_DROP_def]
  unfold applyDrop
  rw [hStk]

/-! #### Bytes ops -/

theorem runOpcode_CAT_bytesBytes
    (s : StackState) (a b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: .vBytes a :: rest) :
    runOpcode "OP_CAT" s = .ok ({ s with stack := rest }.push (.vBytes (a ++ b))) := by
  rw [runOpcode_CAT_def]
  unfold liftBytesBin
  rw [popN_two_local s _ _ rest hStk]
  simp [asBytes?]

theorem runOpcode_SPLIT_bytesNat
    (s : StackState) (bs : ByteArray) (idx : Nat) (rest : List Value)
    (hStk : s.stack = .vBigint (idx : Int) :: .vBytes bs :: rest)
    (hLe : idx ≤ bs.size) :
    runOpcode "OP_SPLIT" s =
      .ok (({ s with stack := rest }.push (.vBytes (bs.extract 0 idx))).push
        (.vBytes (bs.extract idx bs.size))) := by
  rw [runOpcode_SPLIT_def]
  rw [popN_two_local s _ _ rest hStk]
  have hNonneg : ¬ ((idx : Int) < 0) :=
    Int.not_lt.2 (Int.natCast_nonneg idx)
  have hNotPast : ¬ bs.size < idx := Nat.not_lt_of_ge hLe
  simp [asBytes?, asNonNegativeNat?, asInt?, hNonneg, hNotPast]

theorem runOpcode_SIZE_bytes
    (s : StackState) (b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: rest) :
    runOpcode "OP_SIZE" s = .ok (s.push (.vBigint b.size)) := by
  rw [runOpcode_SIZE_def]
  rw [hStk]
  simp [asBytes?]

theorem runOpcode_INVERT_bytes
    (s : StackState) (b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: rest) :
    runOpcode "OP_INVERT" s =
      .ok ({ s with stack := rest }.push (.vBytes (invertBytes b))) := by
  rw [runOpcode_INVERT_def]
  unfold liftBytesUnary StackState.pop?
  rw [hStk]
  simp [asBytes?]

theorem runOpcode_BIN2NUM_bytes
    (s : StackState) (b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: rest) :
    runOpcode "OP_BIN2NUM" s =
      .ok ({ s with stack := rest }.push (.vBigint (decodeMinimalLE b))) := by
  rw [runOpcode_BIN2NUM_def]
  unfold StackState.pop?
  rw [hStk]
  simp [asBytes?]

theorem runOpcode_NUM2BIN_intNat
    (s : StackState) (n : Int) (size : Nat) (encoded : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBigint (Int.ofNat size) :: .vBigint n :: rest)
    (hEnc : num2binEncode? n size = some encoded) :
    runOpcode "OP_NUM2BIN" s =
      .ok ({ s with stack := rest }.push (.vBytes encoded)) := by
  rw [runOpcode_NUM2BIN_def]
  rw [popN_two_local s _ _ rest hStk]
  simp [asInt?, hEnc]

theorem runOpcode_EQUAL_bytesBytes
    (s : StackState) (a b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: .vBytes a :: rest) :
    runOpcode "OP_EQUAL" s =
      .ok ({ s with stack := rest }.push (.vBool (decide (a.toList = b.toList)))) := by
  rw [runOpcode_EQUAL_def]
  rw [popN_two_local s _ _ rest hStk]
  simp [asBytes?]

theorem runOpcode_AND_bytesBytes
    (s : StackState) (a b out : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: .vBytes a :: rest)
    (hZip : zipBytesWith? (fun x y => x &&& y) a b = some out) :
    runOpcode "OP_AND" s = .ok ({ s with stack := rest }.push (.vBytes out)) := by
  rw [runOpcode_AND_def]
  unfold liftBytesBinChecked bitwiseBytes
  rw [popN_two_local s _ _ rest hStk]
  simp [asBytes?, hZip]

theorem runOpcode_OR_bytesBytes
    (s : StackState) (a b out : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: .vBytes a :: rest)
    (hZip : zipBytesWith? (fun x y => x ||| y) a b = some out) :
    runOpcode "OP_OR" s = .ok ({ s with stack := rest }.push (.vBytes out)) := by
  rw [runOpcode_OR_def]
  unfold liftBytesBinChecked bitwiseBytes
  rw [popN_two_local s _ _ rest hStk]
  simp [asBytes?, hZip]

theorem runOpcode_XOR_bytesBytes
    (s : StackState) (a b out : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: .vBytes a :: rest)
    (hZip : zipBytesWith? (fun x y => x ^^^ y) a b = some out) :
    runOpcode "OP_XOR" s = .ok ({ s with stack := rest }.push (.vBytes out)) := by
  rw [runOpcode_XOR_def]
  unfold liftBytesBinChecked bitwiseBytes
  rw [popN_two_local s _ _ rest hStk]
  simp [asBytes?, hZip]

/-! ### Phase 6 Step 4 tail — End-to-end runOps for unary/binary opcodes

These compose the per-opcode reduction above with the
single-op `runOps` step `runOps [.opcode code] s` form — useful
for direct rewriting in Stage B. -/

/-- `runOps [OP_ADD]` on a 2-int stack: end-to-end reduction. -/
theorem run_OP_ADD_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps [.opcode "OP_ADD"] s
    = .ok ({ s with stack := rest }.push (.vBigint (a + b))) := by
  show runOps (.opcode "OP_ADD" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_ADD_intInt s a b rest hStk]
  simp [run_empty]

/-- `runOps [OP_SUB]` on a 2-int stack. -/
theorem run_OP_SUB_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps [.opcode "OP_SUB"] s
    = .ok ({ s with stack := rest }.push (.vBigint (a - b))) := by
  show runOps (.opcode "OP_SUB" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_SUB_intInt s a b rest hStk]
  simp [run_empty]

/-- `runOps [OP_MUL]` on a 2-int stack. -/
theorem run_OP_MUL_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps [.opcode "OP_MUL"] s
    = .ok ({ s with stack := rest }.push (.vBigint (a * b))) := by
  show runOps (.opcode "OP_MUL" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_MUL_intInt s a b rest hStk]
  simp [run_empty]

/-- `runOps [OP_NUMEQUAL]` on a 2-int stack. -/
theorem run_OP_NUMEQUAL_intInt
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOps [.opcode "OP_NUMEQUAL"] s
    = .ok ({ s with stack := rest }.push (.vBool (decide (a = b)))) := by
  show runOps (.opcode "OP_NUMEQUAL" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_NUMEQUAL_intInt s a b rest hStk]
  simp [run_empty]

/-- `runOps [OP_NEGATE]` on a 1-int stack. -/
theorem run_OP_NEGATE_int
    (s : StackState) (i : Int) (rest : List Value)
    (hStk : s.stack = .vBigint i :: rest) :
    runOps [.opcode "OP_NEGATE"] s
    = .ok ({ s with stack := rest }.push (.vBigint (-i))) := by
  show runOps (.opcode "OP_NEGATE" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_NEGATE_int s i rest hStk]
  simp [run_empty]

/-- `runOps [OP_NOT]` on a 1-bool stack. -/
theorem run_OP_NOT_bool
    (s : StackState) (b : Bool) (rest : List Value)
    (hStk : s.stack = .vBool b :: rest) :
    runOps [.opcode "OP_NOT"] s
    = .ok ({ s with stack := rest }.push (.vBool (!b))) := by
  show runOps (.opcode "OP_NOT" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_NOT_bool s b rest hStk]
  simp [run_empty]

/-- `runOps [OP_CAT]` on a 2-bytes stack. -/
theorem run_OP_CAT_bytesBytes
    (s : StackState) (a b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: .vBytes a :: rest) :
    runOps [.opcode "OP_CAT"] s
    = .ok ({ s with stack := rest }.push (.vBytes (a ++ b))) := by
  show runOps (.opcode "OP_CAT" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_CAT_bytesBytes s a b rest hStk]
  simp [run_empty]

/-- `runOps [OP_SPLIT]` on a bytes/index stack. Top is the suffix, with
the prefix retained below it, matching Bitcoin Script `OP_SPLIT`. -/
theorem run_OP_SPLIT_bytesNat
    (s : StackState) (bs : ByteArray) (idx : Nat) (rest : List Value)
    (hStk : s.stack = .vBigint (idx : Int) :: .vBytes bs :: rest)
    (hLe : idx ≤ bs.size) :
    runOps [.opcode "OP_SPLIT"] s
    = .ok (({ s with stack := rest }.push (.vBytes (bs.extract 0 idx))).push
        (.vBytes (bs.extract idx bs.size))) := by
  show runOps (.opcode "OP_SPLIT" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_SPLIT_bytesNat s bs idx rest hStk hLe]
  simp [run_empty]

/-- `runOps [OP_VERIFY]` on a `vBool true` top: reaches the popped state. -/
theorem run_OP_VERIFY_pop_true
    (s : StackState) (rest : List Value)
    (hStk : s.stack = .vBool true :: rest) :
    runOps [.opcode "OP_VERIFY"] s = .ok { s with stack := rest } := by
  show runOps (.opcode "OP_VERIFY" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_verify_pop_vBool_true s rest hStk]
  simp [run_empty]

/-- `runOps [OP_VERIFY]` on a `vBool false` top: error. -/
theorem run_OP_VERIFY_pop_false
    (s : StackState) (rest : List Value)
    (hStk : s.stack = .vBool false :: rest) :
    runOps [.opcode "OP_VERIFY"] s = .error .assertFailed := by
  show runOps (.opcode "OP_VERIFY" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, runOpcode_verify_pop_vBool_false s rest hStk]

end Sim
end RunarVerification.Stack
