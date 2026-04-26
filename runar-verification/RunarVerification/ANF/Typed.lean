import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF

/-!
# ANF IR — Type system (skeleton)

A typed view of ANF programs.

OQ-2 decision (recorded in `EXPLORATION.md`): the contract state is
modelled as a **uniform typed environment** — a single map from binding
name → `ANFType` — rather than a contract-specific record type. This
keeps the `Eval` machinery polymorphic over `ANFProgram` instead of
parameterised over a per-program record.

This module provides:

* `TypeEnv` — typing contexts as ordered association lists with most-recent shadowing.
* Lookup lemmas (`lookup_extend_self`, `lookup_extend_other`).
* `HasType` — a coarse `Γ ⊢ v : τ` typing judgment for a starter
  fragment of `ANFValue`. The full type system (especially for the
  ~110 builtin functions) is **deliberately incomplete** here; the
  verification lead will fill in cases as Phase 3 demands.
* `type_preservation` — weakening of the typing judgment under "agreeing
  environments". Foundation for the Phase 3 simulation proofs that
  Stack Lower's name-mangling preserves typing.

The crypto / hash / EC / preimage primitives are typed by a `builtinSig`
function that the verification lead will refine. For now it is left
abstract — the typing rule for `call` defers to `builtinSig.lookupSig?`
and only requires that the lookup result agrees with the actual
argument-types.
-/

namespace RunarVerification.ANF
namespace Typed

/-! ## Typing context -/

/--
Typing environment: an ordered association list mapping binding-name to
`ANFType`. Most-recent binding wins on lookup, mirroring the
loop-carried "named binding may be re-bound" rule from `WF.lean`.
-/
structure TypeEnv where
  bindings : List (String × ANFType)
  deriving Repr, Inhabited

namespace TypeEnv

def empty : TypeEnv := { bindings := [] }

/-- Look up `name`. Returns the most recent binding's type, or `none`. -/
def lookup (Γ : TypeEnv) (name : String) : Option ANFType :=
  (Γ.bindings.find? (·.fst == name)).map (·.snd)

/-- Extend `Γ` with `name : τ`. Shadows any prior binding. -/
def extend (Γ : TypeEnv) (name : String) (τ : ANFType) : TypeEnv :=
  { bindings := (name, τ) :: Γ.bindings }

/-! ### Lookup lemmas -/

theorem lookup_extend_self (Γ : TypeEnv) (n : String) (τ : ANFType) :
    (Γ.extend n τ).lookup n = some τ := by
  simp [extend, lookup, List.find?]

theorem lookup_extend_other (Γ : TypeEnv) (n m : String) (τ : ANFType)
    (h : n ≠ m) :
    (Γ.extend n τ).lookup m = Γ.lookup m := by
  unfold extend lookup
  show Option.map _ (List.find? _ ((n, τ) :: Γ.bindings)) = _
  rw [List.find?_cons]
  have hbeq : ((n, τ).fst == m) = false := beq_false_of_ne h
  rw [hbeq]

/-! ### Environment "agreement"

`Γ ≈[V] Γ'` means: on every name in `V`, `Γ` and `Γ'` resolve to the
same `ANFType` (or both fail to resolve). This is exactly the property
needed to push a typing judgment from one environment to another while
respecting potential shadowing of names *not* free in the term.
-/

def agreesOn (Γ Γ' : TypeEnv) (V : List String) : Prop :=
  ∀ n, n ∈ V → Γ.lookup n = Γ'.lookup n

theorem agreesOn_refl (Γ : TypeEnv) (V : List String) : agreesOn Γ Γ V := by
  intro _ _; rfl

theorem agreesOn_subset {Γ Γ' : TypeEnv} {V W : List String}
    (hsub : ∀ x, x ∈ W → x ∈ V) (h : agreesOn Γ Γ' V) :
    agreesOn Γ Γ' W := by
  intro n hn; exact h n (hsub n hn)

end TypeEnv

/-! ## Free names of an ANF value (the variables it references) -/

/-- The list of `TempRef` strings that appear directly in `v` (one level deep). -/
def freeNames : ANFValue → List String
  | .loadParam _ => []
  | .loadProp _ => []
  | .loadConst (.refAlias n) => [n]
  | .loadConst _ => []
  | .binOp _ l r _ => [l, r]
  | .unaryOp _ o _ => [o]
  | .call _ args => args
  | .methodCall obj _ args => obj :: args
  | .ifVal cond _ _ => [cond]   -- nested branch references are scoped to nested envs
  | .loop _ _ _ => []           -- loop body has its own scope (with iterVar)
  | .assert v => [v]
  | .updateProp _ v => [v]
  | .getStateScript => []
  | .checkPreimage p => [p]
  | .deserializeState p => [p]
  | .addOutput sats sv pre => sats :: pre :: sv
  | .addRawOutput sats sb => [sats, sb]
  | .addDataOutput sats sb => [sats, sb]
  | .arrayLiteral elems => elems

/-! ## Builtin signatures (left abstract for the verification lead)

Each entry maps a `func` name to its `(argTypes, returnType)` signature.
The full table will be filled in during Phase 3 — see EXPLORATION.md §7
for the categorisation. The Lean type system below only assumes the
existence of such a function, *not* its implementation.
-/

structure FuncSig where
  argTypes : List ANFType
  returnType : ANFType
  deriving Repr, BEq

opaque builtinSig (func : String) : Option FuncSig

/-! ## The typing judgment

A coarse but extensible inductive `HasType`. Only the cases needed for
the Phase 3 weakening proof are filled in here. Adding a new case
(e.g. typed `bin_op` for arithmetic) is a one-line extension; the
weakening proof is by induction so adding cases requires extending the
proof case-analysis as well.
-/

inductive HasType : TypeEnv → ANFValue → ANFType → Prop where
  /-- A reference to a binding looks up its type from the environment. -/
  | refType {Γ : TypeEnv} {n : String} {τ : ANFType}
      (h : Γ.lookup n = some τ) :
      HasType Γ (.loadConst (.refAlias n)) τ
  /-- The `@this` marker types as `addr` (placeholder convention). -/
  | thisRef {Γ : TypeEnv} :
      HasType Γ (.loadConst .thisRef) .addr
  /-- Integer literals type as `bigint`. -/
  | intLit {Γ : TypeEnv} {i : Int} :
      HasType Γ (.loadConst (.int i)) .bigint
  /-- Boolean literals type as `bool`. -/
  | boolLit {Γ : TypeEnv} {b : Bool} :
      HasType Γ (.loadConst (.bool b)) .bool
  /-- Bytes literals type as `byteString`. -/
  | bytesLit {Γ : TypeEnv} {b : ByteArray} :
      HasType Γ (.loadConst (.bytes b)) .byteString
  /-- `assert` has no return type *as a value* — but for uniformity we
      type it as `bool` (the value being asserted). -/
  | assertT {Γ : TypeEnv} {ref : String}
      (h : Γ.lookup ref = some .bool) :
      HasType Γ (.assert ref) .bool
  /-- `getStateScript` types as `byteString`. -/
  | getStateScriptT {Γ : TypeEnv} :
      HasType Γ .getStateScript .byteString
  /--
  A `call` types at the builtin's declared return type, provided every
  argument has the declared argument type.
  -/
  | callT {Γ : TypeEnv} {func : String} {args : List String}
      {sig : FuncSig}
      (hSig : builtinSig func = some sig)
      (hArity : args.length = sig.argTypes.length)
      (hArgs : ∀ i (h : i < args.length),
        Γ.lookup (args.get ⟨i, h⟩) = some (sig.argTypes.get ⟨i, hArity ▸ h⟩)) :
      HasType Γ (.call func args) sig.returnType

/-! ## Type preservation (weakening) -/

/--
**Type preservation** — environment-agreement form.

If `v` is typeable at `τ` in `Γ`, and `Γ'` agrees with `Γ` on all the
names that `v` actually references, then `v` is typeable at `τ` in `Γ'`.

This is the foundation for the Phase 3 Stack Lower simulation: the
stack lowerer extends the environment as it threads bindings, and we
need to know that previously-typed sub-expressions remain typeable.

The proof is by structural induction on the typing derivation. Cases
that touch the environment (`refType`, `assertT`, `callT`) reroute
their lookups through `agreesOn`. Other cases are immediate.
-/
theorem type_preservation
    {Γ Γ' : TypeEnv} {v : ANFValue} {τ : ANFType}
    (hAgree : Γ.agreesOn Γ' (freeNames v))
    (hType : HasType Γ v τ) :
    HasType Γ' v τ := by
  induction hType with
  | refType h =>
      rename_i n _
      have hAg : Γ.lookup n = Γ'.lookup n :=
        hAgree n (by simp [freeNames])
      exact .refType (hAg ▸ h)
  | thisRef => exact .thisRef
  | intLit => exact .intLit
  | boolLit => exact .boolLit
  | bytesLit => exact .bytesLit
  | assertT h =>
      rename_i ref
      have hAg : Γ.lookup ref = Γ'.lookup ref :=
        hAgree ref (by simp [freeNames])
      exact .assertT (hAg ▸ h)
  | getStateScriptT => exact .getStateScriptT
  | callT hSig hArity hArgs =>
      rename_i func args _
      refine .callT hSig hArity ?_
      intro i hi
      have hMem : args.get ⟨i, hi⟩ ∈ freeNames (.call func args) := by
        show args.get ⟨i, hi⟩ ∈ args
        exact List.get_mem args ⟨i, hi⟩
      have hAg : Γ.lookup (args.get ⟨i, hi⟩) = Γ'.lookup (args.get ⟨i, hi⟩) :=
        hAgree _ hMem
      exact hAg ▸ hArgs i hi

/-! ## Decidability of the lookup-side of typing -/

instance (Γ : TypeEnv) (n : String) : Decidable (Γ.lookup n = none) :=
  inferInstanceAs (Decidable (_ = _))

end Typed
end RunarVerification.ANF
