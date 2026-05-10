import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF

/-!
# ANF IR — Type system (skeleton)

A typed view of ANF programs.

The contract state is modelled as a **uniform typed environment** — a
single map from binding name → `ANFType` — rather than a
contract-specific record type. This keeps the `Eval` machinery
polymorphic over `ANFProgram` instead of parameterised over a
per-program record.

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
  simp [extend, lookup]

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

/-! ## Builtin signatures

Each entry maps a `func` name to its `(argTypes, returnType)` signature.
The canonical reference is the TypeScript compiler's `BUILTIN_FUNCTIONS`
table at `packages/runar-compiler/src/passes/03-typecheck.ts:67-212`
(122 entries). We mirror that table exactly here, with the following
caveats:

* `checkMultiSig` takes `Sig[]` / `PubKey[]` array operands. The Lean
  ANF `ANFType` vocabulary does not model array types (see
  `Syntax.lean`'s closed-sum `ANFType`), so `checkMultiSig` is the
  one TS-table entry that returns `none` here. Conformance fixtures
  that exercise `checkMultiSig` are TypeScript-only today, and the
  typing judgment for them is intentionally incomplete until array
  operand types are modelled.
* TS's `'void'` return for `assert` / `exit` is rendered as `.bool`
  here — the Lean `assertT` rule already types `assert` as `.bool`,
  and we never need to *return* `void` since `call` is only invoked
  on builtins that produce a value-typed binding.
-/

structure FuncSig where
  argTypes : List ANFType
  returnType : ANFType
  deriving Repr, BEq

/--
Concrete typing table for every Rúnar built-in the compiler emits as
`call(name, args)`. Mirrors the TS reference table at
`packages/runar-compiler/src/passes/03-typecheck.ts` line-for-line.
Returns `none` for any name not in the table (so unknown builtins are
simply un-typeable, not mis-typeable).
-/
def builtinSig (func : String) : Option FuncSig :=
  match func with
  -- Hashes
  | "sha256"          => some { argTypes := [.byteString],                        returnType := .sha256 }
  | "ripemd160"       => some { argTypes := [.byteString],                        returnType := .ripemd160 }
  | "hash160"         => some { argTypes := [.byteString],                        returnType := .ripemd160 }
  | "hash256"         => some { argTypes := [.byteString],                        returnType := .sha256 }
  -- Signature / preimage / multisig
  | "checkSig"        => some { argTypes := [.sig, .pubKey],                      returnType := .bool }
  -- "checkMultiSig" elided — needs array types
  | "assert"          => some { argTypes := [.bool],                              returnType := .bool }
  | "checkPreimage"   => some { argTypes := [.sigHashPreimage],                   returnType := .bool }
  -- Byte-string primitives
  | "len"             => some { argTypes := [.byteString],                        returnType := .bigint }
  | "cat"             => some { argTypes := [.byteString, .byteString],           returnType := .byteString }
  | "substr"          => some { argTypes := [.byteString, .bigint, .bigint],      returnType := .byteString }
  | "num2bin"         => some { argTypes := [.bigint, .bigint],                   returnType := .byteString }
  | "bin2num"         => some { argTypes := [.byteString],                        returnType := .bigint }
  -- Rabin / WOTS+ / SLH-DSA verifiers
  | "verifyRabinSig"  => some { argTypes := [.byteString, .rabinSig, .byteString, .rabinPubKey], returnType := .bool }
  | "verifyWOTS"               => some { argTypes := [.byteString, .byteString, .byteString], returnType := .bool }
  | "verifySLHDSA_SHA2_128s"   => some { argTypes := [.byteString, .byteString, .byteString], returnType := .bool }
  | "verifySLHDSA_SHA2_128f"   => some { argTypes := [.byteString, .byteString, .byteString], returnType := .bool }
  | "verifySLHDSA_SHA2_192s"   => some { argTypes := [.byteString, .byteString, .byteString], returnType := .bool }
  | "verifySLHDSA_SHA2_192f"   => some { argTypes := [.byteString, .byteString, .byteString], returnType := .bool }
  | "verifySLHDSA_SHA2_256s"   => some { argTypes := [.byteString, .byteString, .byteString], returnType := .bool }
  | "verifySLHDSA_SHA2_256f"   => some { argTypes := [.byteString, .byteString, .byteString], returnType := .bool }
  -- Partial-hash primitives
  | "sha256Compress"  => some { argTypes := [.byteString, .byteString],           returnType := .byteString }
  | "sha256Finalize"  => some { argTypes := [.byteString, .byteString, .bigint],  returnType := .byteString }
  | "blake3Compress"  => some { argTypes := [.byteString, .byteString],           returnType := .byteString }
  | "blake3Hash"      => some { argTypes := [.byteString],                        returnType := .byteString }
  -- Math
  | "abs"             => some { argTypes := [.bigint],                            returnType := .bigint }
  | "min"             => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "max"             => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "within"          => some { argTypes := [.bigint, .bigint, .bigint],          returnType := .bool }
  | "safediv"         => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "safemod"         => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "clamp"           => some { argTypes := [.bigint, .bigint, .bigint],          returnType := .bigint }
  | "sign"            => some { argTypes := [.bigint],                            returnType := .bigint }
  | "pow"             => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "mulDiv"          => some { argTypes := [.bigint, .bigint, .bigint],          returnType := .bigint }
  | "percentOf"       => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "sqrt"            => some { argTypes := [.bigint],                            returnType := .bigint }
  | "gcd"             => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "divmod"          => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "log2"            => some { argTypes := [.bigint],                            returnType := .bigint }
  | "bool"            => some { argTypes := [.bigint],                            returnType := .bool }
  -- Byte-string slicing helpers
  | "split"           => some { argTypes := [.byteString, .bigint],               returnType := .byteString }
  | "reverseBytes"    => some { argTypes := [.byteString],                        returnType := .byteString }
  | "left"            => some { argTypes := [.byteString, .bigint],               returnType := .byteString }
  | "right"           => some { argTypes := [.byteString, .bigint],               returnType := .byteString }
  | "int2str"         => some { argTypes := [.bigint, .bigint],                   returnType := .byteString }
  | "toByteString"    => some { argTypes := [.byteString],                        returnType := .byteString }
  | "exit"            => some { argTypes := [.bool],                              returnType := .bool }
  | "pack"            => some { argTypes := [.bigint],                            returnType := .byteString }
  | "unpack"          => some { argTypes := [.byteString],                        returnType := .bigint }
  -- secp256k1 EC
  | "ecAdd"              => some { argTypes := [.point, .point],                  returnType := .point }
  | "ecMul"              => some { argTypes := [.point, .bigint],                 returnType := .point }
  | "ecMulGen"           => some { argTypes := [.bigint],                         returnType := .point }
  | "ecNegate"           => some { argTypes := [.point],                          returnType := .point }
  | "ecOnCurve"          => some { argTypes := [.point],                          returnType := .bool }
  | "ecModReduce"        => some { argTypes := [.bigint, .bigint],                returnType := .bigint }
  | "ecEncodeCompressed" => some { argTypes := [.point],                          returnType := .byteString }
  | "ecMakePoint"        => some { argTypes := [.bigint, .bigint],                returnType := .point }
  | "ecPointX"           => some { argTypes := [.point],                          returnType := .bigint }
  | "ecPointY"           => some { argTypes := [.point],                          returnType := .bigint }
  -- NIST P-256
  | "p256Add"              => some { argTypes := [.p256Point, .p256Point],        returnType := .p256Point }
  | "p256Mul"              => some { argTypes := [.p256Point, .bigint],           returnType := .p256Point }
  | "p256MulGen"           => some { argTypes := [.bigint],                       returnType := .p256Point }
  | "p256Negate"           => some { argTypes := [.p256Point],                    returnType := .p256Point }
  | "p256OnCurve"          => some { argTypes := [.p256Point],                    returnType := .bool }
  | "p256EncodeCompressed" => some { argTypes := [.p256Point],                    returnType := .byteString }
  | "verifyECDSA_P256"     => some { argTypes := [.byteString, .byteString, .byteString], returnType := .bool }
  -- NIST P-384
  | "p384Add"              => some { argTypes := [.p384Point, .p384Point],        returnType := .p384Point }
  | "p384Mul"              => some { argTypes := [.p384Point, .bigint],           returnType := .p384Point }
  | "p384MulGen"           => some { argTypes := [.bigint],                       returnType := .p384Point }
  | "p384Negate"           => some { argTypes := [.p384Point],                    returnType := .p384Point }
  | "p384OnCurve"          => some { argTypes := [.p384Point],                    returnType := .bool }
  | "p384EncodeCompressed" => some { argTypes := [.p384Point],                    returnType := .byteString }
  | "verifyECDSA_P384"     => some { argTypes := [.byteString, .byteString, .byteString], returnType := .bool }
  -- BabyBear field
  | "bbFieldAdd"      => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "bbFieldSub"      => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "bbFieldMul"      => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "bbFieldInv"      => some { argTypes := [.bigint],                            returnType := .bigint }
  -- BabyBear quartic extension
  | "bbExt4Mul0"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "bbExt4Mul1"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "bbExt4Mul2"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "bbExt4Mul3"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "bbExt4Inv0"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "bbExt4Inv1"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "bbExt4Inv2"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "bbExt4Inv3"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  -- KoalaBear field
  | "kbFieldAdd"      => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "kbFieldSub"      => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "kbFieldMul"      => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "kbFieldInv"      => some { argTypes := [.bigint],                            returnType := .bigint }
  -- KoalaBear quartic extension
  | "kbExt4Mul0"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "kbExt4Mul1"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "kbExt4Mul2"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "kbExt4Mul3"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "kbExt4Inv0"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "kbExt4Inv1"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "kbExt4Inv2"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  | "kbExt4Inv3"      => some { argTypes := [.bigint, .bigint, .bigint, .bigint], returnType := .bigint }
  -- BN254 field
  | "bn254FieldAdd"   => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "bn254FieldSub"   => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "bn254FieldMul"   => some { argTypes := [.bigint, .bigint],                   returnType := .bigint }
  | "bn254FieldInv"   => some { argTypes := [.bigint],                            returnType := .bigint }
  | "bn254FieldNeg"   => some { argTypes := [.bigint],                            returnType := .bigint }
  -- BN254 G1
  | "bn254G1Add"        => some { argTypes := [.point, .point],                   returnType := .point }
  | "bn254G1ScalarMul"  => some { argTypes := [.point, .bigint],                  returnType := .point }
  | "bn254G1Negate"     => some { argTypes := [.point],                           returnType := .point }
  | "bn254G1OnCurve"    => some { argTypes := [.point],                           returnType := .bool }
  -- Merkle
  | "merkleRootSha256"  => some { argTypes := [.byteString, .byteString, .bigint, .bigint], returnType := .byteString }
  | "merkleRootHash256" => some { argTypes := [.byteString, .byteString, .bigint, .bigint], returnType := .byteString }
  -- Preimage extractors
  | "extractVersion"       => some { argTypes := [.sigHashPreimage], returnType := .bigint }
  | "extractHashPrevouts"  => some { argTypes := [.sigHashPreimage], returnType := .sha256 }
  | "extractHashSequence"  => some { argTypes := [.sigHashPreimage], returnType := .sha256 }
  | "extractOutpoint"      => some { argTypes := [.sigHashPreimage], returnType := .byteString }
  | "extractInputIndex"    => some { argTypes := [.sigHashPreimage], returnType := .bigint }
  | "extractScriptCode"    => some { argTypes := [.sigHashPreimage], returnType := .byteString }
  | "extractAmount"        => some { argTypes := [.sigHashPreimage], returnType := .bigint }
  | "extractSequence"      => some { argTypes := [.sigHashPreimage], returnType := .bigint }
  | "extractOutputHash"    => some { argTypes := [.sigHashPreimage], returnType := .sha256 }
  | "extractOutputs"       => some { argTypes := [.sigHashPreimage], returnType := .sha256 }
  | "extractLocktime"      => some { argTypes := [.sigHashPreimage], returnType := .bigint }
  | "extractSigHashType"   => some { argTypes := [.sigHashPreimage], returnType := .bigint }
  | "buildChangeOutput"    => some { argTypes := [.byteString, .bigint], returnType := .byteString }
  | _                  => none

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
