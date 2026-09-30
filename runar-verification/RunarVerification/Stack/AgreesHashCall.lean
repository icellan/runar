import RunarVerification.ANF.Eval
import RunarVerification.ANF.WellTyped
import RunarVerification.Stack.Agrees
import RunarVerification.Stack.Accept
import RunarVerification.Stack.HashOps

/-! # `Stack/AgreesHashCall.lean` — method-level single-hash-call peel-off substrate

**Path 2 Tier 1 — crypto_call peel-off (method level).** This file carries the
honest method-level substrate for peeling a single-`sha256`/`hash160`-call
*method body* off the residual universal `crypto_call` fallback.

The value-level M2 agreement lives in `Stack/AgreesCrypto.lean` (wave 68 +
hash160 follow-up). THIS file provides the LOWERING reductions and the
method-level pieces the in-`Pipeline` consume theorem composes:

* the consume-mode `lowerValueP` reductions for a single `.call sha256/hash160
  [arg]` at depth-0 last-use (arg consumed in place → RAW arm is the bare
  `[OP_SHA256]` / `[OP_HASH160]`),
* the single-binding `lowerBindingsP` lift,
* the method-level `lowerMethodUserRawOps = [opcode]` reduction.

## The consume regime (why RAW = `[OP_SHA256]`, not `[.dup, OP_SHA256]`)

The natural single-hash method `hash(x) { return sha256(x) }` uses its param
`x` exactly once, so the liveness-aware lowerer (`lowerValueP`) CONSUMES it:
`bringToTop` at depth 0 with `consume=true` emits `[]` (the value is already on
top), so the call lowers to the bare opcode. This is the cleanest possible RAW
— a single allowlisted op, trivially round-trippable.

## 2026-06-11 widening (Parts 8-9)

The fragment WIDENED beyond the bare single call: Part 8 carries the
hash-then-assert PRODUCTION shape (the hash-lock `unlock(expected, x)
{ d := func(x); ok := (d === expected); assert ok }` — lowering, both
runtime walks on the shared equality verdict, classifier, smokes) and
Part 9 the 2-chain shape (`d1 := f1(x); d2 := f2(d1)` for the
peephole-stable hash pairs).  The in-`Pipeline` consume theorems are
`hashAssert_consume_{sha256,hash160}` and `hashChain_consume`.

No `sorry`/`admit`, no new axioms. -/

namespace RunarVerification.Stack.AgreesHashCall

open RunarVerification.ANF RunarVerification.Stack RunarVerification.Stack.Agrees

/-! ## Part 1 — the `lowerBindingsP` nil reduction -/

/-- `lowerBindingsP` on an empty body is the identity pair `([], sm)`. The base
case of the program-aware lowerer's recursion. -/
theorem lowerBindingsP_nil
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (sm : Lower.StackMap) :
    Lower.lowerBindingsP progMethods props budget currentIndex lastUses
      outerProtected localBindings constInts sm [] = ([], sm) := by
  rw [Lower.lowerBindingsP]

/-! ## Part 2 — the consume-mode single-call `lowerValueP` reductions

For a single-arg `.call func [arg]` whose `arg` is at depth 0 and consumed
(last-use, not outer-protected), `lowerValueP` falls through its generic
`.call` arm: `lowerArgsLive` consumes `arg` in place (`bringToTop` d0 consume =
`[]`), leaving exactly `(builtinOpcode func).map .opcode`. We pin the two
allowlisted single-opcode hashes (`sha256` → `OP_SHA256`, `hash160` →
`OP_HASH160`). The concrete function literal is REQUIRED so `lowerValueP`'s
special-cased arms (`checkMultiSig`, …) reduce to their `false` branch. -/

/-- `sha256` single-call, consume-d0: RAW arm is `[OP_SHA256]`. -/
theorem lowerValueP_call_sha256_consume_d0
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (bn arg : String) (k : SlotKind) (tsm_rest : TaggedStackMap)
    (hConsume :
      (!Lower.listContains outerProtected arg
        && Lower.isLastUse lastUses arg currentIndex) = true) :
    (Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts
        (untagSm ((arg, k) :: tsm_rest)) bn (.call "sha256" [arg])).1
      = [StackOp.opcode "OP_SHA256"] := by
  have hUntag : untagSm ((arg, k) :: tsm_rest) = some arg :: untagSm tsm_rest := rfl
  have hDepthTop : Lower.StackMap.depth? (arg :: untagSm tsm_rest) arg = some 0 := by
    unfold Lower.StackMap.depth? List.findIdx? List.findIdx?.go; simp
  have hExt : Lower.isExtractor "sha256" = false := by decide +kernel
  unfold Lower.lowerValueP
  simp [hDepthTop, hConsume, hUntag, hExt, Lower.builtinOpcode,
    Lower.lowerArgsLive, Lower.loadRefLive, Lower.bringToTop]

/-- `hash160` single-call, consume-d0: RAW arm is `[OP_HASH160]`. -/
theorem lowerValueP_call_hash160_consume_d0
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (bn arg : String) (k : SlotKind) (tsm_rest : TaggedStackMap)
    (hConsume :
      (!Lower.listContains outerProtected arg
        && Lower.isLastUse lastUses arg currentIndex) = true) :
    (Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts
        (untagSm ((arg, k) :: tsm_rest)) bn (.call "hash160" [arg])).1
      = [StackOp.opcode "OP_HASH160"] := by
  have hUntag : untagSm ((arg, k) :: tsm_rest) = some arg :: untagSm tsm_rest := rfl
  have hDepthTop : Lower.StackMap.depth? (arg :: untagSm tsm_rest) arg = some 0 := by
    unfold Lower.StackMap.depth? List.findIdx? List.findIdx?.go; simp
  have hExt : Lower.isExtractor "hash160" = false := by decide +kernel
  unfold Lower.lowerValueP
  simp [hDepthTop, hConsume, hUntag, hExt, Lower.builtinOpcode,
    Lower.lowerArgsLive, Lower.loadRefLive, Lower.bringToTop]

/-- `ripemd160` single-call, consume-d0: RAW arm is `[OP_RIPEMD160]`. -/
theorem lowerValueP_call_ripemd160_consume_d0
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (bn arg : String) (k : SlotKind) (tsm_rest : TaggedStackMap)
    (hConsume :
      (!Lower.listContains outerProtected arg
        && Lower.isLastUse lastUses arg currentIndex) = true) :
    (Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts
        (untagSm ((arg, k) :: tsm_rest)) bn (.call "ripemd160" [arg])).1
      = [StackOp.opcode "OP_RIPEMD160"] := by
  have hUntag : untagSm ((arg, k) :: tsm_rest) = some arg :: untagSm tsm_rest := rfl
  have hDepthTop : Lower.StackMap.depth? (arg :: untagSm tsm_rest) arg = some 0 := by
    unfold Lower.StackMap.depth? List.findIdx? List.findIdx?.go; simp
  have hExt : Lower.isExtractor "ripemd160" = false := by decide +kernel
  unfold Lower.lowerValueP
  simp [hDepthTop, hConsume, hUntag, hExt, Lower.builtinOpcode,
    Lower.lowerArgsLive, Lower.loadRefLive, Lower.bringToTop]

/-- `hash256` single-call, consume-d0: RAW arm is `[OP_HASH256]`. -/
theorem lowerValueP_call_hash256_consume_d0
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (bn arg : String) (k : SlotKind) (tsm_rest : TaggedStackMap)
    (hConsume :
      (!Lower.listContains outerProtected arg
        && Lower.isLastUse lastUses arg currentIndex) = true) :
    (Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts
        (untagSm ((arg, k) :: tsm_rest)) bn (.call "hash256" [arg])).1
      = [StackOp.opcode "OP_HASH256"] := by
  have hUntag : untagSm ((arg, k) :: tsm_rest) = some arg :: untagSm tsm_rest := rfl
  have hDepthTop : Lower.StackMap.depth? (arg :: untagSm tsm_rest) arg = some 0 := by
    unfold Lower.StackMap.depth? List.findIdx? List.findIdx?.go; simp
  have hExt : Lower.isExtractor "hash256" = false := by decide +kernel
  unfold Lower.lowerValueP
  simp [hDepthTop, hConsume, hUntag, hExt, Lower.builtinOpcode,
    Lower.lowerArgsLive, Lower.loadRefLive, Lower.bringToTop]

/-! ## Part 3 — the single-binding `lowerBindingsP` lift

Given the value-level reduction `(lowerValueP … v).1 = [op]`, a single-binding
body `[mk bn v src]` lowers to `[op]`: the cons case concatenates the value
ops with the empty-tail ops (`lowerBindingsP_nil`). Generic over the value, so
both hash witnesses feed it. -/

/-- Lift a value-level single-op reduction to the single-binding body level. -/
theorem lowerBindingsP_single_lift
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String) (constInts : List (String × Int))
    (bn op : String) (v : ANFValue) (sm : Lower.StackMap) (src : Option SourceLoc)
    (hWit : (Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bn v).1 = [StackOp.opcode op]) :
    (Lower.lowerBindingsP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm [ANFBinding.mk bn v src]).1
      = [StackOp.opcode op] := by
  have hFull : Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bn v
      = ([StackOp.opcode op],
         (Lower.lowerValueP progMethods props budget currentIndex lastUses
            outerProtected localBindings constInts sm bn v).2.1,
         (Lower.lowerValueP progMethods props budget currentIndex lastUses
            outerProtected localBindings constInts sm bn v).2.2) := by
    rw [Prod.ext_iff, Prod.ext_iff]; exact ⟨hWit, rfl, rfl⟩
  rw [Lower.lowerBindingsP, hFull]
  simp [lowerBindingsP_nil]

/-! ## Part 4 — the method-level RAW reduction

`lowerMethodUserRawOps` for a single-public method whose body is exactly one
`sha256`/`hash160` call on its single param reduces to the bare opcode list.
The param's `computeLastUses` last-use is index 0, so the consume hypothesis is
satisfied. Composes Part 2 (the value witness) with Part 3 (the single-binding
lift). -/

/-- The single-binding consume hypothesis: the lone param `arg`, read once at
index 0, is its own last use. -/
theorem single_call_consume_fact (bn arg func : String) (src : Option SourceLoc) :
    (!Lower.listContains [] arg
      && Lower.isLastUse (Lower.computeLastUses [ANFBinding.mk bn (.call func [arg]) src]) arg 0)
      = true := by
  simp [Lower.listContains, Lower.isLastUse, Lower.computeLastUses,
    Lower.computeLastUses.go, Lower.collectRefs, Lower.lastUsesUpdate, Lower.lastUsesLookup]

/-- Method RAW for a single-`sha256`-call method is `[OP_SHA256]`. -/
theorem lowerMethodUserRawOps_single_sha256
    (progMethods : List ANFMethod) (props : List ANFProperty) (anfM : ANFMethod)
    (bn arg : String) (src : Option SourceLoc)
    (hParams : (anfM.params.map (fun p => some p.name)).reverse
      = ([arg] : Lower.StackMap))
    (hBody : anfM.body = [ANFBinding.mk bn (.call "sha256" [arg]) src]) :
    Agrees.lowerMethodUserRawOps progMethods props anfM = [StackOp.opcode "OP_SHA256"] := by
  unfold Agrees.lowerMethodUserRawOps
  rw [hBody, hParams]
  -- NEW-004: a single hash call marks no raw slot, so the method-wide set
  -- is empty and the lift lemma (stated at the default) applies.
  simp only [Lower.collectRawSlots, Lower.collectRawSlotsGo, Lower.rawResultValue]
  simp only [Lower.arrayElemsOf, List.nil_append]
  exact lowerBindingsP_single_lift progMethods props Lower.defaultInlineBudget 0
    (Lower.computeLastUses [ANFBinding.mk bn (.call "sha256" [arg]) src]) []
    ([ANFBinding.mk bn (.call "sha256" [arg]) src].map (·.name))
    (Lower.collectConstInts [ANFBinding.mk bn (.call "sha256" [arg]) src])
    bn "OP_SHA256" (.call "sha256" [arg]) [arg] src
    (lowerValueP_call_sha256_consume_d0 progMethods props Lower.defaultInlineBudget 0
      (Lower.computeLastUses [ANFBinding.mk bn (.call "sha256" [arg]) src]) []
      ([ANFBinding.mk bn (.call "sha256" [arg]) src].map (·.name))
      (Lower.collectConstInts [ANFBinding.mk bn (.call "sha256" [arg]) src])
      bn arg .param [] (single_call_consume_fact bn arg "sha256" src))

/-- Method RAW for a single-`hash160`-call method is `[OP_HASH160]`. -/
theorem lowerMethodUserRawOps_single_hash160
    (progMethods : List ANFMethod) (props : List ANFProperty) (anfM : ANFMethod)
    (bn arg : String) (src : Option SourceLoc)
    (hParams : (anfM.params.map (fun p => some p.name)).reverse
      = ([arg] : Lower.StackMap))
    (hBody : anfM.body = [ANFBinding.mk bn (.call "hash160" [arg]) src]) :
    Agrees.lowerMethodUserRawOps progMethods props anfM = [StackOp.opcode "OP_HASH160"] := by
  unfold Agrees.lowerMethodUserRawOps
  rw [hBody, hParams]
  -- NEW-004: a single hash call marks no raw slot, so the method-wide set
  -- is empty and the lift lemma (stated at the default) applies.
  simp only [Lower.collectRawSlots, Lower.collectRawSlotsGo, Lower.rawResultValue]
  simp only [Lower.arrayElemsOf, List.nil_append]
  exact lowerBindingsP_single_lift progMethods props Lower.defaultInlineBudget 0
    (Lower.computeLastUses [ANFBinding.mk bn (.call "hash160" [arg]) src]) []
    ([ANFBinding.mk bn (.call "hash160" [arg]) src].map (·.name))
    (Lower.collectConstInts [ANFBinding.mk bn (.call "hash160" [arg]) src])
    bn "OP_HASH160" (.call "hash160" [arg]) [arg] src
    (lowerValueP_call_hash160_consume_d0 progMethods props Lower.defaultInlineBudget 0
      (Lower.computeLastUses [ANFBinding.mk bn (.call "hash160" [arg]) src]) []
      ([ANFBinding.mk bn (.call "hash160" [arg]) src].map (·.name))
      (Lower.collectConstInts [ANFBinding.mk bn (.call "hash160" [arg]) src])
      bn arg .param [] (single_call_consume_fact bn arg "hash160" src))

/-- Method RAW for a single-`ripemd160`-call method is `[OP_RIPEMD160]`. -/
theorem lowerMethodUserRawOps_single_ripemd160
    (progMethods : List ANFMethod) (props : List ANFProperty) (anfM : ANFMethod)
    (bn arg : String) (src : Option SourceLoc)
    (hParams : (anfM.params.map (fun p => some p.name)).reverse
      = ([arg] : Lower.StackMap))
    (hBody : anfM.body = [ANFBinding.mk bn (.call "ripemd160" [arg]) src]) :
    Agrees.lowerMethodUserRawOps progMethods props anfM = [StackOp.opcode "OP_RIPEMD160"] := by
  unfold Agrees.lowerMethodUserRawOps
  rw [hBody, hParams]
  -- NEW-004: a single hash call marks no raw slot, so the method-wide set
  -- is empty and the lift lemma (stated at the default) applies.
  simp only [Lower.collectRawSlots, Lower.collectRawSlotsGo, Lower.rawResultValue]
  simp only [Lower.arrayElemsOf, List.nil_append]
  exact lowerBindingsP_single_lift progMethods props Lower.defaultInlineBudget 0
    (Lower.computeLastUses [ANFBinding.mk bn (.call "ripemd160" [arg]) src]) []
    ([ANFBinding.mk bn (.call "ripemd160" [arg]) src].map (·.name))
    (Lower.collectConstInts [ANFBinding.mk bn (.call "ripemd160" [arg]) src])
    bn "OP_RIPEMD160" (.call "ripemd160" [arg]) [arg] src
    (lowerValueP_call_ripemd160_consume_d0 progMethods props Lower.defaultInlineBudget 0
      (Lower.computeLastUses [ANFBinding.mk bn (.call "ripemd160" [arg]) src]) []
      ([ANFBinding.mk bn (.call "ripemd160" [arg]) src].map (·.name))
      (Lower.collectConstInts [ANFBinding.mk bn (.call "ripemd160" [arg]) src])
      bn arg .param [] (single_call_consume_fact bn arg "ripemd160" src))

/-- Method RAW for a single-`hash256`-call method is `[OP_HASH256]`. -/
theorem lowerMethodUserRawOps_single_hash256
    (progMethods : List ANFMethod) (props : List ANFProperty) (anfM : ANFMethod)
    (bn arg : String) (src : Option SourceLoc)
    (hParams : (anfM.params.map (fun p => some p.name)).reverse
      = ([arg] : Lower.StackMap))
    (hBody : anfM.body = [ANFBinding.mk bn (.call "hash256" [arg]) src]) :
    Agrees.lowerMethodUserRawOps progMethods props anfM = [StackOp.opcode "OP_HASH256"] := by
  unfold Agrees.lowerMethodUserRawOps
  rw [hBody, hParams]
  -- NEW-004: a single hash call marks no raw slot, so the method-wide set
  -- is empty and the lift lemma (stated at the default) applies.
  simp only [Lower.collectRawSlots, Lower.collectRawSlotsGo, Lower.rawResultValue]
  simp only [Lower.arrayElemsOf, List.nil_append]
  exact lowerBindingsP_single_lift progMethods props Lower.defaultInlineBudget 0
    (Lower.computeLastUses [ANFBinding.mk bn (.call "hash256" [arg]) src]) []
    ([ANFBinding.mk bn (.call "hash256" [arg]) src].map (·.name))
    (Lower.collectConstInts [ANFBinding.mk bn (.call "hash256" [arg]) src])
    bn "OP_HASH256" (.call "hash256" [arg]) [arg] src
    (lowerValueP_call_hash256_consume_d0 progMethods props Lower.defaultInlineBudget 0
      (Lower.computeLastUses [ANFBinding.mk bn (.call "hash256" [arg]) src]) []
      ([ANFBinding.mk bn (.call "hash256" [arg]) src].map (·.name))
      (Lower.collectConstInts [ANFBinding.mk bn (.call "hash256" [arg]) src])
      bn arg .param [] (single_call_consume_fact bn arg "hash256" src))

/-! ## Part 5 — the body-level M2 walk (`evalBindingsP` ⟷ `runOps [opcode]`)

A single-hash-call method body evaluates (ANF) and runs (Stack) to a SUCCESS on
the matching entry: the ANF interpreter computes the digest through the shared
`Crypto.hashBackend` (`callBuiltin?` arm), and the deployed `[OP_SHA256]` /
`[OP_HASH160]` runs through the SAME backend. Both succeed, so their success
bits agree. Stated UNFOLDED as `isSome ↔ isSome` (the `successAgrees` body the
in-`Pipeline` consume theorem wraps definitionally), so this file stays below
`Pipeline`.

The value-level `evalValue` reductions are re-proved locally (they only need
`ANF.Eval`, NOT the post-`Pipeline` `AgreesCrypto`), mirroring
`AgreesCrypto.evalValue_call_{sha256,hash160}_eq`. -/

section M2
open RunarVerification.ANF.Eval (Value State evalValue evalBindings evalBindingsP)
open RunarVerification.Stack.Eval
open RunarVerification.ANF.Eval.Crypto

/-- Local `sha256` value-eval reduction: on `arg ↦ vBytes bytes`, the call
computes `vBytes (Crypto.sha256 bytes)` through the shared backend. -/
theorem evalValue_call_sha256_eq_local
    (s : State) (x : String) (bytes : ByteArray)
    (hx : s.resolveRef x = some (.vBytes bytes)) :
    evalValue s (.call "sha256" [x]) = .ok (.vBytes (sha256 bytes), s) := by
  show evalValue s (ANFValue.call "sha256" [x]) = .ok (.vBytes (sha256 bytes), s)
  unfold evalValue
  simp only [List.mapM_cons, List.mapM_nil, RunarVerification.ANF.Eval.lookupRef, hx,
    bind, Except.bind, pure, Except.pure]
  rfl

/-- Local `hash160` value-eval reduction. -/
theorem evalValue_call_hash160_eq_local
    (s : State) (x : String) (bytes : ByteArray)
    (hx : s.resolveRef x = some (.vBytes bytes)) :
    evalValue s (.call "hash160" [x]) = .ok (.vBytes (hash160 bytes), s) := by
  show evalValue s (ANFValue.call "hash160" [x]) = .ok (.vBytes (hash160 bytes), s)
  unfold evalValue
  simp only [List.mapM_cons, List.mapM_nil, RunarVerification.ANF.Eval.lookupRef, hx,
    bind, Except.bind, pure, Except.pure]
  rfl

/-- Local `ripemd160` value-eval reduction. -/
theorem evalValue_call_ripemd160_eq_local
    (s : State) (x : String) (bytes : ByteArray)
    (hx : s.resolveRef x = some (.vBytes bytes)) :
    evalValue s (.call "ripemd160" [x]) = .ok (.vBytes (ripemd160 bytes), s) := by
  show evalValue s (ANFValue.call "ripemd160" [x]) = .ok (.vBytes (ripemd160 bytes), s)
  unfold evalValue
  simp only [List.mapM_cons, List.mapM_nil, RunarVerification.ANF.Eval.lookupRef, hx,
    bind, Except.bind, pure, Except.pure]
  rfl

/-- Local `hash256` value-eval reduction. -/
theorem evalValue_call_hash256_eq_local
    (s : State) (x : String) (bytes : ByteArray)
    (hx : s.resolveRef x = some (.vBytes bytes)) :
    evalValue s (.call "hash256" [x]) = .ok (.vBytes (hash256 bytes), s) := by
  show evalValue s (ANFValue.call "hash256" [x]) = .ok (.vBytes (hash256 bytes), s)
  unfold evalValue
  simp only [List.mapM_cons, List.mapM_nil, RunarVerification.ANF.Eval.lookupRef, hx,
    bind, Except.bind, pure, Except.pure]
  rfl

/-- ANF side succeeds for the single `sha256` binding. -/
theorem evalBindingsP_single_sha256_isSome
    (progMethods : List ANFMethod) (s : State)
    (bn x : String) (src : Option SourceLoc) (bytes : ByteArray)
    (hx : s.resolveRef x = some (.vBytes bytes)) :
    (evalBindingsP progMethods s [ANFBinding.mk bn (.call "sha256" [x]) src]).toOption.isSome = true := by
  have hNoMC : RunarVerification.ANF.Eval.noMethodCallBindings
      [ANFBinding.mk bn (.call "sha256" [x]) src] = true := by
    simp [RunarVerification.ANF.Eval.noMethodCallBindings, RunarVerification.ANF.Eval.noMethodCallValue]
  rw [RunarVerification.ANF.Eval.evalBindingsP_eq_evalBindings_of_noMethodCall progMethods s
        [ANFBinding.mk bn (.call "sha256" [x]) src] hNoMC]
  have hEval : evalBindings s [ANFBinding.mk bn (.call "sha256" [x]) src]
      = .ok (s.addBinding bn (.vBytes (sha256 bytes))) := by
    unfold evalBindings
    rw [evalValue_call_sha256_eq_local s x bytes hx]
    simp only [bind, Except.bind, evalBindings]
  rw [hEval]; rfl

/-- ANF side succeeds for the single `hash160` binding. -/
theorem evalBindingsP_single_hash160_isSome
    (progMethods : List ANFMethod) (s : State)
    (bn x : String) (src : Option SourceLoc) (bytes : ByteArray)
    (hx : s.resolveRef x = some (.vBytes bytes)) :
    (evalBindingsP progMethods s [ANFBinding.mk bn (.call "hash160" [x]) src]).toOption.isSome = true := by
  have hNoMC : RunarVerification.ANF.Eval.noMethodCallBindings
      [ANFBinding.mk bn (.call "hash160" [x]) src] = true := by
    simp [RunarVerification.ANF.Eval.noMethodCallBindings, RunarVerification.ANF.Eval.noMethodCallValue]
  rw [RunarVerification.ANF.Eval.evalBindingsP_eq_evalBindings_of_noMethodCall progMethods s
        [ANFBinding.mk bn (.call "hash160" [x]) src] hNoMC]
  have hEval : evalBindings s [ANFBinding.mk bn (.call "hash160" [x]) src]
      = .ok (s.addBinding bn (.vBytes (hash160 bytes))) := by
    unfold evalBindings
    rw [evalValue_call_hash160_eq_local s x bytes hx]
    simp only [bind, Except.bind, evalBindings]
  rw [hEval]; rfl

/-- ANF side succeeds for the single `ripemd160` binding. -/
theorem evalBindingsP_single_ripemd160_isSome
    (progMethods : List ANFMethod) (s : State)
    (bn x : String) (src : Option SourceLoc) (bytes : ByteArray)
    (hx : s.resolveRef x = some (.vBytes bytes)) :
    (evalBindingsP progMethods s [ANFBinding.mk bn (.call "ripemd160" [x]) src]).toOption.isSome = true := by
  have hNoMC : RunarVerification.ANF.Eval.noMethodCallBindings
      [ANFBinding.mk bn (.call "ripemd160" [x]) src] = true := by
    simp [RunarVerification.ANF.Eval.noMethodCallBindings, RunarVerification.ANF.Eval.noMethodCallValue]
  rw [RunarVerification.ANF.Eval.evalBindingsP_eq_evalBindings_of_noMethodCall progMethods s
        [ANFBinding.mk bn (.call "ripemd160" [x]) src] hNoMC]
  have hEval : evalBindings s [ANFBinding.mk bn (.call "ripemd160" [x]) src]
      = .ok (s.addBinding bn (.vBytes (ripemd160 bytes))) := by
    unfold evalBindings
    rw [evalValue_call_ripemd160_eq_local s x bytes hx]
    simp only [bind, Except.bind, evalBindings]
  rw [hEval]; rfl

/-- ANF side succeeds for the single `hash256` binding. -/
theorem evalBindingsP_single_hash256_isSome
    (progMethods : List ANFMethod) (s : State)
    (bn x : String) (src : Option SourceLoc) (bytes : ByteArray)
    (hx : s.resolveRef x = some (.vBytes bytes)) :
    (evalBindingsP progMethods s [ANFBinding.mk bn (.call "hash256" [x]) src]).toOption.isSome = true := by
  have hNoMC : RunarVerification.ANF.Eval.noMethodCallBindings
      [ANFBinding.mk bn (.call "hash256" [x]) src] = true := by
    simp [RunarVerification.ANF.Eval.noMethodCallBindings, RunarVerification.ANF.Eval.noMethodCallValue]
  rw [RunarVerification.ANF.Eval.evalBindingsP_eq_evalBindings_of_noMethodCall progMethods s
        [ANFBinding.mk bn (.call "hash256" [x]) src] hNoMC]
  have hEval : evalBindings s [ANFBinding.mk bn (.call "hash256" [x]) src]
      = .ok (s.addBinding bn (.vBytes (hash256 bytes))) := by
    unfold evalBindings
    rw [evalValue_call_hash256_eq_local s x bytes hx]
    simp only [bind, Except.bind, evalBindings]
  rw [hEval]; rfl

/-- **M2 walk (sha256).** The single-`sha256`-call body's success bit agrees
with the deployed `[OP_SHA256]` run on the matching entry. -/
theorem hashCall_M2_sha256
    (progMethods : List ANFMethod) (anfSt : State)
    (stkSt : StackState) (bn x : String) (src : Option SourceLoc)
    (bytes : ByteArray) (rest : List Value)
    (hArg : anfSt.resolveRef x = some (.vBytes bytes))
    (hStk : stkSt.stack = .vBytes bytes :: rest)
    (hLen : bytes.size ≤ 520) :
    (evalBindingsP progMethods anfSt [ANFBinding.mk bn (.call "sha256" [x]) src]).toOption.isSome
      ↔ (runOps [StackOp.opcode "OP_SHA256"] stkSt).toOption.isSome := by
  have hANF := evalBindingsP_single_sha256_isSome progMethods anfSt bn x src bytes hArg
  have hStack : (runOps [StackOp.opcode "OP_SHA256"] stkSt).toOption.isSome = true := by
    rw [HashOps.runOps_sha256Ops_eq stkSt bytes rest hStk hLen]; rfl
  rw [hANF, hStack]

/-- **M2 walk (hash160).** -/
theorem hashCall_M2_hash160
    (progMethods : List ANFMethod) (anfSt : State)
    (stkSt : StackState) (bn x : String) (src : Option SourceLoc)
    (bytes : ByteArray) (rest : List Value)
    (hArg : anfSt.resolveRef x = some (.vBytes bytes))
    (hStk : stkSt.stack = .vBytes bytes :: rest)
    (hLen : bytes.size ≤ 520) :
    (evalBindingsP progMethods anfSt [ANFBinding.mk bn (.call "hash160" [x]) src]).toOption.isSome
      ↔ (runOps [StackOp.opcode "OP_HASH160"] stkSt).toOption.isSome := by
  have hANF := evalBindingsP_single_hash160_isSome progMethods anfSt bn x src bytes hArg
  have hStack : (runOps [StackOp.opcode "OP_HASH160"] stkSt).toOption.isSome = true := by
    rw [HashOps.runOps_hash160Ops_eq stkSt bytes rest hStk hLen]; rfl
  rw [hANF, hStack]

/-- **M2 walk (ripemd160).** -/
theorem hashCall_M2_ripemd160
    (progMethods : List ANFMethod) (anfSt : State)
    (stkSt : StackState) (bn x : String) (src : Option SourceLoc)
    (bytes : ByteArray) (rest : List Value)
    (hArg : anfSt.resolveRef x = some (.vBytes bytes))
    (hStk : stkSt.stack = .vBytes bytes :: rest)
    (hLen : bytes.size ≤ 520) :
    (evalBindingsP progMethods anfSt [ANFBinding.mk bn (.call "ripemd160" [x]) src]).toOption.isSome
      ↔ (runOps [StackOp.opcode "OP_RIPEMD160"] stkSt).toOption.isSome := by
  have hANF := evalBindingsP_single_ripemd160_isSome progMethods anfSt bn x src bytes hArg
  have hStack : (runOps [StackOp.opcode "OP_RIPEMD160"] stkSt).toOption.isSome = true := by
    rw [HashOps.runOps_ripemd160Ops_eq stkSt bytes rest hStk hLen]; rfl
  rw [hANF, hStack]

/-- **M2 walk (hash256).** -/
theorem hashCall_M2_hash256
    (progMethods : List ANFMethod) (anfSt : State)
    (stkSt : StackState) (bn x : String) (src : Option SourceLoc)
    (bytes : ByteArray) (rest : List Value)
    (hArg : anfSt.resolveRef x = some (.vBytes bytes))
    (hStk : stkSt.stack = .vBytes bytes :: rest)
    (hLen : bytes.size ≤ 520) :
    (evalBindingsP progMethods anfSt [ANFBinding.mk bn (.call "hash256" [x]) src]).toOption.isSome
      ↔ (runOps [StackOp.opcode "OP_HASH256"] stkSt).toOption.isSome := by
  have hANF := evalBindingsP_single_hash256_isSome progMethods anfSt bn x src bytes hArg
  have hStack : (runOps [StackOp.opcode "OP_HASH256"] stkSt).toOption.isSome = true := by
    rw [HashOps.runOps_hash256Ops_eq stkSt bytes rest hStk hLen]; rfl
  rw [hANF, hStack]

end M2

/-! ## Part 6 — the decidable fragment classifier

`hashCallConsumeShapeBool` decides the single-hash-call consume fragment: a
method with exactly one param whose body is one binding `bn = func(param)` with
`func ∈ {sha256, hash160, hash256}` (the param read once → consumed → RAW is the
bare opcode). The in-`Pipeline` dispatch `by_cases` on this; the witnesses are
recovered by the keyed `hHashCallFrag` omnibus premise (vacuous on non-hash
bodies, like `hMathByteFrag`).

2026-06-21 (PROVE-002 widening): `hash256` joins `sha256`/`hash160` — its opcode
`OP_HASH256` (byte 0xaa) IS in `Script.Parse.isAllowedOpcodeName`, so the bare
`[OP_HASH256]` RAW round-trips at the M4 layer and the whole-method consume
theorem `hashCall_consume_hash256` discharges it.  `ripemd160` is DELIBERATELY
EXCLUDED here: `OP_RIPEMD160` is NOT in `isAllowedOpcodeName`, so
`Parse.areRunarEmittablePushBool [.opcode "OP_RIPEMD160"]` is provably `false`
and `hashCall_consume_core`'s `hEmit` premise cannot be discharged — the
ripemd160 RAW/M2 substrate below exists for ANF-side model completeness only and
is NOT a round-trippable fragment (mirrors the `ANF/Eval.lean` `ripemd160` arm
comment). -/

/-- Decidable single-hash-call consume fragment classifier. -/
def hashCallConsumeShapeBool (m : ANFMethod) : Bool :=
  match m.body with
  | [ANFBinding.mk _ (.call func [arg]) _] =>
      (func == "sha256" || func == "hash160" || func == "hash256")
        && (m.params.map (·.name) == [arg])
  | _ => false

/-! ## Part 7 — MANDATORY anti-vacuity smokes (concrete)

A concrete single-`sha256`-call method `h(x) { return sha256(x) }` whose
classifier fires, RAW reduces to `[OP_SHA256]`, and M2 walk agrees on a concrete
entry. Witnesses that the fragment is NON-empty (the keyed premise is
satisfiable). The smokes fire on the success bit, never forcing the backend
digest. -/

/-- The canonical single-`sha256`-call method. -/
def smokeMethod : ANFMethod :=
  { name := "h"
    params := [ANFParam.mk "x" .byteString]
    body := [ANFBinding.mk "c0" (.call "sha256" ["x"]) none]
    isPublic := true }

/-- SMOKE — the classifier fires on the canonical method (anti-vacuity). -/
theorem smoke_classifier_fires : hashCallConsumeShapeBool smokeMethod = true := by
  decide +kernel

/-- SMOKE — RAW reduces to the bare `[OP_SHA256]` for the canonical method. -/
theorem smoke_method_raw :
    Agrees.lowerMethodUserRawOps [] [] smokeMethod = [StackOp.opcode "OP_SHA256"] :=
  lowerMethodUserRawOps_single_sha256 [] [] smokeMethod "c0" "x" none rfl rfl

/-- The canonical single-`hash256`-call method (PROVE-002 widening). -/
def smokeMethodHash256 : ANFMethod :=
  { name := "h"
    params := [ANFParam.mk "x" .byteString]
    body := [ANFBinding.mk "c0" (.call "hash256" ["x"]) none]
    isPublic := true }

/-- SMOKE — the classifier fires on the canonical `hash256` method (anti-vacuity). -/
theorem smoke_classifier_fires_hash256 : hashCallConsumeShapeBool smokeMethodHash256 = true := by
  decide +kernel

/-- SMOKE — RAW reduces to the bare `[OP_HASH256]` for the canonical `hash256` method. -/
theorem smoke_method_raw_hash256 :
    Agrees.lowerMethodUserRawOps [] [] smokeMethodHash256 = [StackOp.opcode "OP_HASH256"] :=
  lowerMethodUserRawOps_single_hash256 [] [] smokeMethodHash256 "c0" "x" none rfl rfl

/-- The canonical single-`ripemd160`-call method.  Witnesses the ripemd160 RAW
substrate (M4-blocked, so NOT admitted by `hashCallConsumeShapeBool`). -/
def smokeMethodRipemd160 : ANFMethod :=
  { name := "h"
    params := [ANFParam.mk "x" .byteString]
    body := [ANFBinding.mk "c0" (.call "ripemd160" ["x"]) none]
    isPublic := true }

/-- SMOKE — the classifier does NOT fire on `ripemd160` (M4-blocked opcode). -/
theorem smoke_classifier_skips_ripemd160 :
    hashCallConsumeShapeBool smokeMethodRipemd160 = false := by
  decide +kernel

/-- SMOKE — RAW reduces to the bare `[OP_RIPEMD160]` for the `ripemd160` method. -/
theorem smoke_method_raw_ripemd160 :
    Agrees.lowerMethodUserRawOps [] [] smokeMethodRipemd160 = [StackOp.opcode "OP_RIPEMD160"] :=
  lowerMethodUserRawOps_single_ripemd160 [] [] smokeMethodRipemd160 "c0" "x" none rfl rfl

/-! ## Part 8 — W1: hash-then-assert (the PRODUCTION hash-lock shape)

The frontend validator (`02-validate.ts:325-344`) requires public methods to
end in `assert()`, so the production-shaped hash contract is the hash-lock

    unlock(expected, x) { d := sha256(x); ok := (d === expected); assert ok }

with params declared `(expected, x)` so the hashed input `x` sits on TOP of
the entry stack (`userMap = reverse [expected, x] = [x, expected]`) and is
consumed in place by the hash opcode.  PROBED lowering (2026-06-11):

    RAW  = [OP_SHA256, .swap, OP_EQUAL, OP_VERIFY]
    ops  = [OP_SHA256, .swap, OP_EQUAL]      (terminal OP_VERIFY elided)

The acceptance bit of the deployed run IS the equality verdict (the elided
assert's bool stays on top), so the consume theorem needs NO truthiness
hypothesis — the agreement is `decide ((H x).toList = expected.toList)` on
BOTH sides through the same decidable `ByteArray.toList` equality (the ANF
`===`/bytes arm and the VM `OP_EQUAL` first arm are the SAME comparison). -/

/-- The hash-then-assert body shape. `d`/`ok`/`anm` are the binding names,
`arg` the hashed param, `expected` the digest param, `func` the hash. -/
def hashAssertBody (d ok anm arg expected func : String)
    (s1 s2 s3 : Option SourceLoc) : List ANFBinding :=
  [ANFBinding.mk d (.call func [arg]) s1,
   ANFBinding.mk ok (.binOp "===" d expected (some "bytes")) s2,
   ANFBinding.mk anm (.assert ok) s3]

/-- Pairwise distinctness of the four REFERENCED names (the terminal assert's
binding name `anm` is never read, so it is unconstrained). -/
def hashAssertNamesOk (d ok arg expected : String) : Bool :=
  d != arg && d != expected && d != ok
    && ok != arg && ok != expected && arg != expected

/-- The lowered (post-elision) method ops of the hash-then-assert fragment. -/
def hashAssertOps (op : String) : List StackOp :=
  [.opcode op, .swap, .opcode "OP_EQUAL"]

/-- The concrete last-use table of the hash-then-assert body. -/
theorem computeLastUses_hashAssert
    (d ok anm arg expected func : String) (s1 s2 s3 : Option SourceLoc)
    (hNames : hashAssertNamesOk d ok arg expected = true) :
    Lower.computeLastUses (hashAssertBody d ok anm arg expected func s1 s2 s3)
      = [(ok, 2), (expected, 1), (d, 1), (arg, 0)] := by
  have h := hNames
  simp only [hashAssertNamesOk, Bool.and_eq_true, bne_iff_ne, ne_eq] at h
  obtain ⟨⟨⟨⟨⟨hDA, hDE⟩, hDO⟩, hOA⟩, hOE⟩, hAE⟩ := h
  simp [hashAssertBody, Lower.computeLastUses, Lower.computeLastUses.go,
    Lower.collectRefs, Lower.lastUsesUpdate,
    hDA, hDE, hDO, hOA, hOE, hAE,
    Ne.symm hDA, Ne.symm hDE, Ne.symm hDO, Ne.symm hOA, Ne.symm hOE, Ne.symm hAE]

/-- Full-tuple variant of the consume-d0 single-hash-call reduction: also pins
the output stack map (`arg` popped, the binding name pushed) so the 3-binding
chain can thread it.  Stated for `sha256`; the `hash160` peer follows. -/
theorem lowerValueP_call_sha256_consume_d0_full
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (bn arg : String) (smRest : Lower.StackMap)
    (hConsume : Lower.isLastUse lastUses arg currentIndex = true) :
    Lower.lowerValueP progMethods props budget currentIndex lastUses
        [] localBindings constInts (arg :: smRest) bn (.call "sha256" [arg])
      = ([StackOp.opcode "OP_SHA256"], some bn :: smRest, localBindings) := by
  have hDepthTop : Lower.StackMap.depth? (arg :: smRest) arg = some 0 := by
    unfold Lower.StackMap.depth? List.findIdx? List.findIdx?.go; simp
  have hExt : Lower.isExtractor "sha256" = false := by decide +kernel
  unfold Lower.lowerValueP
  simp [hDepthTop, hConsume, hExt, Lower.builtinOpcode, Lower.lowerArgsLive,
    Lower.loadRefLive, Lower.bringToTop, Lower.listContains,
    Lower.StackMap.popN, Lower.StackMap.push]

/-- `hash160` peer of the full-tuple consume-d0 reduction. -/
theorem lowerValueP_call_hash160_consume_d0_full
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (bn arg : String) (smRest : Lower.StackMap)
    (hConsume : Lower.isLastUse lastUses arg currentIndex = true) :
    Lower.lowerValueP progMethods props budget currentIndex lastUses
        [] localBindings constInts (arg :: smRest) bn (.call "hash160" [arg])
      = ([StackOp.opcode "OP_HASH160"], some bn :: smRest, localBindings) := by
  have hDepthTop : Lower.StackMap.depth? (arg :: smRest) arg = some 0 := by
    unfold Lower.StackMap.depth? List.findIdx? List.findIdx?.go; simp
  have hExt : Lower.isExtractor "hash160" = false := by decide +kernel
  unfold Lower.lowerValueP
  simp [hDepthTop, hConsume, hExt, Lower.builtinOpcode, Lower.lowerArgsLive,
    Lower.loadRefLive, Lower.bringToTop, Lower.listContains,
    Lower.StackMap.popN, Lower.StackMap.push]

/-- The equality binding `ok := (d === expected)` over the post-hash stack map
`[d, expected]`: `d` is consumed in place (d0 last-use at index 1), `expected`
is consumed by SWAP (d1 last-use), and the bytes-typed `===` selects
`OP_EQUAL`.  Output map: both operands popped, `ok` pushed. -/
theorem lowerValueP_hashAssert_binop
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (localBindings : List String) (constInts : List (String × Int))
    (d ok arg expected : String)
    (hNames : hashAssertNamesOk d ok arg expected = true) :
    Lower.lowerValueP progMethods props budget 1
        [(ok, 2), (expected, 1), (d, 1), (arg, 0)]
        [] localBindings constInts [d, expected] ok
        (.binOp "===" d expected (some "bytes"))
      = ([.swap, .opcode "OP_EQUAL"], ([ok] : Lower.StackMap), localBindings) := by
  have h := hNames
  simp only [hashAssertNamesOk, Bool.and_eq_true, bne_iff_ne, ne_eq] at h
  obtain ⟨⟨⟨⟨⟨hDA, hDE⟩, hDO⟩, hOA⟩, hOE⟩, hAE⟩ := h
  unfold Lower.lowerValueP
  simp [Lower.loadRefOperand, Lower.operandConsume, Lower.bringToTop,
    Lower.StackMap.depth?, Lower.StackMap.popN, Lower.StackMap.push,
    Lower.isLastUse, Lower.lastUsesLookup, Lower.listContains,
    List.findIdx?, List.findIdx?.go, Lower.binopOpcode,
    hDA, hDE, hDO, hOA, hOE, hAE,
    Ne.symm hDA, Ne.symm hDE, Ne.symm hDO, Ne.symm hOA, Ne.symm hOE, Ne.symm hAE]

/-- The terminal `assert ok` over the post-equality map `[ok]`: `ok` consumed
in place (d0 last-use at index 2), bare `OP_VERIFY`, map emptied. -/
theorem lowerValueP_hashAssert_assert
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (localBindings : List String) (constInts : List (String × Int))
    (d ok anm arg expected : String)
    (hNames : hashAssertNamesOk d ok arg expected = true) :
    Lower.lowerValueP progMethods props budget 2
        [(ok, 2), (expected, 1), (d, 1), (arg, 0)]
        [] localBindings constInts [ok] anm (.assert ok)
      = ([.opcode "OP_VERIFY"], [], localBindings) := by
  have h := hNames
  simp only [hashAssertNamesOk, Bool.and_eq_true, bne_iff_ne, ne_eq] at h
  obtain ⟨⟨⟨⟨⟨hDA, hDE⟩, hDO⟩, hOA⟩, hOE⟩, hAE⟩ := h
  unfold Lower.lowerValueP
  simp [Lower.loadRefLive, Lower.bringToTop, Lower.StackMap.depth?,
    Lower.StackMap.popN, Lower.isLastUse, Lower.lastUsesLookup,
    Lower.listContains, List.findIdx?, List.findIdx?.go]

/-- The hash-then-assert body lowers (program-aware, liveness-on) to the
3-op fragment followed by the terminal `OP_VERIFY` (elided by `lowerMethod`),
with an EMPTY final stack map (so the NIP epilogue is a no-op).  Generic over
the hash via the full-tuple call witness `hCallWit`. -/
theorem lowerBindingsP_hashAssert
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (localBindings : List String) (constInts : List (String × Int))
    (d ok anm arg expected func op : String) (s1 s2 s3 : Option SourceLoc)
    (hNames : hashAssertNamesOk d ok arg expected = true)
    (hCallWit : Lower.lowerValueP progMethods props budget 0
        [(ok, 2), (expected, 1), (d, 1), (arg, 0)]
        [] localBindings constInts [arg, expected] d (.call func [arg])
      = ([StackOp.opcode op], ([d, expected] : Lower.StackMap), localBindings)) :
    Lower.lowerBindingsP progMethods props budget 0
        [(ok, 2), (expected, 1), (d, 1), (arg, 0)]
        [] localBindings constInts [arg, expected]
        (hashAssertBody d ok anm arg expected func s1 s2 s3)
      = ([.opcode op, .swap, .opcode "OP_EQUAL", .opcode "OP_VERIFY"], ([] : Lower.StackMap)) := by
  show Lower.lowerBindingsP progMethods props budget 0
        [(ok, 2), (expected, 1), (d, 1), (arg, 0)]
        [] localBindings constInts [arg, expected]
        [⟨d, .call func [arg], s1⟩,
         ⟨ok, .binOp "===" d expected (some "bytes"), s2⟩,
         ⟨anm, .assert ok, s3⟩]
      = ([.opcode op, .swap, .opcode "OP_EQUAL", .opcode "OP_VERIFY"], [])
  rw [Lower.lowerBindingsP.eq_def]
  simp only [hCallWit]
  rw [Lower.lowerBindingsP.eq_def]
  simp only [lowerValueP_hashAssert_binop progMethods props budget
    localBindings constInts d ok arg expected hNames]
  rw [Lower.lowerBindingsP.eq_def]
  simp only [lowerValueP_hashAssert_assert progMethods props budget
    localBindings constInts d ok anm arg expected hNames]
  rw [Lower.lowerBindingsP.eq_def]
  simp

/-- **The method-level lowering reduction (W1).**  A public method with params
`(expected, arg)` and the hash-then-assert body lowers to the 3-op
`hashAssertOps op`: no implicit slots (`bindingsUseCheckPreimage = false`),
the body lowers per `lowerBindingsP_hashAssert`, the terminal-assert elision
drops the trailing `OP_VERIFY`, and the NIP epilogue is empty (final map `[]`,
post-elision depth 1). -/
theorem lowerMethod_ops_hashAssert
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (anfM : ANFMethod)
    (d ok anm arg expected func op : String) (tyE tyA : ANFType)
    (s1 s2 s3 : Option SourceLoc)
    (hParams : anfM.params = [ANFParam.mk expected tyE, ANFParam.mk arg tyA])
    (hBody : anfM.body = hashAssertBody d ok anm arg expected func s1 s2 s3)
    (hPub : anfM.isPublic = true)
    (hNames : hashAssertNamesOk d ok arg expected = true)
    (hFunc : func = "sha256" ∨ func = "hash160")
    (hCallWit : Lower.lowerValueP progMethods props Lower.defaultInlineBudget 0
        [(ok, 2), (expected, 1), (d, 1), (arg, 0)]
        [] [d, ok, anm] (Lower.collectConstInts
          (hashAssertBody d ok anm arg expected func s1 s2 s3))
        [arg, expected] d (.call func [arg])
      = ([StackOp.opcode op], ([d, expected] : Lower.StackMap), [d, ok, anm])) :
    (Lower.lowerMethod progMethods props anfM).ops = hashAssertOps op := by
  -- N-007: the body never deserializes state, so the parameter
  -- shadow-rename is the identity and `lowerMethod` is `lowerMethodCore`.
  rw [Lower.lowerMethod_of_noDeserialize progMethods props anfM (by
    rw [hBody]; simp [hashAssertBody, Lower.bindingsUseDeserializeState])]
  unfold Lower.lowerMethodCore
  rw [hParams, hBody, hPub]
  simp only [List.map_cons, List.map_nil, List.reverse_cons, List.reverse_nil,
    List.nil_append, List.cons_append]
  have hUsesPre : Lower.bindingsUseCheckPreimage
      (hashAssertBody d ok anm arg expected func s1 s2 s3) = false := by
    simp [hashAssertBody, Lower.bindingsUseCheckPreimage]
  have hUsesCode : Lower.bindingsUseCodePart
      (hashAssertBody d ok anm arg expected func s1 s2 s3) = false := by
    rcases hFunc with hF | hF <;> subst hF <;>
      simp [hashAssertBody, Lower.bindingsUseCodePart]
  have hEndsAssert : Lower.bodyEndsInAssert
      (hashAssertBody d ok anm arg expected func s1 s2 s3) = true := by
    simp [hashAssertBody, Lower.bodyEndsInAssert]
  have hNoDeser : Lower.bindingsUseDeserializeState
      (hashAssertBody d ok anm arg expected func s1 s2 s3) = false := by
    simp [hashAssertBody, Lower.bindingsUseDeserializeState]
  rw [hUsesPre, hUsesCode,
      computeLastUses_hashAssert d ok anm arg expected func s1 s2 s3 hNames]
  rw [show ((hashAssertBody d ok anm arg expected func s1 s2 s3).map (·.name))
        = [d, ok, anm] by simp [hashAssertBody, ANFBinding.name]]
  simp only [Bool.false_eq_true, if_false]
  -- NEW-004: the hash-assert body is calls + assert, no byte-array
  -- producer, so the method-wide raw-slot set is empty.
  rw [show Lower.collectRawSlots (hashAssertBody d ok anm arg expected func s1 s2 s3) = [] from by
        simp [hashAssertBody, Lower.collectRawSlots, Lower.collectRawSlotsGo,
              Lower.rawResultValue]]
  -- …and no `array_literal` binding, so the element table is empty too.
  rw [show Lower.arrayElemsOf (hashAssertBody d ok anm arg expected func s1 s2 s3) = [] from by
        simp [hashAssertBody, Lower.arrayElemsOf]]
  rw [lowerBindingsP_hashAssert progMethods props Lower.defaultInlineBudget
    [d, ok, anm] (Lower.collectConstInts
      (hashAssertBody d ok anm arg expected func s1 s2 s3))
    d ok anm arg expected func op s1 s2 s3 hNames hCallWit]
  simp [hEndsAssert, hNoDeser, hashAssertOps]

/-- The hashed param `arg` is its own last use at index 0 under the W1
last-use table (the later entries name OTHER refs — distinctness). -/
theorem hashAssert_arg_consume_fact (d ok arg expected : String)
    (hNames : hashAssertNamesOk d ok arg expected = true) :
    Lower.isLastUse [(ok, 2), (expected, 1), (d, 1), (arg, 0)] arg 0 = true := by
  have h := hNames
  simp only [hashAssertNamesOk, Bool.and_eq_true, bne_iff_ne, ne_eq] at h
  obtain ⟨⟨⟨⟨⟨hDA, hDE⟩, hDO⟩, hOA⟩, hOE⟩, hAE⟩ := h
  have h1 : (ok == arg) = false := beq_false_of_ne hOA
  have h2 : (expected == arg) = false := beq_false_of_ne (Ne.symm hAE)
  have h3 : (d == arg) = false := beq_false_of_ne hDA
  simp [Lower.isLastUse, Lower.lastUsesLookup, List.find?, h1, h2, h3]

/-! ### Part 8b — the W1 runtime walks

Both sides' bits are the SAME decidable byte-list equality
`decide ((H argBytes).toList = expectedBytes.toList)`:

* ANF — `evalBinOp "===" … (some "bytes")` compares via
  `Value.asBytes?` + `decide (ba.toList = bb.toList)`;
* Stack — the VM's `OP_EQUAL` first arm compares via `Eval.asBytes?` +
  `decide (ab.toList = bb.toList)`, with `a` = the SECOND-popped value
  (the digest, after SWAP) and `b` = the top (the expected bytes), so
  even the ORIENTATION matches — no symmetry bridge needed. -/

section W1Walks
open RunarVerification.ANF.Eval (Value State evalValue evalBindings evalBindingsP)
open RunarVerification.ANF.WellTyped (resolveRef_addBinding_self resolveRef_addBinding_ne)
open RunarVerification.Stack.Eval
open RunarVerification.ANF.Eval.Crypto

/-- **ANF walk (W1, hash-generic core).**  The hash-then-assert body's success
bit IS the equality verdict: the digest binds to `d`, the bytes-typed `===`
computes `decide ((digest).toList = expectedBytes.toList)`, and the terminal
`assert` errors exactly on `false`.  Generic over the hash through the
value-level call witness `hCallEval`. -/
theorem evalBindingsP_hashAssert_isSome_eq
    (progMethods : List ANFMethod) (s : State)
    (d ok anm arg expected func : String) (s1 s2 s3 : Option SourceLoc)
    (digest expBytes : ByteArray)
    (hNames : hashAssertNamesOk d ok arg expected = true)
    (hCallEval : evalValue s (.call func [arg]) = .ok (.vBytes digest, s))
    (hExp : s.resolveRef expected = some (.vBytes expBytes)) :
    (evalBindingsP progMethods s
        (hashAssertBody d ok anm arg expected func s1 s2 s3)).toOption.isSome
      = decide (digest.toList = expBytes.toList) := by
  have h := hNames
  simp only [hashAssertNamesOk, Bool.and_eq_true, bne_iff_ne, ne_eq] at h
  obtain ⟨⟨⟨⟨⟨hDA, hDE⟩, hDO⟩, hOA⟩, hOE⟩, hAE⟩ := h
  have hNoMC : RunarVerification.ANF.Eval.noMethodCallBindings
      (hashAssertBody d ok anm arg expected func s1 s2 s3) = true := by
    simp [hashAssertBody, RunarVerification.ANF.Eval.noMethodCallBindings,
      RunarVerification.ANF.Eval.noMethodCallValue]
  rw [RunarVerification.ANF.Eval.evalBindingsP_eq_evalBindings_of_noMethodCall
        progMethods s _ hNoMC]
  show (evalBindings s
      [⟨d, .call func [arg], s1⟩,
       ⟨ok, .binOp "===" d expected (some "bytes"), s2⟩,
       ⟨anm, .assert ok, s3⟩]).toOption.isSome = _
  -- Step 1: the hash call binds the digest to `d`.
  unfold evalBindings
  rw [hCallEval]
  simp only [bind, Except.bind]
  -- Step 2: the bytes-typed equality binds the verdict to `ok`.
  have hLookD : (s.addBinding d (.vBytes digest)).resolveRef d
      = some (.vBytes digest) :=
    resolveRef_addBinding_self s d (.vBytes digest)
  have hLookE : (s.addBinding d (.vBytes digest)).resolveRef expected
      = some (.vBytes expBytes) := by
    rw [resolveRef_addBinding_ne s d expected (.vBytes digest) hDE]
    exact hExp
  have hBinOp : evalValue (s.addBinding d (.vBytes digest))
        (.binOp "===" d expected (some "bytes"))
      = .ok (.vBool (decide (digest.toList = expBytes.toList)),
             s.addBinding d (.vBytes digest)) := by
    show RunarVerification.ANF.Eval.evalValue (s.addBinding d (.vBytes digest))
        (ANFValue.binOp "===" d expected (some "bytes")) = _
    unfold RunarVerification.ANF.Eval.evalValue
    simp only [RunarVerification.ANF.Eval.lookupRef, hLookD, hLookE,
      bind, Except.bind, pure, Except.pure]
    rfl
  unfold evalBindings
  rw [hBinOp]
  simp only [bind, Except.bind]
  -- Step 3: the terminal assert keys on the verdict.
  have hLookOk : ((s.addBinding d (.vBytes digest)).addBinding ok
        (.vBool (decide (digest.toList = expBytes.toList)))).resolveRef ok
      = some (.vBool (decide (digest.toList = expBytes.toList))) :=
    resolveRef_addBinding_self _ ok _
  have hAssert : evalValue ((s.addBinding d (.vBytes digest)).addBinding ok
        (.vBool (decide (digest.toList = expBytes.toList)))) (.assert ok)
      = if decide (digest.toList = expBytes.toList)
        then .ok (.vBool true, (s.addBinding d (.vBytes digest)).addBinding ok
          (.vBool (decide (digest.toList = expBytes.toList))))
        else .error .assertFailed := by
    show RunarVerification.ANF.Eval.evalValue _ (ANFValue.assert ok) = _
    unfold RunarVerification.ANF.Eval.evalValue
    simp only [RunarVerification.ANF.Eval.lookupRef, hLookOk,
      bind, Except.bind]
    cases hb : decide (digest.toList = expBytes.toList) <;>
      simp [pure, Except.pure]
  unfold evalBindings
  rw [hAssert]
  cases hb : decide (digest.toList = expBytes.toList) <;>
    simp [bind, Except.bind, evalBindings, Except.toOption]

/-- **Stack walk (W1, hash-generic core).**  The elided 3-op fragment's
ACCEPTANCE bit is the same equality verdict: the hash opcode replaces the top
with the digest (supplied via the step witness `hHashStep`), SWAP exposes the
expected bytes, and `OP_EQUAL` leaves the verdict bool as the implicit return
value (the elided assert's residue) — truthy exactly on `true`. -/
theorem runOps_hashAssertOps_scriptAccepts
    (stkSt : StackState) (op : String) (argBytes digest expBytes : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes argBytes :: .vBytes expBytes :: rest)
    (hHashStep : runOps [.opcode op] stkSt
      = .ok { stkSt with stack := .vBytes digest :: .vBytes expBytes :: rest }) :
    scriptAccepts (runOps (hashAssertOps op) stkSt)
      = decide (digest.toList = expBytes.toList) := by
  have hSplit : hashAssertOps op
      = [.opcode op] ++ [.swap, .opcode "OP_EQUAL"] := rfl
  rw [hSplit, runOps_append, hHashStep]
  show scriptAccepts (runOps (.swap :: .opcode "OP_EQUAL" :: [])
      { stkSt with stack := .vBytes digest :: .vBytes expBytes :: rest }) = _
  unfold runOps
  rw [stepNonIf_swap]
  have hSwap : applySwap
        { stkSt with stack := .vBytes digest :: .vBytes expBytes :: rest }
      = .ok { stkSt with stack := .vBytes expBytes :: .vBytes digest :: rest } := by
    unfold applySwap
    rfl
  rw [hSwap]
  show scriptAccepts (runOps (.opcode "OP_EQUAL" :: [])
      { stkSt with stack := .vBytes expBytes :: .vBytes digest :: rest }) = _
  unfold runOps
  rw [stepNonIf_opcode]
  have hEq : runOpcode "OP_EQUAL"
        { stkSt with stack := .vBytes expBytes :: .vBytes digest :: rest }
      = .ok { stkSt with
          stack := Value.vBool (decide (digest.toList = expBytes.toList)) :: rest } := by
    simp only [runOpcode, popN, StackState.pop?]
    rfl
  rw [hEq]
  simp [runOps_nil, scriptAccepts, topTruthy, asBool?]

end W1Walks

/-! ### Part 8c — the W1 decidable fragment classifier

`hashAssertConsumeShapeBool` decides the hash-then-assert consume fragment:
exactly two params declared `(expected, arg)` (the hashed input LAST, so it
sits on top of the entry stack), a 3-binding body
`d := func(arg) ; ok := (d === expected : bytes) ; assert ok` with
`func ∈ {sha256, hash160}`, and the four referenced names pairwise distinct
(`hashAssertNamesOk` — shadowing would change the liveness table). -/

/-- Decidable hash-then-assert consume fragment classifier. -/
def hashAssertConsumeShapeBool (m : ANFMethod) : Bool :=
  match m.body with
  | [ANFBinding.mk d (.call func [arg]) _,
     ANFBinding.mk ok (.binOp "===" l r (some rt)) _,
     ANFBinding.mk _ (.assert ar) _] =>
      (func == "sha256" || func == "hash160")
        && rt == "bytes" && l == d && ar == ok
        && (m.params.map (·.name) == [r, arg])
        && hashAssertNamesOk d ok arg r
  | _ => false

/-- Existential extraction from the W1 classifier: a classified method
carries the `(expected, arg)` param pair and the canonical
`hashAssertBody` with an admissible hash and distinct referenced names.
Consumed by the mixed-dispatch widening, which needs the per-branch shape
of EVERY public method (not just the keyed-premise-supplied selected one). -/
theorem hashAssertConsumeShapeBool_extract (m : ANFMethod)
    (h : hashAssertConsumeShapeBool m = true) :
    ∃ (d ok anm arg expected func : String) (tyE tyA : ANFType)
      (s1 s2 s3 : Option SourceLoc),
      m.params = [ANFParam.mk expected tyE, ANFParam.mk arg tyA] ∧
      m.body = hashAssertBody d ok anm arg expected func s1 s2 s3 ∧
      (func = "sha256" ∨ func = "hash160") ∧
      hashAssertNamesOk d ok arg expected = true := by
  unfold hashAssertConsumeShapeBool at h
  split at h
  case _ =>
    rename_i d func arg s1 ok l r rt s2 anm ar s3 hBodyEq
    simp only [Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq] at h
    obtain ⟨⟨⟨⟨⟨hFunc, hRt⟩, hL⟩, hAr⟩, hParamNames⟩, hNames⟩ := h
    rw [hL, hRt, hAr] at hBodyEq
    obtain ⟨tyE, tyA, hParams⟩ :
        ∃ tyE tyA, m.params = [ANFParam.mk r tyE, ANFParam.mk arg tyA] := by
      cases hp : m.params with
      | nil => rw [hp] at hParamNames; simp at hParamNames
      | cons p1 ps =>
        cases ps with
        | nil => rw [hp] at hParamNames; simp at hParamNames
        | cons p2 ps2 =>
          cases ps2 with
          | nil =>
            rw [hp] at hParamNames
            simp only [List.map_cons, List.map_nil, List.cons.injEq,
              and_true] at hParamNames
            obtain ⟨h1, h2, _⟩ := hParamNames
            exact ⟨p1.type, p2.type, by cases p1; cases p2; simp_all⟩
          | cons _ _ => rw [hp] at hParamNames; simp at hParamNames
    exact ⟨d, ok, anm, arg, r, func, tyE, tyA, s1, s2, s3, hParams,
      hBodyEq, hFunc, hNames⟩
  next => exact absurd h (by decide)

/-! ### Part 8d — MANDATORY anti-vacuity smokes (concrete, W1)

The canonical hash-lock `unlock(expected, x) { d := sha256(x); ok := d ===
expected; assert ok }`: classifier fires, method ops reduce to
`hashAssertOps "OP_SHA256"`. -/

/-- The canonical hash-then-assert method. -/
def hashAssertSmokeMethod : ANFMethod :=
  { name := "unlock"
    params := [ANFParam.mk "expected" .byteString, ANFParam.mk "x" .byteString]
    body := hashAssertBody "d" "ok" "a0" "x" "expected" "sha256" none none none
    isPublic := true }

/-- SMOKE — the W1 classifier fires on the canonical hash-lock. -/
theorem smoke_hashAssert_classifier_fires :
    hashAssertConsumeShapeBool hashAssertSmokeMethod = true := by
  decide +kernel

/-- SMOKE — the W1 classifier is disjoint from the single-call classifier
(the 3-binding body never matches the 1-binding shape, and vice versa). -/
theorem smoke_hashAssert_classifier_disjoint :
    hashCallConsumeShapeBool hashAssertSmokeMethod = false ∧
    hashAssertConsumeShapeBool smokeMethod = false := by
  constructor <;> decide +kernel

/-- SMOKE — the canonical hash-lock's method ops reduce to the elided 3-op
fragment. -/
theorem smoke_hashAssert_method_ops :
    (Lower.lowerMethod [] [] hashAssertSmokeMethod).ops
      = hashAssertOps "OP_SHA256" := by
  apply lowerMethod_ops_hashAssert [] [] hashAssertSmokeMethod
    "d" "ok" "a0" "x" "expected" "sha256" "OP_SHA256" .byteString .byteString
    none none none rfl rfl rfl (by decide) (Or.inl rfl)
  exact lowerValueP_call_sha256_consume_d0_full [] [] Lower.defaultInlineBudget 0
    [("ok", 2), ("expected", 1), ("d", 1), ("x", 0)] ["d", "ok", "a0"]
    (Lower.collectConstInts (hashAssertBody "d" "ok" "a0" "x" "expected" "sha256"
      none none none)) "d" "x" ["expected"] (by decide)

/-! ## Part 9 — W2: 2-chains (`d1 := f1(x) ; d2 := f2(d1)`)

Each intermediate is consumed in place (depth-0 last-use), so the method
lowers to the bare 2-opcode list `[op1, op2]` — no elision (the body is
VALUE-terminated), no NIPs (the `bodyEndsInAssert` gate is false).

SCOPE (2026-06-13, widened): all FOUR ordered hash pairs are covered.  Three
are peephole-STABLE (`hashChainOps` survives unchanged).  The pair
`(sha256, sha256)` is peephole-FUSING — `applyDoubleSha256` rewrites
`[OP_SHA256, OP_SHA256]` to `[OP_HASH256]` — and is sound via
`hash256 = sha256 ∘ sha256` (`runOps_hash256Ops_eq_composition`); its M3/M4
image is `[OP_HASH256]`, discharged in `Pipeline.hashChain_consume_sha256d_core`
(`OP_HASH256` is allowlisted for the round-trip in `Script.Parse`). -/

/-- The 2-chain body shape. -/
def hashChainBody (d1 d2 arg f1 f2 : String) (s1 s2 : Option SourceLoc) :
    List ANFBinding :=
  [ANFBinding.mk d1 (.call f1 [arg]) s1,
   ANFBinding.mk d2 (.call f2 [d1]) s2]

/-- The lowered 2-chain method ops. -/
def hashChainOps (op1 op2 : String) : List StackOp :=
  [.opcode op1, .opcode op2]

/-- The admissible function pairs.  Three pairs are peephole-STABLE
(`hashChainOps` survives the peephole unchanged); `(sha256, sha256)` is also
admitted but is peephole-FUSING — the pair `[OP_SHA256, OP_SHA256]` fuses to
`[OP_HASH256]` (sound: `hash256 = sha256 ∘ sha256`).  See the Part 9 header
and `hashChainFuses` for the discriminator. -/
def hashChainFuncsOk (f1 f2 : String) : Bool :=
  (f1 == "sha256" && f2 == "hash160")
    || (f1 == "hash160" && f2 == "sha256")
    || (f1 == "hash160" && f2 == "hash160")
    || (f1 == "sha256" && f2 == "sha256")

/-- Discriminates the peephole-FUSING pair `(sha256, sha256)` from the three
peephole-stable pairs.  The fusing pair lowers to `[OP_SHA256, OP_SHA256]`,
which the peephole `applyDoubleSha256` rewrites to `[OP_HASH256]`. -/
def hashChainFuses (f1 f2 : String) : Bool :=
  f1 == "sha256" && f2 == "sha256"

/-- The concrete last-use table of the 2-chain body. -/
theorem computeLastUses_hashChain
    (d1 d2 arg f1 f2 : String) (s1 s2 : Option SourceLoc)
    (hNe : d1 ≠ arg) :
    Lower.computeLastUses (hashChainBody d1 d2 arg f1 f2 s1 s2)
      = [(d1, 1), (arg, 0)] := by
  simp [hashChainBody, Lower.computeLastUses, Lower.computeLastUses.go,
    Lower.collectRefs, Lower.lastUsesUpdate, hNe, Ne.symm hNe]

/-- `arg` is its own last use at index 0 under the chain table. -/
theorem hashChain_arg_consume_fact (d1 arg : String) (hNe : d1 ≠ arg) :
    Lower.isLastUse [(d1, 1), (arg, 0)] arg 0 = true := by
  have h1 : (d1 == arg) = false := beq_false_of_ne hNe
  simp [Lower.isLastUse, Lower.lastUsesLookup, List.find?, h1]

/-- `d1` is its own last use at index 1 under the chain table. -/
theorem hashChain_d1_consume_fact (d1 arg : String) :
    Lower.isLastUse [(d1, 1), (arg, 0)] d1 1 = true := by
  simp [Lower.isLastUse, Lower.lastUsesLookup, List.find?]

/-- The 2-chain body lowers to the bare 2-opcode list, ending with the
singleton stack map `[d2]` (the final digest).  Generic over the hashes via
the two full-tuple call witnesses. -/
theorem lowerBindingsP_hashChain
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (localBindings : List String) (constInts : List (String × Int))
    (d1 d2 arg f1 f2 op1 op2 : String) (s1 s2 : Option SourceLoc)
    (hCallWit1 : Lower.lowerValueP progMethods props budget 0
        [(d1, 1), (arg, 0)] [] localBindings constInts [arg] d1 (.call f1 [arg])
      = ([StackOp.opcode op1], ([d1] : Lower.StackMap), localBindings))
    (hCallWit2 : Lower.lowerValueP progMethods props budget 1
        [(d1, 1), (arg, 0)] [] localBindings constInts [d1] d2 (.call f2 [d1])
      = ([StackOp.opcode op2], ([d2] : Lower.StackMap), localBindings)) :
    Lower.lowerBindingsP progMethods props budget 0 [(d1, 1), (arg, 0)]
        [] localBindings constInts [arg] (hashChainBody d1 d2 arg f1 f2 s1 s2)
      = (hashChainOps op1 op2, ([d2] : Lower.StackMap)) := by
  show Lower.lowerBindingsP progMethods props budget 0 [(d1, 1), (arg, 0)]
        [] localBindings constInts [arg]
        [⟨d1, .call f1 [arg], s1⟩, ⟨d2, .call f2 [d1], s2⟩]
      = (hashChainOps op1 op2, ([d2] : Lower.StackMap))
  rw [Lower.lowerBindingsP.eq_def]
  simp only [hCallWit1]
  rw [Lower.lowerBindingsP.eq_def]
  simp only [hCallWit2]
  rw [Lower.lowerBindingsP.eq_def]
  simp [hashChainOps]

/-- **The method-level lowering reduction (W2).**  A public single-param
method with the 2-chain body lowers to the bare `hashChainOps op1 op2`: no
implicit slots, no elision (the body is value-terminated), and the NIP
epilogue is gated off by `bodyEndsInAssert = false`. -/
theorem lowerMethod_ops_hashChain
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (anfM : ANFMethod)
    (d1 d2 arg f1 f2 op1 op2 : String) (ty : ANFType)
    (s1 s2 : Option SourceLoc)
    (hParams : anfM.params = [ANFParam.mk arg ty])
    (hBody : anfM.body = hashChainBody d1 d2 arg f1 f2 s1 s2)
    (hPub : anfM.isPublic = true)
    (hNe : d1 ≠ arg)
    (hFuncs : hashChainFuncsOk f1 f2 = true)
    (hCallWit1 : Lower.lowerValueP progMethods props Lower.defaultInlineBudget 0
        [(d1, 1), (arg, 0)] [] [d1, d2]
        (Lower.collectConstInts (hashChainBody d1 d2 arg f1 f2 s1 s2))
        [arg] d1 (.call f1 [arg])
      = ([StackOp.opcode op1], ([d1] : Lower.StackMap), [d1, d2]))
    (hCallWit2 : Lower.lowerValueP progMethods props Lower.defaultInlineBudget 1
        [(d1, 1), (arg, 0)] [] [d1, d2]
        (Lower.collectConstInts (hashChainBody d1 d2 arg f1 f2 s1 s2))
        [d1] d2 (.call f2 [d1])
      = ([StackOp.opcode op2], ([d2] : Lower.StackMap), [d1, d2])) :
    (Lower.lowerMethod progMethods props anfM).ops = hashChainOps op1 op2 := by
  have hF : (f1 = "sha256" ∧ f2 = "hash160") ∨ (f1 = "hash160" ∧ f2 = "sha256")
      ∨ (f1 = "hash160" ∧ f2 = "hash160") ∨ (f1 = "sha256" ∧ f2 = "sha256") := by
    have h := hFuncs
    simp only [hashChainFuncsOk, Bool.or_eq_true, Bool.and_eq_true,
      beq_iff_eq] at h
    rcases h with ((h | h) | h) | h
    · exact Or.inl h
    · exact Or.inr (Or.inl h)
    · exact Or.inr (Or.inr (Or.inl h))
    · exact Or.inr (Or.inr (Or.inr h))
  -- N-007: the body never deserializes state, so the parameter
  -- shadow-rename is the identity and `lowerMethod` is `lowerMethodCore`.
  rw [Lower.lowerMethod_of_noDeserialize progMethods props anfM (by
    rw [hBody]; simp [hashChainBody, Lower.bindingsUseDeserializeState])]
  unfold Lower.lowerMethodCore
  rw [hParams, hBody, hPub]
  simp only [List.map_cons, List.map_nil, List.reverse_cons, List.reverse_nil,
    List.nil_append]
  have hUsesPre : Lower.bindingsUseCheckPreimage
      (hashChainBody d1 d2 arg f1 f2 s1 s2) = false := by
    simp [hashChainBody, Lower.bindingsUseCheckPreimage]
  have hUsesCode : Lower.bindingsUseCodePart
      (hashChainBody d1 d2 arg f1 f2 s1 s2) = false := by
    rcases hF with ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ <;> subst h1 <;>
      subst h2 <;> simp [hashChainBody, Lower.bindingsUseCodePart]
  have hEndsAssert : Lower.bodyEndsInAssert
      (hashChainBody d1 d2 arg f1 f2 s1 s2) = false := by
    simp [hashChainBody, Lower.bodyEndsInAssert]
  have hNoDeser : Lower.bindingsUseDeserializeState
      (hashChainBody d1 d2 arg f1 f2 s1 s2) = false := by
    simp [hashChainBody, Lower.bindingsUseDeserializeState]
  rw [hUsesPre, hUsesCode,
      computeLastUses_hashChain d1 d2 arg f1 f2 s1 s2 hNe]
  rw [show ((hashChainBody d1 d2 arg f1 f2 s1 s2).map (·.name))
        = [d1, d2] by simp [hashChainBody, ANFBinding.name]]
  simp only [Bool.false_eq_true, if_false]
  -- NEW-004: the hash-chain body is two calls, no byte-array producer.
  rw [show Lower.collectRawSlots (hashChainBody d1 d2 arg f1 f2 s1 s2) = [] from by
        simp [hashChainBody, Lower.collectRawSlots, Lower.collectRawSlotsGo,
              Lower.rawResultValue]]
  -- …and no `array_literal` binding, so the element table is empty too.
  rw [show Lower.arrayElemsOf (hashChainBody d1 d2 arg f1 f2 s1 s2) = [] from by
        simp [hashChainBody, Lower.arrayElemsOf]]
  rw [lowerBindingsP_hashChain progMethods props Lower.defaultInlineBudget
    [d1, d2] (Lower.collectConstInts (hashChainBody d1 d2 arg f1 f2 s1 s2))
    d1 d2 arg f1 f2 op1 op2 s1 s2 hCallWit1 hCallWit2]
  simp [hEndsAssert, hashChainOps]

/-! ### Part 9b — the W2 runtime walks (completion bits; value-terminated) -/

section W2Walks
open RunarVerification.ANF.Eval (Value State evalValue evalBindings evalBindingsP)
open RunarVerification.Stack.Eval
open RunarVerification.ANF.Eval.Crypto

/-- **ANF walk (W2).**  The 2-chain body always completes: both hash calls
succeed through the shared backend.  Generic via the two call witnesses (the
second stated at the post-`d1` state). -/
theorem evalBindingsP_hashChain_isSome
    (progMethods : List ANFMethod) (s : State)
    (d1 d2 arg f1 f2 : String) (s1 s2 : Option SourceLoc)
    (dg1 dg2 : ByteArray)
    (hCall1 : evalValue s (.call f1 [arg]) = .ok (.vBytes dg1, s))
    (hCall2 : evalValue (s.addBinding d1 (.vBytes dg1)) (.call f2 [d1])
      = .ok (.vBytes dg2, s.addBinding d1 (.vBytes dg1))) :
    (evalBindingsP progMethods s
        (hashChainBody d1 d2 arg f1 f2 s1 s2)).toOption.isSome = true := by
  have hNoMC : RunarVerification.ANF.Eval.noMethodCallBindings
      (hashChainBody d1 d2 arg f1 f2 s1 s2) = true := by
    simp [hashChainBody, RunarVerification.ANF.Eval.noMethodCallBindings,
      RunarVerification.ANF.Eval.noMethodCallValue]
  rw [RunarVerification.ANF.Eval.evalBindingsP_eq_evalBindings_of_noMethodCall
        progMethods s _ hNoMC]
  show (evalBindings s
      [⟨d1, .call f1 [arg], s1⟩, ⟨d2, .call f2 [d1], s2⟩]).toOption.isSome = true
  unfold evalBindings
  rw [hCall1]
  simp only [bind, Except.bind]
  unfold evalBindings
  rw [hCall2]
  simp [bind, Except.bind, evalBindings, Except.toOption]

/-- Single hash-opcode step WITHOUT the (model-unused) 520-byte premise: the
VM's `runOpcode` imposes no operand-size check, and the intermediate digest
of a chain is backend-opaque (in reality 20/32 bytes, far under the consensus
push limit), so the chain walk steps through this size-free local variant
(sha256). -/
theorem runOps_sha256_step_nosize
    (s : StackState) (b : ByteArray) (tail : List Value)
    (hStk : s.stack = .vBytes b :: tail) :
    runOps [.opcode "OP_SHA256"] s
      = .ok { s with stack := .vBytes (sha256 b) :: tail } := by
  show runOps (.opcode "OP_SHA256" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode]
  have hLift : runOpcode "OP_SHA256" s
      = liftBytesUnary s (fun bb => .vBytes (sha256 bb)) := rfl
  have hPop : s.pop? = some (.vBytes b, { s with stack := tail }) := by
    unfold StackState.pop?
    rw [hStk]
  rw [hLift]
  unfold liftBytesUnary
  rw [hPop]
  simp [runOps_nil, StackState.push, asBytes?]

/-- Size-free `hash160` step (see the sha256 peer for the rationale). -/
theorem runOps_hash160_step_nosize
    (s : StackState) (b : ByteArray) (tail : List Value)
    (hStk : s.stack = .vBytes b :: tail) :
    runOps [.opcode "OP_HASH160"] s
      = .ok { s with stack := .vBytes (hash160 b) :: tail } := by
  show runOps (.opcode "OP_HASH160" :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode]
  have hLift : runOpcode "OP_HASH160" s
      = liftBytesUnary s (fun bb => .vBytes (hash160 bb)) := rfl
  have hPop : s.pop? = some (.vBytes b, { s with stack := tail }) := by
    unfold StackState.pop?
    rw [hStk]
  rw [hLift]
  unfold liftBytesUnary
  rw [hPop]
  simp [runOps_nil, StackState.push, asBytes?]

/-- **Stack walk (W2).**  The 2-chain ops complete, leaving the composed
digest on top.  Generic via the two single-op step witnesses. -/
theorem runOps_hashChainOps_ok
    (stkSt : StackState) (op1 op2 : String) (dg1 dg2 : ByteArray)
    (rest : List Value)
    (hStep1 : runOps [.opcode op1] stkSt
      = .ok { stkSt with stack := .vBytes dg1 :: rest })
    (hStep2 : runOps [.opcode op2] { stkSt with stack := .vBytes dg1 :: rest }
      = .ok { stkSt with stack := .vBytes dg2 :: rest }) :
    runOps (hashChainOps op1 op2) stkSt
      = .ok { stkSt with stack := .vBytes dg2 :: rest } := by
  have hSplit : hashChainOps op1 op2 = [.opcode op1] ++ [.opcode op2] := rfl
  rw [hSplit, runOps_append, hStep1]
  exact hStep2

end W2Walks

/-! ### Part 9c — the W2 decidable fragment classifier -/

/-- Decidable 2-chain consume fragment classifier.  `d2` (the final binding
name) is unconstrained — it is never read. -/
def hashChainConsumeShapeBool (m : ANFMethod) : Bool :=
  match m.body with
  | [ANFBinding.mk d1 (.call f1 [arg]) _,
     ANFBinding.mk _ (.call f2 [r]) _] =>
      hashChainFuncsOk f1 f2 && r == d1
        && (m.params.map (·.name) == [arg]) && d1 != arg
  | _ => false

/-! ### Part 9d — MANDATORY anti-vacuity smokes (concrete, W2) -/

/-- The canonical 2-chain method `h(x) { d1 := sha256(x); d2 := hash160(d1) }`. -/
def hashChainSmokeMethod : ANFMethod :=
  { name := "h"
    params := [ANFParam.mk "x" .byteString]
    body := hashChainBody "d1" "d2" "x" "sha256" "hash160" none none
    isPublic := true }

/-- SMOKE — the W2 classifier fires on the canonical chain (anti-vacuity),
and is disjoint from the single-call and hash-then-assert classifiers. -/
theorem smoke_hashChain_classifier_fires :
    hashChainConsumeShapeBool hashChainSmokeMethod = true ∧
    hashCallConsumeShapeBool hashChainSmokeMethod = false ∧
    hashAssertConsumeShapeBool hashChainSmokeMethod = false := by
  refine ⟨?_, ?_, ?_⟩ <;> decide +kernel

/-- SMOKE — the fusing pair `(sha256, sha256)` IS now classified (2026-06-13
widening; its method ops fuse `[OP_SHA256, OP_SHA256] → [OP_HASH256]`). -/
theorem smoke_hashChain_includes_double_sha256 :
    hashChainConsumeShapeBool
      { hashChainSmokeMethod with
        body := hashChainBody "d1" "d2" "x" "sha256" "sha256" none none } = true := by
  decide +kernel

/-- SMOKE — the canonical chain's method ops reduce to the bare 2-opcode list. -/
theorem smoke_hashChain_method_ops :
    (Lower.lowerMethod [] [] hashChainSmokeMethod).ops
      = hashChainOps "OP_SHA256" "OP_HASH160" := by
  apply lowerMethod_ops_hashChain [] [] hashChainSmokeMethod
    "d1" "d2" "x" "sha256" "hash160" "OP_SHA256" "OP_HASH160" .byteString
    none none rfl rfl rfl (by decide) (by decide)
  · exact lowerValueP_call_sha256_consume_d0_full [] [] Lower.defaultInlineBudget 0
      [("d1", 1), ("x", 0)] ["d1", "d2"]
      (Lower.collectConstInts (hashChainBody "d1" "d2" "x" "sha256" "hash160" none none))
      "d1" "x" [] (by decide)
  · exact lowerValueP_call_hash160_consume_d0_full [] [] Lower.defaultInlineBudget 1
      [("d1", 1), ("x", 0)] ["d1", "d2"]
      (Lower.collectConstInts (hashChainBody "d1" "d2" "x" "sha256" "hash160" none none))
      "d2" "d1" [] (by decide)

end RunarVerification.Stack.AgreesHashCall
