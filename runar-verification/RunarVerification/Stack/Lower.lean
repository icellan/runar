import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Blake3
import RunarVerification.Stack.Wots
import RunarVerification.Stack.Ec
import RunarVerification.Stack.P256P384
import RunarVerification.Stack.SlhDsa
import RunarVerification.Stack.BabyBear
import RunarVerification.Stack.Merkle

/-!
# Stack IR — Lowering pass (Phase 3a, simple-constructor subset)

A pure Lean function `lower : ANFProgram → StackProgram` mirroring the
TypeScript reference at `packages/runar-compiler/src/passes/05-stack-lower.ts`.

**Scope (Phase 3a).** This module handles a tractable subset of the 18
ANFValue constructors — concretely the ten that are common to the
simplest conformance fixtures and that allow byte-exact mirroring
without the multi-page expansions used by `addOutput`,
`getStateScript`, and friends. The supported subset is captured by the
`SimpleANF` predicate at the bottom of this file; programs outside it
are still lowered (so `lake build` passes), but the simulation theorem
in `Sim.lean` only quantifies over `SimpleANF` programs. Phase 3b will
extend coverage to the framework intrinsics.

Supported (concrete):

* `loadParam`, `loadProp`, `loadConst` (all five `ConstValue` forms)
* `binOp` and `unaryOp`
* `call` (built-ins; argument loads + a single opcode)
* `assert`, `updateProp`, `ifVal`, `methodCall`

Out-of-scope (placeholder emission — proven only at the
shape-preservation level, not byte-exact):

* `loop` — bounded unroll, but nested-binding scope tracking is non-trivial
* `addOutput`, `addRawOutput`, `addDataOutput` — full BIP-143 output construction
* `getStateScript`, `checkPreimage`, `deserializeState` — framework intrinsics
* `arrayLiteral` — packed byte layout

For these out-of-scope cases the lower emits a single
`StackOp.opcode "OP_RUNAR_UNSUPPORTED"` sentinel so the program type
checks; the `SimpleANF` predicate forbids their occurrence so the
simulation theorem never has to reason about them.
-/

namespace RunarVerification.Stack
namespace Lower

open RunarVerification.ANF

/-! ## Stack tracking

The TS lowering pass threads a `stackMap : Map<string, number>` where
each entry tracks the depth of an in-scope binding from the top of the
runtime stack. Inserting a new binding pushes onto the map at depth 0
and shifts all others up by one; consuming a stack value pops one
entry. We model this as a flat ordered list of slots, head = top of
stack.

A slot is `some name` when the reference's `stackMap` entry carries a
name, and `none` when it is ANONYMOUS. The TS reference pushes `null`
at 291 of its 383 `push` sites — an anonymous slot occupies a stack
position but cannot be addressed by name — and the issue #149 reconcile
`restoreInheritedLayout` (`05-stack-lower.ts:1212-1300`) ABORTS, emitting
nothing, the moment either the parent's post-`if` model or the arm's
inherited region holds one (`if (n === null) return` at `1236`,
`if (w === null) return` at `1263`). Those bail-outs are load-bearing
correctness: without an anonymous slot in the representation the model
would re-sort in exactly the cases where the reference deliberately does
nothing.

`Option String` rather than a bespoke `Slot` inductive on purpose: it
inherits `BEq`/`DecidableEq`/`Repr`, keeps every `decide` over a literal
stack map working, and — because Lean coerces `String` to `Option String`
at the leaves of a list literal whose expected type is known — leaves the
existing literal spellings (`["f", "a"]`) untouched.

Every slot the model pushes today is still NAMED (`StackMap.push`), so
introducing the representation moves ZERO emitted bytes; `pushAnon` is
the constructor a future faithful port of `restoreInheritedLayout` needs.
-/

abbrev StackMap := List (Option String)

/-- Depth-from-top of `name` in `sm`, or `none` if absent. Anonymous
slots are never found: they have no name to match. -/
def StackMap.depth? (sm : StackMap) (name : String) : Option Nat :=
  sm.findIdx? (· == some name)

/-- Push a fresh binding name onto the top of the tracked stack. -/
def StackMap.push (sm : StackMap) (name : String) : StackMap :=
  some name :: sm

/-- Push an ANONYMOUS slot: it occupies a stack position but no
`depth?` / `findFrom?` lookup can address it. Mirrors the reference's
`push(null)`. -/
def StackMap.pushAnon (sm : StackMap) : StackMap :=
  none :: sm

/-- The names in `sm`, anonymous slots dropped. Used where a stack map
feeds a name-only structure (`outerProtected`, `consumedNames`). -/
def StackMap.names (sm : StackMap) : List String :=
  sm.filterMap id

/--
Remove the entry at the given depth (counted from the top), shifting all
deeper entries up by one. Mirrors the `removeAtDepth` calls inside the TS
`bringToTop` (`05-stack-lower.ts:819-828`). Out-of-range depths return
the input unchanged.
-/
def StackMap.removeAtDepth : StackMap → Nat → StackMap
  | [],      _       => []
  | _ :: xs, 0       => xs
  | x :: xs, n + 1   => x :: StackMap.removeAtDepth xs n

/-! ## Liveness analysis (Phase 3x)

Mirrors the TS `computeLastUses` / `collectRefs` / `isLastUse` trio at
`05-stack-lower.ts:247-332` and `:973-976`. Maps each ref name to the
**last** binding index (within the current sequence) that reads it; on
the final read we may consume the slot via ROLL/SWAP/ROT instead of
copying via PICK/OVER/DUP.

The map is represented as an associative `List (String × Nat)` (no
`Std.RBMap` dependency, no `mathlib`). Lookups are `O(n)` in the size
of the binding list — fine at the scales the conformance suite uses.
-/

/-- Set (or overwrite) `name`'s last-use index in the assoc list. -/
def lastUsesUpdate (m : List (String × Nat)) (name : String) (idx : Nat) :
    List (String × Nat) :=
  (name, idx) :: m.filter (fun p => p.1 != name)

/-- Look up the last-use index for `name`, or `none` if absent. -/
def lastUsesLookup (m : List (String × Nat)) (name : String) : Option Nat :=
  (m.find? (fun p => p.1 == name)).map (·.2)

/-! ## `collectRefs` — which names does an ANFValue read?

Mirrors `collectRefs` in `05-stack-lower.ts:260-332` for the
constructors covered by `simpleValue`. Crypto-only constructors that
are never reached under `SimpleANF` return `[]`.
-/

mutual

/-- Names referenced by an ANFValue, in left-to-right read order. -/
def collectRefs : ANFValue → List String
  | .loadParam n              => [n]
  | .loadProp _               => []
  | .loadConst (.refAlias n)  => [n]
  | .loadConst _              => []
  | .binOp _ l r _            => [l, r]
  | .unaryOp _ operand _      => [operand]
  | .call _ args              => args
  | .methodCall obj _ args    => (obj :: args : List String)
  | .ifVal cond thn els _       =>
      (cond :: collectRefsBindings thn) ++ collectRefsBindings els
  | .loop _ body _            => collectRefsBindings body
  | .assert ref               => [ref]
  | .updateProp _ ref         => [ref]
  | .checkPreimage pre        => [pre]
  | .deserializeState pre     => [pre]
  | .arrayLiteral elems       => elems
  | .addRawOutput sat scr     => [sat, scr]
  | .addDataOutput sat scr    => [sat, scr]
  | .addOutput sat vals pre   => (sat :: vals) ++ [pre]
  | .getStateScript           => []
  | .rawScript _ _ _          => []

def collectRefsBindings : List ANFBinding → List String
  | []                  => []
  | (.mk _ v _) :: rest =>
      collectRefs v ++ collectRefsBindings rest

end

/--
Compute last-use indices for a binding list. Mirrors
`computeLastUses` in `05-stack-lower.ts:247-258`: walk the bindings in
order, and for every ref read by `b_i.value`, set
`lastUse[ref] = i` (later writes override earlier ones, so the last
binding that reads `ref` "wins").
-/
def computeLastUses (bs : List ANFBinding) : List (String × Nat) :=
  let rec go (acc : List (String × Nat)) (idx : Nat) :
      List ANFBinding → List (String × Nat)
    | [] => acc
    | (.mk _ v _) :: rest =>
        let acc' :=
          (collectRefs v).foldl (init := acc) fun a r => lastUsesUpdate a r idx
        go acc' (idx + 1) rest
  go [] 0 bs

/-! ### `constInts` — binding-name → integer literal map (Phase 4-K)

Mirrors the `constValues` tracking in `compilers/go/codegen/stack.go:345`
(see also `getConstantValue` in `packages/runar-compiler/src/passes/05-stack-lower.ts`).
For every binding of the form `name = loadConst (.int i)` in the method
body (including any nested if-branch / loop-body / methodCall-body)
the map records `name → i`. Used by the Merkle codegen dispatch to
extract the compile-time depth literal that becomes the unrolled-loop
bound (`merkleRootSha256(_, _, _, depth)` etc.).

The map is method-wide and immutable for the duration of one
`lowerMethod` call; it is built once at `lowerMethod` entry and threaded
through `lowerValueP` / `lowerBindingsP` like `lastUses`. -/

mutual

/-- Collect `(name, i)` pairs for every `name = loadConst (.int i)`
binding reachable from `bs`, descending into if-branches and loop
bodies so const literals defined in outer scopes remain visible to
inner-scope dispatch arms. -/
def collectConstInts : List ANFBinding → List (String × Int)
  | []                    => []
  | (.mk name v _) :: rest =>
      let here : List (String × Int) :=
        match v with
        | .loadConst (.int i)   => [(name, i)]
        | .ifVal _ thn els _      => collectConstInts thn ++ collectConstInts els
        | .loop _ body _        => collectConstInts body
        | _                     => []
      here ++ collectConstInts rest

end

/-- Look up `name` in the const-int map; return `none` if absent. -/
def constIntsLookup (m : List (String × Int)) (name : String) : Option Int :=
  (m.find? (fun p => p.1 == name)).map (·.2)

/-! ### `arrayElems` — element refs of `array_literal` bindings

Mirrors `LoweringContext.arrayElements` (`05-stack-lower.ts:565`), the
map `lowerArrayLiteral` (`05-stack-lower.ts:2140-2146`) populates and
`lowerCheckMultiSig` (`05-stack-lower.ts:1928-1936`) reads.

An `array_literal` binding is metadata-only in the reference: it emits
nothing and pushes NOTHING onto the stack map, because the map can only
model one slot per binding while an array binding spans N runtime slots.
The element refs stay on the map under their own binding names, and
`checkMultiSig` pulls each one to the top at the use site.

Like `constInts` / `rawSlots`, the table is method-wide and immutable for
the duration of one `lowerMethod` call: built once at `lowerMethod` entry
and threaded UNCHANGED through `lowerValueP` / `lowerBindingsP` (the
inlined-methodCall arm merges the callee's contributions the same way
`rawSlots` does, because TS inlines into the SAME `LoweringContext`). -/

mutual

/-- Collect `(name, elements)` pairs for every `name = array_literal
elements` binding reachable from `bs`, descending into if-branches and
loop bodies so an array defined in an outer scope stays visible to an
inner-scope `checkMultiSig`. -/
def arrayElemsOf : List ANFBinding → List (String × List String)
  | []                     => []
  | (.mk name v _) :: rest =>
      let here : List (String × List String) :=
        match v with
        | .arrayLiteral elems  => [(name, elems)]
        | .ifVal _ thn els _   => arrayElemsOf thn ++ arrayElemsOf els
        -- A zero-count loop is never lowered, so the reference's
        -- `lowerArrayLiteral` never runs for its body and the entries never
        -- reach `arrayElements`. Same gate `collectRawSlotsGo` applies.
        | .loop 0 _ _          => []
        | .loop _ body _       => arrayElemsOf body
        | _                    => []
      here ++ arrayElemsOf rest

end

/-- Look up an `array_literal` binding's element refs; `none` if the ref
does not name an array literal. -/
def arrayElemsLookup (m : List (String × List String)) (name : String) :
    Option (List String) :=
  (m.find? (fun p => p.1 == name)).map (·.2)

/--
Whether reading `ref` at position `currentIndex` is the **final** read
of `ref` within the current binding sequence. Mirrors `isLastUse` in
`05-stack-lower.ts:973-976`: returns `true` when the recorded last-use
index is at or before `currentIndex` (or when `ref` was never recorded).
-/
def isLastUse (m : List (String × Nat)) (ref : String) (currentIndex : Nat) : Bool :=
  match lastUsesLookup m ref with
  | none      => true
  | some last => last ≤ currentIndex

/--
Set membership over `List String` (no mathlib).

Used to discriminate locally-bound names (consume-eligible) from
outer-scope names (must be PICK-copied even on their last use, because
the parent scope's stack map still expects them). Mirrors the TS
`localBindings` field at `05-stack-lower.ts:856-857`.
-/
def listContains (xs : List String) (x : String) : Bool :=
  xs.any (· == x)

/--
Consume-vs-copy decision for one operand of a multi-operand ANF value.
Mirrors TS `operandConsume` (`05-stack-lower.ts:1143-1156`, PRs
#62/#67/#68, implemented identically in all 7 production compilers):

> consume = isLastUse(ref, bindingIndex) AND ref occurs exactly once in
> the value's FULL operand list.

`operands` is the full operand-ref list of the value (including `ref`
itself). A ref that is read at more than one operand position of the
same value must be copied (PICK / DUP) at EVERY position: a consume-mode
load of a ref already on top of the stack is a no-op (`bringToTop` d0
consume = `[]`), so two consume-mode loads of the same ref would leave a
single slot for an opcode that pops one item per operand (e.g.
`t := x + x` underflowing OP_ADD). The original value then simply stays
on the stack, like any ref whose last use is a later binding. Reduces
exactly to the old `isLastUse` form when `ref` occurs at most once.

The Lean model additionally keeps the `outerProtected` gate that
`loadRefLive` applies (the TS equivalent lives in `bringToTop`'s caller
context). The repeated-operand clause is deliberately LAST so that
copy-mode proofs (first conjuncts `false`) short-circuit without
needing operand-distinctness facts.
-/
def operandConsume (lastUses : List (String × Nat)) (outerProtected : List String)
    (ref : String) (operands : List String) (currentIndex : Nat) : Bool :=
  !listContains outerProtected ref && isLastUse lastUses ref currentIndex
    && ((operands.filter (· == ref)).length ≤ 1)

/-- Names bound by a binding sequence — i.e. the LHS of every binding
plus, for `update_prop`, the property name (which the binding writes to). -/
def collectBoundNames : List ANFBinding → List String
  | []                         => []
  | (.mk name v _) :: rest =>
      let here :=
        match v with
        | .updateProp p _ => [name, p]
        | _              => [name]
      here ++ collectBoundNames rest

/-- Every name bound anywhere in `body`, including inside `if` arms and
nested `loop` bodies. TS `collectDeepBindingNames`.

Structurally recursive (no fuel) so that concrete small bodies reduce
definitionally — the `rfl`-level loop pins in `AgreesA7` depend on it. -/
def collectDeepBindingNames : List ANFBinding → List String
  | [] => []
  | (.mk name (.ifVal _ t e _) _) :: rest =>
      (name :: (collectDeepBindingNames t ++ collectDeepBindingNames e))
        ++ collectDeepBindingNames rest
  | (.mk name (.loop _ body _) _) :: rest =>
      (name :: collectDeepBindingNames body) ++ collectDeepBindingNames rest
  | (.mk name _ _) :: rest => name :: collectDeepBindingNames rest
termination_by xs => sizeOf xs

/-- A binding sequence with every nested `loop` and every `if` binding
replaced, in place, by its own recursively-flattened body (`if` arms in
`then ++ else` order, and the `if` binding itself NOT re-appended).
Mirrors TS `flattenNestedLoopBodies`. Only `collectLoopCarriedRebinds`
uses it, and only to order reads against rebindings. -/
def flattenNestedLoopBodies : List ANFBinding → List ANFBinding
  | [] => []
  | (.mk _ (.loop _ body _) _) :: rest =>
      flattenNestedLoopBodies body ++ flattenNestedLoopBodies rest
  | (.mk _ (.ifVal _ t e _) _) :: rest =>
      (flattenNestedLoopBodies t ++ flattenNestedLoopBodies e)
        ++ flattenNestedLoopBodies rest
  | b :: rest => b :: flattenNestedLoopBodies rest
termination_by xs => sizeOf xs

/-- Locals the body REBINDS and then READS again, so their value is carried
across iterations through the rebound slot and they must survive the body
exactly like an outer ref. TS `collectLoopCarriedRebinds`: a name read
before its first binding AND read after its last binding. -/
def collectLoopCarriedRebinds (body : List ANFBinding) : List String :=
  let flat := flattenNestedLoopBodies body
  let names := flat.map ANFBinding.name
  let firstBind (n : String) : Option Nat := names.findIdx? (fun m => m == n)
  let lastBind (n : String) : Option Nat :=
    match names.reverse.findIdx? (fun m => m == n) with
    | some i => some (names.length - 1 - i)
    | none   => none
  let idxs := List.range flat.length
  let scan (pick : Nat → String → Bool) : List String :=
    idxs.foldl (init := ([] : List String)) fun acc i =>
      match flat[i]? with
      | none   => acc
      | some b =>
          (collectRefs b.value).foldl (init := acc) fun a r =>
            if pick i r && !listContains a r then a ++ [r] else a
  let readBeforeBind := scan (fun i r => match firstBind r with
                                          | some f => i < f
                                          | none   => false)
  let readAfterBind  := scan (fun i r => match lastBind r with
                                          | some l => i > l
                                          | none   => false)
  readBeforeBind.filter (fun n => listContains readAfterBind n)

/-- Outer-scope refs referenced by `body`, mirroring TS `lowerLoop`
(`05-stack-lower.ts:2680-2705`).

The scan is RECURSIVE (`collectRefs` descends into `if` arms and nested
loop bodies) and excludes the DEEP bound-name set. An earlier version
scanned only top-level `load_param` / `@ref:` bindings against the
top-level bound names; a ref used only inside an `if` arm was then never
clamped, the first iteration consumed it, and the next iteration emitted
`OP_RUNAR_UNRESOLVED_*` — `loop-if-merged-locals`' `x`. The comment on
that version claimed it matched the TS reference exactly; it matched an
older TS, which has since fixed the same bug ("The previous top-level-only
scan missed nested references"). -/
def bodyOuterRefs (body : List ANFBinding) (iterVar : String) :
    List String :=
  let deepBound := collectDeepBindingNames body
  let base :=
    body.foldl (init := ([] : List String)) fun acc b =>
      (collectRefs b.value).foldl (init := acc) fun a r =>
        if r == iterVar || listContains deepBound r || listContains a r then a
        else a ++ [r]
  (collectLoopCarriedRebinds body).foldl (init := base) fun a n =>
    if n == iterVar || listContains a n then a else a ++ [n]

/-- The loop body's outer refs that the ENCLOSING scope still reads AFTER
the loop binding. TS clamps exactly these in the FINAL iteration as well
(`05-stack-lower.ts:2723-2741`); everything else may be consumed there. -/
def loopOuterRefsUsedAfter (body : List ANFBinding) (iterVar : String)
    (lastUses : List (String × Nat)) (currentIndex : Nat) : List String :=
  (bodyOuterRefs body iterVar).filter fun r =>
    match lastUsesLookup lastUses r with
    | some idx => decide (idx > currentIndex)
    | none     => false

/-- For non-final loop iters, bump the recorded last-use index of every
outer ref to `clampTo` so they cannot be considered last-use within the
body. Mirrors TS `lowerLoop` (`05-stack-lower.ts:2149-2154`). -/
def clampLastUsesForOuter (m : List (String × Nat))
    (outerRefs : List String) (clampTo : Nat) : List (String × Nat) :=
  outerRefs.foldl (init := m) fun acc r => lastUsesUpdate acc r clampTo

/-- Remove the shallowest slot carrying each of `names`, in order. Mirrors TS
`lowerIf`'s post-`OP_ENDIF` parent reconcile (`05-stack-lower.ts:2928-2934`).

`abbrev`, not `def`: it is a spelling of a fold the `.ifVal` arm used inline in
two places and that `Agrees.lean` has to name in a hypothesis. A shared constant
makes the two sides syntactically equal — two textually identical inline
`match`es elaborate to two DIFFERENT auxiliary matchers, which `rw` cannot
bridge — while reducibility keeps every existing `rfl` / `decide` working. -/
abbrev removeNames (sm : StackMap) (names : List String) : StackMap :=
  names.foldl (init := sm) fun m n =>
    match m.depth? n with
    | some d => m.removeAtDepth d
    | none   => m

/-- Names present in `before` but absent from `after`. Used by `lowerIf`
to identify parent-scope items that one branch consumed (asymmetrically)
so the other branch can emit matching ROLL+DROP cleanup. -/
def consumedNames (before : StackMap) (after : StackMap) :
    List String :=
  before.foldl (init := ([] : List String)) fun acc slot =>
    match slot with
    | none   => acc          -- an anonymous slot has no name to consume
    | some n =>
        if listContains acc n then acc
        else if listContains after.names n then acc
        else acc ++ [n]

/-- Insertion-sort descending on `Nat`. -/
def sortDesc : List Nat → List Nat
  | []      => []
  | x :: xs =>
      let rec insert (y : Nat) : List Nat → List Nat
        | []      => [y]
        | a :: as => if y ≥ a then y :: a :: as else a :: insert y as
      insert x (sortDesc xs)

/-- Emit ROLL+DROP cleanup for `names` from a stackmap's perspective.
Mirrors TS `lowerIf`'s asymmetric-consumption fix
(`05-stack-lower.ts:1731-1772`).

For each name we look up its depth, then sort the depths descending so
that deeper drops execute first (avoiding shifts in shallower entries).
Per-depth ops:
* `d = 0` → `[.drop]`
* `d = 1` → `[.nip]`
* `d ≥ 2` → `[push d, OP_ROLL, .drop]`. The literal `push d` consumes
  one slot, ROLL brings the entry from depth `d+1` (after the push) to
  top, DROP removes it.

The stackmap is updated to remove the consumed names. Returns the op
list and the updated stackmap. -/
def removeConsumedAtDepths (sm : StackMap) (names : List String) :
    (List StackOp × StackMap) :=
  -- Collect depths for names that exist in sm.
  let depths : List Nat :=
    names.foldl (init := ([] : List Nat)) fun acc n =>
      match sm.depth? n with
      | some d => acc ++ [d]
      | none   => acc
  let sorted := sortDesc depths
  -- Walk sorted depths; for each emit cleanup and remove from sm.
  let rec go (sm : StackMap) : List Nat → (List StackOp × StackMap)
    | []      => ([], sm)
    | d :: ds =>
        let ops : List StackOp :=
          if d = 0 then [.drop]
          else if d = 1 then [.nip]
          else if d = 2 then [.opcode "OP_ROT", .drop]
          else [.push (.bigint (Int.ofNat d)), .opcode "OP_ROLL", .drop]
        let sm' := sm.removeAtDepth d
        let (rest, smF) := go sm' ds
        (ops ++ rest, smF)
  go sm sorted

/-- Physically drop the slot at depth `d`, mirroring TS `dropSlotAtDepth`
(`05-stack-lower.ts:2314-2333`).

The per-depth op shape is the one `removeConsumedAtDepths` above already
uses — the same TS emitter feeds both — including the `d = 2` `OP_ROT`
form the reference's peephole pass folds `[push 2, OP_ROLL]` into. -/
def dropSlotAtDepth (sm : StackMap) (d : Nat) : (List StackOp × StackMap) :=
  let ops : List StackOp :=
    if d = 0 then [.drop]
    else if d = 1 then [.nip]
    else if d = 2 then [.opcode "OP_ROT", .drop]
    else [.push (.bigint (Int.ofNat d)), .opcode "OP_ROLL", .drop]
  (ops, sm.removeAtDepth d)

/-- Trim a declared-results branch arm down to `target` physical slots by
repeatedly dropping the slot immediately BELOW the `k` result slots.

Mirrors TS `lowerIf` (`05-stack-lower.ts:2620-2624`):
```
for (const ctx of [thenCtx, elseCtx]) {
  while (ctx.stackMap.depth > targetDepth) ctx.dropSlotAtDepth(nDeclared);
}
```
Everything beneath the `k` results is dead by construction: the arm's
`__merge$` block copied each declared result before rebinding it, and a
branch-local binding is not visible after the `if`. `fuel` bounds the
`while` — each step removes one slot, so the arm's own depth suffices. -/
def trimArmToDepth (k target : Nat) : Nat → StackMap → (List StackOp × StackMap)
  | 0, sm => ([], sm)
  | fuel + 1, sm =>
      if sm.length > target then
        let (ops, sm') := dropSlotAtDepth sm k
        let (rest, smF) := trimArmToDepth k target fuel sm'
        (ops ++ rest, smF)
      else
        ([], sm)

/-- Occurrences of `name` in `sm`. Mirrors TS `lowerIf`'s local `countNames`
(`05-stack-lower.ts:2576-2583`), which skips anonymous slots. -/
def StackMap.countName (sm : StackMap) (name : String) : Nat :=
  sm.foldl (init := 0) fun acc slot => if slot == some name then acc + 1 else acc

/-- Worker for `inheritedModel`. `skipped` records, per name, how many
occurrences have already been dropped — the reference decrements a shared
`excess` map instead, which is the same thing counted from the other end. -/
def inheritedModelGo (smParent smArm : StackMap) :
    StackMap → List (String × Nat) → StackMap
  | [],             _       => []
  | none :: rest,   skipped => none :: inheritedModelGo smParent smArm rest skipped
  | some n :: rest, skipped =>
      let excess := smParent.countName n - smArm.countName n
      let already := (lastUsesLookup skipped n).getD 0
      if already < excess then
        inheritedModelGo smParent smArm rest (lastUsesUpdate skipped n (already + 1))
      else
        some n :: inheritedModelGo smParent smArm rest skipped

/--
TS `lowerIf`'s `inheritedModel` (`05-stack-lower.ts:2807-2822`): the parent's
post-`if` model — its slots minus, per name, the occurrences the arms gave up,
dropped SHALLOWEST-first. Anonymous parent slots are never dropped.

An arm whose own map IS this model produced no result of its own, which is what
tells `padBelowResult` that its pad belongs on TOP rather than tucked under a
result (NEW-019). Depth cannot distinguish the two shapes — both reach phase 3
one slot short — so the reference compares positionally, and so do we.
-/
def inheritedModel (smParent smArm : StackMap) : StackMap :=
  inheritedModelGo smParent smArm smParent []

/--
Depth-balance pads for the shallower arm of an `if`, mirroring TS `lowerIf`
phase 3 (`05-stack-lower.ts:2853-2884`).

The reference pads in a `while`, ONE slot per iteration, until the two arms
agree — a conditional write of N state fields leaves N result values on the
then-arm, so the else-arm owes N preserved slots (issue #99 Bug 1). The model
used to emit exactly one pad regardless of the deficit. Each pad is
`push <empty bytes>` plus the anonymous slot it occupies
(`armCtx.stackMap.push(null)`).

`padsBelow` / `padsOnTop` drive the reference's `padBelowResult`
(`05-stack-lower.ts:2833-2840`): for a VALUE-producing conditional the pad must
not land on top of the arm's own result and BECOME the result (NEW-017), so it
is SWAPped underneath — unless the arm produced no result at all, in which case
the swap would displace the whole inherited region instead (NEW-019).

`n = 0` is the common case (arms already agree) and reduces to `([], sm)`
whatever the flags say, which is what keeps the clean-shape lemmas working.
-/
def padArm (padsBelow padsOnTop : Bool) : Nat → StackMap → (List StackOp × StackMap)
  | 0,     sm => ([], sm)
  | n + 1, sm =>
      let smPad := sm.pushAnon
      let (swapOps, smSwapped) : (List StackOp × StackMap) :=
        if padsOnTop || !padsBelow then ([], smPad)
        else
          match smPad with
          | a :: b :: rest => ([StackOp.swap], b :: a :: rest)
          | _              => ([], smPad)     -- TS `armCtx.stackMap.depth < 2`
      let (rest, smF) := padArm padsBelow padsOnTop n smSwapped
      (.push (.bytes ByteArray.empty) :: (swapOps ++ rest), smF)

@[simp] theorem padArm_zero (padsBelow padsOnTop : Bool) (sm : StackMap) :
    padArm padsBelow padsOnTop 0 sm = ([], sm) := rfl

/-- Arms that already agree owe no pad. This is what discharges the
depth-balance step in the `.ifVal` clean-shape lemmas, where the pre-`padArm`
`if thnDepth > elsDepth then … else if …` was discharged by `omega`. -/
theorem padArm_of_eq {a b : Nat} (h : a = b) (padsBelow padsOnTop : Bool)
    (sm : StackMap) :
    padArm padsBelow padsOnTop (a - b) sm = ([], sm) := by
  subst h; simp

/-! ### `restoreInheritedLayout` — issue #149's arm-layout reconcile

An arm may have ROTATED the region it inherited from the enclosing `if`: a
declared-results `if` nested inside it ROLL+DROPs its own stale slot out from
under its results, and that scan reaches into the inherited region. The arm then
comes back with the same names at the same depth in a DIFFERENT ORDER, which
nothing else in `lowerIf` can see — the reconcile compares name multisets, the
balance check compares depths, and an `if` that declares no results and changes
no depth skips every adoption branch. Both faces are fund-safety bugs: the else
path fails `OP_VERIFY` on a spend the source allows, and a guard evaluates TRUE
on inputs the source rejects.

Ported from `05-stack-lower.ts:1212-1300`, called at `:2974` on BOTH arms after
the parent reconcile. The permutation is over SLOT POSITIONS, not names: the
inherited region legitimately holds a stale duplicate of a declared result's
name, and an unrolled loop leaves one identically-named slot per iteration, so
only the mapping from the parent's names to region positions is by name and it
matches the j-th occurrence to the j-th occurrence.

The two `return`s on an ANONYMOUS slot (`:1236`, `:1263`) are load-bearing: a
slot with no name cannot be matched to a model slot, and re-sorting past it
would move a value the reference deliberately leaves alone. Expressing them is
why `StackMap` had to carry anonymity.
-/

/-- The arm's inherited region, top-down, or `none` if it holds an anonymous
slot (TS `if (n === null) return`, `05-stack-lower.ts:1236`). -/
def regionOf : StackMap → Option (List String)
  | []             => some []
  | none :: _      => none
  | some n :: rest => (regionOf rest).map (n :: ·)

/-- Positions in `region` holding `name`, shallowest first (TS `occurrences`). -/
def regionPositions (region : List String) (name : String) : List Nat :=
  (region.foldl (init := ((0 : Nat), ([] : List Nat))) fun (j, acc) n =>
    (j + 1, if n == name then acc ++ [j] else acc)).2

/-- Build the target permutation: the arm's own results (positions `< k`) map to
themselves, then each model slot maps to the region position holding that name,
j-th occurrence to j-th occurrence. `none` for the two abort conditions — an
ANONYMOUS model slot, or a model slot the region does not hold. -/
def restoreTargetGo (k : Nat) (region : List String) :
    StackMap → List (String × Nat) → List Nat → Option (List Nat)
  | [],             _,     acc => some acc
  | none :: _,      _,     _   => none   -- TS `if (w === null) return` (:1263)
  | some w :: ws,   taken, acc =>
      let occ := regionPositions region w
      let next := (lastUsesLookup taken w).getD 0
      match occ[next]? with
      | none   => none                   -- TS `if (!at || next >= at.length) return`
      | some j => restoreTargetGo k region ws (lastUsesUpdate taken w (next + 1))
                    (acc ++ [k + j])

/-- Deepest position that actually differs; everything below it is already right
and must not be disturbed. `none` = already aligned, emits nothing. -/
def deepestMismatch (target : List Nat) : Option Nat :=
  (target.foldl (init := ((0 : Nat), (none : Option Nat)))
    (fun st t => (st.1 + 1, if t == st.1 then st.2 else some st.1))).2

private theorem deepestMismatch_fold_range (k : Nat) :
    (List.range k).foldl
        (fun (st : Nat × Option Nat) (t : Nat) =>
          (st.1 + 1, if t == st.1 then st.2 else some st.1))
        (0, none)
      = (k, none) := by
  induction k with
  | zero => rfl
  | succ n ih => rw [List.range_succ, List.foldl_append, ih]; simp

/-- The identity permutation is already aligned, so the reconcile emits
nothing. -/
theorem deepestMismatch_range (k : Nat) : deepestMismatch (List.range k) = none := by
  unfold deepestMismatch
  rw [deepestMismatch_fold_range]

/-- Move the slot at depth `d` to the top, the net map effect of TS's
`push(null); pop(); removeAtDepth(d); push(rolled)`. -/
def rollToTop (sm : StackMap) (d : Nat) : StackMap :=
  match sm[d]? with
  | some slot => slot :: sm.removeAtDepth d
  | none      => sm

/-- Bring the slots that belong at `m, m-1, …, 0` to the top in that order.
Tracked by ORIGINAL slot position (`order`), because names repeat across the
split. A ROLL from depth `d` leaves every slot deeper than `d` at its index, so
the untouched tail stays untouched. Emits the fused `.roll d`, whose bytes are
the reference's `push d, OP_ROLL` pair — the two agree on `d`, so the
reference's own `PUSH 2, Roll{2} → Rot` / `PUSH 1, Roll{1} → Swap` peephole
folds fire exactly where `rollPickRewriteOne` folds ours. -/
def restoreRollsGo (target : List Nat) :
    List Nat → (List Nat × List StackOp × StackMap) → (List Nat × List StackOp × StackMap)
  | [],      st => st
  | i :: is, st =>
      let (order, ops, sm) := st
      let st' :=
        match target[i]? with
        | none      => (order, ops, sm)
        | some slot =>
            match order.findIdx? (· == slot) with
            | none         => (order, ops, sm)
            | some 0       => (order, ops, sm)   -- TS `if (d === 0) continue`
            | some (d + 1) =>
                (slot :: order.eraseIdx (d + 1),
                 ops ++ [StackOp.roll (d + 1)],
                 rollToTop sm (d + 1))
      restoreRollsGo target is st'

/-- Re-sort an arm's inherited region back into the parent's slot order.
`parentMap` is the POST-reconcile parent; `stillHeld` the names the then-arm
still holds (TS `postBranchNames`). Returns the ops to append INSIDE the arm
plus the arm's updated map. -/
def restoreInheritedLayout (parentMap : StackMap) (stillHeld : List String)
    (armSm : StackMap) : (List StackOp × StackMap) :=
  -- The parent's post-`if` model: its slots minus the ones the arms consumed.
  -- Anonymous slots are never reconciled away, so they stay.
  let want : StackMap :=
    parentMap.filter fun p =>
      match p with
      | none   => true
      | some n => listContains stillHeld n
  let armDepth := armSm.length
  if armDepth < want.length then ([], armSm)   -- TS `if (k < 0) return`
  else
    let k := armDepth - want.length
    match regionOf (armSm.drop k) with
    | none        => ([], armSm)
    | some region =>
      match restoreTargetGo k region want [] (List.range k) with
      | none        => ([], armSm)
      | some target =>
        match deepestMismatch target with
        | none   => ([], armSm)
        | some m =>
            let (_, ops, smF) :=
              restoreRollsGo target ((List.range (m + 1)).reverse)
                (List.range armDepth, [], armSm)
            (ops, smF)

/-- An empty parent model has nothing to reconcile against: `want` is empty, the
whole arm is its own result region, and the target permutation is the identity.
Emits nothing and leaves the arm map alone. -/
theorem restoreInheritedLayout_parent_nil (stillHeld : List String) (armSm : StackMap) :
    restoreInheritedLayout [] stillHeld armSm = ([], armSm) := by
  unfold restoreInheritedLayout
  simp only [List.filter_nil, List.length_nil, Nat.not_lt_zero,
    Nat.sub_zero, List.drop_length]
  simp only [regionOf, restoreTargetGo, deepestMismatch_range]
  simp

/-- Shallowest depth `≥ start` holding `name`, if any. -/
def StackMap.findFrom? (sm : StackMap) (start : Nat) (name : String) : Option Nat :=
  match (sm.drop start).findIdx? (fun n => n == some name) with
  | some i => some (start + i)
  | none   => none

/-- Lift the slot at depth `d` to the top, preserving every other slot's
relative order. Mirrors the reference's `removeAtDepth(d)` followed by pushing
the lifted slot back (`05-stack-lower.ts:2566-2567`). Out-of-range `d` is the
identity, matching `removeAtDepth`. -/
def StackMap.liftFromDepth (sm : StackMap) (d : Nat) : StackMap :=
  match sm[d]? with
  | none   => sm
  | some x => x :: sm.removeAtDepth d

/-! ### `sinkBelow` — issue #149's arm-layout repair

An arm may have ROTATED the region it inherited from the enclosing `if`: the
ROLL+DROP scan in phase 1 above reaches PAST the declared-result block to find
a stale slot, and the copy does not reorder the slots it crossed. The results
come back with the same names at the same depth in a DIFFERENT ORDER — invisible
to the reconcile (which compares name multisets) and to Layer C (which compares
depths). Everything after `OP_ENDIF` is generated against one assumed layout, so
the other path runs to the end and fails `OP_VERIFY`: funds locked.

The reference repairs it by sinking the whole result block back under the
`sinkBelow` slots it crossed, rolling the deepest item of the
`(nDeclared + sinkBelow)` window to the top, `sinkBelow` times
(`05-stack-lower.ts:2559-2569`). That lifts the crossed slots back above the
results while preserving their own relative order, so BOTH paths of the
enclosing `if` leave the same slot order.

Applied UNCONDITIONALLY, not gated on this `if`'s own else: the asymmetry that
makes #149 unspendable belongs to the ENCLOSING `if`, and `lowerIf` has no view
of its parent here. Gating on an empty else was measured and is wrong — the
#149 inner `if` has a real else, so the gate would disable the repair exactly
where it is needed.

No anonymous-slot bail-out is required. The phase-1 scan matches on a NAME
(`findFrom?`), and an anonymous slot never name-matches, so a `none` slot is
simply never selected as the stale one; there is no case in which the model
would re-sort where the reference does nothing. -/
def sinkResultBlock (n : Nat) (sinkBelow : Nat) (sm : StackMap) :
    List StackOp × StackMap :=
  if sinkBelow == 0 then ([], sm)
  else
    let w := n + sinkBelow
    (List.range sinkBelow).foldl
      (init := (([] : List StackOp), sm))
      fun (ops, m) _ =>
        (ops ++ [.push (.bigint (Int.ofNat (w - 1))), .opcode "OP_ROLL"],
         m.liftFromDepth (w - 1))

/-- `sinkBelow = 0` is the common case — no result crossed an inherited slot —
and must emit nothing, so an `if` that needs no repair keeps its old bytes. -/
theorem sinkResultBlock_zero (n : Nat) (sm : StackMap) :
    sinkResultBlock n 0 sm = ([], sm) := by
  unfold sinkResultBlock; simp

/--
Adopt a multi-result `if`'s DECLARED result slots into the stack map.

Mirrors TS `lowerIf` (`05-stack-lower.ts:2481-2495`): the parent adopts
the declared results — `results[0]` deepest — instead of naming a single
`bindingName`.

Map-only, deliberately. TS pairs the adoption with a `push d / OP_ROLL /
drop` that rolls each shadowed parent slot out from under the results. In
this model that removal has ALREADY happened by the time we get here: the
arms consume the shadowed parent slots themselves and
`removeConsumedAtDepths` / `smParentReconciled` reconcile them (visible in
the lowered bytes as the `push 9, OP_ROLL, drop` inside the ELSE arm of
`loop-if-merged-locals`). Emitting the removal again dropped each slot
twice, drifting the depth by one per iteration and making the NEXT loop
iteration fail to resolve a merged local.
-/
def adoptDeclaredResults (sm : StackMap) (results : List String) :
    List StackOp × StackMap :=
  let n := results.length
  let smWith := results.foldl StackMap.push sm
  -- Phase 1: ROLL+DROP each stale parent slot the results shadow, tracking how
  -- far below the result block the scan reached (`sinkBelow`).
  let (ops, m, sinkBelow) :=
    results.reverse.foldl
      (init := (([] : List StackOp), smWith, 0))
      fun (ops, m, sink) name =>
        match m.findFrom? n name with
        | some d =>
            (ops ++ [.push (.bigint (Int.ofNat d)), .opcode "OP_ROLL", .drop],
             m.removeAtDepth d,
             max sink (d - n))
        | none   => (ops, m, sink)
  -- Phase 2: restore the inherited layout (issue #149).
  let (sinkOps, mF) := sinkResultBlock n sinkBelow m
  (ops ++ sinkOps, mF)

/--
Issue #150 — the if-WITHOUT-else "then-arm rebound a parent-held name"
shape, recognised AFTER the phase-2 consumption cleanups.

TS `lowerIf` treats this shape in two coupled halves:

* phase 3 (`05-stack-lower.ts:2710-2729`) pads the shorter arm, and when
  the else-arm has NO bindings of its own and the then-arm's result slot
  carries a name the else-arm still holds, it pads with a PICKed **copy**
  of that name rather than the generic empty-bytes placeholder — so the
  not-taken path preserves the OLD value in the same slot the taken path
  leaves the NEW one;
* the post-`OP_ENDIF` reconcile (`05-stack-lower.ts:3083-3107`) then
  names the parent slot after that value and physically ROLL+DROPs the
  now-stale original out from under it.

`shadowRebind` above already ports both halves, but only for the case
where the then-arm consumed NOTHING from the parent. When it did (a loop
body's second iteration consumes the previous iteration's residue), the
model fell through to the generic depth-balance, pushed `OP_0` instead of
the copy, reconciled nothing, and left the parent naming the `if`'s own
temporary while the stale slot stayed live underneath — every later read
of the merged local then resolved one slot too deep.

Returns `(pickDepth, staleDepth, name)`:
* `pickDepth` — depth of `name` in the post-cleanup ELSE map, i.e. what
  the phase-3 copy PICKs (TS `elseCtx.findDepth(thenName)`);
* `staleDepth` — depth of the stale parent slot AFTER the parent adopts
  `name` on top, i.e. `parentDepth + 1` (TS scans from depth 1 in the map
  it has just pushed `thenTop` onto);
* `name` — the then-arm's result slot (TS `thenTop`).

`none` for every other shape, so the generic path stays definitionally
what it was. Requires `nResults = 1` (`smThn.length = smParent.length + 1`)
because the N ≥ 2 shape is TS's separate multi-result reconcile, and a
one-slot pad deficit (`smThn.length = smEls.length + 1`) because the
model's depth balance emits a single placeholder.

TS's own guard `elseBindings.length === 0` is NOT a parameter here: the
caller matches on `els` itself, so a non-empty else reduces to the
pre-existing generic term definitionally (same reason the `results`
match is written on the constructor rather than on `results.isEmpty`).
-/
def ifWithoutElseCopy (bindingName : String)
    (smParent smThn smEls : StackMap) : Option (Nat × Nat × String) :=
  if smThn.length != smEls.length + 1 then none
  else if smThn.length != smParent.length + 1 then none
  else
    match smThn with
    | []            => none
    | none :: _     => none   -- an anonymous top has no name to copy
    | some nm :: _ =>
        if nm == bindingName then none
        else
          match smEls.depth? nm, smParent.depth? nm with
          | some vd, some pd => some (vd, pd + 1, nm)
          | _, _             => none

/--
Issue #99 Bug 1 — the if-WITHOUT-else shape where the then-arm left **N ≥ 2**
results. Returns `N` (the reference's `nResults`), `none` for N ≤ 1.

A conditional write of N state fields (`if (flag > 0n) { this.a = …;
this.b = … }`) leaves N values on the then-arm and owes the empty else-arm N
preserved ones. TS handles it in two coupled halves that both loop over N,
and both of the model's single-slot shortcuts (`shadowRebind` and
`ifWithoutElseCopy`) collapse the loop to its N = 1 instance:

* phase 3 (`05-stack-lower.ts:2853-2872`) is a `while` over the depth
  deficit — see `ifWithoutElseCopyPad`;
* the post-`OP_ENDIF` reconcile (`:3022-3053`) adopts all N and ROLL+DROPs
  the N stale parent slots they shadow. That loop is *character for
  character* the `nDeclared >= 1` loop at `:3000-3020`, so the model reuses
  `adoptDeclaredResults` for it — the only difference is where the N names
  come from (the arm's top-N slots here, the node's `results` there).

Gating on `2 ≤ N` is TS's own `nResults >= 2` (`:3022`). Below it the
reference falls through to its single-result branches, which is what the two
existing shortcuts model, so they keep their exact terms and bytes. -/
def ifWithoutElseMultiResults (smParent smThn : StackMap) : Option Nat :=
  match smThn.length - smParent.length with
  | 0     => none
  | 1     => none
  | k + 2 => some (k + 2)

/--
TS `lowerIf` phase 3 for the empty-else arm (`05-stack-lower.ts:2853-2872`).

The reference pads in a `while (thenDepth > elseDepth)`, and on EACH
iteration re-reads `thenCtx.stackMap.peekAtDepth(thenDepth - elseDepth - 1)`
and `elseCtx.findDepth(thenName)` against the else map it has just grown. So
the preserved copies land deepest-result-first, and each one shifts the
depths the next lookup sees. `r` is the remaining deficit, which makes the
current `resultDepth` exactly `r - 1`.

A then-slot whose name the else arm does NOT hold (or an anonymous one)
falls back to the reference's generic empty-bytes placeholder. TS's
`padBelowResult` cannot fire on this path: it is gated on
`elseBindings.length > 0` (`:2760`) and this is the empty-else case.

`vd == 0 ⇒ .dup` / `vd == 1 ⇒ .over` pre-apply the peephole folds TS's own
`push vd / pick vd` pair takes (`optimizer/peephole.ts`, pushed value ==
pick depth, so the fold DOES fire here — unlike the ROLL cleanups, where it
cannot). Two adjacent `.over`s then fold again to `OP_2DUP`
(`Peephole.applyDoubleOver`), which is what an N = 2 conditional write
emits. -/
def ifWithoutElseCopyPad (smThn : StackMap) :
    Nat → StackMap → (List StackOp × StackMap)
  | 0,     smEls => ([], smEls)
  | r + 1, smEls =>
      let (padOps, smEls') : List StackOp × StackMap :=
        match smThn[r]? with
        | some (some nm) =>
            match smEls.depth? nm with
            | some 0  => ([StackOp.dup], smEls.push nm)
            | some 1  => ([StackOp.over], smEls.push nm)
            | some vd => ([StackOp.pickStruct vd], smEls.push nm)
            | none    => ([StackOp.push (.bytes ByteArray.empty)], smEls.pushAnon)
        | _ => ([StackOp.push (.bytes ByteArray.empty)], smEls.pushAnon)
      let (restOps, smF) := ifWithoutElseCopyPad smThn r smEls'
      (padOps ++ restOps, smF)

/-- The then-arm's top `k` slot names, DEEPEST FIRST — the list
`adoptDeclaredResults` wants (`results[0]` is its deepest). An anonymous
slot takes `bindingName`, mirroring TS's
`thenCtx.stackMap.peekAtDepth(i) ?? bindingName` (`05-stack-lower.ts:3029`).
-/
def armResultNames (smThn : StackMap) (bindingName : String) (k : Nat) :
    List String :=
  ((List.range k).map fun i =>
      match smThn[i]? with
      | some (some n) => n
      | _             => bindingName).reverse

/-- Compute the set of parent-scope refs that branches must NOT consume.

Mirrors TS `lowerIf` (`05-stack-lower.ts:1660-1667`):
```
const protectedRefs = new Set<string>();
for (const [ref, lastIdx] of lastUses.entries()) {
  if (lastIdx > bindingIndex && this.stackMap.has(ref)) {
    protectedRefs.add(ref);
  }
}
```

Plus the implicit propagation TS achieves via `lowerBindings`'
clamp at `05-stack-lower.ts:862-866` — outer-outer protected refs get
`lastIdx = bindings.length` which is always > the current `bindingIndex`,
so they re-appear in the new `protectedRefs`.

We mirror that here by ALSO including any parent `outerProtected` ref
that is still in `smBranch` (regardless of its lastUses lookup).

`smBranch` is the parent stackmap with the cond peeled off; `lastUses`
is the OUTER scope's last-use table; `currentIndex` is the if-binding's
index in the outer body. -/
def computeBranchProtected (smBranch : StackMap)
    (lastUses : List (String × Nat)) (currentIndex : Nat)
    (parentOuterProtected : List String) : List String :=
  smBranch.foldl (init := ([] : List String)) fun acc slot =>
    match slot with
    | none     => acc        -- an anonymous slot cannot be a protected ref
    | some ref =>
    if listContains acc ref then acc
    else
      let aliveAfter : Bool :=
        match lastUsesLookup lastUses ref with
        | some idx => decide (idx > currentIndex)
        | none     => false
      let parentProtected : Bool := listContains parentOuterProtected ref
      if aliveAfter || parentProtected then acc ++ [ref]
      else acc

/-! ## `bringToTop` — liveness-aware load (Phase 3x)

Mirrors the TS `bringToTop` dispatch table at `05-stack-lower.ts:797-847`:

| depth | consume=false              | consume=true              |
|-------|----------------------------|----------------------------|
| 0     | `[.dup]`                   | `[]`                       |
| 1     | `[.over]`                  | `[.swap]`                  |
| 2     | `[push 2, .pick 2]`        | `[.rot]`                   |
| ≥3    | `[push d, .pick d]`        | `[push d, .roll d]`        |

In the consume path the original entry is removed from the stack map
(`removeAtDepth`) and the name is re-pushed on top. In the copy path
the original entry stays and a fresh copy of the name is pushed on top
(the runtime stack now holds two values associated with the same name;
`StackMap.depth?` returns the **shallower** one, matching TS
`peekAtDepth` semantics).

Returns the op list and the updated stack map. If `name` is not in
`sm`, falls back to a placeholder opcode (matching `loadRef`'s
unresolved branch).
-/
def bringToTop (sm : StackMap) (name : String) (consume : Bool) :
    (List StackOp × StackMap) :=
  match sm.depth? name with
  | none =>
      ([.opcode s!"OP_RUNAR_UNRESOLVED_{name}"], sm)
  | some 0 =>
      if consume then
        ([], sm)
      else
        ([.dup], sm.push name)
  | some 1 =>
      if consume then
        -- SWAP: top two entries flip.
        match sm with
        | a :: b :: rest => ([.swap], b :: a :: rest)
        | _              => ([.swap], sm)
      else
        ([.over], sm.push name)
  | some 2 =>
      if consume then
        ([.rot], (sm.removeAtDepth 2).push name)
      else
        -- `.pickStruct 2` encodes byte-identically to `.pick 2` (`[push 2, OP_PICK]`)
        -- in `Emit.lean`, but has no-pop runtime semantics matching the
        -- copy-only `bringToTop` lowering (no preceding push of depth).
        ([.pickStruct 2], sm.push name)
  | some d =>
      if consume then
        ([.roll d], (sm.removeAtDepth d).push name)
      else
        ([.pickStruct d], sm.push name)

/-- Pop `n` entries off the top of the stack map. -/
def StackMap.popN : StackMap → Nat → StackMap
  | sm,            0     => sm
  | [],            _ + 1 => []
  | _ :: rest, n + 1     => StackMap.popN rest n

/--
Liveness-aware single-ref load. Decides between PICK/OVER/DUP (copy)
and ROLL/SWAP/ROT (consume) using `isLastUse` plus the
outer-protected gate (refs that pre-existed the current scope cannot
be consumed; mirrors the TS `outerProtectedRefs` mechanism in
`05-stack-lower.ts:856-902`).

`outerProtected` should be the snapshot of the parent scope's stack
map at the point this inner scope was entered. At the top-level
method body it is `[]`.
-/
def loadRefLive (sm : StackMap) (name : String) (currentIndex : Nat)
    (lastUses : List (String × Nat)) (outerProtected : List String) :
    (List StackOp × StackMap) :=
  let consume := !listContains outerProtected name
              && isLastUse lastUses name currentIndex
  bringToTop sm name consume

/-- Liveness-aware param load. Mirrors TS `lowerLoadParam`
(`05-stack-lower.ts:982-1003`): consumes the param on its last use
within the current scope, without the `localBindings` check that
`loadConst .refAlias` applies. Phase 7.1: also checks `outerProtected`
to prevent consumption of params that an enclosing scope still needs
(e.g. a param used in BOTH branches of sibling ifs — the first if's
THEN body must NOT ROLL the param when the second if also reads it). -/
def loadRefLiveParam (sm : StackMap) (name : String) (currentIndex : Nat)
    (lastUses : List (String × Nat)) (outerProtected : List String) :
    (List StackOp × StackMap) :=
  let consume := !listContains outerProtected name
              && isLastUse lastUses name currentIndex
  bringToTop sm name consume

/-- Always-copy load (`bringToTop` with `consume=false`) used by
`loadProp` per TS `05-stack-lower.ts:1004-1029`: properties are shared
mutable state, so reading them never consumes. -/
def loadRefLiveCopy (sm : StackMap) (name : String) :
    (List StackOp × StackMap) :=
  bringToTop sm name false

/--
Liveness-aware single-operand load for MULTI-operand ANF values.
Identical to `loadRefLive` except the consume decision goes through
`operandConsume` against the value's FULL operand list (TS
`operandConsume` call sites: binOp, generic call args, checkMultiSig,
methodCall arg binding, computeStateOutput*/buildChangeOutput,
addOutput/addRawOutput, math helpers, crypto builtins). Single-operand
sites (loadParam, unaryOp, assert, if-cond, updateProp,
deserializeState, extractors, checkPreimage, blake3Hash, sqrt, log2,
sign) keep `loadRefLive` — TS uses bare `isLastUse` there.
-/
def loadRefOperand (sm : StackMap) (name : String) (operands : List String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  bringToTop sm name
    (operandConsume lastUses outerProtected name operands currentIndex)

/-- When `name` occurs at most once in `operands`, the repeated-operand
clause is vacuous and `operandConsume` reduces to the old
`loadRefLive` consume decision. -/
theorem operandConsume_eq_of_unique (lastUses : List (String × Nat))
    (outerProtected : List String) (ref : String) (operands : List String)
    (currentIndex : Nat)
    (h : (operands.filter (· == ref)).length ≤ 1) :
    operandConsume lastUses outerProtected ref operands currentIndex
      = (!listContains outerProtected ref && isLastUse lastUses ref currentIndex) := by
  unfold operandConsume
  simp [h]

/-- `loadRefOperand` collapses to `loadRefLive` whenever the ref occurs
at most once in the operand list (i.e. for every non-aliased value). -/
theorem loadRefOperand_eq_of_unique (sm : StackMap) (name : String)
    (operands : List String) (currentIndex : Nat)
    (lastUses : List (String × Nat)) (outerProtected : List String)
    (h : (operands.filter (· == name)).length ≤ 1) :
    loadRefOperand sm name operands currentIndex lastUses outerProtected
      = loadRefLive sm name currentIndex lastUses outerProtected := by
  unfold loadRefOperand loadRefLive
  rw [operandConsume_eq_of_unique _ _ _ _ _ h]

/-- Distinct-pair bridge, left operand: `loadRefOperand` over `[l, r]`
with `l ≠ r` equals the old `loadRefLive`. -/
theorem loadRefOperand_pair_left (sm : StackMap) (l r : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (hne : l ≠ r) :
    loadRefOperand sm l [l, r] currentIndex lastUses outerProtected
      = loadRefLive sm l currentIndex lastUses outerProtected := by
  apply loadRefOperand_eq_of_unique
  have h : (r == l) = false := beq_eq_false_iff_ne.mpr (Ne.symm hne)
  simp [List.filter, h]

/-- Distinct-pair bridge, right operand. -/
theorem loadRefOperand_pair_right (sm : StackMap) (l r : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (hne : l ≠ r) :
    loadRefOperand sm r [l, r] currentIndex lastUses outerProtected
      = loadRefLive sm r currentIndex lastUses outerProtected := by
  apply loadRefOperand_eq_of_unique
  have h : (l == r) = false := beq_eq_false_iff_ne.mpr hne
  simp [List.filter, h]

/-- Singleton bridge: a one-element operand list never repeats. -/
@[simp] theorem loadRefOperand_singleton (sm : StackMap) (x : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) :
    loadRefOperand sm x [x] currentIndex lastUses outerProtected
      = loadRefLive sm x currentIndex lastUses outerProtected := by
  apply loadRefOperand_eq_of_unique
  simp [List.filter]

/--
Liveness-aware multi-arg loader. Threads `sm` through each load (so
later args observe the depth-shifts caused by earlier consumes) and
uses the same `(currentIndex, lastUses, outerProtected)` triple for
every arg (mirroring TS `lowerCall` / `lowerBinOp`, which compute all
`isLast*` flags at the same `bindingIndex`).

`allOperands` is the FULL operand list of the value (TS passes the
complete `args` list to `operandConsume` for every element, so each
element is checked against ALL operands, not just the unprocessed
tail). Callers pass the same list twice at the top level.
-/
def lowerArgsLive (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (allOperands : List String) :
    StackMap → List String → (List StackOp × StackMap)
  | sm, [] => ([], sm)
  | sm, a :: rest =>
      let (load, sm1) := loadRefOperand sm a allOperands currentIndex lastUses outerProtected
      let (restOps, sm2) := lowerArgsLive currentIndex lastUses outerProtected allOperands sm1 rest
      (load ++ restOps, sm2)

/--
Liveness-aware variant of `loadAndBindArgs` for `methodCall` inlining.
Loads each arg via `bringToTop` (consume on last use, modulo
`outerProtected` and the repeated-operand clause — TS `inlineMethodCall`
calls `operandConsume(arg, args, …)` per arg) and renames the new
top-of-stack slot to the corresponding callee param name. `allOperands`
is the full call arg list (the `obj` ref is NOT part of it, matching TS).
-/
def loadAndBindArgsLive (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (allOperands : List String) :
    StackMap → List String → List String → (List StackOp × StackMap)
  | sm, [], _ => ([], sm)
  | sm, _ :: _, [] => ([], sm)
  | sm, a :: rargs, p :: rparams =>
      let (load, sm1) := loadRefOperand sm a allOperands currentIndex lastUses outerProtected
      -- Rename the new top entry from `a` to `p` (the callee's param name).
      let sm2 := match sm1 with
                 | _ :: rest => p :: rest
                 | []        => [p]
      let (rest, sm3) := loadAndBindArgsLive currentIndex lastUses outerProtected allOperands sm2 rargs rparams
      (load ++ rest, sm3)

/-! ## Operator name → Bitcoin Script opcode -/

/--
Mirrors the `BINOP_OPCODES` table in `05-stack-lower.ts:102-125`. Every
ANF binary operator maps to exactly one Bitcoin Script opcode (with the
exception of `===`, which selects between `OP_EQUAL` and `OP_NUMEQUAL`
based on the optional `result_type`).
-/
def binopOpcode (op : String) (resultType : Option String) : String :=
  match op with
  | "+"  => "OP_ADD"
  | "-"  => "OP_SUB"
  | "*"  => "OP_MUL"
  | "/"  => "OP_DIV"
  | "%"  => "OP_MOD"
  | "<"  => "OP_LESSTHAN"
  | "<=" => "OP_LESSTHANOREQUAL"
  | ">"  => "OP_GREATERTHAN"
  | ">=" => "OP_GREATERTHANOREQUAL"
  | "&&" => "OP_BOOLAND"
  | "||" => "OP_BOOLOR"
  | "===" =>
      match resultType with
      | some "bytes" => "OP_EQUAL"
      | _            => "OP_NUMEQUAL"
  | "!==" =>
      -- Issue #116: mirror TS `BINOP_OPCODES['!=='] = ['OP_NUMEQUAL','OP_NOT']`
      -- (`05-stack-lower.ts:132-133`). `!==` always emits the EQUALITY opcode
      -- followed by `OP_NOT` (appended by the binOp lowering arms below): bytes
      -- use `OP_EQUAL`, numeric uses `OP_NUMEQUAL`. All 7 reference compilers
      -- emit this 2-opcode pair; the single `OP_NUMNOTEQUAL` opcode is never
      -- emitted. The semantic bridge `runOps [OP_NUMEQUAL, OP_NOT] = runOps
      -- [OP_NUMNOTEQUAL]` is `Stack.Sim.runOps_numEqualNot_eq_numNotEqual`.
      match resultType with
      | some "bytes" => "OP_EQUAL"
      | _            => "OP_NUMEQUAL"
  | "&"  => "OP_AND"
  | "|"  => "OP_OR"
  | "^"  => "OP_XOR"
  | "<<" => "OP_LSHIFT"
  | ">>" => "OP_RSHIFT"
  | _    => "OP_RUNAR_UNKNOWN_BINOP"

/-- Mirrors `UNARYOP_OPCODES` in `05-stack-lower.ts:127-131`. -/
def unaryOpcode (op : String) : String :=
  match op with
  | "!" => "OP_NOT"
  | "-" => "OP_NEGATE"
  | "~" => "OP_INVERT"
  | _   => "OP_RUNAR_UNKNOWN_UNARYOP"

/--
Built-in function name → emitted opcode (or opcode list for builtins
that fuse).

Handles the common scalar / hash builtins. Anything not in this table
returns `OP_RUNAR_UNKNOWN_BUILTIN` and is rejected by `SimpleANF`.
-/
def builtinOpcode (name : String) : List String :=
  match name with
  -- Hashes
  | "sha256"      => ["OP_SHA256"]
  | "ripemd160"   => ["OP_RIPEMD160"]
  | "hash160"     => ["OP_HASH160"]
  | "hash256"     => ["OP_HASH256"]
  -- Signature ops
  | "checkSig"    => ["OP_CHECKSIG"]
  -- Multisig: the dedicated dispatch arm in `lowerValueP` emits the full
  -- TS-faithful sequence (`OP_0 dummy + sigs + nSigs + pubKeys + nPKs +
  -- OP_CHECKMULTISIG`). The unparameterized `lowerValue` fallback below
  -- collapses to a bare `OP_CHECKMULTISIG` after the arg loads — that's
  -- enough for `compileSafe` to accept the fixture (real opcode, not an
  -- `OP_RUNAR_*` sentinel) even though it is not byte-exact. The
  -- byte-exact emit lives in `lowerValueP` via `lowerCheckMultiSigOpsLive`.
  | "checkMultiSig" => ["OP_CHECKMULTISIG"]
  -- Byte ops
  | "cat"         => ["OP_CAT"]
  | "len"         => ["OP_SIZE", "OP_NIP"]   -- mirrors 05-stack-lower.ts:1168
  | "split"       => ["OP_SPLIT"]
  -- Numeric helpers
  | "abs"         => ["OP_ABS"]
  | "min"         => ["OP_MIN"]
  | "max"         => ["OP_MAX"]
  | "within"      => ["OP_WITHIN"]
  -- Boolean coercion: `bool(x)` ↦ `OP_0NOTEQUAL` (mirrors TS
  -- `BUILTIN_OPCODES.bool` at `05-stack-lower.ts:108`).
  | "bool"        => ["OP_0NOTEQUAL"]
  -- ByteString ⇄ Int coercions
  | "num2bin"     => ["OP_NUM2BIN"]
  | "bin2num"     => ["OP_BIN2NUM"]
  -- Casts (no-op — argument is already on the stack with the right repr)
  | "toByteString" => []
  | "pack"         => []
  -- substr(data, start, length) → SPLIT NIP SPLIT DROP (TS lowerSubstr)
  | "substr"       => ["OP_SPLIT", "OP_NIP", "OP_SPLIT", "OP_DROP"]
  -- __array_access(data, index) → SPLIT NIP <1> SPLIT DROP BIN2NUM. Note
  -- the literal `<1>` is *between* opcodes and emitted as `51` (OP_1), so
  -- we treat it as an opcode (`OP_1`) rather than a `.push` to keep this
  -- helper opcode-only. Mirrors TS `lowerArrayAccess` (`05-stack-lower.ts:4773`).
  | "__array_access" =>
      ["OP_SPLIT", "OP_NIP", "OP_1", "OP_SPLIT", "OP_DROP", "OP_BIN2NUM"]
  | _              => ["OP_RUNAR_UNKNOWN_BUILTIN"]

/--
Whether `func` names a preimage-field extractor (e.g. `extractVersion`,
`extractOutputHash`, `extractAmount`, …). Mirrors TS `lowerExtractor`
dispatch (`05-stack-lower.ts:2957-3220`): every extractor takes one
argument (the BIP-143 preimage) and emits a fixed `OP_SPLIT` sequence
that selects the relevant field.
-/
def isExtractor (func : String) : Bool :=
  func.startsWith "extract"

/-- Body sequence (sans the leading `bringToTop preimage` load) for a
preimage-field extractor. Mirrors TS `lowerExtractor`'s switch arms in
`05-stack-lower.ts:2975-3220`. The two-character literal pushes (e.g.
`push 40`) emit as `01 28` (push 1 byte 0x28) so byte-exact match
holds against the TS reference. Returns `[]` for unknown extractors,
which keeps a robust no-op fallback for non-supported field names.
-/
def extractorBody (func : String) : List StackOp :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  match func with
  | "extractVersion" =>
      [push 4, opc "OP_SPLIT", .drop, opc "OP_BIN2NUM"]
  | "extractHashPrevouts" =>
      [push 4, opc "OP_SPLIT", .nip, push 32, opc "OP_SPLIT", .drop]
  | "extractHashSequence" =>
      [push 36, opc "OP_SPLIT", .nip, push 32, opc "OP_SPLIT", .drop]
  | "extractHashOutputs" =>
      -- End-relative: 32 bytes before the last 8 (nLocktime + sighashType).
      [opc "OP_SIZE", push 40, opc "OP_SUB", opc "OP_SPLIT", .nip,
       push 32, opc "OP_SPLIT", .drop]
  | "extractOutpoint" =>
      -- TS `lowerExtractor` case `extractOutpoint` (`05-stack-lower.ts:
      -- 3039-3061`): skip first 68 bytes (version 4 + hashPrevouts 32 +
      -- hashSequence 32), then take next 36 bytes (txid 32 + vout 4).
      [push 68, opc "OP_SPLIT", .nip, push 36, opc "OP_SPLIT", .drop]
  | "extractOutputHash" =>
      [opc "OP_SIZE", push 40, opc "OP_SUB", opc "OP_SPLIT", .nip,
       push 32, opc "OP_SPLIT", .drop]
  | "extractOutputs" =>
      [opc "OP_SIZE", push 40, opc "OP_SUB", opc "OP_SPLIT", .nip,
       push 32, opc "OP_SPLIT", .drop]
  | "extractNLocktime" =>
      [opc "OP_SIZE", push 8, opc "OP_SUB", opc "OP_SPLIT", .nip,
       push 4, opc "OP_SPLIT", .drop, opc "OP_BIN2NUM"]
  | "extractLocktime" =>
      -- TS `lowerExtractor` case `extractLocktime` (`05-stack-lower.ts:3087-3115`):
      -- end-relative 4 bytes before the last 4 (sighashType).
      [opc "OP_SIZE", push 8, opc "OP_SUB", opc "OP_SPLIT", .nip,
       push 4, opc "OP_SPLIT", .drop, opc "OP_BIN2NUM"]
  | "extractSigHashType" =>
      [opc "OP_SIZE", push 4, opc "OP_SUB", opc "OP_SPLIT", .nip,
       opc "OP_BIN2NUM"]
  | "extractAmount" =>
      -- Amount is 8 bytes immediately after scriptCode (nSeq is 4 after).
      -- Layout from end: nSeq(4) + hashOutputs(32) + nLocktime(4) + hashType(4) = 44 from end,
      -- amount(8) precedes that → amount starts at SIZE-52.
      [opc "OP_SIZE", push 52, opc "OP_SUB", opc "OP_SPLIT", .nip,
       push 8, opc "OP_SPLIT", .drop, opc "OP_BIN2NUM"]
  | "extractScriptCode" =>
      -- scriptCode lives between the prevout (36 + outpoint stuff) and
      -- the trailing fixed-size fields. The TS reference uses a custom
      -- multi-split sequence that we do not reproduce here; downstream
      -- fixtures using extractScriptCode go through the dedicated state
      -- helpers (deserialize_state) instead.
      []
  | _ => []

/-! ## Per-binding lowering

We thread `(StackMap, List StackOp)` through the binding sequence. Each
case produces a list of stack ops and returns the updated stack map.

`loadRef name`: emit `pick depth(name)`, leaving a copy on top.
`pushAndName name v`: pushes value `v`, then names the new top.
-/

def loadRef (sm : StackMap) (name : String) : List StackOp :=
  match sm.depth? name with
  | some 0 => [.dup]
  | some 1 => [.over]
  | some d => [.pickStruct d]   -- no-pop pick; emits `[push d, OP_PICK]` bytes
  | none   => [.opcode s!"OP_RUNAR_UNRESOLVED_{name}"]

def emitConst : ConstValue → List StackOp
  | .int i      => [.push (.bigint i)]
  | .bool b     => [.push (.bool b)]
  | .bytes b    => [.push (.bytes b)]
  | .refAlias _ => []     -- aliases dispatch below via `loadRef`
  | .thisRef    => []     -- `@this` doesn't materialize anything on the stack

/-! ## Argument-list lowering helper

`lowerArgs` loads each ref in turn, threading the stackMap. Pure
structural recursion on the ref-name list (no recursion through
`lowerValue` / `lowerBindings`), so it lives outside the mutual
block.
-/

def lowerArgs (sm : StackMap) : List String → (List StackOp × StackMap)
  | [] => ([], sm)
  | a :: rest =>
      let load := loadRef sm a
      let (restOps, sm') := lowerArgs (sm.push a) rest
      (load ++ restOps, sm')

/-! ## arrayLiteral helper

Concatenates element loads with `OP_CAT`. Pure structural recursion on
the element list — no nested binding recursion.
-/

def lowerArrayElems (sm : StackMap) : List String → List StackOp
  | [] => []
  | [single] => loadRef sm single
  | first :: rest =>
      rest.foldl (init := loadRef sm first) fun acc el =>
        acc ++ loadRef (sm.push first) el ++ [.opcode "OP_CAT"]

/-- Per-iteration iteration-variable cleanup gate for the faithful
loop arm (TS `lowerLoop` `05-stack-lower.ts:2158-2167`): emit a single
`OP_DROP` iff the iter var survives the body at EXACTLY depth 0 of the
stack map; a survivor buried deeper (or absent) emits nothing and the
map is left unchanged (stranded values are cleaned by the
end-of-method NIP pass). Named (rather than inlined in
`lowerLoopItersP`) so proof hypotheses about the gate are plain
equations on a constant application. -/
def iterVarCleanup (smBody : StackMap) (iterVar : String) :
    List StackOp × StackMap :=
  match smBody.depth? iterVar with
  | some 0 => ([.drop], smBody.removeAtDepth 0)
  | _      => ([], smBody)

/-! ## Loop unroll helper

Unrolls a precomputed body op list `count` times, prefixing each
iteration with the iteration index push and suffixing with `OP_DROP`
(to discard the index after the body consumes it).

Pure structural recursion on `Nat`, defined outside the mutual block
because the recursive cycle is not through `lowerValue` /
`lowerBindings`. The body is computed once by `lowerValue`'s `loop`
case (via the mutual `lowerBindings`) and then iterated here.
-/

def unrollIter (innerOps : List StackOp) : Nat → List StackOp
  | 0       => []
  | n + 1   => unrollIter innerOps n
                  ++ [.push (.bigint (Int.ofNat n))]
                  ++ innerOps
                  ++ [.drop]

/-! ## Method-call inlining helpers

`methodCall` lowering inlines the called method's body in place
(mirroring `inlineMethodCall` in `05-stack-lower.ts:1591-1644`). The TS
reference rolls each argument to the top of the stack and renames it
to the corresponding param; we emit a `loadRef` per arg (placing a
copy on top) and bind the param name onto the stack map.

The resolution is by `name` against the program's full method list.
Lean's structural-recursion checker can't see method bodies as
"smaller" than the calling site, so termination is bounded by an
explicit fuel parameter (`budget`); on overflow we emit a placeholder
opcode rather than diverging.
-/

/-- Find a method by name in the program's method list. -/
def lookupMethod (methods : List ANFMethod) (name : String) : Option ANFMethod :=
  methods.find? (fun m => m.name == name)

/-- Default inlining budget. The TS compiler implicitly bounds inlining
because Rúnar forbids recursive private methods; we mirror that with a
fixed fuel large enough for every conformance fixture. -/
def defaultInlineBudget : Nat := 8

/--
Bind the call-site arg list to the callee's params on the stack map.

For each `(arg, param)` pair we emit `loadRef sm arg` (placing a copy
on top) and push `param` onto the stack map so subsequent body
bindings see the param name. Extra args (without a matching param)
are silently dropped — the same shape Rúnar's typechecker enforces
upstream.
-/
def loadAndBindArgs (sm : StackMap) :
    List String → List String → (List StackOp × StackMap)
  | [], _ => ([], sm)
  | _ :: _, [] => ([], sm)
  | a :: rargs, p :: rparams =>
      let load := loadRef sm a
      let (rest, sm') := loadAndBindArgs (sm.push p) rargs rparams
      (load ++ rest, sm')

/-! ## Framework intrinsic helpers

These helpers mirror the BIP-143 / output-construction lowering
sequences from `05-stack-lower.ts`. They are pure constants /
pure functions of their byte payloads — they never recurse through
`lowerValue` / `lowerBindings`, so they live outside the mutual
block.

The Lean lowering uses PICK-style (`loadRef`) loads throughout
(matching the rest of `Lower.lean`), even where the TS reference
sometimes uses ROLL (`bringToTop` with `consume=true`) to avoid
the depth tracking required by liveness analysis. The byte-exact
match against the TS reference for fixtures that exercise these
intrinsics requires a future pass that threads `lastUses`; the
present lowering is byte-exact in the **shape** of the intrinsic
body but may differ in the load sequence.
-/

/--
Mirrors `emitVarintEncoding` in `05-stack-lower.ts:425-518`. On
entry, the runtime stack is `[..., script, len]`. On exit it is
`[..., script, varint(len)]`. The encoding is the standard Bitcoin
compact-size varint: 1, 3, 5, or 9 bytes depending on the length
range, gated by nested OP_IF / OP_ELSE / OP_ENDIF opcode triples.

The TS reference emits `OP_IF` / `OP_ELSE` / `OP_ENDIF` as opcode
strings (not as a structured `StackOp.ifOp`); we mirror that
verbatim so the resulting hex is byte-identical.
-/
def varintEncodingOps : List StackOp :=
  let push (n : Int) : StackOp := .push (.bigint n)
  let opc (s : String) : StackOp := .opcode s
  -- numToLowBytes(nBytes): [..., len] -> [..., low_n_bytes]
  -- Sequence: push (n+1); OP_NUM2BIN; push n; OP_SPLIT; drop
  let numToLowBytes (n : Int) : List StackOp :=
    [push (n + 1), opc "OP_NUM2BIN", push n, opc "OP_SPLIT", .drop]
  -- emitPrefix(b): [..., script, low_bytes] -> [..., script, prefix||low_bytes]
  -- Sequence: push #[b]; swap; OP_CAT
  let emitPrefix (b : UInt8) : List StackOp :=
    [.push (.bytes (ByteArray.mk #[b])), .swap, opc "OP_CAT"]
  -- IF len < 253: 1-byte varint
  [.dup, push 253, opc "OP_LESSTHAN", opc "OP_IF"]
    ++ numToLowBytes 1
    ++ [opc "OP_ELSE"]
    -- ELSE-IF len <= 0xffff: 0xfd + 2-byte LE
    ++ [.dup, push 0x10000, opc "OP_LESSTHAN", opc "OP_IF"]
    ++ numToLowBytes 2
    ++ emitPrefix 0xfd
    ++ [opc "OP_ELSE"]
    -- ELSE-IF len <= 0xffffffff: 0xfe + 4-byte LE
    ++ [.dup, push 0x100000000, opc "OP_LESSTHAN", opc "OP_IF"]
    ++ numToLowBytes 4
    ++ emitPrefix 0xfe
    ++ [opc "OP_ELSE"]
    -- ELSE: 0xff + 8-byte LE
    ++ numToLowBytes 8
    ++ emitPrefix 0xff
    ++ [opc "OP_ENDIF", opc "OP_ENDIF", opc "OP_ENDIF"]

/--
Lowering for `add_raw_output(satoshis, scriptBytes)` and
`add_data_output(satoshis, scriptBytes)` (their stack-IR shape is
identical — see `05-stack-lower.ts:961-965`). Builds a raw output
serialization on the stack:

  amount(8 LE) ++ varint(scriptLen) ++ scriptBytes

Mirrors `lowerAddRawOutput` in `05-stack-lower.ts:2467-2511`.

Returns the op list and the updated `StackMap` with `bindingName`
named on top of the stack.
-/
def lowerAddRawOutputOps (sm : StackMap) (bindingName : String)
    (satoshis scriptBytes : String) : (List StackOp × StackMap) :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  -- Step 1: bring scriptBytes to top (PICK-style copy via loadRef).
  let s1 := loadRef sm scriptBytes
  -- Step 2: OP_SIZE, then varint encoding -> [..., script, varint]
  let s2 := [opc "OP_SIZE"] ++ varintEncodingOps
  -- Step 3: SWAP + OP_CAT -> [..., varint+script]
  let s3 := [.swap, opc "OP_CAT"]
  -- Step 4: bring satoshis to top, NUM2BIN(8), SWAP, OP_CAT -> [..., satoshis(8LE)+varint+script]
  -- After steps 1-3, the stack-map top is the (un-named) "varint+script" slot;
  -- we model that with a single push of bindingName as a placeholder so
  -- subsequent loadRef calls remain consistent. We use the *original* sm
  -- (where scriptBytes lives) for satoshis lookup since scriptBytes was
  -- copied (not consumed); after CATs the top is unnamed.
  let smAfterCat := sm.push bindingName
  let s4Load := loadRef smAfterCat satoshis
  let s4 := s4Load ++ [push 8, opc "OP_NUM2BIN", .swap, opc "OP_CAT"]
  (s1 ++ s2 ++ s3 ++ s4, smAfterCat)

/--
Liveness-aware variant of `lowerAddRawOutputOps`. Mirrors TS
`lowerAddRawOutput` (`05-stack-lower.ts:2467-2511`) more faithfully by
using `bringToTop` with consume semantics on last-use refs (matching
TS `bringToTop(ref, isLast)`), threading the stack map through each
load. This lets PICK→ROLL collapse on dead refs and OVER→SWAP / DUP→
no-op collapse on top-of-stack last uses, producing byte-identical hex
to the TS reference for fixtures whose `_opPushTxSig` / `_codePart`
implicit params live below the user-visible stack region.
-/
def lowerAddRawOutputOpsLive (sm : StackMap) (bindingName : String)
    (satoshis scriptBytes : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  -- Full operand list for the repeated-operand consume gate (TS
  -- `lowerAddRawOutput` passes `[satoshis, scriptBytes]`).
  let rawOperands : List String := [satoshis, scriptBytes]
  -- Step 1: bring scriptBytes to top, consuming on last use.
  let (s1, sm1) := loadRefOperand sm scriptBytes rawOperands currentIndex lastUses outerProtected
  -- Step 2: OP_SIZE, then varint encoding -> [..., script, varint]
  let s2 := [opc "OP_SIZE"] ++ varintEncodingOps
  -- After s2, the top entry on the stack map is the unnamed varint slot
  -- (TS pushes null after OP_SIZE then leaves the IF/ELSE chain depth-
  -- neutral). We model that with a single anonymous push.
  let smAfterVarint := sm1.push "_varint"
  -- Step 3: SWAP + OP_CAT -> [..., varint+script]. SWAP pops 2 / pushes 2;
  -- CAT pops 2 / pushes 1. Net stack-map: pop 1.
  let s3 := [.swap, opc "OP_CAT"]
  let smAfterS3 := smAfterVarint.popN 1
  -- Step 4: bring satoshis to top, NUM2BIN(8), SWAP, OP_CAT.
  let (s4Load, sm4) := loadRefOperand smAfterS3 satoshis rawOperands currentIndex lastUses outerProtected
  let s4 := s4Load ++ [push 8, opc "OP_NUM2BIN", .swap, opc "OP_CAT"]
  -- The final SWAP+CAT pair fuses the satoshis slot with the varint+script
  -- accumulator left on top after step 3 into a single output-bytes slot.
  -- Pop BOTH (popN 2) before pushing bindingName — the earlier `popN 1`
  -- form left the varint+script slot lingering at depth 1 and shifted
  -- every subsequent PICK/ROLL/SWAP by +1 (visible in the token-nft /
  -- auction / add-data-output fixtures' post-add_output emission).
  let smFinal := (sm4.popN 2).push bindingName
  (s1 ++ s2 ++ s3 ++ s4, smFinal)

/--
The fixed 760-byte on-chain OP_PUSH_TX preimage-binding blob (BUG-100).

Byte-identical to the TS reference `CHECK_PREIMAGE_BINDING_HEX`
(`packages/runar-compiler/src/passes/oppushtx-codegen.ts`): a single opaque
opcode span that derives the ECDSA signature on-chain from `hash256(preimage)`
(Optimal OP_PUSH_TX: `z = hash256(preimage)`, `s = (z + r)·k⁻¹ mod n`, fixed
nonce k=2 / privkey d=1, branchless low-S, minimal DER) and runs
`OP_CHECKSIGVERIFY` against the generator `G`. `OP_CHECKSIG` passes iff
`hash256(preimage)` equals the real tx sighash — i.e. iff the pushed preimage
IS the spending transaction's BIP-143 preimage. Net stack effect is zero
(preimage in → preimage out). Emitted as a single `.rawBytes` StackOp so the
peephole optimizer treats it as a hard barrier and all seven tiers pin the
same constant. -/
def checkPreimageBindingBytes : ByteArray := ByteArray.mk #[
    0x76, 0xaa, 0x00, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51,
    0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e,
    0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b,
    0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f,
    0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c,
    0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c,
    0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b,
    0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51,
    0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e,
    0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b,
    0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f,
    0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c,
    0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c,
    0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b,
    0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51,
    0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e,
    0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b,
    0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f,
    0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c,
    0x75, 0x01, 0x00, 0x7e, 0x81, 0x21, 0xe5, 0x9e, 0x70, 0x5c, 0xb9, 0x09,
    0xac, 0xab, 0xa7, 0x3c, 0xef, 0x8c, 0x4b, 0x8e, 0x77, 0x5c, 0xd8, 0x7c,
    0xc0, 0x95, 0x6e, 0x40, 0x45, 0x30, 0x6d, 0x7d, 0xed, 0x41, 0x94, 0x7f,
    0x04, 0xc6, 0x00, 0x93, 0x20, 0xa1, 0x20, 0x1b, 0x68, 0x46, 0x2f, 0xe9,
    0xdf, 0x1d, 0x50, 0xa4, 0x57, 0x73, 0x6e, 0x57, 0x5d, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x7f, 0x95, 0x21, 0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf, 0x3b,
    0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba, 0xfe, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
    0x6e, 0x97, 0x7b, 0x75, 0x78, 0x93, 0x7c, 0x97, 0x76, 0x20, 0xa0, 0x20,
    0x1b, 0x68, 0x46, 0x2f, 0xe9, 0xdf, 0x1d, 0x50, 0xa4, 0x57, 0x73, 0x6e,
    0x57, 0x5d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xa0, 0x78, 0x21, 0x41, 0x41, 0x36,
    0xd0, 0x8c, 0x5e, 0xd2, 0xbf, 0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae,
    0xba, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x7c, 0x8d, 0x7c, 0x94, 0x95, 0x94,
    0x82, 0x6b, 0x01, 0x20, 0x80, 0x00, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c,
    0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b,
    0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51,
    0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e,
    0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b,
    0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f,
    0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c,
    0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c,
    0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b,
    0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51,
    0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e,
    0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b,
    0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f,
    0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c,
    0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c,
    0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b,
    0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51,
    0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e,
    0x7c, 0x51, 0x7f, 0x7b, 0x7b, 0x7c, 0x7e, 0x7c, 0x51, 0x7f, 0x7b, 0x7b,
    0x7c, 0x7e, 0x7c, 0x75, 0x6c, 0x01, 0x20, 0x7c, 0x94, 0x7f, 0x77, 0x76,
    0x82, 0x77, 0x51, 0x80, 0x52, 0x7c, 0x7e, 0x7c, 0x7e, 0x76, 0x82, 0x77,
    0x01, 0x23, 0x93, 0x51, 0x80, 0x23, 0x02, 0x21, 0x00, 0xc6, 0x04, 0x7f,
    0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c,
    0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
    0xb9, 0x5c, 0x70, 0x9e, 0xe5, 0x01, 0x30, 0x52, 0x7a, 0x7e, 0x7c, 0x7e,
    0x7c, 0x7e, 0x01, 0x41, 0x7e, 0x21, 0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9,
    0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02,
    0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
    0xf8, 0x17, 0x98, 0xad]

/--
Lowering for `check_preimage(preimage)` (BUG-100 on-chain binding). Mirrors
`lowerCheckPreimage` in `05-stack-lower.ts:3156-3197`.

Op sequence:

  OP_CODESEPARATOR
  <bring preimage to top>
  <the fixed 760-byte OP_PUSH_TX binding blob (raw_bytes)>

The blob derives the ECDSA signature on-chain from `hash256(preimage)` and
runs `OP_CHECKSIGVERIFY` against `G`, aborting unless the pushed preimage
binds to the real spending transaction. Net stack effect is zero: the
preimage remains on top, renamed to `bindingName` so downstream extractors
can reference it. The old spender-supplied `_opPushTxSig` witness is gone.
-/
def lowerCheckPreimageOps (sm : StackMap) (bindingName : String)
    (preimage : String) : (List StackOp × StackMap) :=
  let s0 : List StackOp := [.opcode "OP_CODESEPARATOR"]
  -- Bring preimage to top.
  let s1 := loadRef sm preimage
  -- Derive + verify the signature on-chain (single opaque raw_bytes blob).
  let s2 : List StackOp := [.rawBytes checkPreimageBindingBytes]
  (s0 ++ s1 ++ s2, sm.push bindingName)

/--
Liveness-aware variant of `lowerCheckPreimageOps` (BUG-100 on-chain
binding). Mirrors TS `lowerCheckPreimage` (`05-stack-lower.ts:3156-3197`):
`OP_CODESEPARATOR`, bring the preimage to top (ROLL-on-last-use), then emit
the fixed 760-byte OP_PUSH_TX binding blob as a single opaque `.rawBytes`
op. Net stack effect is zero — the preimage stays on top, renamed to
`bindingName`. No `_opPushTxSig` witness is loaded (the signature is derived
on-chain from the preimage), so `lowerMethod` no longer prepends it.
-/
def lowerCheckPreimageOpsLive (sm : StackMap) (bindingName : String)
    (preimage : String) (currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let s0 : List StackOp := [.opcode "OP_CODESEPARATOR"]
  -- Step 1: bring preimage to top, consuming on last use.
  let (s1, sm1) := loadRefLive sm preimage currentIndex lastUses outerProtected
  -- Step 2: derive + verify the signature on-chain (single opaque raw_bytes
  -- blob; net stack effect 0 — preimage in → preimage out).
  let s2 : List StackOp := [.rawBytes checkPreimageBindingBytes]
  -- The preimage stays on top; rename the slot to bindingName.
  let smFinal :=
    match sm1 with
    | _ :: rest => bindingName :: rest
    | []        => [bindingName]
  (s0 ++ s1 ++ s2, smFinal)

/-! ## Phase 3z-E framework intrinsics: change & state-output helpers

Mirrors three TS builtins that the parser surfaces as `.call` ANF
nodes with reserved names, but which the TS pass lowers via dedicated
multi-op sequences (not the `BUILTIN_OPCODES` table):

* `buildChangeOutput(pkh, amount)`        — `lowerBuildChangeOutput`
  (`05-stack-lower.ts:2306-2360`)
* `computeStateOutput(pre, state, amt)`   — `lowerComputeStateOutput`
  (`05-stack-lower.ts:2216-2303`)
* `computeStateOutputHash(pre, state)`    — `lowerComputeStateOutputHash`
  (`05-stack-lower.ts:2097-2213`)

Each uses `bringToTop` with consume-on-last-use for user refs and
PICK-style copy (`bringToTop _ _codePart false`) for the implicit
`_codePart` slot prepended by `lowerMethod`.
-/

/-- Lowering for `buildChangeOutput(pkh, amount)`. Builds a P2PKH
output serialization on the stack:

  amount(8 LE) ++ 0x19 ++ 0x76 0xa9 0x14 ++ pkh(20 bytes) ++ 0x88 0xac

Mirrors `lowerBuildChangeOutput` (`05-stack-lower.ts:2306-2360`). -/
def lowerBuildChangeOutputOps (sm : StackMap) (bindingName : String)
    (pkh amount : String) (currentIndex : Nat)
    (lastUses : List (String × Nat)) (outerProtected : List String) :
    (List StackOp × StackMap) :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  -- Step 1: push prefix bytes (varint(25) + OP_DUP + OP_HASH160 + OP_PUSHBYTES_20).
  let s1 : List StackOp :=
    [.push (.bytes (ByteArray.mk #[0x19, 0x76, 0xa9, 0x14]))]
  let smAfterPrefix := sm.push "_prefix"
  -- Step 2: bring pkh to top (consume on last use, modulo the repeated-
  -- operand gate over `[pkh, amount]`), CAT prefix||pkh.
  let (s2Load, sm2) :=
    loadRefOperand smAfterPrefix pkh [pkh, amount] currentIndex lastUses outerProtected
  let s2 : List StackOp := s2Load ++ [opc "OP_CAT"]
  let smAfterPkhCat := (sm2.popN 2).push "_acc"
  -- Step 3: push suffix (OP_EQUALVERIFY + OP_CHECKSIG = 0x88ac), CAT.
  let s3 : List StackOp :=
    [.push (.bytes (ByteArray.mk #[0x88, 0xac])), opc "OP_CAT"]
  let smAfterSuffix := (smAfterPkhCat.push "_suffix").popN 2 |>.push "_acc"
  -- Step 4: bring amount to top, NUM2BIN(8), SWAP, CAT (prepend).
  let (s4Load, sm4) :=
    loadRefOperand smAfterSuffix amount [pkh, amount] currentIndex lastUses outerProtected
  let s4 : List StackOp :=
    s4Load ++ [push 8, opc "OP_NUM2BIN", .swap, opc "OP_CAT"]
  -- Net stack-map effect: the SWAP+CAT pair fuses the amount slot with the
  -- accumulator (`_acc` after step 3) into a single output-bytes slot.
  -- Pop BOTH the amount slot and the `_acc` slot (popN 2) before pushing
  -- bindingName. The earlier `popN 1` form left `_acc` lingering at depth 1
  -- and shifted every subsequent PICK/ROLL by +1 — the off-by-one observed
  -- in the stateful / stateful-counter / state-ripemd160 / token-nft /
  -- auction fixtures' computeStateOutput emission.
  let smFinal := (sm4.popN 2).push bindingName
  (s1 ++ s2 ++ s3 ++ s4, smFinal)

/-- Lowering for `computeStateOutput(preimage, stateBytes, newAmount)`.
Drops the `preimage` ref (uses `_codePart` instead), builds:

  amount(8 LE) ++ varint(scriptLen) ++ codePart ++ OP_RETURN ++ stateBytes

Mirrors `lowerComputeStateOutput` (`05-stack-lower.ts:2220-2303`). -/
def lowerComputeStateOutputOps (sm : StackMap) (bindingName : String)
    (preimage stateBytes newAmount : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  -- Full operand list (TS `csoOperands = [preimageRef, stateBytesRef,
  -- newAmountRef]`) for the repeated-operand consume gate.
  let csoOperands : List String := [preimage, stateBytes, newAmount]
  -- Step A: bring preimage to top (consume on last use), then DROP it.
  --         The preimage is unused — `_codePart` and `_newAmount` carry
  --         all the information needed for the continuation output.
  let (sA, smA) :=
    loadRefOperand sm preimage csoOperands currentIndex lastUses outerProtected
  let sA' : List StackOp := sA ++ [.drop]
  let smA' := smA.popN 1
  -- Step B: bring newAmount to top, NUM2BIN(8), TOALTSTACK.
  let (sB, smB) :=
    loadRefOperand smA' newAmount csoOperands currentIndex lastUses outerProtected
  let sB' : List StackOp :=
    sB ++ [push 8, opc "OP_NUM2BIN", opc "OP_TOALTSTACK"]
  -- Net stack-map after step B: the named amount slot is replaced by
  -- NUM2BIN's anon result, then TOALTSTACK pops it. Pop one entry.
  let smB' := smB.popN 1
  -- Step C: bring stateBytes to top.
  let (sC, smC) :=
    loadRefOperand smB' stateBytes csoOperands currentIndex lastUses outerProtected
  -- Step D: bring _codePart to top (PICK, never consume).
  let (sD, smD) := bringToTop smC "_codePart" false
  -- Stack: [..., stateBytes, codePart]
  -- Step E: push 0x6a; OP_CAT. codePart || OP_RETURN.
  let sE : List StackOp :=
    [.push (.bytes (ByteArray.mk #[0x6a])), opc "OP_CAT"]
  -- After push: pushes 1 (anon). After CAT: pops 2 / pushes 1.
  -- smD has codePart on top, then stateBytes; CAT consumes top + push.
  let smE := (smD.popN 1).push "_codeRet"
  -- Step F: SWAP, OP_CAT. Now top = codePart||OP_RETURN||stateBytes.
  let sF : List StackOp := [.swap, opc "OP_CAT"]
  -- swap then CAT: net pop 1.
  let smF := smE.popN 1
  -- Step G: OP_SIZE, varintEncodingOps. Computes varint over the script.
  let sG : List StackOp := [opc "OP_SIZE"] ++ varintEncodingOps
  -- After OP_SIZE: pushes 1 (the size). varintEncoding leaves top = varint.
  let smG := smF.push "_varint"
  -- Step H: SWAP, OP_CAT. Prepends varint to script.
  let sH : List StackOp := [.swap, opc "OP_CAT"]
  let smH := smG.popN 1
  -- Step I: OP_FROMALTSTACK; SWAP; OP_CAT. Prepends amount.
  let sI : List StackOp :=
    [opc "OP_FROMALTSTACK", .swap, opc "OP_CAT"]
  -- FROMALTSTACK pushes 1 (the amount); SWAP is 0; CAT pops 2 / pushes 1.
  -- Net stack-map change: 0. The top of smH (the SWAP+CAT result from step
  -- H) is then RENAMED to bindingName — not pushed on top of smH, which
  -- would leave smH's varint+script slot lingering at depth 1 and shift
  -- every subsequent PICK/ROLL by +1 (the off-by-one observed in the
  -- stateful / stateful-counter / state-ripemd160 / token-nft / auction
  -- fixtures before Phase 3z-G).
  let smFinal := (smH.popN 1).push bindingName
  (sA' ++ sB' ++ sC ++ sD ++ sE ++ sF ++ sG ++ sH ++ sI, smFinal)

/-- Lowering for `computeStateOutputHash(preimage, stateBytes)`. Same as
`computeStateOutput` but extracts the amount from the preimage's
scriptCode field (last 52 bytes − last 44 = an 8-byte LE field) and
hashes the result with OP_HASH256.

Mirrors `lowerComputeStateOutputHash` (`05-stack-lower.ts:2106-2213`). -/
def lowerComputeStateOutputHashOps (sm : StackMap) (bindingName : String)
    (preimage stateBytes : String) (currentIndex : Nat)
    (lastUses : List (String × Nat)) (outerProtected : List String) :
    (List StackOp × StackMap) :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  -- Step A: bring stateBytes to top (operand gate over the TS list
  -- `[preimageRef, stateBytesRef]`).
  let (sA, smA) :=
    loadRefOperand sm stateBytes [preimage, stateBytes] currentIndex lastUses outerProtected
  -- Step B: bring preimage to top.
  let (sB, smB) :=
    loadRefOperand smA preimage [preimage, stateBytes] currentIndex lastUses outerProtected
  -- Step C: extract amount from preimage. End-relative: SIZE - 52 → split
  -- off prefix; then DROP prefix, take 8 bytes, drop tail.
  -- TS sequence (verbatim, modulo stack-map bookkeeping):
  --   OP_SIZE; push 52; OP_SUB; OP_SPLIT; OP_NIP;
  --   push 8;          OP_SPLIT; OP_DROP
  let sC : List StackOp :=
    [opc "OP_SIZE", push 52, opc "OP_SUB", opc "OP_SPLIT", .nip,
     push 8, opc "OP_SPLIT", .drop]
  -- Net effect on stack-map: top went from preimage to amount(8 LE);
  -- we model this with a single rename via popN 1 + push.
  let smC := (smB.popN 1).push "_amount"
  -- Step D: TOALTSTACK (save amount).
  let sD : List StackOp := [opc "OP_TOALTSTACK"]
  let smD := smC.popN 1
  -- Step E: bring _codePart to top (PICK, never consume).
  let (sE, smE) := bringToTop smD "_codePart" false
  -- Step F: push 0x6a; OP_CAT. codePart || OP_RETURN.
  let sF : List StackOp :=
    [.push (.bytes (ByteArray.mk #[0x6a])), opc "OP_CAT"]
  let smF := (smE.popN 1).push "_codeRet"
  -- Step G: SWAP, OP_CAT.
  let sG : List StackOp := [.swap, opc "OP_CAT"]
  let smG := smF.popN 1
  -- Step H: OP_SIZE, varint encoding.
  let sH : List StackOp := [opc "OP_SIZE"] ++ varintEncodingOps
  let smH := smG.push "_varint"
  -- Step I: SWAP, OP_CAT.
  let sI : List StackOp := [.swap, opc "OP_CAT"]
  let smI := smH.popN 1
  -- Step J: FROMALTSTACK; SWAP; OP_CAT. Prepends amount.
  let sJ : List StackOp :=
    [opc "OP_FROMALTSTACK", .swap, opc "OP_CAT"]
  -- Step K: OP_HASH256.
  let sK : List StackOp := [opc "OP_HASH256"]
  -- Step J net 0 (FROMALTSTACK +1, SWAP 0, CAT -1) and Step K net 0
  -- (HASH256 pops 1 / pushes 1). The top of smI (the SWAP+CAT result of
  -- step I) is RENAMED to bindingName — pushing on top of smI would
  -- leave a stale slot at depth 1 and trigger the same +1 depth shift
  -- as `lowerComputeStateOutputOps` did before Phase 3z-G.
  let smFinal := (smI.popN 1).push bindingName
  (sA ++ sB ++ sC ++ sD ++ sE ++ sF ++ sG ++ sH ++ sI ++ sJ ++ sK, smFinal)

/-- BUG-010's exclusive upper bound on the Rabin padding. Mirrors
`RABIN_PADDING_LIMIT` in `packages/runar-compiler/src/passes/rabin-codegen.ts`.
Emits as `PUSH3(000001)` — 65536 needs 3 script-number bytes. -/
def rabinPaddingLimit : Int := 65536

/-- Lowering for `verifyRabinSig(msg, sig, padding, pubKey)`.

Rabin signature verification checks `(sig^2 + padding) mod pubKey == SHA256(msg)`.

Mirrors `lowerVerifyRabinSig` (TS `05-stack-lower.ts:3884-3931`). The TS
sequence brings the four args to the top of the stack via
`bringToTop(arg, isLast)` — Lean uses the equivalent
`loadRefLive` — yielding the layout

  bottom→top: msg(3) sig(2) padding(1) pubKey(0)

then emits (`emitVerifyRabinSig`, `rabin-codegen.ts:53-70`):

  OP_SWAP
  OP_DUP  OP_0  <65536>  OP_WITHIN  OP_VERIFY   -- BUG-010 padding gate
  OP_ROT  OP_DUP  OP_MUL  OP_ADD
  OP_SWAP  OP_MOD  OP_SWAP  OP_SHA256  <push 0x00>  OP_CAT  OP_BIN2NUM  OP_NUMEQUAL

Net stack-map effect: pop 4 arg slots, push the boolean result under
`bindingName`. -/
def lowerVerifyRabinSigOpsLive (sm : StackMap) (bindingName : String)
    (msg sig padding pubKey : String) (currentIndex : Nat)
    (lastUses : List (String × Nat)) (outerProtected : List String) :
    (List StackOp × StackMap) :=
  let rabinOperands : List String := [msg, sig, padding, pubKey]
  let (loadMsg, sm1) :=
    loadRefOperand sm msg rabinOperands currentIndex lastUses outerProtected
  let (loadSig, sm2) :=
    loadRefOperand sm1 sig rabinOperands currentIndex lastUses outerProtected
  let (loadPad, sm3) :=
    loadRefOperand sm2 padding rabinOperands currentIndex lastUses outerProtected
  let (loadPk, sm4) :=
    loadRefOperand sm3 pubKey rabinOperands currentIndex lastUses outerProtected
  -- Stack bottom→top: msg sig padding pubKey
  --
  -- BUG-010's `OP_WITHIN` padding range check (`0 ≤ padding < 65536`) sits
  -- right after the first `swap`, matching `emitVerifyRabinSig`
  -- (`packages/runar-compiler/src/passes/rabin-codegen.ts:53-70`) opcode for
  -- opcode. `push (.bigint 0)` emits the same `0x00` byte the reference's
  -- `OP_0` does (`Script/Emit.encodePushBigInt`), and 65536 emits as
  -- `PUSH3(000001)`.
  let body : List StackOp :=
    [ StackOp.swap                    -- msg sig pubKey padding
    , StackOp.dup                     -- … padding padding
    , StackOp.push (.bigint 0)        -- … padding padding 0
    , StackOp.push (.bigint rabinPaddingLimit)  -- … 0 65536
    , StackOp.opcode "OP_WITHIN"      -- … padding (0 ≤ padding < 65536)
    , StackOp.opcode "OP_VERIFY"      -- msg sig pubKey padding
    , StackOp.rot                     -- msg pubKey padding sig
    , StackOp.dup                     -- msg pubKey padding sig sig
    , StackOp.opcode "OP_MUL"         -- msg pubKey padding sig^2
    , StackOp.opcode "OP_ADD"         -- msg pubKey (sig^2+padding)
    , StackOp.swap                    -- msg (sig^2+padding) pubKey
    , StackOp.opcode "OP_MOD"         -- msg ((sig^2+padding) mod pubKey)
    , StackOp.swap                    -- ((sig^2+padding) mod pubKey) msg
    , StackOp.opcode "OP_SHA256"
    -- BUG-011 digest-encoding normalization: the raw 32-byte digest is given an
    -- explicit sign byte, collapsed to minimal form and compared NUMERICALLY.
    -- The old OP_EQUAL was a byte compare against OP_MOD's minimal Script
    -- number, which carries a trailing 0x00 whenever the digest's
    -- most-significant byte has its high bit set — ~50% of honest signatures.
    , StackOp.push (.bytes (ByteArray.mk #[0x00]))
    , StackOp.opcode "OP_CAT"
    , StackOp.opcode "OP_BIN2NUM"
    , StackOp.opcode "OP_NUMEQUAL"
    ]
  -- Net: pop 4 args, push 1 result under bindingName.
  let smFinal := (sm4.popN 4).push bindingName
  (loadMsg ++ loadSig ++ loadPad ++ loadPk ++ body, smFinal)

/-! ## State serialization helpers (Phase 3z-A)

These helpers mirror the property-table-aware lowering of three
framework intrinsics from `05-stack-lower.ts`:

* `getStateScript`     — `lowerGetStateScript` (TS lines 2029-2095)
* `addOutput`          — `lowerAddOutput`      (TS lines 2362-2460)
* `deserializeState`   — `lowerDeserializeState` (TS lines 2523-2831)

They are pure functions of the property table plus runtime stack map,
with no recursion through `lowerValue` / `lowerBindings`, so they live
outside the mutual block.

The Lean lowering uses PICK-style (`loadRef`) loads everywhere the TS
reference uses `bringToTop(name, isLast)`. Liveness-aware ROLL
threading would require deeper integration with the per-binding
last-uses table; the current helpers produce byte-identical opcode
sequences for the *intrinsic body* but may differ in the load
opcodes for refs that the TS chooses to consume. SimpleANF coverage
flips to `true` regardless; full byte-exact match for the wider
state-of-the-art fixtures additionally needs concrete `update_prop`
lowering, which is tracked separately (see HANDOFF.md).
-/

/-- Property-type → fixed serialized byte width (for fixed-size fields).
Mirrors the size table in `05-stack-lower.ts:2535-2554`. Returns 0 for
variable-length (ByteString) — caller must special-case. -/
def propTypeFixedSize : ANFType → Nat
  | .bigint          => 8
  | .rabinSig        => 8
  | .rabinPubKey     => 8
  | .bool            => 1
  | .pubKey          => 33
  | .addr            => 20
  | .ripemd160       => 20
  | .sha256          => 32
  | .point           => 64
  | .p256Point       => 64
  | .p384Point       => 96
  | .sig             => 0   -- not used in fixed-state serialization
  | .sigHashPreimage => 0   -- not used
  | .byteString      => 0   -- variable-length sentinel
  | .array _         => 0   -- arrays are never fixed-size state fields

/-- True iff the property type's stored representation is a script
number (bigint, boolean, RabinSig, RabinPubKey). Such props go through
`OP_NUM2BIN` on serialization and `OP_BIN2NUM` on deserialization. -/
def propTypeIsNumeric : ANFType → Bool
  | .bigint      => true
  | .bool        => true
  | .rabinSig    => true
  | .rabinPubKey => true
  | _            => false

/-- Mirrors `pushValue` in `05-stack-lower.ts:1077-1086`: emits a
single push for a property's `initialValue`. -/
def pushInitialValue : ConstValue → StackOp
  | .int i      => .push (.bigint i)
  | .bool b     => .push (.bool b)
  | .bytes b    => .push (.bytes b)
  | .refAlias _ => .push (.bigint 0)   -- unreachable for property defaults
  | .thisRef    => .push (.bigint 0)   -- unreachable

/-- Push-data encode (length-prefix encode a ByteString as Bitcoin
script push-data). On entry stack top is the ByteString value; on
exit it is `prefix || value` (1-byte length, 0x4c||1byte, or
0x4d||2byteLE). Mirrors TS `emitPushDataEncode`
(`05-stack-lower.ts:534-671`). -/
def pushDataEncodeOps : List StackOp :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  -- [..., bs] OP_SIZE OP_DUP push 76 OP_LESSTHAN OP_IF
  [opc "OP_SIZE", .dup, push 76, opc "OP_LESSTHAN", opc "OP_IF"]
  -- THEN: len <= 75 → 1-byte length prefix
  ++ [push 2, opc "OP_NUM2BIN", push 1, opc "OP_SPLIT", .drop,
      .swap, opc "OP_CAT"]
  ++ [opc "OP_ELSE"]
  -- ELSE: len >= 76, OP_DUP push 256 OP_LESSTHAN OP_IF
  ++ [.dup, push 256, opc "OP_LESSTHAN", opc "OP_IF"]
  -- THEN: 76..255 → OP_PUSHDATA1: 0x4c + 1-byte length
  ++ [push 2, opc "OP_NUM2BIN", push 1, opc "OP_SPLIT", .drop,
      .push (.bytes (ByteArray.mk #[0x4c])), .swap, opc "OP_CAT",
      .swap, opc "OP_CAT"]
  ++ [opc "OP_ELSE"]
  -- ELSE: >= 256 → OP_PUSHDATA2: 0x4d + 2-byte LE length
  ++ [push 4, opc "OP_NUM2BIN", push 2, opc "OP_SPLIT", .drop,
      .push (.bytes (ByteArray.mk #[0x4d])), .swap, opc "OP_CAT",
      .swap, opc "OP_CAT"]
  ++ [opc "OP_ENDIF", opc "OP_ENDIF"]

/-- Per-property serialization for `getStateScript` / `addOutput`:
load the property's value onto the stack, then apply the type-aware
NUM2BIN width prefix. Mirrors the inner loop body of
`lowerGetStateScript` (TS 2049-2089) and `lowerAddOutput` (TS 2391-2422).

`sm` is the stack map immediately before this property's load (the
caller threads `sm.push bindingName` in between props). Returns the op
list for this single property's load+convert. -/
def serializeProperty (sm : StackMap) (prop : ANFProperty) :
    List StackOp :=
  -- Step 1: load the property value onto the stack.
  let load : List StackOp :=
    match sm.depth? prop.name with
    | some _ =>
        -- On stack: PICK-style copy (Lean uses copy uniformly; see
        -- helper docstring). Byte-identical when the prop is at depth 0.
        loadRef sm prop.name
    | none =>
        match prop.initialValue with
        | some iv => [pushInitialValue iv]
        | none    => [.push (.bigint 0)]
  -- Step 2: type-aware width prefix.
  let conv : List StackOp :=
    if propTypeIsNumeric prop.type then
      [.push (.bigint (Int.ofNat (propTypeFixedSize prop.type))), .opcode "OP_NUM2BIN"]
    else if prop.type = .byteString then
      pushDataEncodeOps
    else
      []  -- other byte types: no conversion needed
  load ++ conv

/-- Concatenate the serialized bytes for `props` (filtered to
non-readonly), interleaving `OP_CAT` between successive entries.

Returns `(opList, finalSm)` where `finalSm` has `bindingName` on top.
Mirrors `lowerGetStateScript` in `05-stack-lower.ts:2029-2095`. -/
def lowerGetStateScriptOps (sm : StackMap) (bindingName : String)
    (props : List ANFProperty) : (List StackOp × StackMap) :=
  let stateProps := props.filter (fun p => !p.readonly)
  match stateProps with
  | [] =>
      -- Empty state: push empty bytes.
      ([.push (.bytes (ByteArray.mk #[]))], sm.push bindingName)
  | first :: rest =>
      -- Emit first prop's serialized form (no leading CAT).
      let firstOps := serializeProperty sm first
      -- Each subsequent prop: serialize against `sm` (we model the
      -- accumulator as anonymous, leaving `sm` unchanged across props
      -- — it would normally have an unnamed top-of-stack slot).
      let restOps : List StackOp :=
        rest.foldl (init := []) fun acc p =>
          acc ++ serializeProperty sm p ++ [.opcode "OP_CAT"]
      (firstOps ++ restOps, sm.push bindingName)

/-- Per-property serialize step for `lowerGetStateScriptOpsLive`. Mirrors
the inner loop body of TS `lowerGetStateScript` (`05-stack-lower.ts:
2049-2089`): for each state prop, bring it to top with `consume=true`
when it is currently on the stack, applying the type-aware width prefix,
then OP_CAT onto the running accumulator (modeled as the anonymous slot
already on top of `sm` — caller seeds it as `_acc`).

`outerProtected` is honored just like in `loadRefLive`; if the prop name
would have been protected (e.g. it pre-existed the current scope), we
fall back to a PICK-style copy via `bringToTop _ _ false`. -/
private def getStateScriptPropLive
    (outerProtected : List String) :
    StackMap → ANFProperty → (List StackOp × StackMap)
  | sm, prop =>
    let opc (s : String) : StackOp := .opcode s
    let push (n : Int) : StackOp := .push (.bigint n)
    -- Step 1: load (or push initial / placeholder).
    let (load, sm1) :=
      match sm.depth? prop.name with
      | some _ =>
          -- On stack — consume unless the prop name is in outerProtected.
          let consume := !listContains outerProtected prop.name
          bringToTop sm prop.name consume
      | none =>
          let pushed : List StackOp :=
            match prop.initialValue with
            | some iv => [pushInitialValue iv]
            | none    => [push 0]
          (pushed, sm.push prop.name)
    -- Step 2: type-aware width prefix.
    let conv : List StackOp :=
      if propTypeIsNumeric prop.type then
        [push (Int.ofNat (propTypeFixedSize prop.type)), opc "OP_NUM2BIN"]
      else if prop.type = .byteString then
        pushDataEncodeOps
      else
        []  -- other byte types: no conversion needed
    -- After NUM2BIN: pop the named value + width (2 entries) and push
    -- the (anonymous) converted value. For non-numeric, the named entry
    -- stays as-is; we still pop+push to anonymize since it's about to
    -- be CAT'd into the accumulator.
    let smPostConv : StackMap :=
      if propTypeIsNumeric prop.type then (sm1.popN 1).push "_conv"
      else
        match sm1 with
        | _ :: rest => "_conv" :: rest
        | []        => ["_conv"]
    (load ++ conv, smPostConv)

/-- Liveness-aware variant of `lowerGetStateScriptOps`. Mirrors TS
`lowerGetStateScript` (`05-stack-lower.ts:2029-2095`) including the
`bringToTop(prop.name, true)` consume-on-load semantics for state
properties currently on the stack: the prop slot is removed from the
stack map by ROLL/SWAP/ROT and replaced by its serialized byte form,
which then OP_CATs onto the running accumulator.

`outerProtected` is the snapshot of the parent scope's stack map at the
point this binding was reached. Props that pre-existed the current
scope (e.g. in an inner `if` branch) cannot be consumed and fall back to
PICK-style copies, matching TS's `outerProtectedRefs` mechanism. -/
def lowerGetStateScriptOpsLive (sm : StackMap) (bindingName : String)
    (props : List ANFProperty) (_currentIndex : Nat)
    (_lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let stateProps := props.filter (fun p => !p.readonly)
  match stateProps with
  | [] =>
      ([.push (.bytes (ByteArray.mk #[]))], sm.push bindingName)
  | first :: rest =>
      -- First prop: serialize then leave on stack as the running acc.
      let (firstOps, sm1) := getStateScriptPropLive outerProtected sm first
      -- For each subsequent prop, serialize (against the current sm) and
      -- emit OP_CAT to fold into the accumulator.
      let foldStep
          (acc : List StackOp × StackMap) (p : ANFProperty) :
          List StackOp × StackMap :=
        let (accOps, accSm) := acc
        let (pOps, smP) := getStateScriptPropLive outerProtected accSm p
        -- After OP_CAT: pops 2 anon entries (acc + conv) and pushes 1 (new acc).
        let smCat := (smP.popN 2).push "_acc"
        (accOps ++ pOps ++ [.opcode "OP_CAT"], smCat)
      let (restOps, smRest) :=
        rest.foldl (init := (firstOps, sm1)) foldStep
      -- Rename top from `_conv` / `_acc` to `bindingName`.
      let smFinal : StackMap :=
        match smRest with
        | _ :: tl => bindingName :: tl
        | []      => [bindingName]
      (restOps, smFinal)

/-- Lowering for `add_output(satoshis, stateValues, preimage)`. Builds
a full BIP-143 output serialization on the stack:

  amount(8 LE) ++ varint(scriptLen) ++ codePart ++ OP_RETURN ++ stateBytes

Mirrors `lowerAddOutput` in `05-stack-lower.ts:2362-2460`. -/
def lowerAddOutputOps (sm : StackMap) (bindingName : String)
    (satoshis : String) (stateValues : List String)
    (props : List ANFProperty) : (List StackOp × StackMap) :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  let stateProps := props.filter (fun p => !p.readonly)
  -- Step 1: bring _codePart to top (PICK — never consume).
  let s1 := loadRef sm "_codePart"
  -- Step 2: append OP_RETURN byte (0x6a).
  let s2 : List StackOp :=
    [.push (.bytes (ByteArray.mk #[0x6a])), opc "OP_CAT"]
  -- Step 3: serialize each state value, paired with its property type.
  --   For each (valueRef, prop): bring valueRef to top, type-convert,
  --   then OP_CAT onto the accumulator.
  let smAfterCodePart := sm.push bindingName
  let rec go : List String → List ANFProperty → List StackOp
    | [], _ => []
    | _, [] => []
    | v :: vs, p :: ps =>
        let load := loadRef smAfterCodePart v
        let conv : List StackOp :=
          if propTypeIsNumeric p.type then
            [push (Int.ofNat (propTypeFixedSize p.type)), opc "OP_NUM2BIN"]
          else
            []
        load ++ conv ++ [opc "OP_CAT"] ++ go vs ps
  let s3 := go stateValues stateProps
  -- Step 4: compute varint prefix for the script length.
  let s4 : List StackOp := [opc "OP_SIZE"] ++ varintEncodingOps
  -- Step 5: prepend varint to script.
  let s5 : List StackOp := [.swap, opc "OP_CAT"]
  -- Step 6: prepend satoshis as 8-byte LE.
  let s6Load := loadRef smAfterCodePart satoshis
  let s6 : List StackOp :=
    s6Load ++ [push 8, opc "OP_NUM2BIN", .swap, opc "OP_CAT"]
  (s1 ++ s2 ++ s3 ++ s4 ++ s5 ++ s6, smAfterCodePart)

/--
Per-state-value serialize step inside `lowerAddOutputOps`. The TS
reference brings each value to top with consume=isLast (`05-stack-
lower.ts:2391-2422`); we mirror that with `bringToTop`. Each iteration
consumes the value's stack slot, applies the type-aware width prefix,
then OP_CATs onto the accumulator (which is below the value on the
runtime stack but unnamed in the stack map — we model it with a
single `_acc` placeholder pushed by the caller).

(De-`private`d 2026-06-11 so the stateful-widening lowering reduction in
`Stack/AgreesStateful.lean` can unfold it by name — no semantic change.)
-/
def addOutputStateValuesLive (currentIndex : Nat)
    (lastUses : List (String × Nat)) (outerProtected : List String)
    (allOperands : List String) :
    StackMap → List String → List ANFProperty → (List StackOp × StackMap)
  | sm, [], _ => ([], sm)
  | sm, _, [] => ([], sm)
  | sm, v :: vs, p :: ps =>
      let opc (s : String) : StackOp := .opcode s
      let push (n : Int) : StackOp := .push (.bigint n)
      let (load, sm1) := loadRefOperand sm v allOperands currentIndex lastUses outerProtected
      let conv : List StackOp :=
        if propTypeIsNumeric p.type then
          [push (Int.ofNat (propTypeFixedSize p.type)), opc "OP_NUM2BIN"]
        else
          -- A ByteString state field is serialized with a Bitcoin push-data
          -- length prefix, exactly as `getStateScriptPropLive` does — TS
          -- `lowerAddOutput` calls `emitPushDataEncode()` on the
          -- `prop.type === 'ByteString'` arm (`05-stack-lower.ts:3721-3724`).
          -- Without it the continuation output commits the raw bytes and the
          -- SDK's length-prefixed state cannot be re-parsed.
          --
          -- Matched on the CONSTRUCTOR (not `p.type = .byteString`) so every
          -- other property type still reduces definitionally to the `[]` this
          -- arm produced before — the `Agrees*` reductions that pin a concrete
          -- non-ByteString type are unaffected.
          match p.type with
          | .byteString => pushDataEncodeOps
          | _           => []
      -- After load: top is the value (named on sm1).
      -- After conv (numeric): NUM2BIN pops 2 / pushes 1 → net 0 on sm,
      -- but the TS `lowerAddOutput` calls `stackMap.push(null)` then pops
      -- after NUM2BIN — net 0 anyway. We model the post-conv top as the
      -- (anonymous) converted value: pop the named value, push anon.
      --
      -- The ByteString arm needs no peer: TS's `emitPushDataEncode` restores
      -- `smEndTarget`, which is `sm1` with the top ANONYMIZED and the depth
      -- unchanged — and the very next step (`smAfterCat`) pops that slot,
      -- so naming it or not cannot be observed downstream.
      let smAfterConv :=
        if propTypeIsNumeric p.type then (sm1.popN 1).push "_conv" else sm1
      -- After OP_CAT: pops 2 / pushes 1 (the new accumulator).
      let smAfterCat := (smAfterConv.popN 2).push "_acc"
      let (restOps, smRest) :=
        addOutputStateValuesLive currentIndex lastUses outerProtected
          allOperands smAfterCat vs ps
      (load ++ conv ++ [opc "OP_CAT"] ++ restOps, smRest)

/--
Liveness-aware variant of `lowerAddOutputOps`. Mirrors TS
`lowerAddOutput` (`05-stack-lower.ts:2362-2460`). Uses `bringToTop`
with `consume=false` for `_codePart` (always copied — reused across
outputs) and `consume=isLast` for state values + satoshis. Threads
the stack map through all loads so depth shifts induced by consumed
state values (typically the last use of post-update_prop names)
propagate to subsequent loads.
-/
def lowerAddOutputOpsLive (sm : StackMap) (bindingName : String)
    (satoshis : String) (stateValues : List String)
    (props : List ANFProperty) (currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  let stateProps := props.filter (fun p => !p.readonly)
  -- Full operand list (TS `outputOperands = [satoshis, ...stateValues]`)
  -- for the repeated-operand consume gate.
  let outputOperands : List String := satoshis :: stateValues
  -- Step 1: bring _codePart to top (PICK — never consume, reused).
  let (s1, sm1) := bringToTop sm "_codePart" false
  -- Step 2: append OP_RETURN byte (0x6a). Push pops 0 / pushes 1, then
  -- CAT pops 2 / pushes 1 → net +0 on sm.
  let s2 : List StackOp :=
    [.push (.bytes (ByteArray.mk #[0x6a])), opc "OP_CAT"]
  -- After step 1 sm1 has `_codePart` on top (named); after step 2 the
  -- top is the unnamed acc bytes. Pop+push anon to reflect that.
  let smAcc := (sm1.popN 1).push "_acc"
  -- Step 3: serialize each state value.
  let (s3, sm3) :=
    addOutputStateValuesLive currentIndex lastUses outerProtected
      outputOperands smAcc stateValues stateProps
  -- Step 4: compute varint prefix.
  let s4 : List StackOp := [opc "OP_SIZE"] ++ varintEncodingOps
  -- After s4: top is the unnamed varint slot.
  let smAfterVarint := sm3.push "_varint"
  -- Step 5: prepend varint via SWAP+CAT. Net pop 1.
  let s5 : List StackOp := [.swap, opc "OP_CAT"]
  let smAfterS5 := smAfterVarint.popN 1
  -- Step 6: prepend satoshis as 8-byte LE.
  let (s6Load, sm6) :=
    loadRefOperand smAfterS5 satoshis outputOperands currentIndex lastUses outerProtected
  let s6Ops : List StackOp :=
    [push 8, opc "OP_NUM2BIN", .swap, opc "OP_CAT"]
  -- The final SWAP+CAT pair fuses the satoshis slot with the varint+script
  -- accumulator left on top after step 5 into a single output-bytes slot.
  -- Pop BOTH (popN 2) before pushing bindingName — the earlier `popN 1`
  -- form left the varint+script slot lingering at depth 1 and shifted
  -- every subsequent PICK/ROLL/SWAP by +1.
  let smFinal := (sm6.popN 2).push bindingName
  (s1 ++ s2 ++ s3 ++ s4 ++ s5 ++ s6Load ++ s6Ops, smFinal)

/-- Per-property field extractor for `deserializeState` (fixed-size,
non-final case). Mirrors `splitFixedStateFields` middle-iteration in
`05-stack-lower.ts:2849-2868`. Layout:

  [..., remaining]
  → push N, OP_SPLIT          [..., field, rest]
  → OP_SWAP                   [..., rest, field]
  → (if numeric) OP_BIN2NUM   [..., rest, field-as-num]
  → OP_SWAP                   [..., field-as-num, rest]
-/
def deserializeFixedFieldNonFinal (prop : ANFProperty) : List StackOp :=
  let opc (s : String) : StackOp := .opcode s
  let size := propTypeFixedSize prop.type
  let split : List StackOp :=
    [.push (.bigint (Int.ofNat size)), opc "OP_SPLIT", .swap]
  let conv : List StackOp :=
    if propTypeIsNumeric prop.type then [opc "OP_BIN2NUM"] else []
  split ++ conv ++ [.swap]

/-- Final-property variant. Just type-converts; the remaining bytes
ARE the field.
-/
def deserializeFixedFieldFinal (prop : ANFProperty) : List StackOp :=
  if propTypeIsNumeric prop.type then [.opcode "OP_BIN2NUM"] else []

/-- Lower the all-fixed-size case of `deserialize_state`. Iterates
left-to-right, splitting each field and naming it on the stack map.
Mirrors `splitFixedStateFields` in `05-stack-lower.ts:2837-2877`. -/
def splitFixedStateFieldsOps : List ANFProperty → List StackOp
  | []      => []
  | [p]     => deserializeFixedFieldFinal p
  | p :: ps => deserializeFixedFieldNonFinal p ++ splitFixedStateFieldsOps ps

/-! ### Variable-length deserializeState helpers (Phase 3z-I)

The TS reference (`05-stack-lower.ts:2628-2828`) handles ByteString
state fields by parsing the BIP-143 scriptCode varint at runtime,
locating the state region via `_codePart` + `push_codesep_index`, and
decoding each ByteString as a Bitcoin push-data prefix. The helpers
below are pure op-list builders mirroring those byte-for-byte.
-/

/-- Strip BIP-143 scriptCode varint prefix (1/3/5/9-byte). On entry the
top of stack is `varint || scriptCode`; on exit it is `scriptCode`.
Mirrors TS `05-stack-lower.ts:2643-2730`. -/
def varintStripOps : List StackOp :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  let dropMore (n : Int) : List StackOp :=
    [push n, opc "OP_SPLIT", .nip]
  -- Split first byte, swap so [..., rest, fb], pad+BIN2NUM
  [push 1, opc "OP_SPLIT", .swap,
   .push (.bytes (ByteArray.mk #[0x00])), opc "OP_CAT", opc "OP_BIN2NUM"]
  -- Outer IF: fb < 253 → 1-byte (drop fb)
  ++ [.dup, push 253, opc "OP_LESSTHAN", opc "OP_IF", .drop, opc "OP_ELSE"]
  -- Middle IF: fb == 254 → 5-byte (drop fb, then 4 more)
  ++ [.dup, push 254, opc "OP_NUMEQUAL", opc "OP_IF", .drop]
  ++ dropMore 4
  ++ [opc "OP_ELSE"]
  -- Inner IF: fb == 255 → 9-byte (drop fb, then 8 more)
  ++ [.dup, push 255, opc "OP_NUMEQUAL", opc "OP_IF", .drop]
  ++ dropMore 8
  ++ [opc "OP_ELSE"]
  -- Else: fb == 253 → 3-byte (drop fb, then 2 more)
  ++ [.drop]
  ++ dropMore 2
  ++ [opc "OP_ENDIF", opc "OP_ENDIF", opc "OP_ENDIF"]

/-- Push-data prefix decode. On entry stack is `[..., bytes]`; on exit
`[..., data, remaining]`. Mirrors TS `emitPushDataDecode`
(`05-stack-lower.ts:687-790`). -/
def pushDataDecodeOps : List StackOp :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  -- Split first byte and convert to num: [..., rest, fb_num]
  [push 1, opc "OP_SPLIT", .swap, opc "OP_BIN2NUM"]
  -- Outer IF: fb < 76 → fb IS the length (OP_SPLIT directly)
  ++ [.dup, push 76, opc "OP_LESSTHAN", opc "OP_IF", opc "OP_SPLIT", opc "OP_ELSE"]
  -- Middle IF: fb == 77 → 2-byte LE length
  ++ [.dup, push 77, opc "OP_NUMEQUAL", opc "OP_IF",
      .drop, push 2, opc "OP_SPLIT", .swap, opc "OP_BIN2NUM", opc "OP_SPLIT",
      opc "OP_ELSE"]
  -- Else: fb == 76 → 1-byte length
  ++ [.drop, push 1, opc "OP_SPLIT", .swap, opc "OP_BIN2NUM", opc "OP_SPLIT"]
  ++ [opc "OP_ENDIF", opc "OP_ENDIF"]

/-- Per-property decoder for variable-length state, non-final case.
Mirrors TS `05-stack-lower.ts:2782-2812`. On entry top is
`remaining_state`; on exit top is the new `remaining_state` and the
property value lives at depth 1. -/
def deserializeVarFieldNonFinal (prop : ANFProperty) : List StackOp :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  match prop.type with
  | .byteString =>
      -- pushDataDecode: [..., remaining] → [..., data, rest]
      pushDataDecodeOps
  | _ =>
      -- fixed-size: split, swap to bring field on top, optional BIN2NUM, swap back
      let size := propTypeFixedSize prop.type
      let conv : List StackOp :=
        if propTypeIsNumeric prop.type then [opc "OP_BIN2NUM"] else []
      [push (Int.ofNat size), opc "OP_SPLIT", .swap]
        ++ conv
        ++ [.swap]

/-- Per-property decoder for variable-length state, final case.
Mirrors TS `05-stack-lower.ts:2814-2825`. On entry top is the entire
remaining state; on exit top is the property value (drop trailing
empty for ByteString, BIN2NUM for numeric). -/
def deserializeVarFieldFinal (prop : ANFProperty) : List StackOp :=
  let opc (s : String) : StackOp := .opcode s
  match prop.type with
  | .byteString =>
      -- pushDataDecode then drop the trailing empty remainder.
      pushDataDecodeOps ++ [.drop]
  | _ =>
      if propTypeIsNumeric prop.type then [opc "OP_BIN2NUM"] else []

/-- Per-property loop (variable-length path). Iterates left-to-right
and emits the appropriate decoder for each. Last property uses the
"final" form. -/
def deserializeVarFields : List ANFProperty → List StackOp
  | []      => []
  | [p]     => deserializeVarFieldFinal p
  | p :: ps => deserializeVarFieldNonFinal p ++ deserializeVarFields ps

/-- Lowering for `deserialize_state(preimage)`. Extracts the mutable
state bytes from the BIP-143 preimage's scriptCode field and unpacks
them into individual property values on the stack.

Handles both the all-fixed-size path and the variable-length path
(when ByteString state fields are present). The variable-length path
uses `_codePart` and `push_codesep_index` to locate the state region
inside the scriptCode at runtime.

Mirrors `lowerDeserializeState` in `05-stack-lower.ts:2523-2831`. -/
def lowerDeserializeStateOps (sm : StackMap) (preimage : String)
    (props : List ANFProperty) : (List StackOp × StackMap) :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  let stateProps := props.filter (fun p => !p.readonly)
  match stateProps with
  | [] =>
      -- No state — emit no ops, leave sm unchanged.
      ([], sm)
  | _ =>
    -- Bring preimage to top.
    let s0 := loadRef sm preimage
    -- 1. Skip first 104 bytes (header), drop prefix via OP_NIP.
    let s1 : List StackOp := [push 104, opc "OP_SPLIT", .nip]
    -- 2. Drop tail 44 bytes (nSeq + hashOutputs + nLocktime + sighashType).
    let s2 : List StackOp :=
      [opc "OP_SIZE", push 44, opc "OP_SUB", opc "OP_SPLIT", .drop]
    -- 3. Drop amount (last 8 bytes).
    let s3 : List StackOp :=
      [opc "OP_SIZE", push 8, opc "OP_SUB", opc "OP_SPLIT", .drop]
    let allFixed := stateProps.all (fun p => p.type ≠ .byteString)
    if allFixed then
      -- 4. Extract last stateLen bytes (skip varint+codePart+OP_RETURN prefix).
      let stateLen : Nat := stateProps.foldl (fun acc p => acc + propTypeFixedSize p.type) 0
      let s4 : List StackOp :=
        [opc "OP_SIZE", push (Int.ofNat stateLen), opc "OP_SUB", opc "OP_SPLIT", .nip]
      -- 5. Split state bytes into individual property values, naming each.
      let s5 := splitFixedStateFieldsOps stateProps
      -- Stack-map updates: each property is pushed (named) onto the map.
      let smAfter : StackMap :=
        stateProps.foldl (fun m p => m.push p.name) sm
      (s0 ++ s1 ++ s2 ++ s3 ++ s4 ++ s5, smAfter)
    else
      -- Variable-length path requires `_codePart` to be live; if it isn't,
      -- the body cannot reconstruct the state region — emit a single
      -- OP_DROP to discard the leftover varint+scriptCode and skip
      -- deserialization entirely (mirrors TS line 2622-2627).
      match sm.depth? "_codePart" with
      | none =>
          (s0 ++ s1 ++ s2 ++ s3 ++ [.drop], sm)
      | some _ =>
          -- 4a. Strip BIP-143 varint prefix.
          let sVar := varintStripOps
          -- 4b. PICK _codePart, OP_SIZE, OP_NIP (drop _codePart, keep size).
          let sCode := loadRef sm "_codePart"
                    ++ [opc "OP_SIZE", .nip,
                        .pushCodesepIndex,
                        opc "OP_SUB",
                        opc "OP_SPLIT", .nip]
          -- 5. Per-property var-field decode.
          let sFields := deserializeVarFields stateProps
          -- Stack-map updates: each property is pushed (named) onto the map.
          let smAfter : StackMap :=
            stateProps.foldl (fun m p => m.push p.name) sm
          (s0 ++ s1 ++ s2 ++ s3 ++ sVar ++ sCode ++ sFields, smAfter)

/--
Liveness-aware variant of `lowerDeserializeStateOps`. Mirrors TS
`lowerDeserializeState` (`05-stack-lower.ts:2523-2831`) including the
`bringToTop(preimage, isLast)` semantics: when `preimage` is at depth
0 and used for the last time the deserialization runs in-place
(consuming the preimage slot rather than DUP-ing it), so the post-
deserialize stack does not gain an extra slot. The state values
replace the original preimage slot at depth 0.
-/
def lowerDeserializeStateOpsLive (sm : StackMap) (preimage : String)
    (props : List ANFProperty) (currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let opc (s : String) : StackOp := .opcode s
  let push (n : Int) : StackOp := .push (.bigint n)
  let stateProps := props.filter (fun p => !p.readonly)
  match stateProps with
  | [] =>
      ([], sm)
  | _ =>
    -- Bring preimage to top, consuming on last use.
    let (s0, sm1) := loadRefLive sm preimage currentIndex lastUses outerProtected
    -- 1. Skip first 104 bytes (header), drop prefix via OP_NIP.
    let s1 : List StackOp := [push 104, opc "OP_SPLIT", .nip]
    -- 2. Drop tail 44 bytes (nSeq + hashOutputs + nLocktime + sighashType).
    let s2 : List StackOp :=
      [opc "OP_SIZE", push 44, opc "OP_SUB", opc "OP_SPLIT", .drop]
    -- 3. Drop amount (last 8 bytes).
    let s3 : List StackOp :=
      [opc "OP_SIZE", push 8, opc "OP_SUB", opc "OP_SPLIT", .drop]
    let allFixed := stateProps.all (fun p => p.type ≠ .byteString)
    if allFixed then
      -- 4. Extract last stateLen bytes.
      let stateLen : Nat :=
        stateProps.foldl (fun acc p => acc + propTypeFixedSize p.type) 0
      let s4 : List StackOp :=
        [opc "OP_SIZE", push (Int.ofNat stateLen), opc "OP_SUB",
         opc "OP_SPLIT", .nip]
      -- 5. Split state bytes into individual property values, naming each.
      let s5 := splitFixedStateFieldsOps stateProps
      let smPostLoad := sm1.popN 1
      let smAfter : StackMap :=
        stateProps.foldl (fun m p => m.push p.name) smPostLoad
      (s0 ++ s1 ++ s2 ++ s3 ++ s4 ++ s5, smAfter)
    else
      -- Variable-length path: needs `_codePart` to be live; if it isn't,
      -- discard the leftover varint+scriptCode and skip state decoding
      -- (mirrors TS line 2622-2627).
      match sm.depth? "_codePart" with
      | none =>
          let smPostLoad := sm1.popN 1
          (s0 ++ s1 ++ s2 ++ s3 ++ [.drop], smPostLoad)
      | some _ =>
          -- 4a. Strip BIP-143 varint prefix.
          let sVar := varintStripOps
          -- 4b. PICK _codePart, OP_SIZE, OP_NIP, push_codesep_index, OP_SUB,
          -- OP_SPLIT, OP_NIP — extracts state bytes from scriptCode.
          let sCode := loadRef sm1 "_codePart"
                    ++ [opc "OP_SIZE", .nip,
                        .pushCodesepIndex,
                        opc "OP_SUB",
                        opc "OP_SPLIT", .nip]
          -- 5. Per-property var-field decode.
          let sFields := deserializeVarFields stateProps
          let smPostLoad := sm1.popN 1
          let smAfter : StackMap :=
            stateProps.foldl (fun m p => m.push p.name) smPostLoad
          (s0 ++ s1 ++ s2 ++ s3 ++ sVar ++ sCode ++ sFields, smAfter)

/-! ## `update_prop` cleanup helper (Phase 3z-C)

After `lowerUpdateProp` brings the new value to top and renames it to
`propName`, the OLD entry for `propName` (if any) lives somewhere
below. The TS reference (`05-stack-lower.ts:2005-2024`) walks depths
1..(depth-1) and removes the FIRST matching entry it finds, breaking
out as soon as one is removed.

Mirrors the dispatch:
* `d = 1`  → emit `OP_NIP`, drop the `rest[0]` entry.
* `d ≥ 2`  → emit `[push d, roll d+1, drop]`. The literal `push d`
  consumes one extra slot, then `roll d+1` brings the prop entry
  (now at depth d+1) to top, and `drop` removes it.

Recurses on the depth index `d` and the tail of the stackmap, so it
terminates on the length of `rest`.
-/

/-- Internal: scan `tail` for `propName` starting at depth `d` (1-indexed
from the top of the renamed stackmap). Returns the cleanup ops and the
updated tail.

For `d ≥ 2` we mirror the TS reference (`05-stack-lower.ts:2012-2019`)
which emits a *single* push of the depth `d`, immediately followed by a
bare `OP_ROLL` opcode (the `roll` StackOp's `depth` field there is
*metadata* — the encoder strips it; see `06-emit.ts:467-469`). The Lean
encoder bundles `push d` *into* `.roll d` (`Script/Emit.lean:176`), so
emitting `[push d, .roll (d + 1)]` would double-push the depth literal
(producing the spurious `OP_2 OP_3 OP_ROLL` prefix observed in the
auction / add-raw-output / cross-covenant fixtures pre-Phase 3z-G). We
emit `[.push d, .opcode "OP_ROLL", .drop]` to match TS byte-for-byte. -/
def removePropEntryAux (propName : String) :
    Nat → StackMap → (List StackOp × StackMap)
  | _,  []        => ([], [])
  | d,  x :: xs   =>
      if x = some propName then
        if d = 1 then
          ([.nip], xs)
        else
          ([.push (.bigint (Int.ofNat d)), .opcode "OP_ROLL", .drop], xs)
      else
        let (ops, xs') := removePropEntryAux propName (d + 1) xs
        (ops, x :: xs')

/-- Top-level helper: takes the stackmap *after* the rename (top =
`propName`), produces the cleanup ops + updated stackmap. The new
top entry is preserved; only the deeper duplicate (if any) is
removed. -/
def removePropEntryOps (sm : StackMap) (propName : String) :
    (List StackOp × StackMap) :=
  match sm with
  | []        => ([], [])
  | top :: rest =>
      let (ops, rest') := removePropEntryAux propName 1 rest
      (ops, top :: rest')

/-! ## SHA-256 partial-block codegen (Phase 4-D)

Mirrors the TypeScript reference at
`packages/runar-compiler/src/passes/sha256-codegen.ts`. The TS reference
implements `sha256Compress(state, block)` (one-block compression, no
padding) and `sha256Finalize(state, remaining, msgBitLen)` (padding +
1-or-2-block compression behind an OP_IF/OP_ELSE branch).

The TS `Emitter` tracks main- and alt-stack depth at codegen time,
emitting `pushI(BigInt(d))` + a `pick`/`roll` op pair for non-trivial
depths. Lean's `StackOp.pick d` / `StackOp.roll d` already encode the
depth-push during the `Emit` pass, so a single Lean StackOp corresponds
to a TS `pushI` + `pick` pair. Depth tracking in Lean is therefore not
needed inside these helpers — the bodies are pure StackOp lists.

The codegen produces byte-identical output to the TS reference. The
sub-helpers (`sha_*`) follow the TS naming and structure 1:1; readers
should consult `sha256-codegen.ts` for high-level semantics. -/

/-- TS `oc(code)` — single opcode StackOp. -/
@[inline] private def shaOpc (s : String) : StackOp := .opcode s
/-- TS `pushI(BigInt n)` — single bigint push. -/
@[inline] private def shaPushI (n : Int) : StackOp := .push (.bigint n)
/-- TS `pushB(u32ToLE n)` — encode 32-bit `n` as 4 LE bytes and push.
The cast `n.toUInt32` truncates to 32 bits (matching JS bitwise ops). -/
@[inline] private def shaPushU32LE (n : UInt32) : StackOp :=
  let b0 : UInt8 := (n &&& 0xff).toUInt8
  let b1 : UInt8 := ((n >>> 8) &&& 0xff).toUInt8
  let b2 : UInt8 := ((n >>> 16) &&& 0xff).toUInt8
  let b3 : UInt8 := ((n >>> 24) &&& 0xff).toUInt8
  .push (.bytes (ByteArray.mk #[b0, b1, b2, b3]))

/-- Emit `pick(d)` per TS Emitter: 0 → dup, 1 → over, else `pickStruct d`.
The TS reference does NOT push a separate depth before its `pick` opcode
at the StackOp layer (the depth becomes a byte-level push inside `Emit`),
so we use `pickStruct` (no-pop) for byte parity. -/
@[inline] private def shaPick (d : Nat) : List StackOp :=
  match d with
  | 0     => [.dup]
  | 1     => [.over]
  | n + 2 => [.pickStruct (n + 2)]

/-- Emit `roll(d)` per TS Emitter: 0 → [], 1 → swap, 2 → rot, else `roll d`. -/
@[inline] private def shaRoll (d : Nat) : List StackOp :=
  match d with
  | 0     => []
  | 1     => [.swap]
  | 2     => [.rot]
  | n + 3 => [.roll (n + 3)]

/-- Reverse 4 bytes on TOS (LE↔BE conversion). 12 ops. Mirrors
TS `Emitter.reverseBytes4`. -/
private def shaReverseBytes4 : List StackOp :=
  [ shaPushI 1, shaOpc "OP_SPLIT"
  , shaPushI 1, shaOpc "OP_SPLIT"
  , shaPushI 1, shaOpc "OP_SPLIT"
  , .swap, shaOpc "OP_CAT"
  , .swap, shaOpc "OP_CAT"
  , .swap, shaOpc "OP_CAT" ]

/-- LE → numeric. 3 ops. -/
private def shaLe2Num : List StackOp :=
  [ .push (.bytes (ByteArray.mk #[0x00]))
  , shaOpc "OP_CAT"
  , shaOpc "OP_BIN2NUM" ]

/-- numeric → 4-byte LE. 5 ops. -/
private def shaNum2Le : List StackOp :=
  [ shaPushI 5, shaOpc "OP_NUM2BIN"
  , shaPushI 4, shaOpc "OP_SPLIT", .drop ]

/-- ROTR(x, n) on a 4-byte BE value. 7 ops. -/
private def shaRotrBE (n : Nat) : List StackOp :=
  [ .dup
  , shaPushI (Int.ofNat n), shaOpc "OP_RSHIFT"
  , .swap
  , shaPushI (Int.ofNat (32 - n)), shaOpc "OP_LSHIFT"
  , shaOpc "OP_OR" ]

/-- SHR(x, n) on a 4-byte BE value. 2 ops. -/
private def shaShrBE (n : Nat) : List StackOp :=
  [ shaPushI (Int.ofNat n), shaOpc "OP_RSHIFT" ]

/-- 32-bit add on LE values. Net: -1. 13 ops. -/
private def shaAdd32 : List StackOp :=
  shaLe2Num ++ [.swap] ++ shaLe2Num ++ [shaOpc "OP_ADD"] ++ shaNum2Le

/-- Add N LE values: top N are converted, summed, packed back. -/
private def shaAddNAux : Nat → List StackOp
  | 0     => []
  | n + 1 => [.swap] ++ shaLe2Num ++ [shaOpc "OP_ADD"] ++ shaAddNAux n

private def shaAddN (n : Nat) : List StackOp :=
  if n < 2 then []
  else shaLe2Num ++ shaAddNAux (n - 1) ++ shaNum2Le

/-- TS `bigSigma0` Σ0(a) = ROTR(2)^ROTR(13)^ROTR(22). [a(LE)] → [Σ0(LE)]. -/
private def shaBigSigma0 : List StackOp :=
  shaReverseBytes4
  ++ [.dup, .dup]
  ++ shaRotrBE 2 ++ [.swap] ++ shaRotrBE 13
  ++ [shaOpc "OP_XOR"]
  ++ [.swap] ++ shaRotrBE 22
  ++ [shaOpc "OP_XOR"]
  ++ shaReverseBytes4

/-- TS `bigSigma1` Σ1(e) = ROTR(6)^ROTR(11)^ROTR(25). -/
private def shaBigSigma1 : List StackOp :=
  shaReverseBytes4
  ++ [.dup, .dup]
  ++ shaRotrBE 6 ++ [.swap] ++ shaRotrBE 11
  ++ [shaOpc "OP_XOR"]
  ++ [.swap] ++ shaRotrBE 25
  ++ [shaOpc "OP_XOR"]
  ++ shaReverseBytes4

/-- TS `smallSigma0` σ0(x) = ROTR(7)^ROTR(18)^SHR(3). -/
private def shaSmallSigma0 : List StackOp :=
  shaReverseBytes4
  ++ [.dup, .dup]
  ++ shaRotrBE 7 ++ [.swap] ++ shaRotrBE 18
  ++ [shaOpc "OP_XOR"]
  ++ [.swap] ++ shaShrBE 3
  ++ [shaOpc "OP_XOR"]
  ++ shaReverseBytes4

/-- TS `smallSigma1` σ1(x) = ROTR(17)^ROTR(19)^SHR(10). -/
private def shaSmallSigma1 : List StackOp :=
  shaReverseBytes4
  ++ [.dup, .dup]
  ++ shaRotrBE 17 ++ [.swap] ++ shaRotrBE 19
  ++ [shaOpc "OP_XOR"]
  ++ [.swap] ++ shaShrBE 10
  ++ [shaOpc "OP_XOR"]
  ++ shaReverseBytes4

/-- TS `ch` Ch(e,f,g) = (e&f)^(~e&g). [e, f, g] (g=TOS) → [Ch(LE)]. Net: -2. -/
private def shaCh : List StackOp :=
  [ .rot, .dup, shaOpc "OP_INVERT", .rot
  , shaOpc "OP_AND", shaOpc "OP_TOALTSTACK"
  , shaOpc "OP_AND", shaOpc "OP_FROMALTSTACK"
  , shaOpc "OP_XOR" ]

/-- TS `maj` Maj(a,b,c) = (a&b)|(c&(a^b)). [a, b, c] (c=TOS) → [Maj(LE)]. Net: -2. -/
private def shaMaj : List StackOp :=
  [ shaOpc "OP_TOALTSTACK", shaOpc "OP_2DUP"
  , shaOpc "OP_AND", shaOpc "OP_TOALTSTACK"
  , shaOpc "OP_XOR", shaOpc "OP_FROMALTSTACK"
  , .swap, shaOpc "OP_FROMALTSTACK"
  , shaOpc "OP_AND", shaOpc "OP_OR" ]

/-- N-fold concat helper for `beWordsToLE` — emit N×(reverseBytes4 ++ TOALT)
followed by N×FROMALT. Order-preserving alt round-trip. -/
private def shaBeWordsToLEAux1 : Nat → List StackOp
  | 0     => []
  | n + 1 => shaReverseBytes4 ++ [shaOpc "OP_TOALTSTACK"] ++ shaBeWordsToLEAux1 n

private def shaBeWordsToLEAux2 : Nat → List StackOp
  | 0     => []
  | n + 1 => [shaOpc "OP_FROMALTSTACK"] ++ shaBeWordsToLEAux2 n

private def shaBeWordsToLE (n : Nat) : List StackOp :=
  shaBeWordsToLEAux1 n ++ shaBeWordsToLEAux2 n

/-- Convert 8 BE words to LE AND reverse order. TS `beWordsToLEReversed8`.
For i = 7 .. 0: roll i, reverseBytes4, TOALT. Then 8× FROMALT. -/
private def shaBeWordsToLEReversed8Phase1 : Nat → List StackOp
  | 0     => shaRoll 0 ++ shaReverseBytes4 ++ [shaOpc "OP_TOALTSTACK"]
  | n + 1 =>
      shaBeWordsToLEReversed8Phase1 n ++
      shaRoll (n + 1) ++ shaReverseBytes4 ++ [shaOpc "OP_TOALTSTACK"]

-- Note: TS iterates `for i = 7; i >= 0; i--`. So order is roll(7), roll(6), ..., roll(0).
-- Our recursive Aux1 above iterates `0 .. n` which gives the *reverse* order — wrong.
-- Define the correct recursion: take the count `n+1` and emit roll(n), then count down.

/-- Phase 1 (correct order): roll(7), roll(6), ..., roll(0). -/
private def shaBeWordsToLEReversed8P1 : Nat → List StackOp
  | 0     => shaRoll 0 ++ shaReverseBytes4 ++ [shaOpc "OP_TOALTSTACK"]
  | n + 1 =>
      shaRoll (n + 1) ++ shaReverseBytes4 ++ [shaOpc "OP_TOALTSTACK"] ++
      shaBeWordsToLEReversed8P1 n

private def shaBeWordsToLEReversed8 : List StackOp :=
  shaBeWordsToLEReversed8P1 7 ++ shaBeWordsToLEAux2 8

/-- SHA-256 round constant K[t] for t < 64. Values match FIPS 180-4. -/
private def shaK : Nat → UInt32
  | 0  => 0x428a2f98 | 1  => 0x71374491 | 2  => 0xb5c0fbcf | 3  => 0xe9b5dba5
  | 4  => 0x3956c25b | 5  => 0x59f111f1 | 6  => 0x923f82a4 | 7  => 0xab1c5ed5
  | 8  => 0xd807aa98 | 9  => 0x12835b01 | 10 => 0x243185be | 11 => 0x550c7dc3
  | 12 => 0x72be5d74 | 13 => 0x80deb1fe | 14 => 0x9bdc06a7 | 15 => 0xc19bf174
  | 16 => 0xe49b69c1 | 17 => 0xefbe4786 | 18 => 0x0fc19dc6 | 19 => 0x240ca1cc
  | 20 => 0x2de92c6f | 21 => 0x4a7484aa | 22 => 0x5cb0a9dc | 23 => 0x76f988da
  | 24 => 0x983e5152 | 25 => 0xa831c66d | 26 => 0xb00327c8 | 27 => 0xbf597fc7
  | 28 => 0xc6e00bf3 | 29 => 0xd5a79147 | 30 => 0x06ca6351 | 31 => 0x14292967
  | 32 => 0x27b70a85 | 33 => 0x2e1b2138 | 34 => 0x4d2c6dfc | 35 => 0x53380d13
  | 36 => 0x650a7354 | 37 => 0x766a0abb | 38 => 0x81c2c92e | 39 => 0x92722c85
  | 40 => 0xa2bfe8a1 | 41 => 0xa81a664b | 42 => 0xc24b8b70 | 43 => 0xc76c51a3
  | 44 => 0xd192e819 | 45 => 0xd6990624 | 46 => 0xf40e3585 | 47 => 0x106aa070
  | 48 => 0x19a4c116 | 49 => 0x1e376c08 | 50 => 0x2748774c | 51 => 0x34b0bcb5
  | 52 => 0x391c0cb3 | 53 => 0x4ed8aa4a | 54 => 0x5b9cca4f | 55 => 0x682e6ff3
  | 56 => 0x748f82ee | 57 => 0x78a5636f | 58 => 0x84c87814 | 59 => 0x8cc70208
  | 60 => 0x90befffa | 61 => 0xa4506ceb | 62 => 0xbef9a3f7 | 63 => 0xc67178f2
  | _  => 0

/-- One SHA-256 compression round at index `t`. Stack: [W0..W63, a..h] (a=TOS).
Net: 0. Mirrors TS `emitRound` (`sha256-codegen.ts:314-365`). -/
private def shaEmitRound (t : Nat) : List StackOp :=
  -- T1 = Σ1(e) + Ch(e,f,g) + h + K[t] + W[t]
  shaPick 4 ++ shaBigSigma1
  ++ shaPick 5 ++ shaPick 7 ++ shaPick 9 ++ shaCh
  ++ shaPick 9
  ++ [shaPushU32LE (shaK t)]
  ++ shaPick (75 - t)
  ++ shaAddN 5
  -- T2 = Σ0(a) + Maj(a,b,c); first save a copy of T1 to alt
  ++ [.dup, shaOpc "OP_TOALTSTACK"]
  ++ shaPick 1 ++ shaBigSigma0
  ++ shaPick 2 ++ shaPick 4 ++ shaPick 6 ++ shaMaj
  ++ shaAdd32
  -- new_a = T1 + T2; pull T1 back from alt
  ++ [shaOpc "OP_FROMALTSTACK"]
  ++ [.swap] ++ shaAdd32
  -- new_e = d + T1
  ++ [.swap] ++ shaRoll 5 ++ shaAdd32
  -- drop h
  ++ shaRoll 8 ++ [.drop]
  -- rotate: [ne,na,a,b,c,e,f,g] → [na,a,b,c,ne,e,f,g]
  ++ [.swap] ++ shaRoll 4 ++ shaRoll 4 ++ shaRoll 4 ++ shaRoll 3

/-- Unroll W expansion: for t = 16..63 emit
    over;σ1; pick(7); pick(16);σ0; pick(18); addN(4) -/
private def shaWExpand : Nat → List StackOp
  | 0     => []   -- t = 16: handled in helper below
  | _     => []

private def shaWExpandFromTo (t : Nat) (count : Nat) : List StackOp :=
  match count with
  | 0     => []
  | n + 1 =>
      ([.over] ++ shaSmallSigma1
        ++ shaPick (6 + 1)
        ++ shaPick (14 + 2) ++ shaSmallSigma0
        ++ shaPick (15 + 3)
        ++ shaAddN 4)
      ++ shaWExpandFromTo (t + 1) n

/-- Unrolled SHA-256 round loop t = 0..63. -/
private def shaRoundsFromTo (t : Nat) (count : Nat) : List StackOp :=
  match count with
  | 0     => []
  | n + 1 => shaEmitRound t ++ shaRoundsFromTo (t + 1) n

/-- Final-add helper: 8 iterations of (roll(8-i); add32; TOALT) for i = 0..7. -/
private def shaFinalAdd (i : Nat) : List StackOp :=
  match i with
  | 0     => shaRoll 8 ++ shaAdd32 ++ [shaOpc "OP_TOALTSTACK"]
  | n + 1 =>
      shaRoll (8 - (n + 1)) ++ shaAdd32 ++ [shaOpc "OP_TOALTSTACK"]
      ++ shaFinalAdd n

private def shaFinalAddSeq : List StackOp :=
  -- TS: for (let i = 0; i < 8; i++) { roll(8-i); add32; TOALT; }
  -- Indices: i=0..7 ⇒ rolls 8,7,6,5,4,3,2,1.
  let mk (i : Nat) := shaRoll (8 - i) ++ shaAdd32 ++ [shaOpc "OP_TOALTSTACK"]
  mk 0 ++ mk 1 ++ mk 2 ++ mk 3 ++ mk 4 ++ mk 5 ++ mk 6 ++ mk 7

/-- Final pack helper: for i = 1..7 emit FROMALT, reverseBytes4, swap, OP_CAT. -/
private def shaFinalPack : Nat → List StackOp
  | 0     => []
  | n + 1 =>
      [shaOpc "OP_FROMALTSTACK"] ++ shaReverseBytes4 ++ [.swap, shaOpc "OP_CAT"]
      ++ shaFinalPack n

/-- Drop 64 leftover items from the W array: 64×(swap; drop). -/
private def shaDropN : Nat → List StackOp
  | 0     => []
  | n + 1 => [.swap, .drop] ++ shaDropN n

/-- Repeat `split4` (push 4; OP_SPLIT) `n` times. -/
private def shaSplit4N : Nat → List StackOp
  | 0     => []
  | n + 1 => [shaPushI 4, shaOpc "OP_SPLIT"] ++ shaSplit4N n

/-- Full SHA-256 compression op list. Stack on entry: [..., state(32 BE), block(64 BE)].
Stack on exit: [..., newState(32 BE)]. Mirrors TS `generateCompressOps`. -/
private def shaCompressOps : List StackOp :=
  -- Phase 1: save initial state to alt, unpack block to 16 LE words
  [.swap, .dup, shaOpc "OP_TOALTSTACK", shaOpc "OP_TOALTSTACK"]
  ++ shaSplit4N 15
  ++ shaBeWordsToLE 16
  -- Phase 2: W expansion (t = 16..63 ⇒ 48 iterations)
  ++ shaWExpandFromTo 16 48
  -- Phase 3: unpack state into 8 LE working vars
  ++ [shaOpc "OP_FROMALTSTACK"]
  ++ shaSplit4N 7
  ++ shaBeWordsToLEReversed8
  -- Phase 4: 64 compression rounds
  ++ shaRoundsFromTo 0 64
  -- Phase 5: add initial state, pack result
  ++ [shaOpc "OP_FROMALTSTACK"]
  ++ shaSplit4N 7
  ++ shaBeWordsToLEReversed8
  ++ shaFinalAddSeq
  -- pack: pull from alt, reverse, build result
  ++ [shaOpc "OP_FROMALTSTACK"]
  ++ shaReverseBytes4
  ++ shaFinalPack 7
  -- drop the 64 W slots remaining below the result
  ++ shaDropN 64

/-- TS `emitSha256Compress` entry point. -/
private def shaEmitCompress : List StackOp := shaCompressOps

/-- TS `emitSha256Finalize` op list. Stack on entry:
[..., state(32 BE), remaining(var len), msgBitLen(bigint)].
Stack on exit: [..., hash(32 BE)]. Mirrors TS `emitSha256Finalize`. -/
private def shaEmitFinalize : List StackOp :=
  -- Step 1: convert msgBitLen → 8-byte BE; save to alt
  [ shaPushI 9, shaOpc "OP_NUM2BIN"
  , shaPushI 8, shaOpc "OP_SPLIT", .drop
  , shaPushI 4, shaOpc "OP_SPLIT" ]
  ++ shaReverseBytes4
  ++ [.swap]
  ++ shaReverseBytes4
  ++ [ shaOpc "OP_CAT", shaOpc "OP_TOALTSTACK" ]
  -- Step 2: pad remaining with 0x80
  ++ [ .push (.bytes (ByteArray.mk #[0x80])), shaOpc "OP_CAT" ]
  -- Get padded length
  ++ [ shaOpc "OP_SIZE" ]
  -- Branch on paddedLen < 57
  ++ [ .dup, shaPushI 57, shaOpc "OP_LESSTHAN" ]
  ++ [ shaOpc "OP_IF" ]
  -- 1-block path: pad to 56 bytes
  ++ [ shaPushI 56, .swap, shaOpc "OP_SUB"
     , shaPushI 0, .swap, shaOpc "OP_NUM2BIN"
     , shaOpc "OP_CAT"
     , shaOpc "OP_FROMALTSTACK", shaOpc "OP_CAT" ]
  ++ shaCompressOps
  ++ [ shaOpc "OP_ELSE" ]
  -- 2-block path: pad to 120 bytes
  ++ [ shaPushI 120, .swap, shaOpc "OP_SUB"
     , shaPushI 0, .swap, shaOpc "OP_NUM2BIN"
     , shaOpc "OP_CAT"
     , shaOpc "OP_FROMALTSTACK", shaOpc "OP_CAT"
     , shaPushI 64, shaOpc "OP_SPLIT", shaOpc "OP_TOALTSTACK" ]
  ++ shaCompressOps
  ++ [ shaOpc "OP_FROMALTSTACK" ]
  ++ shaCompressOps
  ++ [ shaOpc "OP_ENDIF" ]

/-- Lowering for `sha256Compress(state, block)`. The TS reference loads
both args (PICK-style for non-last-uses, ROLL for last-uses) then splices
`shaEmitCompress`. We mirror with `loadRefLive` / `loadRefLiveCopy` so
the Lean output matches TS hex for fixtures with consume semantics. -/
def lowerSha256CompressOpsLive (sm : StackMap) (bindingName : String)
    (state block : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let (loadState, sm1) := loadRefOperand sm state [state, block] currentIndex lastUses outerProtected
  let (loadBlock, sm2) := loadRefOperand sm1 block [state, block] currentIndex lastUses outerProtected
  -- After compress: pop state+block (2 slots) and push the new state
  -- (named under `bindingName`). The compress body is depth-neutral: -1.
  let smFinal := (sm2.popN 2).push bindingName
  (loadState ++ loadBlock ++ shaEmitCompress, smFinal)

/-- Non-liveness variant: PICK-style copies for both args. -/
def lowerSha256CompressOps (sm : StackMap) (bindingName : String)
    (state block : String) : (List StackOp × StackMap) :=
  let s1 := loadRef sm state
  let s2 := loadRef (sm.push state) block
  let smFinal := sm.push bindingName
  (s1 ++ s2 ++ shaEmitCompress, smFinal)

/-- Lowering for `sha256Finalize(state, remaining, msgBitLen)`. -/
def lowerSha256FinalizeOpsLive (sm : StackMap) (bindingName : String)
    (state remaining msgBitLen : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let finOperands : List String := [state, remaining, msgBitLen]
  let (loadState, sm1) := loadRefOperand sm state finOperands currentIndex lastUses outerProtected
  let (loadRem, sm2)   := loadRefOperand sm1 remaining finOperands currentIndex lastUses outerProtected
  let (loadBits, sm3)  := loadRefOperand sm2 msgBitLen finOperands currentIndex lastUses outerProtected
  -- After finalize: pop 3 args, push 1 result.
  let smFinal := (sm3.popN 3).push bindingName
  (loadState ++ loadRem ++ loadBits ++ shaEmitFinalize, smFinal)

/-- Non-liveness variant. -/
def lowerSha256FinalizeOps (sm : StackMap) (bindingName : String)
    (state remaining msgBitLen : String) : (List StackOp × StackMap) :=
  let s1 := loadRef sm state
  let s2 := loadRef (sm.push state) remaining
  let s3 := loadRef ((sm.push state).push remaining) msgBitLen
  let smFinal := sm.push bindingName
  (s1 ++ s2 ++ s3 ++ shaEmitFinalize, smFinal)

/-! ## BLAKE3 codegen — Phase 4-E

Mirrors the TypeScript reference at
`packages/runar-compiler/src/passes/blake3-codegen.ts`. The TS reference
implements `blake3Compress(chainingValue, block)` (single-block
compression, no padding) and `blake3Hash(message)` (zero-pad message
to 64 bytes, hash with IV as chaining value).

The ops themselves are precomputed in `Stack.Blake3` (pure StackOp
lists). Here we just thread the live stack-map through the two-arg /
one-arg load + splice pattern. -/

open RunarVerification.Stack.Blake3 in
/-- Lowering for `blake3Compress(chainingValue, block)`. After compress:
2 args popped, 1 result pushed. Net: -1. -/
def lowerBlake3CompressOpsLive (sm : StackMap) (bindingName : String)
    (chainingValue block : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let (loadCV, sm1) := loadRefOperand sm chainingValue [chainingValue, block] currentIndex lastUses outerProtected
  let (loadBlock, sm2) := loadRefOperand sm1 block [chainingValue, block] currentIndex lastUses outerProtected
  let smFinal := (sm2.popN 2).push bindingName
  (loadCV ++ loadBlock ++ b3CompressOps, smFinal)

open RunarVerification.Stack.Blake3 in
/-- Lowering for `blake3Hash(message)`. After hash: 1 arg popped,
1 result pushed. Net: 0. -/
def lowerBlake3HashOpsLive (sm : StackMap) (bindingName : String)
    (message : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let (loadMsg, sm1) := loadRefLive sm message currentIndex lastUses outerProtected
  let smFinal := (sm1.popN 1).push bindingName
  (loadMsg ++ b3HashOps, smFinal)

/-! ## WOTS+ codegen — Phase 4-F

Mirrors `lowerVerifyWOTS` (TS `05-stack-lower.ts:4022-4175`). The body
itself is precomputed in `Stack.Wots` (`wotsBodyOps`). Here we just
thread the live stack-map through a 3-arg load + splice, matching the
TS pattern of `bringToTop` for each of `[msg, sig, pubkey]` followed
by 3 stack-map pops. -/

open RunarVerification.Stack.Wots in
/-- Lowering for `verifyWOTS(msg, sig, pubkey)`. After body: 3 args
popped, 1 boolean result pushed. Net: -2. -/
def lowerVerifyWotsOpsLive (sm : StackMap) (bindingName : String)
    (msg sig pubkey : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let (loadMsg, sm1) := loadRefOperand sm msg [msg, sig, pubkey] currentIndex lastUses outerProtected
  let (loadSig, sm2) := loadRefOperand sm1 sig [msg, sig, pubkey] currentIndex lastUses outerProtected
  let (loadPk,  sm3) := loadRefOperand sm2 pubkey [msg, sig, pubkey] currentIndex lastUses outerProtected
  let smFinal := (sm3.popN 3).push bindingName
  (loadMsg ++ loadSig ++ loadPk ++ wotsBodyOps, smFinal)

/-! ## secp256k1 EC codegen — Phase 4-G

Mirrors `lowerEcBuiltin` (TS `05-stack-lower.ts:4290-4325`). Each EC
builtin loads its arguments to TOS via `loadRefLive`, pops the arg slots
from the stack map, splices the precomputed op list from `Stack.Ec`,
then pushes the result slot under `bindingName`.

All EC builtins are pop-N push-1 except `ecAdd` (pop 2 push 1),
`ecMul` (pop 2 push 1), `ecMulGen` (pop 1 push 1), `ecMakePoint`
(pop 2 push 1), and the rest pop 1 push 1. The shape is captured by
`args.length` per call site. -/

open RunarVerification.Stack.Ec in
/-- Lowering for an EC builtin. Loads each arg to TOS, then splices the
appropriate static op list. Net stack-map effect: pop `args.length`,
push `bindingName`. -/
def lowerEcBuiltinOpsLive (sm : StackMap) (bindingName : String)
    (func : String) (args : List String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  -- Load all args to TOS
  let (argOps, sm1) := lowerArgsLive currentIndex lastUses outerProtected args sm args
  -- Pick the right op list
  let body : List StackOp :=
    if func = "ecAdd" then emitEcAdd
    else if func = "ecMul" then emitEcMul
    else if func = "ecMulGen" then emitEcMulGen
    else if func = "ecNegate" then emitEcNegate
    else if func = "ecOnCurve" then emitEcOnCurve
    else if func = "ecModReduce" then emitEcModReduce
    else if func = "ecEncodeCompressed" then emitEcEncodeCompressed
    else if func = "ecMakePoint" then emitEcMakePoint
    else if func = "ecPointX" then emitEcPointX
    else if func = "ecPointY" then emitEcPointY
    else [.opcode "OP_RUNAR_UNKNOWN_EC_BUILTIN"]
  let smFinal := (sm1.popN args.length).push bindingName
  (argOps ++ body, smFinal)

/-! ## NIST P-256 / P-384 EC codegen — Phase 4-H

Mirrors `lowerNistEcBuiltin` and `lowerVerifyECDSA` (TS
`05-stack-lower.ts:4386-4441`). The body op lists for each builtin
are precomputed in `Stack.P256P384`. The dispatch arm here follows the
exact pattern of `lowerEcBuiltinOpsLive` above. -/

open RunarVerification.Stack.P256P384 in
/-- Lowering for a NIST P-256 / P-384 builtin. Loads each arg to TOS,
splices the appropriate static op list. Net stack-map effect: pop
`args.length`, push `bindingName`. -/
def lowerP256P384BuiltinOpsLive (sm : StackMap) (bindingName : String)
    (func : String) (args : List String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let (argOps, sm1) := lowerArgsLive currentIndex lastUses outerProtected args sm args
  let body : List StackOp :=
    if func = "p256Add" then emitP256Add
    else if func = "p256Mul" then emitP256Mul
    else if func = "p256MulGen" then emitP256MulGen
    else if func = "p256Negate" then emitP256Negate
    else if func = "p256OnCurve" then emitP256OnCurve
    else if func = "p256EncodeCompressed" then emitP256EncodeCompressed
    else if func = "verifyECDSA_P256" then emitVerifyECDSA_P256
    else if func = "p384Add" then emitP384Add
    else if func = "p384Mul" then emitP384Mul
    else if func = "p384MulGen" then emitP384MulGen
    else if func = "p384Negate" then emitP384Negate
    else if func = "p384OnCurve" then emitP384OnCurve
    else if func = "p384EncodeCompressed" then emitP384EncodeCompressed
    else if func = "verifyECDSA_P384" then emitVerifyECDSA_P384
    else [.opcode "OP_RUNAR_UNKNOWN_P256P384_BUILTIN"]
  let smFinal := (sm1.popN args.length).push bindingName
  (argOps ++ body, smFinal)

/-! ## SLH-DSA (FIPS 205) codegen — Phase 4-I

Mirrors `lowerVerifySLHDSA` (TS `05-stack-lower.ts` →
`packages/runar-compiler/src/passes/slh-dsa-codegen.ts:emitVerifySLHDSA`).
The body op list is precomputed in `Stack.SlhDsa`. The dispatch arm here
follows the same pattern as `lowerVerifyWotsOpsLive`. -/

open RunarVerification.Stack.SlhDsa in
/-- Lowering for `verifySLHDSA_SHA2_*(msg, sig, pubkey)`. After body: 3
args popped, 1 boolean result pushed. -/
def lowerVerifySlhDsaOpsLive (sm : StackMap) (bindingName : String)
    (paramKey : String) (msg sig pubkey : String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let (loadMsg, sm1) := loadRefOperand sm  msg    [msg, sig, pubkey] currentIndex lastUses outerProtected
  let (loadSig, sm2) := loadRefOperand sm1 sig    [msg, sig, pubkey] currentIndex lastUses outerProtected
  let (loadPk,  sm3) := loadRefOperand sm2 pubkey [msg, sig, pubkey] currentIndex lastUses outerProtected
  let smFinal := (sm3.popN 3).push bindingName
  (loadMsg ++ loadSig ++ loadPk ++ emitVerifySLHDSABody paramKey, smFinal)

/-! ## BabyBear field codegen — Phase 4-J

Mirrors the TS reference dispatch at `05-stack-lower.ts` for the
`bbField{Add,Sub,Mul,Inv}` and `bbExt4{Mul,Inv}{0..3}` builtins. The
body op lists are precomputed in `Stack.BabyBear`. The dispatch arm
here follows the same pattern as `lowerEcBuiltinOpsLive`. -/

open RunarVerification.Stack.BabyBear in
/-- Lowering for a BabyBear builtin. Loads each arg to TOS, then splices
the appropriate static op list. Net stack-map effect: pop `args.length`,
push `bindingName`. -/
def lowerBabyBearBuiltinOpsLive (sm : StackMap) (bindingName : String)
    (func : String) (args : List String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let (argOps, sm1) := lowerArgsLive currentIndex lastUses outerProtected args sm args
  let body : List StackOp :=
    if func = "bbFieldAdd" then emitBBFieldAdd
    else if func = "bbFieldSub" then emitBBFieldSub
    else if func = "bbFieldMul" then emitBBFieldMul
    else if func = "bbFieldInv" then emitBBFieldInv
    else if func = "bbExt4Mul0" then emitBBExt4Mul0
    else if func = "bbExt4Mul1" then emitBBExt4Mul1
    else if func = "bbExt4Mul2" then emitBBExt4Mul2
    else if func = "bbExt4Mul3" then emitBBExt4Mul3
    else if func = "bbExt4Inv0" then emitBBExt4Inv0
    else if func = "bbExt4Inv1" then emitBBExt4Inv1
    else if func = "bbExt4Inv2" then emitBBExt4Inv2
    else if func = "bbExt4Inv3" then emitBBExt4Inv3
    else [.opcode "OP_RUNAR_UNKNOWN_BABYBEAR_BUILTIN"]
  let smFinal := (sm1.popN args.length).push bindingName
  (argOps ++ body, smFinal)

/-! ## Merkle proof codegen — Phase 4-K

Mirrors `lowerMerkleRoot` (TS `05-stack-lower.ts:4652-4706`) and its Go
peer at `compilers/go/codegen/stack.go:4870-4919`. Both variants
(`merkleRootSha256` and `merkleRootHash256`) take 4 args:
`[leaf, proof, index, depth]` where `depth` MUST be a compile-time
constant integer literal — it becomes the unrolled-loop bound for the
Merkle climb.

The TS / Go references implement this by:

1. Looking up `args[3]` in the per-method `constValues` map (populated
   while emitting `loadConst (.int _)` bindings).
2. Bringing the depth slot to top with `consume=true`, emitting `OP_DROP`,
   and popping the slot from the stack map (the depth literal is
   compile-time only — it does not flow into the body op list).
3. Bringing `[leaf, proof, index]` to top via the standard
   `bringToTop(_, isLastUse)` dance.
4. Splicing the precomputed body from `merkle-codegen.ts`.

This Lean port reuses `Stack.Merkle.merkleRootSha256Ops` /
`merkleRootHash256Ops` for the body. The depth comes from the new
`constInts` parameter threaded through `lowerValueP`. -/

open RunarVerification.Stack.Merkle in
/-- Lowering for `merkleRootSha256` / `merkleRootHash256`. Args:
`[leaf, proof, index, depth]`. Depth must be a compile-time int literal
recorded in `constInts`. After the body: 4 args popped, 1 result pushed. -/
def lowerMerkleRootOpsLive (sm : StackMap) (bindingName : String)
    (func : String) (args : List String)
    (constInts : List (String × Int))
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  match args with
  | [leaf, proof, index, depthArg] =>
      -- Resolve the depth literal. Out-of-range / missing constants emit
      -- a sentinel opcode (matching the existing `OP_RUNAR_*_ARITY`
      -- pattern); this is reachable only on malformed IR.
      match constIntsLookup constInts depthArg with
      | none =>
          ([.opcode "OP_RUNAR_MERKLE_DEPTH_NOT_CONST"], sm.push bindingName)
      | some di =>
          if di < 1 ∨ di > 64 then
            ([.opcode "OP_RUNAR_MERKLE_DEPTH_OUT_OF_RANGE"], sm.push bindingName)
          else
            let depth : Nat := di.toNat
            -- Step 1: drop the depth slot from runtime stack.
            -- `bringToTop(_, true)` emits ROLL/SWAP as appropriate; the
            -- subsequent OP_DROP consumes the brought-to-top slot.
            let (depthDropOps, smPostDepth) :=
              match sm.depth? depthArg with
              | some _ =>
                  let (toTop, sm1) := bringToTop sm depthArg true
                  (toTop ++ [StackOp.drop], sm1.popN 1)
              | none   => ([], sm)
            -- Step 2: bring leaf, proof, index to TOS via the standard
            -- liveness-aware load helper. Each call updates `sm` so the
            -- next bringToTop sees the prior arg sitting on top. The
            -- repeated-operand gate checks against the FULL 4-element
            -- arg list (TS `operandConsume(arg, args, …)` — `args`
            -- includes the compile-time `depth` ref).
            let (loadLeaf,  sm2) := loadRefOperand smPostDepth leaf  args currentIndex lastUses outerProtected
            let (loadProof, sm3) := loadRefOperand sm2        proof args currentIndex lastUses outerProtected
            let (loadIndex, sm4) := loadRefOperand sm3        index args currentIndex lastUses outerProtected
            -- Step 3: splice the precomputed body. Body net: pop 3, push 1.
            let body : List StackOp :=
              if func = "merkleRootSha256" then merkleRootSha256Ops depth
              else merkleRootHash256Ops depth
            let smFinal : StackMap := (sm4.popN 3).push bindingName
            (depthDropOps ++ loadLeaf ++ loadProof ++ loadIndex ++ body, smFinal)
  | _ =>
      ([.opcode "OP_RUNAR_MERKLEROOT_ARITY"], sm.push bindingName)

/-! ## checkMultiSig codegen

Mirrors `lowerCheckMultiSig` (TS `05-stack-lower.ts:1619-1663`). The TS
reference layout for `checkMultiSig([sig1,…], [pk1,…])`:

```
OP_0                       -- Bitcoin's CHECKMULTISIG dummy
<sig1> <sig2> … <sigN>     -- elements of the sigs array
<nSigs>                    -- pushed as an integer literal
<pk1> <pk2> … <pkM>        -- elements of the pubkeys array
<nPKs>                     -- pushed as an integer literal
OP_CHECKMULTISIG
```

`args[0]` / `args[1]` name `array_literal` bindings, which are NOT stack
slots (see `lowerValueP`'s `.arrayLiteral` arm): their element refs live
on the stack map under their own binding names. We pull each element to
TOS via `bringToTop` in the layout order above, exactly as TS does, with
the consume decision taken through `operandConsume` against the COMBINED
element list (TS `msigOperands = [...sigElems, ...pkElems]`) so a ref
repeated across the two arrays is copied at every position.

The three non-element pushes (dummy, nSigs, nPKs) occupy anonymous slots
— TS `stackMap.push(null)` — so no lookup can address them. -/

def lowerCheckMultiSigOpsLive (sm : StackMap) (bindingName : String)
    (sigElems pkElems : List String)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let msigOperands : List String := sigElems ++ pkElems
  -- Dummy `0` required by Bitcoin's OP_CHECKMULTISIG off-by-one bug.
  let dummy : List StackOp := [StackOp.push (.bigint 0)]
  let sm0 : StackMap := sm.pushAnon
  -- Bring each sig element to TOS in declaration order.
  let (loadSigs, sm1) :=
    lowerArgsLive currentIndex lastUses outerProtected msigOperands sm0 sigElems
  let nSigs : List StackOp := [StackOp.push (.bigint (Int.ofNat sigElems.length))]
  let sm2 : StackMap := sm1.pushAnon
  -- Bring each pubkey element to TOS in declaration order.
  let (loadPks, sm3) :=
    lowerArgsLive currentIndex lastUses outerProtected msigOperands sm2 pkElems
  let nPks : List StackOp := [StackOp.push (.bigint (Int.ofNat pkElems.length))]
  let sm4 : StackMap := sm3.pushAnon
  -- OP_CHECKMULTISIG consumes dummy + N sigs + nSigs + M pks + nPKs.
  let consumed : Nat := 1 + sigElems.length + 1 + pkElems.length + 1
  let smFinal : StackMap := (sm4.popN consumed).push bindingName
  (dummy ++ loadSigs ++ nSigs ++ loadPks ++ nPks
    ++ [StackOp.opcode "OP_CHECKMULTISIG"], smFinal)

/-! ## Mutual lowering

`lowerValue` and `lowerBindings` recurse via the `ifVal` and `loop`
cases (which descend into branch / body bindings). Termination is by
the auto-derived `sizeOf` on the ANFValue / List ANFBinding inputs:
every recursive call descends to a structurally-smaller payload.

Switching from `partial def` to `def` + `termination_by` unlocks the
`rfl`-level equation lemmas that downstream simulation lemmas depend
on. See HANDOFF.md §7c for the rationale.
-/

mutual

def lowerValue (sm : StackMap) (bindingName : String) :
    ANFValue → (List StackOp × StackMap)
  | .loadParam n =>
      (loadRef sm n, sm.push bindingName)
  | .loadProp n =>
      (loadRef sm n, sm.push bindingName)
  | .loadConst (.refAlias n) =>
      (loadRef sm n, sm.push bindingName)
  | .loadConst .thisRef =>
      ([], sm)
  | .loadConst c =>
      (emitConst c, sm.push bindingName)
  | .binOp op l r rt =>
      let base := loadRef sm l ++ loadRef (sm.push l) r ++ [.opcode (binopOpcode op rt)]
      let ops := if op == "!==" then base ++ [.opcode "OP_NOT"] else base
      (ops, sm.push bindingName)
  | .unaryOp op operand _ =>
      (loadRef sm operand ++ [.opcode (unaryOpcode op)], sm.push bindingName)
  | .call func args =>
      let (argOps, _) := lowerArgs sm args
      let opcodeOps := (builtinOpcode func).map (.opcode)
      (argOps ++ opcodeOps, sm.push bindingName)
  | .methodCall _obj _method _args =>
      -- The unparameterized `lowerValue` has no access to the program's
      -- method table, so it can't inline. Real lowering goes through
      -- `lowerValueP` (below) — see `lowerMethod` and `lower`. This
      -- placeholder is preserved only for Sim.lean's `rfl`-level rewrite
      -- lemmas covering the simple `Phase 3a` constructors.
      ([.opcode "OP_RUNAR_METHODCALL_NOPROG"], sm.push bindingName)
  | .ifVal cond thn els _ =>
      -- Phase 3c: concrete IF/ELSE/ENDIF lowering. Both branches lower
      -- independently against the *original* stack map (each branch is
      -- popped on entry and restored on exit by Bitcoin's IF semantics).
      let (thnOps, _) := lowerBindings sm thn
      let (elsOps, _) := lowerBindings sm els
      (loadRef sm cond ++ [.ifOp thnOps (some elsOps)], sm.push bindingName)
  | .assert ref =>
      (loadRef sm ref ++ [.opcode "OP_VERIFY"], sm)
  | .updateProp _ ref =>
      (loadRef sm ref ++ [.opcode "OP_RUNAR_UPDATEPROP_UNSUPPORTED"], sm)
  | .loop count body iterVar =>
      -- Phase 3d: full count-bounded unroll. The body is lowered once
      -- (with `iterVar` registered as a synthetic param at depth 0);
      -- `unrollIter` then iterates the body `count` times, each
      -- iteration prefixing with `push i` and suffixing with `OP_DROP`.
      --
      -- ⚠ NON-FAITHFUL / LEGACY (2026-06-11 loop-fidelity audit): this
      -- arm is NOT byte-faithful to the TS reference — it lowers the
      -- body once and replays it, drops unconditionally, ignores
      -- liveness, and pushes a phantom `bindingName` entry (loops are
      -- statements in TS). It is EXCLUDED from the production path:
      -- `lowerMethod` / `lower` / `compileSafe` go through
      -- `lowerBindingsP`, whose `.loop` arm performs faithful
      -- per-iteration re-lowering via `lowerLoopItersP`. This
      -- placeholder is preserved only because Sim.lean / Agrees*-era
      -- `rfl`-level lemmas reduce the unparameterized `lowerValue` on
      -- loop-FREE fragments and must keep their existing shape; no
      -- proof may rely on this arm's bytes for a loop-CONTAINING body.
      let (bodyOps, _) := lowerBindings (sm.push iterVar) body
      (unrollIter bodyOps count, sm.push bindingName)
  | .arrayLiteral elems =>
      (lowerArrayElems sm elems, sm.push bindingName)
  -- Phase 3w-b: framework intrinsics with concrete lowering.
  -- `addRawOutput` / `addDataOutput` share the same stack-IR shape (see
  -- `05-stack-lower.ts:961-965`); only the continuation-hash composition
  -- in ANF lowering distinguishes them.
  | .addRawOutput sat scr    => lowerAddRawOutputOps sm bindingName sat scr
  | .addDataOutput sat scr   => lowerAddRawOutputOps sm bindingName sat scr
  | .checkPreimage pre       => lowerCheckPreimageOps sm bindingName pre
  -- Out-of-scope: depend on the program's property table (which
  -- `lowerValue` doesn't have access to). Tracked as Phase 3y deferred.
  | .getStateScript          => ([.opcode "OP_RUNAR_GETSTATESCRIPT_UNSUPPORTED"], sm.push bindingName)
  | .deserializeState _      => ([.opcode "OP_RUNAR_DESERIALIZESTATE_UNSUPPORTED"], sm)
  | .addOutput _ _ _         => ([.opcode "OP_RUNAR_ADDOUTPUT_UNSUPPORTED"], sm)
  -- A14 follow-up: raw_script splices pre-encoded bytes verbatim. We
  -- model the stack effect as pushing the bytes themselves; downstream
  -- emitters output the bytes with no opcode prefix.
  | .rawScript bytes _ _     => ([.rawBytes bytes], sm.push bindingName)

def lowerBindings (sm : StackMap) :
    List ANFBinding → (List StackOp × StackMap)
  | [] => ([], sm)
  | (.mk name v _) :: rest =>
      let (ops, sm') := lowerValue sm name v
      let (ops', sm'') := lowerBindings sm' rest
      (ops ++ ops', sm'')

end

/-! ## Program-aware lowering (with `methodCall` inlining)

`lowerValueP` and `lowerBindingsP` mirror the unparameterized
`lowerValue` / `lowerBindings` above but additionally thread the
program's method table and an inlining budget so the `methodCall`
case can resolve and recursively lower the callee's body.

Termination uses lexicographic order on `(budget, sizeOf payload,
iterations)`: the `methodCall` recursion decrements `budget` (and may
grow the payload arbitrarily); every other recursion preserves `budget`
and descends to a structurally-smaller payload — except the
per-iteration loop fold `lowerLoopItersP`, which keeps the loop body
fixed (already structurally smaller than the `.loop` value that
entered it) and descends on the third component, its remaining
iteration count. Together this is well-founded and Lean's
`decreasing_by` can discharge it.
-/

/-! ### Liveness-aware program lowering (Phase 3x)

`lowerValueP` and `lowerBindingsP` thread last-use information so loads
of refs being read for the **last** time emit consume-style ops
(ROLL / SWAP / ROT) instead of copy-style ops (PICK / OVER / DUP).

Extra parameters compared to the unparameterized `lowerValue` /
`lowerBindings`:

* `currentIndex : Nat` — the binding's position within its enclosing
  sequence. `lowerBindingsP` increments it as it walks the list.
* `lastUses : List (String × Nat)` — assoc list keyed on ref name,
  computed once per binding sequence by `computeLastUses`.
* `outerProtected : List String` — names that pre-existed the
  current scope and therefore cannot be consumed (mirrors the TS
  `outerProtectedRefs` set at `05-stack-lower.ts:856-866`). At the
  top-level method body this is `[]`. When recursing into an `if`
  branch, a `loop` body, or a `methodCall` body, `outerProtected` is
  set to the parent scope's stack map at branch entry (a superset of
  the TS computation that achieves the same protection guarantee).

The `consume` flag for each ref is computed by `loadRefLive`:

  consume = (ref ∉ outerProtected) ∧ isLastUse(ref, currentIndex, lastUses)
-/

/-! ### `rawSlots` — slots holding a non-minimal numeric buffer (NEW-004)

Mirrors `LoweringContext.rawSlots`
(`packages/runar-compiler/src/passes/05-stack-lower.ts:595`).

`OP_LSHIFT` / `OP_RSHIFT` / `OP_AND` / `OP_OR` / `OP_XOR` / `OP_INVERT`
return a buffer as WIDE as their operand, so once the significant bits
leave that width the result is a buffer like `[0x00]` or `[0x80]` —
numerically zero, but NOT the minimal script-number encoding of zero
(the empty buffer). Every numeric-context opcode reads its operands
with `requireMinimal` and aborts, so a contract whose guard reads one
compiles, deploys, and can never be spent.

The repair is `OP_BIN2NUM`, applied at the point of USE (`bringToTop`)
and never at the producing opcode: a byte-array op consumes its
operands as raw bytes and requires them to match in WIDTH, so
re-minimising a result that feeds another byte-array op would silently
revert PR #141 — `(x<<8)|5` would start aborting on a length mismatch
and the provably unspendable `(x<<8)&0` would start reporting as
spendable. Only those consumers read raw; see `rawAllowedBinOpLeft` /
`rawAllowedBinOpRight` below.

TS scopes the set per `LoweringContext` (each `if` arm gets a copy and
the union is merged back at `05-stack-lower.ts:2521-2522`). We model it
as ONE flat, method-wide set, which is extensionally the same thing:
the TS set is ADD-ONLY (nothing is ever removed), ANF binding names are
unique within a method — the very property TS relies on when it calls a
carried-over arm-local name "inert" — and ANF defines every name before
it is used. So at any use site the flat set and the TS scope-at-that-
point contain the same names. -/

/-- TS `BYTE_ARRAY_BINOPS` (`05-stack-lower.ts:169`). -/
def isByteArrayBinOp (op : String) : Bool :=
  op == "&" || op == "|" || op == "^" || op == "<<" || op == ">>"

/-- TS `SHIFT_BINOPS` (`05-stack-lower.ts:170`). -/
def isShiftBinOp (op : String) : Bool :=
  op == "<<" || op == ">>"

/-- The LEFT operand of a byte-array binop is read as raw bytes
(`05-stack-lower.ts:1717`, `allowRaw = byteArrayOp`). -/
def rawAllowedBinOpLeft (op : String) : Bool := isByteArrayBinOp op

/-- The RIGHT operand is read as raw bytes for `& | ^` but NOT for the
shifts, whose right operand is the shift COUNT and is read as a number
(`05-stack-lower.ts:1710`, `rightIsRawOperand = byteArrayOp && !SHIFT`). -/
def rawAllowedBinOpRight (op : String) : Bool :=
  isByteArrayBinOp op && !isShiftBinOp op

/-- A binding whose value leaves a raw (possibly non-minimal) NUMERIC
buffer on the stack. A `bytes`-typed `& | ^ ~` is a ByteString
operation whose width is the whole point, so it is never raw
(`05-stack-lower.ts:1749`, `1804`). -/
@[simp] def rawResultValue : ANFValue → Bool
  | .binOp op _ _ rt   => isByteArrayBinOp op && rt != some "bytes"
  | .unaryOp op _ rt   => op == "~" && rt != some "bytes"
  | _                  => false

/-- The stack-map name a binding leaves on TOP, if it pushes one.
`assert` pushes nothing (it loads, `OP_VERIFY`s, and pops);
`updateProp` renames the top to the PROPERTY name; a declared-results
`if` adopts its result slots rather than its own binding name. Used to
mirror TS `adoptRawArmResult` (`05-stack-lower.ts:1764-1786`). -/
@[simp] def topSlotName (name : String) : ANFValue → Option String
  | .assert _             => none
  | .updateProp p _       => some p
  | .ifVal _ _ _ []       => some name
  | .ifVal _ _ _ results  => results.getLast?
  | _                     => some name

/-- The name an arm leaves on top of the stack: the last binding in the
arm that pushes a slot. -/
@[simp] def armTopName : List ANFBinding → Option String
  | []                  => none
  | (.mk n v _) :: rest =>
      match armTopName rest with
      | some t => some t
      | none   => topSlotName n v

/-- Forward fold building the method-wide raw-slot set. Order matters:
a `@ref` alias inherits the marker of its referent, which ANF always
binds earlier (`05-stack-lower.ts:1648-1650`) — an alias is pure data
movement, not a use, so normalising there would decide the encoding on
the aliased value's behalf before its real consumer is known. -/
@[simp] def collectRawSlotsGo (acc : List String) : List ANFBinding → List String
  | []                     => acc
  | (.mk name v _) :: rest =>
      let acc' : List String :=
        match v with
        | .loadConst (.refAlias r) =>
            if listContains acc r then name :: acc else acc
        | .ifVal _ thn els _ =>
            -- Each arm inherits the parent markers and the union is
            -- merged back — only one arm runs, so a slot the parent
            -- reads afterwards is raw if EITHER arm can leave a
            -- byte-array result in it.
            let accBoth := collectRawSlotsGo (collectRawSlotsGo acc thn) els
            -- TS `adoptRawArmResult`: a value-`if` is adopted under the
            -- `if`'s OWN binding name, so a raw marker on the arm's top
            -- slot would otherwise be dropped on the floor.
            let tops := [armTopName thn, armTopName els].filterMap id
            if tops.any (fun t => listContains accBoth t) then name :: accBoth
            else accBoth
        -- A zero-count loop is never lowered, so TS never marks anything
        -- in its body (`lowerLoop` adds markers from inside the iteration
        -- loop, which does not run). Iterations beyond the first re-lower
        -- the same body and re-add the same names, so one pass suffices.
        | .loop 0 _ _        => acc
        | .loop _ body _     => collectRawSlotsGo acc body
        | _ => if rawResultValue v then name :: acc else acc
      collectRawSlotsGo acc' rest

/-- Method-wide raw-slot set for `bs`. Built once at `lowerMethod` entry
and threaded through `lowerValueP` / `lowerBindingsP` like `constInts`. -/
@[simp] def collectRawSlots (bs : List ANFBinding) : List String :=
  collectRawSlotsGo [] bs

/-- Re-minimise a just-loaded slot when it holds a raw byte-array
result. Depth-neutral: one buffer in, one script number out. Mirrors
`bringToTop`'s `!allowRaw && this.rawSlots.has(name)` guard
(`05-stack-lower.ts:1091-1095`). Defaulting to normalisation makes the
safe choice the automatic one: a forgotten use site emits a redundant
`OP_BIN2NUM`, which costs one byte and cannot change a value, rather
than emitting an unspendable script. -/
def normalizeRaw (rawSlots : List String) (name : String)
    (ops : List StackOp) : List StackOp :=
  if listContains rawSlots name then ops ++ [.opcode "OP_BIN2NUM"] else ops

/-- The raw-slot set visible while lowering the binding named
`bindingName`, i.e. while its OPERANDS are being loaded.

TS adds a binding's own marker AFTER emitting its opcode
(`05-stack-lower.ts:1749`, `1804`, `bringToTop` having already run at
`1714`/`1718`/`1791`), so the marker a binding is about to add is not in
scope for its own operand reads. Our set is method-wide, so we drop it
explicitly.

For well-formed ANF this is byte-neutral — binding names are unique and
distinct from params, so `bindingName` is never one of its own operands
— but it keeps the flat set faithful to TS's scoped one even for a
binding that SHADOWS a name it reads (`x = x << 2`), where the operand
is the OLD `x` and carries no marker yet. -/
def rawSlotsInScope (rawSlots : List String) (bindingName : String) :
    List String :=
  rawSlots.filter (fun s => s != bindingName)

/-- With no raw slots there is nothing to bring into scope. -/
@[simp] theorem rawSlotsInScope_nil (bindingName : String) :
    rawSlotsInScope [] bindingName = [] := rfl

/-- A binding's own marker is exactly what `rawSlotsInScope` drops. -/
@[simp] theorem rawSlotsInScope_singleton_self (bindingName : String) :
    rawSlotsInScope [bindingName] bindingName = [] := by
  simp [rawSlotsInScope]

/-- A singleton value-`if` body marks nothing raw when neither arm does:
the arms are folded first, and the `adoptRawArmResult` carry-over can only
fire on a name the arms already marked. -/
theorem collectRawSlots_singleton_ifVal_of_arms
    (bn cond : String) (thn els : List ANFBinding) (results : List String)
    (src : Option SourceLoc)
    (hThn : collectRawSlotsGo [] thn = [])
    (hEls : collectRawSlotsGo [] els = []) :
    collectRawSlots [ANFBinding.mk bn (.ifVal cond thn els results) src] = [] := by
  simp only [collectRawSlots, collectRawSlotsGo, hThn, hEls, listContains,
             List.any_nil]
  -- Every candidate top is tested against the EMPTY set, so the adopt
  -- carry-over cannot fire whatever the arms leave on top.
  have hAny : ((List.filterMap id [armTopName thn, armTopName els]).any
      fun _ => false) = false := by
    cases armTopName thn <;> cases armTopName els <;> rfl
  rw [hAny]
  rfl

/-- A one-binding body contributes at most its OWN name to the raw set
(`collectRawSlotsGo` prepends `name` or nothing), and that name is out of
scope for that binding's own operands — so the whole gate collapses
whichever way the byte-array test goes. This is the shape the
single-binding lowering lemmas face once `collectRawSlots` is unfolded. -/
@[simp] theorem rawSlotsInScope_ite_singleton_self
    (c : Prop) [Decidable c] (bindingName : String) :
    rawSlotsInScope (if c then [bindingName] else []) bindingName = [] := by
  by_cases h : c <;> simp [h]

/-- With no raw slots in scope there is nothing to re-minimise, so the
lowering is exactly the pre-NEW-004 one. This is what lets every proof
stated at the `rawSlots := []` default keep reducing unchanged. -/
@[simp] theorem normalizeRaw_nil (name : String) (ops : List StackOp) :
    normalizeRaw [] name ops = ops := rfl

mutual

/-- Mirrors TS `LoweringContext.localBindings` (`05-stack-lower.ts:856-857`).
The set of binding names of the *currently-active* `lowerBindings`
invocation. TS sets this once at the top of `lowerBindings` and does NOT
restore it after `inlineMethodCall` returns — so once a methodCall has
been inlined, all subsequent `.refAlias` loads in the OUTER body see
the INNER body's names as `localBindings` and therefore decline to
consume their referent (since outer-scope refs aren't in the stale
inner set). This quirk is load-bearing for byte-exact match in
fixtures with `methodCall` followed by `@ref:` rebinds (e.g.
`function-patterns` `withdraw`, where `fee = @ref:t15` and
`total = @ref:t17` BOTH emit `OP_DUP` instead of consuming).

`lowerValueP` returns the (possibly updated) `localBindings` as part of
its tuple so `lowerBindingsP` can thread it through subsequent
bindings. The methodCall arm overwrites it with the inlined body's
names; every other arm returns it unchanged. -/
def lowerValueP (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName : String) (value : ANFValue)
    (rawSlots : List String := []) (insideBranch : Bool := false)
    (arrayElems : List (String × List String) := []) :
    (List StackOp × StackMap × List String) :=
  match value with
  | .loadParam n =>
      -- Phase 7.1: thread outerProtected so params used in sibling
      -- inner scopes (e.g. both branches of separate ifs) aren't
      -- consumed prematurely inside one branch.
      let (load, sm1) := loadRefLiveParam sm n currentIndex lastUses outerProtected
      let sm2 := match sm1 with
                 | _ :: rest => bindingName :: rest
                 | []        => [bindingName]
      (load, sm2, localBindings)
  | .loadProp n =>
      -- Mirrors TS `lowerLoadProp` (05-stack-lower.ts:1004-1029):
      --   * If the prop is on the stack (post-update_prop), ALWAYS copy
      --     to top — props are shared mutable state, never consumed.
      --   * Else if the prop has an initialValue, push the constant.
      --   * Else emit a `.placeholder` op (encoded as OP_0; deployment SDK
      --     splices in the actual constructor arg byte sequence).
      match sm.depth? n with
      | some _ =>
          let (load, sm1) := loadRefLiveCopy sm n
          let sm2 := match sm1 with
                     | _ :: rest => bindingName :: rest
                     | []        => [bindingName]
          -- A property slot can be raw: a shadow rebind `count = @ref:tN`
          -- carries the marker onto the property name.
          (normalizeRaw (rawSlotsInScope rawSlots bindingName) n load, sm2, localBindings)
      | none =>
          match props.find? (·.name = n) with
          | some prop =>
              match prop.initialValue with
              | some iv => (emitConst iv, sm.push bindingName, localBindings)
              | none =>
                  let ctorProps := props.filter (·.initialValue.isNone)
                  let paramIndex := ctorProps.findIdx? (·.name = n) |>.getD 0
                  ([.placeholder paramIndex n], sm.push bindingName, localBindings)
          | none =>
              ([.placeholder 0 n], sm.push bindingName, localBindings)
  | .loadConst (.refAlias n) =>
      -- Mirror TS `lowerLoadConst @ref:` (`05-stack-lower.ts:1039-1057`):
      --   const consume = this.localBindings.has(refName)
      --                && this.isLastUse(refName, bindingIndex, lastUses);
      -- We thread `localBindings` to capture TS's quirk where it remains
      -- stale (= inlined-body names) after a `methodCall` returns. Without
      -- the localBindings gate the `function-patterns` `withdraw` body's
      -- `fee = @ref:t15` and `total = @ref:t17` rebinds would consume
      -- their referent (no DUP) and the byte sequence drifts.
      let onStack : Bool :=
        match sm.depth? n with
        | some _ => true
        | none   => false
      if onStack then
        let consume :=
          listContains localBindings n
          && !listContains outerProtected n
          && isLastUse lastUses n currentIndex
        let (load, sm1) := bringToTop sm n consume
        let sm2 := match sm1 with
                   | _ :: rest => bindingName :: rest
                   | []        => [bindingName]
        (load, sm2, localBindings)
      else
        -- Mirror TS line 1052-1054: ref target not on stack → push 0n.
        ([.push (.bigint 0)], sm.push bindingName, localBindings)
  | .loadConst .thisRef =>
      -- Mirror TS `lowerLoadConst @this` (`05-stack-lower.ts:1059-1064`):
      -- emit `push 0n` and bind the binding name on top so downstream
      -- loadRef calls resolve. (Closes Gap 4.)
      ([.push (.bigint 0)], sm.push bindingName, localBindings)
  | .loadConst c =>
      (emitConst c, sm.push bindingName, localBindings)
  | .binOp op l r rt =>
      -- Repeated-operand gate (PRs #62/#67/#68): a ref reading BOTH
      -- operand positions (`t := x + x`) is COPIED at every position;
      -- consume only when the ref occurs exactly once in `[l, r]`.
      let (lOps₀, sm1) := loadRefOperand sm l [l, r] currentIndex lastUses outerProtected
      let (rOps₀, sm2) := loadRefOperand sm1 r [l, r] currentIndex lastUses outerProtected
      -- NEW-004: re-minimise a raw operand unless THIS op reads it as raw
      -- bytes. `& | ^` read both operands raw; `<< >>` read the LEFT
      -- operand raw but the right one is the shift COUNT, read as a number.
      let lOps := if rawAllowedBinOpLeft op then lOps₀
                  else normalizeRaw (rawSlotsInScope rawSlots bindingName) l lOps₀
      let rOps := if rawAllowedBinOpRight op then rOps₀
                  else normalizeRaw (rawSlotsInScope rawSlots bindingName) r rOps₀
      let base := lOps ++ rOps ++ [.opcode (binopOpcode op rt)]
      let ops := if op == "!==" then base ++ [.opcode "OP_NOT"] else base
      -- Binop pops 2, pushes 1 (the named result).
      let sm3 := (sm2.popN 2).push bindingName
      (ops, sm3, localBindings)
  | .unaryOp op operand _ =>
      let (load₀, sm1) := loadRefLive sm operand currentIndex lastUses outerProtected
      -- `OP_INVERT` flips its operand's bytes in place — same raw-in /
      -- raw-out contract as the binary byte-array opcodes.
      let load := if op == "~" then load₀
                  else normalizeRaw (rawSlotsInScope rawSlots bindingName) operand load₀
      let ops := load ++ [.opcode (unaryOpcode op)]
      let sm2 := (sm1.popN 1).push bindingName
      (ops, sm2, localBindings)
  | .call func args =>
      let withLB (p : List StackOp × StackMap) : List StackOp × StackMap × List String :=
        (p.1, p.2, localBindings)
      if isExtractor func then
        -- Preimage-field extractor: bring single arg (preimage) to top via
        -- liveness-aware load, then emit the fixed split sequence. Net
        -- stack-map effect: pop arg, push bindingName.
        match args with
        | [preimage] =>
            let (argOps, sm1) :=
              loadRefLive sm preimage currentIndex lastUses outerProtected
            let body := extractorBody func
            let sm2 := (sm1.popN 1).push bindingName
            (argOps ++ body, sm2, localBindings)
        | _ =>
            -- Malformed extractor (wrong arity) — fall back to builtin path.
            let (argOps, sm1) :=
              lowerArgsLive currentIndex lastUses outerProtected args sm args
            let opcodeOps := (builtinOpcode func).map (.opcode)
            let sm2 := (sm1.popN args.length).push bindingName
            (argOps ++ opcodeOps, sm2, localBindings)
      else if func = "buildChangeOutput" then
        -- Phase 3z-E: dedicated multi-op lowering (mirrors TS
        -- `lowerBuildChangeOutput` at `05-stack-lower.ts:2306-2360`).
        match args with
        | [pkh, amount] =>
            withLB <| lowerBuildChangeOutputOps sm bindingName pkh amount
              currentIndex lastUses outerProtected
        | _ =>
            ([.opcode "OP_RUNAR_BUILDCHANGEOUTPUT_ARITY"], sm.push bindingName, localBindings)
      else if func = "computeStateOutput" then
        -- Phase 3z-E: dedicated lowering (mirrors TS
        -- `lowerComputeStateOutput` at `05-stack-lower.ts:2220-2303`).
        match args with
        | [preimage, stateBytes, newAmount] =>
            withLB <| lowerComputeStateOutputOps sm bindingName preimage stateBytes newAmount
              currentIndex lastUses outerProtected
        | _ =>
            ([.opcode "OP_RUNAR_COMPUTESTATEOUTPUT_ARITY"], sm.push bindingName, localBindings)
      else if func = "computeStateOutputHash" then
        -- Phase 3z-E: dedicated lowering (mirrors TS
        -- `lowerComputeStateOutputHash` at `05-stack-lower.ts:2106-2213`).
        match args with
        | [preimage, stateBytes] =>
            withLB <| lowerComputeStateOutputHashOps sm bindingName preimage stateBytes
              currentIndex lastUses outerProtected
        | _ =>
            ([.opcode "OP_RUNAR_COMPUTESTATEOUTPUTHASH_ARITY"], sm.push bindingName, localBindings)
      else if func = "substr" then
        -- Phase 3z-H: dedicated lowering mirroring TS `lowerSubstr`
        -- (`05-stack-lower.ts:4703-4756`). The TS reference INTERLEAVES
        -- the load of the third arg (`length`) between the two SPLITs.
        -- The simple "preload then opcodes" path would put `length` on
        -- top before the first SPLIT — corrupting the byte sequence.
        match args with
        | [data, start, length] =>
            let (loadData, sm1) := loadRefOperand sm data [data, start, length] currentIndex lastUses outerProtected
            let (loadStart, sm2) := loadRefOperand sm1 start [data, start, length] currentIndex lastUses outerProtected
            -- After SPLIT NIP we've popped (data, start) and pushed `right`.
            let smAfterFirst : StackMap := (sm2.popN 2).push "_substr_right"
            let (loadLen, sm3) :=
              loadRefOperand smAfterFirst length [data, start, length] currentIndex lastUses outerProtected
            -- After SPLIT DROP we've popped (right, length) and pushed
            -- the substr result under `bindingName`.
            let smFinal : StackMap := (sm3.popN 2).push bindingName
            ( loadData ++ loadStart
                ++ [StackOp.opcode "OP_SPLIT", StackOp.nip]
                ++ loadLen
                ++ [StackOp.opcode "OP_SPLIT", StackOp.drop]
            , smFinal, localBindings )
        | _ =>
            ([.opcode "OP_RUNAR_SUBSTR_ARITY"], sm.push bindingName, localBindings)
      else if func = "percentOf" then
        -- TS `lowerPercentOf` (`05-stack-lower.ts:3520-3552`): emit
        -- `<amount> <bps> OP_MUL <push 10000> OP_DIV`. Net stack effect:
        -- pop 2 args, push 1 result.
        match args with
        | [amount, bps] =>
            let (loadA, sm1) := loadRefOperand sm amount [amount, bps] currentIndex lastUses outerProtected
            let (loadB, sm2) := loadRefOperand sm1 bps [amount, bps] currentIndex lastUses outerProtected
            let smFinal : StackMap := (sm2.popN 2).push bindingName
            (loadA ++ loadB ++
              [StackOp.opcode "OP_MUL",
               StackOp.push (.bigint 10000),
               StackOp.opcode "OP_DIV"],
             smFinal, localBindings)
        | _ =>
            ([.opcode "OP_RUNAR_PERCENTOF_ARITY"], sm.push bindingName, localBindings)
      else if func = "mulDiv" then
        -- TS `lowerMulDiv` (`05-stack-lower.ts:3490-3518`): emit
        -- `<a> <b> OP_MUL <c> OP_DIV` with the third arg loaded AFTER the
        -- multiply. The interleaved load matters because OP_MUL pops both
        -- before `c` is pushed.
        match args with
        | [a, b, c] =>
            let (loadA, sm1) := loadRefOperand sm a [a, b, c] currentIndex lastUses outerProtected
            let (loadB, sm2) := loadRefOperand sm1 b [a, b, c] currentIndex lastUses outerProtected
            let smPostMul : StackMap := (sm2.popN 2).push "_mulDiv_intermediate"
            let (loadC, sm3) :=
              loadRefOperand smPostMul c [a, b, c] currentIndex lastUses outerProtected
            let smFinal : StackMap := (sm3.popN 2).push bindingName
            (loadA ++ loadB
              ++ [StackOp.opcode "OP_MUL"]
              ++ loadC
              ++ [StackOp.opcode "OP_DIV"],
             smFinal, localBindings)
        | _ =>
            ([.opcode "OP_RUNAR_MULDIV_ARITY"], sm.push bindingName, localBindings)
      else if func = "safediv" || func = "safemod" then
        -- TS `lowerSafeDivMod` (`05-stack-lower.ts:3328-3363`): emit
        -- `<a> <b> OP_DUP OP_0NOTEQUAL OP_VERIFY <DIV|MOD>` to abort if
        -- `b == 0` before the division/mod.
        match args with
        | [a, b] =>
            let (loadA, sm1) := loadRefOperand sm a [a, b] currentIndex lastUses outerProtected
            let (loadB, sm2) := loadRefOperand sm1 b [a, b] currentIndex lastUses outerProtected
            let opc := if func = "safediv" then "OP_DIV" else "OP_MOD"
            let smFinal : StackMap := (sm2.popN 2).push bindingName
            (loadA ++ loadB ++
              [StackOp.opcode "OP_DUP",
               StackOp.opcode "OP_0NOTEQUAL",
               StackOp.opcode "OP_VERIFY",
               StackOp.opcode opc],
             smFinal, localBindings)
        | _ =>
            ([.opcode "OP_RUNAR_SAFEDIVMOD_ARITY"], sm.push bindingName, localBindings)
      else if func = "clamp" then
        -- TS `lowerClamp` (`05-stack-lower.ts:3369-3400`): emit
        -- `<val> <lo> OP_MAX <hi> OP_MIN`. Interleaves the third load
        -- between the two opcode emissions.
        match args with
        | [val, lo, hi] =>
            let (loadV, sm1) := loadRefOperand sm val [val, lo, hi] currentIndex lastUses outerProtected
            let (loadL, sm2) := loadRefOperand sm1 lo [val, lo, hi] currentIndex lastUses outerProtected
            let smPostMax : StackMap := (sm2.popN 2).push "_clamp_intermediate"
            let (loadH, sm3) :=
              loadRefOperand smPostMax hi [val, lo, hi] currentIndex lastUses outerProtected
            let smFinal : StackMap := (sm3.popN 2).push bindingName
            (loadV ++ loadL
              ++ [StackOp.opcode "OP_MAX"]
              ++ loadH
              ++ [StackOp.opcode "OP_MIN"],
             smFinal, localBindings)
        | _ =>
            ([.opcode "OP_RUNAR_CLAMP_ARITY"], sm.push bindingName, localBindings)
      else if func = "pow" then
        -- TS `lowerPow` (`05-stack-lower.ts:3407-3483`): bounded
        -- 32-iteration multiply. The loop body is a flat opcode sequence
        -- (no structured if-blocks at the StackMap level — each iteration
        -- emits a `StackOp.ifOp` whose body multiplies into the accumulator).
        --
        --   <base> <exp>
        --   OP_SWAP OP_1                       -- exp base 1
        --   for i in 0..32:                    -- exp base acc
        --     <2> OP_PICK                       -- exp base acc exp
        --     <i> OP_GREATERTHAN                -- exp base acc (exp > i)
        --     OP_IF OP_OVER OP_MUL OP_ENDIF     -- exp base acc'
        --   OP_NIP OP_NIP                       -- result
        match args with
        | [base, exp] =>
            let (loadB, sm1) := loadRefOperand sm base [base, exp] currentIndex lastUses outerProtected
            let (loadE, sm2) := loadRefOperand sm1 exp [base, exp] currentIndex lastUses outerProtected
            let smFinal : StackMap := (sm2.popN 2).push bindingName
            let header : List StackOp :=
              [StackOp.swap, StackOp.push (.bigint 1)]
            let iter (i : Nat) : List StackOp :=
              [ StackOp.push (.bigint 2)
              , StackOp.opcode "OP_PICK"
              , StackOp.push (.bigint (Int.ofNat i))
              , StackOp.opcode "OP_GREATERTHAN"
              , StackOp.ifOp [StackOp.over, StackOp.opcode "OP_MUL"] none ]
            let body : List StackOp :=
              (List.range 32).flatMap iter
            let trailer : List StackOp := [StackOp.nip, StackOp.nip]
            (loadB ++ loadE ++ header ++ body ++ trailer, smFinal, localBindings)
        | _ =>
            ([.opcode "OP_RUNAR_POW_ARITY"], sm.push bindingName, localBindings)
      else if func = "sqrt" then
        -- TS `lowerSqrt` (`05-stack-lower.ts:3564-3610`): integer square
        -- root via Newton's method, guarded by `OP_DUP OP_IF ... OP_ENDIF`
        -- so that `n == 0` skips the iteration (avoids div-by-zero) and
        -- the original 0 remains on the stack.
        --
        --   <n> OP_DUP
        --   OP_IF
        --     OP_DUP                           -- n guess(=n)
        --     16x: OP_OVER OP_OVER OP_DIV OP_ADD <2> OP_DIV
        --     OP_NIP                           -- result
        --   OP_ENDIF
        match args with
        | [n] =>
            let (loadN, sm1) := loadRefLive sm n currentIndex lastUses outerProtected
            let smFinal : StackMap := (sm1.popN 1).push bindingName
            let iter : List StackOp :=
              [ StackOp.over, StackOp.over
              , StackOp.opcode "OP_DIV"
              , StackOp.opcode "OP_ADD"
              , StackOp.push (.bigint 2)
              , StackOp.opcode "OP_DIV" ]
            let newtonOps : List StackOp :=
              StackOp.opcode "OP_DUP"
                :: ((List.range 16).flatMap (fun _ => iter)) ++ [StackOp.nip]
            let body : List StackOp :=
              [ StackOp.opcode "OP_DUP"
              , StackOp.ifOp newtonOps none ]
            (loadN ++ body, smFinal, localBindings)
        | _ =>
            ([.opcode "OP_RUNAR_SQRT_ARITY"], sm.push bindingName, localBindings)
      else if func = "gcd" then
        -- TS `lowerGcd` (`05-stack-lower.ts:3617-3663`): bounded
        -- Euclidean algorithm with 256 unrolled iterations.
        --
        --   <a> <b>
        --   OP_ABS OP_SWAP OP_ABS OP_SWAP            -- |a| |b|
        --   for _ in 0..256:                          -- a b
        --     OP_DUP OP_0NOTEQUAL
        --     OP_IF OP_TUCK OP_MOD OP_ENDIF
        --   OP_DROP                                   -- result
        match args with
        | [a, b] =>
            let (loadA, sm1) := loadRefOperand sm a [a, b] currentIndex lastUses outerProtected
            let (loadB, sm2) := loadRefOperand sm1 b [a, b] currentIndex lastUses outerProtected
            let smFinal : StackMap := (sm2.popN 2).push bindingName
            let header : List StackOp :=
              [ StackOp.opcode "OP_ABS"
              , StackOp.swap
              , StackOp.opcode "OP_ABS"
              , StackOp.swap ]
            let iter : List StackOp :=
              [ StackOp.opcode "OP_DUP"
              , StackOp.opcode "OP_0NOTEQUAL"
              , StackOp.ifOp
                  [ StackOp.opcode "OP_TUCK", StackOp.opcode "OP_MOD" ]
                  none ]
            let body : List StackOp :=
              (List.range 256).flatMap (fun _ => iter)
            let trailer : List StackOp := [StackOp.drop]
            (loadA ++ loadB ++ header ++ body ++ trailer, smFinal, localBindings)
        | _ =>
            ([.opcode "OP_RUNAR_GCD_ARITY"], sm.push bindingName, localBindings)
      else if func = "log2" then
        -- TS `lowerLog2` (`05-stack-lower.ts:3721-3767`): floor(log2(n))
        -- via 64-iteration bit-scan. Each iteration shifts the input right
        -- and increments the counter when input > 1.
        --
        --   <n> <0>                                   -- input counter
        --   for _ in 0..64:
        --     OP_SWAP OP_DUP <1> OP_GREATERTHAN
        --     OP_IF <2> OP_DIV OP_SWAP OP_1ADD OP_SWAP OP_ENDIF
        --     OP_SWAP                                 -- input counter
        --   OP_NIP                                    -- counter
        match args with
        | [n] =>
            let (loadN, sm1) := loadRefLive sm n currentIndex lastUses outerProtected
            let smFinal : StackMap := (sm1.popN 1).push bindingName
            let iter : List StackOp :=
              [ StackOp.swap
              , StackOp.opcode "OP_DUP"
              , StackOp.push (.bigint 1)
              , StackOp.opcode "OP_GREATERTHAN"
              , StackOp.ifOp
                  [ StackOp.push (.bigint 2)
                  , StackOp.opcode "OP_DIV"
                  , StackOp.swap
                  , StackOp.opcode "OP_1ADD"
                  , StackOp.swap ]
                  none
              , StackOp.swap ]
            let body : List StackOp :=
              StackOp.push (.bigint 0)
                :: ((List.range 64).flatMap (fun _ => iter)) ++ [StackOp.nip]
            (loadN ++ body, smFinal, localBindings)
        | _ =>
            ([.opcode "OP_RUNAR_LOG2_ARITY"], sm.push bindingName, localBindings)
      else if func = "sign" then
        -- TS `lowerSign` (`05-stack-lower.ts:3779-3812`): -1 / 0 / 1
        -- dispatch using OP_DUP + OP_IF guard so that `x == 0` short-circuits
        -- the division.
        --
        --   <x> OP_DUP
        --   OP_IF OP_DUP OP_ABS OP_SWAP OP_DIV OP_ENDIF
        match args with
        | [x] =>
            let (loadX, sm1) := loadRefLive sm x currentIndex lastUses outerProtected
            let smFinal : StackMap := (sm1.popN 1).push bindingName
            let body : List StackOp :=
              [ StackOp.opcode "OP_DUP"
              , StackOp.ifOp
                  [ StackOp.opcode "OP_DUP"
                  , StackOp.opcode "OP_ABS"
                  , StackOp.swap
                  , StackOp.opcode "OP_DIV" ]
                  none ]
            (loadX ++ body, smFinal, localBindings)
        | _ =>
            ([.opcode "OP_RUNAR_SIGN_ARITY"], sm.push bindingName, localBindings)
      else if func = "divmod" then
        -- TS `lowerDivmod` (`05-stack-lower.ts:3792-3824`): emit
        -- `OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD OP_DROP` and keep only
        -- the quotient on the stack (the remainder is dropped). Net
        -- stack effect: pop 2, push 1.
        match args with
        | [a, b] =>
            let (loadA, sm1) := loadRefOperand sm a [a, b] currentIndex lastUses outerProtected
            let (loadB, sm2) := loadRefOperand sm1 b [a, b] currentIndex lastUses outerProtected
            let smFinal : StackMap := (sm2.popN 2).push bindingName
            (loadA ++ loadB ++
              [StackOp.opcode "OP_2DUP",
               StackOp.opcode "OP_DIV",
               StackOp.opcode "OP_ROT",
               StackOp.opcode "OP_ROT",
               StackOp.opcode "OP_MOD",
               StackOp.drop],
             smFinal, localBindings)
        | _ =>
            ([.opcode "OP_RUNAR_DIVMOD_ARITY"], sm.push bindingName, localBindings)
      else if func = "verifyRabinSig" then
        -- Phase 3z-K: dedicated lowering (mirrors TS `lowerVerifyRabinSig`
        -- at `05-stack-lower.ts:3884-3931`). Verifies the Rabin equation
        -- `(sig^2 + padding) mod pubKey == SHA256(msg)`.
        match args with
        | [msg, sig, padding, pubKey] =>
            withLB <|
              lowerVerifyRabinSigOpsLive sm bindingName msg sig padding pubKey
                currentIndex lastUses outerProtected
        | _ =>
            ([.opcode "OP_RUNAR_VERIFYRABINSIG_ARITY"], sm.push bindingName, localBindings)
      else if func = "sha256Compress" then
        -- Phase 4-D: dedicated lowering (mirrors TS `emitSha256Compress`
        -- at `sha256-codegen.ts:217-219`).
        match args with
        | [state, block] =>
            withLB <|
              lowerSha256CompressOpsLive sm bindingName state block
                currentIndex lastUses outerProtected
        | _ =>
            ([.opcode "OP_RUNAR_SHA256COMPRESS_ARITY"], sm.push bindingName, localBindings)
      else if func = "sha256Finalize" then
        -- Phase 4-D: dedicated lowering (mirrors TS `emitSha256Finalize`
        -- at `sha256-codegen.ts:229-311`).
        match args with
        | [state, remaining, msgBitLen] =>
            withLB <|
              lowerSha256FinalizeOpsLive sm bindingName state remaining msgBitLen
                currentIndex lastUses outerProtected
        | _ =>
            ([.opcode "OP_RUNAR_SHA256FINALIZE_ARITY"], sm.push bindingName, localBindings)
      else if func = "blake3Compress" then
        -- Phase 4-E: dedicated lowering (mirrors TS `emitBlake3Compress`
        -- at `blake3-codegen.ts:406-408`).
        match args with
        | [chainingValue, block] =>
            withLB <|
              lowerBlake3CompressOpsLive sm bindingName chainingValue block
                currentIndex lastUses outerProtected
        | _ =>
            ([.opcode "OP_RUNAR_BLAKE3COMPRESS_ARITY"], sm.push bindingName, localBindings)
      else if func = "blake3Hash" then
        -- Phase 4-E: dedicated lowering (mirrors TS `emitBlake3Hash`
        -- at `blake3-codegen.ts:418-447`).
        match args with
        | [message] =>
            withLB <|
              lowerBlake3HashOpsLive sm bindingName message
                currentIndex lastUses outerProtected
        | _ =>
            ([.opcode "OP_RUNAR_BLAKE3HASH_ARITY"], sm.push bindingName, localBindings)
      else if func = "verifyWOTS" then
        -- Phase 4-F: dedicated lowering (mirrors TS `lowerVerifyWOTS`
        -- at `05-stack-lower.ts:4022-4175`).
        match args with
        | [msg, sig, pubkey] =>
            withLB <|
              lowerVerifyWotsOpsLive sm bindingName msg sig pubkey
                currentIndex lastUses outerProtected
        | _ =>
            ([.opcode "OP_RUNAR_VERIFYWOTS_ARITY"], sm.push bindingName, localBindings)
      else if func = "ecAdd" || func = "ecMul" || func = "ecMulGen" ||
              func = "ecNegate" || func = "ecOnCurve" || func = "ecModReduce" ||
              func = "ecEncodeCompressed" || func = "ecMakePoint" ||
              func = "ecPointX" || func = "ecPointY" then
        -- Phase 4-G: secp256k1 EC builtins (mirrors TS `lowerEcBuiltin`
        -- at `05-stack-lower.ts:4294-4325`).
        withLB <|
          lowerEcBuiltinOpsLive sm bindingName func args
            currentIndex lastUses outerProtected
      else if func = "p256Add" || func = "p256Mul" || func = "p256MulGen" ||
              func = "p256Negate" || func = "p256OnCurve" ||
              func = "p256EncodeCompressed" || func = "verifyECDSA_P256" ||
              func = "p384Add" || func = "p384Mul" || func = "p384MulGen" ||
              func = "p384Negate" || func = "p384OnCurve" ||
              func = "p384EncodeCompressed" || func = "verifyECDSA_P384" then
        -- Phase 4-H: NIST P-256 / P-384 EC builtins (mirrors TS
        -- `lowerNistEcBuiltin` / `lowerVerifyECDSA`
        -- at `05-stack-lower.ts:4386-4441`).
        withLB <|
          lowerP256P384BuiltinOpsLive sm bindingName func args
            currentIndex lastUses outerProtected
      else if func = "verifySLHDSA_SHA2_128s" || func = "verifySLHDSA_SHA2_128f" ||
              func = "verifySLHDSA_SHA2_192s" || func = "verifySLHDSA_SHA2_192f" ||
              func = "verifySLHDSA_SHA2_256s" || func = "verifySLHDSA_SHA2_256f" then
        -- Phase 4-I: SLH-DSA (FIPS 205) verify (mirrors TS
        -- `slh-dsa-codegen.ts:emitVerifySLHDSA`).
        match args with
        | [msg, sig, pubkey] =>
            let paramKey : String := (func.drop "verifySLHDSA_".length).toString
            withLB <|
              lowerVerifySlhDsaOpsLive sm bindingName paramKey msg sig pubkey
                currentIndex lastUses outerProtected
        | _ =>
            ([.opcode "OP_RUNAR_VERIFYSLHDSA_ARITY"], sm.push bindingName, localBindings)
      else if func = "bbFieldAdd" || func = "bbFieldSub" ||
              func = "bbFieldMul" || func = "bbFieldInv" ||
              func = "bbExt4Mul0" || func = "bbExt4Mul1" ||
              func = "bbExt4Mul2" || func = "bbExt4Mul3" ||
              func = "bbExt4Inv0" || func = "bbExt4Inv1" ||
              func = "bbExt4Inv2" || func = "bbExt4Inv3" then
        -- Phase 4-J: BabyBear prime-field + ext4 builtins (mirrors TS
        -- `babybear-codegen.ts`).
        withLB <|
          lowerBabyBearBuiltinOpsLive sm bindingName func args
            currentIndex lastUses outerProtected
      else if func = "merkleRootSha256" || func = "merkleRootHash256" then
        -- Phase 4-K: Merkle proof verification (mirrors TS
        -- `lowerMerkleRoot` at `05-stack-lower.ts:4652-4706` and Go
        -- peer at `compilers/go/codegen/stack.go:4870-4919`). The
        -- `depth` argument is a compile-time constant resolved via the
        -- `constInts` map.
        withLB <|
          lowerMerkleRootOpsLive sm bindingName func args constInts
            currentIndex lastUses outerProtected
      else if func = "checkMultiSig" then
        -- Multisig: dedicated dispatch mirroring TS `lowerCheckMultiSig`
        -- (`05-stack-lower.ts:1619-1663`). Args: `[sigsArrayRef,
        -- pubkeysArrayRef]` — each names an `array_literal` binding, so the
        -- ELEMENT refs come from the method-wide `arrayElems` table rather
        -- than from the stack map (the array binding itself has no slot).
        match args with
        | [sigsRef, pubkeysRef] =>
            match arrayElemsLookup arrayElems sigsRef,
                  arrayElemsLookup arrayElems pubkeysRef with
            | some sigElems, some pkElems =>
                withLB <|
                  lowerCheckMultiSigOpsLive sm bindingName sigElems pkElems
                    currentIndex lastUses outerProtected
            | _, _ =>
                -- TS throws `checkMultiSig: array_literal metadata missing`
                -- here; the model's equivalent is a marker opcode no emitter
                -- can encode, so the shape cannot pass silently.
                ([.opcode "OP_RUNAR_CHECKMULTISIG_NO_ARRAY_METADATA"],
                 sm.push bindingName, localBindings)
        | _ =>
            ([.opcode "OP_RUNAR_CHECKMULTISIG_ARITY"], sm.push bindingName, localBindings)
      else
        let (argOps, sm1) := lowerArgsLive currentIndex lastUses outerProtected args sm args
        let opcodeOps := (builtinOpcode func).map (.opcode)
        -- Most builtins are pop-N push-1; we approximate with that shape.
        let sm2 := (sm1.popN args.length).push bindingName
        (argOps ++ opcodeOps, sm2, localBindings)
  | .methodCall obj method args =>
      match budget with
      | 0 =>
          ([.opcode "OP_RUNAR_METHODCALL_BUDGET_EXHAUSTED"], sm.push bindingName, localBindings)
      | budget' + 1 =>
          match lookupMethod progMethods method with
          | none =>
              -- Unresolved method — fall back to a builtin-style call.
              let (argOps, sm1) := lowerArgsLive currentIndex lastUses outerProtected args sm args
              let opcodeOps := (builtinOpcode method).map (.opcode)
              let sm2 := (sm1.popN args.length).push bindingName
              (argOps ++ opcodeOps, sm2, localBindings)
          | some m =>
              -- Mirror TS `lowerMethodCall` (`05-stack-lower.ts:1574-1585`):
              -- when the object reference (e.g. `@this` placeholder) is on
              -- the stack, bring it to top consuming, emit OP_DROP, and pop
              -- the slot. This sheds the compile-time `@this` push before
              -- inlining the callee body.
              let (objDropOps, smPostObj) : (List StackOp × StackMap) :=
                match sm.depth? obj with
                | some _ =>
                    let (toTop, sm1) := bringToTop sm obj true
                    (toTop ++ [StackOp.drop], sm1.popN 1)
                | none   => ([], sm)
              let paramNames := m.params.map (·.name)
              let (argLoads, smArgs) :=
                loadAndBindArgsLive currentIndex lastUses outerProtected args smPostObj args paramNames
              -- TS `inlineMethodCall` (`05-stack-lower.ts:1591-1644`) reuses
              -- the SAME `LoweringContext` (and thus the same
              -- `outerProtectedRefs`) when it calls `lowerBindings` on the
              -- callee body. We mirror that by propagating the OUTER scope's
              -- `outerProtected` rather than the post-arg-binding stackmap
              -- snapshot. Snapshotting the local stack would falsely protect
              -- inner-body bindings whose names happen to collide with outer
              -- temporaries (e.g. both bodies using `t0`/`t1`).
              --
              -- TS quirk (load-bearing): `LoweringContext.localBindings` is
              -- RESET inside the recursive `lowerBindings(method.body)` call
              -- and NOT restored on return. We mirror by using the inner
              -- body's binding names as the post-call `localBindings`, so
              -- subsequent outer `.refAlias` rebinds (e.g. `fee = @ref:t15`)
              -- skip consumption and emit DUP/PICK.
              let innerLocalBindings := m.body.map (fun b => b.name)
              let bodyLastUses := computeLastUses m.body
              -- Merge the callee body's const-int contributions onto the
              -- outer-scope map. The outer map keeps its entries (visible
              -- through scope) while the callee adds its own literals.
              let bodyConstInts := constInts ++ collectConstInts m.body
              -- Same merge for the raw-slot markers: TS inlines the callee
              -- into the SAME `LoweringContext`, so the callee's byte-array
              -- results are marked in the very set the inlined body reads.
              let bodyRawSlots := rawSlots ++ collectRawSlots m.body
              -- …and for the array-literal element table: TS inlines the
              -- callee into the SAME `LoweringContext`, so the callee's
              -- `array_literal` bindings land in the very map its own
              -- `checkMultiSig` reads.
              let bodyArrayElems := arrayElems ++ arrayElemsOf m.body
              let (bodyOps, smAfterBody) :=
                lowerBindingsP progMethods props budget' 0 bodyLastUses outerProtected
                  innerLocalBindings bodyConstInts smArgs m.body bodyRawSlots insideBranch
                  bodyArrayElems
              -- After inlining, the callee body has either left its return
              -- value on top (named after its last binding) or — if its
              -- last binding was an assert — left whatever was below
              -- exposed. Mirror TS `inlineMethodCall` (`05-stack-lower.ts:
              -- 1637-1643`): rename top to `bindingName` ONLY when the top
              -- IS the method's last binding name. Otherwise the inlined
              -- body produced no return value (e.g. `requireOwner` in
              -- function-patterns ends in `assert`) and the outer scope's
              -- pre-existing top entry must be preserved.
              let smFinal : StackMap :=
                match m.body.reverse with
                | (.mk lastName _ _) :: _ =>
                    match smAfterBody with
                    | top :: rest =>
                        if top = lastName then bindingName :: rest
                        else smAfterBody
                    | [] => smAfterBody
                | [] => smAfterBody
              -- Propagate the inner `localBindings` to the outer continuation
              -- (the load-bearing TS bug).
              (objDropOps ++ argLoads ++ bodyOps, smFinal, innerLocalBindings)
  | .ifVal cond thn els results =>
      -- Bring the cond to top (consume on last use, modulo outerProtected).
      let (condOps₀, sm1) := loadRefLive sm cond currentIndex lastUses outerProtected
      -- OP_IF reads the cond as a boolean, so a raw byte-array result is
      -- re-minimised here like any other numeric-context read.
      let condOps := normalizeRaw (rawSlotsInScope rawSlots bindingName) cond condOps₀
      -- The IF block consumes the cond, so peel it off the stack map for
      -- the branch lowering. Branches inherit `sm1` minus the cond top —
      -- which matches Bitcoin Script's IF semantics: cond is popped at
      -- entry, the active branch runs against the remaining stack.
      let smBranch := sm1.popN 1
      -- Mirror TS `lowerIf` (`05-stack-lower.ts:1660-1667`): only protect
      -- parent refs that are STILL ALIVE AFTER the if-expression. Refs
      -- whose last use is at-or-before the if can be consumed (ROLLed)
      -- inside a branch — TS does this and the byte-exact reference
      -- relies on it (e.g. token-ft transfer's `amount` is consumed
      -- inside the empty-else then-branch). Pre-fix we used the full
      -- `smBranch` here, which over-protected and forced PICK where
      -- TS emits ROLL, causing a +1 stack-depth drift downstream.
      -- Issue #150: a DECLARED result is read by BOTH arms' `__merge$`
      -- block, and that read is reconciliation, not a use — TS protects
      -- every declared result the parent still holds so each arm COPIES it
      -- (`05-stack-lower.ts:2470-2472`) and both arms leave exactly K
      -- equally-named result slots. Without it an arm ROLLs the slot away,
      -- the merge block emits nothing, and the arm comes back short.
      -- Matched on `results` so the no-results case stays DEFINITIONALLY
      -- the pre-existing term the Agrees* proofs reduce through.
      let innerProtected :=
        match results with
        | [] => computeBranchProtected smBranch lastUses currentIndex outerProtected
        | _ :: _ =>
            computeBranchProtected smBranch lastUses currentIndex outerProtected
              ++ results.filter (fun n => (smBranch.depth? n).isSome)
      let thnLastUses := computeLastUses thn
      let elsLastUses := computeLastUses els
      -- TS `lowerIf` creates a new `LoweringContext` per branch, so each
      -- branch's `localBindings` is reset to its own bindings (line 1673,
      -- 1688). Mirror that.
      let thnLocal := thn.map (fun b => b.name)
      let elsLocal := els.map (fun b => b.name)
      -- Each arm inherits the parent's raw-slot markers
      -- (`05-stack-lower.ts:2485`, `2503`); `collectRawSlots` already folded
      -- both arms' own contributions into the method-wide set.
      -- Issue #150: `true` is TS `lowerIf`'s `thenCtx._insideBranch = true` /
      -- `elseCtx._insideBranch = true` (`05-stack-lower.ts:2481`, `2502`) —
      -- the ONLY two places the reference sets the flag, and the only two
      -- places it builds a sub-context. Loops and inlined private methods
      -- lower into the SAME context there, which is why every other call
      -- site below propagates the incoming value instead of resetting it.
      let (thnOps, smThn) := lowerBindingsP progMethods props budget 0 thnLastUses innerProtected thnLocal constInts smBranch thn rawSlots true arrayElems
      let (elsOps, smEls) := lowerBindingsP progMethods props budget 0 elsLastUses innerProtected elsLocal constInts smBranch els rawSlots true arrayElems
      -- Phase 3z-F: empty-else shadow-rebind synthesis. When the THEN
      -- branch's top-of-stack name was already in `smBranch` (a property
      -- shadow-rebind like `count = @ref:t5`) and `els = []`, TS
      -- (`05-stack-lower.ts:1776-1796`, `1850-1875`) emits a DUP/PICK in
      -- the empty else and a NIP after ENDIF to remove the stale slot.
      -- This is distinct from the asymmetric-consumption path below: the
      -- shadow case does NOT involve THEN consuming parent items, so
      -- `smThn` and `smBranch` differ ONLY by the new top.
      -- Recognise both the legacy empty-else shape (`els = []`) and the
      -- newer canonical TS shape (`els = [{name = topName, value =
      -- load_const ""}]`). Commit `3fed3295` ("close cross-compiler test
      -- gaps + fixes") flipped the TS reference to always emit the
      -- explicit single-binding else; the byte-exact lowering it
      -- generates is identical to the empty-else case (DUP/PICK in
      -- else, NIP after ENDIF). Treat both shapes as the shadow-rebind
      -- path. token-ft is the regression that surfaces this.
      let isEmptyBytesRebind (b : ANFBinding) (topName : String) : Bool :=
        b.name = topName &&
        match b.value with
        | .loadConst (.bytes ba) => ba.size = 0
        | _ => false
      -- Issue #99 Bug 1: the shape above is the SINGLE-result instance of
      -- TS's post-`OP_ENDIF` reconcile — the `else if (thenCtx.stackMap.depth
      -- > this.stackMap.depth)` branches at `05-stack-lower.ts:3054-3106`,
      -- which the reference only reaches once its `nResults >= 2` branch
      -- (`:3022`) has declined. `singleResult` is that gate. Without it a
      -- conditional write of N ≥ 2 fields matched here on its TOP name alone:
      -- the model synthesised ONE copy for an N-slot deficit and NIPped ONE
      -- of the N stale slots, so the arms left the stack at different depths
      -- and every later read resolved (N-1) slots off. `cond-write-multi-field`
      -- is the fixture written for exactly that shape.
      let singleResult : Bool := smThn.length == smBranch.length + 1
      let shadowRebind : Option (StackMap × Nat × String) :=
        match els, smThn with
        | [], some topName :: _ =>
            if !singleResult then none else
            match smBranch.depth? topName with
            | some d =>
                -- Only treat as shadow-rebind if NO parent items were
                -- consumed by THEN (else asymmetric path applies).
                let consumedByThen := consumedNames smBranch (smThn.tail)
                if consumedByThen.isEmpty then some (smBranch, d, topName)
                else none
            | none => none
        | [b], some topName :: _ =>
            if !singleResult then none else
            if isEmptyBytesRebind b topName then
              match smBranch.depth? topName with
              | some d =>
                  let consumedByThen := consumedNames smBranch (smThn.tail)
                  if consumedByThen.isEmpty then some (smBranch, d, topName)
                  else none
              | none => none
            else none
        | _, _ => none
      match shadowRebind with
      | some (_smB, d, topName) =>
          -- Phase 7.1.c: Mirror TS `lowerIf` (`05-stack-lower.ts:1839-1846`)
          -- and the post-ENDIF stale-removal loop (`1905-1929`).
          --
          -- elseSynth: TS emits `push(d), pick(d)` where the TS `pick`
          -- opcode is bare `OP_PICK` (`06-emit.ts:471-473`), giving
          -- on-wire bytes `OP_<d> OP_PICK`. Our `StackOp.pick d` already
          -- encodes as `pushBigInt(d) ++ OP_PICK` (`Script/Emit.lean:177`),
          -- so a standalone `[.pickStruct d]` is byte-identical to TS's
          -- `[push d, pick]` pair. Adding an explicit `[.push d]` before
          -- it would double-emit the depth (the bug closed here).
          --
          -- Issue #150 (d == 1): TS's pair is `push 1, pick 1` — the two
          -- values AGREE, so the TS peephole's "PUSH 1, Pick{1} → Over"
          -- rule fires (`optimizer/peephole.ts:371-375`) and the reference
          -- emits a single `OP_OVER`. Emit the folded form directly, the
          -- same way `removeConsumedAtDepths` writes `.opcode "OP_ROT"`
          -- for its own d == 2 fold: `.pickStruct` is deliberately outside
          -- `rollPickRewriteOne`, so leaving `[.pickStruct 1]` here kept
          -- the unfolded `OP_1 OP_PICK` (2 bytes vs 1).
          --
          -- cleanup: TS emits `push(d'), roll(d'+1), drop` where d' is
          -- the post-ENDIF stale depth = `d + 1` (the elseSynth pushed
          -- a new top, displacing the original `topName` by 1). Bytes:
          -- `OP_<d+1> OP_ROLL OP_DROP`.
          --
          -- Issue #150: emitted as an explicit `[.push (d+1), .opcode
          -- "OP_ROLL", .drop]` — the same shape `adoptDeclaredResults`
          -- uses for this identical TS loop — and NOT as `[.roll (d+1),
          -- .drop]`. The two are byte-equal for `d + 1 ≥ 3`, but at
          -- `d + 1 = 2` our fused `.roll 2` is fold-eligible and
          -- `rollPickRewriteOne` rewrites it to `.rot` (1 byte). TS CANNOT
          -- fold here: its pushed value (d') and its roll depth (d'+1)
          -- DISAGREE, and "PUSH 2, Roll{2} → Rot"
          -- (`optimizer/peephole.ts:352-357`) requires them equal. The
          -- reference therefore keeps `OP_2 OP_ROLL`, and so must we —
          -- `loop-if-merged-locals` reaches this at d == 1.
          let elseSynth : List StackOp :=
            if d == 0 then [.dup]
            else if d == 1 then [.over]
            else [.pickStruct d]
          let cleanup : List StackOp :=
            if d == 0 then [.nip]
            else [.push (.bigint (Int.ofNat (d + 1))), .opcode "OP_ROLL", .drop]
          let smCleaned : StackMap := (smBranch.removeAtDepth d).push topName
          (condOps ++ [.ifOp thnOps (some elseSynth)] ++ cleanup, smCleaned, localBindings)
      | none =>
          -- Mirror TS asymmetric-consumption reconciliation
          -- (`05-stack-lower.ts:1712-1800`):
          -- 1. Names consumed by THEN that still exist in ELSE → emit
          --    cleanup ROLL+DROPs in ELSE.
          -- 2. Names consumed by ELSE that still exist in THEN → emit
          --    cleanup ROLL+DROPs in THEN.
          -- 3. After both cleanups, balance depth via empty-bytes push
          --    (OP_0 is the empty bytestring placeholder TS uses).
          -- 4. Reconcile parent sm: remove names consumed by both branches.
          -- Mirrors TS `lowerIf` (`05-stack-lower.ts:1714-1727`).
          -- `preIfNames` (= smBranch) restricts to parent-scope items;
          -- branch-local pushes are NOT eligible for cleanup.
          --
          -- `dropsForEls` = parent items missing from smThn but still in smEls
          --              ⇒ THEN consumed them; ELSE must drop them too.
          -- `dropsForThn` = parent items missing from smEls but still in smThn
          --              ⇒ ELSE consumed them; THEN must drop them too.
          let parentInBoth (refSm : StackMap) (otherSm : StackMap) :
              List String :=
            smBranch.foldl (init := ([] : List String)) fun acc slot =>
              match slot with
              | none   => acc   -- anonymous: no name for either arm to drop
              | some n =>
              if listContains acc n then acc
              else
                match refSm.depth? n, otherSm.depth? n with
                | some _, none => acc ++ [n]   -- present in refSm, missing from otherSm
                | _, _         => acc
          let dropsForEls := parentInBoth smEls smThn
          let dropsForThn := parentInBoth smThn smEls
          let (elsCleanupOps, smElsAfter) :=
            removeConsumedAtDepths smEls dropsForEls
          let (thnCleanupOps, smThnAfter) :=
            removeConsumedAtDepths smThn dropsForThn
          -- Depth balance: if THEN deeper, push empty bytes in ELSE; vice versa.
          --
          -- Issue #150 gap 1. The pad OCCUPIES a stack slot, and the reference
          -- RECORDS it: `emitOp({op:'push', value: new Uint8Array(0)});
          -- armCtx.stackMap.push(null)` (`05-stack-lower.ts:2872`, `:2878`).
          -- That is the ONE `push(null)` of the reference's 291 that survives
          -- onto a map a later phase reads (the post-`OP_ENDIF` reconcile, the
          -- `nResults` depth test, and `restoreInheritedLayout`) — every other
          -- one is transient, pushed for a depth literal and popped on the next
          -- line. Emitting the op without recording the slot left the model's
          -- arm maps one slot shallower than the reference's wherever a pad
          -- fired. `pushAnon`, not `push`: the pad has no name, and the
          -- reconcile's `if (n === null) return` bail-outs are exactly what
          -- must stay expressible.
          --
          -- Issue #150 gap 2. The reference pads in a `while` — one slot per
          -- iteration until the arms agree — so an N-slot deficit gets N pads.
          -- The model emitted exactly one. `padArm` is that loop; `Nat`
          -- subtraction truncates, so at most one side is non-zero.
          --
          -- Issue #150 gap 3. `padBelowResult` (`05-stack-lower.ts:2833-2840`)
          -- SWAPs the pad under the arm's own result, for the VALUE-producing
          -- shape only: `results.length === 0 && thenBindings.length > 0 &&
          -- elseBindings.length > 0` (`:2760`). An arm that produced NO result
          -- has none to protect, and tucking the pad under its top slot would
          -- displace the whole inherited region (NEW-019) — that arm is
          -- recognised POSITIONALLY, by its map being exactly the parent's
          -- post-`if` model, because both shapes reach here one slot short.
          -- Evaluated ONCE, before any pad, so an arm owed several slots places
          -- all of them consistently.
          let thnDepth := smThnAfter.length
          let elsDepth := smElsAfter.length
          let inhModel := inheritedModel smBranch smThnAfter
          let padsBelow : Bool := results.isEmpty && !thn.isEmpty && !els.isEmpty
          let (extraEls, smElsPad) :=
            padArm padsBelow (smElsAfter == inhModel) (thnDepth - elsDepth) smElsAfter
          let (extraThn, smThnPad) :=
            padArm padsBelow (smThnAfter == inhModel) (elsDepth - thnDepth) smThnAfter
          let elsFinalOps := elsOps ++ elsCleanupOps ++ extraEls
          let thnFinalOps := thnOps ++ thnCleanupOps ++ extraThn
          -- Reconcile parent sm: drop entries consumed by THEN (use THEN
          -- as canonical reference, mirroring TS `lowerIf`'s post-ENDIF
          -- reconcile, `05-stack-lower.ts:2925-2935`).
          --
          -- NEW-014: reconcile against the POST-cleanup THEN map. TS emits
          -- phase 1's compensating ROLL+DROPs *into* `thenCtx` and updates
          -- `thenCtx.stackMap` with them, so by the time it reconciles, the
          -- reference map has already given up every slot EITHER arm gave
          -- up. Reading the PRE-cleanup `smThn` here left a slot in the
          -- parent that neither arm still holds, and the depth test below
          -- then read `armDepth == parentDepth` and registered no result at
          -- all: a value-producing `if` whose consumer resolved to
          -- `OP_RUNAR_UNRESOLVED_*`. Reachable from ordinary source since
          -- `&&`/`||` desugar to a conditional whose else-arm reads a
          -- parent local for the last time (`a >= 0n || a < 0n`), so
          -- `bitwise-ops`, `boolean-logic` and `shift-ops` stopped
          -- compiling in the model. The declared-results path below already
          -- reconciles against its post-cleanup map (`smThnTrim`).
          let parentConsumed := consumedNames smBranch smThnPad
          let smParentReconciled : StackMap := removeNames smBranch parentConsumed
          -- Issue #149 / #150 step 3: re-sort each arm's inherited region back
          -- into the parent's slot order. The reference runs this on BOTH arms
          -- AFTER the parent reconcile and AFTER `emitOp({op:'if', …})`,
          -- mutating the arm's already-emitted op array BY REFERENCE
          -- (`05-stack-lower.ts:2974`), so the ops land INSIDE the branch.
          -- Rolls only permute, so no depth test below changes and the
          -- restored maps feed nothing the model reads — they are named `_` to
          -- say so rather than silently dropped.
          --
          -- `stillHeld` is TS's `postBranchNames` (`:2927`): the names the THEN
          -- arm still holds after phase 1/2 and the pad.
          -- The reference repairs #149 in the PARENT, after `OP_ENDIF`, by
          -- sinking the adopted result block back under the inherited slots it
          -- crossed (`sinkResultBlock`, called from `adoptDeclaredResults`).
          -- Nothing is emitted inside either arm, so both arms contribute an
          -- empty op list here.
          let thnRestoreOps : List StackOp := []
          let elsRestoreOps : List StackOp := []
          -- Determine the post-IF stack.
          --
          -- Multi-result branch node (`results` non-empty): the parent
          -- adopts the DECLARED result slots rather than a single
          -- `bindingName`, and drops the parent slots they shadow. TS
          -- takes this path whenever `nDeclared >= 1` and never pushes
          -- `bindingName` for it (`05-stack-lower.ts:2481`).
          --
          -- Otherwise (single-result `if`): if the branches added a
          -- value, the parent names it `bindingName`.
          --
          -- The emptiness test is on the PRE-restore else, deliberately: TS
          -- decides `else: elseOps.length > 0 ? elseOps : undefined` before the
          -- restore runs, so an else-arm that was empty at that moment stays
          -- `undefined` and never receives the restore's ops, even though its
          -- stackMap was updated. Replicated, not repaired — it is the
          -- reference's bytes we must match.
          let elseOpt : Option (List StackOp) :=
            if elsFinalOps.isEmpty then none else some (elsFinalOps ++ elsRestoreOps)
          -- Matched on `results` (not `results.isEmpty`) so that the
          -- single-result case reduces DEFINITIONALLY to the term the
          -- pre-existing Agrees* proofs already reason about — an
          -- `if`-expression would leave a `++ []` residue that blocks
          -- their `rfl`/`simp` steps.
          match results with
          | [] =>
              -- Issue #150: the empty-else COPY pad + post-ENDIF stale
              -- reconcile that `shadowRebind` above ports only for the
              -- "then consumed nothing" case. See `ifWithoutElseCopy`.
              -- Matched on `els` (not `els.isEmpty`) so a branch WITH an
              -- else reduces definitionally to the pre-existing generic
              -- term, exactly as the `results` match above does.
              match els with
              | _ :: _ =>
                  let smPostIf : StackMap :=
                    if smThnPad.length > smParentReconciled.length then
                      smParentReconciled.push bindingName
                    else
                      smParentReconciled
                  (condOps ++ [.ifOp (thnFinalOps ++ thnRestoreOps) elseOpt],
                   smPostIf, localBindings)
              | [] =>
              -- Issue #99 Bug 1: N ≥ 2 results first. TS reaches its
              -- single-result branches only after `nResults >= 2` declines
              -- (`05-stack-lower.ts:3022` vs `:3054`), so this must be tried
              -- BEFORE `ifWithoutElseCopy` — and `ifWithoutElseMultiResults`
              -- returning `none` for N ≤ 1 is what makes the single-result
              -- case reduce definitionally to the term that was here before.
              match ifWithoutElseMultiResults smParentReconciled smThnAfter with
              | some k =>
                  -- Phase 3: one preserved copy per owed slot, deepest first.
                  -- The deficit is measured against the POST-cleanup else map
                  -- (TS's `while (thenDepth > elseDepth)` runs after phase 1),
                  -- which is `k` only when the else arm gave up nothing.
                  let (padOps, smElsCopy) :=
                    ifWithoutElseCopyPad smThnAfter
                      (smThnAfter.length - smElsAfter.length) smElsAfter
                  let elsCopyOps := elsOps ++ elsCleanupOps ++ padOps
                  -- The else arm's post-phase-3 map is the COPY pad, not the
                  -- generic `smElsPad`, so its restore is computed against it.
                  -- Repaired in the parent by `sinkResultBlock`; the arm
                  -- emits nothing (see the declared-results site above).
                  let elsCopyRestoreOps : List StackOp := []
                  -- Post-ENDIF: adopt all N, then ROLL+DROP the N stale parent
                  -- slots they shadow. TS's `:3022-3053` loop is the same loop
                  -- as the declared-results `:3000-3020` one, so this is
                  -- literally `adoptDeclaredResults` over the arm's top-N
                  -- names instead of over the node's `results`.
                  let (adoptOps, smPostIf) :=
                    adoptDeclaredResults smParentReconciled
                      (armResultNames smThnAfter bindingName k)
                  (condOps
                     ++ [.ifOp (thnFinalOps ++ thnRestoreOps)
                           (some (elsCopyOps ++ elsCopyRestoreOps))]
                     ++ adoptOps,
                   smPostIf, localBindings)
              | none =>
              match ifWithoutElseCopy bindingName
                      smParentReconciled smThnAfter smElsAfter with
              | some (vd, staleD, nm) =>
                  -- Pad the else with a COPY of `nm` (TS phase 3). The
                  -- `vd == 1` fold to `.over` is TS's own peephole rule
                  -- firing on its matching `push 1 / pick 1` pair — see
                  -- the `elseSynth` note above.
                  let copyOps : List StackOp :=
                    if vd == 0 then [.dup]
                    else if vd == 1 then [.over]
                    else [.pickStruct vd]
                  -- Post-ENDIF stale removal. Explicit `push / OP_ROLL`
                  -- (not the fused `.roll`) for the same reason as the
                  -- `shadowRebind` cleanup: TS's pushed value and roll
                  -- depth DISAGREE here, so its rot-fold cannot fire.
                  let cleanupOps : List StackOp :=
                    if staleD == 1 then [.nip]
                    else [.push (.bigint (Int.ofNat staleD)), .opcode "OP_ROLL", .drop]
                  let elsCopyOps := elsOps ++ elsCleanupOps ++ copyOps
                  -- The else arm's post-phase-3 map is the COPY pad, not the
                  -- generic `smElsPad`, so its restore is computed against it.
                  -- Repaired in the parent by `sinkResultBlock`; the arm
                  -- emits nothing (see the declared-results site above).
                  let elsCopyRestoreOps : List StackOp := []
                  let smPostIf : StackMap :=
                    (smParentReconciled.push nm).removeAtDepth staleD
                  (condOps
                     ++ [.ifOp (thnFinalOps ++ thnRestoreOps)
                           (some (elsCopyOps ++ elsCopyRestoreOps))]
                     ++ cleanupOps,
                   smPostIf, localBindings)
              | none =>
              let smPostIf : StackMap :=
                if smThnPad.length > smParentReconciled.length then
                  smParentReconciled.push bindingName
                else
                  smParentReconciled
              (condOps ++ [.ifOp (thnFinalOps ++ thnRestoreOps) elseOpt],
               smPostIf, localBindings)
          | _ :: _ =>
              -- Issue #150: with DECLARED results, TS trims each arm down to
              -- the parent's surviving depth plus the K result slots
              -- (`05-stack-lower.ts:2612-2624`), dropping at depth K — the
              -- slot immediately below the result block. That removal happens
              -- INSIDE each arm and is driven by the declared arity alone, so
              -- it fires even when both arms rebind the same merged local and
              -- the asymmetric-consumption reconciliation above therefore
              -- finds nothing to do. Omitting it left every declared-results
              -- arm one slot too deep — one missing `OP_NIP` per arm.
              --
              -- The phase-3 depth balance and the parent reconcile are
              -- recomputed from the TRIMMED arms, matching the TS ordering
              -- (trim at 2620, balance at 2710, reconcile at 2771).
              let nDeclared := results.length
              let consumedFromParent := (consumedNames smBranch smThnAfter).length
              let targetDepth := smBranch.length - consumedFromParent + nDeclared
              let (thnTrimOps, smThnTrim) :=
                trimArmToDepth nDeclared targetDepth smThnAfter.length smThnAfter
              let (elsTrimOps, smElsTrim) :=
                trimArmToDepth nDeclared targetDepth smElsAfter.length smElsAfter
              -- Same phase-3 balance as the `results = []` path above: the
              -- reference runs ONE `while` for both, after the trim
              -- (`05-stack-lower.ts:2620` trims, `2853` pads), and records each
              -- pad as an anonymous slot.
              -- `padBelowResult` is gated on `results.length === 0`
              -- (`05-stack-lower.ts:2760`), so it can never fire on this path;
              -- the flags are passed in their inert form rather than computed.
              let (extraEls', smElsTrimPad) :=
                padArm false true (smThnTrim.length - smElsTrim.length) smElsTrim
              let (extraThn', smThnTrimPad) :=
                padArm false true (smElsTrim.length - smThnTrim.length) smThnTrim
              let elsResultOps := elsOps ++ elsCleanupOps ++ elsTrimOps ++ extraEls'
              let thnResultOps := thnOps ++ thnCleanupOps ++ thnTrimOps ++ extraThn'
              let parentConsumedTrim := consumedNames smBranch smThnTrimPad
              let smParentTrimmed : StackMap := removeNames smBranch parentConsumedTrim
              -- Issue #149 / #150 step 3, declared-results peer. Same call, same
              -- ordering: after the parent reconcile, before the adopt.
              let stillHeldTrim := smThnTrimPad.names
              let (thnRestoreOps', _) :=
                restoreInheritedLayout smParentTrimmed stillHeldTrim smThnTrimPad
              let (elsRestoreOps', _) :=
                restoreInheritedLayout smParentTrimmed stillHeldTrim smElsTrimPad
              let elseResultOpt : Option (List StackOp) :=
                if elsResultOps.isEmpty then none
                else some (elsResultOps ++ elsRestoreOps')
              let (adoptOps, smPostIf) := adoptDeclaredResults smParentTrimmed results
              (condOps ++ [.ifOp (thnResultOps ++ thnRestoreOps') elseResultOpt]
                 ++ adoptOps,
               smPostIf, localBindings)
  | .assert ref =>
      let (load, sm1) := loadRefLive sm ref currentIndex lastUses outerProtected
      -- `OP_VERIFY` reads a script number, so a raw operand is re-minimised
      -- (TS `bringToTop` defaults `allowRaw = false`).
      let ops := normalizeRaw (rawSlotsInScope rawSlots bindingName) ref load ++ [.opcode "OP_VERIFY"]
      let sm2 := sm1.popN 1
      (ops, sm2, localBindings)
  | .updateProp propName ref =>
      -- Phase 3z-C: mirror TS `lowerUpdateProp` (`05-stack-lower.ts:1985-2027`).
      -- 1. Bring the new value to top via liveness-aware load.
      -- 2. Rename top from `ref` to `propName` so subsequent `loadProp`
      --    finds the updated value.
      -- 3. If the OLD `propName` entry survives below (depth ≥ 1), the TS
      --    reference removes it via NIP (depth 1) or [push d, roll d+1,
      --    drop] (depth ≥ 2) — but ONLY when it is not lowering inside an
      --    `if` arm (`!this._insideBranch`, `05-stack-lower.ts:3312`).
      --    Inside an arm the stale slot is kept ON PURPOSE, because it is
      --    what `lowerIf`'s same-property detection reads after OP_ENDIF.
      --
      --    Issue #150: this arm used to claim the skip path was
      --    unreachable, on the grounds that `liftBranchUpdateProps` hoists
      --    branch-local `update_prop`s to the top level. It does not hoist
      --    all of them — that pass only rewrites chains of TWO OR MORE and
      --    does not recurse into loop bodies — and `assert-false-guard` is
      --    the fixture written to sit in both holes: every one of its
      --    `update_prop`s stays inside an arm, the model cleaned up all of
      --    them, and it came out 38 bytes over the golden.
      -- The binding name `_bindingName` is the t-temporary the IR assigns
      -- to the update_prop result; subsequent code references the prop by
      -- its property name, not the temporary.
      let (load, sm1) := loadRefLive sm ref currentIndex lastUses outerProtected
      let smRenamed : StackMap :=
        match sm1 with
        | _ :: rest => some propName :: rest
        | []        => [some propName]
      -- Matched on the constructor (not `if insideBranch then …`) so the
      -- `false` case reduces DEFINITIONALLY to the pre-existing term —
      -- the same containment the `results` / `els` matches above rely on,
      -- and what lets the `insideBranch` optParam default carry every
      -- existing `Agrees*` proof term through unchanged.
      let (cleanup, sm2) :=
        match insideBranch with
        | false => removePropEntryOps smRenamed propName
        | true  => (([] : List StackOp), smRenamed)
      -- NEW-004/NEW-007: a property written from a byte-array result is
      -- re-minimised on the way in, so the state continuation commits the
      -- minimal encoding.
      (normalizeRaw (rawSlotsInScope rawSlots bindingName) ref load ++ cleanup, sm2, localBindings)
  | .loop count body iterVar =>
      -- Loop-fidelity rewrite (2026-06-11; replaces the Phase 3z-F
      -- lower-once-and-replay arm): per-ITERATION re-lowering against the
      -- live threaded stack map, mirroring TS `lowerLoop` at
      -- `05-stack-lower.ts:2109-2176`.
      --
      -- The TS reference unrolls the loop at compile time and lowers the
      -- body EVERY iteration in the SAME context, so PICK/ROLL depths GROW
      -- across iterations when values strand (e.g. an unreferenced iter
      -- var buried under the accumulator). `lowerLoopItersP` (below in
      -- this mutual block) reproduces that fold; the old arm lowered the
      -- body once per liveness mode and replayed the iteration-0 depths,
      -- which produced semantically wrong bytes for every body whose
      -- ending map shape differs from its starting one (the pinned
      -- `loopCx*` divergence in `Pipeline.lean`).
      --
      -- * `outerRefs` (TS 2115-2133): only `load_param` names (≠ iterVar)
      --   and `@ref:` targets not body-bound. Non-final iterations clamp
      --   their recorded last-use to `body.length` so they are never
      --   consumed (TS 2149-2154); ONLY the final iteration sees natural
      --   last-uses, allowing ROLL/SWAP consumption on the last access.
      -- * `localBindings` (TS 2136-2138): the body is lowered with the
      --   ENCLOSING localBindings extended by the body's binding names
      --   (`new Set([...this.localBindings, ...bodyBindingNames])`), so
      --   the final-iteration `@ref:` consume gate sees outer locals too
      --   (ROLL where the previous body-names-only set wrongly PICKed).
      --   TS restores the enclosing set after the loop (2171); we return
      --   the unmodified `localBindings`.
      -- * per-iteration iterVar cleanup (TS 2158-2167): drop iff the iter
      --   var survives at EXACTLY depth 0. A survivor buried deeper emits
      --   NOTHING and stays on the map (stranded values are cleaned by
      --   the end-of-method NIP pass) — the old arm's any-depth `.drop`
      --   destroyed the body's last value instead.
      --
      -- TS does NOT use a generic `outerProtected` set inside loop bodies
      -- — it relies on the lastUses clamping for outer-refs and on
      -- `localBindings` for the `@ref:` consume gate — so the body is
      -- lowered with `outerProtected = []` (the `[]` literal below).
      let outerRefs := bodyOuterRefs body iterVar
      let naturalLU := computeLastUses body
      let nonFinalLU := clampLastUsesForOuter naturalLU outerRefs body.length
      -- FINAL iteration: TS clamps an outer ref too when the ENCLOSING scope
      -- still reads it after the loop (`05-stack-lower.ts:2723-2741`).
      -- Without this the last iteration consumes it at its last body use, so
      -- a value read after the loop is gone from the stack — TS's own comment
      -- records the consequence: "compilation succeeded, the env-based
      -- interpreter passed, but the emitted Script failed at runtime (silent
      -- interpreter <-> Script divergence)". Here it surfaces instead as an
      -- `OP_RUNAR_UNRESOLVED_*` sentinel (`loop-if-merged-locals`' `na`).
      let usedAfterLoop := loopOuterRefsUsedAfter body iterVar lastUses currentIndex
      -- Matched (not `if`) so that a body with no after-loop outer ref
      -- reduces DEFINITIONALLY to `naturalLU`, keeping the pre-existing
      -- `rfl`-level loop pins in `AgreesA7` matching syntactically.
      let finalLU :=
        match usedAfterLoop with
        | []     => naturalLU
        | _ :: _ => clampLastUsesForOuter naturalLU usedAfterLoop body.length
      let loopLocal := localBindings ++ body.map (fun b => b.name)
      let (ops, smPostLoop) :=
        lowerLoopItersP progMethods props budget finalLU nonFinalLU
          loopLocal constInts body iterVar count sm count rawSlots insideBranch
          arrayElems
      -- Loops are statements, not expressions — no stack value is produced
      -- (TS 2172-2175) and the enclosing localBindings set is restored
      -- (TS 2171). The post-loop sm is the THREADED map from the final
      -- iteration, including any stranded iter-var entries (TS leaves
      -- them on `this.stackMap`; the public-method epilogue NIPs them).
      (ops, smPostLoop, localBindings)
  | .arrayLiteral _ =>
      -- Metadata-only, mirroring TS `lowerArrayLiteral`
      -- (`05-stack-lower.ts:2140-2146`): emit NOTHING and push NOTHING onto
      -- the stack map. A map slot models one runtime slot, but an array
      -- binding spans N of them, so laying the elements out here would
      -- desync the two. The elements stay on the map under their own
      -- binding names and `arrayElemsOf` has already recorded which they
      -- are; `checkMultiSig` pulls each to the top at the use site.
      ([], sm, localBindings)
  -- Phase 3w-b: framework intrinsics with concrete lowering. The
  -- liveness-aware variants (`*OpsLive`) thread `currentIndex` /
  -- `lastUses` / `outerProtected` so PICK→ROLL collapse on dead refs
  -- and OVER→SWAP / DUP→nop collapse on top-of-stack last uses, which
  -- is required to produce byte-identical hex against the TS reference
  -- once `lowerMethod` prepends the `_codePart` / `_opPushTxSig`
  -- implicit param entries to the initial stack map (see Phase 3z-D).
  | .addRawOutput sat scr    =>
      let (ops, sm') := lowerAddRawOutputOpsLive sm bindingName sat scr currentIndex lastUses outerProtected
      (ops, sm', localBindings)
  | .addDataOutput sat scr   =>
      let (ops, sm') := lowerAddRawOutputOpsLive sm bindingName sat scr currentIndex lastUses outerProtected
      (ops, sm', localBindings)
  | .checkPreimage pre       =>
      let (ops, sm') := lowerCheckPreimageOpsLive sm bindingName pre currentIndex lastUses outerProtected
      (ops, sm', localBindings)
  -- Phase 3z-A: property-table-aware framework intrinsics.
  | .getStateScript          =>
      let (ops, sm') := lowerGetStateScriptOpsLive sm bindingName props currentIndex lastUses outerProtected
      (ops, sm', localBindings)
  | .deserializeState pre    =>
      let (ops, sm') := lowerDeserializeStateOpsLive sm pre props currentIndex lastUses outerProtected
      (ops, sm', localBindings)
  | .addOutput sat vs _      =>
      let (ops, sm') := lowerAddOutputOpsLive sm bindingName sat vs props currentIndex lastUses outerProtected
      (ops, sm', localBindings)
  -- A14 follow-up: raw_script is also emitted verbatim by the
  -- program-aware lowerer. No liveness analysis is needed because the
  -- value carries no temp refs.
  | .rawScript bytes _ _     =>
      ([.rawBytes bytes], sm.push bindingName, localBindings)
termination_by (budget, sizeOf value, 0)

/-- Per-iteration loop unrolling for the program-aware lowerer. Mirrors
the iteration loop `for (let i = 0; i < count; i++)` of TS `lowerLoop`
(`05-stack-lower.ts:2140-2169`): each iteration

1. pushes the iteration index constant and registers `iterVar` on the
   LIVE threaded stack map,
2. RE-LOWERS the body against that map (so PICK/ROLL depths grow when
   values strand across iterations — TS re-runs `lowerBinding` per
   iteration in the same context),
3. drops the iter var iff it survives the body at EXACTLY depth 0
   (TS 2158-2167); a buried survivor is left stranded on map + stack.

`remaining` counts down from `count`; the iteration index is
`count - remaining`. The FINAL iteration (`remaining = 1`) lowers under
the natural last-uses (`naturalLU`) while every earlier iteration uses
the outer-clamped ones (`nonFinalLU`) so outer refs are only consumable
on the last pass (TS 2149-2154). `loopLocal` is the enclosing
localBindings ∪ body binding names (TS 2136-2138); `outerProtected` is
`[]` inside loop bodies (TS has no such set — see the `.loop` arm). -/
def lowerLoopItersP (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (naturalLU nonFinalLU : List (String × Nat))
    (loopLocal : List String) (constInts : List (String × Int))
    (body : List ANFBinding) (iterVar : String) (count : Nat)
    (sm : StackMap) (n : Nat) (rawSlots : List String := [])
    (insideBranch : Bool := false)
    (arrayElems : List (String × List String) := []) :
    (List StackOp × StackMap) :=
  match n with
  | 0 => ([], sm)
  | remaining + 1 =>
      let i := count - (remaining + 1)
      let lu := if remaining == 0 then naturalLU else nonFinalLU
      let smInner := sm.push iterVar
      let (bodyOps, smBody) :=
        lowerBindingsP progMethods props budget 0 lu [] loopLocal constInts smInner body rawSlots insideBranch arrayElems
      let (dropOps, smIter) := iterVarCleanup smBody iterVar
      let (restOps, smFinal) :=
        lowerLoopItersP progMethods props budget naturalLU nonFinalLU
          loopLocal constInts body iterVar count smIter remaining rawSlots insideBranch
          arrayElems
      ([StackOp.push (.bigint (Int.ofNat i))] ++ bodyOps ++ dropOps ++ restOps,
       smFinal)
termination_by (budget, sizeOf body, n)

def lowerBindingsP (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (localBindings : List String)
    (constInts : List (String × Int)) (sm : StackMap)
    (bs : List ANFBinding) (rawSlots : List String := [])
    (insideBranch : Bool := false)
    (arrayElems : List (String × List String) := []) :
    (List StackOp × StackMap) :=
  match bs with
  | [] => ([], sm)
  | (.mk name v _) :: rest =>
      let (ops, sm', localBindings') :=
        lowerValueP progMethods props budget currentIndex lastUses outerProtected localBindings constInts sm name v rawSlots insideBranch arrayElems
      let (ops', sm'') :=
        lowerBindingsP progMethods props budget (currentIndex + 1) lastUses outerProtected localBindings' constInts sm' rest rawSlots insideBranch arrayElems
      (ops ++ ops', sm'')
termination_by (budget, sizeOf bs, 0)

end

/-- Body's last binding is `.assert _`. Used by `lowerMethod` to decide
whether to elide the terminal `OP_VERIFY` from a public method's spend
script — Bitcoin Script treats the boolean left on top of the stack as
the implicit return value, so a public method's terminal assert can drop
its `OP_VERIFY`. Mirrors TS `05-stack-lower.ts:856-902`. -/
def bodyEndsInAssert : List ANFBinding → Bool
  | []        => false
  | [.mk _ (.assert _) _] => true
  | _ :: rest => bodyEndsInAssert rest

/--
Whether a method body contains a `check_preimage` binding (recursing
through if-branches and loops). Mirrors TS `methodUsesCheckPreimage`
(`05-stack-lower.ts:4889-4894`). When this returns true, the unlocking
script pushes an implicit `_opPushTxSig` parameter at the bottom of
the stack; `lowerMethod` must prepend it to the initial stack map.

Recurses on the binding list `sizeOf` to keep termination structural.
-/
def bindingsUseCheckPreimage : List ANFBinding → Bool
  | []                  => false
  | (.mk _ v _) :: rest =>
      let here : Bool :=
        match v with
        | .checkPreimage _    => true
        | .ifVal _ thn els _    =>
            bindingsUseCheckPreimage thn || bindingsUseCheckPreimage els
        | .loop _ body _      => bindingsUseCheckPreimage body
        | _                   => false
      here || bindingsUseCheckPreimage rest

/--
Whether a method body needs the implicit `_codePart` parameter. Mirrors
TS `methodUsesCodePart` (`05-stack-lower.ts:4896-4908`):
* `add_output`, `add_raw_output` — both reference `_codePart` directly
* `call computeStateOutput` / `call computeStateOutputHash` — single-
  output stateful continuations.

Note: `add_data_output` is intentionally excluded (the TS reference's
`lowerAddDataOutput` does not reference `_codePart`).
-/
def bindingsUseCodePart : List ANFBinding → Bool
  | []                  => false
  | (.mk _ v _) :: rest =>
      let here : Bool :=
        match v with
        | .addOutput _ _ _    => true
        | .addRawOutput _ _   => true
        | .call f _           =>
            f = "computeStateOutput" || f = "computeStateOutputHash"
        | .ifVal _ thn els _    =>
            bindingsUseCodePart thn || bindingsUseCodePart els
        | .loop _ body _      => bindingsUseCodePart body
        | _                   => false
      here || bindingsUseCodePart rest

/--
Whether a method body READS a mutable variable-length (`ByteString`)
state field, via `load_prop`. Mirrors TS `methodReadsVarLenState`
(`05-stack-lower.ts:5980-6003`).

Issue #100: such a method needs `_codePart` even when it builds NO
continuation output. `lowerDeserializeState`'s variable-length path
locates the mutable-state region inside the BIP-143 scriptCode by
subtracting `_codePart`'s length; without `_codePart` on the stack it
takes its `none` fallback, drops the scriptCode and skips state
decoding entirely — so a terminal var-length read silently returns the
DEPLOY-time value instead of the live on-chain one.

C18: the read may sit entirely inside a private helper reached by
`method_call`. Private methods are INLINED by `lowerValueP`, so their
`load_prop` executes in the caller's stack context at runtime — a
public method whose only var-len read is behind a helper must still
provision `_codePart`. `fuel` bounds that descent (the reference uses a
`seen` set for the same purpose); `progMethods.length` is always
enough, since a descent that revisited a method is exactly what the
reference's cycle guard cuts off.
-/
def bindingsReadVarLenState (progMethods : List ANFMethod)
    (varLenProps : List String) : Nat → List ANFBinding → Bool
  | _,    []                  => false
  | fuel, (.mk _ v _) :: rest =>
      let here : Bool :=
        match v with
        | .loadProp n         => listContains varLenProps n
        | .ifVal _ thn els _  =>
            bindingsReadVarLenState progMethods varLenProps fuel thn
              || bindingsReadVarLenState progMethods varLenProps fuel els
        | .loop _ body _      =>
            bindingsReadVarLenState progMethods varLenProps fuel body
        | .methodCall _ mn _  =>
            match fuel with
            | 0         => false
            | fuel' + 1 =>
                match lookupMethod progMethods mn with
                | some tgt =>
                    bindingsReadVarLenState progMethods varLenProps fuel' tgt.body
                | none     => false
        | _                   => false
      here || bindingsReadVarLenState progMethods varLenProps fuel rest
termination_by fuel bs => (fuel, sizeOf bs)

/-- The mutable `ByteString` property names — TS `lowerMethod`'s
`varLenProps` set (`05-stack-lower.ts:6033-6035`). -/
def varLenPropNames (props : List ANFProperty) : List String :=
  (props.filter (fun p => !p.readonly && p.type = .byteString)).map (·.name)

/--
Whether a method body contains a `deserialize_state` binding. Mirrors the
TS `lowerMethod` post-pass at `05-stack-lower.ts:4937-4942`:

```
const hasDeserializeState =
  method.body.some(b => b.value.kind === 'deserialize_state');
if (method.isPublic && hasDeserializeState) {
  ctx.cleanupExcessStack();
}
```

When the method body deserialized state from the preimage (and is public),
we must follow the body with `(stack-depth - 1)` `OP_NIP` opcodes so the
spend script returns a single boolean on top — matching Bitcoin Script's
truthy-top-of-stack contract.

Recurses into if-branches and loop bodies so nested deserialize_state
nodes (rare but legal in some hand-written ANF) trigger the cleanup.
-/
def bindingsUseDeserializeState : List ANFBinding → Bool
  | []                  => false
  | (.mk _ v _) :: rest =>
      let here : Bool :=
        match v with
        | .deserializeState _ => true
        | .ifVal _ thn els _    =>
            bindingsUseDeserializeState thn || bindingsUseDeserializeState els
        | .loop _ body _      => bindingsUseDeserializeState body
        | _                   => false
      here || bindingsUseDeserializeState rest

def lowerMethod (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod) : StackMethod :=
  -- Initial stack map: parameter names in declaration order, top = last param.
  -- For methods that call `check_preimage`, the unlocking script pushes ONE
  -- implicit param before the user-visible params (BUG-100: the OP_PUSH_TX
  -- signature is now derived on-chain from the preimage, so there is NO
  -- `_opPushTxSig` witness — see TS lowerMethod at `05-stack-lower.ts:4956-4980`):
  --   * `_codePart` — the code portion of the locking script, prepended only
  --                   when add_output / add_raw_output / computeStateOutput*
  --                   reference it, OR (issue #100) when the method READS a
  --                   mutable variable-length state field, whose
  --                   deserialization needs it for the preimage-relative
  --                   state offset.
  -- It sits at the bottom of the stack; in our top-first list it is at the
  -- *tail*. The user params (which get DUP/PICK loads) remain on top.
  let userMap : StackMap := m.params.map (·.name) |>.reverse
  let usesPreimage := bindingsUseCheckPreimage m.body
  -- TS `lowerMethod` (`05-stack-lower.ts:6036-6040`):
  --   usesCodePart = methodUsesCheckPreimage(...)
  --                  && (methodUsesCodePart(body) || methodReadsVarLenState(body, varLenProps, …))
  -- The `methodUsesCheckPreimage` conjunct is the `if usesPreimage` below.
  let usesCode     := bindingsUseCodePart m.body
                        || bindingsReadVarLenState progMethods
                             (varLenPropNames props) progMethods.length m.body
  -- Nested form (BUG-100): a `check_preimage` method prepends `_codePart` only
  -- when the continuation builders need it, and NEVER `_opPushTxSig`. The
  -- outer `if usesPreimage` is kept so non-stateful methods reduce through the
  -- same `if_false` path their proofs already use.
  let initialMap : StackMap :=
    if usesPreimage then
      if usesCode then
        userMap ++ ([some "_codePart"] : StackMap)
      else
        userMap
    else
      userMap
  -- Liveness analysis is per-binding-list. At the top-level method body
  -- there is no outer scope, so `outerProtected = []` and parameters can
  -- be consumed (ROLLed away) on their last use.
  let bodyLastUses := computeLastUses m.body
  let topLevelLocal := m.body.map (fun b => b.name)
  -- Phase 4-K: collect compile-time integer literals (binding name → int)
  -- for the entire method body, including nested if-branches and loop
  -- bodies. Used by the Merkle codegen dispatch arm to extract the
  -- depth literal that becomes the unrolled-loop bound.
  let bodyConstInts := collectConstInts m.body
  -- NEW-004: slots holding a byte-array result whose bytes may not be the
  -- minimal script-number encoding of their value. Collected once for the
  -- whole method and threaded like `constInts`; every numeric-context read
  -- of one is re-minimised with `OP_BIN2NUM`.
  let bodyRawSlots := collectRawSlots m.body
  -- Element refs of every `array_literal` binding in the method body.
  -- Collected once for the whole method and threaded like `constInts`;
  -- `checkMultiSig` reads it to pull each element to the top at the use
  -- site (the array binding itself is metadata-only and never occupies a
  -- stack-map slot).
  let bodyArrayElems := arrayElemsOf m.body
  let (rawOps, finalSm) :=
    lowerBindingsP progMethods props defaultInlineBudget 0 bodyLastUses [] topLevelLocal bodyConstInts initialMap m.body bodyRawSlots false bodyArrayElems
  -- Terminal-assert elision:
  -- A public method whose body ends in `.assert _` drops the trailing
  -- `OP_VERIFY` — the boolean stays on top of the stack as the script's
  -- implicit return value.
  let endsInOpVerify : Bool :=
    match rawOps.getLast? with
    | some (.opcode "OP_VERIFY") => true
    | _                          => false
  let opsAfterAssert :=
    if m.isPublic && bodyEndsInAssert m.body && endsInOpVerify then
      rawOps.dropLast
    else
      rawOps
  -- Excess-stack cleanup. Mirrors TS `lowerMethod`'s post-pass
  -- (`05-stack-lower.ts:4920-4935` + `cleanupExcessStack`): public
  -- methods emit `OP_NIP` repeatedly until only the truthy boolean (the
  -- terminal assert's residue) remains on top of the runtime stack.
  -- The TS reference runs `cleanupExcessStack()` UNCONDITIONALLY for
  -- public methods (the old `hasDeserializeState` gate missed the
  -- readonly-field-binding path and failed mainnet CLEANSTACK; it also
  -- removes refs left behind by the repeated-operand COPY rule of PRs
  -- #62/#67/#68 — the canonical `t := x + x` fixtures end with a NIP
  -- that removes the lingering `x`).
  --
  -- The Lean gate is `isPublic && bodyEndsInAssert && depth > 1`. The
  -- extra `bodyEndsInAssert` conjunct is byte-IDENTICAL to TS on every
  -- validator-accepted program: `02-validate.ts:325-344` REQUIRES public
  -- methods to end with `assert()` (stateful contracts auto-inject it),
  -- so `bodyEndsInAssert = true` whenever the TS epilogue can differ
  -- from a no-op. The conjunct exists so the `*_no_post` bridge lemmas
  -- (keyed on `bodyEndsInAssert = false` — shapes reachable only via
  -- hand-written `--ir` input) remain true as stated. Known residual
  -- model-vs-TS divergence: a hand-written public IR body that does NOT
  -- end in assert and leaves ≥ 2 stack slots gets TS NIPs but no model
  -- NIPs — degenerate (validator-rejected) and outside every pinned
  -- fixture.
  --
  -- The TS reference computes `excess = stackMap.depth - 1` against the
  -- depth *after* the body has run, including the terminal assert's
  -- residue (TS leaves it on the stack via the `terminal=true` path of
  -- `lowerAssert`). Our `.assert` arm above always pops after emitting
  -- `OP_VERIFY`, and the terminal trailing `OP_VERIFY` is later stripped
  -- by `dropLast`. To re-align with the TS depth model we add `+1` to
  -- `finalSm.length` whenever the terminal-assert elision actually fires.
  let droppedTerminalVerify : Bool :=
    m.isPublic && bodyEndsInAssert m.body && endsInOpVerify
  let depthAfterBody : Nat :=
    finalSm.length + (if droppedTerminalVerify then 1 else 0)
  let nipCount : Nat :=
    if m.isPublic && bodyEndsInAssert m.body && depthAfterBody > 1 then
      depthAfterBody - 1
    else
      0
  let nipOps : List StackOp := List.replicate nipCount StackOp.nip
  let ops := opsAfterAssert ++ nipOps
  { name := m.name
    ops := ops
    maxStackDepth := 0 }

def lower (p : ANFProgram) : StackProgram :=
  -- Mirror TS: only public methods become top-level `StackMethod` entries.
  -- Private methods are inlined at call sites by `lowerValueP`'s `.methodCall`
  -- arm. Constructors are also excluded (their bodies populate property slots
  -- at deploy time, not at runtime).
  { contractName := p.contractName
    methods := (p.methods.filter (·.isPublic)).map (lowerMethod p.methods p.properties) }

/-! ## SimpleANF predicate

A program is `SimpleANF` when every binding-value uses one of the ten
concretely-handled constructors and every method body is similarly
restricted. Programs satisfying this predicate are byte-exact under
`lower`, peephole-stable, and provably correct via the simulation
theorem in `Sim.lean`.
-/

mutual

/--
Phase 3d admits eleven constructors: the ten Phase 3b "simple" cases
plus `methodCall` (which inlines via `lowerValueP` against the
program's method table; see `lookupMethod` and `loadAndBindArgs`).
The predicate doesn't recursively check the *callee's* body — that
check is performed during top-level lowering when the callee itself
is visited as a method in the program.

Out-of-scope (`OP_RUNAR_*_UNSUPPORTED` sentinels): `getStateScript`,
`checkPreimage`, `deserializeState`, `addOutput`, `addRawOutput`,
`addDataOutput`. These require full BIP-143 byte construction.
-/
def simpleValue : ANFValue → Bool
  | .loadParam _              => true
  | .loadProp _               => true
  | .loadConst _              => true
  | .binOp _ _ _ _            => true
  | .unaryOp _ _ _            => true
  | .call _ _                 => true
  | .assert _                 => true
  | .updateProp _ _           => true
  | .arrayLiteral _           => true
  | .methodCall _ _ _         => true
  | .ifVal _ thn els _          =>
      simpleBindings thn && simpleBindings els
  | .loop _ body _            =>
      simpleBindings body
  -- Phase 3w-b — concretely lowered framework intrinsics:
  | .checkPreimage _          => true
  | .addRawOutput _ _         => true
  | .addDataOutput _ _        => true
  -- Phase 3z-A — property-table-aware framework intrinsics:
  | .getStateScript           => true
  | .deserializeState _       => true
  | .addOutput _ _ _          => true
  -- A14 follow-up — raw_script lowers to a single `.rawBytes` op:
  | .rawScript _ _ _          => true

def simpleBindings : List ANFBinding → Bool
  | [] => true
  | (.mk _ v _) :: rest => simpleValue v && simpleBindings rest

end

def simpleMethod (m : ANFMethod) : Bool :=
  simpleBindings m.body

def SimpleANF (p : ANFProgram) : Prop :=
  p.methods.all simpleMethod = true

instance (p : ANFProgram) : Decidable (SimpleANF p) :=
  inferInstanceAs (Decidable (_ = true))

/-! ## Generic-else bridge lemmas for `lowerValueP (.call …)`

When `func` is not in the set of specially-cased builtins, `lowerValueP`
falls through to the generic else branch:

```lean
let (argOps, sm1) := lowerArgsLive currentIndex lastUses outerProtected sm args
let sm2 := (sm1.popN args.length).push bindingName
(argOps ++ (builtinOpcode func).map (.opcode), sm2, localBindings)
```

The predicate `isSpecialCallFunc` captures ALL special-case function names
so that bridge lemmas in `Agrees.lean` can avoid triggering kernel whnf
evaluation of the 60-guard chain by using `native_decide` for closed-term
string checks.
-/

/-- Boolean guard: `true` iff `func` is handled by a special-case branch
in `lowerValueP`'s `.call` arm (i.e. anything **except** the generic-else
fallthrough). -/
def isSpecialCallFunc (func : String) : Bool :=
  func.startsWith "extract" ||
  func == "buildChangeOutput" || func == "computeStateOutput" ||
  func == "computeStateOutputHash" || func == "substr" ||
  func == "percentOf" || func == "mulDiv" ||
  func == "safediv" || func == "safemod" ||
  func == "clamp" || func == "pow" || func == "sqrt" ||
  func == "gcd" || func == "log2" || func == "sign" ||
  func == "verifyRabinSig" ||
  func == "sha256Compress" || func == "sha256Finalize" ||
  func == "blake3Compress" || func == "blake3Hash" ||
  func == "verifyWOTS" ||
  func == "ecAdd" || func == "ecMul" || func == "ecMulGen" ||
  func == "ecNegate" || func == "ecOnCurve" || func == "ecModReduce" ||
  func == "ecEncodeCompressed" || func == "ecMakePoint" ||
  func == "ecPointX" || func == "ecPointY" ||
  func == "p256Add" || func == "p256Mul" || func == "p256MulGen" ||
  func == "p256Negate" || func == "p256OnCurve" ||
  func == "p256EncodeCompressed" || func == "verifyECDSA_P256" ||
  func == "p384Add" || func == "p384Mul" || func == "p384MulGen" ||
  func == "p384Negate" || func == "p384OnCurve" ||
  func == "p384EncodeCompressed" || func == "verifyECDSA_P384" ||
  func == "verifySLHDSA_SHA2_128s" || func == "verifySLHDSA_SHA2_128f" ||
  func == "verifySLHDSA_SHA2_192s" || func == "verifySLHDSA_SHA2_192f" ||
  func == "verifySLHDSA_SHA2_256s" || func == "verifySLHDSA_SHA2_256f" ||
  func == "bbFieldAdd" || func == "bbFieldSub" ||
  func == "bbFieldMul" || func == "bbFieldInv" ||
  func == "bbExt4Mul0" || func == "bbExt4Mul1" ||
  func == "bbExt4Mul2" || func == "bbExt4Mul3" ||
  func == "bbExt4Inv0" || func == "bbExt4Inv1" ||
  func == "bbExt4Inv2" || func == "bbExt4Inv3" ||
  func == "merkleRootSha256" || func == "merkleRootHash256"

-- NOTE: The abstract `lowerValueP_call_not_special` theorem cannot be proved
-- in Lean 4.29.1 because `simp only [lowerValueP]` for abstract `func` triggers
-- a whnf timeout (the well-founded fixpoint unfolding exhausts 200k heartbeats).
-- Bridge lemmas in Agrees.lean instead case-split on the concrete function name
-- first (via `rcases hFunc with rfl | ...`), then use `unfold lowerValueP` on
-- the resulting concrete `.call "abs" [x]` goal, which IS reducible cheaply.
-- See `section A4BridgeLemmas` in Agrees.lean for the implementation.

end Lower
end RunarVerification.Stack
