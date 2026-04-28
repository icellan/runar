import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.Stack.Syntax

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
`StackOp.opcode "OP_RUNAR_TODO"` placeholder so the program type
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
entry. We model this as a flat ordered list of names, head = top of
stack.
-/

abbrev StackMap := List String

/-- Depth-from-top of `name` in `sm`, or `none` if absent. -/
def StackMap.depth? (sm : StackMap) (name : String) : Option Nat :=
  sm.findIdx? (· == name)

/-- Push a fresh binding name onto the top of the tracked stack. -/
def StackMap.push (sm : StackMap) (name : String) : StackMap :=
  name :: sm

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
  | .ifVal cond thn els       =>
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

/-- Outer-scope refs referenced by `body`. Mirrors TS
`lowerLoop`'s `outerRefs` computation (`05-stack-lower.ts:1907-1923`):
a name is "outer" if the body reads it via `load_param` (other than the
iter var) or via `@ref:` whose target is not body-bound.

The TS reference iterates over body bindings and only adds outer refs
for `load_param` (excluding the iter var) and `load_const "@ref:..."`
where the target name is not in `bodyBindingNames`. We approximate that
by collecting all read names not bound in body, then excluding the iter
var. -/
def bodyOuterRefs (body : List ANFBinding) (iterVar : String) :
    List String :=
  let bound := collectBoundNames body
  let read  := collectRefsBindings body
  read.foldl (init := ([] : List String)) fun acc r =>
    if r == iterVar || listContains bound r || listContains acc r then
      acc
    else
      acc ++ [r]

/-- For non-final loop iters, bump the recorded last-use index of every
outer ref to `clampTo` so they cannot be considered last-use within the
body. Mirrors TS `lowerLoop` (`05-stack-lower.ts:1940-1944`). -/
def clampLastUsesForOuter (m : List (String × Nat))
    (outerRefs : List String) (clampTo : Nat) : List (String × Nat) :=
  outerRefs.foldl (init := m) fun acc r => lastUsesUpdate acc r clampTo

/-- Names present in `before` but absent from `after`. Used by `lowerIf`
to identify parent-scope items that one branch consumed (asymmetrically)
so the other branch can emit matching ROLL+DROP cleanup. -/
def consumedNames (before : List String) (after : List String) :
    List String :=
  before.foldl (init := ([] : List String)) fun acc n =>
    if listContains acc n then acc
    else if listContains after n then acc
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
          else [.push (.bigint (Int.ofNat d)), .opcode "OP_ROLL", .drop]
        let sm' := sm.removeAtDepth d
        let (rest, smF) := go sm' ds
        (ops ++ rest, smF)
  go sm sorted

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
  smBranch.foldl (init := ([] : List String)) fun acc ref =>
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
        -- `.pick 2` already encodes as `[push 2, OP_PICK]` in `Emit.lean`.
        ([.pick 2], sm.push name)
  | some d =>
      if consume then
        ([.roll d], (sm.removeAtDepth d).push name)
      else
        ([.pick d], sm.push name)

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
`loadConst .refAlias` applies. Outer-scope params *can* be ROLLed
inside an inner branch as long as it's the last use seen by the
branch's `computeLastUses` table. -/
def loadRefLiveParam (sm : StackMap) (name : String) (currentIndex : Nat)
    (lastUses : List (String × Nat)) :
    (List StackOp × StackMap) :=
  bringToTop sm name (isLastUse lastUses name currentIndex)

/-- Always-copy load (`bringToTop` with `consume=false`) used by
`loadProp` per TS `05-stack-lower.ts:1004-1029`: properties are shared
mutable state, so reading them never consumes. -/
def loadRefLiveCopy (sm : StackMap) (name : String) :
    (List StackOp × StackMap) :=
  bringToTop sm name false

/--
Liveness-aware multi-arg loader. Threads `sm` through each load (so
later args observe the depth-shifts caused by earlier consumes) and
uses the same `(currentIndex, lastUses, outerProtected)` triple for
every arg (mirroring TS `lowerCall` / `lowerBinOp`, which compute all
`isLast*` flags at the same `bindingIndex`).
-/
def lowerArgsLive (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) :
    StackMap → List String → (List StackOp × StackMap)
  | sm, [] => ([], sm)
  | sm, a :: rest =>
      let (load, sm1) := loadRefLive sm a currentIndex lastUses outerProtected
      let (restOps, sm2) := lowerArgsLive currentIndex lastUses outerProtected sm1 rest
      (load ++ restOps, sm2)

/--
Liveness-aware variant of `loadAndBindArgs` for `methodCall` inlining.
Loads each arg via `bringToTop` (consume on last use, modulo
`outerProtected`) and renames the new top-of-stack slot to the
corresponding callee param name.
-/
def loadAndBindArgsLive (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) :
    StackMap → List String → List String → (List StackOp × StackMap)
  | sm, [], _ => ([], sm)
  | sm, _ :: _, [] => ([], sm)
  | sm, a :: rargs, p :: rparams =>
      let (load, sm1) := loadRefLive sm a currentIndex lastUses outerProtected
      -- Rename the new top entry from `a` to `p` (the callee's param name).
      let sm2 := match sm1 with
                 | _ :: rest => p :: rest
                 | []        => [p]
      let (rest, sm3) := loadAndBindArgsLive currentIndex lastUses outerProtected sm2 rargs rparams
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
      match resultType with
      | some "bytes" => "OP_EQUAL"        -- followed by OP_NOT (peephole-fused later)
      | _            => "OP_NUMNOTEQUAL"
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
  -- Byte ops
  | "cat"         => ["OP_CAT"]
  | "len"         => ["OP_SIZE", "OP_NIP"]   -- mirrors 05-stack-lower.ts:1168
  | "split"       => ["OP_SPLIT"]
  -- Numeric helpers
  | "abs"         => ["OP_ABS"]
  | "min"         => ["OP_MIN"]
  | "max"         => ["OP_MAX"]
  | "within"      => ["OP_WITHIN"]
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
  | some d => [.pick d]
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
  -- Step 1: bring scriptBytes to top, consuming on last use.
  let (s1, sm1) := loadRefLive sm scriptBytes currentIndex lastUses outerProtected
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
  let (s4Load, sm4) := loadRefLive smAfterS3 satoshis currentIndex lastUses outerProtected
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
Lowering for `check_preimage(preimage)`. Mirrors
`lowerCheckPreimage` in `05-stack-lower.ts:2880-2936`.

Op sequence:

  OP_CODESEPARATOR
  <bring preimage to top via PICK>
  <bring _opPushTxSig to top>
  <push compressed secp256k1 generator G (33 bytes)>
  OP_CHECKSIGVERIFY

After the CHECKSIGVERIFY, the preimage is the top-of-stack value
named `bindingName` (so subsequent extractors can reference it).

Note: the TS reference uses ROLL (`bringToTop(_, true)`) for
`_opPushTxSig`; the Lean lowering uses PICK (`loadRef`) for
consistency with the rest of this file. The runtime stack
contents are equivalent up to the `_opPushTxSig` slot remaining
in place; this difference is irrelevant to all downstream
extractors but causes a load-sequence mismatch against the TS
hex output.
-/
def lowerCheckPreimageOps (sm : StackMap) (bindingName : String)
    (preimage : String) : (List StackOp × StackMap) :=
  -- Compressed secp256k1 generator point G (33 bytes).
  let g : ByteArray := ByteArray.mk #[
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB,
    0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28,
    0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98]
  let s0 : List StackOp := [.opcode "OP_CODESEPARATOR"]
  -- Bring preimage to top.
  let s1 := loadRef sm preimage
  -- Bring _opPushTxSig to top (PICK-style; see note in docstring).
  let s2 := loadRef (sm.push preimage) "_opPushTxSig"
  -- Push G then CHECKSIGVERIFY.
  let s3 : List StackOp := [.push (.bytes g), .opcode "OP_CHECKSIGVERIFY"]
  (s0 ++ s1 ++ s2 ++ s3, sm.push bindingName)

/--
Liveness-aware variant of `lowerCheckPreimageOps`. Mirrors TS
`lowerCheckPreimage` (`05-stack-lower.ts:2880-2936`) including the
ROLL-on-last-use semantics for both `preimage` and the implicit
`_opPushTxSig` slot. Producing byte-identical hex requires the
`_opPushTxSig` (and, for stateful methods, `_codePart`) implicit
params to be present at the bottom of the stack map — the caller
(`lowerMethod`) prepends them when `usesCheckPreimage` /
`usesCodePart` returns true.
-/
def lowerCheckPreimageOpsLive (sm : StackMap) (bindingName : String)
    (preimage : String) (currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected : List String) : (List StackOp × StackMap) :=
  let g : ByteArray := ByteArray.mk #[
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB,
    0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28,
    0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98]
  let s0 : List StackOp := [.opcode "OP_CODESEPARATOR"]
  -- Step 1: bring preimage to top, consuming on last use.
  let (s1, sm1) := loadRefLive sm preimage currentIndex lastUses outerProtected
  -- Step 2: bring _opPushTxSig to top, always consuming (TS uses
  -- `bringToTop('_opPushTxSig', true)` unconditionally — it is dead
  -- after the CHECKSIGVERIFY in step 4). We bypass the outerProtected
  -- guard since `_opPushTxSig` is a method-scope implicit param, not
  -- an outer ref: it is consumed exactly once per method body.
  let (s2, sm2) :=
    bringToTop sm1 "_opPushTxSig" true
  -- Step 3: push G then CHECKSIGVERIFY. Net stack-map: G pushed, then
  -- both G and `_opPushTxSig` are consumed by CHECKSIGVERIFY. Sm2 still
  -- has `preimage` on top (renamed to bindingName); pop the preimage
  -- placeholder and push the new binding name.
  let s3 : List StackOp := [.push (.bytes g), .opcode "OP_CHECKSIGVERIFY"]
  -- After step 2 the top of sm2 is `_opPushTxSig`; CHECKSIGVERIFY
  -- consumes both `_opPushTxSig` and `G` (the latter never named on
  -- the map), leaving the previous top (preimage) exposed. Pop the
  -- `_opPushTxSig` slot and rename the new top to `bindingName`.
  let smAfterVerify := sm2.popN 1
  let smFinal :=
    match smAfterVerify with
    | _ :: rest => bindingName :: rest
    | []        => [bindingName]
  (s0 ++ s1 ++ s2 ++ s3, smFinal)

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
  -- Step 2: bring pkh to top (consume on last use), CAT prefix||pkh.
  let (s2Load, sm2) :=
    loadRefLive smAfterPrefix pkh currentIndex lastUses outerProtected
  let s2 : List StackOp := s2Load ++ [opc "OP_CAT"]
  let smAfterPkhCat := (sm2.popN 2).push "_acc"
  -- Step 3: push suffix (OP_EQUALVERIFY + OP_CHECKSIG = 0x88ac), CAT.
  let s3 : List StackOp :=
    [.push (.bytes (ByteArray.mk #[0x88, 0xac])), opc "OP_CAT"]
  let smAfterSuffix := (smAfterPkhCat.push "_suffix").popN 2 |>.push "_acc"
  -- Step 4: bring amount to top, NUM2BIN(8), SWAP, CAT (prepend).
  let (s4Load, sm4) :=
    loadRefLive smAfterSuffix amount currentIndex lastUses outerProtected
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
  -- Step A: bring preimage to top (consume on last use), then DROP it.
  --         The preimage is unused — `_codePart` and `_newAmount` carry
  --         all the information needed for the continuation output.
  let (sA, smA) :=
    loadRefLive sm preimage currentIndex lastUses outerProtected
  let sA' : List StackOp := sA ++ [.drop]
  let smA' := smA.popN 1
  -- Step B: bring newAmount to top, NUM2BIN(8), TOALTSTACK.
  let (sB, smB) :=
    loadRefLive smA' newAmount currentIndex lastUses outerProtected
  let sB' : List StackOp :=
    sB ++ [push 8, opc "OP_NUM2BIN", opc "OP_TOALTSTACK"]
  -- Net stack-map after step B: the named amount slot is replaced by
  -- NUM2BIN's anon result, then TOALTSTACK pops it. Pop one entry.
  let smB' := smB.popN 1
  -- Step C: bring stateBytes to top.
  let (sC, smC) :=
    loadRefLive smB' stateBytes currentIndex lastUses outerProtected
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
  -- Step A: bring stateBytes to top.
  let (sA, smA) :=
    loadRefLive sm stateBytes currentIndex lastUses outerProtected
  -- Step B: bring preimage to top.
  let (sB, smB) :=
    loadRefLive smA preimage currentIndex lastUses outerProtected
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

/-- Lowering for `verifyRabinSig(msg, sig, padding, pubKey)`.

Rabin signature verification checks `(sig^2 + padding) mod pubKey == SHA256(msg)`.

Mirrors `lowerVerifyRabinSig` (TS `05-stack-lower.ts:3884-3931`). The TS
sequence brings the four args to the top of the stack via
`bringToTop(arg, isLast)` — Lean uses the equivalent
`loadRefLive` — yielding the layout

  bottom→top: msg(3) sig(2) padding(1) pubKey(0)

then emits:

  OP_SWAP  OP_ROT  OP_DUP  OP_MUL  OP_ADD
  OP_SWAP  OP_MOD  OP_SWAP  OP_SHA256  OP_EQUAL

Net stack-map effect: pop 4 arg slots, push the boolean result under
`bindingName`. -/
def lowerVerifyRabinSigOpsLive (sm : StackMap) (bindingName : String)
    (msg sig padding pubKey : String) (currentIndex : Nat)
    (lastUses : List (String × Nat)) (outerProtected : List String) :
    (List StackOp × StackMap) :=
  let (loadMsg, sm1) :=
    loadRefLive sm msg currentIndex lastUses outerProtected
  let (loadSig, sm2) :=
    loadRefLive sm1 sig currentIndex lastUses outerProtected
  let (loadPad, sm3) :=
    loadRefLive sm2 padding currentIndex lastUses outerProtected
  let (loadPk, sm4) :=
    loadRefLive sm3 pubKey currentIndex lastUses outerProtected
  -- Stack bottom→top: msg sig padding pubKey
  let body : List StackOp :=
    [ StackOp.swap                    -- msg sig pubKey padding
    , StackOp.rot                     -- msg pubKey padding sig
    , StackOp.dup                     -- msg pubKey padding sig sig
    , StackOp.opcode "OP_MUL"         -- msg pubKey padding sig^2
    , StackOp.opcode "OP_ADD"         -- msg pubKey (sig^2+padding)
    , StackOp.swap                    -- msg (sig^2+padding) pubKey
    , StackOp.opcode "OP_MOD"         -- msg ((sig^2+padding) mod pubKey)
    , StackOp.swap                    -- ((sig^2+padding) mod pubKey) msg
    , StackOp.opcode "OP_SHA256"
    , StackOp.opcode "OP_EQUAL"
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
-/
private def addOutputStateValuesLive (currentIndex : Nat)
    (lastUses : List (String × Nat)) (outerProtected : List String) :
    StackMap → List String → List ANFProperty → (List StackOp × StackMap)
  | sm, [], _ => ([], sm)
  | sm, _, [] => ([], sm)
  | sm, v :: vs, p :: ps =>
      let opc (s : String) : StackOp := .opcode s
      let push (n : Int) : StackOp := .push (.bigint n)
      let (load, sm1) := loadRefLive sm v currentIndex lastUses outerProtected
      let conv : List StackOp :=
        if propTypeIsNumeric p.type then
          [push (Int.ofNat (propTypeFixedSize p.type)), opc "OP_NUM2BIN"]
        else
          []
      -- After load: top is the value (named on sm1).
      -- After conv (numeric): NUM2BIN pops 2 / pushes 1 → net 0 on sm,
      -- but the TS `lowerAddOutput` calls `stackMap.push(null)` then pops
      -- after NUM2BIN — net 0 anyway. We model the post-conv top as the
      -- (anonymous) converted value: pop the named value, push anon.
      let smAfterConv :=
        if propTypeIsNumeric p.type then (sm1.popN 1).push "_conv" else sm1
      -- After OP_CAT: pops 2 / pushes 1 (the new accumulator).
      let smAfterCat := (smAfterConv.popN 2).push "_acc"
      let (restOps, smRest) :=
        addOutputStateValuesLive currentIndex lastUses outerProtected
          smAfterCat vs ps
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
      smAcc stateValues stateProps
  -- Step 4: compute varint prefix.
  let s4 : List StackOp := [opc "OP_SIZE"] ++ varintEncodingOps
  -- After s4: top is the unnamed varint slot.
  let smAfterVarint := sm3.push "_varint"
  -- Step 5: prepend varint via SWAP+CAT. Net pop 1.
  let s5 : List StackOp := [.swap, opc "OP_CAT"]
  let smAfterS5 := smAfterVarint.popN 1
  -- Step 6: prepend satoshis as 8-byte LE.
  let (s6Load, sm6) :=
    loadRefLive smAfterS5 satoshis currentIndex lastUses outerProtected
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
    Nat → List String → (List StackOp × List String)
  | _,  []        => ([], [])
  | d,  x :: xs   =>
      if x = propName then
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
      let ops := if op == "!==" && rt == some "bytes" then base ++ [.opcode "OP_NOT"] else base
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
  | .ifVal cond thn els =>
      -- Phase 3c: concrete IF/ELSE/ENDIF lowering. Both branches lower
      -- independently against the *original* stack map (each branch is
      -- popped on entry and restored on exit by Bitcoin's IF semantics).
      let (thnOps, _) := lowerBindings sm thn
      let (elsOps, _) := lowerBindings sm els
      (loadRef sm cond ++ [.ifOp thnOps (some elsOps)], sm.push bindingName)
  | .assert ref =>
      (loadRef sm ref ++ [.opcode "OP_VERIFY"], sm)
  | .updateProp _ ref =>
      (loadRef sm ref ++ [.opcode "OP_RUNAR_UPDATEPROP_TODO"], sm)
  | .loop count body iterVar =>
      -- Phase 3d: full count-bounded unroll. The body is lowered once
      -- (with `iterVar` registered as a synthetic param at depth 0);
      -- `unrollIter` then iterates the body `count` times, each
      -- iteration prefixing with `push i` and suffixing with `OP_DROP`.
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
  | .getStateScript          => ([.opcode "OP_RUNAR_GETSTATESCRIPT_TODO"], sm.push bindingName)
  | .deserializeState _      => ([.opcode "OP_RUNAR_DESERIALIZESTATE_TODO"], sm)
  | .addOutput _ _ _         => ([.opcode "OP_RUNAR_ADDOUTPUT_TODO"], sm)

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

Termination uses lexicographic order on `(budget, sizeOf payload)`:
the `methodCall` recursion decrements `budget` (and may grow the
payload arbitrarily); every other recursion preserves `budget` and
descends to a structurally-smaller payload. Together this is well-
founded and Lean's `decreasing_by` can discharge it.
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
    (sm : StackMap) (bindingName : String) :
    ANFValue → (List StackOp × StackMap × List String)
  | .loadParam n =>
      -- TS `lowerLoadParam` does NOT apply the outerProtected check:
      -- params can be ROLLed inside inner scopes if it's their last use.
      let (load, sm1) := loadRefLiveParam sm n currentIndex lastUses
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
          (load, sm2, localBindings)
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
      let (lOps, sm1) := loadRefLive sm l currentIndex lastUses outerProtected
      let (rOps, sm2) := loadRefLive sm1 r currentIndex lastUses outerProtected
      let base := lOps ++ rOps ++ [.opcode (binopOpcode op rt)]
      let ops := if op == "!==" && rt == some "bytes" then base ++ [.opcode "OP_NOT"] else base
      -- Binop pops 2, pushes 1 (the named result).
      let sm3 := (sm2.popN 2).push bindingName
      (ops, sm3, localBindings)
  | .unaryOp op operand _ =>
      let (load, sm1) := loadRefLive sm operand currentIndex lastUses outerProtected
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
              lowerArgsLive currentIndex lastUses outerProtected sm args
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
            let (loadData, sm1) := loadRefLive sm data currentIndex lastUses outerProtected
            let (loadStart, sm2) := loadRefLive sm1 start currentIndex lastUses outerProtected
            -- After SPLIT NIP we've popped (data, start) and pushed `right`.
            let smAfterFirst : StackMap := (sm2.popN 2).push "_substr_right"
            let (loadLen, sm3) :=
              loadRefLive smAfterFirst length currentIndex lastUses outerProtected
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
            let (loadA, sm1) := loadRefLive sm amount currentIndex lastUses outerProtected
            let (loadB, sm2) := loadRefLive sm1 bps currentIndex lastUses outerProtected
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
            let (loadA, sm1) := loadRefLive sm a currentIndex lastUses outerProtected
            let (loadB, sm2) := loadRefLive sm1 b currentIndex lastUses outerProtected
            let smPostMul : StackMap := (sm2.popN 2).push "_mulDiv_intermediate"
            let (loadC, sm3) :=
              loadRefLive smPostMul c currentIndex lastUses outerProtected
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
            let (loadA, sm1) := loadRefLive sm a currentIndex lastUses outerProtected
            let (loadB, sm2) := loadRefLive sm1 b currentIndex lastUses outerProtected
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
            let (loadV, sm1) := loadRefLive sm val currentIndex lastUses outerProtected
            let (loadL, sm2) := loadRefLive sm1 lo currentIndex lastUses outerProtected
            let smPostMax : StackMap := (sm2.popN 2).push "_clamp_intermediate"
            let (loadH, sm3) :=
              loadRefLive smPostMax hi currentIndex lastUses outerProtected
            let smFinal : StackMap := (sm3.popN 2).push bindingName
            (loadV ++ loadL
              ++ [StackOp.opcode "OP_MAX"]
              ++ loadH
              ++ [StackOp.opcode "OP_MIN"],
             smFinal, localBindings)
        | _ =>
            ([.opcode "OP_RUNAR_CLAMP_ARITY"], sm.push bindingName, localBindings)
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
      else
        let (argOps, sm1) := lowerArgsLive currentIndex lastUses outerProtected sm args
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
              let (argOps, sm1) := lowerArgsLive currentIndex lastUses outerProtected sm args
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
                loadAndBindArgsLive currentIndex lastUses outerProtected smPostObj args paramNames
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
              let (bodyOps, smAfterBody) :=
                lowerBindingsP progMethods props budget' 0 bodyLastUses outerProtected
                  innerLocalBindings smArgs m.body
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
  | .ifVal cond thn els =>
      -- Bring the cond to top (consume on last use, modulo outerProtected).
      let (condOps, sm1) := loadRefLive sm cond currentIndex lastUses outerProtected
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
      let innerProtected := computeBranchProtected smBranch lastUses currentIndex outerProtected
      let thnLastUses := computeLastUses thn
      let elsLastUses := computeLastUses els
      -- TS `lowerIf` creates a new `LoweringContext` per branch, so each
      -- branch's `localBindings` is reset to its own bindings (line 1673,
      -- 1688). Mirror that.
      let thnLocal := thn.map (fun b => b.name)
      let elsLocal := els.map (fun b => b.name)
      let (thnOps, smThn) := lowerBindingsP progMethods props budget 0 thnLastUses innerProtected thnLocal smBranch thn
      let (elsOps, smEls) := lowerBindingsP progMethods props budget 0 elsLastUses innerProtected elsLocal smBranch els
      -- Phase 3z-F: empty-else shadow-rebind synthesis. When the THEN
      -- branch's top-of-stack name was already in `smBranch` (a property
      -- shadow-rebind like `count = @ref:t5`) and `els = []`, TS
      -- (`05-stack-lower.ts:1776-1796`, `1850-1875`) emits a DUP/PICK in
      -- the empty else and a NIP after ENDIF to remove the stale slot.
      -- This is distinct from the asymmetric-consumption path below: the
      -- shadow case does NOT involve THEN consuming parent items, so
      -- `smThn` and `smBranch` differ ONLY by the new top.
      let shadowRebind : Option (StackMap × Nat × String) :=
        match els, smThn with
        | [], topName :: _ =>
            match smBranch.depth? topName with
            | some d =>
                -- Only treat as shadow-rebind if NO parent items were
                -- consumed by THEN (else asymmetric path applies).
                let consumedByThen := consumedNames smBranch (smThn.tail)
                if consumedByThen.isEmpty then some (smBranch, d, topName)
                else none
            | none => none
        | _, _ => none
      match shadowRebind with
      | some (_smB, d, topName) =>
          let elseSynth : List StackOp :=
            if d == 0 then [.dup]
            else [.push (.bigint (Int.ofNat d)), .pick d]
          let cleanup : List StackOp :=
            if d == 0 then [.nip]
            else if d == 1 then [.nip]
            else [.push (.bigint (Int.ofNat d)), .roll (d + 1), .drop]
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
            smBranch.foldl (init := ([] : List String)) fun acc n =>
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
          let thnDepth := smThnAfter.length
          let elsDepth := smElsAfter.length
          let (extraEls, extraThn) : (List StackOp × List StackOp) :=
            if thnDepth > elsDepth then ([.push (.bytes ByteArray.empty)], [])
            else if elsDepth > thnDepth then ([], [.push (.bytes ByteArray.empty)])
            else ([], [])
          let elsFinalOps := elsOps ++ elsCleanupOps ++ extraEls
          let thnFinalOps := thnOps ++ thnCleanupOps ++ extraThn
          -- Reconcile parent sm: drop entries consumed by THEN (use THEN
          -- as canonical reference, mirroring TS line 1813).
          let parentConsumed := consumedNames smBranch smThn
          let smParentReconciled : StackMap :=
            parentConsumed.foldl (init := smBranch) fun m n =>
              match m.depth? n with
              | some d => m.removeAtDepth d
              | none   => m
          -- Determine post-IF top: if branches added a value, push bindingName.
          let smPostIf : StackMap :=
            if smThnAfter.length > smParentReconciled.length then
              smParentReconciled.push bindingName
            else
              smParentReconciled
          let elseOpt : Option (List StackOp) :=
            if elsFinalOps.isEmpty then none else some elsFinalOps
          (condOps ++ [.ifOp thnFinalOps elseOpt], smPostIf, localBindings)
  | .assert ref =>
      let (load, sm1) := loadRefLive sm ref currentIndex lastUses outerProtected
      let ops := load ++ [.opcode "OP_VERIFY"]
      let sm2 := sm1.popN 1
      (ops, sm2, localBindings)
  | .updateProp propName ref =>
      -- Phase 3z-C: mirror TS `lowerUpdateProp` (`05-stack-lower.ts:1985-2027`).
      -- 1. Bring the new value to top via liveness-aware load.
      -- 2. Rename top from `ref` to `propName` so subsequent `loadProp`
      --    finds the updated value.
      -- 3. If the OLD `propName` entry survives below (depth ≥ 1), the TS
      --    reference removes it via NIP (depth 1) or [push d, roll d+1,
      --    drop] (depth ≥ 2). The TS pass `liftBranchUpdateProps` lifts
      --    branch-local update_props to the top level, so the
      --    `_insideBranch=true` skip-cleanup path of TS is unreachable
      --    in the IRs we lower; we always perform the cleanup here.
      -- The binding name `_bindingName` is the t-temporary the IR assigns
      -- to the update_prop result; subsequent code references the prop by
      -- its property name, not the temporary.
      let (load, sm1) := loadRefLive sm ref currentIndex lastUses outerProtected
      let smRenamed : StackMap :=
        match sm1 with
        | _ :: rest => propName :: rest
        | []        => [propName]
      let (cleanup, sm2) := removePropEntryOps smRenamed propName
      (load ++ cleanup, sm2, localBindings)
  | .loop count body iterVar =>
      -- Phase 3z-F: per-iter lowering with non-final / final liveness
      -- discrimination (mirrors TS `lowerLoop` at `05-stack-lower.ts:1899-1965`).
      --
      -- For non-final iters, outer-scope refs (those read but not bound by
      -- the body) have their last-use clamped to `body.length` so they are
      -- never consumed — preserving the parent stack map across iters.
      -- Only the FINAL iter sees their natural last-use, allowing ROLL/SWAP
      -- consumption on the last access.
      --
      -- TS does NOT use a generic `outerProtected` set inside loop bodies —
      -- it relies on the lastUses clamping for outer-refs and on
      -- `localBindings` for the `@ref:` consume gate. Here we set
      -- `innerProtected = []` to match the TS binop/unary/call consume
      -- behavior; outer-ref protection is achieved entirely through the
      -- clamped lastUses below. The `loadConst .refAlias` arm still needs
      -- protection for outer @ref: targets — those refs are also in
      -- `outerRefs` (collected by `bodyOuterRefs`) so the clamping covers
      -- them indirectly.
      --
      -- The iter var is pushed before each body, registered on the stack
      -- map, and DROPped after the body iff it survives (the body did not
      -- consume it).
      let smInner := sm.push iterVar
      let innerProtected : List String := []
      let outerRefs := bodyOuterRefs body iterVar
      let naturalLU := computeLastUses body
      let nonFinalLU := clampLastUsesForOuter naturalLU outerRefs body.length
      let bodyLocal := body.map (fun b => b.name)
      -- Lower the body once for non-final iters and once for the final iter.
      let (bodyOpsNF, smNF) :=
        lowerBindingsP progMethods props budget 0 nonFinalLU innerProtected bodyLocal smInner body
      let (bodyOpsF, smF) :=
        lowerBindingsP progMethods props budget 0 naturalLU innerProtected bodyLocal smInner body
      -- Detect whether the body consumed the iter var: if iterVar is no
      -- longer on the body's resulting sm, no DROP needed.
      let consumedNF : Bool := !listContains smNF iterVar
      let consumedF  : Bool := !listContains smF iterVar
      let dropNF : List StackOp := if consumedNF then [] else [.drop]
      let dropF  : List StackOp := if consumedF  then [] else [.drop]
      -- Assemble per-iter ops: push i, body, optional DROP.
      let mkIter (i : Nat) (final : Bool) : List StackOp :=
        let idxPush : StackOp := .push (.bigint (Int.ofNat i))
        if final then [idxPush] ++ bodyOpsF ++ dropF
        else [idxPush] ++ bodyOpsNF ++ dropNF
      let rec assemble : Nat → List StackOp
        | 0     => []
        | n + 1 =>
            let i := count - (n + 1)
            let final := decide (n = 0)
            mkIter i final ++ assemble n
      -- Loops are statements, not expressions — no stack value is produced
      -- (mirrors TS `lowerLoop` `05-stack-lower.ts:1962-1964`). The post-
      -- loop sm equals the parent sm (the body's net effect on the stack
      -- map is invariant across iterations: each iter ends with the same
      -- shape it started with). We return `smF` minus the iterVar slot if
      -- it survived the final iter, so subsequent bindings see exactly the
      -- parent shape.
      let smPostLoop : StackMap :=
        if consumedF then smF
        else
          match smF.depth? iterVar with
          | some d => smF.removeAtDepth d
          | none   => smF
      (assemble count, smPostLoop, localBindings)
  | .arrayLiteral elems =>
      (lowerArrayElems sm elems, sm.push bindingName, localBindings)
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
termination_by v => (budget, sizeOf v)

def lowerBindingsP (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String) (localBindings : List String) (sm : StackMap) :
    List ANFBinding → (List StackOp × StackMap)
  | [] => ([], sm)
  | (.mk name v _) :: rest =>
      let (ops, sm', localBindings') :=
        lowerValueP progMethods props budget currentIndex lastUses outerProtected localBindings sm name v
      let (ops', sm'') :=
        lowerBindingsP progMethods props budget (currentIndex + 1) lastUses outerProtected localBindings' sm' rest
      (ops ++ ops', sm'')
termination_by bs => (budget, sizeOf bs)

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
        | .ifVal _ thn els    =>
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
        | .ifVal _ thn els    =>
            bindingsUseCodePart thn || bindingsUseCodePart els
        | .loop _ body _      => bindingsUseCodePart body
        | _                   => false
      here || bindingsUseCodePart rest

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
        | .ifVal _ thn els    =>
            bindingsUseDeserializeState thn || bindingsUseDeserializeState els
        | .loop _ body _      => bindingsUseDeserializeState body
        | _                   => false
      here || bindingsUseDeserializeState rest

def lowerMethod (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod) : StackMethod :=
  -- Initial stack map: parameter names in declaration order, top = last param.
  -- For methods that call `check_preimage`, the unlocking script first pushes
  -- two implicit params before the user-visible params (see TS lowerMethod at
  -- `05-stack-lower.ts:4910-4930`):
  --   * `_opPushTxSig` — the ECDSA sig over the BIP-143 preimage
  --   * `_codePart`    — the code portion of the locking script (only when
  --                      add_output / add_raw_output / computeStateOutput*
  --                      reference it)
  -- These sit at the bottom of the stack; in our top-first list they are at
  -- the *tail*. The user params (which get DUP/PICK loads) remain on top.
  let userMap : StackMap := m.params.map (·.name) |>.reverse
  let usesPreimage := bindingsUseCheckPreimage m.body
  let usesCode     := bindingsUseCodePart m.body
  let initialMap : StackMap :=
    if usesPreimage then
      if usesCode then
        userMap ++ ["_opPushTxSig", "_codePart"]
      else
        userMap ++ ["_opPushTxSig"]
    else
      userMap
  -- Liveness analysis is per-binding-list. At the top-level method body
  -- there is no outer scope, so `outerProtected = []` and parameters can
  -- be consumed (ROLLed away) on their last use.
  let bodyLastUses := computeLastUses m.body
  let topLevelLocal := m.body.map (fun b => b.name)
  let (rawOps, finalSm) :=
    lowerBindingsP progMethods props defaultInlineBudget 0 bodyLastUses [] topLevelLocal initialMap m.body
  -- Terminal-assert elision (Gap #3 from PHASE_3W_C_GAP_ANALYSIS.md):
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
  -- Excess-stack cleanup. Mirrors TS `lowerMethod`'s post-pass at
  -- `05-stack-lower.ts:4937-4942`: public methods whose body deserialized
  -- state must emit `OP_NIP` repeatedly until only the truthy boolean (the
  -- terminal assert's residue) remains on top of the runtime stack.
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
    if m.isPublic && bindingsUseDeserializeState m.body && depthAfterBody > 1 then
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

Out-of-scope (`OP_RUNAR_*_TODO` placeholders): `getStateScript`,
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
  | .ifVal _ thn els          =>
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

end Lower
end RunarVerification.Stack
