/-!
# Stack IR — Syntax

Lean 4 inductive definitions for the Rúnar Stack IR (Pass 5 output).

Mirrors `packages/runar-ir-schema/src/stack-ir.ts:1–128` 1:1 — fourteen
discriminator constructors, each capturing exactly the fields produced by
the TypeScript reference lowering pass.

Stack IR is *compiler-specific*: the conformance boundary uses ANF on
the input side and the emitted Bitcoin Script on the output side, with
no Stack IR golden in `conformance/tests/`. The Lean Stack IR therefore
exists only to support the simulation proofs in `Sim.lean`, the
peephole soundness proofs in `Peephole.lean`, and the byte-emission
proof in `Script/Emit.lean`.
-/

namespace RunarVerification.Stack

/-- Optional source location for debug source maps. -/
structure StackSourceLoc where
  file : String
  line : Nat
  column : Nat
  deriving Repr, BEq, Inhabited

/-! ## Push values

The TypeScript `PushOp.value` is `Uint8Array | bigint | boolean`. We
model that as a closed sum so the Lean evaluator can dispatch on the
payload kind without having to consult a runtime type tag.
-/

inductive PushVal where
  | bigint (i : Int)         : PushVal
  | bool   (b : Bool)        : PushVal
  | bytes  (b : ByteArray)   : PushVal
  deriving Inhabited

instance : Repr PushVal where
  reprPrec v _ := match v with
    | .bigint i => s!"PushVal.bigint {i}"
    | .bool b   => s!"PushVal.bool {b}"
    | .bytes _  => "PushVal.bytes <…>"

/-! ## Stack operations -/

/--
A single Stack-IR instruction. Constructors mirror the discriminator
strings in `StackOp` from `stack-ir.ts`:

| Lean constructor    | TS `op` value         |
|---------------------|-----------------------|
| `push`              | `'push'`              |
| `dup`               | `'dup'`               |
| `swap`              | `'swap'`              |
| `roll`              | `'roll'`              |
| `pick`              | `'pick'`              |
| `pickStruct`        | (Lean-only; same bytes as `pick`) |
| `drop`              | `'drop'`              |
| `nip`               | `'nip'`               |
| `over`              | `'over'`              |
| `rot`               | `'rot'`               |
| `tuck`              | `'tuck'`              |
| `opcode`            | `'opcode'`            |
| `ifOp`              | `'if'`                |
| `placeholder`       | `'placeholder'`       |
| `pushCodesepIndex`  | `'push_codesep_index'`|
-/
inductive StackOp where
  | push (val : PushVal) : StackOp
  | dup : StackOp
  | swap : StackOp
  | roll (depth : Nat) : StackOp
  | pick (depth : Nat) : StackOp
  /--
  Structural pick (no-pop). Same emitted bytes as `pick d`
  (`[push d, OP_PICK]`), but the runtime semantics are no-pop:
  copy the value at structural depth `d` to the top of the stack
  without first consuming a runtime depth value.

  Used by `Stack.Lower.loadRef` and crypto codegen modules where
  the lowering does *not* push the depth as a separate stack op
  before the pick. The byte-level encoding remains identical to
  `.pick d` because `OP_PICK` itself reads the depth from a
  bytecode-level push that `Script.Emit` synthesises.

  `pick d` retains its pop semantics so existing peephole
  `_pass_sound` proofs (Phase 3z-B refactor) are unaffected.
  -/
  | pickStruct (depth : Nat) : StackOp
  | drop : StackOp
  | nip : StackOp
  | over : StackOp
  | rot : StackOp
  | tuck : StackOp
  /--
  A primitive Bitcoin Script opcode by name. The reference compiler
  produces strings like `OP_ADD`, `OP_CHECKSIG`, `OP_CAT`, etc. We keep
  the string form here (rather than enumerating opcodes inline) so that
  the Stack/Eval dispatch shares its opcode table with `Script/Emit`'s
  encoding table.
  -/
  | opcode (code : String) : StackOp
  /-- An if-then-else block. Both branches are themselves Stack op lists. -/
  | ifOp (thenBranch : List StackOp) (elseBranch : Option (List StackOp)) : StackOp
  /--
  Constructor parameter slot. Emits `OP_0` (a single zero byte) but
  records the byte-offset in `EmitResult.constructorSlots` so the SDK
  can splice the real argument in at deploy time.
  -/
  | placeholder (paramIndex : Nat) (paramName : String) : StackOp
  /--
  CodeSep index slot. Like `placeholder`, emits `OP_0` but records the
  byte-offset in `EmitResult.codeSepIndexSlots` so the SDK can splice
  in the OP_CODESEPARATOR index for state-method dispatch.
  -/
  | pushCodesepIndex : StackOp
  /--
  Raw script bytes verbatim. Lowered from an ANF `raw_script` value,
  it emits the carried bytes directly with no opcode prefix and
  evaluates by pushing the bytes onto the stack as a `vBytes` value.
  Used by the `asm-raw-script` fixture family so the compiler can
  splice in pre-encoded scriptlets without round-tripping through
  the named-opcode table.
  -/
  | rawBytes (bytes : ByteArray) : StackOp
  deriving Inhabited

/-! ## Containers

A `StackMethod` is the lowered form of one ANF method; a `StackProgram`
is the lowered form of a whole `ANFProgram`. The `maxStackDepth` field
matches the TS reference and is consumed by the emit pass for diagnostic
output (it is *not* part of the byte-exact correctness theorem).
-/

structure StackMethod where
  name : String
  ops : List StackOp
  maxStackDepth : Nat := 0
  deriving Inhabited

structure StackProgram where
  contractName : String
  methods : List StackMethod
  deriving Inhabited

namespace StackProgram

/-- Find the lowered form of a method by name. -/
def findMethod (p : StackProgram) (name : String) : Option StackMethod :=
  p.methods.find? (·.name == name)

/-- The flat op list of a named method, or `[]` if absent. -/
def bodyOf (p : StackProgram) (name : String) : List StackOp :=
  match p.findMethod name with
  | some m => m.ops
  | none   => []

end StackProgram

end RunarVerification.Stack
