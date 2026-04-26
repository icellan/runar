/-!
# ANF IR — Syntax

Lean 4 inductive definitions for the Rúnar ANF IR.

Mirrors `packages/runar-ir-schema/src/anf-ir.ts` and the JSON Schema at
`packages/runar-ir-schema/src/schemas/anf-ir.schema.json` 1:1, with two
deliberate refinements (decided as open questions OQ-1 and OQ-6 in
`EXPLORATION.md`):

* `ConstValue` is a closed sum that distinguishes literal integers / bools /
  byte-strings from the two compile-time markers `@ref:NAME` and `@this`
  that the canonical IR encodes as magic strings inside `LoadConst.value`.
* `ANFType` is a closed inductive over the v0.x type vocabulary.

The TypeScript-side `kind` field becomes the constructor name; the JSON
field names are documented above each constructor and are produced
verbatim by `Json.lean`.
-/

namespace RunarVerification.ANF

/-! ## Source locations (debug-only — excluded from conformance) -/

structure SourceLoc where
  file : String
  line : Nat
  column : Nat
  deriving Repr, BEq, Inhabited

/-! ## Refined constant values (OQ-1: first-class) -/

/--
The set of values that may appear inside `LoadConst.value` (or in
`ANFProperty.initialValue`). The schema permits `string ∪ integer ∪ boolean`;
the string form has three sub-flavors that we surface as distinct
constructors:

* literal byte-strings, encoded as `0x…` hex on the wire,
* `@ref:NAME` aliases (zero-cost rename of an in-scope binding),
* `@this`, the contract instance marker.

Property `initialValue`s only ever use `int`, `bool`, or `bytes` —
`refAlias` and `thisRef` make no sense as property defaults and are
excluded by the well-formedness predicate.
-/
inductive ConstValue where
  | int      : Int → ConstValue
  | bool     : Bool → ConstValue
  | bytes    : ByteArray → ConstValue
  | refAlias : String → ConstValue
  | thisRef  : ConstValue
  deriving Inhabited

instance : Repr ConstValue where
  reprPrec v _ := match v with
    | .int i      => s!"ConstValue.int {i}"
    | .bool b     => s!"ConstValue.bool {b}"
    | .bytes _    => "ConstValue.bytes <…>"
    | .refAlias n => s!"ConstValue.refAlias {n}"
    | .thisRef    => "ConstValue.thisRef"

/-! ## Type vocabulary (OQ-6: closed sum) -/

/--
The closed set of v0.x ANF types. Adding a new variant requires a Lean
edit and re-deriving any `Decidable` instances; see the package README
for the extension protocol.
-/
inductive ANFType where
  | bigint
  | bool
  | byteString
  | pubKey
  | sig
  | sha256
  | ripemd160
  | addr
  | sigHashPreimage
  | point        -- secp256k1 (64 B: x ‖ y)
  | p256Point
  | p384Point
  | rabinPubKey
  | rabinSig
  deriving Repr, BEq, DecidableEq, Inhabited

namespace ANFType

/-- Parse the canonical type-string used in ANFParam / ANFProperty. -/
def fromString? : String → Option ANFType
  | "bigint"          => some .bigint
  | "boolean"         => some .bool
  | "ByteString"      => some .byteString
  | "PubKey"          => some .pubKey
  | "Sig"             => some .sig
  | "Sha256"          => some .sha256
  | "Ripemd160"       => some .ripemd160
  | "Addr"            => some .addr
  | "SigHashPreimage" => some .sigHashPreimage
  | "Point"           => some .point
  | "P256Point"       => some .p256Point
  | "P384Point"       => some .p384Point
  | "RabinPubKey"     => some .rabinPubKey
  | "RabinSig"        => some .rabinSig
  | _                 => none

/-- Round-trip back to the canonical type-string. -/
def toString : ANFType → String
  | .bigint          => "bigint"
  | .bool            => "boolean"
  | .byteString      => "ByteString"
  | .pubKey          => "PubKey"
  | .sig             => "Sig"
  | .sha256          => "Sha256"
  | .ripemd160       => "Ripemd160"
  | .addr            => "Addr"
  | .sigHashPreimage => "SigHashPreimage"
  | .point           => "Point"
  | .p256Point       => "P256Point"
  | .p384Point       => "P384Point"
  | .rabinPubKey     => "RabinPubKey"
  | .rabinSig        => "RabinSig"

instance : ToString ANFType := ⟨ANFType.toString⟩

theorem fromString_toString (t : ANFType) : fromString? t.toString = some t := by
  cases t <;> rfl

end ANFType

/-! ## ANF values and bindings (mutual nesting via `List`) -/

/--
Reference to a temporary or named binding in scope. Always a string at
the schema level; we wrap for documentation. The well-formedness
predicate enforces that every `TempRef` resolves to a binding defined
earlier in scope (or to a parameter / property / loop iterVar).
-/
abbrev TempRef := String

mutual

/--
A single ANF value. Exactly 18 constructors mirroring the JSON Schema's
`ANFValue` `oneOf` discriminated on the `kind` field.
-/
inductive ANFValue where
  /-- `{kind: "load_param", name}`  — load a method parameter onto the stack. -/
  | loadParam       (name : String) : ANFValue
  /-- `{kind: "load_prop", name}`   — load a contract property onto the stack. -/
  | loadProp        (name : String) : ANFValue
  /-- `{kind: "load_const", value}` — push a literal or alias marker. -/
  | loadConst       (value : ConstValue) : ANFValue
  /--
  `{kind: "bin_op", op, left, right, result_type?}` — two-operand primitive.
  `result_type` is `some "bytes"` when the operands are byte-typed
  (`PubKey`, `Sig`, `Sha256`, …) and disambiguates `===` between
  `OP_EQUAL` and `OP_NUMEQUAL`. Omitted on numeric ops.
  -/
  | binOp           (op : String) (left right : TempRef)
                    (resultType : Option String) : ANFValue
  /-- `{kind: "unary_op", op, operand, result_type?}` — single-operand op. -/
  | unaryOp         (op : String) (operand : TempRef)
                    (resultType : Option String) : ANFValue
  /-- `{kind: "call", func, args}` — built-in / framework call. -/
  | call            (func : String) (args : List TempRef) : ANFValue
  /-- `{kind: "method_call", object, method, args}` — `obj.method(args)`. -/
  | methodCall      (object : TempRef) (method : String)
                    (args : List TempRef) : ANFValue
  /-- `{kind: "if", cond, then, else}` — conditional with two binding lists. -/
  | ifVal           (cond : TempRef) (thenBranch elseBranch : List ANFBinding) : ANFValue
  /-- `{kind: "loop", count, body, iterVar}` — bounded loop, fully unrollable. -/
  | loop            (count : Nat) (body : List ANFBinding) (iterVar : String) : ANFValue
  /-- `{kind: "assert", value}` — script aborts iff `value` is false. -/
  | assert          (value : TempRef) : ANFValue
  /-- `{kind: "update_prop", name, value}` — write to a (mutable) property slot. -/
  | updateProp      (name : String) (value : TempRef) : ANFValue
  /-- `{kind: "get_state_script"}` — produce the contract's codePart bytes. -/
  | getStateScript  : ANFValue
  /-- `{kind: "check_preimage", preimage}` — BIP-143 preimage verification. -/
  | checkPreimage   (preimage : TempRef) : ANFValue
  /-- `{kind: "deserialize_state", preimage}` — load mutable state from preimage scriptCode. -/
  | deserializeState (preimage : TempRef) : ANFValue
  /-- `{kind: "add_output", satoshis, stateValues, preimage}` — emit a state continuation output. -/
  | addOutput       (satoshis : TempRef) (stateValues : List TempRef)
                    (preimage : TempRef) : ANFValue
  /-- `{kind: "add_raw_output", satoshis, scriptBytes}` — emit an arbitrary-script output. -/
  | addRawOutput    (satoshis : TempRef) (scriptBytes : TempRef) : ANFValue
  /-- `{kind: "add_data_output", satoshis, scriptBytes}` — emit a data output (ordered after state outputs in continuation hash). -/
  | addDataOutput   (satoshis : TempRef) (scriptBytes : TempRef) : ANFValue
  /-- `{kind: "array_literal", elements}` — fixed-length array. -/
  | arrayLiteral    (elements : List TempRef) : ANFValue

/--
A single let-binding `let <name> = <value>`.

Binding-name conventions (enforced by `WF.lean`):
* Names matching `^t\d+$` are SSA temporaries — globally unique within
  the (transitively flattened) method body.
* Other names are developer-introduced locals and may be re-bound; the
  last writer wins.
-/
inductive ANFBinding where
  | mk (name : String) (value : ANFValue) (sourceLoc : Option SourceLoc := none) : ANFBinding

end

namespace ANFBinding
def name : ANFBinding → String      | .mk n _ _ => n
def value : ANFBinding → ANFValue   | .mk _ v _ => v
def sourceLoc : ANFBinding → Option SourceLoc | .mk _ _ s => s
end ANFBinding

/-! ## Top-level structure -/

structure ANFParam where
  name : String
  type : ANFType
  deriving Repr, BEq, Inhabited

structure ANFProperty where
  name : String
  type : ANFType
  readonly : Bool
  initialValue : Option ConstValue := none
  deriving Inhabited

structure ANFMethod where
  name : String
  params : List ANFParam
  body : List ANFBinding
  isPublic : Bool
  deriving Inhabited

structure ANFProgram where
  contractName : String
  properties : List ANFProperty
  methods : List ANFMethod
  deriving Inhabited

end RunarVerification.ANF
