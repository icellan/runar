import Lean.Data.Json
import RunarVerification.ANF.Syntax

/-!
# ANF IR — JSON parsing & serialisation

`FromJson` / `ToJson` instances for every type in `Syntax.lean`, designed
to round-trip with the golden `expected-ir.json` files in
`conformance/tests/`.

Wire format details (per `packages/runar-ir-schema/`):

* JSON objects use the `kind` discriminator string (`load_param`,
  `bin_op`, …) and snake_case field names.
* `LoadConst.value` and `ANFProperty.initialValue` accept JSON
  `string | integer | boolean`. Strings are decoded as:
  - `"0x…"` → `ConstValue.bytes` (hex-decoded)
  - `"@ref:NAME"` → `ConstValue.refAlias`
  - `"@this"` → `ConstValue.thisRef`
* `bigint` literals are bare JSON integers with no quotes and no size
  bound (RFC 8785 / JCS). Lean's `Lean.Json.parse` handles arbitrary
  precision via `JsonNumber.mantissa : Int`.
* Optional fields (`sourceLoc`, `result_type`, `initialValue`) are
  omitted from the output when `none`.
-/

namespace RunarVerification.ANF

open Lean (Json JsonNumber FromJson ToJson)
open Lean.Json (mkObj)

/-! ## Hex helpers -/

private def hexDigit? (c : Char) : Option UInt8 :=
  if '0' ≤ c ∧ c ≤ '9' then some ((c.toNat - '0'.toNat).toUInt8)
  else if 'a' ≤ c ∧ c ≤ 'f' then some ((10 + c.toNat - 'a'.toNat).toUInt8)
  else if 'A' ≤ c ∧ c ≤ 'F' then some ((10 + c.toNat - 'A'.toNat).toUInt8)
  else none

private def hexCharLow (n : Nat) : Char :=
  if n < 10 then Char.ofNat ('0'.toNat + n)
  else Char.ofNat ('a'.toNat + (n - 10))

/--
Parse a hex-encoded byte-string literal into a `ByteArray`. Accepts the
canonical `"raw hex without prefix"` form used by the Rúnar conformance
goldens (e.g. `"1976a914…"`, `"006a"`, `"79be…"`). Also accepts an
optional `0x` prefix for resilience.

Returns `none` if the input has odd length or contains a non-hex
character. The empty string parses as the empty `ByteArray`.
-/
def parseHex? (s : String) : Option ByteArray := do
  let hex := if s.startsWith "0x" then s.drop 2 else s
  guard (hex.length % 2 == 0)
  let rec go (acc : ByteArray) : List Char → Option ByteArray
    | [] => some acc
    | hi :: lo :: rest => do
        let h ← hexDigit? hi
        let l ← hexDigit? lo
        go (acc.push (h * 16 + l)) rest
    | _ => none
  go ByteArray.empty hex.toList

/--
Encode a `ByteArray` to the canonical raw-hex form (no `0x` prefix) used
by the Rúnar conformance goldens.
-/
def toHex (b : ByteArray) : String := Id.run do
  let mut s := ""
  for byte in b.toList do
    let n := byte.toNat
    s := s.push (hexCharLow (n / 16))
    s := s.push (hexCharLow (n % 16))
  return s

/-! ## JsonNumber → Int (only when exponent = 0) -/

private def jsonNumberToInt? : JsonNumber → Option Int
  | ⟨m, 0⟩ => some m
  | _      => none

/-! ## ConstValue -/

instance : FromJson ConstValue where
  fromJson? j := match j with
    | .bool b => .ok (.bool b)
    | .num n =>
        match jsonNumberToInt? n with
        | some i => .ok (.int i)
        | none   => .error s!"ConstValue: non-integer JSON number"
    | .str s =>
        if s == "@this" then
          .ok .thisRef
        else if s.startsWith "@ref:" then
          .ok (.refAlias (s.drop 5))
        else
          -- Anything else is a hex-encoded ByteString literal
          -- (the Rúnar goldens encode bytestrings as raw hex without
          -- a `0x` prefix; the parser also accepts the prefix).
          match parseHex? s with
          | some b => .ok (.bytes b)
          | none   => .error s!"ConstValue: malformed bytestring literal {s}"
    | _ => .error s!"ConstValue: expected string|integer|boolean, got {j.compress}"

instance : ToJson ConstValue where
  toJson
    | .int i      => .num ⟨i, 0⟩
    | .bool b     => .bool b
    | .bytes b    => .str (toHex b)
    | .refAlias n => .str ("@ref:" ++ n)
    | .thisRef    => .str "@this"

/-! ## SourceLoc -/

instance : FromJson SourceLoc where
  fromJson? j := do
    let file ← j.getObjValAs? String "file"
    let line ← j.getObjValAs? Nat "line"
    let column ← j.getObjValAs? Nat "column"
    return { file, line, column }

instance : ToJson SourceLoc where
  toJson s := mkObj [
    ("file",   .str s.file),
    ("line",   .num ⟨s.line, 0⟩),
    ("column", .num ⟨s.column, 0⟩)
  ]

/-! ## ANFType -/

instance : FromJson ANFType where
  fromJson? j := match j with
    | .str s =>
        match ANFType.fromString? s with
        | some t => .ok t
        | none   => .error s!"ANFType: unknown type string {s}"
    | _ => .error "ANFType: expected string"

instance : ToJson ANFType where
  toJson t := .str t.toString

/-! ## ANFParam -/

instance : FromJson ANFParam where
  fromJson? j := do
    let name ← j.getObjValAs? String "name"
    let type ← j.getObjValAs? ANFType "type"
    return { name, type }

instance : ToJson ANFParam where
  toJson p := mkObj [
    ("name", .str p.name),
    ("type", .str p.type.toString)
  ]

/-! ## ANFValue / ANFBinding (mutual recursion) -/

private def parseTempRefList? (j : Json) : Except String (List String) := do
  let arr ← j.getArr?
  arr.toList.mapM fun e => match e with
    | .str s => .ok s
    | _ => .error s!"expected string in ref list, got {e.compress}"

mutual

private partial def fromJsonANFValue? (j : Json) : Except String ANFValue := do
  let kind ← j.getObjValAs? String "kind"
  match kind with
  | "load_param" =>
      let name ← j.getObjValAs? String "name"
      return .loadParam name
  | "load_prop" =>
      let name ← j.getObjValAs? String "name"
      return .loadProp name
  | "load_const" =>
      let v ← j.getObjVal? "value"
      let cv ← FromJson.fromJson? (α := ConstValue) v
      return .loadConst cv
  | "bin_op" =>
      let op ← j.getObjValAs? String "op"
      let left ← j.getObjValAs? String "left"
      let right ← j.getObjValAs? String "right"
      let resultType :=
        (j.getObjValAs? String "result_type").toOption
      return .binOp op left right resultType
  | "unary_op" =>
      let op ← j.getObjValAs? String "op"
      let operand ← j.getObjValAs? String "operand"
      let resultType :=
        (j.getObjValAs? String "result_type").toOption
      return .unaryOp op operand resultType
  | "call" =>
      let func ← j.getObjValAs? String "func"
      let argsJ ← j.getObjVal? "args"
      let args ← parseTempRefList? argsJ
      return .call func args
  | "method_call" =>
      let object ← j.getObjValAs? String "object"
      let method ← j.getObjValAs? String "method"
      let argsJ ← j.getObjVal? "args"
      let args ← parseTempRefList? argsJ
      return .methodCall object method args
  | "if" =>
      let cond ← j.getObjValAs? String "cond"
      let thenJ ← j.getObjVal? "then"
      let elseJ ← j.getObjVal? "else"
      let thenArr ← thenJ.getArr?
      let elseArr ← elseJ.getArr?
      let thenBranch ← thenArr.toList.mapM fromJsonANFBinding?
      let elseBranch ← elseArr.toList.mapM fromJsonANFBinding?
      return .ifVal cond thenBranch elseBranch
  | "loop" =>
      let count ← j.getObjValAs? Nat "count"
      let bodyJ ← j.getObjVal? "body"
      let bodyArr ← bodyJ.getArr?
      let body ← bodyArr.toList.mapM fromJsonANFBinding?
      let iterVar ← j.getObjValAs? String "iterVar"
      return .loop count body iterVar
  | "assert" =>
      let value ← j.getObjValAs? String "value"
      return .assert value
  | "update_prop" =>
      let name ← j.getObjValAs? String "name"
      let value ← j.getObjValAs? String "value"
      return .updateProp name value
  | "get_state_script" =>
      return .getStateScript
  | "check_preimage" =>
      let preimage ← j.getObjValAs? String "preimage"
      return .checkPreimage preimage
  | "deserialize_state" =>
      let preimage ← j.getObjValAs? String "preimage"
      return .deserializeState preimage
  | "add_output" =>
      let satoshis ← j.getObjValAs? String "satoshis"
      let svJ ← j.getObjVal? "stateValues"
      let stateValues ← parseTempRefList? svJ
      let preimage ← j.getObjValAs? String "preimage"
      return .addOutput satoshis stateValues preimage
  | "add_raw_output" =>
      let satoshis ← j.getObjValAs? String "satoshis"
      let scriptBytes ← j.getObjValAs? String "scriptBytes"
      return .addRawOutput satoshis scriptBytes
  | "add_data_output" =>
      let satoshis ← j.getObjValAs? String "satoshis"
      let scriptBytes ← j.getObjValAs? String "scriptBytes"
      return .addDataOutput satoshis scriptBytes
  | "array_literal" =>
      let elemsJ ← j.getObjVal? "elements"
      let elements ← parseTempRefList? elemsJ
      return .arrayLiteral elements
  | other => .error s!"unknown ANFValue kind: {other}"

private partial def fromJsonANFBinding? (j : Json) : Except String ANFBinding := do
  let name ← j.getObjValAs? String "name"
  let valueJ ← j.getObjVal? "value"
  let value ← fromJsonANFValue? valueJ
  let sourceLoc ← match j.getObjVal? "sourceLoc" with
    | .ok sl =>
        match FromJson.fromJson? (α := SourceLoc) sl with
        | .ok s    => .ok (some s)
        | .error e => .error e
    | .error _ => .ok none
  return .mk name value sourceLoc

end

instance : FromJson ANFValue where
  fromJson? := fromJsonANFValue?

instance : FromJson ANFBinding where
  fromJson? := fromJsonANFBinding?

private def refList (xs : List String) : Json :=
  .arr (xs.map Json.str).toArray

mutual

private partial def toJsonANFValue : ANFValue → Json
  | .loadParam name => mkObj [("kind", .str "load_param"), ("name", .str name)]
  | .loadProp name  => mkObj [("kind", .str "load_prop"),  ("name", .str name)]
  | .loadConst cv   => mkObj [("kind", .str "load_const"), ("value", ToJson.toJson cv)]
  | .binOp op l r rt =>
      let base : List (String × Json) :=
        [("kind", .str "bin_op"), ("op", .str op), ("left", .str l), ("right", .str r)]
      mkObj (match rt with
        | some t => base ++ [("result_type", .str t)]
        | none   => base)
  | .unaryOp op operand rt =>
      let base : List (String × Json) :=
        [("kind", .str "unary_op"), ("op", .str op), ("operand", .str operand)]
      mkObj (match rt with
        | some t => base ++ [("result_type", .str t)]
        | none   => base)
  | .call func args =>
      mkObj [("kind", .str "call"), ("func", .str func), ("args", refList args)]
  | .methodCall obj m args =>
      mkObj [("kind", .str "method_call"), ("object", .str obj),
             ("method", .str m), ("args", refList args)]
  | .ifVal cond t e =>
      mkObj [("kind", .str "if"), ("cond", .str cond),
             ("then", .arr (t.map toJsonANFBinding).toArray),
             ("else", .arr (e.map toJsonANFBinding).toArray)]
  | .loop count body iter =>
      mkObj [("kind", .str "loop"), ("count", .num ⟨count, 0⟩),
             ("body", .arr (body.map toJsonANFBinding).toArray),
             ("iterVar", .str iter)]
  | .assert value => mkObj [("kind", .str "assert"), ("value", .str value)]
  | .updateProp name value =>
      mkObj [("kind", .str "update_prop"), ("name", .str name), ("value", .str value)]
  | .getStateScript => mkObj [("kind", .str "get_state_script")]
  | .checkPreimage preimage =>
      mkObj [("kind", .str "check_preimage"), ("preimage", .str preimage)]
  | .deserializeState preimage =>
      mkObj [("kind", .str "deserialize_state"), ("preimage", .str preimage)]
  | .addOutput sats sv preimage =>
      mkObj [("kind", .str "add_output"), ("satoshis", .str sats),
             ("stateValues", refList sv), ("preimage", .str preimage)]
  | .addRawOutput sats sb =>
      mkObj [("kind", .str "add_raw_output"), ("satoshis", .str sats), ("scriptBytes", .str sb)]
  | .addDataOutput sats sb =>
      mkObj [("kind", .str "add_data_output"), ("satoshis", .str sats), ("scriptBytes", .str sb)]
  | .arrayLiteral elems =>
      mkObj [("kind", .str "array_literal"), ("elements", refList elems)]

private partial def toJsonANFBinding : ANFBinding → Json
  | .mk name value sourceLoc =>
      let base : List (String × Json) := [("name", .str name), ("value", toJsonANFValue value)]
      mkObj (match sourceLoc with
        | some sl => base ++ [("sourceLoc", ToJson.toJson sl)]
        | none    => base)

end

instance : ToJson ANFValue := ⟨toJsonANFValue⟩
instance : ToJson ANFBinding := ⟨toJsonANFBinding⟩

/-! ## ANFProperty -/

instance : FromJson ANFProperty where
  fromJson? j := do
    let name ← j.getObjValAs? String "name"
    let type ← j.getObjValAs? ANFType "type"
    let readonly ← j.getObjValAs? Bool "readonly"
    let initialValue ← match j.getObjVal? "initialValue" with
      | .ok iv =>
          match FromJson.fromJson? (α := ConstValue) iv with
          | .ok c    => .ok (some c)
          | .error e => .error e
      | .error _ => .ok none
    return { name, type, readonly, initialValue }

instance : ToJson ANFProperty where
  toJson p :=
    let base : List (String × Json) :=
      [("name", .str p.name), ("type", .str p.type.toString),
       ("readonly", .bool p.readonly)]
    mkObj (match p.initialValue with
      | some iv => base ++ [("initialValue", ToJson.toJson iv)]
      | none    => base)

/-! ## ANFMethod -/

instance : FromJson ANFMethod where
  fromJson? j := do
    let name ← j.getObjValAs? String "name"
    let paramsJ ← j.getObjVal? "params"
    let paramsArr ← paramsJ.getArr?
    let params ← paramsArr.toList.mapM (FromJson.fromJson? (α := ANFParam))
    let bodyJ ← j.getObjVal? "body"
    let bodyArr ← bodyJ.getArr?
    let body ← bodyArr.toList.mapM (FromJson.fromJson? (α := ANFBinding))
    let isPublic ← j.getObjValAs? Bool "isPublic"
    return { name, params, body, isPublic }

instance : ToJson ANFMethod where
  toJson m := mkObj [
    ("name", .str m.name),
    ("params", .arr (m.params.map ToJson.toJson).toArray),
    ("body", .arr (m.body.map ToJson.toJson).toArray),
    ("isPublic", .bool m.isPublic)
  ]

/-! ## ANFProgram -/

instance : FromJson ANFProgram where
  fromJson? j := do
    let contractName ← j.getObjValAs? String "contractName"
    let propsJ ← j.getObjVal? "properties"
    let propsArr ← propsJ.getArr?
    let properties ← propsArr.toList.mapM (FromJson.fromJson? (α := ANFProperty))
    let methodsJ ← j.getObjVal? "methods"
    let methodsArr ← methodsJ.getArr?
    let methods ← methodsArr.toList.mapM (FromJson.fromJson? (α := ANFMethod))
    return { contractName, properties, methods }

instance : ToJson ANFProgram where
  toJson p := mkObj [
    ("contractName", .str p.contractName),
    ("properties", .arr (p.properties.map ToJson.toJson).toArray),
    ("methods", .arr (p.methods.map ToJson.toJson).toArray)
  ]

/-! ## Top-level helpers -/

/--
Parse an ANF program from a JSON source string. Returns
`Except String ANFProgram` so that load failures are explicit.
-/
def ANFProgram.fromString (src : String) : Except String ANFProgram := do
  let j ← Lean.Json.parse src
  FromJson.fromJson? j

/-- Serialise an ANF program to compact JSON (not yet RFC 8785 canonical). -/
def ANFProgram.toJsonString (p : ANFProgram) : String :=
  (ToJson.toJson p).compress

end RunarVerification.ANF
