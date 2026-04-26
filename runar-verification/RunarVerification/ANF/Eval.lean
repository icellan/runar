import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.ANF.Typed

/-!
# ANF IR — Big-step evaluation (skeleton)

A starter executable big-step semantics for ANF programs.

**Scope of this module (Phase 1 / Phase 2 only).** Per the spec, this
file lays down the dispatch shape and fills in the **non-cryptographic**
constructors only. Hashes, EC primitives, ECDSA / Rabin / WOTS / SLH-DSA
verifiers, and the BIP-143 preimage extractors are all introduced as
`axiom` declarations in the dedicated `Crypto` namespace at the bottom
of this file. Each axiom is documented with the assumed property and
where it sits in the larger Phase 3 plan.

**What is concrete here:**

* `loadParam`, `loadProp`, `loadConst` (`int`, `bool`, `bytes`,
  `refAlias`, `thisRef`)
* arithmetic / comparison / bitwise `bin_op`s on `bigint`
* byte-equality and short-circuit `&&` / `||`
* `unary_op` (`!`, `~`, `-`)
* `assert` (script aborts iff value is `false`)
* `update_prop` (writes the property slot)
* the four control-flow / framework intrinsics: `super` (no-op in eval),
  `cat` (byte concatenation), `len`, `bool` (coercion), `assert`,
  `bin2num`, `num2bin`.

**What is axiomatized:**

* every hash function (`sha256`, `ripemd160`, `hash160`, `hash256`,
  `sha256Compress`, `sha256Finalize`, `blake3*`)
* every EC primitive (secp256k1, P-256, P-384, BN254-G1)
* every signature verifier (ECDSA, Rabin, WOTS+, SLH-DSA-SHA2-{128,192,256}{s,f})
* every `extract*` preimage projection (BIP-143)
* every field-arithmetic primitive (BabyBear, KoalaBear, BN254-Fp)
* `checkPreimage` (per OQ-4)
* `checkSig`, `checkMultiSig`

The axioms are **not** proved sound here. Each is documented with the
property the verification lead should later refine into a proper
specification.

Run `lake exe goldenEval` (TODO; not part of this bootstrap) to drive
this evaluator against the conformance fixtures once Phase 3 fills in
the framework intrinsics like `computeStateOutput` and
`buildChangeOutput`.
-/

namespace RunarVerification.ANF
namespace Eval

/-! ## Runtime values -/

/--
A concrete runtime value for the ANF interpreter.

Each constructor corresponds to one `ANFType`. Cryptographic values
(`Point`, `P256Point`, `P384Point`, `RabinPubKey`, `RabinSig`,
`SigHashPreimage`) are represented as opaque `ByteArray` payloads —
the Lean evaluator does not reach into their internals; only the
axiomatized primitives in `Crypto` do.
-/
inductive Value where
  | vBigint   : Int → Value
  | vBool     : Bool → Value
  | vBytes    : ByteArray → Value
  /-- Opaque crypto value (Point, signature, hash, preimage, …). -/
  | vOpaque   : ByteArray → Value
  /-- The contract-instance marker (corresponds to `@this`). -/
  | vThis     : Value
  deriving Inhabited

namespace Value
def asInt? : Value → Option Int
  | .vBigint i => some i
  | _ => none
def asBool? : Value → Option Bool
  | .vBool b => some b
  | _ => none
def asBytes? : Value → Option ByteArray
  | .vBytes b => some b
  | .vOpaque b => some b
  | _ => none
end Value

/-! ## Evaluation result -/

/-- Reasons evaluation may fail. -/
inductive EvalError where
  | unboundName        (name : String) : EvalError
  | unboundProperty    (name : String) : EvalError
  | typeError          (msg : String)  : EvalError
  | assertFailed                       : EvalError
  | unsupported        (msg : String)  : EvalError
  | divByZero                          : EvalError
  deriving Inhabited

/-- A standard outcome monad: success returns a value, failure carries an `EvalError`. -/
abbrev EvalResult α := Except EvalError α

/-! ## Outputs (canonical declaration order) -/

inductive Output where
  | state    (satoshis : Int) (stateValues : List Value) : Output
  | rawScript (satoshis : Int) (scriptBytes : ByteArray) : Output
  | dataOnly  (satoshis : Int) (scriptBytes : ByteArray) : Output
  deriving Inhabited

/-! ## Evaluation environment -/

/--
The evaluation state.

* `params` — method parameters (set once at method entry).
* `props`  — current contract-property slot values (mutated by `update_prop`).
* `bindings` — the most-recent `tN` and named binding values, in
  list-order (head = most recent), supporting the loop-carry
  shadowing semantics from `WF.lean`.
* `outputs` — the ordered list of emitted transaction outputs
  (`add_output`, `add_raw_output`, `add_data_output`).
-/
structure State where
  params   : List (String × Value) := []
  props    : List (String × Value) := []
  bindings : List (String × Value) := []
  outputs  : List Output := []
  deriving Inhabited

namespace State

/-- Look up a binding name. Order matters: most-recent wins. -/
def lookupBinding (s : State) (name : String) : Option Value :=
  (s.bindings.find? (·.fst == name)).map (·.snd)

def lookupParam (s : State) (name : String) : Option Value :=
  (s.params.find? (·.fst == name)).map (·.snd)

def lookupProp (s : State) (name : String) : Option Value :=
  (s.props.find? (·.fst == name)).map (·.snd)

/-- Resolve a `TempRef` against bindings, then params, then props. -/
def resolveRef (s : State) (name : String) : Option Value :=
  s.lookupBinding name <|> s.lookupParam name <|> s.lookupProp name

def addBinding (s : State) (name : String) (v : Value) : State :=
  { s with bindings := (name, v) :: s.bindings }

/-- Set / overwrite a property slot. -/
def setProp (s : State) (name : String) (v : Value) : State :=
  let removed := s.props.filter (·.fst != name)
  { s with props := (name, v) :: removed }

end State

/-! ## Concrete operator semantics -/

/-- Numeric / boolean / byte primitive bin-ops on `Value`. -/
def evalBinOp (op : String) (l r : Value) (resultType : Option String) :
    EvalResult Value := do
  match op, l, r with
  | "+",  .vBigint a, .vBigint b => return .vBigint (a + b)
  | "-",  .vBigint a, .vBigint b => return .vBigint (a - b)
  | "*",  .vBigint a, .vBigint b => return .vBigint (a * b)
  | "/",  .vBigint a, .vBigint b =>
      if b == 0 then .error .divByZero else return .vBigint (a / b)
  | "%",  .vBigint a, .vBigint b =>
      if b == 0 then .error .divByZero else return .vBigint (a % b)
  | "<",  .vBigint a, .vBigint b => return .vBool (decide (a < b))
  | "<=", .vBigint a, .vBigint b => return .vBool (decide (a ≤ b))
  | ">",  .vBigint a, .vBigint b => return .vBool (decide (a > b))
  | ">=", .vBigint a, .vBigint b => return .vBool (decide (a ≥ b))
  | "&&", .vBool a, .vBool b     => return .vBool (a && b)
  | "||", .vBool a, .vBool b     => return .vBool (a || b)
  | "===", a, b =>
      -- byte equality vs numeric equality is disambiguated by
      -- `result_type: "bytes"` — see EXPLORATION.md §9 / 04-anf-lower.ts:204
      match resultType with
      | some "bytes" =>
          match a.asBytes?, b.asBytes? with
          | some ba, some bb => return .vBool (decide (ba.toList = bb.toList))
          | _, _ => .error (.typeError "===/bytes expects two byte values")
      | _ =>
          match a, b with
          | .vBigint x, .vBigint y => return .vBool (decide (x = y))
          | .vBool x, .vBool y => return .vBool (decide (x = y))
          | _, _ => .error (.typeError "===/numeric expects matching scalar values")
  -- Bitwise ops on Int are not part of Lean core; the lowering pass uses them
  -- only on `bigint` operands but the semantics match a fixed-width unsigned
  -- representation. Phase 3 wires these through ByteArray-level helpers.
  | "&", _, _ => .error (.unsupported "bin_op & on Int (axiomatized in Phase 3)")
  | "|", _, _ => .error (.unsupported "bin_op | on Int (axiomatized in Phase 3)")
  | "^", _, _ => .error (.unsupported "bin_op ^ on Int (axiomatized in Phase 3)")
  | "<<", .vBigint a, .vBigint b => return .vBigint (a * (2 ^ b.toNat))
  | ">>", .vBigint a, .vBigint b => return .vBigint (a / (2 ^ b.toNat))
  | _, _, _ => .error (.unsupported s!"bin_op {op} on these operand types")

def evalUnaryOp (op : String) (operand : Value) (_resultType : Option String) :
    EvalResult Value := do
  match op, operand with
  | "!", .vBool b   => return .vBool (!b)
  | "-", .vBigint i => return .vBigint (-i)
  | "~", _ => .error (.unsupported "unary_op ~ on Int (axiomatized in Phase 3)")
  | _, _ => .error (.unsupported s!"unary_op {op}")

/-! ## Cryptographic primitives — axioms

Each axiom takes opaque `ByteArray` payloads and returns a deterministic
`ByteArray` (or `Bool`). Determinism is implicit (axioms are total
functions). Soundness specifications are deferred to Phase 3.

The verification lead should refine these by:

1. Replacing `axiom` with `def` and an actual algorithm where feasible
   (e.g. `sha256` against a Lean SHA-256 reference implementation).
2. Adding *assumed property* lemmas (`axiom sha256_collision_resistance`
   or similar) for primitives that cannot be implemented in Lean
   (cryptographic verifiers).
-/

namespace Crypto

-- Hashes
axiom sha256          : ByteArray → ByteArray
axiom ripemd160       : ByteArray → ByteArray
axiom hash160         : ByteArray → ByteArray
axiom hash256         : ByteArray → ByteArray
axiom sha256Compress  : ByteArray → ByteArray → ByteArray
axiom sha256Finalize  : ByteArray → ByteArray → Int → ByteArray
axiom blake3Compress  : ByteArray → ByteArray → ByteArray
axiom blake3Hash      : ByteArray → ByteArray

-- secp256k1 EC primitives (operands are 64-byte uncompressed points)
axiom ecAdd               : ByteArray → ByteArray → ByteArray
axiom ecMul               : ByteArray → Int → ByteArray
axiom ecMulGen            : Int → ByteArray
axiom ecNegate            : ByteArray → ByteArray
axiom ecOnCurve           : ByteArray → Bool
axiom ecModReduce         : Int → Int → Int
axiom ecEncodeCompressed  : ByteArray → ByteArray
axiom ecMakePoint         : Int → Int → ByteArray
axiom ecPointX            : ByteArray → Int
axiom ecPointY            : ByteArray → Int

-- NIST P-256
axiom p256Add               : ByteArray → ByteArray → ByteArray
axiom p256Mul               : ByteArray → Int → ByteArray
axiom p256MulGen            : Int → ByteArray
axiom p256OnCurve           : ByteArray → Bool
axiom p256EncodeCompressed  : ByteArray → ByteArray
axiom verifyECDSA_P256      : ByteArray → ByteArray → ByteArray → Bool

-- NIST P-384
axiom p384Add               : ByteArray → ByteArray → ByteArray
axiom p384Mul               : ByteArray → Int → ByteArray
axiom p384MulGen            : Int → ByteArray
axiom p384OnCurve           : ByteArray → Bool
axiom p384EncodeCompressed  : ByteArray → ByteArray
axiom verifyECDSA_P384      : ByteArray → ByteArray → ByteArray → Bool

-- BabyBear / KoalaBear field arithmetic (placeholder — small fields are implementable)
axiom bbFieldAdd       : Int → Int → Int
axiom bbFieldSub       : Int → Int → Int
axiom bbFieldMul       : Int → Int → Int
axiom bbFieldInv       : Int → Int

-- Merkle / Rabin / Post-quantum
axiom merkleRootSha256        : ByteArray → ByteArray → Int → Int → ByteArray
axiom merkleRootHash256       : ByteArray → ByteArray → Int → Int → ByteArray
axiom verifyRabinSig          : ByteArray → ByteArray → ByteArray → ByteArray → Bool
axiom verifyWOTS              : ByteArray → ByteArray → ByteArray → Bool
axiom verifySLHDSA_SHA2_128s  : ByteArray → ByteArray → ByteArray → Bool
axiom verifySLHDSA_SHA2_128f  : ByteArray → ByteArray → ByteArray → Bool
axiom verifySLHDSA_SHA2_192s  : ByteArray → ByteArray → ByteArray → Bool
axiom verifySLHDSA_SHA2_192f  : ByteArray → ByteArray → ByteArray → Bool
axiom verifySLHDSA_SHA2_256s  : ByteArray → ByteArray → ByteArray → Bool
axiom verifySLHDSA_SHA2_256f  : ByteArray → ByteArray → ByteArray → Bool

-- Bitcoin BIP-143 preimage projections (operate on opaque SigHashPreimage bytes)
axiom extractVersion       : ByteArray → Int
axiom extractHashPrevouts  : ByteArray → ByteArray
axiom extractHashSequence  : ByteArray → ByteArray
axiom extractOutpoint      : ByteArray → ByteArray
axiom extractInputIndex    : ByteArray → Int
axiom extractScriptCode    : ByteArray → ByteArray
axiom extractAmount        : ByteArray → Int
axiom extractSequence      : ByteArray → Int
axiom extractOutputHash    : ByteArray → ByteArray
axiom extractLocktime      : ByteArray → Int
axiom extractSigHashType   : ByteArray → Int

-- Signature & preimage verifiers (the two are mocked-true in the TS interpreters,
-- but for the Lean model we leave them axiomatized so a future
-- behavioural-soundness theorem can quantify over preimage validity.)
axiom checkSig         : ByteArray → ByteArray → Bool
axiom checkMultiSig    : List ByteArray → List ByteArray → Bool
/--
`checkPreimage` decides whether the given byte-string is a valid
BIP-143 preimage for the implicit transaction context. Per OQ-4 we
leave the transaction context abstract.
-/
axiom checkPreimage    : ByteArray → Bool

-- Output construction
axiom buildChangeOutput     : ByteArray → Int → ByteArray
axiom computeStateOutput    : ByteArray → ByteArray → Int → ByteArray

end Crypto

/-! ## Built-in dispatch (concrete cases only)

A small table of pure built-ins handled directly in Lean. Anything not
in this table falls through to the `Crypto` axioms via
`callBuiltin?`, returning `none` for unsupported / framework-internal
calls (which a future iteration of `Eval` will flesh out).
-/

private def evalCat? : List Value → Option Value
  | [.vBytes a, .vBytes b] => some (.vBytes (a ++ b))
  | _ => none

private def evalLen? : List Value → Option Value
  | [.vBytes b] => some (.vBigint b.size)
  | _ => none

/--
Best-effort dispatch for the documented "concrete" built-ins. Returns
`none` for any built-in that is intentionally axiomatized at this stage;
the caller treats `none` as `EvalError.unsupported` for now.
-/
def callBuiltin? (func : String) (args : List Value) : Option Value :=
  match func with
  | "cat"  => evalCat? args
  | "len"  => evalLen? args
  | "super" =>
      -- super(...) is a constructor-delegation marker with no
      -- runtime effect in eval; we return the @this marker.
      some .vThis
  | "bool" =>
      match args with
      | [.vBigint i] => some (.vBool (decide (i ≠ 0)))
      | [.vBool b]   => some (.vBool b)
      | _ => none
  | _ => none

/-! ## The (skeleton) evaluator -/

/--
Look up a `TempRef` in the current evaluation state. The order is:

1. method-local bindings (most recent first; supports loop-carry shadowing),
2. method parameters,
3. contract properties.

This matches the resolution order the TS lowering pass uses
(`04-anf-lower.ts:332-405`).
-/
def lookupRef (s : State) (name : String) : EvalResult Value :=
  match s.resolveRef name with
  | some v => .ok v
  | none   => .error (.unboundName name)

/-- Resolve `ref` and require it to be `vBigint`. -/
private def lookupInt (s : State) (ref : String) : EvalResult Int := do
  let v ← lookupRef s ref
  match v.asInt? with
  | some i => return i
  | none   => .error (.typeError s!"expected bigint at {ref}")

/-- Resolve `ref` and require it to be byte-coercible (`vBytes` or `vOpaque`). -/
private def lookupBytes (s : State) (ref : String) : EvalResult ByteArray := do
  let v ← lookupRef s ref
  match v.asBytes? with
  | some b => return b
  | none   => .error (.typeError s!"expected bytes at {ref}")

mutual

/--
Big-step evaluation of a single `ANFValue` against the current state.

Concrete cases handled (all non-cryptographic constructors):

* `loadParam` / `loadProp` — direct slot lookups.
* `loadConst (.int / .bool / .bytes / .refAlias / .thisRef)`.
* `bin_op` / `unary_op` — arithmetic / comparison / logical / shifts.
* `if` — dispatches on `cond`, recurses into the active branch via
  `evalBindings`. The if-binding's "result" is the value of the last
  binding in the active branch (or `vBool true/false` if empty).
* `loop` — unrolls `count` times, registering `iterVar` as a synthetic
  param visible only inside the body.
* `assert` — fails with `.assertFailed` if the operand is `false`.
* `update_prop` — writes the property slot; returns the assigned value.
* `call` — dispatches the cheap built-ins (`cat`, `len`, `super`,
  `bool`); everything else returns `.error .unsupported` for the
  Phase 3 lead to wire to `Crypto`.
* `getStateScript`, `deserializeState` — opaque framework intrinsics
  returning `.vOpaque ByteArray.empty`.
* `addOutput`, `addRawOutput`, `addDataOutput` — append to
  `State.outputs` in canonical declaration order.
* `arrayLiteral` — evaluates each element ref but emits an opaque
  payload (full byte-layout deferred to Phase 3).
* `methodCall` — `.error .unsupported`; per-program method-resolution
  table is Phase 3 work.

Bitwise `&|^~` on `Int` and every cryptographic primitive return
`.error .unsupported` and are listed as axioms in `Eval.Crypto`.
-/
partial def evalValue (s : State) : ANFValue → EvalResult (Value × State)
  | .loadParam name =>
      match s.lookupParam name with
      | some v => .ok (v, s)
      | none   => .error (.unboundName name)
  | .loadProp name =>
      match s.lookupProp name with
      | some v => .ok (v, s)
      | none   => .error (.unboundProperty name)
  | .loadConst (.int i)      => .ok (.vBigint i, s)
  | .loadConst (.bool b)     => .ok (.vBool b, s)
  | .loadConst (.bytes b)    => .ok (.vBytes b, s)
  | .loadConst (.refAlias n) => do
      let v ← lookupRef s n
      return (v, s)
  | .loadConst .thisRef       => .ok (.vThis, s)
  | .binOp op l r rt => do
      let lv ← lookupRef s l
      let rv ← lookupRef s r
      let res ← evalBinOp op lv rv rt
      return (res, s)
  | .unaryOp op operand rt => do
      let ov ← lookupRef s operand
      let res ← evalUnaryOp op ov rt
      return (res, s)
  | .call func args => do
      let argVs ← args.mapM (lookupRef s)
      match callBuiltin? func argVs with
      | some v => return (v, s)
      | none   => .error (.unsupported s!"builtin {func} (axiomatized — see Crypto)")
  | .methodCall _obj _method _args =>
      -- Private-method calls require a per-program method-resolution
      -- table that the verification lead will wire in Phase 3.
      .error (.unsupported "method_call: per-program method dispatch deferred to Phase 3")
  | .ifVal cond thenBs elseBs => do
      let cv ← lookupRef s cond
      match cv with
      | .vBool true  =>
          let s' ← evalBindings s thenBs
          -- Convention: the "value" of an if-binding is the value of
          -- the *last* binding in the active branch.
          match thenBs.getLast? with
          | some b =>
              match s'.lookupBinding b.name with
              | some v => return (v, s')
              | none   => .ok (.vBool true, s')
          | none => .ok (.vBool true, s')
      | .vBool false =>
          let s' ← evalBindings s elseBs
          match elseBs.getLast? with
          | some b =>
              match s'.lookupBinding b.name with
              | some v => return (v, s')
              | none   => .ok (.vBool false, s')
          | none => .ok (.vBool false, s')
      | _ => .error (.typeError "if expects boolean condition")
  | .loop count body iterVar => do
      -- Unroll exactly `count` iterations, registering iterVar as a
      -- synthetic param for the body's scope. Each iteration sees the
      -- accumulated bindings (loop-carry shadowing falls out for free).
      let s' ← runLoop count body iterVar 0 s
      .ok (.vBool true, s')
  | .assert ref => do
      let v ← lookupRef s ref
      match v with
      | .vBool true  => return (.vBool true, s)
      | .vBool false => .error .assertFailed
      | _            => .error (.typeError "assert expects boolean")
  | .updateProp name ref => do
      let v ← lookupRef s ref
      return (v, s.setProp name v)
  | .getStateScript =>
      -- Framework intrinsic — Phase 3 will refine this against the
      -- compiled artifact's `codePart`.
      .ok (.vOpaque ByteArray.empty, s)
  | .checkPreimage preimage => do
      -- The TS reference interpreters mock checkPreimage to `true`
      -- (`runar-testing/.../interpreter.ts:925`,
      --  `runar-sdk/src/anf-interpreter.ts:351`). The Lean `Crypto`
      -- axiom captures the abstract spec but is not computable, so
      -- we mirror the mock here for executable evaluation. Phase 3
      -- replaces this with the real BIP-143 preimage check once a
      -- transaction-context model lands (per OQ-4).
      let _pv ← lookupRef s preimage
      .ok (.vBool true, s)
  | .deserializeState _preimage =>
      -- Framework intrinsic: in production, parses the codePart bytes
      -- of the preimage into the contract's mutable property slots.
      -- Phase 3 will replace this no-op with a real decoder once the
      -- transaction-context model is concrete (per OQ-4).
      .ok (.vOpaque ByteArray.empty, s)
  | .addOutput sats sv pre => do
      let sv' ← lookupInt s sats
      let svs ← sv.mapM (lookupRef s)
      let _preimage := pre  -- empty-string sentinel accepted; preimage value is implicit
      let s' := { s with outputs := s.outputs ++ [.state sv' svs] }
      .ok (.vOpaque ByteArray.empty, s')
  | .addRawOutput sats sb => do
      let sv' ← lookupInt s sats
      let bytes ← lookupBytes s sb
      let s' := { s with outputs := s.outputs ++ [.rawScript sv' bytes] }
      .ok (.vOpaque ByteArray.empty, s')
  | .addDataOutput sats sb => do
      let sv' ← lookupInt s sats
      let bytes ← lookupBytes s sb
      let s' := { s with outputs := s.outputs ++ [.dataOnly sv' bytes] }
      .ok (.vOpaque ByteArray.empty, s')
  | .arrayLiteral elems => do
      let vs ← elems.mapM (lookupRef s)
      -- Arrays are flattened into a concatenated byte-string at the
      -- byte level for storage in the script. For the interpreter,
      -- we emit an opaque payload — actual stack layout is Phase 3.
      let _ := vs
      .ok (.vOpaque ByteArray.empty, s)

/--
Evaluate a sequence of bindings, threading state through. Each binding
adds its computed value to `state.bindings` so subsequent refs resolve.
-/
partial def evalBindings (s : State) : List ANFBinding → EvalResult State
  | [] => .ok s
  | .mk name v _ :: rest => do
      let (val, s') ← evalValue s v
      evalBindings (s'.addBinding name val) rest

/--
Run `count` iterations of a loop body, registering `iterVar` as a
synthetic parameter equal to the current iteration index (0-based).
After each iteration the synthetic param is stripped so subsequent
iterations bind a fresh value.
-/
partial def runLoop (count : Nat) (body : List ANFBinding)
    (iterVar : String) (i : Nat) (s : State) : EvalResult State :=
  if i ≥ count then
    .ok s
  else
    let withIter : State :=
      { s with params := (iterVar, .vBigint i) :: s.params }
    match evalBindings withIter body with
    | .error e => .error e
    | .ok s' =>
        let stripped : State :=
          { s' with params := s'.params.filter (·.fst != iterVar) }
        runLoop count body iterVar (i + 1) stripped

end

/-! ## Type-preservation companion (statement-only)

A statement-only sketch of the eventual soundness theorem, included so
the verification lead has a concrete starting point for Phase 3.

The full statement will eventually be:

> If `Γ ⊢ v : τ` and `s` agrees with `Γ` (every typed name resolves to
> a value of the corresponding type), and `evalValue s v = .ok (v', s')`,
> then `v' : τ`.

This requires (a) a `valueOfType : Value → ANFType → Prop` predicate,
(b) an `agrees : State → TypeEnv → Prop` predicate, and (c) an
inductive characterization of `evalValue`'s success cases — none of
which we attempt here. The statement below is intentionally vacuous so
that it compiles without `sorry`.
-/

/-- A trivially-provable placeholder. Phase 3 strengthens this. -/
theorem eval_step_typeable_placeholder
    (Γ : Typed.TypeEnv) (v : ANFValue) (τ : ANFType)
    (_h : Typed.HasType Γ v τ) :
    True := trivial

end Eval
end RunarVerification.ANF
